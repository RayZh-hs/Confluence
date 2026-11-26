//! Reliable epoch-based Datagram Path MTU agreement and floor-violation state machines (Spec §6.6).

use crate::constants::{
    DG_OVERHEAD, MTU_REASSERT_INTERVAL, MTU_REPORT_TIMEOUT, MTU_RETRY_DELAYS,
};
use crate::runtime::MonotonicTime;

/// Serial-number freshness check (RFC 1982 / Spec §6.6):
/// returns `true` iff `1 <= incoming.wrapping_sub(seen) < 2^31`.
#[inline]
#[must_use]
pub const fn advance_epoch(seen: u32, incoming: u32) -> bool {
    let diff = incoming.wrapping_sub(seen);
    diff >= 1 && diff < (1u32 << 31)
}

#[derive(Debug, Clone, Copy)]
struct PendingReport {
    epoch: u32,
    mtu: u16,
    retries_sent: usize,
    next_retry_at: Option<MonotonicTime>,
}

/// Reliable single-peer MTU advertisement driver with serial-number epochs,
/// `[150, 300, 600, 1200, 2400]` ms retries, and `200 ms` unsolicited reassertion (Spec §6.6).
#[derive(Debug, Clone)]
pub struct MtuReporter {
    epoch: u32,
    advertised: Option<u16>,
    pending: Option<PendingReport>,
    last_sent_at: Option<MonotonicTime>,
}

impl Default for MtuReporter {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl MtuReporter {
    /// Creates an `MtuReporter` initialized with no prior advertised MTU (`epoch = 0`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            epoch: 0,
            advertised: None,
            pending: None,
            last_sent_at: None,
        }
    }

    /// Creates an `MtuReporter` knowing the initial MTU already delivered in `SETUP_OK`.
    #[must_use]
    pub const fn with_initial(initial_mtu: u16) -> Self {
        Self {
            epoch: 0,
            advertised: Some(initial_mtu),
            pending: None,
            last_sent_at: None,
        }
    }

    /// Publishes a new MTU if it differs from the last advertised value (superseding any pending report).
    ///
    /// Returns `Some((epoch, mtu))` to transmit immediately, or `None` if unchanged.
    pub fn publish(&mut self, mtu: u16, now: MonotonicTime) -> Option<(u32, u16)> {
        if self.advertised == Some(mtu) {
            return None;
        }
        Some(self.start_report(mtu, now))
    }

    /// Unsolicited reassertion triggered on oversize drop or `MtuTooSmall` send error.
    ///
    /// Publishes a fresh epoch carrying `current_mtu` ONLY if no report is currently pending
    /// and at least `200 ms` have elapsed since the previous send (Spec §6.6).
    pub fn reassert(&mut self, current_mtu: u16, now: MonotonicTime) -> Option<(u32, u16)> {
        if self.pending.is_some() {
            return None;
        }
        if let Some(last) = self.last_sent_at {
            if now.saturating_duration_since(last) < MTU_REASSERT_INTERVAL {
                return None;
            }
        }
        Some(self.start_report(current_mtu, now))
    }

    fn start_report(&mut self, mtu: u16, now: MonotonicTime) -> (u32, u16) {
        self.epoch = self.epoch.wrapping_add(1);
        self.advertised = Some(mtu);
        self.last_sent_at = Some(now);
        self.pending = Some(PendingReport {
            epoch: self.epoch,
            mtu,
            retries_sent: 0,
            next_retry_at: Some(now.saturating_add(MTU_RETRY_DELAYS[0])),
        });
        (self.epoch, mtu)
    }

    /// Clears the pending report if `ack_epoch` matches the active report's epoch.
    pub fn on_ack(&mut self, ack_epoch: u32) -> bool {
        if self.pending.is_some_and(|p| p.epoch == ack_epoch) {
            self.pending = None;
            true
        } else {
            false
        }
    }

    /// Returns the next retry deadline, if a report is currently pending retry.
    #[must_use]
    pub fn next_deadline(&self) -> Option<MonotonicTime> {
        self.pending.and_then(|p| p.next_retry_at)
    }

    /// Emits a scheduled retry if `now >= next_retry_at`, preserving the exact same `epoch`
    /// (caller encrypts under a fresh AEAD sequence number).
    pub fn poll_retry(&mut self, now: MonotonicTime) -> Option<(u32, u16)> {
        let mut p = self.pending?;
        let deadline = p.next_retry_at?;
        if now < deadline {
            return None;
        }
        p.retries_sent += 1;
        p.next_retry_at = MTU_RETRY_DELAYS
            .get(p.retries_sent)
            .map(|d| now.saturating_add(*d));
        self.last_sent_at = Some(now);
        let out = (p.epoch, p.mtu);
        if p.next_retry_at.is_none() {
            // All 5 retries emitted; clear pending so future reassertions may proceed.
            self.pending = None;
        } else {
            self.pending = Some(p);
        }
        Some(out)
    }

    #[must_use]
    pub const fn is_pending(&self) -> bool {
        self.pending.is_some()
    }
}

/// Outcome of applying a local or peer MTU update at Origin or Destination.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtuChange {
    /// Effective path MTU did not change (or incoming epoch was stale).
    Unchanged,
    /// Effective path MTU changed to `u16` while staying `>= floor`.
    Changed(u16),
    /// Effective path MTU fell strictly below `floor` -> terminate with `MtuTooSmall(u16)`.
    BelowFloor(u16),
}

/// Originator per-leg path MTU tracker `[local_mtu, hop_0..hop_{N-1}, dest_local_mtu]` (Spec §6.6).
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct OriginPathMtu {
    legs: Vec<u16>,
    hop_epochs: Vec<u32>,
    dest_epoch: u32,
    floor: u16,
    effective: u16,
}

#[allow(dead_code)]
impl OriginPathMtu {
    /// Initializes from the authenticated leg vector `[origin_mtu, hop_0..hop_{N-1}, dest_mtu]`.
    #[must_use]
    pub fn new(legs: Vec<u16>, floor: u16) -> Self {
        let hop_count = legs.len().saturating_sub(2);
        let effective = legs.iter().copied().min().unwrap_or(0);
        Self {
            legs,
            hop_epochs: vec![0; hop_count],
            dest_epoch: 0,
            floor,
            effective,
        }
    }

    #[must_use]
    pub const fn current_mtu(&self) -> u16 {
        self.effective
    }

    #[must_use]
    pub const fn max_payload(&self) -> usize {
        (self.effective as usize).saturating_sub(DG_OVERHEAD)
    }

    fn recompute(&mut self) -> MtuChange {
        let next = self.legs.iter().copied().min().unwrap_or(0);
        if next < self.floor {
            self.effective = next;
            return MtuChange::BelowFloor(next);
        }
        if next != self.effective {
            self.effective = next;
            MtuChange::Changed(next)
        } else {
            MtuChange::Unchanged
        }
    }

    /// Updates Origin's own local first-hop link MTU (leg 0).
    pub fn update_local(&mut self, mtu: u16) -> MtuChange {
        if let Some(slot) = self.legs.first_mut() {
            *slot = mtu;
        }
        self.recompute()
    }

    /// Clamps Origin's local link MTU downward on an `MtuTooSmall(bound)` send error.
    pub fn clamp_local(&mut self, bound: u16) -> MtuChange {
        if let Some(slot) = self.legs.first_mut() {
            *slot = (*slot).min(bound);
        }
        self.recompute()
    }

    /// Processes an authenticated `hop::DG_MTU(epoch, mtu)` from intermediate hop `hop_index`.
    ///
    /// Caller MUST always ACK any valid `hop_index` (even when `advance_epoch` is `false`).
    pub fn on_hop_mtu(&mut self, hop_index: usize, epoch: u32, mtu: u16) -> MtuChange {
        let Some(seen) = self.hop_epochs.get_mut(hop_index) else {
            return MtuChange::Unchanged;
        };
        if !advance_epoch(*seen, epoch) {
            return MtuChange::Unchanged;
        }
        *seen = epoch;
        if let Some(slot) = self.legs.get_mut(1 + hop_index) {
            *slot = mtu;
        }
        self.recompute()
    }

    /// Processes an authenticated `e2e::DG_MTU(epoch, mtu)` from Destination.
    ///
    /// Caller MUST always reply with `e2e::DG_MTU_ACK(epoch)` even when stale.
    pub fn on_dest_mtu(&mut self, epoch: u32, mtu: u16) -> MtuChange {
        if !advance_epoch(self.dest_epoch, epoch) {
            return MtuChange::Unchanged;
        }
        self.dest_epoch = epoch;
        if let Some(slot) = self.legs.last_mut() {
            *slot = mtu;
        }
        self.recompute()
    }
}

/// Destination path MTU tracker (`min(origin_path_mtu, local_mtu)`, Spec §6.6).
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct DestPathMtu {
    origin_path_mtu: u16,
    local_mtu: u16,
    origin_epoch: u32,
    floor: u16,
    effective: u16,
}

#[allow(dead_code)]
impl DestPathMtu {
    #[must_use]
    pub fn new(origin_path_mtu: u16, local_mtu: u16, floor: u16) -> Self {
        let effective = origin_path_mtu.min(local_mtu);
        Self {
            origin_path_mtu,
            local_mtu,
            origin_epoch: 0,
            floor,
            effective,
        }
    }

    #[must_use]
    pub const fn current_mtu(&self) -> u16 {
        self.effective
    }

    #[must_use]
    pub const fn local_mtu(&self) -> u16 {
        self.local_mtu
    }

    #[must_use]
    pub const fn max_payload(&self) -> usize {
        (self.effective as usize).saturating_sub(DG_OVERHEAD)
    }

    fn recompute(&mut self) -> MtuChange {
        let next = self.origin_path_mtu.min(self.local_mtu);
        if next < self.floor {
            self.effective = next;
            return MtuChange::BelowFloor(next);
        }
        if next != self.effective {
            self.effective = next;
            MtuChange::Changed(next)
        } else {
            MtuChange::Unchanged
        }
    }

    pub fn update_local(&mut self, mtu: u16) -> MtuChange {
        self.local_mtu = mtu;
        self.recompute()
    }

    pub fn clamp_local(&mut self, bound: u16) -> MtuChange {
        self.local_mtu = self.local_mtu.min(bound);
        self.recompute()
    }

    /// Processes an authenticated `e2e::DG_MTU(epoch, mtu)` from Origin.
    ///
    /// Caller MUST always reply with `e2e::DG_MTU_ACK(epoch)` even if stale.
    pub fn on_origin_mtu(&mut self, epoch: u32, mtu: u16) -> MtuChange {
        if !advance_epoch(self.origin_epoch, epoch) {
            return MtuChange::Unchanged;
        }
        self.origin_epoch = epoch;
        self.origin_path_mtu = mtu;
        self.recompute()
    }
}

/// Outcome of a link MTU shift on an intermediate Datagram Transit hop (Spec §6.6).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitMtuEvent {
    Unchanged,
    /// Effective hop MTU shifted while remaining `>= floor`: advertise upstream via `hop::DG_MTU`.
    Updated(u16),
    /// Effective hop MTU fell `< floor`: enter/continue `5 s` drain window while publishing `mtu` upstream.
    FloorViolation {
        mtu: u16,
        drain_deadline: MonotonicTime,
    },
}

/// Intermediate Datagram Transit leg MTU tracker with `5 s` floor-violation drain window (Spec §6.6).
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct TransitPathMtu {
    left_mtu: u16,
    right_mtu: u16,
    floor: u16,
    effective: u16,
    drain_deadline: Option<MonotonicTime>,
}

#[allow(dead_code)]
impl TransitPathMtu {
    #[must_use]
    pub fn new(left_mtu: u16, right_mtu: u16, floor: u16) -> Self {
        let effective = left_mtu.min(right_mtu);
        Self {
            left_mtu,
            right_mtu,
            floor,
            effective,
            drain_deadline: None,
        }
    }

    #[must_use]
    pub const fn left_mtu(&self) -> u16 {
        self.left_mtu
    }

    #[must_use]
    pub const fn right_mtu(&self) -> u16 {
        self.right_mtu
    }

    #[must_use]
    pub const fn effective(&self) -> u16 {
        self.effective
    }

    #[must_use]
    pub const fn drain_deadline(&self) -> Option<MonotonicTime> {
        self.drain_deadline
    }

    fn evaluate(&mut self, now: MonotonicTime) -> TransitMtuEvent {
        let next = self.left_mtu.min(self.right_mtu);
        if next < self.floor {
            self.effective = next;
            let deadline = *self
                .drain_deadline
                .get_or_insert_with(|| now.saturating_add(MTU_REPORT_TIMEOUT));
            return TransitMtuEvent::FloorViolation {
                mtu: next,
                drain_deadline: deadline,
            };
        }
        if next != self.effective {
            self.effective = next;
            TransitMtuEvent::Updated(next)
        } else {
            TransitMtuEvent::Unchanged
        }
    }

    pub fn update_left(&mut self, mtu: u16, now: MonotonicTime) -> TransitMtuEvent {
        self.left_mtu = mtu;
        self.evaluate(now)
    }

    pub fn update_right(&mut self, mtu: u16, now: MonotonicTime) -> TransitMtuEvent {
        self.right_mtu = mtu;
        self.evaluate(now)
    }

    pub fn clamp_leg(&mut self, is_right: bool, bound: u16, now: MonotonicTime) -> TransitMtuEvent {
        if is_right {
            self.right_mtu = self.right_mtu.min(bound);
        } else {
            self.left_mtu = self.left_mtu.min(bound);
        }
        self.evaluate(now)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use core::time::Duration;

    use super::*;

    #[test]
    fn advance_epoch_handles_wraparound_and_half_space() {
        assert!(!advance_epoch(0, 0));
        assert!(advance_epoch(0, 1));
        assert!(advance_epoch(0, (1u32 << 31) - 1));
        assert!(!advance_epoch(0, 1u32 << 31));
        assert!(!advance_epoch(10, 9));

        // Wrap across u32::MAX -> 0 -> 1.
        assert!(advance_epoch(u32::MAX, 0));
        assert!(advance_epoch(u32::MAX - 5, 2));
        assert!(!advance_epoch(2, u32::MAX - 5));
    }

    #[test]
    fn mtu_reporter_retries_ack_and_reassert_throttling() {
        let mut rep = MtuReporter::with_initial(1232);
        let t0 = MonotonicTime::ZERO;

        // Same MTU suppressed.
        assert_eq!(rep.publish(1232, t0), None);

        // Lower MTU bumps epoch to 1 and schedules 5 retries at [150, 300, 600, 1200, 2400] ms.
        assert_eq!(rep.publish(1200, t0), Some((1, 1200)));

        let mut t = t0;
        for expected_delay in MTU_RETRY_DELAYS {
            let dl = rep.next_deadline().unwrap();
            assert_eq!(dl, t.saturating_add(expected_delay));
            t = dl;
            assert_eq!(rep.poll_retry(t), Some((1, 1200)));
        }
        // Exhausted all 5 retries -> pending cleared.
        assert!(!rep.is_pending());

        // Reassert blocked for < 200 ms, succeeds at >= 200 ms.
        assert_eq!(
            rep.reassert(1200, t.saturating_add(Duration::from_millis(199))),
            None
        );
        let t_re = t.saturating_add(Duration::from_millis(200));
        assert_eq!(rep.reassert(1200, t_re), Some((2, 1200)));

        // Stale ACK ignored; matching ACK clears pending.
        assert!(!rep.on_ack(1));
        assert!(rep.is_pending());
        assert!(rep.on_ack(2));
        assert!(!rep.is_pending());
    }

    #[test]
    fn origin_dest_transit_mtu_calculators_and_drain_window() {
        let mut orig = OriginPathMtu::new(vec![1400, 1300, 1250], 1152);
        assert_eq!(orig.current_mtu(), 1250);
        assert_eq!(orig.max_payload(), 1220);

        // Hop 0 drops to 1200 (epoch 1) -> Changed(1200).
        assert_eq!(orig.on_hop_mtu(0, 1, 1200), MtuChange::Changed(1200));
        // Stale epoch 1 ignored.
        assert_eq!(orig.on_hop_mtu(0, 1, 1180), MtuChange::Unchanged);
        // Hop 0 drops below floor (epoch 2) -> BelowFloor(1100).
        assert_eq!(orig.on_hop_mtu(0, 2, 1100), MtuChange::BelowFloor(1100));

        // Transit floor violation enters 5 s drain window.
        let mut tr = TransitPathMtu::new(1300, 1250, 1152);
        let t0 = MonotonicTime::from_nanos(1_000_000_000);
        assert_eq!(
            tr.update_right(1100, t0),
            TransitMtuEvent::FloorViolation {
                mtu: 1100,
                drain_deadline: t0.saturating_add(Duration::from_secs(5)),
            }
        );
    }
}
