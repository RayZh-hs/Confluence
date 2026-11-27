//! Datagram link-local `SETUP_FWD` fragmentation sender and per-port reassembler (Spec §5.6).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use rand_core::{OsRng, RngCore};

use crate::constants::{
    CHALLENGE_LEN, FRAG_HEADER, FRAG_MAX_ACTIVE, FRAG_MAX_COMPLETED, FRAG_RETRY_DELAYS,
    FWD_HEADER, MAX_FRAGS, MAX_SEGMENT, MAX_SETUP, SETUP_TIMEOUT,
};
use crate::error::CoreError;
use crate::packet::PacketBuf;
use crate::runtime::MonotonicTime;
use crate::types::{Cid, Plane, ScopeKid};
use crate::wire::setup::{
    ForwardHeader, LeadingSegment, SetupFragAck, SetupFragHeader,
};

/// Sender-side prepared outbound datagram setup flight (either single packet or `2..=8` fragments).
#[allow(dead_code)]
pub enum PreparedFlight {
    /// Fits within `link_mtu`: transmit as a single plain `SETUP_FWD`.
    Single(PacketBuf),
    /// Exceeds `link_mtu`: transmit fragment burst and retransmit at `[150, 300, 600]` ms until ACK.
    Fragmented(FragmentBurst),
}

/// Pure synchronous sender state machine for a fragmented datagram `SETUP_FWD` flight.
#[allow(dead_code)]
pub struct FragmentBurst {
    upstream_cid: Cid,
    message_id: u64,
    frames: Vec<PacketBuf>,
    retries_sent: usize,
    acked: bool,
}

#[allow(dead_code)]
impl FragmentBurst {
    /// Prepares a single or fragmented flight using a CSPRNG `message_id`.
    pub fn prepare(wire: &[u8], link_mtu: u16, upstream_cid: Cid) -> Result<PreparedFlight, CoreError> {
        Self::prepare_with_id(wire, link_mtu, upstream_cid, OsRng.next_u64())
    }

    /// Prepares a single or fragmented flight with an explicit `message_id` (deterministic testing).
    pub fn prepare_with_id(
        wire: &[u8],
        link_mtu: u16,
        upstream_cid: Cid,
        message_id: u64,
    ) -> Result<PreparedFlight, CoreError> {
        if wire.len() <= usize::from(link_mtu) {
            return Ok(PreparedFlight::Single(PacketBuf::from_payload(wire)));
        }
        let stride = usize::from(link_mtu).saturating_sub(FRAG_HEADER);
        if stride == 0 || wire.len() > stride * MAX_FRAGS {
            return Err(CoreError::MtuTooSmall(link_mtu));
        }
        let count_usize = wire.len().div_ceil(stride);
        let count = u8::try_from(count_usize).map_err(|_| CoreError::MtuTooSmall(link_mtu))?;
        let mut frames = Vec::with_capacity(count_usize);
        for (idx, chunk) in wire.chunks(stride).enumerate() {
            let index = u8::try_from(idx).map_err(|_| CoreError::MtuTooSmall(link_mtu))?;
            let hdr = SetupFragHeader {
                index,
                count,
                upstream_cid,
                message_id,
            };
            frames.push(hdr.encode_packet(chunk));
        }
        Ok(PreparedFlight::Fragmented(Self {
            upstream_cid,
            message_id,
            frames,
            retries_sent: 0,
            acked: false,
        }))
    }

    #[must_use]
    pub const fn message_id(&self) -> u64 {
        self.message_id
    }

    #[must_use]
    pub const fn upstream_cid(&self) -> Cid {
        self.upstream_cid
    }

    /// Returns all `2..=8` fragment packets in this burst.
    #[must_use]
    pub fn frames(&self) -> &[PacketBuf] {
        &self.frames
    }

    /// Marks the burst acknowledged if `ack` matches `(upstream_cid, message_id)`.
    pub fn on_ack(&mut self, ack: &SetupFragAck) -> bool {
        if ack.upstream_cid == self.upstream_cid && ack.message_id == self.message_id {
            self.acked = true;
            true
        } else {
            false
        }
    }

    #[must_use]
    pub const fn is_acked(&self) -> bool {
        self.acked
    }

    /// Returns the next scheduled burst retry deadline (after initial TX at `last_sent`), or
    /// `None` if already acknowledged or all 3 retries (`[150, 300, 600]` ms) have been sent.
    #[must_use]
    pub fn next_retry_deadline(&self, last_sent: MonotonicTime) -> Option<MonotonicTime> {
        if self.acked {
            return None;
        }
        FRAG_RETRY_DELAYS
            .get(self.retries_sent)
            .map(|d| last_sent.saturating_add(*d))
    }

    /// Advances the retry counter when a retransmission burst is emitted.
    pub fn mark_retry_sent(&mut self) {
        if self.retries_sent < FRAG_RETRY_DELAYS.len() {
            self.retries_sent += 1;
        }
    }
}

/// Unique key identifying one fragmented setup flight on a `DatagramPort`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FragmentKey {
    pub upstream_cid: Cid,
    pub message_id: u64,
}

/// Caller verdict returned when validating fragment 0 before allocating reassembly memory.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum OpeningVerdict {
    /// Scope accepted `ScopeKid` + `mac1` (and `mac2` if under load).
    Verified,
    /// Scope is under load and requires a cookie challenge.
    Challenge([u8; CHALLENGE_LEN]),
    /// Unknown `ScopeKid` or invalid `mac1` (caller increments `mac1_drops_total`).
    DropMac1,
    /// Matching scope is shutting down / not accepting.
    NotAccepting,
}

/// Outcome of feeding one `SETUP_FRAG` packet into [`FragmentReassembler`].
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum FeedOutcome {
    /// Fragment ignored (invalid, duplicate, unknown non-zero fragment, or capacity full).
    Ignore,
    /// Duplicate fragment 0 for an already-authenticated flight: immediately re-send ACK.
    ReAck(SetupFragAck),
    /// Fragment 0 failed `mac1`: caller increments `mac1_drops_total` and discards.
    DropMac1,
    /// Fragment 0 hit an under-load scope: emit `SETUP_COOKIE` without allocating reassembly memory.
    Challenge {
        upstream_cid: Cid,
        challenge: [u8; CHALLENGE_LEN],
    },
    /// Valid fragment stored; waiting for remaining fragments.
    NeedMore,
    /// Final fragment completed reassembly; hand `(wire, key)` to setup admission with a [`FragmentReceipt`].
    Complete { wire: Vec<u8>, key: FragmentKey },
}

struct ActiveAssembly {
    count: u8,
    stride: usize,
    total: usize,
    received_mask: u8,
    expires: MonotonicTime,
    /// `Some(buf)` while gathering fragments; `None` once detached for authentication
    /// (so the reserved slot is NOT expired mid-authentication per Spec §5.6 Rule 2).
    buf: Option<Vec<u8>>,
}

/// Per-`DatagramPort` bounded fragment reassembler enforcing pre-allocation fragment-0
/// validation, `16` active / `MAX_SETUP` aggregate byte / `32` completed caps (Spec §5.6).
pub struct FragmentReassembler {
    active: HashMap<FragmentKey, ActiveAssembly>,
    allocated_bytes: usize,
    completed: VecDeque<(FragmentKey, MonotonicTime)>,
}

impl Default for FragmentReassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl FragmentReassembler {
    #[must_use]
    pub fn new() -> Self {
        Self {
            active: HashMap::new(),
            allocated_bytes: 0,
            completed: VecDeque::new(),
        }
    }

    /// Expires stale active buffers (`buf.is_some() && expires <= now`) and completed receipts.
    pub fn expire(&mut self, now: MonotonicTime) {
        let mut freed = 0usize;
        self.active.retain(|_, entry| {
            if entry.buf.is_some() && entry.expires <= now {
                freed = freed.saturating_add(entry.total);
                false
            } else {
                true
            }
        });
        self.allocated_bytes = self.allocated_bytes.saturating_sub(freed);

        while self
            .completed
            .front()
            .is_some_and(|&(_, exp)| exp <= now)
        {
            self.completed.pop_front();
        }
    }

    /// Processes one inbound `SETUP_FRAG` wire packet.
    ///
    /// Fragment 0 is validated completely on `&[u8]` slices via `verify_opening` BEFORE
    /// allocating any reassembly memory.
    pub fn feed(
        &mut self,
        packet: &[u8],
        now: MonotonicTime,
        verify_opening: impl FnOnce(ScopeKid, &[u8], bool) -> OpeningVerdict,
    ) -> FeedOutcome {
        let Ok((hdr, payload)) = SetupFragHeader::parse(packet) else {
            return FeedOutcome::Ignore;
        };
        self.expire(now);

        let key = FragmentKey {
            upstream_cid: hdr.upstream_cid,
            message_id: hdr.message_id,
        };

        // Rule 3: completed cache hit -> re-ACK fragment 0 without re-running setup.
        if self.completed.iter().any(|&(k, _)| k == key) {
            return if hdr.index == 0 {
                FeedOutcome::ReAck(SetupFragAck {
                    upstream_cid: hdr.upstream_cid,
                    message_id: hdr.message_id,
                })
            } else {
                FeedOutcome::Ignore
            };
        }

        // Rule 4: existing active assembly.
        if let Some(entry) = self.active.get_mut(&key) {
            let Some(buf) = entry.buf.as_mut() else {
                // Currently authenticating; ignore duplicate fragments until acknowledged/dropped.
                return FeedOutcome::Ignore;
            };
            let bit = 1u8 << hdr.index;
            if hdr.count != entry.count || (entry.received_mask & bit) != 0 {
                return FeedOutcome::Ignore;
            }
            let offset = entry.stride.saturating_mul(usize::from(hdr.index));
            let end = offset.saturating_add(entry.stride).min(entry.total);
            if offset >= entry.total || payload.len() != end - offset {
                return FeedOutcome::Ignore;
            }
            buf[offset..end].copy_from_slice(payload);
            entry.received_mask |= bit;

            // Compute mask for `count in 2..=8` without u8 shift overflow.
            let full_mask = ((1u16 << u16::from(entry.count)) - 1) as u8;
            if entry.received_mask == full_mask {
                if let Some(wire) = entry.buf.take() {
                    // Keep `entry.total` charged against `allocated_bytes` (`MAX_SETUP`) while
                    // the detached flight's `FragmentReceipt` is outstanding during authentication;
                    // `acknowledge` or `abandon` releases `removed.total` exactly once.
                    return FeedOutcome::Complete { wire, key };
                }
            }
            return FeedOutcome::NeedMore;
        }

        // Rule 5: no active assembly -> only fragment 0 may open a new slot.
        if hdr.index != 0 {
            return FeedOutcome::Ignore;
        }
        let Ok(fwd) = ForwardHeader::parse(payload) else {
            return FeedOutcome::Ignore;
        };
        if fwd.upstream != hdr.upstream_cid {
            return FeedOutcome::Ignore;
        }
        let Ok(seg) = LeadingSegment::parse_leading(&payload[FWD_HEADER..]) else {
            return FeedOutcome::Ignore;
        };
        if seg.prefix.plane != Plane::Datagram || seg.encrypted.len() > MAX_SEGMENT {
            return FeedOutcome::Ignore;
        }
        let total = FWD_HEADER + seg.prefix.encoded_total_len();
        if total <= payload.len() + FRAG_HEADER
            || total.div_ceil(payload.len()) != usize::from(hdr.count)
        {
            return FeedOutcome::Ignore;
        }

        match verify_opening(seg.scope_kid(), seg.encrypted, seg.prefix.has_mac2) {
            OpeningVerdict::DropMac1 => return FeedOutcome::DropMac1,
            OpeningVerdict::Challenge(challenge) => {
                return FeedOutcome::Challenge {
                    upstream_cid: hdr.upstream_cid,
                    challenge,
                };
            }
            OpeningVerdict::NotAccepting => return FeedOutcome::Ignore,
            OpeningVerdict::Verified => {}
        }

        // Enforce 16 active / MAX_SETUP aggregate byte caps.
        if self.active.len() >= FRAG_MAX_ACTIVE
            || total.saturating_add(self.allocated_bytes) > MAX_SETUP
        {
            return FeedOutcome::Ignore;
        }

        let mut buf = vec![0u8; total];
        buf[..payload.len()].copy_from_slice(payload);
        self.allocated_bytes += total;
        self.active.insert(
            key,
            ActiveAssembly {
                count: hdr.count,
                stride: payload.len(),
                total,
                received_mask: 1,
                expires: now.saturating_add(SETUP_TIMEOUT),
                buf: Some(buf),
            },
        );
        FeedOutcome::NeedMore
    }

    /// Commits a post-authentication fragment receipt: frees active slot and its reserved byte
    /// budget exactly once, inserts into the bounded 32-entry FIFO `completed` cache, and returns
    /// the `SETUP_FRAG_ACK` to send.
    pub fn acknowledge(&mut self, key: FragmentKey, now: MonotonicTime) -> SetupFragAck {
        if let Some(removed) = self.active.remove(&key) {
            self.allocated_bytes = self.allocated_bytes.saturating_sub(removed.total);
        }
        self.expire(now);
        if self.completed.len() >= FRAG_MAX_COMPLETED {
            self.completed.pop_front();
        }
        self.completed
            .push_back((key, now.saturating_add(SETUP_TIMEOUT)));
        SetupFragAck {
            upstream_cid: key.upstream_cid,
            message_id: key.message_id,
        }
    }

    /// Abandons a reassembled flight that failed cookie re-check or `Responder::authenticate`:
    /// removes the reserved active slot and releases its byte budget exactly once WITHOUT adding
    /// to `completed` and WITHOUT emitting ACK.
    pub fn abandon(&mut self, key: FragmentKey) {
        if let Some(removed) = self.active.remove(&key) {
            self.allocated_bytes = self.allocated_bytes.saturating_sub(removed.total);
        }
    }

    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    #[must_use]
    pub fn allocated_bytes(&self) -> usize {
        self.allocated_bytes
    }

    #[must_use]
    pub fn completed_count(&self) -> usize {
        self.completed.len()
    }
}

/// RAII receipt guarding a reassembled fragmented setup flight during authentication (Spec §5.6 Rule 6).
///
/// Calling [`Self::acknowledge`] strictly after `CookieProtector::verify_segment` and
/// `Responder::authenticate` succeed transitions the flight into the `completed` cache and yields
/// the `SETUP_FRAG_ACK`. Dropping without calling `acknowledge` automatically abandons the active
/// slot without sending `SETUP_FRAG_ACK`.
#[allow(dead_code)]
pub struct FragmentReceipt {
    reassembler: Arc<Mutex<FragmentReassembler>>,
    key: Option<FragmentKey>,
}

#[allow(dead_code)]
impl FragmentReceipt {
    #[must_use]
    pub fn new(reassembler: Arc<Mutex<FragmentReassembler>>, key: FragmentKey) -> Self {
        Self {
            reassembler,
            key: Some(key),
        }
    }

    /// Acknowledges post-authentication receipt and returns the `SETUP_FRAG_ACK` frame to transmit.
    pub fn acknowledge(mut self, now: MonotonicTime) -> Option<SetupFragAck> {
        let key = self.key.take()?;
        let mut guard = self
            .reassembler
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Some(guard.acknowledge(key, now))
    }
}

impl Drop for FragmentReceipt {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            let mut guard = self
                .reassembler
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.abandon(key);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use core::time::Duration;

    use super::*;
    use crate::crypto::identity::ScopeKeypair;
    use crate::protocol::setup::{HopFlightInput, SetupFlightBuilder, SetupFlightParams};

    fn build_large_flight(hop_count: usize, cid: Cid) -> (ScopeKeypair, Vec<u8>) {
        let origin = ScopeKeypair::generate();
        let dest = ScopeKeypair::generate();
        let hop_kps: Vec<ScopeKeypair> = (0..hop_count).map(|_| ScopeKeypair::generate()).collect();
        let hops: Vec<HopFlightInput<'_>> = hop_kps
            .iter()
            .map(|kp| HopFlightInput {
                peer: kp.public_key(),
                target: "transit-hop-name-with-padding-for-size",
                credential: &[0xAB; 128],
            })
            .collect();
        let cookies = HashMap::new();
        let (_st, wire) = SetupFlightBuilder::build(&SetupFlightParams {
            local: &origin,
            plane: Plane::Datagram,
            origin_local_mtu: 1200,
            min_mtu: 1152,
            upstream_cid: cid,
            destination: dest.public_key(),
            endpoint: "endpoint-name",
            dest_credential: &[0xCD; 128],
            hops: &hops,
            cookies: &cookies,
            wall_time_ms: 1_700_000_000_000,
        })
        .unwrap();
        let first_kp = hop_kps.into_iter().next().unwrap_or(dest);
        (first_kp, wire)
    }

    #[test]
    fn burst_retries_and_reassembly_with_duplicate_frag0_reack() {
        let cid = Cid::from_parts(1, 7).unwrap();
        // 5 hops with 128B credentials > 1200 B MTU -> fragments cleanly into 2..=8 chunks.
        let (first_kp, wire) = build_large_flight(5, cid);
        assert!(wire.len() > 1200);

        let mut burst = match FragmentBurst::prepare_with_id(&wire, 1200, cid, 42).unwrap() {
            PreparedFlight::Fragmented(b) => b,
            PreparedFlight::Single(_) => panic!("expected fragmented flight"),
        };
        assert!((2..=8).contains(&burst.frames().len()));

        // Verify [150, 300, 600] ms retry schedule.
        let t0 = MonotonicTime::ZERO;
        assert_eq!(
            burst.next_retry_deadline(t0),
            Some(t0.saturating_add(Duration::from_millis(150)))
        );
        burst.mark_retry_sent();
        assert_eq!(
            burst.next_retry_deadline(t0),
            Some(t0.saturating_add(Duration::from_millis(300)))
        );
        burst.mark_retry_sent();
        assert_eq!(
            burst.next_retry_deadline(t0),
            Some(t0.saturating_add(Duration::from_millis(600)))
        );
        burst.mark_retry_sent();
        assert_eq!(burst.next_retry_deadline(t0), None);

        // Reassemble out-of-order (non-0 before 0 ignored; 0 opens; last then middle completes).
        let reasm = Arc::new(Mutex::new(FragmentReassembler::new()));
        let frames: Vec<PacketBuf> = burst.frames().to_vec();
        assert_eq!(
            reasm.lock().unwrap().feed(frames[1].payload(), t0, |_, _, _| OpeningVerdict::Verified),
            FeedOutcome::Ignore
        );
        assert_eq!(reasm.lock().unwrap().active_count(), 0);

        // Invalid mac1 on frag 0 allocates ZERO reassembly memory.
        assert_eq!(
            reasm.lock().unwrap().feed(frames[0].payload(), t0, |_, _, _| OpeningVerdict::DropMac1),
            FeedOutcome::DropMac1
        );
        assert_eq!(reasm.lock().unwrap().active_count(), 0);
        assert_eq!(reasm.lock().unwrap().allocated_bytes(), 0);

        // Valid frag 0 allocates reassembly buffer.
        assert_eq!(
            reasm.lock().unwrap().feed(frames[0].payload(), t0, |kid, seg, mac2| {
                if kid == first_kp.scope_kid() && first_kp.verify_segment_mac1(seg, mac2).is_ok() {
                    OpeningVerdict::Verified
                } else {
                    OpeningVerdict::DropMac1
                }
            }),
            FeedOutcome::NeedMore
        );
        assert_eq!(reasm.lock().unwrap().active_count(), 1);
        assert_eq!(reasm.lock().unwrap().allocated_bytes(), wire.len());

        // Feed remaining fragments.
        let mut completed = None;
        for f in &frames[1..] {
            let res = reasm
                .lock()
                .unwrap()
                .feed(f.payload(), t0, |_, _, _| OpeningVerdict::Verified);
            if let FeedOutcome::Complete { wire: out, key } = res {
                completed = Some((out, key));
            }
        }
        let (reassembled, key) = completed.unwrap();
        assert_eq!(reassembled, wire);
        // Active slot and byte budget remain reserved while authenticating and do NOT expire mid-auth!
        reasm
            .lock()
            .unwrap()
            .expire(t0.saturating_add(Duration::from_secs(10)));
        assert_eq!(reasm.lock().unwrap().active_count(), 1);
        assert_eq!(reasm.lock().unwrap().allocated_bytes(), wire.len());

        // Acknowledge receipt -> emits SETUP_FRAG_ACK, releases byte budget, and moves into completed cache.
        let receipt = FragmentReceipt::new(Arc::clone(&reasm), key);
        let ack = receipt.acknowledge(t0).unwrap();
        assert!(burst.on_ack(&ack));
        assert_eq!(reasm.lock().unwrap().active_count(), 0);
        assert_eq!(reasm.lock().unwrap().allocated_bytes(), 0);
        assert_eq!(reasm.lock().unwrap().completed_count(), 1);

        // Duplicate frag 0 triggers ReAck without re-running setup.
        assert_eq!(
            reasm.lock().unwrap().feed(frames[0].payload(), t0, |_, _, _| panic!("must not verify")),
            FeedOutcome::ReAck(ack)
        );
        // Duplicate non-0 fragment is ignored.
        assert_eq!(
            reasm.lock().unwrap().feed(frames[1].payload(), t0, |_, _, _| panic!("must not verify")),
            FeedOutcome::Ignore
        );
    }

    #[test]
    fn dropping_unacknowledged_receipt_abandons_without_completing() {
        let cid = Cid::from_parts(1, 9).unwrap();
        let (_kp, wire) = build_large_flight(5, cid);
        let burst = match FragmentBurst::prepare_with_id(&wire, 1200, cid, 99).unwrap() {
            PreparedFlight::Fragmented(b) => b,
            PreparedFlight::Single(_) => panic!("expected fragmented"),
        };
        let reasm = Arc::new(Mutex::new(FragmentReassembler::new()));
        let t0 = MonotonicTime::ZERO;
        let mut key = None;
        for f in burst.frames() {
            if let FeedOutcome::Complete { key: k, .. } =
                reasm.lock().unwrap().feed(f.payload(), t0, |_, _, _| OpeningVerdict::Verified)
            {
                key = Some(k);
            }
        }
        let receipt = FragmentReceipt::new(Arc::clone(&reasm), key.unwrap());
        assert_eq!(reasm.lock().unwrap().allocated_bytes(), wire.len());
        drop(receipt); // Auth failed or cookie re-challenged -> no ACK, not in completed, bytes released!
        assert_eq!(reasm.lock().unwrap().active_count(), 0);
        assert_eq!(reasm.lock().unwrap().allocated_bytes(), 0);
        assert_eq!(reasm.lock().unwrap().completed_count(), 0);
    }

    #[test]
    fn detached_authenticating_flights_stay_charged_against_max_setup() {
        // Exact L03-09 scenario: link MTU = 1232 (stride = 1216, max 8 frags = 9728 B).
        // Craft ~9000-byte flights that fit in 8 fragments so 15 flights exceed MAX_SETUP (131_086)
        // even though active_count (14) < FRAG_MAX_ACTIVE (16).
        let cid0 = Cid::from_parts(1, 1).unwrap();
        let (_kp, sample_wire) = build_large_flight(29, cid0);
        let stride = 1232usize - FRAG_HEADER;
        assert!(
            sample_wire.len() > 8_800 && sample_wire.len() <= stride * MAX_FRAGS,
            "expected ~9000B flight fitting in <= 8 fragments, got {} bytes",
            sample_wire.len()
        );
        let fit_count = MAX_SETUP / sample_wire.len();
        assert!(
            fit_count < FRAG_MAX_ACTIVE,
            "byte cap must bind before 16-active cap (fit_count = {fit_count}, wire = {})",
            sample_wire.len()
        );

        let reasm = Arc::new(Mutex::new(FragmentReassembler::new()));
        let t0 = MonotonicTime::ZERO;
        let mut receipts = Vec::with_capacity(fit_count);

        for i in 0..fit_count {
            let cid = Cid::from_parts(1, (i + 1) as u32).unwrap();
            let mut wire = sample_wire.clone();
            wire[4..8].copy_from_slice(&cid.raw().to_be_bytes());
            let burst = match FragmentBurst::prepare_with_id(&wire, 1232, cid, i as u64 + 1).unwrap() {
                PreparedFlight::Fragmented(b) => b,
                PreparedFlight::Single(_) => panic!("expected fragmented flight"),
            };
            let mut key = None;
            for f in burst.frames() {
                if let FeedOutcome::Complete { key: k, .. } =
                    reasm.lock().unwrap().feed(f.payload(), t0, |_, _, _| OpeningVerdict::Verified)
                {
                    key = Some(k);
                }
            }
            receipts.push(FragmentReceipt::new(Arc::clone(&reasm), key.unwrap()));
        }

        // All detached in-authentication flights MUST stay charged against MAX_SETUP!
        assert_eq!(reasm.lock().unwrap().active_count(), fit_count);
        assert_eq!(
            reasm.lock().unwrap().allocated_bytes(),
            fit_count * sample_wire.len()
        );

        // Next flight pushes total > MAX_SETUP -> MUST be rejected while receipts remain live!
        let extra_cid = Cid::from_parts(1, 99).unwrap();
        let mut extra_wire = sample_wire.clone();
        extra_wire[4..8].copy_from_slice(&extra_cid.raw().to_be_bytes());
        let extra_burst =
            match FragmentBurst::prepare_with_id(&extra_wire, 1232, extra_cid, 999).unwrap() {
                PreparedFlight::Fragmented(b) => b,
                PreparedFlight::Single(_) => panic!("expected fragmented flight"),
            };
        assert_eq!(
            reasm
                .lock()
                .unwrap()
                .feed(extra_burst.frames()[0].payload(), t0, |_, _, _| OpeningVerdict::Verified),
            FeedOutcome::Ignore
        );
        assert_eq!(reasm.lock().unwrap().active_count(), fit_count);

        // Acknowledging one receipt releases its exact byte budget once -> extra flight now admitted!
        let first = receipts.remove(0);
        assert!(first.acknowledge(t0).is_some());
        assert_eq!(
            reasm.lock().unwrap().allocated_bytes(),
            (fit_count - 1) * sample_wire.len()
        );
        assert_eq!(
            reasm
                .lock()
                .unwrap()
                .feed(extra_burst.frames()[0].payload(), t0, |_, _, _| OpeningVerdict::Verified),
            FeedOutcome::NeedMore
        );
        assert_eq!(
            reasm.lock().unwrap().allocated_bytes(),
            fit_count * sample_wire.len()
        );

        // Dropping all remaining receipts (abandon) + expiring the incomplete flight returns budget to exact 0.
        drop(receipts);
        reasm
            .lock()
            .unwrap()
            .expire(t0.saturating_add(SETUP_TIMEOUT));
        assert_eq!(reasm.lock().unwrap().active_count(), 0);
        assert_eq!(reasm.lock().unwrap().allocated_bytes(), 0);
    }
}
