//! Cache-line-aligned atomic `LeaseHandle`, lock-free `TrafficGateCache`, and live `SessionAuth` updates (Spec §7.3).

use core::future::{Future, poll_fn};
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use event_listener::{Event, EventListener};

use crate::error::CoreError;
use crate::runtime::sync::Watch;
use crate::runtime::{Clock, MonotonicTime};
use crate::seam::auth::{AuthExtensions, Lease, SessionAuth, SessionGuard, TrafficGate};
use crate::types::PublicKey;

/// Cache-line-aligned lock-free hot-path state shared between data plane and control plane.
#[repr(align(64))]
struct HotLeaseState {
    expires_at_ns: AtomicU64,
    revoked: AtomicBool,
    gate_gen: AtomicU64,
}

struct SlowLeaseState {
    gate: Option<Arc<dyn TrafficGate>>,
    guards: Vec<Box<dyn SessionGuard>>,
    revoked_reason: Option<CoreError>,
}

/// Active session/circuit lease handle with lock-free hot-path validity checks,
/// cached `TrafficGate` swapping, preserved RAII `SessionGuard`s, and live `SessionAuth` updates.
pub struct LeaseHandle {
    hot: HotLeaseState,
    peer: PublicKey,
    clock: Arc<dyn Clock>,
    ext_watch: Watch<AuthExtensions>,
    state_event: Event,
    slow: Mutex<SlowLeaseState>,
}

#[allow(dead_code)]
impl LeaseHandle {
    /// Creates an active `LeaseHandle` from an authorized [`Lease`] (clamped to `max_ttl`).
    pub fn new(
        peer: PublicKey,
        lease: Lease,
        max_ttl: Duration,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>, CoreError> {
        if lease.ttl.as_millis() == 0 || lease.ttl > max_ttl {
            return Err(CoreError::Denied);
        }
        let expires_at = clock.now().saturating_add(lease.ttl);
        let (ext_watch, _rx) = Watch::new(lease.extensions);
        Ok(Arc::new(Self {
            hot: HotLeaseState {
                expires_at_ns: AtomicU64::new(expires_at.as_nanos()),
                revoked: AtomicBool::new(false),
                gate_gen: AtomicU64::new(1),
            },
            peer,
            clock,
            ext_watch,
            state_event: Event::new(),
            slow: Mutex::new(SlowLeaseState {
                gate: lease.gate,
                guards: lease.guards,
                revoked_reason: None,
            }),
        }))
    }

    /// Creates a lightweight TTL-only `LeaseHandle` (used by Originator to track Destination TTL).
    pub fn from_ttl(
        peer: PublicKey,
        ttl: Duration,
        max_ttl: Duration,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>, CoreError> {
        Self::new(peer, Lease::new(ttl), max_ttl, clock)
    }

    /// Lock-free hot-path check returning `true` iff unrevoked and strictly before expiration.
    #[inline]
    #[must_use]
    pub fn is_active(&self) -> bool {
        if self.hot.revoked.load(Ordering::Acquire) {
            return false;
        }
        self.clock.now().as_nanos() < self.hot.expires_at_ns.load(Ordering::Acquire)
    }

    /// Returns the remaining lifetime, or the terminal revocation/expiration error.
    pub fn remaining(&self) -> Result<Duration, CoreError> {
        if self.hot.revoked.load(Ordering::Acquire) {
            let slow = self
                .slow
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            return Err(slow
                .revoked_reason
                .clone()
                .unwrap_or(CoreError::Revoked));
        }
        let now_ns = self.clock.now().as_nanos();
        let exp_ns = self.hot.expires_at_ns.load(Ordering::Acquire);
        if now_ns >= exp_ns {
            Err(CoreError::Expired)
        } else {
            Ok(Duration::from_nanos(exp_ns - now_ns))
        }
    }

    /// Returns a live [`SessionAuth`] handle whose claims update atomically on renewal.
    #[must_use]
    pub fn session_auth(&self) -> SessionAuth {
        SessionAuth::from_watch(self.peer, self.ext_watch.subscribe())
    }

    /// Atomically applies a renewed [`Lease`] in place (Spec §7.3):
    /// - Validates `1 ms <= ttl <= max_ttl` and active status.
    /// - Swaps `TrafficGate` and increments `gate_gen`.
    /// - Preserves all existing `SessionGuard`s while appending any newly returned guards.
    /// - Publishes updated `AuthExtensions` to all [`SessionAuth`] handles.
    /// - Extends `expires_at` and wakes [`Self::cancelled`] sleepers to re-arm timers.
    pub fn renew_lease_with_max_ttl(
        &self,
        lease: Lease,
        max_ttl: Duration,
    ) -> Result<Duration, CoreError> {
        if lease.ttl.as_millis() == 0 || lease.ttl > max_ttl {
            return Err(CoreError::Denied);
        }

        let mut slow = self
            .slow
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.hot.revoked.load(Ordering::Acquire) {
            return Err(slow
                .revoked_reason
                .clone()
                .unwrap_or(CoreError::Revoked));
        }
        let now = self.clock.now();
        if now.as_nanos() >= self.hot.expires_at_ns.load(Ordering::Acquire) {
            return Err(CoreError::Expired);
        }

        slow.gate = lease.gate;
        slow.guards.extend(lease.guards);
        let new_expires = now.saturating_add(lease.ttl);
        self.hot
            .expires_at_ns
            .store(new_expires.as_nanos(), Ordering::Release);
        self.hot.gate_gen.fetch_add(1, Ordering::Release);
        drop(slow);

        self.ext_watch.send(lease.extensions);
        self.state_event.notify(usize::MAX);
        Ok(lease.ttl)
    }

    /// Extends only the lease TTL (used by Originator on receiving `RENEW_OK`).
    pub fn renew_ttl_only(&self, ttl: Duration, max_ttl: Duration) -> Result<Duration, CoreError> {
        if ttl.as_millis() == 0 || ttl > max_ttl {
            return Err(CoreError::Denied);
        }
        let slow = self
            .slow
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.hot.revoked.load(Ordering::Acquire) {
            return Err(slow
                .revoked_reason
                .clone()
                .unwrap_or(CoreError::Revoked));
        }
        let now = self.clock.now();
        if now.as_nanos() >= self.hot.expires_at_ns.load(Ordering::Acquire) {
            return Err(CoreError::Expired);
        }
        let new_expires = now.saturating_add(ttl);
        self.hot
            .expires_at_ns
            .store(new_expires.as_nanos(), Ordering::Release);
        drop(slow);

        self.state_event.notify(usize::MAX);
        Ok(ttl)
    }

    /// Immediately revokes this lease with `reason` (idempotent; preserves the first reason).
    pub fn revoke(&self, reason: CoreError) {
        {
            let mut slow = self
                .slow
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if slow.revoked_reason.is_none() {
                slow.revoked_reason = Some(reason);
            }
        }
        self.hot.revoked.store(true, Ordering::Release);
        self.state_event.notify(usize::MAX);
    }

    /// Resolves with the terminal [`CoreError`] as soon as the lease is revoked or expires.
    ///
    /// Automatically re-arms its timer whenever [`Self::renew_lease_with_max_ttl`] extends TTL.
    pub async fn cancelled(&self) -> CoreError {
        loop {
            if let Err(err) = self.remaining() {
                return err;
            }
            let deadline = MonotonicTime::from_nanos(self.hot.expires_at_ns.load(Ordering::Acquire));
            let mut sleep_fut = self.clock.sleep_until(deadline);
            let mut listener: Option<EventListener> = None;

            poll_fn(|cx: &mut Context<'_>| {
                if self.remaining().is_err() {
                    return Poll::Ready(());
                }
                if sleep_fut.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(());
                }
                let l = listener.get_or_insert_with(|| self.state_event.listen());
                if self.remaining().is_err()
                    || self.hot.expires_at_ns.load(Ordering::Acquire) != deadline.as_nanos()
                {
                    return Poll::Ready(());
                }
                Pin::new(l).poll(cx)
            })
            .await;
        }
    }
}

/// Per-task lock-free cache of a [`LeaseHandle`]'s active [`TrafficGate`] (Spec §7.3).
///
/// Hot-path lookups pay a single relaxed/acquire atomic load between lease renewals.
#[derive(Default)]
pub struct TrafficGateCache {
    seen_gen: u64,
    gate: Option<Arc<dyn TrafficGate>>,
}

#[allow(dead_code)]
impl TrafficGateCache {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            seen_gen: 0,
            gate: None,
        }
    }

    /// Returns the currently active `TrafficGate`, refreshing from `handle` only when `gate_gen` changes.
    #[inline]
    pub fn get(&mut self, handle: &LeaseHandle) -> Option<&Arc<dyn TrafficGate>> {
        let current_gen = handle.hot.gate_gen.load(Ordering::Acquire);
        if current_gen != self.seen_gen {
            let slow = handle
                .slow
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.gate = slow.gate.clone();
            self.seen_gen = current_gen;
        }
        self.gate.as_ref()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;
    use crate::runtime::TaskSpawner;
    use crate::seam::auth::{DatagramAction, StreamAction};
    use crate::testing::{TestSpawner, VirtualClock};
    use crate::types::Direction;

    struct DropCounter(Arc<AtomicUsize>);
    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct TagGate(usize);
    impl TrafficGate for TagGate {
        fn check_datagram(&self, _dir: Direction, _bytes: usize) -> DatagramAction {
            if self.0 == 1 {
                DatagramAction::Allow
            } else {
                DatagramAction::Drop
            }
        }
        fn charge_stream(&self, _dir: Direction, _bytes: usize) -> StreamAction {
            StreamAction::Allow
        }
    }

    #[test]
    fn lease_renewal_preserves_guards_swaps_gate_updates_claims_and_extends_cancelled() {
        let clock = VirtualClock::new();
        let spawner = TestSpawner::new();
        let peer = PublicKey::from_bytes([1u8; 32]);

        let dropped = Arc::new(AtomicUsize::new(0));
        let initial = Lease::new(Duration::from_secs(10))
            .with_gate(Arc::new(TagGate(1)))
            .with_guard(DropCounter(Arc::clone(&dropped)))
            .with_context("role-v1".to_string());

        let handle = LeaseHandle::new(peer, initial, Duration::from_secs(60), clock.clone()).unwrap();
        let mut auth = handle.session_auth();
        assert_eq!(auth.context::<String>().as_deref().map(String::as_str), Some("role-v1"));

        let mut cache = TrafficGateCache::new();
        assert_eq!(
            cache.get(&handle).unwrap().check_datagram(Direction::Ingress, 100),
            DatagramAction::Allow
        );

        // Spawn watcher awaiting cancelled().
        let h2 = Arc::clone(&handle);
        let (done_tx, done_rx) = Watch::new(None::<CoreError>);
        spawner.spawn(Box::pin(async move {
            done_tx.send(Some(h2.cancelled().await));
        }));
        spawner.drive_until_idle();

        // Advance to t = 8s and renew for 20s (expires at t = 28s).
        clock.advance(Duration::from_secs(8));
        spawner.drive_until_idle();
        assert_eq!(done_rx.borrow_cloned(), None);

        let renewed = Lease::new(Duration::from_secs(20))
            .with_gate(Arc::new(TagGate(2)))
            .with_guard(DropCounter(Arc::clone(&dropped)))
            .with_context("role-v2".to_string());
        handle.renew_lease_with_max_ttl(renewed, Duration::from_secs(60)).unwrap();

        // Initial guard MUST still be alive!
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        // Gate cache picks up new TagGate(2) via gate_gen bump.
        assert_eq!(
            cache.get(&handle).unwrap().check_datagram(Direction::Ingress, 100),
            DatagramAction::Drop
        );
        // Live SessionAuth reflects updated claim and wakes changed().
        assert_eq!(spawner.try_block_on(auth.changed()), Some(true));
        assert_eq!(auth.context::<String>().as_deref().map(String::as_str), Some("role-v2"));

        // Past original 10s deadline (at t = 15s), still active!
        clock.advance(Duration::from_secs(7));
        spawner.drive_until_idle();
        assert!(handle.is_active());
        assert_eq!(done_rx.borrow_cloned(), None);

        // Revoke -> cancelled() resolves immediately with Revoked.
        handle.revoke(CoreError::Revoked);
        spawner.drive_until_idle();
        assert_eq!(done_rx.borrow_cloned(), Some(CoreError::Revoked));
        assert!(!handle.is_active());

        // Dropping final handle drops BOTH guards (initial + renewal).
        drop(handle);
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
    }
}
