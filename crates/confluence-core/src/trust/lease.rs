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
use crate::seam::auth::{Lease, LeaseSnapshot, SessionAuth, SessionGuard, TrafficGate};
use crate::types::PublicKey;

/// Cache-line-aligned lock-free hot-path state shared between data plane and control plane.
#[repr(align(64))]
struct HotLeaseState {
    expires_at_ns: AtomicU64,
    revoked: AtomicBool,
}

struct SlowLeaseState {
    guards: Vec<Box<dyn SessionGuard>>,
    revoked_reason: Option<CoreError>,
}

/// Active session/circuit lease handle with lock-free hot-path validity checks,
/// atomically committed `TrafficGate` + `AuthExtensions` + TTL renewal snapshots,
/// preserved RAII `SessionGuard`s, and live `SessionAuth` updates.
pub struct LeaseHandle {
    hot: HotLeaseState,
    peer: PublicKey,
    clock: Arc<dyn Clock>,
    snapshot_watch: Watch<Arc<LeaseSnapshot>>,
    state_event: Event,
    slow: Mutex<SlowLeaseState>,
}

impl Drop for LeaseHandle {
    fn drop(&mut self) {
        // Release any retained TrafficGate immediately on LeaseHandle drop without bumping
        // the watch version (preserving final AuthExtensions for surviving SessionAuth clones)
        // and strictly outside the Watch lock so re-entrant gate destructors cannot deadlock.
        let old_snap = self.snapshot_watch.replace_silent_if(|cur| {
            cur.gate.as_ref().map(|_| {
                Arc::new(LeaseSnapshot {
                    gate: None,
                    extensions: cur.extensions.clone(),
                })
            })
        });
        drop(old_snap);
    }
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
        let (snapshot_watch, _rx) = Watch::new(Arc::new(LeaseSnapshot {
            gate: lease.gate,
            extensions: lease.extensions,
        }));
        Ok(Arc::new(Self {
            hot: HotLeaseState {
                expires_at_ns: AtomicU64::new(expires_at.as_nanos()),
                revoked: AtomicBool::new(false),
            },
            peer,
            clock,
            snapshot_watch,
            state_event: Event::new(),
            slow: Mutex::new(SlowLeaseState {
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
        SessionAuth::from_watch(self.peer, self.snapshot_watch.subscribe())
    }

    /// Atomically applies a renewed [`Lease`] in place (Spec §6.7 & §7.3):
    /// - Validates `1 ms <= ttl <= max_ttl` and active status.
    /// - Publishes the new `TrafficGate`, `AuthExtensions`, and `expires_at` through a single
    ///   versioned commit so `TrafficGateCache`, `SessionAuth`, and `is_active()` never observe
    ///   a split renewal state.
    /// - Preserves all existing `SessionGuard`s while appending any newly returned guards.
    /// - Releases all internal locks BEFORE waking observers or dropping retired gates/claims
    ///   (preventing re-entrant destructor deadlocks).
    pub fn renew_lease_with_max_ttl(
        &self,
        lease: Lease,
        max_ttl: Duration,
    ) -> Result<Duration, CoreError> {
        if lease.ttl.as_millis() == 0 || lease.ttl > max_ttl {
            return Err(CoreError::Denied);
        }

        let old_snap = {
            let mut slow = self
                .slow
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.hot.revoked.load(Ordering::Acquire) {
                let reason = slow
                    .revoked_reason
                    .clone()
                    .unwrap_or(CoreError::Revoked);
                drop(slow);
                return Err(reason);
            }
            let now = self.clock.now();
            if now.as_nanos() >= self.hot.expires_at_ns.load(Ordering::Acquire) {
                drop(slow);
                return Err(CoreError::Expired);
            }

            let new_expires_ns = now.saturating_add(lease.ttl).as_nanos();
            let new_snap = Arc::new(LeaseSnapshot {
                gate: lease.gate,
                extensions: lease.extensions,
            });
            slow.guards.extend(lease.guards);

            // Commit gate + extensions + version + expires_at_ns atomically under Watch::state:
            // Watch::version is stored with Release BEFORE expires_at_ns (also Release),
            // guaranteeing that observing any one of {expires_at_ns, TrafficGate, SessionAuth}
            // at the new version forces causally-subsequent reads of the others to see >= new.
            self.snapshot_watch.replace_with_commit(new_snap, |_| {
                self.hot
                    .expires_at_ns
                    .store(new_expires_ns, Ordering::Release);
            })
        };

        // All internal locks (`slow` and `Watch::state`) are released BEFORE notifying or dropping!
        self.snapshot_watch.notify_waiters();
        self.state_event.notify(usize::MAX);
        drop(old_snap);
        Ok(lease.ttl)
    }

    /// Extends only the lease TTL (used by Originator on receiving `RENEW_OK`).
    pub fn renew_ttl_only(&self, ttl: Duration, max_ttl: Duration) -> Result<Duration, CoreError> {
        if ttl.as_millis() == 0 || ttl > max_ttl {
            return Err(CoreError::Denied);
        }
        {
            let slow = self
                .slow
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.hot.revoked.load(Ordering::Acquire) {
                let reason = slow
                    .revoked_reason
                    .clone()
                    .unwrap_or(CoreError::Revoked);
                drop(slow);
                return Err(reason);
            }
            let now = self.clock.now();
            if now.as_nanos() >= self.hot.expires_at_ns.load(Ordering::Acquire) {
                drop(slow);
                return Err(CoreError::Expired);
            }
            let new_expires = now.saturating_add(ttl);
            self.hot
                .expires_at_ns
                .store(new_expires.as_nanos(), Ordering::Release);
        }

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
            self.hot.revoked.store(true, Ordering::Release);
        }
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
/// Hot-path lookups pay a single acquire atomic load between lease renewals, and retired
/// gates are moved out via `mem::replace` and dropped strictly outside all internal locks.
#[derive(Default)]
pub struct TrafficGateCache {
    seen_ver: u64,
    gate: Option<Arc<dyn TrafficGate>>,
}

#[allow(dead_code)]
impl TrafficGateCache {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            seen_ver: 0,
            gate: None,
        }
    }

    /// Returns the currently active `TrafficGate`, refreshing from `handle` only when the
    /// committed renewal version changes.
    #[inline]
    pub fn get(&mut self, handle: &LeaseHandle) -> Option<&Arc<dyn TrafficGate>> {
        let current_ver = handle.snapshot_watch.version();
        if current_ver != self.seen_ver {
            let (ver, new_gate) = handle
                .snapshot_watch
                .borrow_with_version(|snap| snap.gate.clone());
            // Watch lock is ALREADY released before dropping any retired gate!
            let old_gate = core::mem::replace(&mut self.gate, new_gate);
            self.seen_ver = ver;
            drop(old_gate);
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

    #[test]
    fn lease_renewal_commits_gate_claims_and_ttl_atomically() {
        use std::sync::atomic::AtomicBool as StdAtomicBool;
        use std::thread;

        struct VersionGate(u64);
        impl TrafficGate for VersionGate {
            fn check_datagram(&self, _dir: Direction, _bytes: usize) -> DatagramAction {
                // Encode version into a synthetic Drop/Allow? Better: use charge_stream Delay(ns)!
                DatagramAction::Allow
            }
            fn charge_stream(&self, _dir: Direction, _bytes: usize) -> StreamAction {
                StreamAction::Delay(Duration::from_nanos(self.0))
            }
        }

        let clock = VirtualClock::new();
        let peer = PublicKey::from_bytes([9u8; 32]);
        let initial = Lease::new(Duration::from_secs(10))
            .with_gate(Arc::new(VersionGate(1)))
            .with_context(1u64);
        let handle =
            LeaseHandle::new(peer, initial, Duration::from_secs(3600), clock.clone()).unwrap();
        let done = Arc::new(StdAtomicBool::new(false));

        let read_gate_ver = |cache: &mut TrafficGateCache, h: &LeaseHandle| -> u64 {
            match cache.get(h).unwrap().charge_stream(Direction::Ingress, 1) {
                StreamAction::Delay(d) => d.as_nanos() as u64,
                _ => panic!("expected Delay carrying version"),
            }
        };

        // Reader 1: observes gate version, then checks claims >= gate version.
        let h1 = Arc::clone(&handle);
        let d1 = Arc::clone(&done);
        let t1 = thread::spawn(move || {
            let auth = h1.session_auth();
            let mut cache = TrafficGateCache::new();
            while !d1.load(Ordering::Acquire) {
                let gv = read_gate_ver(&mut cache, &h1);
                let cv = *auth.context::<u64>().unwrap();
                assert!(
                    cv >= gv,
                    "split renewal observed: new gate v{gv} with old claims v{cv}"
                );
            }
        });

        // Reader 2: observes claims version, then checks gate >= claims version.
        let h2 = Arc::clone(&handle);
        let d2 = Arc::clone(&done);
        let t2 = thread::spawn(move || {
            let auth = h2.session_auth();
            let mut cache = TrafficGateCache::new();
            while !d2.load(Ordering::Acquire) {
                let cv = *auth.context::<u64>().unwrap();
                let gv = read_gate_ver(&mut cache, &h2);
                assert!(
                    gv >= cv,
                    "split renewal observed: new claims v{cv} with old gate v{gv}"
                );
            }
        });

        // Reader 3: observes extended TTL for version v, then checks gate >= v and claims >= v.
        let h3 = Arc::clone(&handle);
        let d3 = Arc::clone(&done);
        let t3 = thread::spawn(move || {
            let auth = h3.session_auth();
            let mut cache = TrafficGateCache::new();
            while !d3.load(Ordering::Acquire) {
                let rem_ms = h3.remaining().unwrap().as_millis() as u64;
                if rem_ms > 10_000 {
                    let min_v = rem_ms - 10_000;
                    let gv = read_gate_ver(&mut cache, &h3);
                    let cv = *auth.context::<u64>().unwrap();
                    assert!(
                        gv >= min_v && cv >= min_v,
                        "split renewal observed: TTL implies >= v{min_v}, got gate v{gv}, claims v{cv}"
                    );
                }
            }
        });

        for v in 2..=2_000u64 {
            let renewed = Lease::new(Duration::from_millis(10_000 + v))
                .with_gate(Arc::new(VersionGate(v)))
                .with_context(v);
            handle
                .renew_lease_with_max_ttl(renewed, Duration::from_secs(3600))
                .unwrap();
        }
        done.store(true, Ordering::Release);
        t1.join().unwrap();
        t2.join().unwrap();
        t3.join().unwrap();
    }

    #[test]
    fn lease_renewal_and_gate_cache_reentrant_destructors_do_not_deadlock() {
        use std::sync::{Mutex as StdMutex, Weak};

        struct ReentrantGate {
            lease: StdMutex<Option<Weak<LeaseHandle>>>,
            auth: StdMutex<Option<SessionAuth>>,
            ran: Arc<AtomicBool>,
        }
        impl TrafficGate for ReentrantGate {
            fn check_datagram(&self, _dir: Direction, _bytes: usize) -> DatagramAction {
                DatagramAction::Allow
            }
            fn charge_stream(&self, _dir: Direction, _bytes: usize) -> StreamAction {
                StreamAction::Allow
            }
        }
        impl Drop for ReentrantGate {
            fn drop(&mut self) {
                if let Some(auth) = self.auth.lock().unwrap().as_ref() {
                    let _ = auth.context::<String>();
                }
                if let Some(weak) = self.lease.lock().unwrap().as_ref() {
                    if let Some(h) = weak.upgrade() {
                        h.revoke(CoreError::Revoked);
                    }
                }
                self.ran.store(true, Ordering::SeqCst);
            }
        }

        struct ReentrantClaim {
            auth: StdMutex<Option<SessionAuth>>,
            saw_v2: Arc<AtomicBool>,
        }
        impl Drop for ReentrantClaim {
            fn drop(&mut self) {
                if let Some(auth) = self.auth.lock().unwrap().as_ref() {
                    let is_v2 = auth
                        .context::<String>()
                        .as_deref()
                        .map(String::as_str)
                        == Some("v2");
                    self.saw_v2.store(is_v2, Ordering::SeqCst);
                }
            }
        }

        let clock = VirtualClock::new();
        let peer = PublicKey::from_bytes([7u8; 32]);

        // Case 1: Re-entrant TrafficGate + typed claim drop during renew_lease_with_max_ttl.
        let gate_dropped = Arc::new(AtomicBool::new(false));
        let claim_saw_v2 = Arc::new(AtomicBool::new(false));
        let gate1 = Arc::new(ReentrantGate {
            lease: StdMutex::new(None),
            auth: StdMutex::new(None),
            ran: Arc::clone(&gate_dropped),
        });
        let claim1 = Arc::new(ReentrantClaim {
            auth: StdMutex::new(None),
            saw_v2: Arc::clone(&claim_saw_v2),
        });
        let mut ext1 = crate::seam::auth::AuthExtensions::new();
        ext1.insert("v1".to_string());
        ext1.insert_arc(Arc::clone(&claim1));

        let handle = LeaseHandle::new(
            peer,
            Lease::new(Duration::from_secs(60))
                .with_gate(Arc::clone(&gate1) as Arc<dyn TrafficGate>)
                .with_extensions(ext1),
            Duration::from_secs(60),
            clock.clone(),
        )
        .unwrap();
        let auth = handle.session_auth();
        *gate1.lease.lock().unwrap() = Some(Arc::downgrade(&handle));
        *gate1.auth.lock().unwrap() = Some(auth.clone());
        *claim1.auth.lock().unwrap() = Some(auth);
        drop(gate1);
        drop(claim1);

        handle
            .renew_lease_with_max_ttl(
                Lease::new(Duration::from_secs(60)).with_context("v2".to_string()),
                Duration::from_secs(60),
            )
            .unwrap();
        assert!(gate_dropped.load(Ordering::SeqCst));
        assert!(claim_saw_v2.load(Ordering::SeqCst));
        assert_eq!(handle.remaining(), Err(CoreError::Revoked));

        // Case 2: Re-entrant TrafficGate drop when TrafficGateCache holds the last Arc and refreshes.
        let cache_gate_dropped = Arc::new(AtomicBool::new(false));
        let gate2 = Arc::new(ReentrantGate {
            lease: StdMutex::new(None),
            auth: StdMutex::new(None),
            ran: Arc::clone(&cache_gate_dropped),
        });
        let handle2 = LeaseHandle::new(
            peer,
            Lease::new(Duration::from_secs(60))
                .with_gate(Arc::clone(&gate2) as Arc<dyn TrafficGate>),
            Duration::from_secs(60),
            clock,
        )
        .unwrap();
        let mut cache = TrafficGateCache::new();
        assert!(cache.get(&handle2).is_some());
        *gate2.lease.lock().unwrap() = Some(Arc::downgrade(&handle2));
        *gate2.auth.lock().unwrap() = Some(handle2.session_auth());
        drop(gate2);

        // Renew swaps out gate2 on LeaseHandle; cache still owns the last Arc to gate2.
        handle2
            .renew_lease_with_max_ttl(Lease::new(Duration::from_secs(60)), Duration::from_secs(60))
            .unwrap();
        assert!(!cache_gate_dropped.load(Ordering::SeqCst));

        // Refreshing cache drops the last Arc to gate2 strictly AFTER releasing Watch lock!
        assert!(cache.get(&handle2).is_none());
        assert!(cache_gate_dropped.load(Ordering::SeqCst));
        assert_eq!(handle2.remaining(), Err(CoreError::Revoked));
    }
}
