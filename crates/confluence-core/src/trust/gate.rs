//! Fail-closed `AuthGate` enforcing local hard veto, per-peer pending quota, concurrency,
//! hard monotonic timeout, and lease TTL bounds (Spec §7.1).

use core::future::{Future, poll_fn};
use core::task::Poll;
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::constants::{
    DEFAULT_AUTH_CONCURRENCY, DEFAULT_AUTH_TIMEOUT, DEFAULT_MAX_LEASE_TTL,
    DEFAULT_PER_PEER_PENDING, MAX_AUTH_TIMEOUT, MAX_WIRE_LEASE_TTL, MIN_AUTH_TIMEOUT,
    MIN_MAX_LEASE_TTL,
};
use crate::error::CoreError;
use crate::runtime::Clock;
use crate::runtime::sync::CloseableSemaphore;
use crate::seam::auth::{AuthDenied, AuthRequest, Authorizer, Lease};
use crate::stats::{ScopeMetrics, should_warn_pow2};
use crate::trust::registry::PublishRegistry;
use crate::types::PublicKey;

/// Clamped authorization concurrency, timeout, per-peer pending, and lease TTL limits (Spec §3.2 & §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthLimits {
    /// Maximum concurrent in-flight pending setups per remote peer (default `8`, min `1`).
    pub per_peer_pending: usize,
    /// Maximum concurrent `Authorizer::authorize` evaluations (default `32`, min `1`).
    pub auth_concurrency: usize,
    /// Hard monotonic timeout for authorization and credential fetches (default `500 ms`, clamped `[10 ms, 5 s]`).
    pub auth_timeout: Duration,
    /// Maximum accepted lease lifetime (default `3600 s`, clamped `[1 s, 24 h]`).
    pub max_lease_ttl: Duration,
}

impl Default for AuthLimits {
    fn default() -> Self {
        Self {
            per_peer_pending: DEFAULT_PER_PEER_PENDING,
            auth_concurrency: DEFAULT_AUTH_CONCURRENCY,
            auth_timeout: DEFAULT_AUTH_TIMEOUT,
            max_lease_ttl: DEFAULT_MAX_LEASE_TTL,
        }
    }
}

impl AuthLimits {
    /// Returns a copy of these limits clamped to the normative Spec §3.2 bounds.
    #[must_use]
    pub fn clamped(self) -> Self {
        Self {
            per_peer_pending: self.per_peer_pending.max(1),
            auth_concurrency: self.auth_concurrency.max(1),
            auth_timeout: self.auth_timeout.clamp(MIN_AUTH_TIMEOUT, MAX_AUTH_TIMEOUT),
            max_lease_ttl: self
                .max_lease_ttl
                .clamp(MIN_MAX_LEASE_TTL, MAX_WIRE_LEASE_TTL),
        }
    }
}

/// RAII guard reserving one per-peer pending setup slot inside [`AuthGate`].
///
/// Automatically decrements (and removes zero-count peer entries) on drop.
pub struct PendingSetup {
    peer: PublicKey,
    per_peer: Arc<Mutex<HashMap<PublicKey, usize>>>,
}

impl Drop for PendingSetup {
    fn drop(&mut self) {
        let mut map = self
            .per_peer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = map.get_mut(&self.peer) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&self.peer);
            }
        }
    }
}

/// Races `fut` against a monotonic `sleep_fut`, returning `None` if the timer fires first.
async fn race_timeout<F, S, T>(fut: F, sleep_fut: S) -> Option<T>
where
    F: Future<Output = T>,
    S: Future<Output = ()>,
{
    let mut fut = core::pin::pin!(fut);
    let mut sleep_fut = core::pin::pin!(sleep_fut);
    poll_fn(|cx| {
        if let Poll::Ready(val) = fut.as_mut().poll(cx) {
            return Poll::Ready(Some(val));
        }
        if sleep_fut.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        Poll::Pending
    })
    .await
}

/// Fail-closed enforcement wrapper around an [`Authorizer`] (Spec §7.1).
pub struct AuthGate {
    authorizer: Arc<dyn Authorizer>,
    limits: AuthLimits,
    clock: Arc<dyn Clock>,
    concurrency: Arc<CloseableSemaphore>,
    per_peer: Arc<Mutex<HashMap<PublicKey, usize>>>,
    registry: Arc<PublishRegistry>,
    metrics: Arc<ScopeMetrics>,
}

#[allow(dead_code)]
impl AuthGate {
    #[must_use]
    pub fn new(
        authorizer: Arc<dyn Authorizer>,
        limits: AuthLimits,
        clock: Arc<dyn Clock>,
        registry: Arc<PublishRegistry>,
        metrics: Arc<ScopeMetrics>,
    ) -> Self {
        let limits = limits.clamped();
        Self {
            authorizer,
            concurrency: CloseableSemaphore::new(limits.auth_concurrency),
            limits,
            clock,
            per_peer: Arc::new(Mutex::new(HashMap::new())),
            registry,
            metrics,
        }
    }

    #[must_use]
    pub const fn limits(&self) -> AuthLimits {
        self.limits
    }

    /// Closes the authorization concurrency semaphore during scope shutdown.
    pub fn close(&self) {
        self.concurrency.close();
    }

    /// Reserves a per-peer pending setup quota slot (checked after peer authentication).
    pub fn acquire_pending(&self, peer: PublicKey) -> Result<PendingSetup, CoreError> {
        if self.registry.is_vetoed(peer) {
            return Err(CoreError::Revoked);
        }
        let mut map = self
            .per_peer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = map.entry(peer).or_insert(0);
        if *entry >= self.limits.per_peer_pending {
            drop(map);
            let count = self.metrics.record_capacity_drop();
            if should_warn_pow2(count) {
                tracing::warn!(
                    count,
                    error = CoreError::Busy.static_code(),
                    "per-peer pending setup quota saturated"
                );
            }
            return Err(CoreError::Busy);
        }
        *entry += 1;
        Ok(PendingSetup {
            peer,
            per_peer: Arc::clone(&self.per_peer),
        })
    }

    /// Evaluates [`Authorizer::authorize`] fail-closed under local veto checks, bounded
    /// concurrency, a single hard monotonic `auth_timeout`, and lease TTL validation (Spec §7.1).
    pub async fn authorize(&self, req: AuthRequest<'_>) -> Result<Lease, CoreError> {
        let is_transit = req.target.is_transit();
        if self.registry.is_vetoed(req.peer) {
            return Err(CoreError::Revoked);
        }

        let started = self.clock.now();
        let deadline = started.saturating_add(self.limits.auth_timeout);

        let permit_res =
            race_timeout(self.concurrency.acquire(), self.clock.sleep_until(deadline)).await;
        let _permit = match permit_res {
            Some(Ok(p)) => p,
            Some(Err(err)) => return Err(err),
            None => {
                self.record_timeout(is_transit);
                return Err(CoreError::Timeout);
            }
        };

        if self.clock.now() >= deadline {
            self.record_timeout(is_transit);
            return Err(CoreError::Timeout);
        }

        let auth_res = race_timeout(
            self.authorizer.authorize(req),
            self.clock.sleep_until(deadline),
        )
        .await;

        let finished = self.clock.now();
        let elapsed_ms =
            u64::try_from(finished.saturating_duration_since(started).as_millis()).unwrap_or(u64::MAX);
        self.metrics
            .auth(is_transit)
            .duration_ms_total
            .fetch_add(elapsed_ms, std::sync::atomic::Ordering::Relaxed);

        // Hard monotonic deadline check even if authorizer completed at/past deadline (Spec §7.1 Step 3).
        let Some(decision) = auth_res else {
            self.record_timeout(is_transit);
            return Err(CoreError::Timeout);
        };
        if finished >= deadline {
            self.record_timeout(is_transit);
            return Err(CoreError::Timeout);
        }

        // Re-check local hard veto after async authorization completes.
        if self.registry.is_vetoed(req.peer) {
            return Err(CoreError::Revoked);
        }

        match decision {
            Err(AuthDenied::Denied) => {
                self.metrics
                    .auth(is_transit)
                    .rejected
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err(CoreError::Denied)
            }
            Err(AuthDenied::Busy) => {
                self.metrics
                    .auth(is_transit)
                    .busy
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err(CoreError::Busy)
            }
            Ok(lease) => {
                if lease.ttl.as_millis() == 0 || lease.ttl > self.limits.max_lease_ttl {
                    self.metrics
                        .auth(is_transit)
                        .rejected
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Err(CoreError::Denied);
                }
                self.metrics
                    .auth(is_transit)
                    .allowed
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(lease)
            }
        }
    }

    fn record_timeout(&self, is_transit: bool) {
        let count = self.metrics.record_auth_timeout(is_transit);
        if should_warn_pow2(count) {
            tracing::warn!(
                count,
                is_transit,
                error = CoreError::Timeout.static_code(),
                "authorization evaluation timed out"
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::runtime::{BoxFuture, TaskSpawner};
    use crate::runtime::sync::Watch;
    use crate::testing::{TestSpawner, VirtualClock};
    use crate::types::{Plane, TargetRef};

    struct SlowAuth {
        clock: Arc<dyn Clock>,
        delay: Duration,
        ttl: Duration,
    }

    impl Authorizer for SlowAuth {
        fn authorize<'a>(&'a self, _req: AuthRequest<'a>) -> BoxFuture<'a, Result<Lease, AuthDenied>> {
            Box::pin(async move {
                self.clock.sleep(self.delay).await;
                Ok(Lease::new(self.ttl))
            })
        }
    }

    #[test]
    fn auth_gate_enforces_limits_veto_per_peer_quota_and_hard_timeout() {
        let clock = VirtualClock::new();
        let spawner = TestSpawner::new();
        let metrics = Arc::new(ScopeMetrics::new());
        let registry = Arc::new(PublishRegistry::new(Arc::clone(&metrics)));
        let peer = PublicKey::from_bytes([7u8; 32]);

        let limits = AuthLimits {
            per_peer_pending: 2,
            auth_concurrency: 1,
            auth_timeout: Duration::from_millis(100),
            max_lease_ttl: Duration::from_secs(60),
        };
        let gate = Arc::new(AuthGate::new(
            Arc::new(SlowAuth {
                clock: clock.clone(),
                delay: Duration::from_millis(150),
                ttl: Duration::from_secs(30),
            }),
            limits,
            clock.clone(),
            Arc::clone(&registry),
            Arc::clone(&metrics),
        ));

        // Per-peer pending cap = 2.
        let p1 = gate.acquire_pending(peer).unwrap();
        let p2 = gate.acquire_pending(peer).unwrap();
        assert!(matches!(gate.acquire_pending(peer), Err(CoreError::Busy)));
        drop(p1);
        drop(p2);

        // Hard monotonic timeout at 100 ms beats 150 ms authorizer!
        let g2 = Arc::clone(&gate);
        let (tx, rx) = Watch::new(None::<Result<Duration, CoreError>>);
        spawner.spawn(Box::pin(async move {
            let req = AuthRequest {
                peer,
                target: TargetRef::Endpoint {
                    name: "ep",
                    plane: Plane::Datagram,
                },
                credential: &[],
                is_renewal: false,
            };
            tx.send(Some(g2.authorize(req).await.map(|l| l.ttl)));
        }));
        spawner.drive_until_idle();
        clock.advance(Duration::from_millis(100));
        spawner.drive_until_idle();
        assert_eq!(rx.borrow_cloned(), Some(Err(CoreError::Timeout)));
        assert_eq!(metrics.snapshot().auth_endpoint.timed_out, 1);

        // Local hard veto rejects immediately before invoking Authorizer.
        registry.veto_peer(peer);
        assert!(matches!(gate.acquire_pending(peer), Err(CoreError::Revoked)));
        let req = AuthRequest {
            peer,
            target: TargetRef::Endpoint {
                name: "ep",
                plane: Plane::Datagram,
            },
            credential: &[],
            is_renewal: false,
        };
        assert_eq!(
            spawner.try_block_on(gate.authorize(req)).map(|r| r.map(|l| l.ttl)),
            Some(Err(CoreError::Revoked))
        );

        // TTL validation: 0 ms or > max_lease_ttl -> Denied.
        registry.unveto_peer(peer);
        let zero_gate = AuthGate::new(
            Arc::new(SlowAuth {
                clock: clock.clone(),
                delay: Duration::ZERO,
                ttl: Duration::ZERO,
            }),
            limits,
            clock.clone(),
            Arc::clone(&registry),
            Arc::clone(&metrics),
        );
        assert_eq!(
            spawner.try_block_on(zero_gate.authorize(req)).map(|r| r.map(|l| l.ttl)),
            Some(Err(CoreError::Denied))
        );
    }
}
