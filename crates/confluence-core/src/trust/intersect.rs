//! Host-sovereign policy composition (`IntersectAuthorizer` & `IntersectGate`, Spec §7.2).

use std::sync::Arc;

use crate::runtime::BoxFuture;
use crate::seam::auth::{
    AuthDenied, AuthRequest, Authorizer, DatagramAction, Lease, RevocationReceiver, StreamAction,
    TrafficGate,
};
use crate::types::Direction;

/// Fail-closed intersection of two [`TrafficGate`]s with strict local-first evaluation (Spec §7.2).
struct IntersectGate {
    local: Arc<dyn TrafficGate>,
    external: Arc<dyn TrafficGate>,
}

impl TrafficGate for IntersectGate {
    fn check_datagram(&self, dir: Direction, bytes: usize) -> DatagramAction {
        match self.local.check_datagram(dir, bytes) {
            DatagramAction::Allow => self.external.check_datagram(dir, bytes),
            other => other,
        }
    }

    fn charge_stream(&self, dir: Direction, bytes: usize) -> StreamAction {
        match self.local.charge_stream(dir, bytes) {
            StreamAction::Close(err) => StreamAction::Close(err),
            StreamAction::Allow => self.external.charge_stream(dir, bytes),
            StreamAction::Delay(a) => match self.external.charge_stream(dir, bytes) {
                StreamAction::Close(err) => StreamAction::Close(err),
                StreamAction::Delay(b) => StreamAction::Delay(a.max(b)),
                StreamAction::Allow => StreamAction::Delay(a),
            },
        }
    }
}

/// Intersects `local` and `external` [`Lease`] decisions with strict host sovereignty (Spec §7.2).
#[must_use]
pub(crate) fn intersect_leases(mut local: Lease, external: Lease) -> Lease {
    let ttl = local.ttl.min(external.ttl);
    let gate = match (local.gate.take(), external.gate) {
        (Some(a), Some(b)) => Some(Arc::new(IntersectGate {
            local: a,
            external: b,
        }) as Arc<dyn TrafficGate>),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };
    local.guards.extend(external.guards);
    let extensions = local.extensions.merge_prefer_self(&external.extensions);
    Lease {
        ttl,
        gate,
        guards: local.guards,
        extensions,
    }
}

/// Host-sovereign [`Authorizer`] combinator intersecting a `local` hard-veto policy with an
/// `external` verifier (Spec §7.2).
///
/// - Evaluates `local` FIRST; if `local` denies, `external` is never called.
/// - Intersects granted leases: `min(ttl)`, fail-closed `IntersectGate`, concatenated `guards`,
///   and `AuthExtensions` merged with `local`-key precedence.
/// - Collects both `revocation_streams()` vectors directly with zero intermediate tasks.
pub struct IntersectAuthorizer {
    local: Arc<dyn Authorizer>,
    external: Arc<dyn Authorizer>,
}

impl IntersectAuthorizer {
    /// Creates an `IntersectAuthorizer` enforcing `local` as hard veto before `external`.
    #[must_use]
    pub fn new(local: Arc<dyn Authorizer>, external: Arc<dyn Authorizer>) -> Self {
        Self { local, external }
    }

    /// Alias for [`Self::new`].
    #[must_use]
    pub fn compose(local: Arc<dyn Authorizer>, external: Arc<dyn Authorizer>) -> Self {
        Self::new(local, external)
    }
}

impl Authorizer for IntersectAuthorizer {
    fn authorize<'a>(&'a self, req: AuthRequest<'a>) -> BoxFuture<'a, Result<Lease, AuthDenied>> {
        Box::pin(async move {
            let local_lease = self.local.authorize(req).await?;
            let external_lease = self.external.authorize(req).await?;
            Ok(intersect_leases(local_lease, external_lease))
        })
    }

    fn revocation_streams(&self) -> Vec<RevocationReceiver> {
        let mut streams = self.local.revocation_streams();
        streams.extend(self.external.revocation_streams());
        streams
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use core::time::Duration;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::error::CoreError;
    use crate::seam::auth::revocation_channel;
    use crate::testing::TestSpawner;
    use crate::types::{Plane, PublicKey, TargetRef};

    #[derive(Clone)]
    struct FixedLeaseSpec {
        ttl: Duration,
        gate: Option<Arc<dyn TrafficGate>>,
        claim: &'static str,
        extra: Option<u32>,
    }

    struct FixedAuth {
        calls: Arc<AtomicUsize>,
        result: Result<FixedLeaseSpec, AuthDenied>,
        tx: Option<crate::seam::auth::RevocationSender>,
    }

    impl Authorizer for FixedAuth {
        fn authorize<'a>(&'a self, _req: AuthRequest<'a>) -> BoxFuture<'a, Result<Lease, AuthDenied>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let spec = self.result.clone()?;
                let mut lease = Lease::new(spec.ttl).with_context(spec.claim.to_string());
                if let Some(g) = spec.gate {
                    lease = lease.with_gate(g);
                }
                if let Some(v) = spec.extra {
                    lease = lease.with_context(v);
                }
                Ok(lease)
            })
        }

        fn revocation_streams(&self) -> Vec<RevocationReceiver> {
            self.tx.iter().map(|t| t.subscribe()).collect()
        }
    }

    struct DelayGate {
        dg: DatagramAction,
        st: StreamAction,
        calls: Arc<AtomicUsize>,
    }

    impl TrafficGate for DelayGate {
        fn check_datagram(&self, _dir: Direction, _bytes: usize) -> DatagramAction {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.dg.clone()
        }
        fn charge_stream(&self, _dir: Direction, _bytes: usize) -> StreamAction {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.st.clone()
        }
    }

    #[test]
    fn intersect_authorizer_enforces_local_veto_and_merges_with_local_precedence() {
        let spawner = TestSpawner::new();
        let req = AuthRequest {
            peer: PublicKey::from_bytes([9u8; 32]),
            target: TargetRef::Endpoint {
                name: "ep",
                plane: Plane::Datagram,
            },
            credential: &[],
            is_renewal: false,
        };

        // Case 1: local veto short-circuits without calling external.
        let local_calls = Arc::new(AtomicUsize::new(0));
        let ext_calls = Arc::new(AtomicUsize::new(0));
        let veto = IntersectAuthorizer::new(
            Arc::new(FixedAuth {
                calls: Arc::clone(&local_calls),
                result: Err(AuthDenied::Denied),
                tx: None,
            }),
            Arc::new(FixedAuth {
                calls: Arc::clone(&ext_calls),
                result: Ok(FixedLeaseSpec {
                    ttl: Duration::from_secs(60),
                    gate: None,
                    claim: "ext",
                    extra: None,
                }),
                tx: None,
            }),
        );
        assert!(matches!(
            spawner.try_block_on(veto.authorize(req)),
            Some(Err(AuthDenied::Denied))
        ));
        assert_eq!(local_calls.load(Ordering::SeqCst), 1);
        assert_eq!(ext_calls.load(Ordering::SeqCst), 0);

        // Case 2: both allow -> min TTL, IntersectGate, local claim precedence, both revocation streams.
        let (tx1, _) = revocation_channel(4);
        let (tx2, _) = revocation_channel(4);
        let g1_calls = Arc::new(AtomicUsize::new(0));
        let g2_calls = Arc::new(AtomicUsize::new(0));
        let combined = IntersectAuthorizer::new(
            Arc::new(FixedAuth {
                calls: Arc::new(AtomicUsize::new(0)),
                result: Ok(FixedLeaseSpec {
                    ttl: Duration::from_secs(30),
                    gate: Some(Arc::new(DelayGate {
                        dg: DatagramAction::Drop,
                        st: StreamAction::Delay(Duration::from_millis(20)),
                        calls: Arc::clone(&g1_calls),
                    })),
                    claim: "local-role",
                    extra: None,
                }),
                tx: Some(tx1),
            }),
            Arc::new(FixedAuth {
                calls: Arc::new(AtomicUsize::new(0)),
                result: Ok(FixedLeaseSpec {
                    ttl: Duration::from_secs(120),
                    gate: Some(Arc::new(DelayGate {
                        dg: DatagramAction::Close(CoreError::Denied),
                        st: StreamAction::Delay(Duration::from_millis(50)),
                        calls: Arc::clone(&g2_calls),
                    })),
                    claim: "external-role",
                    extra: Some(42u32),
                }),
                tx: Some(tx2),
            }),
        );

        assert_eq!(combined.revocation_streams().len(), 2);
        let lease = spawner.try_block_on(combined.authorize(req)).unwrap().unwrap();
        assert_eq!(lease.ttl, Duration::from_secs(30));
        // Local claim wins on String collision; non-colliding u32 claim from external is preserved!
        assert_eq!(
            lease.extensions.get::<String>().as_deref().map(String::as_str),
            Some("local-role")
        );
        assert_eq!(lease.extensions.get::<u32>().as_deref().copied(), Some(42));

        let gate = lease.gate.unwrap();
        // Local Drop short-circuits external on check_datagram!
        assert_eq!(gate.check_datagram(Direction::Ingress, 100), DatagramAction::Drop);
        assert_eq!(g1_calls.load(Ordering::SeqCst), 1);
        assert_eq!(g2_calls.load(Ordering::SeqCst), 0);
        // Stream delay takes max(20ms, 50ms) = 50ms!
        assert_eq!(
            gate.charge_stream(Direction::Ingress, 100),
            StreamAction::Delay(Duration::from_millis(50))
        );
    }
}
