use crate::error::{CoreError, Result};
use crate::types::{
    ChannelAddr, ChannelId, EndpointName, OpaqueCredential, PeerId, Plane, ScopeId,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

/// Control-plane action evaluated by an `AccessControl` verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// End-to-end endpoint access verified by Core's E2E Trust Boundary on destination `B`.
    OpenEndpoint {
        endpoint: EndpointName,
        plane: Plane,
    },
    /// Outbound transit forwarding verified by a composable `NoiseAclChannel` wrapper.
    ChannelForward {
        channel: ChannelId,
        target: ChannelAddr,
        plane: Plane,
    },
    /// Custom channel plugin action (e.g., `relay_register` or `relay_connect` in `confluence-relay`).
    ChannelCustom {
        kind: String,
        target: String,
        plane: Plane,
    },
    /// In-band renewal of an existing action's Grant.
    RenewGrant { target_action: Box<Action> },
}

/// Request submitted to `AccessControl::evaluate` on control events only (never per data packet).
#[derive(Debug, Clone)]
pub struct AccessRequest {
    pub scope: ScopeId,
    pub peer: PeerId,
    pub credential: Option<OpaqueCredential>,
    pub action: Action,
}

/// Bounded authorization grant enforced on the live data path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    /// Monotonic instant at which this grant expires unless renewed.
    pub expires_at: Instant,
    /// Optional sustained byte throughput cap (bytes/second).
    pub max_bytes_per_sec: Option<u64>,
    /// Optional sustained discrete message rate cap (datagrams/second).
    pub max_datagrams_per_sec: Option<u64>,
    /// Optional maximum concurrent active streams under this grant.
    pub max_concurrent_streams: Option<u32>,
}

impl Grant {
    /// Creates an unbounded-rate grant expiring after `ttl` from `Instant::now()`.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            expires_at: Instant::now() + ttl,
            max_bytes_per_sec: None,
            max_datagrams_per_sec: None,
            max_concurrent_streams: None,
        }
    }

    /// Returns `true` if `now >= self.expires_at`.
    pub fn is_expired_at(&self, now: Instant) -> bool {
        now >= self.expires_at
    }

    /// Computes the strict intersection of two grants (minimum expiry and minimum rate/concurrency bounds).
    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            expires_at: self.expires_at.min(other.expires_at),
            max_bytes_per_sec: min_opt(self.max_bytes_per_sec, other.max_bytes_per_sec),
            max_datagrams_per_sec: min_opt(
                self.max_datagrams_per_sec,
                other.max_datagrams_per_sec,
            ),
            max_concurrent_streams: min_opt(
                self.max_concurrent_streams,
                other.max_concurrent_streams,
            ),
        }
    }
}

fn min_opt<T: Ord + Copy>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) => Some(x),
        (None, Some(y)) => Some(y),
        (None, None) => None,
    }
}

/// Policy decision returned by an `AccessControl` verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow(Grant),
    Deny { reason: String },
}

/// Asynchronous revocation signal causing immediate local teardown of matching sessions/streams/circuits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationEvent {
    /// If `Some`, restricts revocation to this `ScopeId`; if `None`, applies across all scopes.
    pub scope: Option<ScopeId>,
    /// If `Some`, restricts revocation to this `PeerId`; if `None`, applies to all peers.
    pub peer: Option<PeerId>,
    /// If `Some`, restricts revocation to this `EndpointName`; if `None`, applies to all endpoints/actions.
    pub endpoint: Option<EndpointName>,
}

impl RevocationEvent {
    /// Checks whether this revocation event applies to `(scope, peer, endpoint)`.
    pub fn matches(
        &self,
        scope: &ScopeId,
        peer: &PeerId,
        endpoint: Option<&EndpointName>,
    ) -> bool {
        if let Some(ref s) = self.scope {
            if s != scope {
                return false;
            }
        }
        if let Some(ref p) = self.peer {
            if p != peer {
                return false;
            }
        }
        if let Some(ref ep) = self.endpoint {
            match endpoint {
                Some(target_ep) if target_ep == ep => {}
                _ => return false,
            }
        }
        true
    }
}

/// Access Control verifier seam (Seam 3) — "Verifier, never an issuer".
#[async_trait]
pub trait AccessControl: Send + Sync + 'static {
    /// Evaluates `(scope, verified peer, opaque credential, action)` on a control event.
    /// Any error or timeout MUST be treated as fail-closed denial by callers.
    async fn evaluate(&self, req: AccessRequest) -> Result<Decision>;

    /// Subscribes to live revocation events.
    fn revocations(&self) -> broadcast::Receiver<RevocationEvent>;
}

/// Composes a local host policy `L` with an external policy `E`, guaranteeing **Host Sovereignty**
/// (Cleanroom Invariant #7):
/// - Local policy `L` always retains final hard veto.
/// - External policy `E` is bounded by `eval_timeout` and fails closed on error or timeout.
/// - Resulting `Grant` is the strict intersection (`min` expiry and `min` rate/concurrency bounds).
/// - Revocations from either `L` or `E` propagate immediately.
pub struct IntersectAccessControl<L, E> {
    local: Arc<L>,
    external: Arc<E>,
    eval_timeout: Duration,
    merged_revocations: broadcast::Sender<RevocationEvent>,
}

impl<L, E> IntersectAccessControl<L, E>
where
    L: AccessControl,
    E: AccessControl,
{
    pub fn new(local: Arc<L>, external: Arc<E>, eval_timeout: Duration) -> Self {
        let (tx, _) = broadcast::channel(256);

        let mut rx_local = local.revocations();
        let tx_local = tx.clone();
        tokio::spawn(async move {
            while let Ok(ev) = rx_local.recv().await {
                if tx_local.send(ev).is_err() {
                    break;
                }
            }
        });

        let mut rx_ext = external.revocations();
        let tx_ext = tx.clone();
        tokio::spawn(async move {
            while let Ok(ev) = rx_ext.recv().await {
                if tx_ext.send(ev).is_err() {
                    break;
                }
            }
        });

        Self {
            local,
            external,
            eval_timeout,
            merged_revocations: tx,
        }
    }
}

#[async_trait]
impl<L, E> AccessControl for IntersectAccessControl<L, E>
where
    L: AccessControl,
    E: AccessControl,
{
    async fn evaluate(&self, req: AccessRequest) -> Result<Decision> {
        // 1. Local policy evaluates first (hard local veto; never overridden by external policy).
        let local_decision = tokio::time::timeout(self.eval_timeout, self.local.evaluate(req.clone()))
            .await
            .map_err(|_| CoreError::PolicyError("local policy evaluation timed out".into()))??;

        let local_grant = match local_decision {
            Decision::Allow(g) => g,
            Decision::Deny { reason } => return Ok(Decision::Deny { reason }),
        };

        // 2. External policy evaluates with fail-closed timeout.
        let ext_decision = tokio::time::timeout(self.eval_timeout, self.external.evaluate(req))
            .await
            .map_err(|_| CoreError::PolicyError("external policy evaluation timed out".into()))??;

        let ext_grant = match ext_decision {
            Decision::Allow(g) => g,
            Decision::Deny { reason } => return Ok(Decision::Deny { reason }),
        };

        let combined = local_grant.intersect(&ext_grant);
        if combined.is_expired_at(Instant::now()) {
            return Ok(Decision::Deny {
                reason: "intersected grant is already expired".into(),
            });
        }
        Ok(Decision::Allow(combined))
    }

    fn revocations(&self) -> broadcast::Receiver<RevocationEvent> {
        self.merged_revocations.subscribe()
    }
}
