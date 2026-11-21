use async_trait::async_trait;
use confluence_core::seams::access::{
    AccessControl, AccessRequest, Decision, Grant, RevocationEvent,
};
use confluence_core::seams::routing::{ExplicitPath, PathSource};
use confluence_core::{CoreError, PeerId, Plane, Result, ScopeId};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

type RulePredicate = Box<dyn Fn(&AccessRequest) -> Option<Decision> + Send + Sync>;

/// Deterministic `AccessControl` test fixture recording control-plane evaluation count
/// (to prove `AccessControl` is never invoked per data packet — Cleanroom Invariant #7)
/// and supporting instant `revoke(...)` broadcast triggers.
pub struct AuditAccessControl {
    default_ttl: Duration,
    default_allow: bool,
    rules: Mutex<Vec<RulePredicate>>,
    evaluations: AtomicUsize,
    recorded_requests: Mutex<Vec<AccessRequest>>,
    rev_tx: broadcast::Sender<RevocationEvent>,
}

impl AuditAccessControl {
    pub fn allow_all(default_ttl: Duration) -> Arc<Self> {
        let (rev_tx, _) = broadcast::channel(64);
        Arc::new(Self {
            default_ttl,
            default_allow: true,
            rules: Mutex::new(Vec::new()),
            evaluations: AtomicUsize::new(0),
            recorded_requests: Mutex::new(Vec::new()),
            rev_tx,
        })
    }

    pub fn deny_by_default(default_ttl: Duration) -> Arc<Self> {
        let (rev_tx, _) = broadcast::channel(64);
        Arc::new(Self {
            default_ttl,
            default_allow: false,
            rules: Mutex::new(Vec::new()),
            evaluations: AtomicUsize::new(0),
            recorded_requests: Mutex::new(Vec::new()),
            rev_tx,
        })
    }

    pub fn add_rule<F>(&self, rule: F)
    where
        F: Fn(&AccessRequest) -> Option<Decision> + Send + Sync + 'static,
    {
        self.rules.lock().push(Box::new(rule));
    }

    pub fn evaluation_count(&self) -> usize {
        self.evaluations.load(Ordering::Acquire)
    }

    pub fn requests(&self) -> Vec<AccessRequest> {
        self.recorded_requests.lock().clone()
    }

    pub fn trigger_revocation(&self, event: RevocationEvent) {
        let _ = self.rev_tx.send(event);
    }
}

#[async_trait]
impl AccessControl for AuditAccessControl {
    async fn evaluate(&self, req: AccessRequest) -> Result<Decision> {
        self.evaluations.fetch_add(1, Ordering::AcqRel);
        self.recorded_requests.lock().push(req.clone());

        let guard = self.rules.lock();
        for rule in guard.iter() {
            if let Some(decision) = rule(&req) {
                return Ok(decision);
            }
        }
        if self.default_allow {
            Ok(Decision::Allow(Grant::with_ttl(self.default_ttl)))
        } else {
            Ok(Decision::Deny {
                reason: "denied by default test policy".into(),
            })
        }
    }

    fn revocations(&self) -> broadcast::Receiver<RevocationEvent> {
        self.rev_tx.subscribe()
    }
}

/// Deterministic in-memory `PathSource` mapping `(ScopeId, PeerId, Plane)` to an `ExplicitPath`.
#[derive(Default)]
pub struct StaticMapPathSource {
    routes: Mutex<HashMap<(ScopeId, PeerId, Plane), ExplicitPath>>,
}

impl StaticMapPathSource {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn insert(&self, scope: ScopeId, target: PeerId, path: ExplicitPath) {
        self.routes
            .lock()
            .insert((scope, target, path.plane), path);
    }
}

#[async_trait]
impl PathSource for StaticMapPathSource {
    async fn resolve(
        &self,
        scope: &ScopeId,
        target: &PeerId,
        plane: Plane,
    ) -> Result<ExplicitPath> {
        self.routes
            .lock()
            .get(&(scope.clone(), *target, plane))
            .cloned()
            .ok_or_else(|| {
                CoreError::PathSetupFailed(format!(
                    "no explicit path configured for ({scope}, {target}, {plane})"
                ))
            })
    }
}
