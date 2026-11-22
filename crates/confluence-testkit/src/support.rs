//! Auditing [`Authorizer`] test fixture for proving control-only policy evaluation
//! (zero evaluations per data packet) and live revocation fan-out.

use confluence_core::{
    AuthDenied, AuthRequest, Authorizer, BoxFut, Lease, Plane, PublicKey, Revocation, TargetRef,
};
use parking_lot::Mutex;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::broadcast;

/// Owned snapshot of an [`Authorizer::authorize`] call recorded by [`AuditAuthorizer`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedAuth {
    pub peer: PublicKey,
    pub plane: Plane,
    pub is_transit: bool,
    pub target: String,
    pub credential: Vec<u8>,
    pub is_renewal: bool,
}

type RulePredicate =
    Box<dyn Fn(AuthRequest<'_>) -> Option<Result<Lease, AuthDenied>> + Send + Sync>;

/// Deterministic [`Authorizer`] fixture recording exact control-plane evaluation counts
/// and supporting instant revocation broadcasts.
pub struct AuditAuthorizer {
    default_ttl: Option<Duration>,
    rules: Mutex<Vec<RulePredicate>>,
    evaluations: AtomicUsize,
    recorded: Mutex<Vec<RecordedAuth>>,
    events: broadcast::Sender<Revocation>,
}

impl AuditAuthorizer {
    /// Allows all authenticated peers by default with `default_ttl`.
    pub fn allow_all(default_ttl: Duration) -> Arc<Self> {
        Self::with_default_ttl(Some(default_ttl))
    }

    /// Denies by default unless an added rule matches.
    pub fn deny_by_default() -> Arc<Self> {
        Self::with_default_ttl(None)
    }

    /// Uses `default_ttl` when no explicit rule matches.
    pub fn with_default_ttl(default_ttl: Option<Duration>) -> Arc<Self> {
        Arc::new(Self {
            default_ttl,
            rules: Default::default(),
            evaluations: AtomicUsize::new(0),
            recorded: Default::default(),
            events: broadcast::channel(64).0,
        })
    }

    /// Appends a custom decision rule evaluated in insertion order.
    pub fn add_rule<F>(&self, rule: F)
    where
        F: Fn(AuthRequest<'_>) -> Option<Result<Lease, AuthDenied>> + Send + Sync + 'static,
    {
        self.rules.lock().push(Box::new(rule));
    }

    /// Total number of times `Authorizer::authorize` has been invoked.
    pub fn evaluation_count(&self) -> usize {
        self.evaluations.load(Ordering::Acquire)
    }

    /// Snapshot of all recorded authorization requests.
    pub fn requests(&self) -> Vec<RecordedAuth> {
        self.recorded.lock().clone()
    }

    /// Emits a live revocation event to all scopes attached to this authorizer.
    pub fn trigger_revocation(&self, event: Revocation) {
        let _ = self.events.send(event);
    }
}

impl Authorizer for AuditAuthorizer {
    fn authorize<'a>(&'a self, req: AuthRequest<'a>) -> BoxFut<'a, Result<Lease, AuthDenied>> {
        self.evaluations.fetch_add(1, Ordering::AcqRel);
        self.recorded.lock().push(RecordedAuth {
            peer: req.peer,
            plane: req.target.plane(),
            is_transit: req.target.is_transit(),
            target: req.target.name().to_owned(),
            credential: req.credential.to_vec(),
            is_renewal: req.is_renewal,
        });

        let decision = {
            let rules = self.rules.lock();
            let mut matched = None;
            for rule in rules.iter() {
                if let Some(res) = rule(req) {
                    matched = Some(res);
                    break;
                }
            }
            matched.unwrap_or_else(|| self.default_ttl.map(Lease::new).ok_or(AuthDenied::Denied))
        };
        Box::pin(async move { decision })
    }

    fn revocations(&self) -> Option<broadcast::Receiver<Revocation>> {
        Some(self.events.subscribe())
    }
}

/// Helper predicate check matching `TargetRef::Endpoint` or `TargetRef::Transit`.
pub fn target_kind_label(target: TargetRef<'_>) -> &'static str {
    if target.is_endpoint() {
        "endpoint"
    } else {
        "transit"
    }
}
