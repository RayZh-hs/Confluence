//! Static in-memory & TOML-driven [`Authorizer`], [`CredentialProvider`], and [`PathSource`]
//! plugins.

use confluence_core::{
    AuthDenied, AuthRequest, Authorizer, BoxFut, CoreErr, CredentialProvider, CredentialRequest,
    ExplicitPath, Lease, PathOutcome, PathSource, Plane, PublicKey, Revocation, TargetRef,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::broadcast;

use crate::qos::{ConcurrencyLimiter, QosLimits, RateGate};

/// Minimal programmatic peer allowlist implementing [`Authorizer`].
pub struct StaticAuthorizer {
    leases: RwLock<HashMap<PublicKey, Lease>>,
    events: broadcast::Sender<Revocation>,
}

impl Default for StaticAuthorizer {
    fn default() -> Self {
        Self {
            leases: Default::default(),
            events: broadcast::channel(128).0,
        }
    }
}

impl StaticAuthorizer {
    /// Allows `peer` with `lease` for any endpoint or transit target on this scope.
    pub fn allow(&self, peer: PublicKey, lease: Lease) {
        self.leases.write().insert(peer, lease);
    }

    /// Convenience helper allowing `peer` with a simple `ttl` and no extra context.
    pub fn allow_ttl(&self, peer: PublicKey, ttl: Duration) {
        self.allow(peer, Lease::new(ttl));
    }

    /// Removes `peer` and broadcasts an immediate revocation event.
    pub fn revoke(&self, peer: PublicKey) {
        self.leases.write().remove(&peer);
        let _ = self.events.send(Revocation::Peer(peer));
    }
}

impl Authorizer for StaticAuthorizer {
    fn authorize<'a>(&'a self, req: AuthRequest<'a>) -> BoxFut<'a, Result<Lease, AuthDenied>> {
        Box::pin(async move {
            self.leases
                .read()
                .get(&req.peer)
                .cloned()
                .ok_or(AuthDenied::Denied)
        })
    }

    fn revocations(&self) -> Option<broadcast::Receiver<Revocation>> {
        Some(self.events.subscribe())
    }
}

/// Declarative target category matched by a [`StaticPolicy`] rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleTargetKind {
    Endpoint,
    Transit,
    Any,
}

/// One declarative authorization rule evaluated on control events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRuleConfig {
    /// Optional scope name filter (`None` matches any scope).
    pub scope: Option<String>,
    /// Allowed peer hex public keys (`["*"]` matches any authenticated peer).
    pub peers: Vec<String>,
    /// Target kind matched by this rule (`"endpoint"`, `"transit"`, or `"any"`).
    pub action: RuleTargetKind,
    /// Optional plane restriction (`"stream"` or `"datagram"`).
    pub plane: Option<Plane>,
    /// Optional target name match (`"*"` or trailing-`*` prefix like `"relay/*"`).
    pub target: Option<String>,
    /// Optional opaque UTF-8 credential required to match this rule.
    pub required_credential: Option<String>,
    /// Lease TTL in seconds when matched (overrides `default_ttl_secs`).
    pub ttl_secs: Option<u64>,
    /// Optional out-of-core byte rate limit attached via [`QosLimits`] in `Lease::context`.
    pub max_bytes_per_sec: Option<u64>,
    /// Optional out-of-core datagram-per-second cap attached via [`QosLimits`].
    pub max_datagrams_per_sec: Option<u64>,
    /// Optional out-of-core concurrent stream cap attached via [`QosLimits`].
    pub max_concurrent_streams: Option<u32>,
}

/// Top-level TOML-loadable static policy configuration (fails closed by default).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub default_allow: bool,
    #[serde(default = "default_ttl_secs")]
    pub default_ttl_secs: u64,
    #[serde(default)]
    pub rules: Vec<PolicyRuleConfig>,
}

fn default_ttl_secs() -> u64 {
    300
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default_allow: false,
            default_ttl_secs: default_ttl_secs(),
            rules: Vec::new(),
        }
    }
}

/// Rich TOML-driven [`Authorizer`] supporting named endpoints, named transits (including
/// wildcard prefix rules like `"relay/*"`), credential matching, out-of-core [`RateGate`] and
/// [`ConcurrencyLimiter`] enforcement directly on [`Lease`], and live revocations.
pub struct StaticPolicy {
    scope_name: Option<String>,
    config: RwLock<PolicyConfig>,
    revoked_peers: RwLock<Vec<PublicKey>>,
    limiter: Arc<ConcurrencyLimiter<(PublicKey, Plane, String)>>,
    events: broadcast::Sender<Revocation>,
}

impl StaticPolicy {
    /// Creates a policy engine from a parsed [`PolicyConfig`].
    pub fn new(config: PolicyConfig) -> Self {
        Self {
            scope_name: None,
            config: RwLock::new(config),
            revoked_peers: Default::default(),
            limiter: ConcurrencyLimiter::new(),
            events: broadcast::channel(128).0,
        }
    }

    /// Creates a policy engine scoped to rules matching `scope_name` (or wildcard `scope = None`).
    pub fn for_scope(config: PolicyConfig, scope_name: impl Into<String>) -> Self {
        Self {
            scope_name: Some(scope_name.into()),
            config: RwLock::new(config),
            revoked_peers: Default::default(),
            limiter: ConcurrencyLimiter::new(),
            events: broadcast::channel(128).0,
        }
    }

    /// Parses a [`PolicyConfig`] from TOML text.
    pub fn from_toml_str(toml_str: &str) -> Result<Self, CoreErr> {
        let cfg: PolicyConfig = toml::from_str(toml_str).map_err(|_| CoreErr::Malformed)?;
        Ok(Self::new(cfg))
    }

    /// Revokes `peer` and broadcasts a live teardown event.
    pub fn revoke_peer(&self, peer: PublicKey) {
        self.revoked_peers.write().push(peer);
        let _ = self.events.send(Revocation::Peer(peer));
    }

    /// Broadcasts a live teardown event for all sessions bound to endpoint `name`.
    pub fn revoke_endpoint(&self, name: impl Into<String>) {
        let _ = self.events.send(Revocation::Endpoint(name.into()));
    }

    /// Broadcasts a live teardown event for all circuits bound to transit `name`.
    pub fn revoke_transit(&self, name: impl Into<String>) {
        let _ = self.events.send(Revocation::Transit(name.into()));
    }

    fn rule_matches(
        scope_name: Option<&str>,
        rule: &PolicyRuleConfig,
        req: AuthRequest<'_>,
    ) -> bool {
        if let Some(req_scope) = rule.scope.as_deref()
            && scope_name != Some(req_scope)
        {
            return false;
        }
        let peer_hex = req.peer.to_string();
        if !rule
            .peers
            .iter()
            .any(|p| p == "*" || p.eq_ignore_ascii_case(&peer_hex))
        {
            return false;
        }
        if let Some(ref req_cred) = rule.required_credential
            && req.credential != req_cred.as_bytes()
        {
            return false;
        }
        if let Some(req_plane) = rule.plane
            && req_plane != req.target.plane()
        {
            return false;
        }
        let kind_ok = matches!(
            (rule.action, req.target),
            (RuleTargetKind::Any, _)
                | (RuleTargetKind::Endpoint, TargetRef::Endpoint { .. })
                | (RuleTargetKind::Transit, TargetRef::Transit { .. })
        );
        if !kind_ok {
            return false;
        }
        rule.target
            .as_deref()
            .is_none_or(|pattern| target_matches(pattern, req.target.name()))
    }
}

fn target_matches(pattern: &str, actual: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        actual.starts_with(prefix)
    } else {
        pattern == actual
    }
}

impl Authorizer for StaticPolicy {
    fn authorize<'a>(&'a self, req: AuthRequest<'a>) -> BoxFut<'a, Result<Lease, AuthDenied>> {
        Box::pin(async move {
            if self.revoked_peers.read().contains(&req.peer) {
                return Err(AuthDenied::Denied);
            }
            let cfg = self.config.read();
            for rule in &cfg.rules {
                if Self::rule_matches(self.scope_name.as_deref(), rule, req) {
                    let ttl = Duration::from_secs(rule.ttl_secs.unwrap_or(cfg.default_ttl_secs));
                    let mut lease = Lease::new(ttl);
                    let qos = QosLimits {
                        max_bytes_per_sec: rule.max_bytes_per_sec.unwrap_or(0),
                        max_datagrams_per_sec: rule.max_datagrams_per_sec.unwrap_or(0),
                        max_concurrent_streams: rule.max_concurrent_streams.unwrap_or(0),
                    };
                    if req.target.plane() == Plane::Stream && qos.max_concurrent_streams > 0 {
                        let key = (req.peer, req.target.plane(), req.target.name().to_owned());
                        if let Some(slot) =
                            self.limiter
                                .acquire(key, qos.max_concurrent_streams, req.is_renewal)?
                        {
                            lease = lease.with_guard(slot);
                        }
                    }
                    if qos.has_rate_limit() {
                        lease = lease.with_gate(RateGate::new(qos));
                    }
                    if !qos.is_unlimited() {
                        lease = lease.with_context(qos);
                    }
                    return Ok(lease);
                }
            }
            if cfg.default_allow {
                Ok(Lease::new(Duration::from_secs(cfg.default_ttl_secs)))
            } else {
                Err(AuthDenied::Denied)
            }
        })
    }

    fn revocations(&self) -> Option<broadcast::Receiver<Revocation>> {
        Some(self.events.subscribe())
    }
}

/// One declarative credential entry for [`StaticCredentials`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRuleConfig {
    /// Optional verifier public key (`None` matches any verifier).
    pub verifier: Option<PublicKey>,
    /// Target kind (`"endpoint"`, `"transit"`, or `"any"`).
    #[serde(default = "default_any_kind")]
    pub action: RuleTargetKind,
    /// Optional plane restriction (`"stream"` or `"datagram"`).
    pub plane: Option<Plane>,
    /// Optional target name pattern (`"*"` or `"prefix*"`).
    pub target: Option<String>,
    /// Opaque UTF-8 credential value presented to the verifier.
    pub credential: String,
}

fn default_any_kind() -> RuleTargetKind {
    RuleTargetKind::Any
}

#[derive(Clone, Debug)]
struct CredRule {
    verifier: Option<PublicKey>,
    kind: RuleTargetKind,
    plane: Option<Plane>,
    target: Option<String>,
    credential: Vec<u8>,
}

/// Rule-based static [`CredentialProvider`] mapping `(verifier, target)` to opaque credentials.
///
/// Supports live updates (`set_endpoint`, `set_transit`, `set_default`), so rotating a token
/// takes effect automatically on the next in-band lease renewal.
#[derive(Default)]
pub struct StaticCredentials {
    rules: RwLock<Vec<CredRule>>,
    default: RwLock<Vec<u8>>,
}

impl StaticCredentials {
    /// Builds a provider from declarative [`CredentialRuleConfig`] entries.
    pub fn from_configs(configs: &[CredentialRuleConfig]) -> Self {
        let rules = configs
            .iter()
            .map(|c| CredRule {
                verifier: c.verifier,
                kind: c.action,
                plane: c.plane,
                target: c.target.clone(),
                credential: c.credential.as_bytes().to_vec(),
            })
            .collect();
        Self {
            rules: RwLock::new(rules),
            default: Default::default(),
        }
    }

    /// Sets the credential presented to `destination` when opening `endpoint`.
    pub fn set_endpoint(
        &self,
        destination: PublicKey,
        endpoint: impl Into<String>,
        credential: impl Into<Vec<u8>>,
    ) {
        let ep = endpoint.into();
        let cred = credential.into();
        let mut rules = self.rules.write();
        if let Some(existing) = rules.iter_mut().find(|r| {
            r.verifier == Some(destination)
                && r.kind == RuleTargetKind::Endpoint
                && r.target.as_deref() == Some(ep.as_str())
                && r.plane.is_none()
        }) {
            existing.credential = cred;
            return;
        }
        rules.push(CredRule {
            verifier: Some(destination),
            kind: RuleTargetKind::Endpoint,
            plane: None,
            target: Some(ep),
            credential: cred,
        });
    }

    /// Sets the credential presented to intermediate hop `hop_peer` for named transit `target`.
    pub fn set_transit(
        &self,
        hop_peer: PublicKey,
        target: impl Into<String>,
        credential: impl Into<Vec<u8>>,
    ) {
        let tgt = target.into();
        let cred = credential.into();
        let mut rules = self.rules.write();
        if let Some(existing) = rules.iter_mut().find(|r| {
            r.verifier == Some(hop_peer)
                && r.kind == RuleTargetKind::Transit
                && r.target.as_deref() == Some(tgt.as_str())
                && r.plane.is_none()
        }) {
            existing.credential = cred;
            return;
        }
        rules.push(CredRule {
            verifier: Some(hop_peer),
            kind: RuleTargetKind::Transit,
            plane: None,
            target: Some(tgt),
            credential: cred,
        });
    }

    /// Sets a fallback credential used when no specific rule matches.
    pub fn set_default(&self, credential: impl Into<Vec<u8>>) {
        *self.default.write() = credential.into();
    }
}

impl CredentialProvider for StaticCredentials {
    fn credential<'a>(
        &'a self,
        req: CredentialRequest<'a>,
    ) -> BoxFut<'a, Result<Vec<u8>, CoreErr>> {
        let found = {
            let rules = self.rules.read();
            rules
                .iter()
                .find(|r| {
                    if let Some(v) = r.verifier
                        && v != req.verifier
                    {
                        return false;
                    }
                    if let Some(p) = r.plane
                        && p != req.target.plane()
                    {
                        return false;
                    }
                    let kind_ok = matches!(
                        (r.kind, req.target),
                        (RuleTargetKind::Any, _)
                            | (RuleTargetKind::Endpoint, TargetRef::Endpoint { .. })
                            | (RuleTargetKind::Transit, TargetRef::Transit { .. })
                    );
                    if !kind_ok {
                        return false;
                    }
                    r.target
                        .as_deref()
                        .is_none_or(|pattern| target_matches(pattern, req.target.name()))
                })
                .map(|r| r.credential.clone())
        };
        let cred = found.unwrap_or_else(|| self.default.read().clone());
        Box::pin(async move { Ok(cred) })
    }
}

type RouteKey = (PublicKey, String, Plane);

/// Static explicit path table implementing [`PathSource`] (Seam 2).
pub struct StaticPathSource {
    routes: RwLock<HashMap<RouteKey, ExplicitPath>>,
    outcomes: broadcast::Sender<(u64, PathOutcome)>,
}

impl Default for StaticPathSource {
    fn default() -> Self {
        Self {
            routes: Default::default(),
            outcomes: broadcast::channel(128).0,
        }
    }
}

impl StaticPathSource {
    /// Registers an explicit path for `(peer, endpoint, plane)`.
    pub fn set(
        &self,
        peer: PublicKey,
        endpoint: impl Into<String>,
        plane: Plane,
        path: ExplicitPath,
    ) {
        self.routes
            .write()
            .insert((peer, endpoint.into(), plane), path);
    }

    /// Subscribes to all [`PathOutcome`] feedback reported by Core.
    pub fn outcomes(&self) -> broadcast::Receiver<(u64, PathOutcome)> {
        self.outcomes.subscribe()
    }
}

impl PathSource for StaticPathSource {
    fn resolve_path<'a>(
        &'a self,
        peer: &'a PublicKey,
        endpoint: &'a str,
        plane: Plane,
    ) -> BoxFut<'a, Result<ExplicitPath, CoreErr>> {
        Box::pin(async move {
            self.routes
                .read()
                .get(&(*peer, endpoint.into(), plane))
                .cloned()
                .ok_or(CoreErr::NoPath)
        })
    }

    fn report_outcome(&self, path_id: u64, outcome: PathOutcome) {
        let _ = self.outcomes.send((path_id, outcome));
    }
}
