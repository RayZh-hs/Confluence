#![forbid(unsafe_code)]
//! Static TOML-driven allowlist and bounded `Grant` policy backend implementing Seam 3 (`AccessControl`).

use async_trait::async_trait;
use confluence_core::seams::access::{
    AccessControl, AccessRequest, Action, Decision, Grant, RevocationEvent,
};
use confluence_core::{CoreError, EndpointName, PeerId, Plane, Result, ScopeId};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

/// Declarative kind matcher for a policy rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleActionKind {
    OpenEndpoint,
    ChannelForward,
    ChannelCustom,
    Any,
}

/// One static authorization rule evaluated on control events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRuleConfig {
    /// Scope name (`"*"` or `None` matches any scope).
    pub scope: Option<String>,
    /// Allowed peer hex public keys (`["*"]` matches any authenticated peer).
    pub peers: Vec<String>,
    /// Action category matched by this rule.
    pub action: RuleActionKind,
    /// Optional plane restriction (`stream` or `datagram`).
    pub plane: Option<Plane>,
    /// Optional target name (`endpoint` for `open_endpoint`, `next_addr` for `channel_forward`,
    /// or `kind` / `kind:target` for `channel_custom`; `"*"` matches any).
    pub target: Option<String>,
    /// Optional opaque UTF-8 credential required to match this rule.
    pub required_credential: Option<String>,
    /// Grant TTL in seconds when matched (overrides `default_ttl_secs`).
    pub ttl_secs: Option<u64>,
    pub max_bytes_per_sec: Option<u64>,
    pub max_datagrams_per_sec: Option<u64>,
    pub max_concurrent_streams: Option<u32>,
}

/// Top-level static policy configuration loadable from TOML.
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

/// Static allowlist `AccessControl` implementation with live local revocation support.
pub struct StaticPolicy {
    config: RwLock<PolicyConfig>,
    active_revocations: RwLock<Vec<RevocationEvent>>,
    rev_tx: broadcast::Sender<RevocationEvent>,
}

impl StaticPolicy {
    pub fn new(config: PolicyConfig) -> Arc<Self> {
        let (rev_tx, _) = broadcast::channel(256);
        Arc::new(Self {
            config: RwLock::new(config),
            active_revocations: RwLock::new(Vec::new()),
            rev_tx,
        })
    }

    pub fn from_toml_str(toml_str: &str) -> Result<Arc<Self>> {
        let cfg: PolicyConfig = toml::from_str(toml_str)
            .map_err(|e| CoreError::InvalidInput(format!("invalid policy TOML: {e}")))?;
        Ok(Self::new(cfg))
    }

    /// Records a permanent local revocation and broadcasts `event` to immediately tear down live sessions.
    pub fn revoke(&self, event: RevocationEvent) {
        self.active_revocations.write().push(event.clone());
        let _ = self.rev_tx.send(event);
    }

    pub fn revoke_peer(&self, scope: Option<ScopeId>, peer: PeerId) {
        self.revoke(RevocationEvent {
            scope,
            peer: Some(peer),
            endpoint: None,
        });
    }
}

fn extract_endpoint(action: &Action) -> Option<&EndpointName> {
    match action {
        Action::OpenEndpoint { endpoint, .. } => Some(endpoint),
        Action::RenewGrant { target_action } => extract_endpoint(target_action),
        _ => None,
    }
}

fn unwrap_action(action: &Action) -> &Action {
    match action {
        Action::RenewGrant { target_action } => unwrap_action(target_action),
        other => other,
    }
}

fn rule_matches(rule: &PolicyRuleConfig, req: &AccessRequest) -> bool {
    if let Some(ref s) = rule.scope {
        if s != "*" && s != req.scope.as_str() {
            return false;
        }
    }

    let peer_hex = req.peer.to_string();
    if !rule.peers.iter().any(|p| p == "*" || p.eq_ignore_ascii_case(&peer_hex)) {
        return false;
    }

    if let Some(ref req_cred) = rule.required_credential {
        match req.credential {
            Some(ref c) if c.as_bytes() == req_cred.as_bytes() => {}
            _ => return false,
        }
    }

    let core_action = unwrap_action(&req.action);
    let action_plane = match core_action {
        Action::OpenEndpoint { plane, .. }
        | Action::ChannelForward { plane, .. }
        | Action::ChannelCustom { plane, .. } => *plane,
        Action::RenewGrant { .. } => unreachable!(),
    };
    if let Some(p) = rule.plane {
        if p != action_plane {
            return false;
        }
    }

    match (&rule.action, core_action) {
        (RuleActionKind::Any, _) => true,
        (RuleActionKind::OpenEndpoint, Action::OpenEndpoint { endpoint, .. }) => {
            match rule.target.as_deref() {
                None | Some("*") => true,
                Some(t) => t == endpoint.as_str(),
            }
        }
        (RuleActionKind::ChannelForward, Action::ChannelForward { target, .. }) => {
            match rule.target.as_deref() {
                None | Some("*") => true,
                Some(t) => t == target.as_str(),
            }
        }
        (RuleActionKind::ChannelCustom, Action::ChannelCustom { kind, target, .. }) => {
            match rule.target.as_deref() {
                None | Some("*") => true,
                Some(t) => t == kind || t == format!("{kind}:{target}"),
            }
        }
        _ => false,
    }
}

#[async_trait]
impl AccessControl for StaticPolicy {
    async fn evaluate(&self, req: AccessRequest) -> Result<Decision> {
        let ep = extract_endpoint(&req.action);
        if self
            .active_revocations
            .read()
            .iter()
            .any(|rev| rev.matches(&req.scope, &req.peer, ep))
        {
            return Ok(Decision::Deny {
                reason: "revoked by local policy".into(),
            });
        }

        let cfg = self.config.read();
        for rule in &cfg.rules {
            if rule_matches(rule, &req) {
                let ttl = Duration::from_secs(rule.ttl_secs.unwrap_or(cfg.default_ttl_secs).max(1));
                return Ok(Decision::Allow(Grant {
                    expires_at: Instant::now() + ttl,
                    max_bytes_per_sec: rule.max_bytes_per_sec,
                    max_datagrams_per_sec: rule.max_datagrams_per_sec,
                    max_concurrent_streams: rule.max_concurrent_streams,
                }));
            }
        }

        if cfg.default_allow {
            Ok(Decision::Allow(Grant::with_ttl(Duration::from_secs(
                cfg.default_ttl_secs.max(1),
            ))))
        } else {
            Ok(Decision::Deny {
                reason: "no matching allow rule in static policy".into(),
            })
        }
    }

    fn revocations(&self) -> broadcast::Receiver<RevocationEvent> {
        self.rev_tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use confluence_core::{OpaqueCredential, StaticKeypair};

    #[tokio::test]
    async fn static_policy_toml_matching_renewal_and_revocation() {
        let alice = StaticKeypair::generate().peer_id();
        let eve = StaticKeypair::generate().peer_id();

        let toml_cfg = format!(
            r#"
            default_allow = false
            default_ttl_secs = 120

            [[rules]]
            scope = "prod"
            peers = ["{alice}"]
            action = "open_endpoint"
            plane = "stream"
            target = "api"
            required_credential = "tok-123"
            ttl_secs = 60
            max_bytes_per_sec = 1048576
            max_concurrent_streams = 8
            "#
        );

        let policy = StaticPolicy::from_toml_str(&toml_cfg).unwrap();
        let scope = ScopeId::new("prod").unwrap();
        let ep = EndpointName::new("api").unwrap();

        // Alice with valid credential -> Allow with configured bounds.
        let req_ok = AccessRequest {
            scope: scope.clone(),
            peer: alice,
            credential: Some(OpaqueCredential::from_utf8("tok-123").unwrap()),
            action: Action::OpenEndpoint {
                endpoint: ep.clone(),
                plane: Plane::Stream,
            },
        };
        match policy.evaluate(req_ok.clone()).await.unwrap() {
            Decision::Allow(g) => {
                assert_eq!(g.max_bytes_per_sec, Some(1_048_576));
                assert_eq!(g.max_concurrent_streams, Some(8));
            }
            Decision::Deny { reason } => panic!("expected allow, got {reason}"),
        }

        // Eve -> Deny.
        let mut req_eve = req_ok.clone();
        req_eve.peer = eve;
        assert!(matches!(
            policy.evaluate(req_eve).await.unwrap(),
            Decision::Deny { .. }
        ));

        // Renewal of allowed action -> Allow.
        let req_renew = AccessRequest {
            scope: scope.clone(),
            peer: alice,
            credential: Some(OpaqueCredential::from_utf8("tok-123").unwrap()),
            action: Action::RenewGrant {
                target_action: Box::new(Action::OpenEndpoint {
                    endpoint: ep,
                    plane: Plane::Stream,
                }),
            },
        };
        assert!(matches!(
            policy.evaluate(req_renew).await.unwrap(),
            Decision::Allow(_)
        ));

        // Revoke Alice -> subsequent evaluation immediately Denied!
        policy.revoke_peer(Some(scope), alice);
        assert!(matches!(
            policy.evaluate(req_ok).await.unwrap(),
            Decision::Deny { .. }
        ));
    }
}
