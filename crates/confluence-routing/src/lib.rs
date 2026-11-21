#![forbid(unsafe_code)]
//! Static TOML-driven `ExplicitPath` resolver implementing Seam 2 (`PathSource`).

use async_trait::async_trait;
use confluence_core::seams::routing::{ExplicitPath, PathHop, PathSource};
use confluence_core::{
    ChannelAddr, ChannelId, CoreError, OpaqueCredential, PeerId, Plane, Result, ScopeId,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteHopConfig {
    pub channel_pubkey: PeerId,
    pub next_addr: String,
    pub credential: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntryConfig {
    pub scope: String,
    pub target_pubkey: PeerId,
    pub plane: Plane,
    pub entry_channel: String,
    pub entry_addr: String,
    pub target_credential: Option<String>,
    #[serde(default)]
    pub hops: Vec<RouteHopConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoutingConfig {
    #[serde(default)]
    pub routes: Vec<RouteEntryConfig>,
}

/// Static explicit path table implementing [`PathSource`] (Seam 2).
///
/// Upholds Cleanroom Invariant #4: supplies the single explicit route configured for
/// `(scope, target_peer, plane)` with zero auto-routing or implicit cross-plane fallback.
#[derive(Default)]
pub struct StaticRouter {
    table: RwLock<HashMap<(ScopeId, PeerId, Plane), ExplicitPath>>,
}

impl StaticRouter {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn from_config(cfg: &RoutingConfig) -> Result<Arc<Self>> {
        let router = Self::new();
        for entry in &cfg.routes {
            let scope = ScopeId::new(&entry.scope)?;
            let mut hops = Vec::with_capacity(entry.hops.len());
            for h in &entry.hops {
                let cred = match h.credential {
                    Some(ref s) => Some(OpaqueCredential::from_utf8(s)?),
                    None => None,
                };
                hops.push(PathHop {
                    target_tag: h.channel_pubkey.target_tag(),
                    channel_pubkey: h.channel_pubkey,
                    next_addr: ChannelAddr::new(&h.next_addr)?,
                    credential: cred,
                });
            }
            let target_credential = match entry.target_credential {
                Some(ref s) => Some(OpaqueCredential::from_utf8(s)?),
                None => None,
            };
            let path = ExplicitPath {
                plane: entry.plane,
                entry_channel: ChannelId::new(&entry.entry_channel)?,
                entry_addr: ChannelAddr::new(&entry.entry_addr)?,
                hops,
                target_scope_tag: entry.target_pubkey.target_tag(),
                target_pubkey: entry.target_pubkey,
                target_credential,
            };
            router.upsert_route(scope, path);
        }
        Ok(router)
    }

    pub fn from_toml_str(toml_str: &str) -> Result<Arc<Self>> {
        let cfg: RoutingConfig = toml::from_str(toml_str)
            .map_err(|e| CoreError::InvalidInput(format!("invalid routing TOML: {e}")))?;
        Self::from_config(&cfg)
    }

    pub fn upsert_route(&self, scope: ScopeId, path: ExplicitPath) {
        self.table
            .write()
            .insert((scope, path.target_pubkey, path.plane), path);
    }

    pub fn remove_route(&self, scope: &ScopeId, target: &PeerId, plane: Plane) {
        self.table.write().remove(&(scope.clone(), *target, plane));
    }
}

#[async_trait]
impl PathSource for StaticRouter {
    async fn resolve(
        &self,
        scope: &ScopeId,
        target: &PeerId,
        plane: Plane,
    ) -> Result<ExplicitPath> {
        self.table
            .read()
            .get(&(scope.clone(), *target, plane))
            .cloned()
            .ok_or_else(|| {
                CoreError::PathSetupFailed(format!(
                    "no explicit {plane} route configured to peer {target} in scope '{scope}'"
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use confluence_core::StaticKeypair;

    #[tokio::test]
    async fn static_router_parses_multihop_toml_and_enforces_plane_key() {
        let bob = StaticKeypair::generate().peer_id();
        let hop1 = StaticKeypair::generate().peer_id();

        let toml_str = format!(
            r#"
            [[routes]]
            scope = "lab"
            target_pubkey = "{bob}"
            plane = "stream"
            entry_channel = "tcp0"
            entry_addr = "127.0.0.1:7000"
            target_credential = "bob-cred"

            [[routes.hops]]
            channel_pubkey = "{hop1}"
            next_addr = "127.0.0.1:8000"
            credential = "hop1-cred"
            "#
        );

        let router = StaticRouter::from_toml_str(&toml_str).unwrap();
        let scope = ScopeId::new("lab").unwrap();

        let stream_path = router.resolve(&scope, &bob, Plane::Stream).await.unwrap();
        assert_eq!(stream_path.hops.len(), 1);
        assert_eq!(stream_path.hops[0].target_tag, hop1.target_tag());
        assert_eq!(stream_path.target_scope_tag, bob.target_tag());

        // Datagram plane route was not configured -> must fail explicitly (no cross-plane fallback!).
        assert!(router.resolve(&scope, &bob, Plane::Datagram).await.is_err());
    }
}
