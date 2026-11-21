use crate::error::Result;
use crate::types::{ChannelAddr, ChannelId, OpaqueCredential, PeerId, Plane, ScopeId, TargetTag};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// One intermediate hop in an explicit multi-hop route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathHop {
    /// 8-byte opaque tag selecting the forwardable channel on this hop.
    pub target_tag: TargetTag,
    /// Static X25519 public key of that forwardable channel (for direct `channel <-> originator` auth).
    pub channel_pubkey: PeerId,
    /// Address or slot identifier passed inside the encrypted setup payload to this hop's channel.
    pub next_addr: ChannelAddr,
    /// Optional bounded credential verified only by this hop's channel `AccessControl` plugin.
    pub credential: Option<OpaqueCredential>,
}

/// A single, explicit path from an originator to a destination peer's Trust Scope.
///
/// Core never discovers, probes, races, or auto-switches paths; it validates and executes
/// the single `ExplicitPath` supplied by `PathSource`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplicitPath {
    /// Required end-to-end plane (`Datagram` or `Stream`).
    pub plane: Plane,
    /// Local outbound carrier on the originator used to enter the path.
    pub entry_channel: ChannelId,
    /// First-hop address dialed/sent to via `entry_channel` (either `H1` or directly `B`).
    pub entry_addr: ChannelAddr,
    /// Ordered sequence of intermediate forwardable channels (`empty` for direct `A -> B`).
    pub hops: Vec<PathHop>,
    /// 8-byte opaque tag selecting destination `B`'s Trust Scope.
    pub target_scope_tag: TargetTag,
    /// Destination `B`'s static X25519 public key within the Trust Scope.
    pub target_pubkey: PeerId,
    /// Optional bounded credential verified only by destination `B`'s `AccessControl` plugin.
    pub target_credential: Option<OpaqueCredential>,
}

/// Route / Path Source extension seam (Seam 2).
#[async_trait]
pub trait PathSource: Send + Sync + 'static {
    /// Resolves the single explicit path to `target` within `scope` on `plane`.
    async fn resolve(&self, scope: &ScopeId, target: &PeerId, plane: Plane)
        -> Result<ExplicitPath>;
}
