//! Out-of-core plugin suite evaluating Confluence Core's modularity and composition.
//!
//! Built strictly against the public API of `confluence-core` (and existing helper crates)
//! without modifying core internals.

pub mod acl;
pub mod cross_plane;
pub mod encrypted;
pub mod tailscale_mesh;
pub mod udp_p2p;

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
