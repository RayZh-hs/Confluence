use crate::error::Result;
use crate::seams::channel::BoxedAsyncStream;
use crate::types::{EndpointName, OpaqueCredential, PeerId, ScopeId};
use async_trait::async_trait;
use bytes::Bytes;

/// End-to-end authenticated datagram session abstraction exposed to Edge Adapters (Seam 4).
#[async_trait]
pub trait DatagramSession: Send + Sync + 'static {
    /// Authenticated remote peer identity.
    fn remote_peer(&self) -> PeerId;

    /// Scope within which this session operates.
    fn scope(&self) -> &ScopeId;

    /// Target endpoint name.
    fn endpoint(&self) -> &EndpointName;

    /// Sends an end-to-end encrypted discrete datagram over the session.
    async fn send(&self, payload: &[u8]) -> Result<()>;

    /// Receives the next decrypted discrete datagram from the session.
    async fn recv(&self) -> Result<Bytes>;

    /// Renews the session's authorization Grant in-band without interrupting live traffic.
    async fn renew(&self, credential: Option<OpaqueCredential>) -> Result<()>;

    /// Explicitly closes the session and notifies the peer.
    async fn close(&self) -> Result<()>;
}

/// End-to-end authenticated byte stream metadata delivered to a published Stream endpoint (Seam 4).
pub struct InboundStream<S = BoxedAsyncStream> {
    pub remote_peer: PeerId,
    pub scope: ScopeId,
    pub endpoint: EndpointName,
    pub stream: S,
}
