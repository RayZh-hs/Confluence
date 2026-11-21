use crate::error::{CoreError, Result};
use crate::types::{ChannelAddr, ChannelId, Plane, TargetTag};
use async_trait::async_trait;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

/// Semantic capabilities declared by a transport carrier or composable channel plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelCaps {
    /// The traffic plane exposed by this channel.
    pub plane: Plane,
    /// Whether the underlying link guarantees reliable delivery.
    pub reliable_underlay: bool,
    /// Whether the underlying link guarantees in-order delivery.
    pub ordered_underlay: bool,
    /// Maximum discrete payload size (required for datagram channels).
    pub max_payload_bytes: Option<usize>,
}

/// Health state surfaced upward by a channel so Core can reject or tear down broken paths honestly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelHealth {
    Healthy,
    Degraded(String),
    Closed(String),
}

impl ChannelHealth {
    pub fn is_usable(&self) -> bool {
        !matches!(self, ChannelHealth::Closed(_))
    }
}

/// Trait alias for asynchronous bidirectional byte streams.
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> AsyncStream for T {}

/// Heap-allocated asynchronous bidirectional byte stream.
pub type BoxedAsyncStream = Pin<Box<dyn AsyncStream>>;

/// Raw connectivity carrier on the Datagram Plane (Seam 1).
#[async_trait]
pub trait DatagramChannel: Send + Sync + 'static {
    /// Local identifier of this datagram carrier.
    fn id(&self) -> &ChannelId;

    /// Declared capabilities (must declare `Plane::Datagram` and `max_payload_bytes`).
    fn caps(&self) -> ChannelCaps;

    /// Sends a discrete datagram to `addr`.
    async fn send_to(&self, addr: &ChannelAddr, payload: &[u8]) -> Result<()>;

    /// Receives a discrete datagram into `buf`, returning `(bytes_read, source_addr)`.
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, ChannelAddr)>;

    /// Current health of the carrier.
    fn health(&self) -> ChannelHealth;

    /// Cleanly closes the carrier.
    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// Raw connectivity carrier on the Stream Plane (Seam 1).
#[async_trait]
pub trait StreamChannel: Send + Sync + 'static {
    /// Local identifier of this stream carrier.
    fn id(&self) -> &ChannelId;

    /// Declared capabilities (must declare `Plane::Stream`).
    fn caps(&self) -> ChannelCaps;

    /// Opens an outbound byte stream to `addr`.
    async fn open(&self, addr: &ChannelAddr) -> Result<BoxedAsyncStream>;

    /// Accepts an inbound byte stream, returning `(stream, source_addr)`.
    async fn accept(&self) -> Result<(BoxedAsyncStream, ChannelAddr)>;

    /// Current health of the carrier.
    fn health(&self) -> ChannelHealth;

    /// Cleanly closes the carrier.
    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// Outcome returned by a forwardable channel when handling an opaque per-hop setup payload.
pub enum SetupOutcome<H> {
    /// Originator was authenticated and authorized; `handle` enforces channel Grant limits.
    Accept {
        handle: H,
        reply_hint: Option<Vec<u8>>,
    },
    /// Stateless DoS challenge (e.g., MAC2 cookie reply) to propagate back to the originator.
    Challenge(Vec<u8>),
    /// Setup rejected by channel auth or policy.
    Reject(String),
}

/// Authorized outbound forwarding handle for a datagram circuit.
/// Implementations enforce channel-level Grant expiry, byte/datagram rate limits, and revocation.
#[async_trait]
pub trait DatagramForwardHandle: Send + Sync + 'static {
    /// Sends a framed Confluence datagram to the authorized downstream target,
    /// enforcing channel Grant bounds.
    async fn send(&self, packet: &[u8]) -> Result<()>;

    /// Checks and accounts for a reverse-path datagram of `byte_len` bytes against
    /// the same channel Grant (expiry, rate limits, revocation).
    fn check_and_record_reverse(&self, byte_len: usize) -> Result<()>;

    /// Processes an authenticated channel grant renewal payload (`channel <-> originator`),
    /// updating the live Grant in place and returning an authenticated response payload.
    async fn renew(&self, _renew_payload: &[u8]) -> Result<Vec<u8>> {
        Err(CoreError::AccessDenied(
            "grant renewal not supported by channel".into(),
        ))
    }

    /// Watch receiver that flips to `true` immediately when the handle is revoked or closed.
    fn closed(&self) -> tokio::sync::watch::Receiver<bool>;
}

/// Shared handle to an authorized datagram forwarding circuit.
pub type BoxedDatagramForwardHandle = Arc<dyn DatagramForwardHandle>;

/// Forwardable outbound Datagram channel plugin mounted on a Node by `TargetTag` (Seam 1).
///
/// Covers composable `NoiseAclChannel` egress wrappers, passive `RelayDatagramChannel` slots,
/// and explicit cross-plane channel adapters without any special-casing inside Core.
#[async_trait]
pub trait DatagramForwardChannel: Send + Sync + 'static {
    /// Opaque 8-byte tag (`BLAKE2s256(channel_pubkey)[..8]`) selecting this channel.
    fn target_tag(&self) -> TargetTag;

    /// Declared capabilities (must declare `Plane::Datagram`).
    fn caps(&self) -> ChannelCaps;

    /// Optional underlying carrier so a Node can ensure reply packets on that carrier are polled.
    fn underlying_carrier(&self) -> Option<Arc<dyn DatagramChannel>> {
        None
    }

    /// Evaluates an opaque `channel <-> originator` setup segment and returns a rate-limited handle.
    async fn handle_setup(
        &self,
        source_addr: &ChannelAddr,
        setup_payload: &[u8],
    ) -> Result<SetupOutcome<BoxedDatagramForwardHandle>>;

    /// Handles an opaque channel-specific control datagram (such as passive relay slot registration
    /// or keepalive) arriving on `ingress` from `source_addr`.
    async fn handle_control(
        &self,
        _ingress: Arc<dyn DatagramChannel>,
        _source_addr: &ChannelAddr,
        _payload: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

/// Forwardable outbound Stream channel plugin mounted on a Node by `TargetTag` (Seam 1).
///
/// Covers composable `NoiseAclChannel` egress wrappers, passive `RelayStreamChannel` slots,
/// and explicit cross-plane channel adapters without any special-casing inside Core.
#[async_trait]
pub trait StreamForwardChannel: Send + Sync + 'static {
    /// Opaque 8-byte tag (`BLAKE2s256(channel_pubkey)[..8]`) selecting this channel.
    fn target_tag(&self) -> TargetTag;

    /// Declared capabilities (must declare `Plane::Stream`).
    fn caps(&self) -> ChannelCaps;

    /// Evaluates an opaque `channel <-> originator` setup segment and returns an authorized,
    /// Grant-enforced outbound stream ready for immediate bidirectional byte splicing.
    async fn handle_setup(
        &self,
        source_addr: &ChannelAddr,
        setup_payload: &[u8],
    ) -> Result<SetupOutcome<BoxedAsyncStream>>;

    /// Handles a channel-specific control stream (such as passive relay idle stream parking)
    /// arriving from `source_addr` with initial control payload `payload`.
    async fn handle_control_stream(
        &self,
        _stream: BoxedAsyncStream,
        _source_addr: &ChannelAddr,
        _payload: &[u8],
    ) -> Result<()> {
        Err(CoreError::AccessDenied(
            "control stream not supported by channel".into(),
        ))
    }
}
