//! Seam 1: Pure Composable Channels (strictly separated Stream and Datagram planes).
//!
//! Channels are **pure transport**: they move opaque byte streams or discrete datagrams and
//! report live MTU/health signals—never handling Core handshakes, cookies, credentials, or policy.
//! Vertical wrappers compose **statically at compile time** via associated `Stream`/`Link` types
//! and poll-based data-plane I/O (`StreamRead`, `StreamWrite`, `DatagramLink`); `confluence-core`
//! erases once at the runtime boundary via [`DynAsyncStream`], [`DynStreamChannel`], and
//! [`DynDatagramChannel`].

use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::sync::watch;

use crate::{BoxFut, CoreErr, PacketBuf};

/// Channel-layer error alias.
pub type ChannelErr = CoreErr;

/// Opaque logical identity for a [`DatagramLink`] used to scope per-link `Cid` tables and
/// deduplicate `DatagramPort` dispatchers without colliding across distinct peers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LinkId(u64);

const ALLOCATED_LINK_BIT: u64 = 1 << 63;
static NEXT_LINK_ID: AtomicU64 = AtomicU64::new(1);

impl LinkId {
    /// Allocates a globally unique logical [`LinkId`] that can never collide with pointer-derived IDs.
    pub fn allocate() -> Self {
        Self(ALLOCATED_LINK_BIT | NEXT_LINK_ID.fetch_add(1, Ordering::Relaxed))
    }

    fn from_ptr_addr(addr: usize) -> Self {
        Self((addr as u64) & !ALLOCATED_LINK_BIT)
    }
}

/// Live MTU watch supporting zero-cost vertical framing overhead subtraction and ceiling capping
/// (zero background tasks).
#[derive(Clone, Debug)]
pub struct MtuWatch {
    rx: watch::Receiver<u16>,
    overhead: u16,
    cap: u16,
    last_seen: u16,
}

impl MtuWatch {
    /// Wraps a raw `watch::Receiver<u16>` with zero vertical overhead.
    pub fn new(rx: watch::Receiver<u16>) -> Self {
        let last_seen = *rx.borrow();
        Self {
            rx,
            overhead: 0,
            cap: u16::MAX,
            last_seen,
        }
    }

    /// Constructs a watch whose MTU never changes.
    pub fn fixed(mtu: u16) -> Self {
        Self::new(watch::channel(mtu).1)
    }

    /// Returns a derived watch subtracting an additional `extra` vertical framing bytes.
    pub fn with_overhead(self, extra: u16) -> Self {
        Self {
            rx: self.rx,
            overhead: self.overhead.saturating_add(extra),
            cap: self.cap.saturating_sub(extra),
            last_seen: self.last_seen.saturating_sub(extra),
        }
    }

    /// Returns a derived watch clamping the effective MTU to at most `max`.
    pub fn with_cap(self, max: u16) -> Self {
        Self {
            rx: self.rx,
            overhead: self.overhead,
            cap: self.cap.min(max),
            last_seen: self.last_seen.min(max),
        }
    }

    #[inline]
    fn apply(&self, raw: u16) -> u16 {
        raw.saturating_sub(self.overhead).min(self.cap)
    }

    /// Reads the latest effective MTU without marking the watch as seen.
    pub fn mtu(&self) -> u16 {
        self.apply(*self.rx.borrow())
    }

    /// Reads the latest effective MTU and marks the current value as seen.
    pub fn mtu_and_update(&mut self) -> u16 {
        let raw = *self.rx.borrow_and_update();
        let effective = self.apply(raw);
        self.last_seen = effective;
        effective
    }

    /// Waits for the effective MTU (after overhead subtraction and capping) to change.
    pub async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        loop {
            self.rx.changed().await?;
            let current = self.mtu();
            if current != self.last_seen {
                self.last_seen = current;
                return Ok(());
            }
        }
    }
}

impl From<watch::Receiver<u16>> for MtuWatch {
    fn from(rx: watch::Receiver<u16>) -> Self {
        Self::new(rx)
    }
}

/// Live semantic capabilities and dynamic MTU watch exported by a channel or carrier link.
#[derive(Clone, Debug)]
pub struct ChannelCaps {
    /// Current effective payload ceiling in bytes.
    pub effective_mtu: u16,
    /// Whether the underlying link guarantees reliable delivery.
    pub reliable_underlay: bool,
    /// Live watch reporting mid-session MTU changes.
    pub mtu_watch: MtuWatch,
}

impl ChannelCaps {
    /// Constructs fixed-MTU capabilities whose watch never changes.
    pub fn fixed(effective_mtu: u16, reliable_underlay: bool) -> Self {
        Self {
            effective_mtu,
            reliable_underlay,
            mtu_watch: MtuWatch::fixed(effective_mtu),
        }
    }

    /// Constructs dynamic capabilities backed by `rx`.
    pub fn dynamic(rx: watch::Receiver<u16>, reliable_underlay: bool) -> Self {
        let mtu_watch = MtuWatch::new(rx);
        Self {
            effective_mtu: mtu_watch.mtu(),
            reliable_underlay,
            mtu_watch,
        }
    }

    /// Subtracts `overhead` vertical framing bytes from both `effective_mtu` and `mtu_watch`
    /// without spawning any background forwarding task.
    pub fn with_overhead(self, overhead: u16) -> Self {
        let mtu_watch = self.mtu_watch.with_overhead(overhead);
        Self {
            effective_mtu: mtu_watch
                .mtu()
                .min(self.effective_mtu.saturating_sub(overhead)),
            reliable_underlay: self.reliable_underlay,
            mtu_watch,
        }
    }

    /// Clamps both `effective_mtu` and `mtu_watch` to at most `max` without spawning any task.
    pub fn with_cap(self, max: u16) -> Self {
        let mtu_watch = self.mtu_watch.with_cap(max);
        Self {
            effective_mtu: mtu_watch.mtu().min(self.effective_mtu.min(max)),
            reliable_underlay: self.reliable_underlay,
            mtu_watch,
        }
    }

    /// Reads the latest effective MTU from `mtu_watch`.
    pub fn mtu(&self) -> u16 {
        self.mtu_watch.mtu()
    }
}

/// Poll-based read half of an [`AsyncStream`] (zero `BoxFut`, natively dyn-safe).
pub trait StreamRead: Send + Unpin + 'static {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ChannelErr>>;
}

/// Poll-based write half of an [`AsyncStream`] (zero `BoxFut`, natively dyn-safe).
pub trait StreamWrite: Send + Unpin + 'static {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, ChannelErr>>;

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), ChannelErr>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ChannelErr>>;
}

impl<T: StreamRead + ?Sized> StreamRead for Box<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ChannelErr>> {
        Pin::new(&mut **self).poll_read(cx, buf)
    }
}

impl<T: StreamWrite + ?Sized> StreamWrite for Box<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, ChannelErr>> {
        Pin::new(&mut **self).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ChannelErr>> {
        Pin::new(&mut **self).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ChannelErr>> {
        Pin::new(&mut **self).poll_shutdown(cx)
    }
}

/// Zero-allocation async convenience helpers for any [`StreamRead`] (concrete or `dyn`).
pub trait StreamReadExt: StreamRead {
    /// Reads up to `buf.len()` bytes, returning `Ok(0)` on clean EOF.
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, ChannelErr>> + Send + 'a {
        poll_fn(move |cx| Pin::new(&mut *self).poll_read(cx, buf))
    }

    /// Reads exactly `into.len()` bytes, returning `UnexpectedEof` on premature EOF.
    fn read_exact<'a>(
        &'a mut self,
        mut into: &'a mut [u8],
    ) -> impl Future<Output = Result<(), ChannelErr>> + Send + 'a {
        async move {
            while !into.is_empty() {
                let amount = poll_fn(|cx| Pin::new(&mut *self).poll_read(cx, into)).await?;
                if amount == 0 {
                    return Err(CoreErr::UnexpectedEof);
                }
                if amount > into.len() {
                    return Err(CoreErr::Malformed);
                }
                into = &mut into[amount..];
            }
            Ok(())
        }
    }
}

impl<T: StreamRead + ?Sized> StreamReadExt for T {}

/// Zero-allocation async convenience helpers for any [`StreamWrite`] (concrete or `dyn`).
pub trait StreamWriteExt: StreamWrite {
    /// Writes some bytes from `buf`, returning how many bytes were accepted.
    fn write<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> impl Future<Output = Result<usize, ChannelErr>> + Send + 'a {
        poll_fn(move |cx| Pin::new(&mut *self).poll_write(cx, buf))
    }

    /// Writes all bytes in `buf` and flushes any buffered framing records.
    fn write_all<'a>(
        &'a mut self,
        mut buf: &'a [u8],
    ) -> impl Future<Output = Result<(), ChannelErr>> + Send + 'a {
        async move {
            while !buf.is_empty() {
                let amount = poll_fn(|cx| Pin::new(&mut *self).poll_write(cx, buf)).await?;
                if amount == 0 {
                    return Err(CoreErr::UnexpectedEof);
                }
                if amount > buf.len() {
                    return Err(CoreErr::Malformed);
                }
                buf = &buf[amount..];
            }
            poll_fn(|cx| Pin::new(&mut *self).poll_flush(cx)).await
        }
    }

    /// Flushes any buffered bytes to the underlying carrier.
    fn flush(&mut self) -> impl Future<Output = Result<(), ChannelErr>> + Send + '_ {
        poll_fn(|cx| Pin::new(&mut *self).poll_flush(cx))
    }

    /// Flushes and cleanly shuts down the write half.
    fn shutdown(&mut self) -> impl Future<Output = Result<(), ChannelErr>> + Send + '_ {
        poll_fn(|cx| Pin::new(&mut *self).poll_shutdown(cx))
    }
}

impl<T: StreamWrite + ?Sized> StreamWriteExt for T {}

/// Reads exactly `into.len()` bytes from `reader`, returning `UnexpectedEof` on premature EOF.
pub async fn read_exact<R: StreamRead + ?Sized>(
    reader: &mut R,
    into: &mut [u8],
) -> Result<(), CoreErr> {
    StreamReadExt::read_exact(reader, into).await
}

/// Bidirectional byte stream returned by a [`StreamChannel`] or [`StreamListener`].
pub trait AsyncStream: Send + 'static {
    type Read: StreamRead;
    type Write: StreamWrite;

    fn caps(&self) -> ChannelCaps;
    fn split(self) -> (Self::Read, Self::Write);

    /// Optional per-source identifier used to bind stateless `MAC2` flood cookies to the peer.
    fn source_tag(&self) -> [u8; 16] {
        [0; 16]
    }

    /// Erases this stream into `Box<dyn DynAsyncStream>` at the Core boundary without double-boxing.
    fn into_dyn_stream(self) -> Box<dyn DynAsyncStream>
    where
        Self: Sized,
    {
        Box::new(self)
    }
}

/// Dyn-safe type-erased stream boundary used once inside `confluence-core`.
pub trait DynAsyncStream: Send + 'static {
    fn dyn_caps(&self) -> ChannelCaps;
    fn split_boxed(self: Box<Self>) -> (Box<dyn StreamRead>, Box<dyn StreamWrite>);
    fn dyn_source_tag(&self) -> [u8; 16] {
        [0; 16]
    }
}

impl<S: AsyncStream> DynAsyncStream for S {
    fn dyn_caps(&self) -> ChannelCaps {
        AsyncStream::caps(self)
    }

    fn split_boxed(self: Box<Self>) -> (Box<dyn StreamRead>, Box<dyn StreamWrite>) {
        let (read, write) = AsyncStream::split(*self);
        (Box::new(read), Box::new(write))
    }

    fn dyn_source_tag(&self) -> [u8; 16] {
        AsyncStream::source_tag(self)
    }
}

impl AsyncStream for Box<dyn DynAsyncStream> {
    type Read = Box<dyn StreamRead>;
    type Write = Box<dyn StreamWrite>;

    fn caps(&self) -> ChannelCaps {
        DynAsyncStream::dyn_caps(&**self)
    }

    fn split(self) -> (Self::Read, Self::Write) {
        DynAsyncStream::split_boxed(self)
    }

    fn source_tag(&self) -> [u8; 16] {
        DynAsyncStream::dyn_source_tag(&**self)
    }

    fn into_dyn_stream(self) -> Box<dyn DynAsyncStream> {
        self
    }
}

impl<S: AsyncStream> AsyncStream for Box<S> {
    type Read = S::Read;
    type Write = S::Write;

    fn caps(&self) -> ChannelCaps {
        (**self).caps()
    }

    fn split(self) -> (Self::Read, Self::Write) {
        (*self).split()
    }

    fn source_tag(&self) -> [u8; 16] {
        (**self).source_tag()
    }

    fn into_dyn_stream(self) -> Box<dyn DynAsyncStream> {
        self
    }
}

/// Reassembles a split `(StreamRead, StreamWrite)` pair back into an [`AsyncStream`].
pub struct RejoinedStream<R, W> {
    pub caps: ChannelCaps,
    pub source_tag: [u8; 16],
    pub reader: R,
    pub writer: W,
}

impl<R: StreamRead, W: StreamWrite> AsyncStream for RejoinedStream<R, W> {
    type Read = R;
    type Write = W;

    fn caps(&self) -> ChannelCaps {
        self.caps.clone()
    }

    fn split(self) -> (R, W) {
        (self.reader, self.writer)
    }

    fn source_tag(&self) -> [u8; 16] {
        self.source_tag
    }
}

/// Poll-based bidirectional discrete-message link (zero `BoxFut`, natively dyn-safe).
pub trait DatagramLink: Send + Sync + 'static {
    fn caps(&self) -> ChannelCaps;

    /// Lightweight hot-path query for the current effective MTU without cloning a watch receiver.
    fn current_mtu(&self) -> u16 {
        self.caps().mtu()
    }

    /// Polls until the link is ready to accept an outbound datagram via [`Self::try_send`].
    fn poll_send_ready(&self, _cx: &mut Context<'_>) -> Poll<Result<(), ChannelErr>> {
        Poll::Ready(Ok(()))
    }

    /// Synchronously transmits one discrete datagram.
    fn try_send(&self, packet: PacketBuf) -> Result<(), ChannelErr>;

    /// Polls for the next inbound discrete datagram.
    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<PacketBuf, ChannelErr>>;

    /// Optional per-source identifier used to bind stateless `MAC2` flood cookies to the peer.
    fn source_tag(&self) -> [u8; 16] {
        [0; 16]
    }

    /// Stable logical identity for `DatagramPort` deduplication and per-link `Cid` isolation.
    fn link_id(&self) -> LinkId {
        LinkId::from_ptr_addr(self as *const Self as *const () as usize)
    }
}

impl<T: DatagramLink + ?Sized> DatagramLink for Arc<T> {
    fn caps(&self) -> ChannelCaps {
        (**self).caps()
    }

    fn current_mtu(&self) -> u16 {
        (**self).current_mtu()
    }

    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), ChannelErr>> {
        (**self).poll_send_ready(cx)
    }

    fn try_send(&self, packet: PacketBuf) -> Result<(), ChannelErr> {
        (**self).try_send(packet)
    }

    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<PacketBuf, ChannelErr>> {
        (**self).poll_recv(cx)
    }

    fn source_tag(&self) -> [u8; 16] {
        (**self).source_tag()
    }

    fn link_id(&self) -> LinkId {
        (**self).link_id()
    }
}

/// Zero-allocation async convenience helpers for any [`DatagramLink`] (concrete or `dyn`).
pub trait DatagramLinkExt: DatagramLink {
    /// Waits for send readiness and transmits `packet`.
    fn send(&self, packet: PacketBuf) -> impl Future<Output = Result<(), ChannelErr>> + Send + '_ {
        async move {
            poll_fn(|cx| self.poll_send_ready(cx)).await?;
            self.try_send(packet)
        }
    }

    /// Receives the next discrete datagram.
    fn recv(&self) -> impl Future<Output = Result<PacketBuf, ChannelErr>> + Send + '_ {
        poll_fn(|cx| self.poll_recv(cx))
    }
}

impl<T: DatagramLink + ?Sized> DatagramLinkExt for T {}

/// Converts a concrete `Arc<L>` or already-erased `Arc<dyn DatagramLink>` into
/// `Arc<dyn DatagramLink>` without double-wrapping or losing pointer identity.
pub trait IntoDynDatagramLink: DatagramLink + Sized {
    fn into_dyn_link(self) -> Arc<dyn DatagramLink>;
}

impl<L: DatagramLink> IntoDynDatagramLink for Arc<L> {
    fn into_dyn_link(self) -> Arc<dyn DatagramLink> {
        self
    }
}

impl IntoDynDatagramLink for Arc<dyn DatagramLink> {
    fn into_dyn_link(self) -> Arc<dyn DatagramLink> {
        self
    }
}

/// Symmetric inbound accept trait for Stream Plane carriers and compile-time vertical wrappers.
pub trait StreamListener: Send + Sync + 'static {
    type Stream: AsyncStream;

    fn accept(&self) -> impl Future<Output = Result<Self::Stream, ChannelErr>> + Send + '_;
}

impl<L: StreamListener> StreamListener for Arc<L> {
    type Stream = L::Stream;

    fn accept(&self) -> impl Future<Output = Result<Self::Stream, ChannelErr>> + Send + '_ {
        (**self).accept()
    }
}

/// Symmetric inbound link-accept trait for Datagram Plane carriers and compile-time vertical wrappers.
pub trait DatagramListener: Send + Sync + 'static {
    type Link: IntoDynDatagramLink;

    fn accept_link(&self) -> impl Future<Output = Result<Self::Link, ChannelErr>> + Send + '_;
}

impl<L: DatagramListener> DatagramListener for Arc<L> {
    type Link = L::Link;

    fn accept_link(&self) -> impl Future<Output = Result<Self::Link, ChannelErr>> + Send + '_ {
        (**self).accept_link()
    }
}

/// Pure Stream Plane transport channel (Seam 1A).
///
/// Moves opaque byte streams without any authentication, credential, or policy logic.
pub trait StreamChannel: Send + Sync + 'static {
    type Stream: AsyncStream;

    /// Channel capabilities (effective MTU and reliability).
    fn caps(&self) -> ChannelCaps;

    /// Opens an outbound stream to `locator`.
    fn dial_stream<'a>(
        &'a self,
        locator: &'a [u8],
    ) -> impl Future<Output = Result<Self::Stream, ChannelErr>> + Send + 'a;
}

/// Pure Datagram Plane transport channel (Seam 1B).
///
/// Moves discrete datagrams without any authentication, credential, or policy logic.
pub trait DatagramChannel: Send + Sync + 'static {
    type Link: IntoDynDatagramLink;

    /// Channel capabilities (effective MTU and reliability).
    fn caps(&self) -> ChannelCaps;

    /// Opens an outbound datagram link to `locator`.
    fn open_link<'a>(
        &'a self,
        locator: &'a [u8],
    ) -> impl Future<Output = Result<Self::Link, ChannelErr>> + Send + 'a;
}

/// Dyn-safe boundary trait erased once when registering a [`StreamChannel`] on a `ScopeInstance`.
pub trait DynStreamChannel: Send + Sync + 'static {
    fn dyn_caps(&self) -> ChannelCaps;
    fn dyn_dial_stream<'a>(
        &'a self,
        locator: &'a [u8],
    ) -> BoxFut<'a, Result<Box<dyn DynAsyncStream>, ChannelErr>>;
}

impl<C: StreamChannel> DynStreamChannel for C {
    fn dyn_caps(&self) -> ChannelCaps {
        StreamChannel::caps(self)
    }

    fn dyn_dial_stream<'a>(
        &'a self,
        locator: &'a [u8],
    ) -> BoxFut<'a, Result<Box<dyn DynAsyncStream>, ChannelErr>> {
        Box::pin(async move {
            let stream = StreamChannel::dial_stream(self, locator).await?;
            Ok(stream.into_dyn_stream())
        })
    }
}

/// Dyn-safe boundary trait erased once when registering a [`DatagramChannel`] on a `ScopeInstance`.
pub trait DynDatagramChannel: Send + Sync + 'static {
    fn dyn_caps(&self) -> ChannelCaps;
    fn dyn_open_link<'a>(
        &'a self,
        locator: &'a [u8],
    ) -> BoxFut<'a, Result<Arc<dyn DatagramLink>, ChannelErr>>;
}

impl<C: DatagramChannel> DynDatagramChannel for C {
    fn dyn_caps(&self) -> ChannelCaps {
        DatagramChannel::caps(self)
    }

    fn dyn_open_link<'a>(
        &'a self,
        locator: &'a [u8],
    ) -> BoxFut<'a, Result<Arc<dyn DatagramLink>, ChannelErr>> {
        Box::pin(async move {
            let link = DatagramChannel::open_link(self, locator).await?;
            Ok(link.into_dyn_link())
        })
    }
}

impl<T: StreamChannel> StreamChannel for Arc<T> {
    type Stream = T::Stream;

    fn caps(&self) -> ChannelCaps {
        (**self).caps()
    }

    fn dial_stream<'a>(
        &'a self,
        locator: &'a [u8],
    ) -> impl Future<Output = Result<Self::Stream, ChannelErr>> + Send + 'a {
        (**self).dial_stream(locator)
    }
}

impl<T: DatagramChannel> DatagramChannel for Arc<T> {
    type Link = T::Link;

    fn caps(&self) -> ChannelCaps {
        (**self).caps()
    }

    fn open_link<'a>(
        &'a self,
        locator: &'a [u8],
    ) -> impl Future<Output = Result<Self::Link, ChannelErr>> + Send + 'a {
        (**self).open_link(locator)
    }
}
