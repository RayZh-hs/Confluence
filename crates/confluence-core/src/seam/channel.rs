//! Seam 1: Pure composable Stream and Datagram transport channels, listeners, and live MTU watches.

use core::fmt;
use core::future::{Future, poll_fn};
use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::error::CoreError;
use crate::packet::PacketBuf;
use crate::runtime::BoxFuture;
use crate::runtime::sync::{Watch, WatchReceiver};
use crate::types::LinkId;

// ---------------------------------------------------------------------------
// Live Composable MtuWatch & ChannelCaps
// ---------------------------------------------------------------------------

/// Publisher half of a live [`MtuWatch`].
#[derive(Clone)]
pub struct MtuSender {
    tx: Watch<u16>,
}

impl MtuSender {
    /// Updates the underlying link MTU and wakes any observing [`MtuWatch`] handles.
    pub fn set(&self, mtu: u16) {
        self.tx.send(mtu);
    }

    /// Returns the most recently published raw MTU.
    #[must_use]
    pub fn current(&self) -> u16 {
        self.tx.borrow_cloned()
    }

    /// Subscribes a new [`MtuWatch`] starting at the current MTU value.
    #[must_use]
    pub fn subscribe(&self) -> MtuWatch {
        let (rx, current) = self.tx.subscribe_with_value();
        MtuWatch {
            source: MtuSource::Dynamic(rx),
            overhead: 0,
            cap: u16::MAX,
            seen: current,
        }
    }
}

impl fmt::Debug for MtuSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MtuSender")
            .field("current", &self.current())
            .finish()
    }
}

#[derive(Clone)]
enum MtuSource {
    Fixed(u16),
    Dynamic(WatchReceiver<u16>),
}

/// Zero-task composable watch over a transport channel's live effective MTU.
///
/// Vertical transport wrappers compose overhead and caps via [`Self::with_overhead`] and
/// [`Self::with_cap`] with zero background tasks and zero allocations. Spurious notifications
/// whose transformed effective MTU equals the last observed value are suppressed automatically.
#[derive(Clone)]
pub struct MtuWatch {
    source: MtuSource,
    overhead: u16,
    cap: u16,
    seen: u16,
}

impl MtuWatch {
    /// Creates an immutable `MtuWatch` fixed at `mtu`.
    #[must_use]
    pub const fn fixed(mtu: u16) -> Self {
        Self {
            source: MtuSource::Fixed(mtu),
            overhead: 0,
            cap: u16::MAX,
            seen: mtu,
        }
    }

    /// Creates a dynamic `(MtuSender, MtuWatch)` pair initialized to `initial`.
    #[must_use]
    pub fn channel(initial: u16) -> (MtuSender, Self) {
        let (tx, rx) = Watch::new(initial);
        let watch = Self {
            source: MtuSource::Dynamic(rx),
            overhead: 0,
            cap: u16::MAX,
            seen: initial,
        };
        (MtuSender { tx }, watch)
    }

    #[inline]
    fn raw_current(&self) -> u16 {
        match &self.source {
            MtuSource::Fixed(v) => *v,
            MtuSource::Dynamic(rx) => rx.borrow_cloned(),
        }
    }

    #[inline]
    const fn apply(raw: u16, overhead: u16, cap: u16) -> u16 {
        let reduced = raw.saturating_sub(overhead);
        if reduced < cap { reduced } else { cap }
    }

    /// Returns the current transformed effective MTU without blocking or advancing this watch's
    /// observation cursor.
    ///
    /// Workers that read an initial MTU before awaiting [`Self::changed`] SHOULD use
    /// [`Self::sample`] so the watch cursor and baseline stay synchronized.
    #[must_use]
    pub fn current(&self) -> u16 {
        Self::apply(self.raw_current(), self.overhead, self.cap)
    }

    /// Atomically samples the current transformed effective MTU AND synchronizes this watch's
    /// observation baseline and underlying watch cursor.
    ///
    /// Subsequent updates away from the returned value (including drops back to an earlier value
    /// that was present before sampling) are guaranteed to wake [`Self::changed`].
    #[must_use]
    pub fn sample(&mut self) -> u16 {
        let raw = match &mut self.source {
            MtuSource::Fixed(v) => *v,
            MtuSource::Dynamic(rx) => rx.borrow_and_mark_seen(),
        };
        let effective = Self::apply(raw, self.overhead, self.cap);
        self.seen = effective;
        effective
    }

    /// Returns a derived `MtuWatch` subtracting `extra` wrapper framing bytes (saturating at `0`).
    ///
    /// Preserves exact composition semantics even when interleaved with [`Self::with_cap`]:
    /// `min(raw - o, c) - extra == min(raw - (o + extra), c - extra)`.
    #[must_use]
    pub fn with_overhead(&self, extra: u16) -> Self {
        let overhead = self.overhead.saturating_add(extra);
        let cap = self.cap.saturating_sub(extra);
        let (source, seen) = match &self.source {
            MtuSource::Fixed(v) => (MtuSource::Fixed(*v), Self::apply(*v, overhead, cap)),
            MtuSource::Dynamic(rx) => {
                let mut cloned = rx.clone();
                let raw = cloned.borrow_and_mark_seen();
                (MtuSource::Dynamic(cloned), Self::apply(raw, overhead, cap))
            }
        };
        Self {
            source,
            overhead,
            cap,
            seen,
        }
    }

    /// Returns a derived `MtuWatch` capping the effective MTU at `max`.
    #[must_use]
    pub fn with_cap(&self, max: u16) -> Self {
        let cap = self.cap.min(max);
        let (source, seen) = match &self.source {
            MtuSource::Fixed(v) => (MtuSource::Fixed(*v), Self::apply(*v, self.overhead, cap)),
            MtuSource::Dynamic(rx) => {
                let mut cloned = rx.clone();
                let raw = cloned.borrow_and_mark_seen();
                (
                    MtuSource::Dynamic(cloned),
                    Self::apply(raw, self.overhead, cap),
                )
            }
        };
        Self {
            source,
            overhead: self.overhead,
            cap,
            seen,
        }
    }

    /// Clamps the locally observed MTU bound (e.g., after an `MtuTooSmall` send error) so
    /// subsequent updates matching `bound` are suppressed while recoveries above `bound` wake.
    pub fn clamp_seen(&mut self, bound: u16) {
        self.seen = self.seen.min(bound);
    }

    /// Waits for the transformed effective MTU to change from the last observed value.
    ///
    /// Reads the watch value and consumes its version atomically so concurrent rapid updates
    /// cannot be missed. Returns `None` for fixed watches or once all [`MtuSender`] handles have
    /// been dropped.
    pub async fn changed(&mut self) -> Option<u16> {
        let rx = match &mut self.source {
            MtuSource::Fixed(_) => return None,
            MtuSource::Dynamic(rx) => rx,
        };
        loop {
            let raw = rx.changed_value().await?;
            let next = Self::apply(raw, self.overhead, self.cap);
            if next != self.seen {
                self.seen = next;
                return Some(next);
            }
        }
    }
}

impl fmt::Debug for MtuWatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MtuWatch")
            .field("current", &self.current())
            .field("overhead", &self.overhead)
            .field("cap", &self.cap)
            .field("seen", &self.seen)
            .finish()
    }
}

/// Capabilities and live payload-limit metadata exported by a pure transport channel.
#[derive(Clone)]
pub struct ChannelCaps {
    effective_mtu: u16,
    base_mtu: u16,
    reliable_underlay: bool,
    mtu_watch: MtuWatch,
}

impl ChannelCaps {
    /// Creates capabilities for a channel with a fixed payload MTU.
    #[must_use]
    pub const fn fixed(mtu: u16, reliable_underlay: bool) -> Self {
        Self {
            effective_mtu: mtu,
            base_mtu: mtu,
            reliable_underlay,
            mtu_watch: MtuWatch::fixed(mtu),
        }
    }

    /// Creates capabilities for a channel backed by a live [`MtuWatch`].
    #[must_use]
    pub fn dynamic(base_mtu: u16, reliable_underlay: bool, mtu_watch: MtuWatch) -> Self {
        let effective_mtu = mtu_watch.current();
        Self {
            effective_mtu,
            base_mtu,
            reliable_underlay,
            mtu_watch,
        }
    }

    /// Returns the current live effective payload MTU in wire bytes.
    #[must_use]
    pub fn mtu(&self) -> u16 {
        let live = self.mtu_watch.current();
        // Fixed watches return `self.effective_mtu` directly; dynamic watches reflect live updates.
        let _ = self.effective_mtu;
        live
    }

    /// Returns the underlying base MTU prior to vertical wrapper overhead.
    #[must_use]
    pub const fn base_mtu(&self) -> u16 {
        self.base_mtu
    }

    /// Returns `true` if the underlay delivers ordered reliable bytes (e.g., TCP, QUIC stream).
    #[must_use]
    pub const fn reliable_underlay(&self) -> bool {
        self.reliable_underlay
    }

    /// Returns a cloned [`MtuWatch`] observing live effective MTU updates for this channel.
    #[must_use]
    pub fn mtu_watch(&self) -> MtuWatch {
        self.mtu_watch.clone()
    }

    /// Derives wrapped capabilities subtracting `extra` wrapper framing overhead.
    #[must_use]
    pub fn with_overhead(&self, extra: u16) -> Self {
        let mtu_watch = self.mtu_watch.with_overhead(extra);
        let effective_mtu = mtu_watch.current();
        Self {
            effective_mtu,
            base_mtu: self.base_mtu,
            reliable_underlay: self.reliable_underlay,
            mtu_watch,
        }
    }

    /// Derives wrapped capabilities capping the effective MTU at `max`.
    #[must_use]
    pub fn with_cap(&self, max: u16) -> Self {
        let mtu_watch = self.mtu_watch.with_cap(max);
        let effective_mtu = mtu_watch.current();
        Self {
            effective_mtu,
            base_mtu: self.base_mtu,
            reliable_underlay: self.reliable_underlay,
            mtu_watch,
        }
    }
}

impl fmt::Debug for ChannelCaps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelCaps")
            .field("mtu", &self.mtu())
            .field("base_mtu", &self.base_mtu)
            .field("reliable_underlay", &self.reliable_underlay)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Stream Plane Traits & Zero-Alloc Extension Helpers
// ---------------------------------------------------------------------------

/// Object-safe poll-based byte stream read half.
pub trait StreamRead: Send + Unpin + 'static {
    /// Attempts to read available bytes into `buf`, returning `Ok(0)` on clean EOF.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, CoreError>>;
}

impl StreamRead for Box<dyn StreamRead> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, CoreError>> {
        Pin::new(&mut **self).poll_read(cx, buf)
    }
}

/// Object-safe poll-based byte stream write half.
pub trait StreamWrite: Send + Unpin + 'static {
    /// Attempts to write bytes from `buf`, returning the number of bytes accepted.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, CoreError>>;

    /// Flushes any buffered writes to the underlying transport.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), CoreError>>;

    /// Half-closes the outbound write direction cleanly.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), CoreError>>;
}

impl StreamWrite for Box<dyn StreamWrite> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, CoreError>> {
        Pin::new(&mut **self).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
        Pin::new(&mut **self).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), CoreError>> {
        Pin::new(&mut **self).poll_shutdown(cx)
    }
}

/// Zero-allocation async convenience helpers for any [`StreamRead`].
pub trait StreamReadExt: StreamRead {
    /// Reads at least one byte (or returns `Ok(0)` on EOF) without heap allocation.
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, CoreError>> + Send + 'a {
        poll_fn(move |cx| Pin::new(&mut *self).poll_read(cx, buf))
    }

    /// Reads exact `buf.len()` bytes, returning [`CoreError::UnexpectedEof`] on premature EOF.
    fn read_exact<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = Result<(), CoreError>> + Send + 'a {
        async move {
            let mut offset = 0usize;
            while offset < buf.len() {
                let n = self.read(&mut buf[offset..]).await?;
                if n == 0 {
                    return Err(CoreError::UnexpectedEof);
                }
                offset += n;
            }
            Ok(())
        }
    }
}

impl<R: StreamRead + ?Sized> StreamReadExt for R {}

/// Zero-allocation async convenience helpers for any [`StreamWrite`].
pub trait StreamWriteExt: StreamWrite {
    /// Writes some prefix of `buf` without heap allocation.
    fn write<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> impl Future<Output = Result<usize, CoreError>> + Send + 'a {
        poll_fn(move |cx| Pin::new(&mut *self).poll_write(cx, buf))
    }

    /// Writes the entire `buf`, returning [`CoreError::UnexpectedEof`] if `write` returns `Ok(0)`.
    fn write_all<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> impl Future<Output = Result<(), CoreError>> + Send + 'a {
        async move {
            let mut offset = 0usize;
            while offset < buf.len() {
                let n = self.write(&buf[offset..]).await?;
                if n == 0 {
                    return Err(CoreError::UnexpectedEof);
                }
                offset += n;
            }
            Ok(())
        }
    }

    /// Flushes the write half without heap allocation.
    fn flush(&mut self) -> impl Future<Output = Result<(), CoreError>> + Send + '_ {
        poll_fn(move |cx| Pin::new(&mut *self).poll_flush(cx))
    }

    /// Half-closes the write half cleanly without heap allocation.
    fn shutdown(&mut self) -> impl Future<Output = Result<(), CoreError>> + Send + '_ {
        poll_fn(move |cx| Pin::new(&mut *self).poll_shutdown(cx))
    }
}

impl<W: StreamWrite + ?Sized> StreamWriteExt for W {}

/// Pure bidirectional byte stream that splits into independent read and write halves.
pub trait IntoStreamHalves: Send + 'static {
    /// Read half type.
    type Read: StreamRead;
    /// Write half type.
    type Write: StreamWrite;

    /// Returns channel capabilities and live MTU watch.
    fn caps(&self) -> ChannelCaps;

    /// Optional 16-byte peer source tag used to bind flood cookies (`[0; 16]` default).
    fn source_tag(&self) -> [u8; 16] {
        [0u8; 16]
    }

    /// Splits this stream into independent read and write halves.
    fn into_halves(self) -> (Self::Read, Self::Write);
}

/// Type-erased pure stream handle used at the Core boundary.
pub struct BoxedStream {
    caps: ChannelCaps,
    source_tag: [u8; 16],
    read: Box<dyn StreamRead>,
    write: Box<dyn StreamWrite>,
}

impl BoxedStream {
    /// Erases any [`IntoStreamHalves`] stream into a `BoxedStream`.
    #[must_use]
    pub fn from_stream<S: IntoStreamHalves>(stream: S) -> Self {
        let caps = stream.caps();
        let source_tag = stream.source_tag();
        let (read, write) = stream.into_halves();
        Self {
            caps,
            source_tag,
            read: Box::new(read),
            write: Box::new(write),
        }
    }

    /// Constructs a `BoxedStream` directly from parts.
    #[must_use]
    pub fn from_parts(
        caps: ChannelCaps,
        source_tag: [u8; 16],
        read: Box<dyn StreamRead>,
        write: Box<dyn StreamWrite>,
    ) -> Self {
        Self {
            caps,
            source_tag,
            read,
            write,
        }
    }
}

impl IntoStreamHalves for BoxedStream {
    type Read = Box<dyn StreamRead>;
    type Write = Box<dyn StreamWrite>;

    fn caps(&self) -> ChannelCaps {
        self.caps.clone()
    }

    fn source_tag(&self) -> [u8; 16] {
        self.source_tag
    }

    fn into_halves(self) -> (Self::Read, Self::Write) {
        (self.read, self.write)
    }
}

impl fmt::Debug for BoxedStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoxedStream")
            .field("caps", &self.caps)
            .finish_non_exhaustive()
    }
}

/// Pure outbound Stream transport carrier (Seam 1).
///
/// Uses Rust 2024 RPITIT with an associated `Stream` type so vertical transport wrappers
/// compose statically at compile time and erase once at the Core boundary.
pub trait StreamCarrier: Send + Sync + 'static {
    /// Stream type opened by this carrier.
    type Stream: IntoStreamHalves;

    /// Returns static/live capabilities for streams opened by this carrier.
    fn caps(&self) -> ChannelCaps;

    /// Opens an outbound stream to the carrier-specific opaque `locator`.
    fn dial_stream<'a>(
        &'a self,
        locator: &'a [u8],
    ) -> impl Future<Output = Result<Self::Stream, CoreError>> + Send + 'a;
}

/// Pure inbound Stream transport listener (Seam 1).
pub trait StreamListener: Send + Sync + 'static {
    /// Accepted stream type.
    type Stream: IntoStreamHalves;

    /// Accepts the next inbound pure byte stream.
    fn accept(&self) -> impl Future<Output = Result<Self::Stream, CoreError>> + Send + '_;
}

/// Internal type-erased wrapper registered once at the Core boundary.
#[allow(dead_code)]
pub(crate) trait ErasedStreamCarrier: Send + Sync + 'static {
    fn caps(&self) -> ChannelCaps;
    fn dial_stream<'a>(&'a self, locator: &'a [u8]) -> BoxFuture<'a, Result<BoxedStream, CoreError>>;
}

impl<C: StreamCarrier> ErasedStreamCarrier for C {
    fn caps(&self) -> ChannelCaps {
        StreamCarrier::caps(self)
    }

    fn dial_stream<'a>(&'a self, locator: &'a [u8]) -> BoxFuture<'a, Result<BoxedStream, CoreError>> {
        Box::pin(async move {
            let stream = StreamCarrier::dial_stream(self, locator).await?;
            Ok(BoxedStream::from_stream(stream))
        })
    }
}

// ---------------------------------------------------------------------------
// Datagram Plane Traits, Arc Blanket Impl, Zero-Alloc Helpers & Ingress Handle
// ---------------------------------------------------------------------------

/// Object-safe poll-based discrete datagram transport link (Seam 1).
///
/// Multiple circuits may share a single `DatagramLink` (deduplicated by [`Self::link_id`]).
pub trait DatagramLink: Send + Sync + 'static {
    /// Returns capabilities and live MTU watch for this link.
    fn caps(&self) -> ChannelCaps;

    /// Returns the link's current effective payload MTU in bytes.
    fn current_mtu(&self) -> u16 {
        self.caps().mtu()
    }

    /// Polls until the link can accept another outbound datagram via [`Self::try_send`].
    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), CoreError>>;

    /// Attempts to transmit `packet` without blocking.
    ///
    /// Returns [`CoreError::WouldBlock`] if the transmit queue is full, or
    /// [`CoreError::MtuTooSmall`] if the packet exceeds the link's live MTU.
    fn try_send(&self, packet: PacketBuf) -> Result<(), CoreError>;

    /// Polls for the next inbound datagram.
    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<PacketBuf, CoreError>>;

    /// Optional 16-byte peer source tag used to bind flood cookies (`[0; 16]` default).
    fn source_tag(&self) -> [u8; 16] {
        [0u8; 16]
    }

    /// Stable logical identifier deduplicating concurrent attachments of the same link.
    fn link_id(&self) -> LinkId;
}

impl<L: DatagramLink + ?Sized> DatagramLink for Arc<L> {
    fn caps(&self) -> ChannelCaps {
        (**self).caps()
    }

    fn current_mtu(&self) -> u16 {
        (**self).current_mtu()
    }

    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
        (**self).poll_send_ready(cx)
    }

    fn try_send(&self, packet: PacketBuf) -> Result<(), CoreError> {
        (**self).try_send(packet)
    }

    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<PacketBuf, CoreError>> {
        (**self).poll_recv(cx)
    }

    fn source_tag(&self) -> [u8; 16] {
        (**self).source_tag()
    }

    fn link_id(&self) -> LinkId {
        (**self).link_id()
    }
}

/// Zero-allocation async convenience helpers for any [`DatagramLink`].
pub trait DatagramLinkExt: DatagramLink {
    /// Waits until the link reports transmit readiness.
    fn send_ready(&self) -> impl Future<Output = Result<(), CoreError>> + Send + '_ {
        poll_fn(move |cx| self.poll_send_ready(cx))
    }

    /// Waits until the link reports transmit readiness and transmits `packet`.
    fn send(
        &self,
        packet: PacketBuf,
    ) -> impl Future<Output = Result<(), CoreError>> + Send + '_ {
        async move {
            self.send_ready().await?;
            self.try_send(packet)
        }
    }

    /// Receives the next inbound datagram without per-packet future allocation.
    fn recv(&self) -> impl Future<Output = Result<PacketBuf, CoreError>> + Send + '_ {
        poll_fn(move |cx| self.poll_recv(cx))
    }
}

impl<L: DatagramLink + ?Sized> DatagramLinkExt for L {}

/// Pure outbound Datagram transport carrier (Seam 1).
pub trait DatagramCarrier: Send + Sync + 'static {
    /// Datagram link type opened by this carrier.
    type Link: DatagramLink;

    /// Returns static/live capabilities for links opened by this carrier.
    fn caps(&self) -> ChannelCaps;

    /// Opens or returns a shared outbound datagram link to `locator`.
    fn open_link<'a>(
        &'a self,
        locator: &'a [u8],
    ) -> impl Future<Output = Result<Self::Link, CoreError>> + Send + 'a;
}

/// Pure inbound Datagram transport listener (Seam 1).
pub trait DatagramListener: Send + Sync + 'static {
    /// Accepted datagram link type.
    type Link: DatagramLink;

    /// Accepts the next inbound datagram link.
    fn accept_link(&self) -> impl Future<Output = Result<Self::Link, CoreError>> + Send + '_;
}

/// Internal type-erased wrapper registered once at the Core boundary.
#[allow(dead_code)]
pub(crate) trait ErasedDatagramCarrier: Send + Sync + 'static {
    fn caps(&self) -> ChannelCaps;
    fn open_link<'a>(
        &'a self,
        locator: &'a [u8],
    ) -> BoxFuture<'a, Result<Arc<dyn DatagramLink>, CoreError>>;
}

impl<C: DatagramCarrier> ErasedDatagramCarrier for C {
    fn caps(&self) -> ChannelCaps {
        DatagramCarrier::caps(self)
    }

    fn open_link<'a>(
        &'a self,
        locator: &'a [u8],
    ) -> BoxFuture<'a, Result<Arc<dyn DatagramLink>, CoreError>> {
        Box::pin(async move {
            let link = DatagramCarrier::open_link(self, locator).await?;
            Ok(Arc::new(link) as Arc<dyn DatagramLink>)
        })
    }
}

/// Admission lifecycle state observed on an attached inbound `DatagramPort` (Spec §6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DatagramAdmission {
    /// No complete setup flight has entered admission on this link yet.
    Idle,
    /// At least one setup attempt is currently in flight (and none has been admitted yet).
    Pending,
    /// Sticky terminal state: at least one transit or destination circuit was admitted.
    Admitted,
    /// All prior setup attempts dropped before admission; subsequent attempts may still succeed.
    Rejected,
}

/// Shared lock-free admission tracker owned by a `DatagramPort` and observed by [`DatagramIngress`].
#[allow(dead_code)]
pub(crate) struct AdmissionTracker {
    admitted: AtomicBool,
    rejected: AtomicBool,
    in_flight: AtomicUsize,
}

#[allow(dead_code)]
impl AdmissionTracker {
    pub fn new() -> Self {
        Self {
            admitted: AtomicBool::new(false),
            rejected: AtomicBool::new(false),
            in_flight: AtomicUsize::new(0),
        }
    }

    pub fn status(&self) -> DatagramAdmission {
        if self.admitted.load(Ordering::Acquire) {
            DatagramAdmission::Admitted
        } else if self.in_flight.load(Ordering::Acquire) > 0 {
            DatagramAdmission::Pending
        } else if self.rejected.load(Ordering::Acquire) {
            DatagramAdmission::Rejected
        } else {
            DatagramAdmission::Idle
        }
    }

    pub fn begin_attempt(self: &Arc<Self>) -> AdmissionAttempt {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        AdmissionAttempt {
            tracker: Arc::clone(self),
            admitted: false,
        }
    }

    pub fn mark_admitted(&self) {
        self.admitted.store(true, Ordering::Release);
    }
}

/// RAII guard for one in-flight inbound datagram setup attempt.
#[allow(dead_code)]
pub(crate) struct AdmissionAttempt {
    tracker: Arc<AdmissionTracker>,
    admitted: bool,
}

#[allow(dead_code)]
impl AdmissionAttempt {
    /// Marks the link permanently [`DatagramAdmission::Admitted`].
    pub fn mark_admitted(&mut self) {
        self.admitted = true;
        self.tracker.mark_admitted();
    }
}

impl Drop for AdmissionAttempt {
    fn drop(&mut self) {
        if !self.admitted && !self.tracker.admitted.load(Ordering::Acquire) {
            self.tracker.rejected.store(true, Ordering::Release);
        }
        self.tracker.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Lifecycle handle returned when attaching a [`DatagramLink`] via `ScopeInstance::attach_datagram`
/// or `Node::attach_datagram` (Spec §6.2).
///
/// Observing [`DatagramAdmission::Rejected`] takes no automatic action inside Core and never closes
/// the underlying link; embedding hosts decide whether to retain or drop rejected links.
#[derive(Clone)]
pub struct DatagramIngress {
    tracker: Arc<AdmissionTracker>,
    closed_rx: WatchReceiver<Option<CoreError>>,
}

#[allow(dead_code)]
impl DatagramIngress {
    pub(crate) fn new(
        tracker: Arc<AdmissionTracker>,
        closed_rx: WatchReceiver<Option<CoreError>>,
    ) -> Self {
        Self { tracker, closed_rx }
    }

    /// Returns the current [`DatagramAdmission`] status without blocking.
    #[must_use]
    pub fn admission(&self) -> DatagramAdmission {
        self.tracker.status()
    }

    /// Resolves with the terminal [`CoreError`] once the attached `DatagramPort` stops running.
    pub async fn closed(&self) -> CoreError {
        let mut rx = self.closed_rx.clone();
        loop {
            if let Some(err) = rx.borrow_cloned() {
                return err;
            }
            if !rx.changed().await {
                return rx.borrow_cloned().unwrap_or(CoreError::Closed);
            }
        }
    }
}

impl fmt::Debug for DatagramIngress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramIngress")
            .field("admission", &self.admission())
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::runtime::TaskSpawner;
    use crate::testing::TestSpawner;

    #[test]
    fn mtu_watch_composition_and_spurious_suppression() {
        let spawner = TestSpawner::new();
        let (tx, base) = MtuWatch::channel(1500);
        // Apply cap(1400) THEN overhead(12) => effective = min(raw, 1400) - 12 = min(raw - 12, 1388).
        let mut wrapped = base.with_cap(1400).with_overhead(12);
        assert_eq!(wrapped.current(), 1388);

        // Changing 1500 -> 1450 stays above cap(1400), so transformed MTU is still 1388 -> suppressed!
        let mut w_clone = wrapped.clone();
        let (done_tx, done_rx) = Watch::new(None::<Option<u16>>);
        spawner.spawn(Box::pin(async move {
            let v = w_clone.changed().await;
            done_tx.send(Some(v));
        }));
        spawner.drive_until_idle();
        assert_eq!(done_rx.borrow_cloned(), None);

        tx.set(1450);
        spawner.drive_until_idle();
        // Still waiting because 1450 -> 1388 == seen!
        assert_eq!(done_rx.borrow_cloned(), None);

        // Dropping to 1300 -> 1288 != 1388 wakes the watcher!
        tx.set(1300);
        spawner.drive_until_idle();
        assert_eq!(done_rx.borrow_cloned(), Some(Some(1288)));
        assert_eq!(wrapped.current(), 1288);

        // clamp_seen suppresses identical update, allows recovery.
        wrapped.clamp_seen(1200);
        tx.set(1212); // 1212 - 12 = 1200 == seen
        let mut w2 = wrapped.clone();
        let (d2_tx, d2_rx) = Watch::new(None::<Option<u16>>);
        spawner.spawn(Box::pin(async move {
            d2_tx.send(Some(w2.changed().await));
        }));
        spawner.drive_until_idle();
        assert_eq!(d2_rx.borrow_cloned(), None);

        tx.set(1262); // 1262 - 12 = 1250 != 1200
        spawner.drive_until_idle();
        assert_eq!(d2_rx.borrow_cloned(), Some(Some(1250)));

        // Fixed watch returns None immediately.
        let mut fixed = MtuWatch::fixed(1232);
        assert_eq!(spawner.try_block_on(fixed.changed()), Some(None));
    }

    #[test]
    fn mtu_watch_sample_synchronizes_baseline_on_1100_1400_1100_drop() {
        let spawner = TestSpawner::new();

        // Exact L03-08 scenario: create at 1100, publish 1400, sample 1400 at startup
        // (against floor 1152), then drop back to 1100 before polling changed().
        let (tx, mut watch) = MtuWatch::channel(1100);
        tx.set(1400);
        assert_eq!(watch.sample(), 1400);

        // Drop back to original 1100 BEFORE changed() is polled -> MUST NOT be suppressed!
        tx.set(1100);
        assert_eq!(spawner.try_block_on(watch.changed()), Some(Some(1100)));

        // Verify with composed overhead/cap wrapper too.
        let (tx2, base2) = MtuWatch::channel(1120);
        tx2.set(1420);
        let mut wrapped = base2.with_overhead(20); // initialized at 1400
        assert_eq!(wrapped.sample(), 1400);
        tx2.set(1120); // effective 1100
        assert_eq!(spawner.try_block_on(wrapped.changed()), Some(Some(1100)));
    }

    #[test]
    fn datagram_admission_state_machine_transitions() {
        let tracker = Arc::new(AdmissionTracker::new());
        let (close_tx, close_rx) = Watch::new(None);
        let ingress = DatagramIngress::new(Arc::clone(&tracker), close_rx);

        assert_eq!(ingress.admission(), DatagramAdmission::Idle);
        let attempt1 = tracker.begin_attempt();
        assert_eq!(ingress.admission(), DatagramAdmission::Pending);
        drop(attempt1);
        assert_eq!(ingress.admission(), DatagramAdmission::Rejected);

        // Subsequent attempt transitions Rejected -> Pending -> Admitted (sticky!).
        let mut attempt2 = tracker.begin_attempt();
        assert_eq!(ingress.admission(), DatagramAdmission::Pending);
        attempt2.mark_admitted();
        assert_eq!(ingress.admission(), DatagramAdmission::Admitted);
        drop(attempt2);
        assert_eq!(ingress.admission(), DatagramAdmission::Admitted);

        // Failed subsequent attempt does not clear sticky Admitted.
        let attempt3 = tracker.begin_attempt();
        assert_eq!(ingress.admission(), DatagramAdmission::Admitted);
        drop(attempt3);
        assert_eq!(ingress.admission(), DatagramAdmission::Admitted);

        let spawner = TestSpawner::new();
        close_tx.send(Some(CoreError::UnexpectedEof));
        assert_eq!(
            spawner.try_block_on(ingress.closed()),
            Some(CoreError::UnexpectedEof)
        );
    }
}
