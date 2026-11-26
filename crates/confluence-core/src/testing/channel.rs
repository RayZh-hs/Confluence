//! Controllable in-memory Stream and Datagram channels with live `MtuWatch` and fault injection.

use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::error::CoreError;
use crate::packet::PacketBuf;
use crate::seam::channel::{
    ChannelCaps, DatagramCarrier, DatagramLink, DatagramListener, IntoStreamHalves, MtuSender,
    MtuWatch, StreamCarrier, StreamListener, StreamRead, StreamWrite,
};
use crate::types::LinkId;

fn lock_unpoisoned<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Controllable In-Memory Stream Pair + Carrier/Listener
// ---------------------------------------------------------------------------

struct StreamPipe {
    buf: VecDeque<u8>,
    capacity: usize,
    write_closed: bool,
    read_dropped: bool,
    max_write_chunk: Option<usize>,
    retryable_write_errors: usize,
    fatal_error: Option<CoreError>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

impl StreamPipe {
    fn new(capacity: usize) -> Self {
        Self {
            buf: VecDeque::new(),
            capacity: capacity.max(1),
            write_closed: false,
            read_dropped: false,
            max_write_chunk: None,
            retryable_write_errors: 0,
            fatal_error: None,
            read_waker: None,
            write_waker: None,
        }
    }
}

/// Fault and live-MTU controller for one direction of a [`MemoryStreamPair`].
#[derive(Clone)]
pub struct StreamFaults {
    outbound: Arc<Mutex<StreamPipe>>,
    mtu_tx: MtuSender,
}

impl StreamFaults {
    /// Dynamically updates this end's live effective MTU.
    pub fn set_mtu(&self, mtu: u16) {
        self.mtu_tx.set(mtu);
    }

    /// Limits each `poll_write` call to at most `max_bytes` to test partial-write resumption.
    pub fn set_max_write_chunk(&self, max_bytes: Option<usize>) {
        lock_unpoisoned(&self.outbound).max_write_chunk = max_bytes;
    }

    /// Forces the next `count` `poll_write` calls to fail with a transient retryable carrier error.
    pub fn inject_retryable_write_errors(&self, count: usize) {
        lock_unpoisoned(&self.outbound).retryable_write_errors = count;
    }

    /// Abruptly closes the outbound pipe (simulating carrier drop before `ST_FIN`).
    pub fn inject_abrupt_eof(&self) {
        let waker = {
            let mut pipe = lock_unpoisoned(&self.outbound);
            pipe.write_closed = true;
            pipe.read_waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }

    /// Injects a persistent fatal carrier error into future reads/writes on this pipe.
    pub fn inject_fatal_error(&self, err: CoreError) {
        let (rw, ww) = {
            let mut pipe = lock_unpoisoned(&self.outbound);
            pipe.fatal_error = Some(err);
            (pipe.read_waker.take(), pipe.write_waker.take())
        };
        if let Some(w) = rw {
            w.wake();
        }
        if let Some(w) = ww {
            w.wake();
        }
    }
}

/// Read half of an in-memory [`MemoryStream`].
pub struct MemoryStreamRead {
    inbound: Arc<Mutex<StreamPipe>>,
}

impl StreamRead for MemoryStreamRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, CoreError>> {
        let mut pipe = lock_unpoisoned(&self.inbound);
        if let Some(ref err) = pipe.fatal_error {
            return Poll::Ready(Err(err.clone()));
        }
        if !pipe.buf.is_empty() {
            let n = buf.len().min(pipe.buf.len());
            for slot in buf.iter_mut().take(n) {
                if let Some(b) = pipe.buf.pop_front() {
                    *slot = b;
                }
            }
            if let Some(w) = pipe.write_waker.take() {
                w.wake();
            }
            return Poll::Ready(Ok(n));
        }
        if pipe.write_closed {
            return Poll::Ready(Ok(0));
        }
        pipe.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl Drop for MemoryStreamRead {
    fn drop(&mut self) {
        let waker = {
            let mut pipe = lock_unpoisoned(&self.inbound);
            pipe.read_dropped = true;
            pipe.write_waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
}

/// Write half of an in-memory [`MemoryStream`].
pub struct MemoryStreamWrite {
    outbound: Arc<Mutex<StreamPipe>>,
}

impl StreamWrite for MemoryStreamWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, CoreError>> {
        let mut pipe = lock_unpoisoned(&self.outbound);
        if let Some(ref err) = pipe.fatal_error {
            return Poll::Ready(Err(err.clone()));
        }
        if pipe.retryable_write_errors > 0 {
            pipe.retryable_write_errors -= 1;
            return Poll::Ready(Err(CoreError::CarrierFailure {
                message: "injected transient write error".into(),
                transient: true,
            }));
        }
        if pipe.write_closed || pipe.read_dropped {
            return Poll::Ready(Err(CoreError::Closed));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let free = pipe.capacity.saturating_sub(pipe.buf.len());
        if free == 0 {
            pipe.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let mut to_write = buf.len().min(free);
        if let Some(limit) = pipe.max_write_chunk {
            to_write = to_write.min(limit.max(1));
        }
        pipe.buf.extend(&buf[..to_write]);
        if let Some(w) = pipe.read_waker.take() {
            w.wake();
        }
        Poll::Ready(Ok(to_write))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
        let pipe = lock_unpoisoned(&self.outbound);
        if let Some(ref err) = pipe.fatal_error {
            return Poll::Ready(Err(err.clone()));
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
        let waker = {
            let mut pipe = lock_unpoisoned(&self.outbound);
            pipe.write_closed = true;
            pipe.read_waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for MemoryStreamWrite {
    fn drop(&mut self) {
        let waker = {
            let mut pipe = lock_unpoisoned(&self.outbound);
            pipe.write_closed = true;
            pipe.read_waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
}

/// Connected in-memory pure byte stream implementing [`IntoStreamHalves`].
pub struct MemoryStream {
    caps: ChannelCaps,
    source_tag: [u8; 16],
    read: MemoryStreamRead,
    write: MemoryStreamWrite,
}

impl IntoStreamHalves for MemoryStream {
    type Read = MemoryStreamRead;
    type Write = MemoryStreamWrite;

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

/// Connected pair of [`MemoryStream`] endpoints with live MTU and fault controllers.
pub struct MemoryStreamPair {
    /// Client/A end of the stream.
    pub a: MemoryStream,
    /// Server/B end of the stream.
    pub b: MemoryStream,
    /// Fault and live-MTU controller for end A -> B.
    pub a_faults: StreamFaults,
    /// Fault and live-MTU controller for end B -> A.
    pub b_faults: StreamFaults,
}

impl MemoryStreamPair {
    /// Creates a connected pair of in-memory streams initialized at `mtu`.
    #[must_use]
    pub fn pair(mtu: u16) -> Self {
        Self::with_source_tags(mtu, [0x11; 16], [0x22; 16])
    }

    /// Creates a connected pair with explicit 16-byte peer `source_tag`s.
    #[must_use]
    pub fn with_source_tags(mtu: u16, tag_a: [u8; 16], tag_b: [u8; 16]) -> Self {
        let a_to_b = Arc::new(Mutex::new(StreamPipe::new(65_536)));
        let b_to_a = Arc::new(Mutex::new(StreamPipe::new(65_536)));
        let (mtu_tx_a, mtu_rx_a) = MtuWatch::channel(mtu);
        let (mtu_tx_b, mtu_rx_b) = MtuWatch::channel(mtu);

        Self {
            a: MemoryStream {
                caps: ChannelCaps::dynamic(mtu, true, mtu_rx_a),
                source_tag: tag_a,
                read: MemoryStreamRead {
                    inbound: Arc::clone(&b_to_a),
                },
                write: MemoryStreamWrite {
                    outbound: Arc::clone(&a_to_b),
                },
            },
            b: MemoryStream {
                caps: ChannelCaps::dynamic(mtu, true, mtu_rx_b),
                source_tag: tag_b,
                read: MemoryStreamRead {
                    inbound: Arc::clone(&a_to_b),
                },
                write: MemoryStreamWrite {
                    outbound: Arc::clone(&b_to_a),
                },
            },
            a_faults: StreamFaults {
                outbound: a_to_b,
                mtu_tx: mtu_tx_a,
            },
            b_faults: StreamFaults {
                outbound: b_to_a,
                mtu_tx: mtu_tx_b,
            },
        }
    }
}

/// In-memory [`StreamCarrier`] paired with a [`MemoryStreamListener`].
#[derive(Clone)]
pub struct MemoryStreamCarrier {
    caps: ChannelCaps,
    tx: async_channel::Sender<MemoryStream>,
    source_tag: [u8; 16],
}

/// In-memory [`StreamListener`] accepting streams dialed through its paired [`MemoryStreamCarrier`].
pub struct MemoryStreamListener {
    rx: async_channel::Receiver<MemoryStream>,
}

/// Creates a paired `(MemoryStreamCarrier, MemoryStreamListener, MtuSender)` initialized at `mtu`.
#[must_use]
pub fn memory_stream_channel(mtu: u16) -> (MemoryStreamCarrier, MemoryStreamListener, MtuSender) {
    let (mtu_tx, mtu_rx) = MtuWatch::channel(mtu);
    let (tx, rx) = async_channel::unbounded();
    let carrier = MemoryStreamCarrier {
        caps: ChannelCaps::dynamic(mtu, true, mtu_rx),
        tx,
        source_tag: [0xA5; 16],
    };
    (carrier, MemoryStreamListener { rx }, mtu_tx)
}

impl StreamCarrier for MemoryStreamCarrier {
    type Stream = MemoryStream;

    fn caps(&self) -> ChannelCaps {
        self.caps.clone()
    }

    async fn dial_stream(&self, _locator: &[u8]) -> Result<Self::Stream, CoreError> {
        let mtu = self.caps.mtu();
        let pair = MemoryStreamPair::with_source_tags(mtu, self.source_tag, self.source_tag);
        self.tx
            .send(pair.b)
            .await
            .map_err(|_| CoreError::TargetUnreachable)?;
        Ok(pair.a)
    }
}

impl StreamListener for MemoryStreamListener {
    type Stream = MemoryStream;

    async fn accept(&self) -> Result<Self::Stream, CoreError> {
        self.rx.recv().await.map_err(|_| CoreError::Closed)
    }
}

// ---------------------------------------------------------------------------
// Controllable In-Memory Datagram Pair + Carrier/Listener
// ---------------------------------------------------------------------------

struct DatagramPipe {
    queue: VecDeque<PacketBuf>,
    capacity: usize,
    drop_next: usize,
    reorder_hold: Option<PacketBuf>,
    reorder_next_pair: bool,
    retryable_send_errors: usize,
    fatal_error: Option<CoreError>,
    closed: bool,
    capture_enabled: bool,
    captured: Vec<PacketBuf>,
    recv_waker: Option<Waker>,
    send_waker: Option<Waker>,
}

impl DatagramPipe {
    fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            capacity: capacity.max(1),
            drop_next: 0,
            reorder_hold: None,
            reorder_next_pair: false,
            retryable_send_errors: 0,
            fatal_error: None,
            closed: false,
            capture_enabled: false,
            captured: Vec::new(),
            recv_waker: None,
            send_waker: None,
        }
    }
}

/// Fault and live-MTU controller for one direction of a [`MemoryDatagramPair`].
#[derive(Clone)]
pub struct DatagramFaults {
    outbound: Arc<Mutex<DatagramPipe>>,
    mtu_tx: MtuSender,
}

impl DatagramFaults {
    /// Dynamically updates this link end's live effective MTU.
    pub fn set_mtu(&self, mtu: u16) {
        self.mtu_tx.set(mtu);
    }

    /// Silently drops the next `count` outbound packets sent on this link end.
    pub fn drop_next(&self, count: usize) {
        lock_unpoisoned(&self.outbound).drop_next = count;
    }

    /// Reorders the next two outbound packets (delivers packet 2 before packet 1).
    pub fn reorder_next_pair(&self) {
        lock_unpoisoned(&self.outbound).reorder_next_pair = true;
    }

    /// Causes the next `count` `try_send` calls to return a transient retryable carrier error.
    pub fn inject_retryable_send_errors(&self, count: usize) {
        lock_unpoisoned(&self.outbound).retryable_send_errors = count;
    }

    /// Injects a fatal carrier error into future sends/recvs on this direction.
    pub fn inject_fatal_error(&self, err: CoreError) {
        let (rw, sw) = {
            let mut pipe = lock_unpoisoned(&self.outbound);
            pipe.fatal_error = Some(err);
            (pipe.recv_waker.take(), pipe.send_waker.take())
        };
        if let Some(w) = rw {
            w.wake();
        }
        if let Some(w) = sw {
            w.wake();
        }
    }

    /// Closes this direction's queue (peer receives [`CoreError::Closed`]).
    pub fn close(&self) {
        let (rw, sw) = {
            let mut pipe = lock_unpoisoned(&self.outbound);
            pipe.closed = true;
            (pipe.recv_waker.take(), pipe.send_waker.take())
        };
        if let Some(w) = rw {
            w.wake();
        }
        if let Some(w) = sw {
            w.wake();
        }
    }

    /// Enables or disables wire-packet capture for inspection in tests.
    pub fn set_capture(&self, enabled: bool) {
        lock_unpoisoned(&self.outbound).capture_enabled = enabled;
    }

    /// Drains all captured outbound wire packets.
    #[must_use]
    pub fn drain_captured(&self) -> Vec<PacketBuf> {
        core::mem::take(&mut lock_unpoisoned(&self.outbound).captured)
    }
}

/// Connected in-memory pure [`DatagramLink`] enforcing live MTU and fault injection.
pub struct MemoryDatagramLink {
    caps: ChannelCaps,
    source_tag: [u8; 16],
    link_id: LinkId,
    outbound: Arc<Mutex<DatagramPipe>>,
    inbound: Arc<Mutex<DatagramPipe>>,
}

impl DatagramLink for MemoryDatagramLink {
    fn caps(&self) -> ChannelCaps {
        self.caps.clone()
    }

    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
        let mut pipe = lock_unpoisoned(&self.outbound);
        if let Some(ref err) = pipe.fatal_error {
            return Poll::Ready(Err(err.clone()));
        }
        if pipe.closed {
            return Poll::Ready(Err(CoreError::Closed));
        }
        if pipe.queue.len() < pipe.capacity {
            Poll::Ready(Ok(()))
        } else {
            pipe.send_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    fn try_send(&self, packet: PacketBuf) -> Result<(), CoreError> {
        let mtu = self.caps.mtu();
        if packet.len() > usize::from(mtu) {
            return Err(CoreError::MtuTooSmall(mtu));
        }
        let waker = {
            let mut pipe = lock_unpoisoned(&self.outbound);
            if let Some(ref err) = pipe.fatal_error {
                return Err(err.clone());
            }
            if pipe.closed {
                return Err(CoreError::Closed);
            }
            if pipe.retryable_send_errors > 0 {
                pipe.retryable_send_errors -= 1;
                return Err(CoreError::CarrierFailure {
                    message: "injected transient datagram send error".into(),
                    transient: true,
                });
            }
            if pipe.queue.len() >= pipe.capacity {
                return Err(CoreError::WouldBlock);
            }
            if pipe.capture_enabled {
                pipe.captured.push(packet.clone());
            }
            if pipe.drop_next > 0 {
                pipe.drop_next -= 1;
                return Ok(());
            }
            if pipe.reorder_next_pair {
                pipe.reorder_next_pair = false;
                pipe.reorder_hold = Some(packet);
                return Ok(());
            }
            pipe.queue.push_back(packet);
            if let Some(held) = pipe.reorder_hold.take() {
                pipe.queue.push_back(held);
            }
            pipe.recv_waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
        Ok(())
    }

    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<PacketBuf, CoreError>> {
        let mut pipe = lock_unpoisoned(&self.inbound);
        if let Some(pkt) = pipe.queue.pop_front() {
            if let Some(w) = pipe.send_waker.take() {
                w.wake();
            }
            return Poll::Ready(Ok(pkt));
        }
        if let Some(ref err) = pipe.fatal_error {
            return Poll::Ready(Err(err.clone()));
        }
        if pipe.closed {
            return Poll::Ready(Err(CoreError::Closed));
        }
        pipe.recv_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn source_tag(&self) -> [u8; 16] {
        self.source_tag
    }

    fn link_id(&self) -> LinkId {
        self.link_id
    }
}

/// Connected pair of [`MemoryDatagramLink`] endpoints with live MTU and fault controllers.
pub struct MemoryDatagramPair {
    /// End A link (wrapped in `Arc` for 1:N sharing).
    pub a: Arc<MemoryDatagramLink>,
    /// End B link (wrapped in `Arc` for 1:N sharing).
    pub b: Arc<MemoryDatagramLink>,
    /// Fault and live-MTU controller for A -> B.
    pub a_faults: DatagramFaults,
    /// Fault and live-MTU controller for B -> A.
    pub b_faults: DatagramFaults,
}

impl MemoryDatagramPair {
    /// Creates a connected pair of in-memory datagram links initialized at `mtu`.
    #[must_use]
    pub fn pair(mtu: u16) -> Self {
        Self::with_source_tags(mtu, [0x33; 16], [0x44; 16])
    }

    /// Creates a connected pair with explicit 16-byte peer `source_tag`s.
    #[must_use]
    pub fn with_source_tags(mtu: u16, tag_a: [u8; 16], tag_b: [u8; 16]) -> Self {
        let a_to_b = Arc::new(Mutex::new(DatagramPipe::new(256)));
        let b_to_a = Arc::new(Mutex::new(DatagramPipe::new(256)));
        let (mtu_tx_a, mtu_rx_a) = MtuWatch::channel(mtu);
        let (mtu_tx_b, mtu_rx_b) = MtuWatch::channel(mtu);

        Self {
            a: Arc::new(MemoryDatagramLink {
                caps: ChannelCaps::dynamic(mtu, false, mtu_rx_a),
                source_tag: tag_a,
                link_id: LinkId::allocate(),
                outbound: Arc::clone(&a_to_b),
                inbound: Arc::clone(&b_to_a),
            }),
            b: Arc::new(MemoryDatagramLink {
                caps: ChannelCaps::dynamic(mtu, false, mtu_rx_b),
                source_tag: tag_b,
                link_id: LinkId::allocate(),
                outbound: Arc::clone(&b_to_a),
                inbound: Arc::clone(&a_to_b),
            }),
            a_faults: DatagramFaults {
                outbound: a_to_b,
                mtu_tx: mtu_tx_a,
            },
            b_faults: DatagramFaults {
                outbound: b_to_a,
                mtu_tx: mtu_tx_b,
            },
        }
    }
}

/// In-memory [`DatagramCarrier`] paired with a [`MemoryDatagramListener`].
#[derive(Clone)]
pub struct MemoryDatagramCarrier {
    caps: ChannelCaps,
    tx: async_channel::Sender<Arc<MemoryDatagramLink>>,
    source_tag: [u8; 16],
}

/// In-memory [`DatagramListener`] accepting links opened via its paired [`MemoryDatagramCarrier`].
pub struct MemoryDatagramListener {
    rx: async_channel::Receiver<Arc<MemoryDatagramLink>>,
}

/// Creates a paired `(MemoryDatagramCarrier, MemoryDatagramListener, MtuSender)` initialized at `mtu`.
#[must_use]
pub fn memory_datagram_channel(
    mtu: u16,
) -> (MemoryDatagramCarrier, MemoryDatagramListener, MtuSender) {
    let (mtu_tx, mtu_rx) = MtuWatch::channel(mtu);
    let (tx, rx) = async_channel::unbounded();
    let carrier = MemoryDatagramCarrier {
        caps: ChannelCaps::dynamic(mtu, false, mtu_rx),
        tx,
        source_tag: [0x5A; 16],
    };
    (carrier, MemoryDatagramListener { rx }, mtu_tx)
}

impl DatagramCarrier for MemoryDatagramCarrier {
    type Link = Arc<MemoryDatagramLink>;

    fn caps(&self) -> ChannelCaps {
        self.caps.clone()
    }

    async fn open_link(&self, _locator: &[u8]) -> Result<Self::Link, CoreError> {
        let mtu = self.caps.mtu();
        let pair = MemoryDatagramPair::with_source_tags(mtu, self.source_tag, self.source_tag);
        self.tx
            .send(pair.b)
            .await
            .map_err(|_| CoreError::TargetUnreachable)?;
        Ok(pair.a)
    }
}

impl DatagramListener for MemoryDatagramListener {
    type Link = Arc<MemoryDatagramLink>;

    async fn accept_link(&self) -> Result<Self::Link, CoreError> {
        self.rx.recv().await.map_err(|_| CoreError::Closed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::seam::channel::{DatagramLinkExt, StreamReadExt, StreamWriteExt};
    use crate::testing::TestSpawner;

    #[test]
    fn memory_stream_partial_writes_and_retryable_errors() {
        let spawner = TestSpawner::new();
        let pair = MemoryStreamPair::pair(16_384);
        pair.a_faults.set_max_write_chunk(Some(3));
        pair.a_faults.inject_retryable_write_errors(1);

        let (_ar, mut aw) = pair.a.into_halves();
        let (mut br, _bw) = pair.b.into_halves();

        // First write returns transient error.
        let err = spawner.try_block_on(aw.write(b"hello")).unwrap().unwrap_err();
        assert!(err.is_retryable());
        // Second write respects partial chunk limit = 3.
        assert_eq!(spawner.try_block_on(aw.write(b"hello")), Some(Ok(3)));
        let mut buf = [0u8; 3];
        assert_eq!(spawner.try_block_on(br.read_exact(&mut buf)), Some(Ok(())));
        assert_eq!(&buf, b"hel");
    }

    #[test]
    fn memory_datagram_mtu_drop_and_reorder_injection() {
        let spawner = TestSpawner::new();
        let pair = MemoryDatagramPair::pair(1200);

        // Oversized packet rejected with MtuTooSmall(1200).
        assert_eq!(
            pair.a.try_send(PacketBuf::with_payload_len(1201)),
            Err(CoreError::MtuTooSmall(1200))
        );

        // Reorder next pair: send P1 then P2 -> peer receives P2 then P1!
        pair.a_faults.reorder_next_pair();
        pair.a.try_send(PacketBuf::from_payload(b"first")).unwrap();
        pair.a.try_send(PacketBuf::from_payload(b"second")).unwrap();

        let r1 = spawner.try_block_on(pair.b.recv()).unwrap().unwrap();
        let r2 = spawner.try_block_on(pair.b.recv()).unwrap().unwrap();
        assert_eq!(r1.payload(), b"second");
        assert_eq!(r2.payload(), b"first");
    }
}
