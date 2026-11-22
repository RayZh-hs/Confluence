//! In-memory Stream and Datagram channels for fast local testing and embedding.

use parking_lot::Mutex;
use std::{
    collections::HashMap,
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, ReadHalf, WriteHalf},
    sync::{Mutex as AsyncMutex, mpsc, watch},
};

use confluence_core::{
    AsyncStream, ChannelCaps, ChannelErr, CoreErr, DatagramChannel, DatagramLink, DatagramListener,
    IntoDynDatagramLink, Node, PacketBuf, ScopeInstance, StreamChannel, StreamListener, StreamRead,
    StreamWrite,
};

const ACCEPT_QUEUE: usize = 32;

type ListenerMap<T> = Arc<Mutex<HashMap<Vec<u8>, Weak<mpsc::Sender<T>>>>>;

static NEXT_TAG: AtomicU64 = AtomicU64::new(1);

fn unique_source_tag() -> [u8; 16] {
    let mut tag = [0u8; 16];
    tag[..8].copy_from_slice(&NEXT_TAG.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    tag
}

/// In-memory listener returned by [`MemStreamChannel::listen`] and [`MemDatagramChannel::listen`].
pub struct MemListener<T> {
    _keep_open: Arc<mpsc::Sender<T>>,
    incoming: AsyncMutex<mpsc::Receiver<T>>,
}

impl<T> MemListener<T> {
    pub async fn accept(&self) -> Option<T> {
        self.incoming.lock().await.recv().await
    }
}

fn listen<T>(addresses: &ListenerMap<T>, address: &[u8]) -> Result<MemListener<T>, CoreErr> {
    let mut addresses = addresses.lock();
    if addresses.get(address).and_then(Weak::upgrade).is_some() {
        return Err(CoreErr::AlreadyPublished);
    }
    let (sender, incoming) = mpsc::channel(ACCEPT_QUEUE);
    let sender = Arc::new(sender);
    addresses.insert(address.into(), Arc::downgrade(&sender));
    Ok(MemListener {
        _keep_open: sender,
        incoming: AsyncMutex::new(incoming),
    })
}

fn lookup<T>(addresses: &ListenerMap<T>, address: &[u8]) -> Result<Arc<mpsc::Sender<T>>, CoreErr> {
    addresses
        .lock()
        .get(address)
        .and_then(Weak::upgrade)
        .ok_or(CoreErr::TargetUnreachable)
}

fn queue_error<T>(error: mpsc::error::TrySendError<T>) -> CoreErr {
    match error {
        mpsc::error::TrySendError::Full(_) => CoreErr::WouldBlock,
        mpsc::error::TrySendError::Closed(_) => CoreErr::Closed,
    }
}

fn io_error(error: std::io::Error) -> CoreErr {
    CoreErr::Carrier(error.to_string())
}

impl<S: AsyncStream> StreamListener for MemListener<S> {
    type Stream = S;

    async fn accept(&self) -> Result<S, CoreErr> {
        self.incoming
            .lock()
            .await
            .recv()
            .await
            .ok_or(CoreErr::Closed)
    }
}

impl<L: IntoDynDatagramLink> DatagramListener for MemListener<L> {
    type Link = L;

    async fn accept_link(&self) -> Result<L, CoreErr> {
        self.incoming
            .lock()
            .await
            .recv()
            .await
            .ok_or(CoreErr::Closed)
    }
}

/// In-memory Stream Plane channel.
#[derive(Clone)]
pub struct MemStreamChannel {
    addresses: ListenerMap<MemStream>,
    mtu: u16,
    buffer: usize,
}

impl MemStreamChannel {
    pub fn new(mtu: u16, buffer: usize) -> Self {
        Self {
            addresses: Default::default(),
            mtu,
            buffer: buffer.max(1),
        }
    }

    pub fn listen(&self, name: &[u8]) -> Result<MemListener<MemStream>, CoreErr> {
        listen(&self.addresses, name)
    }
}

impl<S: AsyncStream> MemListener<S> {
    pub async fn serve_stream(self, scope: ScopeInstance) {
        while let Some(stream) = self.accept().await {
            let _ = scope.accept_stream(stream);
        }
    }

    pub async fn serve_stream_node(self, node: Node) {
        while let Some(stream) = self.accept().await {
            let _ = node.accept_stream(stream);
        }
    }
}

impl StreamChannel for MemStreamChannel {
    type Stream = MemStream;

    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(self.mtu, true)
    }

    async fn dial_stream(&self, locator: &[u8]) -> Result<MemStream, CoreErr> {
        let listener = lookup(&self.addresses, locator)?;
        let (left, right) = mem_stream_pair(self.mtu, self.buffer);
        listener.try_send(right).map_err(queue_error)?;
        Ok(left)
    }
}

/// Creates a connected pair of in-memory [`MemStream`]s with bounded duplex buffers.
pub fn mem_stream_pair(mtu: u16, capacity: usize) -> (MemStream, MemStream) {
    let (left, right) = tokio::io::duplex(capacity);
    (
        MemStream(left, mtu, [1; 16]),
        MemStream(right, mtu, [2; 16]),
    )
}

/// Concrete in-memory [`AsyncStream`] backed by a Tokio [`DuplexStream`].
pub struct MemStream(DuplexStream, u16, [u8; 16]);

/// Poll-based read half of [`MemStream`].
pub struct MemRead(ReadHalf<DuplexStream>);

/// Poll-based write half of [`MemStream`].
pub struct MemWrite(WriteHalf<DuplexStream>);

impl AsyncStream for MemStream {
    type Read = MemRead;
    type Write = MemWrite;

    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(self.1, true)
    }

    fn split(self) -> (MemRead, MemWrite) {
        let (read, write) = tokio::io::split(self.0);
        (MemRead(read), MemWrite(write))
    }

    fn source_tag(&self) -> [u8; 16] {
        self.2
    }
}

impl StreamRead for MemRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ChannelErr>> {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut self.0).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(io_error(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl StreamWrite for MemWrite {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, ChannelErr>> {
        Pin::new(&mut self.0).poll_write(cx, buf).map_err(io_error)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ChannelErr>> {
        Pin::new(&mut self.0).poll_flush(cx).map_err(io_error)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ChannelErr>> {
        Pin::new(&mut self.0).poll_shutdown(cx).map_err(io_error)
    }
}

/// In-memory Datagram Plane channel.
#[derive(Clone)]
pub struct MemDatagramChannel {
    addresses: ListenerMap<Arc<MemDatagramLink>>,
    mtu: u16,
}

impl MemDatagramChannel {
    pub fn new(mtu: u16) -> Self {
        Self {
            addresses: Default::default(),
            mtu,
        }
    }

    pub fn listen(&self, name: &[u8]) -> Result<MemListener<Arc<MemDatagramLink>>, CoreErr> {
        listen(&self.addresses, name)
    }
}

impl MemListener<Arc<MemDatagramLink>> {
    pub async fn serve_datagram(self, scope: ScopeInstance) {
        while let Some(link) = self.accept().await {
            if let Ok(ingress) = scope.attach_datagram(link) {
                tokio::spawn(async move {
                    ingress.closed().await;
                });
            }
        }
    }

    pub async fn serve_datagram_node(self, node: Node) {
        while let Some(link) = self.accept().await {
            if let Ok(ingress) = node.attach_datagram(link) {
                tokio::spawn(async move {
                    ingress.closed().await;
                });
            }
        }
    }
}

impl DatagramChannel for MemDatagramChannel {
    type Link = Arc<MemDatagramLink>;

    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(self.mtu, false)
    }

    async fn open_link(&self, locator: &[u8]) -> Result<Arc<MemDatagramLink>, CoreErr> {
        let listener = lookup(&self.addresses, locator)?;
        let (left, right) = mem_datagram_pair(self.mtu, 32);
        listener.try_send(right).map_err(queue_error)?;
        Ok(left)
    }
}

/// In-memory [`DatagramLink`] supporting dynamic MTU changes and single-packet fault injection.
pub struct MemDatagramLink {
    outbound: mpsc::Sender<PacketBuf>,
    inbound: Mutex<mpsc::Receiver<PacketBuf>>,
    mtu: watch::Sender<u16>,
    drop_kind: AtomicU8,
    corrupt_kind: AtomicU8,
    tag: [u8; 16],
}

impl MemDatagramLink {
    pub fn set_mtu(&self, mtu: u16) {
        self.mtu.send_replace(mtu);
    }

    pub fn drop_next_kind(&self, kind: u8) {
        self.drop_kind.store(kind, Ordering::Release);
    }

    pub fn corrupt_next_kind(&self, kind: u8) {
        self.corrupt_kind.store(kind, Ordering::Release);
    }
}

/// Creates a connected pair of in-memory [`MemDatagramLink`]s.
pub fn mem_datagram_pair(mtu: u16, queue: usize) -> (Arc<MemDatagramLink>, Arc<MemDatagramLink>) {
    let (left_tx, right_rx) = mpsc::channel(queue);
    let (right_tx, left_rx) = mpsc::channel(queue);
    let link = |outbound, inbound| {
        Arc::new(MemDatagramLink {
            outbound,
            inbound: Mutex::new(inbound),
            mtu: watch::channel(mtu).0,
            drop_kind: 0.into(),
            corrupt_kind: 0.into(),
            tag: unique_source_tag(),
        })
    };
    (link(left_tx, left_rx), link(right_tx, right_rx))
}

impl DatagramLink for MemDatagramLink {
    fn caps(&self) -> ChannelCaps {
        ChannelCaps::dynamic(self.mtu.subscribe(), false)
    }

    fn try_send(&self, mut packet: PacketBuf) -> Result<(), CoreErr> {
        let mtu = *self.mtu.borrow();
        if packet.len() > usize::from(mtu) {
            return Err(CoreErr::MtuTooSmall(mtu));
        }
        if let Some(kind) = packet.as_slice().first().copied().filter(|kind| *kind != 0) {
            if self
                .drop_kind
                .compare_exchange(kind, 0, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(());
            }
            if self
                .corrupt_kind
                .compare_exchange(kind, 0, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
                && let Some(last) = packet.as_mut_slice().last_mut()
            {
                *last ^= 1;
            }
        }
        self.outbound.try_send(packet).map_err(queue_error)
    }

    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<PacketBuf, CoreErr>> {
        self.inbound
            .lock()
            .poll_recv(cx)
            .map(|opt| opt.ok_or(CoreErr::Closed))
    }

    fn source_tag(&self) -> [u8; 16] {
        self.tag
    }
}
