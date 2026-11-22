use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU8, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf},
    sync::{Mutex as AsyncMutex, mpsc, watch},
};

use confluence_core::{
    AsyncStream, BoxFut, ChannelCaps, CoreErr, DatagramChannel, DatagramLink, PacketBuf,
    ScopeInstance, StreamChannel, StreamRead, StreamWrite,
};

const ACCEPT_QUEUE: usize = 32;

type ListenerMap<T> = Arc<Mutex<HashMap<Vec<u8>, Weak<mpsc::Sender<T>>>>>;

pub struct MemListener<T> {
    _keep_open: Arc<mpsc::Sender<T>>,
    incoming: mpsc::Receiver<T>,
}
impl<T> MemListener<T> {
    pub async fn accept(&mut self) -> Option<T> {
        self.incoming.recv().await
    }
}

fn listen<T>(addresses: &ListenerMap<T>, address: &[u8]) -> Result<MemListener<T>, CoreErr> {
    let mut addresses = addresses.lock().unwrap();
    if addresses.get(address).and_then(Weak::upgrade).is_some() {
        return Err(CoreErr::AlreadyPublished);
    }
    let (sender, incoming) = mpsc::channel(ACCEPT_QUEUE);
    let sender = Arc::new(sender);
    addresses.insert(address.into(), Arc::downgrade(&sender));
    Ok(MemListener {
        _keep_open: sender,
        incoming,
    })
}
fn lookup<T>(addresses: &ListenerMap<T>, address: &[u8]) -> Result<Arc<mpsc::Sender<T>>, CoreErr> {
    addresses
        .lock()
        .unwrap()
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

#[derive(Clone)]
pub struct MemStreamChannel {
    addresses: ListenerMap<Box<dyn AsyncStream>>,
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
    pub fn listen(&self, name: &[u8]) -> Result<MemListener<Box<dyn AsyncStream>>, CoreErr> {
        listen(&self.addresses, name)
    }
}
impl MemListener<Box<dyn AsyncStream>> {
    pub async fn serve_stream(mut self, scope: ScopeInstance) {
        while let Some(stream) = self.accept().await {
            let _ = scope.accept_stream(stream);
        }
    }
}
impl StreamChannel for MemStreamChannel {
    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(self.mtu, true)
    }
    fn dial_stream<'a>(
        &'a self,
        locator: &'a [u8],
    ) -> BoxFut<'a, Result<Box<dyn AsyncStream>, CoreErr>> {
        Box::pin(async move {
            let listener = lookup(&self.addresses, locator)?;
            let (left, right) = mem_stream_pair(self.mtu, self.buffer);
            listener.try_send(right).map_err(queue_error)?;
            Ok(left)
        })
    }
}
pub fn mem_stream_pair(mtu: u16, capacity: usize) -> (Box<dyn AsyncStream>, Box<dyn AsyncStream>) {
    let (left, right) = tokio::io::duplex(capacity);
    (
        Box::new(MemStream(left, mtu)),
        Box::new(MemStream(right, mtu)),
    )
}
struct MemStream(DuplexStream, u16);
struct MemRead(ReadHalf<DuplexStream>);
struct MemWrite(WriteHalf<DuplexStream>);
impl AsyncStream for MemStream {
    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(self.1, true)
    }
    fn split(self: Box<Self>) -> (Box<dyn StreamRead>, Box<dyn StreamWrite>) {
        let (read, write) = tokio::io::split(self.0);
        (Box::new(MemRead(read)), Box::new(MemWrite(write)))
    }
}
impl StreamRead for MemRead {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFut<'a, Result<usize, CoreErr>> {
        Box::pin(async move { self.0.read(buf).await.map_err(io_error) })
    }
}
impl StreamWrite for MemWrite {
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> BoxFut<'a, Result<(), CoreErr>> {
        Box::pin(async move { self.0.write_all(buf).await.map_err(io_error) })
    }
    fn shutdown(&mut self) -> BoxFut<'_, Result<(), CoreErr>> {
        Box::pin(async move { self.0.shutdown().await.map_err(io_error) })
    }
}

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
    pub async fn serve_datagram(mut self, scope: ScopeInstance) {
        while let Some(link) = self.accept().await {
            if let Ok(ingress) = scope.attach_datagram(link) {
                tokio::spawn(async move {
                    ingress.closed().await;
                });
            }
        }
    }
}
impl DatagramChannel for MemDatagramChannel {
    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(self.mtu, false)
    }
    fn open_link<'a>(
        &'a self,
        locator: &'a [u8],
    ) -> BoxFut<'a, Result<Arc<dyn DatagramLink>, CoreErr>> {
        Box::pin(async move {
            let listener = lookup(&self.addresses, locator)?;
            let (left, right) = mem_datagram_pair(self.mtu, 32);
            listener.try_send(right).map_err(queue_error)?;
            Ok(left as Arc<dyn DatagramLink>)
        })
    }
}
pub struct MemDatagramLink {
    outbound: mpsc::Sender<PacketBuf>,
    inbound: AsyncMutex<mpsc::Receiver<PacketBuf>>,
    mtu: watch::Sender<u16>,
    drop_kind: AtomicU8,
    corrupt_kind: AtomicU8,
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
pub fn mem_datagram_pair(mtu: u16, queue: usize) -> (Arc<MemDatagramLink>, Arc<MemDatagramLink>) {
    let (left_tx, right_rx) = mpsc::channel(queue);
    let (right_tx, left_rx) = mpsc::channel(queue);
    let link = |outbound, inbound| {
        Arc::new(MemDatagramLink {
            outbound,
            inbound: AsyncMutex::new(inbound),
            mtu: watch::channel(mtu).0,
            drop_kind: 0.into(),
            corrupt_kind: 0.into(),
        })
    };
    (link(left_tx, left_rx), link(right_tx, right_rx))
}
impl DatagramLink for MemDatagramLink {
    fn caps(&self) -> ChannelCaps {
        ChannelCaps {
            effective_mtu: *self.mtu.borrow(),
            reliable_underlay: false,
            mtu_watch: self.mtu.subscribe(),
        }
    }
    fn send(&self, mut packet: PacketBuf) -> BoxFut<'_, Result<(), CoreErr>> {
        Box::pin(async move {
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
        })
    }
    fn recv(&self) -> BoxFut<'_, Result<PacketBuf, CoreErr>> {
        Box::pin(async move {
            self.inbound
                .lock()
                .await
                .recv()
                .await
                .ok_or(CoreErr::Closed)
        })
    }
}
