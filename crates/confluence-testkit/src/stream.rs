//! Deterministic in-memory Stream hub with dial counters, wire-tap capture, and mid-session link cuts.

use confluence_core::{
    AsyncStream, BoxFut, ChannelCaps, ChannelErr, CoreErr, StreamChannel, StreamListener,
    StreamRead, StreamWrite,
};
use parking_lot::Mutex;
use std::{
    collections::HashMap,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, ReadHalf, WriteHalf},
    sync::{Mutex as AsyncMutex, mpsc, watch},
};

type LinkKey = (Vec<u8>, Vec<u8>);

struct StreamEndpoint {
    accept_tx: mpsc::Sender<HubStream>,
    mtu: watch::Sender<u16>,
    buf_cap: usize,
}

/// Deterministic in-memory Stream fabric with wire-tap capture, dial counters, and link cuts.
pub struct MemStreamHub {
    default_mtu: u16,
    default_buf: usize,
    endpoints: Mutex<HashMap<Vec<u8>, StreamEndpoint>>,
    down_links: Mutex<HashMap<LinkKey, bool>>,
    latencies: Mutex<HashMap<LinkKey, Duration>>,
    wire_tap: Mutex<HashMap<LinkKey, Vec<u8>>>,
    cut_signals: Mutex<HashMap<LinkKey, Vec<watch::Sender<bool>>>>,
}

impl MemStreamHub {
    pub fn new(default_mtu: u16, default_buf: usize) -> Arc<Self> {
        Arc::new(Self {
            default_mtu,
            default_buf: default_buf.max(256),
            endpoints: Default::default(),
            down_links: Default::default(),
            latencies: Default::default(),
            wire_tap: Default::default(),
            cut_signals: Default::default(),
        })
    }

    pub fn bind(self: &Arc<Self>, addr: impl AsRef<[u8]>) -> Arc<HubStreamChannel> {
        self.bind_with_mtu(addr, self.default_mtu, self.default_buf)
    }

    pub fn bind_with_mtu(
        self: &Arc<Self>,
        addr: impl AsRef<[u8]>,
        mtu: u16,
        buf_cap: usize,
    ) -> Arc<HubStreamChannel> {
        let local_addr = addr.as_ref().to_vec();
        let (accept_tx, accept_rx) = mpsc::channel(64);
        let (mtu_tx, _) = watch::channel(mtu);
        self.endpoints.lock().insert(
            local_addr.clone(),
            StreamEndpoint {
                accept_tx,
                mtu: mtu_tx.clone(),
                buf_cap: buf_cap.max(256),
            },
        );
        Arc::new(HubStreamChannel {
            local_addr,
            hub: self.clone(),
            mtu: mtu_tx,
            accept_rx: AsyncMutex::new(accept_rx),
            outbound_dials: AtomicUsize::new(0),
        })
    }

    pub fn set_link_down(&self, src: impl AsRef<[u8]>, dst: impl AsRef<[u8]>, down: bool) {
        self.down_links
            .lock()
            .insert((src.as_ref().to_vec(), dst.as_ref().to_vec()), down);
    }

    pub fn set_link_latency(
        &self,
        src: impl AsRef<[u8]>,
        dst: impl AsRef<[u8]>,
        latency: Duration,
    ) {
        self.latencies
            .lock()
            .insert((src.as_ref().to_vec(), dst.as_ref().to_vec()), latency);
    }

    /// Immediately aborts all live streams between `a` and `b` in both directions.
    pub fn cut_active_links(&self, a: impl AsRef<[u8]>, b: impl AsRef<[u8]>) {
        let mut cuts = self.cut_signals.lock();
        for key in [
            (a.as_ref().to_vec(), b.as_ref().to_vec()),
            (b.as_ref().to_vec(), a.as_ref().to_vec()),
        ] {
            if let Some(senders) = cuts.remove(&key) {
                for tx in senders {
                    let _ = tx.send(true);
                }
            }
        }
    }

    /// Returns all raw wire bytes observed on `src -> dst`.
    pub fn captured_bytes(&self, src: impl AsRef<[u8]>, dst: impl AsRef<[u8]>) -> Vec<u8> {
        self.wire_tap
            .lock()
            .get(&(src.as_ref().to_vec(), dst.as_ref().to_vec()))
            .cloned()
            .unwrap_or_default()
    }

    /// Returns all raw wire bytes captured across every link in the hub.
    pub fn all_captured_bytes(&self) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        self.wire_tap
            .lock()
            .iter()
            .map(|((s, d), bytes)| (s.clone(), d.clone(), bytes.clone()))
            .collect()
    }

    pub fn clear_wire_tap(&self) {
        self.wire_tap.lock().clear();
    }

    fn record_bytes(&self, src: &[u8], dst: &[u8], data: &[u8]) {
        self.wire_tap
            .lock()
            .entry((src.to_vec(), dst.to_vec()))
            .or_default()
            .extend_from_slice(data);
    }
}

/// Hub-attached [`StreamChannel`] + [`StreamListener`] with outbound-dial auditing.
pub struct HubStreamChannel {
    local_addr: Vec<u8>,
    hub: Arc<MemStreamHub>,
    mtu: watch::Sender<u16>,
    accept_rx: AsyncMutex<mpsc::Receiver<HubStream>>,
    outbound_dials: AtomicUsize,
}

impl HubStreamChannel {
    pub fn local_addr(&self) -> &[u8] {
        &self.local_addr
    }

    /// Number of times `dial_stream()` was invoked (assert `0` on passive relays!).
    pub fn outbound_dial_count(&self) -> usize {
        self.outbound_dials.load(Ordering::Acquire)
    }
}

impl StreamListener for HubStreamChannel {
    type Stream = HubStream;

    async fn accept(&self) -> Result<HubStream, CoreErr> {
        self.accept_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(CoreErr::Closed)
    }
}

impl StreamChannel for HubStreamChannel {
    type Stream = HubStream;

    fn caps(&self) -> ChannelCaps {
        ChannelCaps::dynamic(self.mtu.subscribe(), true)
    }

    async fn dial_stream(&self, locator: &[u8]) -> Result<HubStream, CoreErr> {
        self.outbound_dials.fetch_add(1, Ordering::AcqRel);
        let key = (self.local_addr.clone(), locator.to_vec());
        if self
            .hub
            .down_links
            .lock()
            .get(&key)
            .copied()
            .unwrap_or(false)
        {
            return Err(CoreErr::TargetUnreachable);
        }
        let latency = self
            .hub
            .latencies
            .lock()
            .get(&key)
            .copied()
            .unwrap_or_default();
        if !latency.is_zero() {
            tokio::time::sleep(latency).await;
        }
        let (remote_accept, remote_mtu, buf_cap) = {
            let eps = self.hub.endpoints.lock();
            let ep = eps.get(locator).ok_or(CoreErr::TargetUnreachable)?;
            (ep.accept_tx.clone(), ep.mtu.subscribe(), ep.buf_cap)
        };
        let (a_io, b_io) = tokio::io::duplex(buf_cap);
        let (cut_tx, cut_rx) = watch::channel(false);
        self.hub
            .cut_signals
            .lock()
            .entry(key)
            .or_default()
            .push(cut_tx);

        let client = HubStream {
            io: a_io,
            mtu: self.mtu.subscribe(),
            hub: self.hub.clone(),
            local_addr: self.local_addr.clone(),
            peer_addr: locator.to_vec(),
            cut: cut_rx.clone(),
            source_tag: tag_from_bytes(locator),
        };
        let server = HubStream {
            io: b_io,
            mtu: remote_mtu,
            hub: self.hub.clone(),
            local_addr: locator.to_vec(),
            peer_addr: self.local_addr.clone(),
            cut: cut_rx,
            source_tag: tag_from_bytes(&self.local_addr),
        };
        remote_accept.try_send(server).map_err(|_| CoreErr::Busy)?;
        Ok(client)
    }
}

/// Concrete [`AsyncStream`] connecting two endpoints inside a [`MemStreamHub`].
pub struct HubStream {
    io: DuplexStream,
    mtu: watch::Receiver<u16>,
    hub: Arc<MemStreamHub>,
    local_addr: Vec<u8>,
    peer_addr: Vec<u8>,
    cut: watch::Receiver<bool>,
    source_tag: [u8; 16],
}

impl AsyncStream for HubStream {
    type Read = HubRead;
    type Write = HubWrite;

    fn caps(&self) -> ChannelCaps {
        ChannelCaps::dynamic(self.mtu.clone(), true)
    }

    fn split(self) -> (HubRead, HubWrite) {
        let (r, w) = tokio::io::split(self.io);
        let mut cut_wait_rx = self.cut.clone();
        let cut_wait = Box::pin(async move {
            let _ = cut_wait_rx.wait_for(|&cut| cut).await;
        });
        (
            HubRead {
                inner: r,
                cut: self.cut.clone(),
                cut_wait,
            },
            HubWrite {
                inner: w,
                hub: self.hub,
                src: self.local_addr,
                dst: self.peer_addr,
                cut: self.cut,
            },
        )
    }

    fn source_tag(&self) -> [u8; 16] {
        self.source_tag
    }
}

/// Poll-based read half of [`HubStream`].
pub struct HubRead {
    inner: ReadHalf<DuplexStream>,
    cut: watch::Receiver<bool>,
    cut_wait: BoxFut<'static, ()>,
}

impl StreamRead for HubRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ChannelErr>> {
        if *self.cut.borrow() || self.cut_wait.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(CoreErr::UnexpectedEof));
        }
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(CoreErr::Carrier(e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Poll-based write half of [`HubStream`].
pub struct HubWrite {
    inner: WriteHalf<DuplexStream>,
    hub: Arc<MemStreamHub>,
    src: Vec<u8>,
    dst: Vec<u8>,
    cut: watch::Receiver<bool>,
}

impl StreamWrite for HubWrite {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, ChannelErr>> {
        if *self.cut.borrow() {
            return Poll::Ready(Err(CoreErr::UnexpectedEof));
        }
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    self.hub.record_bytes(&self.src, &self.dst, &buf[..n]);
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(CoreErr::Carrier(e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ChannelErr>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(|e| CoreErr::Carrier(e.to_string()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ChannelErr>> {
        Pin::new(&mut self.inner)
            .poll_shutdown(cx)
            .map_err(|e| CoreErr::Carrier(e.to_string()))
    }
}

fn tag_from_bytes(addr: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, &b) in addr.iter().enumerate() {
        out[i % 16] ^= b.wrapping_add(i as u8);
    }
    out
}
