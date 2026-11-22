use async_trait::async_trait;
use confluence_core::seams::channel::{
    BoxedAsyncStream, ChannelCaps, ChannelHealth, StreamChannel,
};
use confluence_core::{ChannelAddr, ChannelId, CoreError, Plane, Result};
use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::{mpsc, watch};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LinkKey {
    src: ChannelAddr,
    dst: ChannelAddr,
}

struct LinkState {
    down: bool,
    kill_tx: watch::Sender<bool>,
    kill_rx: watch::Receiver<bool>,
}

impl LinkState {
    fn new() -> Self {
        let (kill_tx, kill_rx) = watch::channel(false);
        Self {
            down: false,
            kill_tx,
            kill_rx,
        }
    }
}

/// Deterministic in-memory Stream fabric with wire byte inspection, zero-dial verification,
/// and instantaneous mid-stream link-severing for testing honest failure propagation.
pub struct MemStreamHub {
    listeners: DashMap<ChannelAddr, mpsc::Sender<(BoxedAsyncStream, ChannelAddr)>>,
    links: Mutex<HashMap<LinkKey, LinkState>>,
    wire_tap: Arc<Mutex<HashMap<LinkKey, Vec<u8>>>>,
}

impl Default for MemStreamHub {
    fn default() -> Self {
        Self {
            listeners: DashMap::new(),
            links: Mutex::new(HashMap::new()),
            wire_tap: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl MemStreamHub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn bind(self: &Arc<Self>, id: &str, addr: &str) -> Arc<MemStreamChannel> {
        let channel_id = ChannelId::new(id).expect("valid ChannelId");
        let local_addr = ChannelAddr::new(addr).expect("valid ChannelAddr");
        let (tx, rx) = mpsc::channel(256);
        let (closed_tx, closed_rx) = watch::channel(None);
        self.listeners.insert(local_addr.clone(), tx);

        Arc::new(MemStreamChannel {
            id: channel_id,
            local_addr,
            hub: Arc::clone(self),
            accept_rx: tokio::sync::Mutex::new(rx),
            closed_flag: AtomicBool::new(false),
            closed_tx,
            closed_rx,
            outbound_dials: AtomicUsize::new(0),
        })
    }

    /// Cuts or restores `(src <-> dst)`. Severing immediately terminates all active streams on that link!
    pub fn set_symmetric_link_down(&self, a: &str, b: &str, down: bool) {
        self.set_link_down(a, b, down);
        self.set_link_down(b, a, down);
    }

    pub fn set_link_down(&self, src: &str, dst: &str, down: bool) {
        let key = LinkKey {
            src: ChannelAddr::new(src).unwrap(),
            dst: ChannelAddr::new(dst).unwrap(),
        };
        let mut guard = self.links.lock();
        let entry = guard.entry(key).or_insert_with(LinkState::new);
        entry.down = down;
        if down {
            let _ = entry.kill_tx.send(true);
        } else {
            let (tx, rx) = watch::channel(false);
            entry.kill_tx = tx;
            entry.kill_rx = rx;
        }
    }

    /// Returns all raw wire bytes written from `src` to `dst` across streams on this link.
    pub fn captured_bytes(&self, src: &str, dst: &str) -> Vec<u8> {
        let key = LinkKey {
            src: ChannelAddr::new(src).unwrap(),
            dst: ChannelAddr::new(dst).unwrap(),
        };
        self.wire_tap.lock().get(&key).cloned().unwrap_or_default()
    }

    fn connect(&self, src: &ChannelAddr, dst: &ChannelAddr) -> Result<BoxedAsyncStream> {
        let fwd_key = LinkKey {
            src: src.clone(),
            dst: dst.clone(),
        };
        let rev_key = LinkKey {
            src: dst.clone(),
            dst: src.clone(),
        };

        let (fwd_kill, rev_kill) = {
            let mut guard = self.links.lock();
            let fwd = guard.entry(fwd_key.clone()).or_insert_with(LinkState::new);
            if fwd.down {
                return Err(CoreError::ChannelUnhealthy(format!(
                    "link {} -> {} is down",
                    src, dst
                )));
            }
            let fwd_rx = fwd.kill_rx.clone();
            let rev = guard.entry(rev_key.clone()).or_insert_with(LinkState::new);
            if rev.down {
                return Err(CoreError::ChannelUnhealthy(format!(
                    "link {} -> {} is down",
                    dst, src
                )));
            }
            let rev_rx = rev.kill_rx.clone();
            (fwd_rx, rev_rx)
        };

        let accept_tx = self
            .listeners
            .get(dst)
            .map(|r| r.value().clone())
            .ok_or_else(|| CoreError::ChannelUnhealthy(format!("no listener bound at {}", dst)))?;

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client_wrapped: BoxedAsyncStream = Box::pin(TappedDuplexStream::new(
            client_io,
            fwd_key,
            Arc::clone(&self.wire_tap),
            fwd_kill.clone(),
            rev_kill.clone(),
        ));
        let server_wrapped: BoxedAsyncStream = Box::pin(TappedDuplexStream::new(
            server_io,
            rev_key,
            Arc::clone(&self.wire_tap),
            rev_kill,
            fwd_kill,
        ));

        accept_tx
            .try_send((server_wrapped, src.clone()))
            .map_err(|_| {
                CoreError::ChannelUnhealthy("listener accept backlog full or closed".into())
            })?;

        Ok(client_wrapped)
    }
}

/// In-memory `StreamChannel` attached to a `MemStreamHub`.
pub struct MemStreamChannel {
    id: ChannelId,
    local_addr: ChannelAddr,
    hub: Arc<MemStreamHub>,
    accept_rx: tokio::sync::Mutex<mpsc::Receiver<(BoxedAsyncStream, ChannelAddr)>>,
    closed_flag: AtomicBool,
    closed_tx: watch::Sender<Option<String>>,
    closed_rx: watch::Receiver<Option<String>>,
    outbound_dials: AtomicUsize,
}

impl MemStreamChannel {
    pub fn local_addr(&self) -> &ChannelAddr {
        &self.local_addr
    }

    /// Number of times `open()` was invoked on this `StreamChannel` (must be `0` on passive relays!).
    pub fn outbound_dial_count(&self) -> usize {
        self.outbound_dials.load(Ordering::Acquire)
    }

    pub fn fail_channel(&self, reason: impl Into<String>) {
        let r = reason.into();
        self.closed_flag.store(true, Ordering::Release);
        self.hub.listeners.remove(&self.local_addr);
        let _ = self.closed_tx.send(Some(r));
    }
}

#[async_trait]
impl StreamChannel for MemStreamChannel {
    fn id(&self) -> &ChannelId {
        &self.id
    }

    fn caps(&self) -> ChannelCaps {
        ChannelCaps {
            plane: Plane::Stream,
            reliable_underlay: true,
            ordered_underlay: true,
            max_payload_bytes: None,
        }
    }

    async fn open(&self, addr: &ChannelAddr) -> Result<BoxedAsyncStream> {
        if self.closed_flag.load(Ordering::Acquire) {
            return Err(CoreError::ChannelUnhealthy("stream channel closed".into()));
        }
        self.outbound_dials.fetch_add(1, Ordering::AcqRel);
        self.hub.connect(&self.local_addr, addr)
    }

    async fn accept(&self) -> Result<(BoxedAsyncStream, ChannelAddr)> {
        if let Some(ref reason) = *self.closed_rx.borrow() {
            return Err(CoreError::Closed(reason.clone()));
        }
        let mut closed_rx = self.closed_rx.clone();
        let mut guard = self.accept_rx.lock().await;
        tokio::select! {
            _ = closed_rx.changed() => {
                let reason = closed_rx.borrow().clone().unwrap_or_else(|| "closed".into());
                Err(CoreError::Closed(reason))
            }
            res = guard.recv() => {
                res.ok_or_else(|| CoreError::Closed("stream listener closed".into()))
            }
        }
    }

    fn health(&self) -> ChannelHealth {
        if let Some(ref reason) = *self.closed_rx.borrow() {
            ChannelHealth::Closed(reason.clone())
        } else {
            ChannelHealth::Healthy
        }
    }

    async fn close(&self) -> Result<()> {
        self.fail_channel("explicitly closed");
        Ok(())
    }
}

struct TappedDuplexStream {
    inner: DuplexStream,
    write_key: LinkKey,
    wire_tap: Arc<Mutex<HashMap<LinkKey, Vec<u8>>>>,
    kill_wait_a: Pin<Box<dyn Future<Output = ()> + Send + Sync>>,
    kill_wait_b: Pin<Box<dyn Future<Output = ()> + Send + Sync>>,
    severed: bool,
}

impl TappedDuplexStream {
    fn new(
        inner: DuplexStream,
        write_key: LinkKey,
        wire_tap: Arc<Mutex<HashMap<LinkKey, Vec<u8>>>>,
        mut rx_a: watch::Receiver<bool>,
        mut rx_b: watch::Receiver<bool>,
    ) -> Self {
        let kill_wait_a = Box::pin(async move {
            let _ = rx_a.wait_for(|&dead| dead).await;
        });
        let kill_wait_b = Box::pin(async move {
            let _ = rx_b.wait_for(|&dead| dead).await;
        });
        Self {
            inner,
            write_key,
            wire_tap,
            kill_wait_a,
            kill_wait_b,
            severed: false,
        }
    }

    fn poll_severed(&mut self, cx: &mut Context<'_>) -> bool {
        if self.severed {
            return true;
        }
        if self.kill_wait_a.as_mut().poll(cx).is_ready()
            || self.kill_wait_b.as_mut().poll(cx).is_ready()
        {
            self.severed = true;
            return true;
        }
        false
    }
}

impl AsyncRead for TappedDuplexStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.poll_severed(cx) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "underlying link severed",
            )));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TappedDuplexStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.poll_severed(cx) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "underlying link severed",
            )));
        }
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    self.wire_tap
                        .lock()
                        .entry(self.write_key.clone())
                        .or_default()
                        .extend_from_slice(&buf[..n]);
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.poll_severed(cx) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "underlying link severed",
            )));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
