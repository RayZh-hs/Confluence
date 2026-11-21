use async_trait::async_trait;
use confluence_core::seams::channel::{BoxedAsyncStream, ChannelCaps, ChannelHealth, StreamChannel};
use confluence_core::{ChannelAddr, ChannelId, CoreError, Plane, Result};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::sync::watch;

/// Pure native TCP connectivity carrier implementing [`StreamChannel`] (Seam 1).
///
/// Enables `TCP_NODELAY` on all streams so single-pass pipelined setup bursts experience
/// zero Nagle buffering delay.
pub struct TcpStreamChannel {
    id: ChannelId,
    listener: Option<tokio::sync::Mutex<TcpListener>>,
    local_addr: Option<SocketAddr>,
    closed: AtomicBool,
    closed_tx: watch::Sender<bool>,
    closed_rx: watch::Receiver<bool>,
}

impl TcpStreamChannel {
    /// Binds a listening + outbound TCP stream carrier on `bind_addr`.
    pub async fn bind(id: ChannelId, bind_addr: SocketAddr) -> Result<Arc<Self>> {
        let listener = TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let (closed_tx, closed_rx) = watch::channel(false);
        Ok(Arc::new(Self {
            id,
            listener: Some(tokio::sync::Mutex::new(listener)),
            local_addr: Some(local_addr),
            closed: AtomicBool::new(false),
            closed_tx,
            closed_rx,
        }))
    }

    /// Creates an outbound-only TCP stream carrier (for client or NATed nodes with no listening port).
    pub fn outbound_only(id: ChannelId) -> Arc<Self> {
        let (closed_tx, closed_rx) = watch::channel(false);
        Arc::new(Self {
            id,
            listener: None,
            local_addr: None,
            closed: AtomicBool::new(false),
            closed_tx,
            closed_rx,
        })
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }
}

async fn resolve_addr(addr: &ChannelAddr) -> Result<SocketAddr> {
    if let Ok(sa) = addr.as_str().parse::<SocketAddr>() {
        return Ok(sa);
    }
    lookup_host(addr.as_str())
        .await?
        .next()
        .ok_or_else(|| CoreError::InvalidInput(format!("unable to resolve address '{addr}'")))
}

#[async_trait]
impl StreamChannel for TcpStreamChannel {
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
        if self.closed.load(Ordering::Acquire) {
            return Err(CoreError::ChannelUnhealthy("TCP channel closed".into()));
        }
        let sa = resolve_addr(addr).await?;
        let stream = TcpStream::connect(sa).await?;
        let _ = stream.set_nodelay(true);
        Ok(Box::pin(stream))
    }

    async fn accept(&self) -> Result<(BoxedAsyncStream, ChannelAddr)> {
        if self.closed.load(Ordering::Acquire) {
            return Err(CoreError::Closed("TCP channel closed".into()));
        }
        let Some(ref listener_mtx) = self.listener else {
            // Outbound-only carrier: park until closed.
            let mut rx = self.closed_rx.clone();
            let _ = rx.wait_for(|&c| c).await;
            return Err(CoreError::Closed("outbound-only TCP channel closed".into()));
        };

        let mut rx = self.closed_rx.clone();
        let guard = listener_mtx.lock().await;
        tokio::select! {
            _ = rx.wait_for(|&c| c) => Err(CoreError::Closed("TCP channel closed".into())),
            res = guard.accept() => {
                let (stream, peer_sa) = res?;
                let _ = stream.set_nodelay(true);
                Ok((Box::pin(stream), ChannelAddr::new(peer_sa.to_string())?))
            }
        }
    }

    fn health(&self) -> ChannelHealth {
        if self.closed.load(Ordering::Acquire) {
            ChannelHealth::Closed("closed".into())
        } else {
            ChannelHealth::Healthy
        }
    }

    async fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::Release);
        let _ = self.closed_tx.send(true);
        Ok(())
    }
}
