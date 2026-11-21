use async_trait::async_trait;
use confluence_core::seams::channel::{ChannelCaps, ChannelHealth, DatagramChannel};
use confluence_core::{ChannelAddr, ChannelId, CoreError, Plane, Result};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::{lookup_host, UdpSocket};
use tokio::sync::watch;

/// Pure native UDP connectivity carrier implementing [`DatagramChannel`] (Seam 1).
///
/// Owns zero routing or authorization policy; hop-level ACL attaches vertically via
/// [`crate::NoiseAclDatagramChannel`].
pub struct UdpDatagramChannel {
    id: ChannelId,
    socket: UdpSocket,
    local_addr: SocketAddr,
    mtu: usize,
    closed: AtomicBool,
    closed_tx: watch::Sender<bool>,
    closed_rx: watch::Receiver<bool>,
}

impl UdpDatagramChannel {
    pub async fn bind(id: ChannelId, bind_addr: SocketAddr, mtu: usize) -> Result<Arc<Self>> {
        let socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;
        let (closed_tx, closed_rx) = watch::channel(false);
        Ok(Arc::new(Self {
            id,
            socket,
            local_addr,
            mtu,
            closed: AtomicBool::new(false),
            closed_tx,
            closed_rx,
        }))
    }

    pub fn local_addr(&self) -> SocketAddr {
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
impl DatagramChannel for UdpDatagramChannel {
    fn id(&self) -> &ChannelId {
        &self.id
    }

    fn caps(&self) -> ChannelCaps {
        ChannelCaps {
            plane: Plane::Datagram,
            reliable_underlay: false,
            ordered_underlay: false,
            max_payload_bytes: Some(self.mtu),
        }
    }

    async fn send_to(&self, addr: &ChannelAddr, payload: &[u8]) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(CoreError::ChannelUnhealthy("UDP channel closed".into()));
        }
        if payload.len() > self.mtu {
            return Err(CoreError::CapabilityMismatch(format!(
                "UDP payload {} exceeds configured MTU {}",
                payload.len(),
                self.mtu
            )));
        }
        let sa = resolve_addr(addr).await?;
        self.socket.send_to(payload, sa).await?;
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, ChannelAddr)> {
        if self.closed.load(Ordering::Acquire) {
            return Err(CoreError::Closed("UDP channel closed".into()));
        }
        let mut rx = self.closed_rx.clone();
        tokio::select! {
            _ = rx.wait_for(|&c| c) => Err(CoreError::Closed("UDP channel closed".into())),
            res = self.socket.recv_from(buf) => {
                let (n, peer_sa) = res?;
                Ok((n, ChannelAddr::new(peer_sa.to_string())?))
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
