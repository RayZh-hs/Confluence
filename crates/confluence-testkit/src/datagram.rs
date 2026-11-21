use async_trait::async_trait;
use bytes::Bytes;
use confluence_core::seams::channel::{ChannelCaps, ChannelHealth, DatagramChannel};
use confluence_core::{ChannelAddr, ChannelId, CoreError, Plane, Result};
use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LinkKey {
    src: ChannelAddr,
    dst: ChannelAddr,
}

#[derive(Default)]
struct LinkPolicy {
    down: bool,
    latency: Duration,
    drop_remaining: usize,
    reorder_adjacent: bool,
    held_packet: Option<Bytes>,
}

/// Deterministic in-memory Datagram fabric with per-link MTU, drop, reorder, link-cut, and wire-tap inspection.
pub struct MemDatagramHub {
    default_mtu: usize,
    endpoints: DashMap<ChannelAddr, mpsc::Sender<(Bytes, ChannelAddr)>>,
    mtus: DashMap<ChannelAddr, usize>,
    links: Mutex<HashMap<LinkKey, LinkPolicy>>,
    wire_tap: Mutex<HashMap<LinkKey, Vec<Bytes>>>,
}

impl MemDatagramHub {
    pub fn new(default_mtu: usize) -> Arc<Self> {
        Arc::new(Self {
            default_mtu,
            endpoints: DashMap::new(),
            mtus: DashMap::new(),
            links: Mutex::new(HashMap::new()),
            wire_tap: Mutex::new(HashMap::new()),
        })
    }

    pub fn bind(self: &Arc<Self>, id: &str, addr: &str) -> Arc<MemDatagramChannel> {
        self.bind_with_mtu(id, addr, self.default_mtu)
    }

    pub fn bind_with_mtu(
        self: &Arc<Self>,
        id: &str,
        addr: &str,
        mtu: usize,
    ) -> Arc<MemDatagramChannel> {
        let channel_id = ChannelId::new(id).expect("valid ChannelId");
        let local_addr = ChannelAddr::new(addr).expect("valid ChannelAddr");
        let (tx, rx) = mpsc::channel(1024);
        let (closed_tx, closed_rx) = watch::channel(None);
        self.endpoints.insert(local_addr.clone(), tx);
        self.mtus.insert(local_addr.clone(), mtu);

        Arc::new(MemDatagramChannel {
            id: channel_id,
            local_addr,
            mtu,
            hub: Arc::clone(self),
            rx: tokio::sync::Mutex::new(rx),
            closed_flag: AtomicBool::new(false),
            closed_tx,
            closed_rx,
            outbound_targets: Mutex::new(HashSet::new()),
        })
    }

    /// Cuts or restores `(src -> dst)` deterministically (and optionally symmetric if called both ways).
    pub fn set_link_down(&self, src: &str, dst: &str, down: bool) {
        let key = LinkKey {
            src: ChannelAddr::new(src).unwrap(),
            dst: ChannelAddr::new(dst).unwrap(),
        };
        self.links.lock().entry(key).or_default().down = down;
    }

    pub fn set_symmetric_link_down(&self, a: &str, b: &str, down: bool) {
        self.set_link_down(a, b, down);
        self.set_link_down(b, a, down);
    }

    pub fn set_link_latency(&self, src: &str, dst: &str, latency: Duration) {
        let key = LinkKey {
            src: ChannelAddr::new(src).unwrap(),
            dst: ChannelAddr::new(dst).unwrap(),
        };
        self.links.lock().entry(key).or_default().latency = latency;
    }

    /// Deterministically drops the next `count` datagrams sent from `src` to `dst`.
    pub fn drop_next(&self, src: &str, dst: &str, count: usize) {
        let key = LinkKey {
            src: ChannelAddr::new(src).unwrap(),
            dst: ChannelAddr::new(dst).unwrap(),
        };
        self.links.lock().entry(key).or_default().drop_remaining += count;
    }

    /// Enables deterministic adjacent-pair swapping: holds every odd packet and flushes `[2nd, 1st]`.
    pub fn set_reorder_adjacent(&self, src: &str, dst: &str, enabled: bool) {
        let key = LinkKey {
            src: ChannelAddr::new(src).unwrap(),
            dst: ChannelAddr::new(dst).unwrap(),
        };
        let mut guard = self.links.lock();
        let entry = guard.entry(key).or_default();
        entry.reorder_adjacent = enabled;
    }

    /// Returns a snapshot of all wire datagrams transmitted across `(src -> dst)`.
    pub fn captured_packets(&self, src: &str, dst: &str) -> Vec<Bytes> {
        let key = LinkKey {
            src: ChannelAddr::new(src).unwrap(),
            dst: ChannelAddr::new(dst).unwrap(),
        };
        self.wire_tap
            .lock()
            .get(&key)
            .cloned()
            .unwrap_or_default()
    }

    /// Returns all wire datagrams transmitted across any link in the hub.
    pub fn all_captured_packets(&self) -> Vec<(ChannelAddr, ChannelAddr, Bytes)> {
        let guard = self.wire_tap.lock();
        let mut out = Vec::new();
        for (k, pkts) in guard.iter() {
            for p in pkts {
                out.push((k.src.clone(), k.dst.clone(), p.clone()));
            }
        }
        out
    }

    async fn route(&self, src: &ChannelAddr, dst: &ChannelAddr, payload: &[u8]) -> Result<()> {
        if let Some(dst_mtu) = self.mtus.get(dst) {
            if payload.len() > *dst_mtu {
                return Err(CoreError::CapabilityMismatch(format!(
                    "datagram len {} exceeds destination MTU {}",
                    payload.len(),
                    *dst_mtu
                )));
            }
        }

        let key = LinkKey {
            src: src.clone(),
            dst: dst.clone(),
        };

        let pkt = Bytes::copy_from_slice(payload);
        self.wire_tap
            .lock()
            .entry(key.clone())
            .or_default()
            .push(pkt.clone());

        let (to_deliver, latency) = {
            let mut guard = self.links.lock();
            let policy = guard.entry(key).or_default();
            if policy.down {
                // Simulate blackhole/dropped packet on severed UDP link (or unreachable).
                return Ok(());
            }
            if policy.drop_remaining > 0 {
                policy.drop_remaining -= 1;
                return Ok(());
            }
            let lat = policy.latency;
            if policy.reorder_adjacent {
                if let Some(prev) = policy.held_packet.take() {
                    (vec![pkt, prev], lat)
                } else {
                    policy.held_packet = Some(pkt);
                    (Vec::new(), lat)
                }
            } else {
                (vec![pkt], lat)
            }
        };

        if to_deliver.is_empty() {
            return Ok(());
        }

        let Some(tx) = self.endpoints.get(dst).map(|r| r.value().clone()) else {
            return Ok(());
        };
        let src_clone = src.clone();

        if latency.is_zero() {
            for p in to_deliver {
                let _ = tx.try_send((p, src_clone.clone()));
            }
        } else {
            tokio::spawn(async move {
                tokio::time::sleep(latency).await;
                for p in to_deliver {
                    let _ = tx.send((p, src_clone.clone())).await;
                }
            });
        }
        Ok(())
    }
}

/// In-memory `DatagramChannel` attached to a `MemDatagramHub`.
pub struct MemDatagramChannel {
    id: ChannelId,
    local_addr: ChannelAddr,
    mtu: usize,
    hub: Arc<MemDatagramHub>,
    rx: tokio::sync::Mutex<mpsc::Receiver<(Bytes, ChannelAddr)>>,
    closed_flag: AtomicBool,
    closed_tx: watch::Sender<Option<String>>,
    closed_rx: watch::Receiver<Option<String>>,
    outbound_targets: Mutex<HashSet<ChannelAddr>>,
}

impl MemDatagramChannel {
    pub fn local_addr(&self) -> &ChannelAddr {
        &self.local_addr
    }

    /// Simulates a local interface failure, flipping `health()` to `Closed(reason)` and waking `recv_from`.
    pub fn fail_channel(&self, reason: impl Into<String>) {
        let r = reason.into();
        self.closed_flag.store(true, Ordering::Release);
        self.hub.endpoints.remove(&self.local_addr);
        let _ = self.closed_tx.send(Some(r));
    }

    /// Distinct destination addresses to which this channel has transmitted packets.
    pub fn outbound_destinations(&self) -> Vec<ChannelAddr> {
        self.outbound_targets.lock().iter().cloned().collect()
    }
}

#[async_trait]
impl DatagramChannel for MemDatagramChannel {
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
        if self.closed_flag.load(Ordering::Acquire) {
            return Err(CoreError::ChannelUnhealthy("channel closed".into()));
        }
        if payload.len() > self.mtu {
            return Err(CoreError::CapabilityMismatch(format!(
                "datagram len {} exceeds local MTU {}",
                payload.len(),
                self.mtu
            )));
        }
        self.outbound_targets.lock().insert(addr.clone());
        self.hub.route(&self.local_addr, addr, payload).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, ChannelAddr)> {
        if let Some(ref reason) = *self.closed_rx.borrow() {
            return Err(CoreError::Closed(reason.clone()));
        }
        let mut closed_rx = self.closed_rx.clone();
        let mut rx_guard = self.rx.lock().await;
        tokio::select! {
            _ = closed_rx.changed() => {
                let reason = closed_rx.borrow().clone().unwrap_or_else(|| "closed".into());
                Err(CoreError::Closed(reason))
            }
            msg = rx_guard.recv() => {
                match msg {
                    Some((bytes, src)) => {
                        if bytes.len() > buf.len() {
                            return Err(CoreError::Framing("receive buffer too small".into()));
                        }
                        buf[..bytes.len()].copy_from_slice(&bytes);
                        Ok((bytes.len(), src))
                    }
                    None => Err(CoreError::Closed("channel receiver closed".into())),
                }
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
