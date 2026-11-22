//! Deterministic in-memory Datagram hub with latency, drop, adjacent-packet reorder,
//! dynamic MTU watch, link-cut injection, wire-tap capture, and outbound-open counters.

use confluence_core::{
    ChannelCaps, CoreErr, DatagramChannel, DatagramLink, DatagramListener, PacketBuf,
};
use parking_lot::Mutex;
use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::{Mutex as AsyncMutex, mpsc, watch};

type LinkKey = (Vec<u8>, Vec<u8>);

#[derive(Default)]
struct LinkPolicy {
    down: bool,
    latency: Duration,
    drop_remaining: usize,
    reorder_adjacent: bool,
    held_packet: Option<Vec<u8>>,
}

struct EndpointEntry {
    accept_tx: mpsc::Sender<Arc<HubDatagramLink>>,
    mtu: watch::Sender<u16>,
}

/// Deterministic in-memory Datagram fabric for multi-hop, relay, and chaos testing.
pub struct MemDatagramHub {
    default_mtu: u16,
    endpoints: Mutex<HashMap<Vec<u8>, EndpointEntry>>,
    links: Mutex<HashMap<LinkKey, LinkPolicy>>,
    wire_tap: Mutex<HashMap<LinkKey, Vec<Vec<u8>>>>,
}

impl MemDatagramHub {
    /// Creates a new hub with `default_mtu` applied to newly bound endpoints.
    pub fn new(default_mtu: u16) -> Arc<Self> {
        Arc::new(Self {
            default_mtu,
            endpoints: Default::default(),
            links: Default::default(),
            wire_tap: Default::default(),
        })
    }

    /// Binds a channel at `addr` using the hub's `default_mtu`.
    pub fn bind(self: &Arc<Self>, addr: impl AsRef<[u8]>) -> Arc<HubDatagramChannel> {
        self.bind_with_mtu(addr, self.default_mtu)
    }

    /// Binds a channel at `addr` with an explicit initial `mtu`.
    pub fn bind_with_mtu(
        self: &Arc<Self>,
        addr: impl AsRef<[u8]>,
        mtu: u16,
    ) -> Arc<HubDatagramChannel> {
        let local_addr = addr.as_ref().to_vec();
        let (accept_tx, accept_rx) = mpsc::channel(64);
        let (mtu_tx, _mtu_rx) = watch::channel(mtu);
        self.endpoints.lock().insert(
            local_addr.clone(),
            EndpointEntry {
                accept_tx,
                mtu: mtu_tx.clone(),
            },
        );
        Arc::new(HubDatagramChannel {
            local_addr,
            hub: self.clone(),
            mtu: mtu_tx,
            accept_rx: AsyncMutex::new(accept_rx),
            outbound_opens: AtomicUsize::new(0),
            outbound_targets: Mutex::new(HashSet::new()),
            link_cache: Mutex::new(HashMap::new()),
        })
    }

    /// Updates the live MTU of `addr` (propagating immediately through `mtu_watch`).
    pub fn set_mtu(&self, addr: impl AsRef<[u8]>, mtu: u16) {
        if let Some(ep) = self.endpoints.lock().get(addr.as_ref()) {
            ep.mtu.send_replace(mtu);
        }
    }

    /// Cuts or restores the directional link `src -> dst`.
    pub fn set_link_down(&self, src: impl AsRef<[u8]>, dst: impl AsRef<[u8]>, down: bool) {
        self.links
            .lock()
            .entry((src.as_ref().to_vec(), dst.as_ref().to_vec()))
            .or_default()
            .down = down;
    }

    /// Cuts or restores both directions between `a` and `b`.
    pub fn set_symmetric_link_down(&self, a: impl AsRef<[u8]>, b: impl AsRef<[u8]>, down: bool) {
        self.set_link_down(&a, &b, down);
        self.set_link_down(&b, &a, down);
    }

    /// Injects deterministic one-way propagation latency on `src -> dst`.
    pub fn set_link_latency(
        &self,
        src: impl AsRef<[u8]>,
        dst: impl AsRef<[u8]>,
        latency: Duration,
    ) {
        self.links
            .lock()
            .entry((src.as_ref().to_vec(), dst.as_ref().to_vec()))
            .or_default()
            .latency = latency;
    }

    /// Deterministically drops the next `count` datagrams sent from `src` to `dst`.
    pub fn drop_next(&self, src: impl AsRef<[u8]>, dst: impl AsRef<[u8]>, count: usize) {
        self.links
            .lock()
            .entry((src.as_ref().to_vec(), dst.as_ref().to_vec()))
            .or_default()
            .drop_remaining += count;
    }

    /// Enables adjacent-pair reordering on `src -> dst` (holds odd packet and flushes `[2nd, 1st]`).
    pub fn set_reorder_adjacent(
        &self,
        src: impl AsRef<[u8]>,
        dst: impl AsRef<[u8]>,
        enabled: bool,
    ) {
        self.links
            .lock()
            .entry((src.as_ref().to_vec(), dst.as_ref().to_vec()))
            .or_default()
            .reorder_adjacent = enabled;
    }

    /// Returns all raw wire datagrams captured on `src -> dst`.
    pub fn captured_packets(&self, src: impl AsRef<[u8]>, dst: impl AsRef<[u8]>) -> Vec<Vec<u8>> {
        self.wire_tap
            .lock()
            .get(&(src.as_ref().to_vec(), dst.as_ref().to_vec()))
            .cloned()
            .unwrap_or_default()
    }

    /// Returns all raw wire datagrams captured across every link in the hub.
    pub fn all_captured_packets(&self) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let tap = self.wire_tap.lock();
        let mut out = Vec::new();
        for ((src, dst), pkts) in tap.iter() {
            for pkt in pkts {
                out.push((src.clone(), dst.clone(), pkt.clone()));
            }
        }
        out
    }

    /// Clears captured wire-tap packets.
    pub fn clear_wire_tap(&self) {
        self.wire_tap.lock().clear();
    }

    fn deliver(
        &self,
        src: &[u8],
        dst: &[u8],
        bytes: Vec<u8>,
    ) -> Result<(Duration, Vec<Vec<u8>>), CoreErr> {
        let key = (src.to_vec(), dst.to_vec());
        self.wire_tap
            .lock()
            .entry(key.clone())
            .or_default()
            .push(bytes.clone());

        let mut links = self.links.lock();
        let policy = links.entry(key).or_default();
        if policy.down {
            return Err(CoreErr::Carrier("simulated datagram link down".into()));
        }
        if policy.drop_remaining > 0 {
            policy.drop_remaining -= 1;
            return Ok((Duration::ZERO, Vec::new()));
        }
        let latency = policy.latency;
        if policy.reorder_adjacent {
            if let Some(held) = policy.held_packet.take() {
                return Ok((latency, vec![bytes, held]));
            } else {
                policy.held_packet = Some(bytes);
                return Ok((Duration::ZERO, Vec::new()));
            }
        }
        Ok((latency, vec![bytes]))
    }
}

/// Hub-attached [`DatagramChannel`] + [`DatagramListener`] with outbound-open auditing.
pub struct HubDatagramChannel {
    local_addr: Vec<u8>,
    hub: Arc<MemDatagramHub>,
    mtu: watch::Sender<u16>,
    accept_rx: AsyncMutex<mpsc::Receiver<Arc<HubDatagramLink>>>,
    outbound_opens: AtomicUsize,
    outbound_targets: Mutex<HashSet<Vec<u8>>>,
    link_cache: Mutex<HashMap<Vec<u8>, Arc<HubDatagramLink>>>,
}

impl HubDatagramChannel {
    /// Returns this endpoint's hub address bytes.
    pub fn local_addr(&self) -> &[u8] {
        &self.local_addr
    }

    /// Number of times `open_link()` was called (assert `0` on passive relays!).
    pub fn outbound_open_count(&self) -> usize {
        self.outbound_opens.load(Ordering::Acquire)
    }

    /// Set of distinct locators dialed via `open_link()`.
    pub fn outbound_targets(&self) -> HashSet<Vec<u8>> {
        self.outbound_targets.lock().clone()
    }
}

impl DatagramListener for HubDatagramChannel {
    type Link = Arc<HubDatagramLink>;

    async fn accept_link(&self) -> Result<Arc<HubDatagramLink>, CoreErr> {
        self.accept_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(CoreErr::Closed)
    }
}

impl DatagramChannel for HubDatagramChannel {
    type Link = Arc<HubDatagramLink>;

    fn caps(&self) -> ChannelCaps {
        ChannelCaps::dynamic(self.mtu.subscribe(), false)
    }

    async fn open_link(&self, locator: &[u8]) -> Result<Arc<HubDatagramLink>, CoreErr> {
        self.outbound_opens.fetch_add(1, Ordering::AcqRel);
        self.outbound_targets.lock().insert(locator.to_vec());
        if let Some(existing) = self.link_cache.lock().get(locator).cloned() {
            return Ok(existing);
        }
        let (remote_accept, remote_mtu) = {
            let eps = self.hub.endpoints.lock();
            let entry = eps.get(locator).ok_or(CoreErr::TargetUnreachable)?;
            (entry.accept_tx.clone(), entry.mtu.subscribe())
        };
        let (a_tx, b_rx) = mpsc::channel(128);
        let (b_tx, a_rx) = mpsc::channel(128);
        let src_tag = tag_from_bytes(&self.local_addr);
        let dst_tag = tag_from_bytes(locator);
        let client_link = Arc::new(HubDatagramLink {
            hub: self.hub.clone(),
            local_addr: self.local_addr.clone(),
            peer_addr: locator.to_vec(),
            mtu: self.mtu.subscribe(),
            tx: a_tx,
            rx: Mutex::new(a_rx),
            source_tag: dst_tag,
        });
        let server_link = Arc::new(HubDatagramLink {
            hub: self.hub.clone(),
            local_addr: locator.to_vec(),
            peer_addr: self.local_addr.clone(),
            mtu: remote_mtu,
            tx: b_tx,
            rx: Mutex::new(b_rx),
            source_tag: src_tag,
        });
        remote_accept
            .try_send(server_link)
            .map_err(|_| CoreErr::Busy)?;
        self.link_cache
            .lock()
            .insert(locator.to_vec(), client_link.clone());
        Ok(client_link)
    }
}

/// Concrete [`DatagramLink`] connecting two endpoints inside a [`MemDatagramHub`].
pub struct HubDatagramLink {
    hub: Arc<MemDatagramHub>,
    local_addr: Vec<u8>,
    peer_addr: Vec<u8>,
    mtu: watch::Receiver<u16>,
    tx: mpsc::Sender<PacketBuf>,
    rx: Mutex<mpsc::Receiver<PacketBuf>>,
    source_tag: [u8; 16],
}

impl DatagramLink for HubDatagramLink {
    fn caps(&self) -> ChannelCaps {
        ChannelCaps::dynamic(self.mtu.clone(), false)
    }

    fn try_send(&self, packet: PacketBuf) -> Result<(), CoreErr> {
        let mtu = *self.mtu.borrow();
        if packet.len() > usize::from(mtu) {
            return Err(CoreErr::MtuTooSmall(mtu));
        }
        let (latency, batch) = self.hub.deliver(
            &self.local_addr,
            &self.peer_addr,
            packet.as_slice().to_vec(),
        )?;
        if latency.is_zero() {
            for bytes in batch {
                self.tx
                    .try_send(PacketBuf::from_slice(&bytes))
                    .map_err(|err| match err {
                        mpsc::error::TrySendError::Full(_) => CoreErr::WouldBlock,
                        mpsc::error::TrySendError::Closed(_) => CoreErr::Closed,
                    })?;
            }
        } else if !batch.is_empty() {
            let tx = self.tx.clone();
            tokio::spawn(async move {
                tokio::time::sleep(latency).await;
                for bytes in batch {
                    let _ = tx.try_send(PacketBuf::from_slice(&bytes));
                }
            });
        }
        Ok(())
    }

    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<PacketBuf, CoreErr>> {
        self.rx
            .lock()
            .poll_recv(cx)
            .map(|opt| opt.ok_or(CoreErr::Closed))
    }

    fn source_tag(&self) -> [u8; 16] {
        self.source_tag
    }
}

fn tag_from_bytes(addr: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, &b) in addr.iter().enumerate() {
        out[i % 16] ^= b.wrapping_add(i as u8);
    }
    out
}
