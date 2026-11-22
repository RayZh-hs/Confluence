//! Explicit symmetric cross-plane channel adapters (`DESIGN.md` §3.2):
//!
//! 1. `StripedTcpDatagramChannel` (`Datagram-over-Stream`, faithful to
//!    `archived/docs/transport/striped-tls.md`): pools `K` independent encrypted
//!    TCP lanes (`TCP_NODELAY`, Linux `TCP_NOTSENT_LOWAT`), `POOL_BIND`,
//!    least-loaded writable lane scheduling, pre-write freshness TTL, and
//!    receiver relative-delay stale-frame shedding.
//! 2. `StreamOverDatagramChannel<D>` (`Stream-over-Datagram`): reliable,
//!    ordered, backpressured byte-stream framing (SYN/DATA/ACK/FIN + ARQ
//!    retransmission + reorder buffer) statically composed over any `DatagramChannel`.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex, Weak,
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker, ready},
    time::{Duration, Instant},
};

use confluence_core::{
    AsyncStream, ChannelCaps, ChannelErr, CoreErr, DATAGRAM_MTU, DatagramChannel, DatagramLink,
    DatagramLinkExt, PacketBuf, PublicKey, RejoinedStream, STREAM_CHUNK, ScopeInstance,
    ScopeKeypair, StreamChannel, StreamRead, StreamWrite, StreamWriteExt,
    crypto::replay::SetupReplay, read_exact, scope::DatagramIngress,
};
use confluence_net::TcpIo;
use rand_core::{OsRng, RngCore};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Notify, mpsc, watch},
};

use crate::{
    encrypted::{EncryptedLocator, EncryptedStream},
    now_ms,
};

// ===========================================================================
// PART 1: StripedTcpDatagramChannel (`archived/docs/transport/striped-tls.md`)
// ===========================================================================

const LANE_DATA: u8 = 0x01;
const LANE_POOL_BIND: u8 = 0x02;
const LANE_PING: u8 = 0x03;
const LANE_PONG: u8 = 0x04;
const POOL_BIND_VERSION: u8 = 0x01;
const STRIPED_MTU: u16 = 1280;

#[derive(Clone, Copy, Debug)]
pub struct StripedConfig {
    /// Number of independent encrypted TCP lanes (`K = 4..6`).
    pub lanes: usize,
    /// Sender-side pre-write freshness TTL (drops stale datagrams before TCP commit).
    pub sender_freshness_ttl: Duration,
    /// Receiver-side relative-delay shedding budget (`delta_stall > budget` dropped).
    pub receiver_freshness_budget_ms: u64,
    /// Linux `TCP_NOTSENT_LOWAT` threshold in bytes (e.g. 24 KiB).
    pub tcp_notsent_lowat: u32,
}

impl Default for StripedConfig {
    fn default() -> Self {
        Self {
            lanes: 4,
            sender_freshness_ttl: Duration::from_millis(150),
            receiver_freshness_budget_ms: 250,
            tcp_notsent_lowat: 24 * 1024,
        }
    }
}

#[cfg(target_os = "linux")]
fn tune_tcp_lane(stream: &TcpStream, notsent_lowat: u32) {
    use std::os::fd::AsRawFd;
    let _ = stream.set_nodelay(true);
    let val = notsent_lowat as libc::c_int;
    // Best-effort rootless socket tuning (kernel >= 3.12).
    #[allow(unsafe_code)]
    unsafe {
        let _ = libc::setsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_NOTSENT_LOWAT,
            (&raw const val).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn tune_tcp_lane(stream: &TcpStream, _notsent_lowat: u32) {
    let _ = stream.set_nodelay(true);
}

struct QueuedDatagram {
    packet: PacketBuf,
    enqueued_at: Instant,
    tx_ts_ms: u16,
}

struct DelayTracker {
    min_offset: Option<i32>,
    budget_ms: u64,
    shed_count: AtomicUsize,
}

impl DelayTracker {
    fn new(budget_ms: u64) -> Self {
        Self {
            min_offset: None,
            budget_ms,
            shed_count: AtomicUsize::new(0),
        }
    }

    /// Relative one-way delay tracker (`striped-tls.md` §4.4) requiring no clock sync.
    fn is_fresh(&mut self, tx_ts_ms: u16) -> bool {
        let rx_now = (now_ms() & 0xffff) as u16;
        let offset = rx_now.wrapping_sub(tx_ts_ms) as i16 as i32;
        let min = match self.min_offset {
            None => {
                self.min_offset = Some(offset);
                offset
            }
            Some(prev) => {
                let m = prev.min(offset);
                self.min_offset = Some(m);
                m
            }
        };
        let delta = (offset - min).max(0) as u64;
        if delta > self.budget_ms {
            self.shed_count.fetch_add(1, Ordering::Relaxed);
            false
        } else {
            true
        }
    }
}

pub struct StripedPoolLink {
    lanes: StdMutex<Vec<mpsc::Sender<QueuedDatagram>>>,
    rr: AtomicUsize,
    inbound_tx: mpsc::Sender<PacketBuf>,
    inbound_rx: StdMutex<mpsc::Receiver<PacketBuf>>,
    mtu: watch::Sender<u16>,
    config: StripedConfig,
    delay: Arc<StdMutex<DelayTracker>>,
}

impl StripedPoolLink {
    fn new(config: StripedConfig) -> Arc<Self> {
        let (in_tx, in_rx) = mpsc::channel(128);
        Arc::new(Self {
            lanes: Default::default(),
            rr: AtomicUsize::new(0),
            inbound_tx: in_tx,
            inbound_rx: StdMutex::new(in_rx),
            mtu: watch::channel(STRIPED_MTU).0,
            config,
            delay: Arc::new(StdMutex::new(DelayTracker::new(
                config.receiver_freshness_budget_ms,
            ))),
        })
    }

    pub fn active_lanes(&self) -> usize {
        self.lanes
            .lock()
            .unwrap()
            .iter()
            .filter(|tx| !tx.is_closed())
            .count()
    }

    fn attach_lane<S: AsyncStream>(self: &Arc<Self>, stream: S) {
        let (mut reader, mut writer) = stream.split();
        let (lane_tx, mut lane_rx) = mpsc::channel::<QueuedDatagram>(8);
        {
            let mut lanes = self.lanes.lock().unwrap();
            lanes.retain(|tx| !tx.is_closed());
            lanes.push(lane_tx);
        }
        let sender_ttl = self.config.sender_freshness_ttl;
        // Lane writer task with sender-side pre-write freshness TTL
        tokio::spawn(async move {
            let mut hdr = [0u8; 5];
            while let Some(item) = lane_rx.recv().await {
                if item.enqueued_at.elapsed() > sender_ttl {
                    // Drop before committing stale datagram into kernel TCP!
                    continue;
                }
                let payload = item.packet.as_slice();
                hdr[0] = LANE_DATA;
                hdr[1..3].copy_from_slice(&(payload.len() as u16).to_be_bytes());
                hdr[3..5].copy_from_slice(&item.tx_ts_ms.to_be_bytes());
                if writer.write_all(&hdr).await.is_err() {
                    break;
                }
                if writer.write_all(payload).await.is_err() {
                    break;
                }
            }
            let _ = writer.shutdown().await;
        });

        // Lane reader task delivering immediately out-of-order with stale shedding
        let inbound_tx = self.inbound_tx.clone();
        let delay = self.delay.clone();
        tokio::spawn(async move {
            let mut hdr = [0u8; 5];
            while read_exact(&mut reader, &mut hdr).await.is_ok() {
                let kind = hdr[0] & 0x0f;
                let len = u16::from_be_bytes(hdr[1..3].try_into().unwrap()) as usize;
                let tx_ts_ms = u16::from_be_bytes(hdr[3..5].try_into().unwrap());
                if len > usize::from(STRIPED_MTU) + 64 {
                    break;
                }
                let mut pkt = PacketBuf::with_payload_cap(len);
                if len > 0
                    && read_exact(&mut reader, &mut pkt.spare_payload()[..len])
                        .await
                        .is_err()
                {
                    break;
                }
                pkt.advance_payload(len);
                match kind {
                    LANE_DATA => {
                        let fresh = delay.lock().unwrap().is_fresh(tx_ts_ms);
                        if fresh {
                            let _ = inbound_tx.try_send(pkt);
                        }
                    }
                    LANE_PING | LANE_PONG => {}
                    _ => break,
                }
            }
        });
    }
}

impl DatagramLink for StripedPoolLink {
    fn caps(&self) -> ChannelCaps {
        // Explicitly declare reliable_underlay: true per DESIGN.md & striped-tls.md §3
        ChannelCaps::dynamic(self.mtu.subscribe(), true)
    }

    fn try_send(&self, packet: PacketBuf) -> Result<(), ChannelErr> {
        let mtu = *self.mtu.borrow();
        if packet.len() > usize::from(mtu) {
            return Err(CoreErr::MtuTooSmall(mtu));
        }
        let lanes: Vec<_> = {
            let mut guard = self.lanes.lock().unwrap();
            guard.retain(|tx| !tx.is_closed());
            guard.clone()
        };
        if lanes.is_empty() {
            return Err(CoreErr::Closed);
        }
        let start = self.rr.fetch_add(1, Ordering::Relaxed) % lanes.len();
        let mut item = QueuedDatagram {
            packet,
            enqueued_at: Instant::now(),
            tx_ts_ms: (now_ms() & 0xffff) as u16,
        };
        // Least-loaded / writable lane routing: skip backpressured or dead lanes!
        for offset in 0..lanes.len() {
            let lane = &lanes[(start + offset) % lanes.len()];
            match lane.try_send(item) {
                Ok(()) => return Ok(()),
                Err(mpsc::error::TrySendError::Full(returned))
                | Err(mpsc::error::TrySendError::Closed(returned)) => {
                    item = returned;
                }
            }
        }
        Err(CoreErr::WouldBlock)
    }

    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<PacketBuf, ChannelErr>> {
        self.inbound_rx
            .lock()
            .unwrap()
            .poll_recv(cx)
            .map(|opt| opt.ok_or(CoreErr::Closed))
    }
}

async fn write_pool_bind<S: AsyncStream>(
    stream: S,
    pool_id: [u8; 16],
    lane_id: u8,
    generation: u32,
) -> Result<RejoinedStream<S::Read, S::Write>, CoreErr> {
    let source_tag = stream.source_tag();
    let (reader, mut writer) = stream.split();
    let mut frame = [0u8; 27];
    frame[0] = LANE_POOL_BIND;
    frame[1..3].copy_from_slice(&22u16.to_be_bytes());
    frame[3..5].copy_from_slice(&0u16.to_be_bytes());
    frame[5] = POOL_BIND_VERSION;
    frame[6..22].copy_from_slice(&pool_id);
    frame[22] = lane_id;
    frame[23..27].copy_from_slice(&generation.to_be_bytes());
    writer.write_all(&frame).await?;
    Ok(RejoinedStream {
        caps: ChannelCaps::fixed(STRIPED_MTU, true),
        source_tag,
        reader,
        writer,
    })
}

/// Explicit `Datagram-over-Stream` channel (`archived/docs/transport/striped-tls.md`).
/// Locator format: `EncryptedLocator::encode(remote_link_pubkey, tcp_socket_addr_utf8)`.
#[derive(Clone)]
pub struct StripedTcpDatagramChannel {
    link_key: Arc<ScopeKeypair>,
    config: StripedConfig,
    pools: Arc<StdMutex<HashMap<Vec<u8>, Weak<StripedPoolLink>>>>,
}

impl StripedTcpDatagramChannel {
    pub fn new(link_key: Arc<ScopeKeypair>, config: StripedConfig) -> Self {
        Self {
            link_key,
            config,
            pools: Default::default(),
        }
    }

    async fn dial_one_lane(
        &self,
        addr: SocketAddr,
        remote_key: PublicKey,
        pool_id: [u8; 16],
        lane_id: u8,
        generation: u32,
    ) -> Result<
        RejoinedStream<
            <EncryptedStream<TcpIo> as AsyncStream>::Read,
            <EncryptedStream<TcpIo> as AsyncStream>::Write,
        >,
        CoreErr,
    > {
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(confluence_net::connect_error)?;
        tune_tcp_lane(&tcp, self.config.tcp_notsent_lowat);
        let io = TcpIo::new(tcp, STREAM_CHUNK as u16)?;
        let enc = EncryptedStream::handshake_client(io, &self.link_key, remote_key).await?;
        write_pool_bind(enc, pool_id, lane_id, generation).await
    }
}

impl DatagramChannel for StripedTcpDatagramChannel {
    type Link = Arc<StripedPoolLink>;

    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(STRIPED_MTU, true)
    }

    async fn open_link(&self, locator: &[u8]) -> Result<Arc<StripedPoolLink>, ChannelErr> {
        if let Some(existing) = self
            .pools
            .lock()
            .unwrap()
            .get(locator)
            .and_then(Weak::upgrade)
            .filter(|p| p.active_lanes() > 0)
        {
            return Ok(existing);
        }
        let (remote_key, inner) = EncryptedLocator::decode(locator)?;
        let addr: SocketAddr = std::str::from_utf8(inner)
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or(CoreErr::Malformed)?;

        let mut pool_id = [0u8; 16];
        OsRng.fill_bytes(&mut pool_id);
        let pool = StripedPoolLink::new(self.config);

        // Lane 0 opens immediately for 1-RTT readiness
        let lane0 = self.dial_one_lane(addr, remote_key, pool_id, 0, 1).await?;
        pool.attach_lane(lane0);

        // Lanes 1..K-1 open concurrently (staggered/parallel ramp-up)
        let total = self.config.lanes.max(1);
        for lane_id in 1..total {
            let this = self.clone();
            let pool_ref = pool.clone();
            tokio::spawn(async move {
                if let Ok(lane) = this
                    .dial_one_lane(addr, remote_key, pool_id, lane_id as u8, 1)
                    .await
                {
                    pool_ref.attach_lane(lane);
                }
            });
        }

        self.pools
            .lock()
            .unwrap()
            .insert(locator.to_vec(), Arc::downgrade(&pool));
        Ok(pool)
    }
}

/// Server ingress for `StripedTcpDatagramChannel`: groups incoming TCP lanes by
/// `pool_id` into one `StripedPoolLink` attached to `scope`.
pub async fn serve_striped_tcp_datagram(
    listener: TcpListener,
    scope: ScopeInstance,
    link_key: Arc<ScopeKeypair>,
    config: StripedConfig,
) -> Result<(), CoreErr> {
    let replay = Arc::new(SetupReplay::default());
    type PoolTable = Arc<StdMutex<HashMap<[u8; 16], (Arc<StripedPoolLink>, DatagramIngress)>>>;
    let pools: PoolTable = Default::default();

    loop {
        let (tcp, _) = listener
            .accept()
            .await
            .map_err(|e| CoreErr::Carrier(e.to_string()))?;
        tune_tcp_lane(&tcp, config.tcp_notsent_lowat);
        let Ok(io) = TcpIo::new(tcp, STREAM_CHUNK as u16) else {
            continue;
        };
        let scope = scope.clone();
        let link_key = link_key.clone();
        let replay = replay.clone();
        let pools = pools.clone();
        tokio::spawn(async move {
            let Ok(Ok(enc)) = tokio::time::timeout(
                Duration::from_secs(3),
                EncryptedStream::handshake_server(io, &link_key, &replay),
            )
            .await
            else {
                return;
            };
            let source_tag = enc.source_tag();
            let (mut reader, writer) = enc.split();
            let mut bind = [0u8; 27];
            if tokio::time::timeout(Duration::from_secs(2), read_exact(&mut reader, &mut bind))
                .await
                .ok()
                .and_then(Result::ok)
                .is_none()
            {
                return;
            }
            if bind[0] != LANE_POOL_BIND || bind[5] != POOL_BIND_VERSION {
                return;
            }
            let pool_id: [u8; 16] = bind[6..22].try_into().unwrap();
            let stream = RejoinedStream {
                caps: ChannelCaps::fixed(STRIPED_MTU, true),
                source_tag,
                reader,
                writer,
            };

            let pool = {
                let mut map = pools.lock().unwrap();
                if let Some((existing, _)) = map.get(&pool_id) {
                    existing.clone()
                } else {
                    let created = StripedPoolLink::new(config);
                    let Ok(guard) = scope.attach_datagram(created.clone()) else {
                        return;
                    };
                    map.insert(pool_id, (created.clone(), guard));
                    created
                }
            };
            pool.attach_lane(stream);
        });
    }
}

// ===========================================================================
// PART 2: StreamOverDatagramChannel<D> (`Stream-over-Datagram` Adapter)
// ===========================================================================
//
// Proves symmetric cross-plane composition (`DESIGN.md` §3.2): carries reliable,
// ordered Confluence Stream Plane traffic statically over ANY `DatagramChannel`
// (e.g. UDP P2P, Encrypted UDP, or MemDatagramChannel) with ARQ retransmission
// and reordering.

const SOD_SYN: u8 = 0xE1;
const SOD_SYN_ACK: u8 = 0xE2;
const SOD_DATA: u8 = 0xE3;
const SOD_ACK: u8 = 0xE4;
const SOD_FIN: u8 = 0xE5;
const SOD_HDR: usize = 9; // [kind(1B) | conn_id(4B) | seq_or_ack(4B)]
const SOD_MAX_SEG: usize = 1100;
const SOD_WINDOW: usize = 16;

type UnackedMap = BTreeMap<u32, (u8, Vec<u8>, Instant)>;

struct SodConnState<L> {
    conn_id: u32,
    link: L,
    /// Unacknowledged outbound segments: seq -> (kind, bytes, last_sent)
    unacked: StdMutex<UnackedMap>,
    next_tx_seq: AtomicU32,
    tx_wakers: StdMutex<Vec<Waker>>,
    /// Reordering buffer on receiver
    rx_next_expected: StdMutex<u32>,
    rx_ooo: StdMutex<BTreeMap<u32, (u8, Vec<u8>)>>,
    rx_delivered: mpsc::Sender<Option<Vec<u8>>>,
    syn_acked: Notify,
    syn_done: std::sync::atomic::AtomicBool,
    closed: watch::Sender<bool>,
}

impl<L: DatagramLink> SodConnState<L> {
    fn new(conn_id: u32, link: L) -> (Arc<Self>, mpsc::Receiver<Option<Vec<u8>>>) {
        let (tx, rx) = mpsc::channel(64);
        let state = Arc::new(Self {
            conn_id,
            link,
            unacked: Default::default(),
            next_tx_seq: AtomicU32::new(1),
            tx_wakers: Default::default(),
            rx_next_expected: StdMutex::new(1),
            rx_ooo: Default::default(),
            rx_delivered: tx,
            syn_acked: Notify::new(),
            syn_done: false.into(),
            closed: watch::channel(false).0,
        });
        // Retransmission timer loop (ARQ)
        let weak = Arc::downgrade(&state);
        let mut closed_rx = state.closed.subscribe();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(25));
            loop {
                tokio::select! {
                    _ = closed_rx.changed() => break,
                    _ = tick.tick() => {
                        let Some(st) = weak.upgrade() else { break };
                        let now = Instant::now();
                        let resend: Vec<(u8, u32, Vec<u8>)> = {
                            let mut map = st.unacked.lock().unwrap();
                            let mut list = Vec::new();
                            for (&seq, (kind, body, sent_at)) in map.iter_mut() {
                                if now.duration_since(*sent_at) >= Duration::from_millis(45) {
                                    *sent_at = now;
                                    list.push((*kind, seq, body.clone()));
                                }
                            }
                            list
                        };
                        for (kind, seq, body) in resend {
                            let _ = st.send_raw(kind, seq, &body).await;
                        }
                    }
                }
            }
        });
        (state, rx)
    }

    fn encode_raw(&self, kind: u8, seq: u32, payload: &[u8]) -> PacketBuf {
        let mut buf = Vec::with_capacity(SOD_HDR + payload.len());
        buf.push(kind);
        buf.extend_from_slice(&self.conn_id.to_be_bytes());
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.extend_from_slice(payload);
        PacketBuf::from_slice(&buf)
    }

    fn try_send_raw(&self, kind: u8, seq: u32, payload: &[u8]) -> Result<(), CoreErr> {
        self.link.try_send(self.encode_raw(kind, seq, payload))
    }

    async fn send_raw(&self, kind: u8, seq: u32, payload: &[u8]) -> Result<(), CoreErr> {
        self.link.send(self.encode_raw(kind, seq, payload)).await
    }

    fn wake_writers(&self) {
        let wakers = std::mem::take(&mut *self.tx_wakers.lock().unwrap());
        for w in wakers {
            w.wake();
        }
    }

    fn on_ack(&self, ack_seq: u32) {
        let should_wake = {
            let mut map = self.unacked.lock().unwrap();
            let to_remove: Vec<u32> = map.keys().copied().take_while(|&s| s <= ack_seq).collect();
            for s in to_remove {
                map.remove(&s);
            }
            map.len() < SOD_WINDOW
        };
        if should_wake {
            self.wake_writers();
        }
    }

    async fn on_data_or_fin(&self, kind: u8, seq: u32, payload: Vec<u8>) {
        let (deliver, ack) = {
            let mut expected = self.rx_next_expected.lock().unwrap();
            let mut ooo = self.rx_ooo.lock().unwrap();
            if seq >= *expected {
                ooo.entry(seq).or_insert((kind, payload));
            }
            let mut ready = Vec::new();
            while let Some((k, data)) = ooo.remove(&*expected) {
                *expected = expected.wrapping_add(1);
                ready.push((k, data));
            }
            (ready, expected.wrapping_sub(1))
        };
        let _ = self.send_raw(SOD_ACK, ack, &[]).await;
        for (k, data) in deliver {
            let item = if k == SOD_FIN { None } else { Some(data) };
            let _ = self.rx_delivered.send(item).await;
        }
    }
}

/// Concrete reliable byte stream running over any [`DatagramLink`].
pub struct SodStream<L> {
    state: Arc<SodConnState<L>>,
    rx: mpsc::Receiver<Option<Vec<u8>>>,
    mtu: u16,
}

/// Poll-based read half of [`SodStream`].
pub struct SodRead<L> {
    _state: Arc<SodConnState<L>>,
    rx: mpsc::Receiver<Option<Vec<u8>>>,
    pending: VecDeque<u8>,
    eof: bool,
}

/// Poll-based write half of [`SodStream`].
pub struct SodWrite<L> {
    state: Arc<SodConnState<L>>,
    shut_down: bool,
    fin_deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<L> Drop for SodWrite<L> {
    fn drop(&mut self) {
        let _ = self.state.closed.send(true);
        let wakers = std::mem::take(&mut *self.state.tx_wakers.lock().unwrap());
        for w in wakers {
            w.wake();
        }
    }
}

impl<L: DatagramLink> AsyncStream for SodStream<L> {
    type Read = SodRead<L>;
    type Write = SodWrite<L>;

    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(self.mtu, false)
    }

    fn split(self) -> (SodRead<L>, SodWrite<L>) {
        (
            SodRead {
                _state: self.state.clone(),
                rx: self.rx,
                pending: VecDeque::new(),
                eof: false,
            },
            SodWrite {
                state: self.state,
                shut_down: false,
                fin_deadline: None,
            },
        )
    }
}

impl<L: DatagramLink> StreamRead for SodRead<L> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ChannelErr>> {
        if buf.is_empty() || self.eof {
            return Poll::Ready(Ok(0));
        }
        let this = &mut *self;
        while this.pending.is_empty() {
            match ready!(this.rx.poll_recv(cx)) {
                Some(Some(chunk)) => this.pending.extend(chunk),
                Some(None) => {
                    this.eof = true;
                    return Poll::Ready(Ok(0));
                }
                None => return Poll::Ready(Err(CoreErr::UnexpectedEof)),
            }
        }
        let n = this.pending.len().min(buf.len());
        for slot in &mut buf[..n] {
            *slot = this.pending.pop_front().unwrap();
        }
        Poll::Ready(Ok(n))
    }
}

impl<L: DatagramLink> StreamWrite for SodWrite<L> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, ChannelErr>> {
        if self.shut_down || *self.state.closed.borrow() {
            return Poll::Ready(Err(CoreErr::Closed));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.state.unacked.lock().unwrap().len() >= SOD_WINDOW {
            self.state
                .tx_wakers
                .lock()
                .unwrap()
                .push(cx.waker().clone());
            if self.state.unacked.lock().unwrap().len() >= SOD_WINDOW {
                return Poll::Pending;
            }
        }
        ready!(self.state.link.poll_send_ready(cx))?;
        let chunk = &buf[..buf.len().min(SOD_MAX_SEG)];
        let seq = self.state.next_tx_seq.fetch_add(1, Ordering::Relaxed);
        self.state
            .unacked
            .lock()
            .unwrap()
            .insert(seq, (SOD_DATA, chunk.to_vec(), Instant::now()));
        match self.state.try_send_raw(SOD_DATA, seq, chunk) {
            Ok(()) | Err(CoreErr::WouldBlock) => Poll::Ready(Ok(chunk.len())),
            Err(err) => Poll::Ready(Err(err)),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ChannelErr>> {
        let this = &mut *self;
        if !this.shut_down {
            ready!(this.state.link.poll_send_ready(cx))?;
            this.shut_down = true;
            let seq = this.state.next_tx_seq.fetch_add(1, Ordering::Relaxed);
            this.state
                .unacked
                .lock()
                .unwrap()
                .insert(seq, (SOD_FIN, Vec::new(), Instant::now()));
            match this.state.try_send_raw(SOD_FIN, seq, &[]) {
                Ok(()) | Err(CoreErr::WouldBlock) => {}
                Err(err) => return Poll::Ready(Err(err)),
            }
            this.fin_deadline = Some(Box::pin(tokio::time::sleep(Duration::from_millis(500))));
        }
        if this.state.unacked.lock().unwrap().is_empty() {
            return Poll::Ready(Ok(()));
        }
        this.state
            .tx_wakers
            .lock()
            .unwrap()
            .push(cx.waker().clone());
        if this.state.unacked.lock().unwrap().is_empty() {
            return Poll::Ready(Ok(()));
        }
        if let Some(timer) = &mut this.fin_deadline
            && timer.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Ok(()));
        }
        Poll::Pending
    }
}

/// Manages multiplexed `StreamOverDatagram` connections over a single `L: DatagramLink`.
pub struct SodMux<L> {
    link: L,
    conns: Arc<StdMutex<HashMap<u32, Arc<SodConnState<L>>>>>,
    next_id: AtomicU32,
}

impl<L: DatagramLink + Clone> SodMux<L> {
    pub fn start(link: L, inbound_scope: Option<ScopeInstance>) -> Arc<Self> {
        let mux = Arc::new(Self {
            link: link.clone(),
            conns: Default::default(),
            next_id: AtomicU32::new(OsRng.next_u32().max(1)),
        });
        let conns = mux.conns.clone();
        let link_bg = link;
        tokio::spawn(async move {
            while let Ok(pkt) = link_bg.recv().await {
                let b = pkt.as_slice();
                if b.len() < SOD_HDR {
                    continue;
                }
                let kind = b[0];
                let conn_id = u32::from_be_bytes(b[1..5].try_into().unwrap());
                let seq = u32::from_be_bytes(b[5..9].try_into().unwrap());
                let body = b[9..].to_vec();

                match kind {
                    SOD_SYN => {
                        let Some(scope) = &inbound_scope else {
                            continue;
                        };
                        let existing = conns.lock().unwrap().get(&conn_id).cloned();
                        let state = if let Some(s) = existing {
                            s
                        } else {
                            let (state, rx) = SodConnState::new(conn_id, link_bg.clone());
                            conns.lock().unwrap().insert(conn_id, state.clone());
                            let stream = SodStream {
                                state: state.clone(),
                                rx,
                                mtu: STREAM_CHUNK as u16,
                            };
                            let _ = scope.accept_stream(stream);
                            state
                        };
                        let _ = state.send_raw(SOD_SYN_ACK, 0, &[]).await;
                    }
                    SOD_SYN_ACK => {
                        if let Some(st) = conns.lock().unwrap().get(&conn_id).cloned() {
                            st.syn_done.store(true, Ordering::Release);
                            st.syn_acked.notify_waiters();
                        }
                    }
                    SOD_DATA | SOD_FIN => {
                        let st = conns.lock().unwrap().get(&conn_id).cloned();
                        if let Some(st) = st {
                            st.on_data_or_fin(kind, seq, body).await;
                        }
                    }
                    SOD_ACK => {
                        if let Some(st) = conns.lock().unwrap().get(&conn_id).cloned() {
                            st.on_ack(seq);
                        }
                    }
                    _ => {}
                }
            }
        });
        mux
    }

    pub async fn open_stream(&self) -> Result<SodStream<L>, CoreErr> {
        let conn_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (state, rx) = SodConnState::new(conn_id, self.link.clone());
        self.conns.lock().unwrap().insert(conn_id, state.clone());

        let ok = tokio::time::timeout(Duration::from_secs(2), async {
            for _ in 0..20 {
                if state.syn_done.load(Ordering::Acquire) {
                    return Ok::<_, CoreErr>(());
                }
                state.send_raw(SOD_SYN, 0, &[]).await?;
                let _ = tokio::time::timeout(Duration::from_millis(60), state.syn_acked.notified())
                    .await;
            }
            Err(CoreErr::Timeout)
        })
        .await;

        if !state.syn_done.load(Ordering::Acquire) || ok.is_err() {
            self.conns.lock().unwrap().remove(&conn_id);
            return Err(CoreErr::Timeout);
        }

        Ok(SodStream {
            state,
            rx,
            mtu: STREAM_CHUNK as u16,
        })
    }
}

type SodMuxMap<L> = Arc<StdMutex<HashMap<Vec<u8>, Arc<SodMux<L>>>>>;

/// Explicit `Stream-over-Datagram` `StreamChannel` adapter statically wrapping any `DatagramChannel`.
pub struct StreamOverDatagramChannel<D: DatagramChannel> {
    inner: D,
    muxes: SodMuxMap<D::Link>,
}

impl<D: DatagramChannel + Clone> Clone for StreamOverDatagramChannel<D> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            muxes: self.muxes.clone(),
        }
    }
}

impl<D: DatagramChannel> StreamOverDatagramChannel<D>
where
    D::Link: Clone,
{
    pub fn new(inner: D) -> Result<Self, CoreErr> {
        if inner.caps().mtu() < DATAGRAM_MTU {
            return Err(CoreErr::MtuTooSmall(inner.caps().mtu()));
        }
        Ok(Self {
            inner,
            muxes: Default::default(),
        })
    }
}

impl<D: DatagramChannel> StreamChannel for StreamOverDatagramChannel<D>
where
    D::Link: Clone,
{
    type Stream = SodStream<D::Link>;

    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(STREAM_CHUNK as u16, false)
    }

    async fn dial_stream(&self, locator: &[u8]) -> Result<SodStream<D::Link>, ChannelErr> {
        let existing = self.muxes.lock().unwrap().get(locator).cloned();
        let mux = if let Some(m) = existing {
            m
        } else {
            let link = self.inner.open_link(locator).await?;
            let m = SodMux::start(link, None);
            self.muxes
                .lock()
                .unwrap()
                .insert(locator.to_vec(), m.clone());
            m
        };
        mux.open_stream().await
    }
}
