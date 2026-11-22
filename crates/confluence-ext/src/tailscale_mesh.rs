//! Original Tailscale-replacement overlay mesh + Smart PathSource + Native App SDK demos:
//!
//! 1. `SmartPathSource`: Multi-candidate pure path resolution with Blind Rendezvous
//!    Home-Relay discovery and outcome-driven failover (Direct UDP P2P -> Encrypted
//!    Home UDP Relay -> Striped Encrypted-TCP), cleanly decoupled from credentials.
//! 2. `VirtualL3Node`: Tailscale-style virtual subnet (`100.64.x.y`) + MagicDNS
//!    Edge Adapter owning L3 fragmentation/reassembly outside Core, supporting
//!    multi-scope isolation on a single host and automatic failover re-dialing.
//! 3. Native embedded applications (`KvService` over `E2eStream`) running on the
//!    exact same `ScopeInstance`, channels, and `Authorizer`.

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{
        Arc, Mutex as StdMutex, RwLock,
        atomic::{AtomicU16, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use confluence_core::{
    AsyncStream, BoxFut, CoreErr, DATAGRAM_MTU, DatagramEndpointHandler, DatagramLinkExt,
    E2eDatagram, ExplicitPath, HopSpec, PacketBuf, PathOutcome, PathSource, Plane, PublicKey,
    PublishGuard, ScopeInstance, SessionAuth, StreamEndpointHandler, StreamWriteExt, read_exact,
};
use confluence_plugins::{MemDatagramLink, MemStream, mem_datagram_pair, mem_stream_pair};
use tokio::sync::{Mutex as AsyncMutex, mpsc};

use crate::{
    encrypted::{EncryptedLocator, encode_slot_hex},
    udp_p2p::UdpP2pNode,
};

// ===========================================================================
// PART 1: SmartPathSource (Multi-Candidate Pure Routing & Failover)
// ===========================================================================

#[derive(Clone, Debug)]
pub struct PathCandidate {
    pub label: String,
    pub path: ExplicitPath,
}

struct ActivePathMeta {
    peer: PublicKey,
    endpoint: String,
    plane: Plane,
    candidate_idx: usize,
    established: bool,
}

#[derive(Clone, Debug)]
struct FailRecord {
    failed_at: Instant,
    _reason: CoreErr,
}

type CandidateKey = (PublicKey, String, Plane);
type FailKey = (PublicKey, String, Plane, usize);

/// Out-of-core pure routing & failover controller implementing [`PathSource`].
///
/// Supports:
/// - Ordered candidate lists per `(Peer, Endpoint, Plane)`
/// - Dynamic Home-Relay fallback discovery from `UdpP2pNode`'s decrypted `SealedEnvelope`
/// - Outcome-driven failure cooldown & automatic fallback on `report_outcome(Failed(..))`
pub struct SmartPathSource {
    candidates: RwLock<HashMap<CandidateKey, Vec<PathCandidate>>>,
    failures: RwLock<HashMap<FailKey, FailRecord>>,
    active_meta: RwLock<HashMap<u64, ActivePathMeta>>,
    next_path_id: AtomicU64,
    cooldown: Duration,
    outcomes: StdMutex<Vec<(u64, String, PathOutcome)>>,
    p2p_discovery: RwLock<Option<DynamicRelayFallback>>,
}

struct DynamicRelayFallback {
    p2p: UdpP2pNode,
    enc_udp_channel: String,
    relay_prefix: String,
    relay_scope_key: PublicKey,
}

impl Default for SmartPathSource {
    fn default() -> Self {
        Self {
            candidates: Default::default(),
            failures: Default::default(),
            active_meta: Default::default(),
            next_path_id: AtomicU64::new(1000),
            cooldown: Duration::from_secs(30),
            outcomes: Default::default(),
            p2p_discovery: Default::default(),
        }
    }
}

impl SmartPathSource {
    pub fn set_candidates(
        &self,
        peer: PublicKey,
        endpoint: impl Into<String>,
        plane: Plane,
        list: Vec<PathCandidate>,
    ) {
        self.candidates
            .write()
            .unwrap()
            .insert((peer, endpoint.into(), plane), list);
    }

    pub fn enable_p2p_relay_fallback(
        &self,
        p2p: UdpP2pNode,
        enc_udp_channel: impl Into<String>,
        relay_prefix: impl Into<String>,
        relay_scope_key: PublicKey,
    ) {
        *self.p2p_discovery.write().unwrap() = Some(DynamicRelayFallback {
            p2p,
            enc_udp_channel: enc_udp_channel.into(),
            relay_prefix: relay_prefix.into(),
            relay_scope_key,
        });
    }

    pub fn recorded_outcomes(&self) -> Vec<(u64, String, PathOutcome)> {
        self.outcomes.lock().unwrap().clone()
    }

    pub fn clear_failures(&self) {
        self.failures.write().unwrap().clear();
    }
}

impl PathSource for SmartPathSource {
    fn resolve_path<'a>(
        &'a self,
        peer: &'a PublicKey,
        endpoint: &'a str,
        plane: Plane,
    ) -> BoxFut<'a, Result<ExplicitPath, CoreErr>> {
        Box::pin(async move {
            let key = (*peer, endpoint.to_owned(), plane);
            let mut list = self
                .candidates
                .read()
                .unwrap()
                .get(&key)
                .cloned()
                .unwrap_or_default();

            // If Blind Rendezvous discovered a Home UDP Relay slot for this peer,
            // dynamically splice it in right after Direct UDP P2P!
            if plane == Plane::Datagram
                && let Some(dyn_fb) = self.p2p_discovery.read().unwrap().as_ref()
                && let Some(info) = dyn_fb.p2p.discovered_peer(peer)
                && let Some((relay_addr, relay_link_key, slot_token)) = info.metadata.home_relay
            {
                let has_home = list.iter().any(|c| c.label == "home-udp-relay");
                if !has_home {
                    let target = format!("{}{}", dyn_fb.relay_prefix, encode_slot_hex(&slot_token));
                    let candidate = PathCandidate {
                        label: "home-udp-relay".into(),
                        path: ExplicitPath {
                            id: 0,
                            first_channel: dyn_fb.enc_udp_channel.clone(),
                            first_locator: EncryptedLocator::encode(
                                relay_link_key,
                                relay_addr.to_string().as_bytes(),
                            ),
                            min_mtu: DATAGRAM_MTU,
                            hops: vec![HopSpec {
                                peer: dyn_fb.relay_scope_key,
                                target,
                            }],
                        },
                    };
                    let pos = usize::from(!list.is_empty());
                    list.insert(pos, candidate);
                    self.candidates
                        .write()
                        .unwrap()
                        .insert(key.clone(), list.clone());
                }
            }

            if list.is_empty() {
                return Err(CoreErr::NoPath);
            }

            let now = Instant::now();
            let failures = self.failures.read().unwrap();
            let chosen = list.iter().enumerate().find(|(idx, _)| {
                failures
                    .get(&(*peer, endpoint.to_owned(), plane, *idx))
                    .is_none_or(|f| now.duration_since(f.failed_at) >= self.cooldown)
            });
            drop(failures);

            let (idx, candidate) = chosen.ok_or(CoreErr::NoPath)?;
            let id = self.next_path_id.fetch_add(1, Ordering::Relaxed);
            let mut path = candidate.path.clone();
            path.id = id;

            self.active_meta.write().unwrap().insert(
                id,
                ActivePathMeta {
                    peer: *peer,
                    endpoint: endpoint.to_owned(),
                    plane,
                    candidate_idx: idx,
                    established: false,
                },
            );
            Ok(path)
        })
    }

    fn report_outcome(&self, path_id: u64, outcome: PathOutcome) {
        let meta = {
            let mut active = self.active_meta.write().unwrap();
            active.get_mut(&path_id).map(|m| {
                if matches!(outcome, PathOutcome::Established { .. }) {
                    m.established = true;
                }
                (
                    m.peer,
                    m.endpoint.clone(),
                    m.plane,
                    m.candidate_idx,
                    m.established,
                )
            })
        };
        let label = if let Some((peer, ep, plane, idx, was_established)) = meta {
            if let PathOutcome::Failed(ref err) = outcome
                && !was_established
                && err.is_path_failure()
            {
                self.failures.write().unwrap().insert(
                    (peer, ep.clone(), plane, idx),
                    FailRecord {
                        failed_at: Instant::now(),
                        _reason: err.clone(),
                    },
                );
            }
            self.candidates
                .read()
                .unwrap()
                .get(&(peer, ep, plane))
                .and_then(|v| v.get(idx))
                .map(|c| c.label.clone())
                .unwrap_or_else(|| format!("cand-{idx}"))
        } else {
            "unknown".into()
        };
        self.outcomes
            .lock()
            .unwrap()
            .push((path_id, label, outcome));
    }
}

// ===========================================================================
// PART 2: VirtualL3Mesh — Tailscale-Style Overlay Mesh + L3 Fragmentation
// ===========================================================================

const L3_MAGIC: u8 = 0x4C;
const L3_HDR: usize = 14; // [magic(1) | flags(1) | frag_id(2) | idx(1) | total(1) | src(4) | dst(4)]
pub const MESH_ENDPOINT: &str = "l3-mesh";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtualIpPacket {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub payload: Vec<u8>,
}

struct ReassemblyEntry {
    total: u8,
    parts: HashMap<u8, Vec<u8>>,
    created: Instant,
}

struct Reassembler {
    inflight: HashMap<(Ipv4Addr, u16), ReassemblyEntry>,
}

impl Reassembler {
    fn new() -> Self {
        Self {
            inflight: HashMap::new(),
        }
    }

    fn feed(&mut self, frame: &[u8]) -> Option<VirtualIpPacket> {
        if frame.len() < L3_HDR || frame[0] != L3_MAGIC {
            return None;
        }
        let frag_id = u16::from_be_bytes(frame[2..4].try_into().unwrap());
        let idx = frame[4];
        let total = frame[5];
        if total == 0 || idx >= total {
            return None;
        }
        let src = Ipv4Addr::new(frame[6], frame[7], frame[8], frame[9]);
        let dst = Ipv4Addr::new(frame[10], frame[11], frame[12], frame[13]);
        let body = frame[L3_HDR..].to_vec();

        if total == 1 {
            return Some(VirtualIpPacket {
                src,
                dst,
                payload: body,
            });
        }
        let now = Instant::now();
        self.inflight
            .retain(|_, e| now.duration_since(e.created) < Duration::from_secs(5));
        let entry = self
            .inflight
            .entry((src, frag_id))
            .or_insert_with(|| ReassemblyEntry {
                total,
                parts: HashMap::new(),
                created: now,
            });
        if entry.total != total {
            return None;
        }
        entry.parts.insert(idx, body);
        if entry.parts.len() == usize::from(total) {
            let entry = self.inflight.remove(&(src, frag_id)).unwrap();
            let mut full = Vec::new();
            for i in 0..total {
                full.extend_from_slice(entry.parts.get(&i)?);
            }
            Some(VirtualIpPacket {
                src,
                dst,
                payload: full,
            })
        } else {
            None
        }
    }
}

struct MeshEndpointHandler {
    deliver: mpsc::Sender<VirtualIpPacket>,
}

impl DatagramEndpointHandler for MeshEndpointHandler {
    type Link = Arc<MemDatagramLink>;

    async fn open(&self, _auth: SessionAuth) -> Result<Arc<MemDatagramLink>, CoreErr> {
        let deliver = self.deliver.clone();
        let (server, app) = mem_datagram_pair(u16::MAX, 64);
        tokio::spawn(async move {
            let mut reasm = Reassembler::new();
            while let Ok(pkt) = app.recv().await {
                if let Some(ip_pkt) = reasm.feed(pkt.as_slice()) {
                    let _ = deliver.send(ip_pkt).await;
                }
            }
        });
        Ok(server)
    }
}

/// Tailscale-like userspace Virtual L3 Overlay Node sitting above `ScopeInstance`.
pub struct VirtualL3Node {
    scope: ScopeInstance,
    local_ip: Ipv4Addr,
    dns: RwLock<HashMap<String, Ipv4Addr>>,
    ip_to_peer: RwLock<HashMap<Ipv4Addr, PublicKey>>,
    sessions: AsyncMutex<HashMap<Ipv4Addr, E2eDatagram>>,
    inbound_rx: AsyncMutex<mpsc::Receiver<VirtualIpPacket>>,
    frag_id: AtomicU16,
    _publish: PublishGuard,
}

impl VirtualL3Node {
    pub fn attach(scope: ScopeInstance, local_ip: Ipv4Addr) -> Result<Self, CoreErr> {
        let (tx, rx) = mpsc::channel(128);
        let guard = scope.publish_datagram(
            MESH_ENDPOINT,
            DATAGRAM_MTU,
            Arc::new(MeshEndpointHandler { deliver: tx }),
        )?;
        Ok(Self {
            scope,
            local_ip,
            dns: Default::default(),
            ip_to_peer: Default::default(),
            sessions: Default::default(),
            inbound_rx: AsyncMutex::new(rx),
            frag_id: AtomicU16::new(1),
            _publish: guard,
        })
    }

    pub fn local_ip(&self) -> Ipv4Addr {
        self.local_ip
    }

    pub fn add_peer(&self, hostname: impl Into<String>, ip: Ipv4Addr, peer: PublicKey) {
        self.dns.write().unwrap().insert(hostname.into(), ip);
        self.ip_to_peer.write().unwrap().insert(ip, peer);
    }

    pub fn resolve_dns(&self, hostname: &str) -> Option<Ipv4Addr> {
        self.dns.read().unwrap().get(hostname).copied()
    }

    /// Sends a virtual L3 IP packet (of arbitrary size up to ~32 KiB) to `dst_ip`.
    pub async fn send_ip(&self, dst_ip: Ipv4Addr, payload: &[u8]) -> Result<(), CoreErr> {
        let peer = self
            .ip_to_peer
            .read()
            .unwrap()
            .get(&dst_ip)
            .copied()
            .ok_or(CoreErr::TargetUnreachable)?;

        let session = self.get_or_dial(dst_ip, peer).await?;
        if self
            .send_fragmented(&session, dst_ip, payload)
            .await
            .is_ok()
        {
            return Ok(());
        }
        self.sessions.lock().await.remove(&dst_ip);
        let fresh = self.get_or_dial(dst_ip, peer).await?;
        self.send_fragmented(&fresh, dst_ip, payload).await
    }

    pub async fn send_to_name(&self, hostname: &str, payload: &[u8]) -> Result<(), CoreErr> {
        let ip = self
            .resolve_dns(hostname)
            .ok_or(CoreErr::TargetUnreachable)?;
        self.send_ip(ip, payload).await
    }

    pub async fn recv_ip(&self) -> Result<VirtualIpPacket, CoreErr> {
        self.inbound_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(CoreErr::Closed)
    }

    pub async fn drop_session(&self, dst_ip: Ipv4Addr) {
        self.sessions.lock().await.remove(&dst_ip);
    }

    async fn get_or_dial(&self, dst_ip: Ipv4Addr, peer: PublicKey) -> Result<E2eDatagram, CoreErr> {
        if let Some(existing) = self.sessions.lock().await.get(&dst_ip).cloned() {
            return Ok(existing);
        }
        let mut last_err = CoreErr::NoPath;
        for _ in 0..4 {
            match self
                .scope
                .dial_datagram(peer, MESH_ENDPOINT, DATAGRAM_MTU)
                .await
            {
                Ok(session) => {
                    self.sessions.lock().await.insert(dst_ip, session.clone());
                    return Ok(session);
                }
                Err(CoreErr::NoPath) => return Err(last_err),
                Err(err) => {
                    last_err = err;
                }
            }
        }
        Err(last_err)
    }

    async fn send_fragmented(
        &self,
        session: &E2eDatagram,
        dst_ip: Ipv4Addr,
        payload: &[u8],
    ) -> Result<(), CoreErr> {
        let max_chunk = session.max_payload().saturating_sub(L3_HDR);
        if max_chunk == 0 {
            return Err(CoreErr::MtuTooSmall(0));
        }
        let chunks: Vec<&[u8]> = if payload.is_empty() {
            vec![&[]]
        } else {
            payload.chunks(max_chunk).collect()
        };
        let total = u8::try_from(chunks.len()).map_err(|_| CoreErr::MessageTooLarge(max_chunk))?;
        let fid = self.frag_id.fetch_add(1, Ordering::Relaxed);

        for (idx, chunk) in chunks.into_iter().enumerate() {
            let mut frame = Vec::with_capacity(L3_HDR + chunk.len());
            frame.push(L3_MAGIC);
            frame.push(u8::from(idx + 1 < usize::from(total)));
            frame.extend_from_slice(&fid.to_be_bytes());
            frame.push(idx as u8);
            frame.push(total);
            frame.extend_from_slice(&self.local_ip.octets());
            frame.extend_from_slice(&dst_ip.octets());
            frame.extend_from_slice(chunk);
            session.send_wait(PacketBuf::from_slice(&frame)).await?;
        }
        Ok(())
    }
}

// ===========================================================================
// PART 3: Native Embedded Application SDK Demos (Zero Local Sockets!)
// ===========================================================================

/// Native in-process Key-Value RPC endpoint implementing [`StreamEndpointHandler`].
#[derive(Default)]
pub struct KvService {
    store: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl KvService {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

impl StreamEndpointHandler for KvService {
    type Stream = MemStream;

    async fn open(&self, _auth: SessionAuth) -> Result<MemStream, CoreErr> {
        let store = self.store.clone();
        let (server, app) = mem_stream_pair(16384, 16384);
        tokio::spawn(async move {
            let (mut r, mut w) = app.split();
            let mut hdr = [0u8; 5]; // [op(1) | klen(2) | vlen(2)]
            while read_exact(&mut r, &mut hdr).await.is_ok() {
                let op = hdr[0];
                let klen = u16::from_be_bytes(hdr[1..3].try_into().unwrap()) as usize;
                let vlen = u16::from_be_bytes(hdr[3..5].try_into().unwrap()) as usize;
                let mut key = vec![0u8; klen];
                let mut val = vec![0u8; vlen];
                if read_exact(&mut r, &mut key).await.is_err()
                    || read_exact(&mut r, &mut val).await.is_err()
                {
                    break;
                }
                let Ok(key_str) = String::from_utf8(key) else {
                    break;
                };
                match op {
                    1 => {
                        store.write().unwrap().insert(key_str, val);
                        if w.write_all(&[1, 0, 0]).await.is_err() {
                            break;
                        }
                    }
                    2 => {
                        let found = store.read().unwrap().get(&key_str).cloned();
                        match found {
                            Some(v) => {
                                let mut resp = Vec::with_capacity(3 + v.len());
                                resp.push(1);
                                resp.extend_from_slice(&(v.len() as u16).to_be_bytes());
                                resp.extend_from_slice(&v);
                                if w.write_all(&resp).await.is_err() {
                                    break;
                                }
                            }
                            None => {
                                if w.write_all(&[0, 0, 0]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    _ => break,
                }
            }
            let _ = w.shutdown().await;
        });
        Ok(server)
    }
}

pub struct KvClient {
    stream: confluence_core::E2eStream,
}

impl KvClient {
    pub async fn connect(
        scope: &ScopeInstance,
        peer: PublicKey,
        endpoint: &str,
    ) -> Result<Self, CoreErr> {
        let stream = scope.dial_stream(peer, endpoint).await?;
        Ok(Self { stream })
    }

    pub async fn put(&self, key: &str, val: &[u8]) -> Result<(), CoreErr> {
        let mut req = Vec::with_capacity(5 + key.len() + val.len());
        req.push(1);
        req.extend_from_slice(&(key.len() as u16).to_be_bytes());
        req.extend_from_slice(&(val.len() as u16).to_be_bytes());
        req.extend_from_slice(key.as_bytes());
        req.extend_from_slice(val);
        self.stream.write_all(&req).await?;
        let mut resp = [0u8; 3];
        self.read_exact_e2e(&mut resp).await?;
        if resp[0] == 1 {
            Ok(())
        } else {
            Err(CoreErr::Malformed)
        }
    }

    pub async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, CoreErr> {
        let mut req = Vec::with_capacity(5 + key.len());
        req.push(2);
        req.extend_from_slice(&(key.len() as u16).to_be_bytes());
        req.extend_from_slice(&0u16.to_be_bytes());
        req.extend_from_slice(key.as_bytes());
        self.stream.write_all(&req).await?;
        let mut resp = [0u8; 3];
        self.read_exact_e2e(&mut resp).await?;
        if resp[0] == 0 {
            return Ok(None);
        }
        let vlen = u16::from_be_bytes(resp[1..3].try_into().unwrap()) as usize;
        let mut val = vec![0u8; vlen];
        self.read_exact_e2e(&mut val).await?;
        Ok(Some(val))
    }

    async fn read_exact_e2e(&self, mut buf: &mut [u8]) -> Result<(), CoreErr> {
        while !buf.is_empty() {
            let n = self.stream.read(buf).await?;
            if n == 0 {
                return Err(CoreErr::UnexpectedEof);
            }
            buf = &mut buf[n..];
        }
        Ok(())
    }
}
