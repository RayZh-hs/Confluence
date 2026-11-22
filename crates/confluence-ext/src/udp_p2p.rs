//! UDP P2P transport faithful to `archived/docs/transport/udp-p2p.md`:
//! - Realistic localhost NAT Simulator (`AddressPortRestrictedCone`, `Symmetric`, `UdpBlocked`)
//! - Blind `Noise_IK` Rendezvous server with `XChaCha20-Poly1305` `SealedEnvelope`
//! - Simultaneous NAT hole-punching (zero service side effects during punching)
//! - Single-socket `UdpP2pNode` implementing `DatagramChannel` with bidirectional
//!   `DatagramPort` reuse and link-layer authenticated stateless roaming.

use std::{
    collections::{HashMap, HashSet},
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use confluence_core::{
    ChannelCaps, ChannelErr, CoreErr, DATAGRAM_MTU, DatagramChannel, DatagramLink, PacketBuf,
    PublicKey, ScopeInstance, ScopeKeypair,
    crypto::{
        aead::{DatagramRx, DatagramTx},
        noise_ik::{self, REPLY_LEN, Responder},
        replay::SetupReplay,
    },
    scope::DatagramIngress,
};
use rand_core::{OsRng, RngCore};
use tokio::{
    net::UdpSocket,
    sync::{Mutex as AsyncMutex, mpsc, oneshot, watch},
};

use crate::now_ms;

// ===========================================================================
// PART 1: Realistic Localhost NAT Simulator (`SimNat`)
// ===========================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatKind {
    /// Drops all inbound packets from remote `X` unless internal host already
    /// transmitted a packet to `X` (real simultaneous hole-punching required!).
    AddressPortRestrictedCone,
    /// Allocates a distinct external WAN socket/port per destination address so
    /// the Rendezvous-observed WAN port does NOT match peer-to-peer packets.
    Symmetric,
    /// Strict firewall: drops all UDP packets in both directions.
    UdpBlocked,
}

/// Real localhost UDP NAT router used to test simultaneous hole-punching,
/// symmetric-NAT fallback to Home Relay, UDP-blocked fallback to Striped-TCP,
/// and NAT port rebinding (roaming).
pub struct SimNat {
    lan_addr: SocketAddr,
    wan_addr: Arc<StdMutex<SocketAddr>>,
    wan_socket: Arc<StdMutex<Arc<UdpSocket>>>,
    kind: NatKind,
    rebind_notify: Arc<tokio::sync::Notify>,
    _task: tokio::task::JoinHandle<()>,
}

impl SimNat {
    pub async fn start(kind: NatKind) -> io::Result<Self> {
        let lan_sock = Arc::new(UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?);
        let wan_sock = Arc::new(UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?);
        let lan_addr = lan_sock.local_addr()?;
        let wan_addr = Arc::new(StdMutex::new(wan_sock.local_addr()?));
        let wan_socket = Arc::new(StdMutex::new(wan_sock));
        let rebind_notify = Arc::new(tokio::sync::Notify::new());

        let internal_peer: Arc<StdMutex<Option<SocketAddr>>> = Default::default();
        let pinholes: Arc<StdMutex<HashSet<SocketAddr>>> = Default::default();

        let wan_addr_bg = wan_addr.clone();
        let wan_socket_bg = wan_socket.clone();
        let rebind_bg = rebind_notify.clone();

        let task = tokio::spawn(async move {
            let mut lan_buf = vec![0u8; 65536];
            let mut wan_buf = vec![0u8; 65536];
            let mut sym_sockets: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();

            loop {
                let active_wan = wan_socket_bg.lock().unwrap().clone();
                tokio::select! {
                    _ = rebind_bg.notified() => {
                        // Loop restarts with the newly bound WAN socket!
                        continue;
                    }
                    res = lan_sock.recv_from(&mut lan_buf) => {
                        let Ok((n, src_lan)) = res else { break };
                        if n < 6 { continue; }
                        *internal_peer.lock().unwrap() = Some(src_lan);
                        if kind == NatKind::UdpBlocked {
                            continue;
                        }
                        let dst = decode_v4(&lan_buf[..6]);
                        let payload = &lan_buf[6..n];
                        match kind {
                            NatKind::AddressPortRestrictedCone => {
                                pinholes.lock().unwrap().insert(dst);
                                let _ = active_wan.send_to(payload, dst).await;
                            }
                            NatKind::Symmetric => {
                                let sock = if let Some(s) = sym_sockets.get(&dst) {
                                    s.clone()
                                } else {
                                    let Ok(fresh) = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await else {
                                        continue;
                                    };
                                    let fresh = Arc::new(fresh);
                                    sym_sockets.insert(dst, fresh.clone());
                                    let lan_fwd = lan_sock.clone();
                                    let int_peer = internal_peer.clone();
                                    let expected_src = dst;
                                    let recv_sock = fresh.clone();
                                    tokio::spawn(async move {
                                        let mut b = vec![0u8; 65536];
                                        while let Ok((k, from)) = recv_sock.recv_from(&mut b).await {
                                            if from != expected_src { continue; }
                                            let target_ip = *int_peer.lock().unwrap();
                                            if let Some(ip) = target_ip {
                                                let mut framed = Vec::with_capacity(6 + k);
                                                framed.extend_from_slice(&encode_v4(from));
                                                framed.extend_from_slice(&b[..k]);
                                                let _ = lan_fwd.send_to(&framed, ip).await;
                                            }
                                        }
                                    });
                                    fresh
                                };
                                let _ = sock.send_to(payload, dst).await;
                            }
                            NatKind::UdpBlocked => {}
                        }
                    }
                    res = active_wan.recv_from(&mut wan_buf) => {
                        let Ok((n, remote_src)) = res else { continue };
                        if kind != NatKind::AddressPortRestrictedCone {
                            continue;
                        }
                        // Real Address+Port Restricted Cone check: DROP unless punched!
                        if !pinholes.lock().unwrap().contains(&remote_src) {
                            continue;
                        }
                        let target_ip = *internal_peer.lock().unwrap();
                        if let Some(int_addr) = target_ip {
                            let mut framed = Vec::with_capacity(6 + n);
                            framed.extend_from_slice(&encode_v4(remote_src));
                            framed.extend_from_slice(&wan_buf[..n]);
                            let _ = lan_sock.send_to(&framed, int_addr).await;
                        }
                    }
                }
            }
            let _ = wan_addr_bg;
        });

        Ok(Self {
            lan_addr,
            wan_addr,
            wan_socket,
            kind,
            rebind_notify,
            _task: task,
        })
    }

    pub fn lan_addr(&self) -> SocketAddr {
        self.lan_addr
    }
    pub fn wan_addr(&self) -> SocketAddr {
        *self.wan_addr.lock().unwrap()
    }
    pub fn kind(&self) -> NatKind {
        self.kind
    }

    /// Simulates a carrier/router NAT port rebind (roaming event) mid-session!
    pub async fn rebind_wan_port(&self) -> io::Result<SocketAddr> {
        let fresh = Arc::new(UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?);
        let new_addr = fresh.local_addr()?;
        *self.wan_socket.lock().unwrap() = fresh;
        *self.wan_addr.lock().unwrap() = new_addr;
        self.rebind_notify.notify_one();
        Ok(new_addr)
    }
}

impl Drop for SimNat {
    fn drop(&mut self) {
        self._task.abort();
    }
}

fn encode_v4(addr: SocketAddr) -> [u8; 6] {
    match addr {
        SocketAddr::V4(v4) => {
            let ip = v4.ip().octets();
            let port = v4.port().to_be_bytes();
            [ip[0], ip[1], ip[2], ip[3], port[0], port[1]]
        }
        SocketAddr::V6(_) => panic!("SimNat supports IPv4 loopback sockets"),
    }
}

fn decode_v4(buf: &[u8]) -> SocketAddr {
    let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
    let port = u16::from_be_bytes([buf[4], buf[5]]);
    SocketAddr::V4(SocketAddrV4::new(ip, port))
}

/// Abstracts either a direct OS `UdpSocket` or a `UdpSocket` sitting behind a `SimNat`.
#[derive(Clone)]
pub struct HostUdpTransport {
    socket: Arc<UdpSocket>,
    nat_lan: Option<SocketAddr>,
}

impl HostUdpTransport {
    pub async fn direct(addr: SocketAddr) -> io::Result<Self> {
        Ok(Self {
            socket: Arc::new(UdpSocket::bind(addr).await?),
            nat_lan: None,
        })
    }

    pub async fn behind_nat(nat: &SimNat) -> io::Result<Self> {
        Ok(Self {
            socket: Arc::new(UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?),
            nat_lan: Some(nat.lan_addr()),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_send_ready(cx)
    }

    pub fn try_send_to(&self, data: &[u8], dst: SocketAddr) -> io::Result<usize> {
        if let Some(nat) = self.nat_lan {
            let mut framed = Vec::with_capacity(6 + data.len());
            framed.extend_from_slice(&encode_v4(dst));
            framed.extend_from_slice(data);
            self.socket.try_send_to(&framed, nat)?;
            Ok(data.len())
        } else {
            self.socket.try_send_to(data, dst)
        }
    }

    pub async fn send_to(&self, data: &[u8], dst: SocketAddr) -> io::Result<usize> {
        if let Some(nat) = self.nat_lan {
            let mut framed = Vec::with_capacity(6 + data.len());
            framed.extend_from_slice(&encode_v4(dst));
            framed.extend_from_slice(data);
            self.socket.send_to(&framed, nat).await?;
            Ok(data.len())
        } else {
            self.socket.send_to(data, dst).await
        }
    }

    pub async fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        if self.nat_lan.is_some() {
            let mut framed = vec![0u8; 6 + out.len()];
            loop {
                let (n, _) = self.socket.recv_from(&mut framed).await?;
                if n < 6 {
                    continue;
                }
                let src = decode_v4(&framed[..6]);
                let payload_len = n - 6;
                out[..payload_len].copy_from_slice(&framed[6..n]);
                return Ok((payload_len, src));
            }
        } else {
            self.socket.recv_from(out).await
        }
    }
}

// ===========================================================================
// PART 2: SealedEnvelope (XChaCha20-Poly1305) & Blind Noise_IK Rendezvous
// ===========================================================================

pub const MAX_SEALED_ENVELOPE: usize = 1024;
const RV_AAD: [u8; 32] = *b"confluence-v1-blind-rv-link-----";
const RV_FRAME_INIT: u8 = 0xC1;
const RV_FRAME_REPLY: u8 = 0xC2;
const RV_FRAME_MSG: u8 = 0xC3;

const RV_MSG_REGISTER: u8 = 0x01;
const RV_MSG_QUERY: u8 = 0x02;
const RV_MSG_QUERY_REPLY: u8 = 0x03;
const RV_MSG_PUNCH_NOTIFY: u8 = 0x04;
const RV_MSG_NOT_FOUND: u8 = 0x05;

/// Peer discovery metadata sealed inside `XChaCha20-Poly1305` so the Rendezvous
/// server learns ZERO LAN endpoints or Home Relay slot tokens (`udp-p2p.md` §1.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerMetadata {
    pub lan_addrs: Vec<SocketAddr>,
    pub home_relay: Option<(SocketAddr, PublicKey, [u8; 16])>,
    pub timestamp_ms: u64,
}

impl PeerMetadata {
    pub fn seal(
        &self,
        discovery_key: &[u8; 32],
        topic_id: u64,
        peer: PublicKey,
    ) -> Result<Vec<u8>, CoreErr> {
        let mut plain = Vec::with_capacity(64);
        plain.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        plain.push(self.lan_addrs.len().min(8) as u8);
        for addr in self.lan_addrs.iter().take(8) {
            plain.extend_from_slice(&encode_v4(*addr));
        }
        match &self.home_relay {
            None => plain.push(0),
            Some((addr, relay_key, slot)) => {
                plain.push(1);
                plain.extend_from_slice(&encode_v4(*addr));
                plain.extend_from_slice(&relay_key.0);
                plain.extend_from_slice(slot);
            }
        }
        let aad = envelope_aad(topic_id, peer);
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new(discovery_key.into());
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &aad,
                },
            )
            .map_err(|_| CoreErr::Malformed)?;
        let mut out = Vec::with_capacity(24 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        if out.len() > MAX_SEALED_ENVELOPE {
            return Err(CoreErr::Malformed);
        }
        Ok(out)
    }

    pub fn open(
        discovery_key: &[u8; 32],
        topic_id: u64,
        peer: PublicKey,
        envelope: &[u8],
    ) -> Result<Self, CoreErr> {
        if envelope.len() < 24 + 16 || envelope.len() > MAX_SEALED_ENVELOPE {
            return Err(CoreErr::Authentication);
        }
        let aad = envelope_aad(topic_id, peer);
        let cipher = XChaCha20Poly1305::new(discovery_key.into());
        let plain = cipher
            .decrypt(
                XNonce::from_slice(&envelope[..24]),
                Payload {
                    msg: &envelope[24..],
                    aad: &aad,
                },
            )
            .map_err(|_| CoreErr::Authentication)?;
        if plain.len() < 10 {
            return Err(CoreErr::Malformed);
        }
        let timestamp_ms = u64::from_be_bytes(plain[..8].try_into().unwrap());
        let lan_count = plain[8] as usize;
        let mut off = 9;
        if plain.len() < off + lan_count * 6 + 1 {
            return Err(CoreErr::Malformed);
        }
        let mut lan_addrs = Vec::with_capacity(lan_count);
        for _ in 0..lan_count {
            lan_addrs.push(decode_v4(&plain[off..off + 6]));
            off += 6;
        }
        let has_relay = plain[off];
        off += 1;
        let home_relay = if has_relay == 1 {
            if plain.len() != off + 6 + 32 + 16 {
                return Err(CoreErr::Malformed);
            }
            let addr = decode_v4(&plain[off..off + 6]);
            let key = PublicKey(plain[off + 6..off + 38].try_into().unwrap());
            let slot: [u8; 16] = plain[off + 38..off + 54].try_into().unwrap();
            Some((addr, key, slot))
        } else {
            None
        };
        Ok(Self {
            lan_addrs,
            home_relay,
            timestamp_ms,
        })
    }
}

fn envelope_aad(topic_id: u64, peer: PublicKey) -> Vec<u8> {
    let mut aad = Vec::with_capacity(17 + 8 + 32);
    aad.extend_from_slice(b"confluence-v1-env");
    aad.extend_from_slice(&topic_id.to_be_bytes());
    aad.extend_from_slice(&peer.0);
    aad
}

struct RvClientState {
    remote_sid: u32,
    addr: SocketAddr,
    peer_key: PublicKey,
    tx: DatagramTx,
    rx: DatagramRx,
}

struct RvRegistration {
    observed_addr: SocketAddr,
    client_sid: u32,
    sealed_envelope: Vec<u8>,
    expires_at: Instant,
}

/// Blind `Noise_IK` UDP Rendezvous server (`udp-p2p.md` §1).
/// Never holds any `DiscoveryKey`; stores opaque `SealedEnvelope`s with bounded TTL.
pub struct BlindRendezvous {
    addr: SocketAddr,
    public_key: PublicKey,
    _task: tokio::task::JoinHandle<()>,
}

impl BlindRendezvous {
    pub async fn start(keypair: ScopeKeypair) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?);
        let addr = socket.local_addr()?;
        let public_key = keypair.public_key();

        let task = tokio::spawn(async move {
            let replay = SetupReplay::default();
            let mut clients: HashMap<u32, RvClientState> = HashMap::new();
            let mut regs: HashMap<(u64, PublicKey), RvRegistration> = HashMap::new();
            let mut next_sid = 1u32;
            let mut buf = vec![0u8; 4096];

            while let Ok((n, src)) = socket.recv_from(&mut buf).await {
                if n < 5 {
                    continue;
                }
                let data = &buf[..n];
                match data[0] {
                    RV_FRAME_INIT => {
                        let seg = &data[5..];
                        if !keypair.verify_mac1(seg) {
                            continue;
                        }
                        let client_sid = u32::from_be_bytes(data[1..5].try_into().unwrap());
                        let Ok(resp) = Responder::accept(&keypair, &replay, seg, &RV_AAD, now_ms())
                        else {
                            continue;
                        };
                        let peer_key = resp.peer;
                        let Ok((reply_body, keys)) = resp.reply(&[0u8; 10]) else {
                            continue;
                        };
                        let server_sid = next_sid;
                        next_sid = next_sid.wrapping_add(1).max(1);
                        clients.insert(
                            server_sid,
                            RvClientState {
                                remote_sid: client_sid,
                                addr: src,
                                peer_key,
                                tx: DatagramTx::new(keys.tx),
                                rx: DatagramRx::new(keys.rx),
                            },
                        );
                        let mut reply = Vec::with_capacity(9 + REPLY_LEN);
                        reply.push(RV_FRAME_REPLY);
                        reply.extend_from_slice(&client_sid.to_be_bytes());
                        reply.extend_from_slice(&server_sid.to_be_bytes());
                        reply.extend_from_slice(&reply_body);
                        let _ = socket.send_to(&reply, src).await;
                    }
                    RV_FRAME_MSG if n >= 30 => {
                        let sid = u32::from_be_bytes(data[1..5].try_into().unwrap());
                        let Some(client) = clients.get_mut(&sid) else {
                            continue;
                        };
                        let Ok((msg_type, plain)) =
                            client.rx.open(PacketBuf::from_slice(&data[5..]))
                        else {
                            continue;
                        };
                        client.addr = src;
                        let requester_key = client.peer_key;
                        let body = plain.as_slice();

                        match msg_type {
                            RV_MSG_REGISTER if body.len() >= 10 => {
                                let topic_id = u64::from_be_bytes(body[..8].try_into().unwrap());
                                let env_len =
                                    u16::from_be_bytes(body[8..10].try_into().unwrap()) as usize;
                                if env_len <= MAX_SEALED_ENVELOPE && body.len() == 10 + env_len {
                                    // Bound soft-state table
                                    let now = Instant::now();
                                    regs.retain(|_, r| r.expires_at > now);
                                    if regs.len() < 1024
                                        || regs.contains_key(&(topic_id, requester_key))
                                    {
                                        regs.insert(
                                            (topic_id, requester_key),
                                            RvRegistration {
                                                observed_addr: src,
                                                client_sid: sid,
                                                sealed_envelope: body[10..].to_vec(),
                                                expires_at: now + Duration::from_secs(120),
                                            },
                                        );
                                    }
                                }
                            }
                            RV_MSG_QUERY if body.len() == 40 => {
                                let topic_id = u64::from_be_bytes(body[..8].try_into().unwrap());
                                let target = PublicKey(body[8..40].try_into().unwrap());
                                let now = Instant::now();
                                let found = regs
                                    .get(&(topic_id, target))
                                    .filter(|r| r.expires_at > now)
                                    .map(|r| {
                                        (r.observed_addr, r.client_sid, r.sealed_envelope.clone())
                                    });
                                let requester_env = regs
                                    .get(&(topic_id, requester_key))
                                    .filter(|r| r.expires_at > now)
                                    .map(|r| r.sealed_envelope.clone())
                                    .unwrap_or_default();

                                if let Some((target_addr, target_sid, target_env)) = found {
                                    // 1. Send QueryReply(target_key, target_pub_addr, target_env) to requester
                                    let mut qreply = Vec::with_capacity(32 + 6 + target_env.len());
                                    qreply.extend_from_slice(&target.0);
                                    qreply.extend_from_slice(&encode_v4(target_addr));
                                    qreply.extend_from_slice(&target_env);
                                    if let Some(c) = clients.get_mut(&sid) {
                                        let _ =
                                            send_rv_msg(&socket, c, RV_MSG_QUERY_REPLY, &qreply)
                                                .await;
                                    }
                                    // 2. Simultaneously send PunchNotify(requester_key, src, requester_env) to target!
                                    let mut notify =
                                        Vec::with_capacity(32 + 6 + requester_env.len());
                                    notify.extend_from_slice(&requester_key.0);
                                    notify.extend_from_slice(&encode_v4(src));
                                    notify.extend_from_slice(&requester_env);
                                    if let Some(t) = clients.get_mut(&target_sid) {
                                        let _ =
                                            send_rv_msg(&socket, t, RV_MSG_PUNCH_NOTIFY, &notify)
                                                .await;
                                    }
                                } else if let Some(c) = clients.get_mut(&sid) {
                                    let _ =
                                        send_rv_msg(&socket, c, RV_MSG_NOT_FOUND, &target.0).await;
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        });

        Ok(Self {
            addr,
            public_key,
            _task: task,
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }
}

impl Drop for BlindRendezvous {
    fn drop(&mut self) {
        self._task.abort();
    }
}

async fn send_rv_msg(
    socket: &UdpSocket,
    client: &mut RvClientState,
    msg_type: u8,
    body: &[u8],
) -> io::Result<()> {
    let Ok(mut sealed) = client.tx.seal(msg_type, PacketBuf::from_slice(body)) else {
        return Ok(());
    };
    let mut hdr = [0u8; 5];
    hdr[0] = RV_FRAME_MSG;
    hdr[1..5].copy_from_slice(&client.remote_sid.to_be_bytes());
    sealed.prepend_header(&hdr);
    socket.send_to(sealed.as_slice(), client.addr).await?;
    Ok(())
}

// ===========================================================================
// PART 3: UdpP2pNode & UdpP2pChannel (Simultaneous Hole-Punching + Roaming)
// ===========================================================================

const P2P_FRAME_PING: u8 = 0xD1;
const P2P_FRAME_PONG: u8 = 0xD2;
const P2P_FRAME_DATA: u8 = 0xD3;
const P2P_OVERHEAD: u16 = 30;
const P2P_PENDING_MAX: usize = 64;

#[derive(Clone, Debug)]
pub struct DiscoveredPeer {
    pub peer: PublicKey,
    pub public_addr: SocketAddr,
    pub metadata: PeerMetadata,
}

struct P2pLinkState {
    peer_key: PublicKey,
    remote_addr: StdMutex<SocketAddr>,
    transport: HostUdpTransport,
    tx: StdMutex<DatagramTx>,
    rx: StdMutex<DatagramRx>,
    inbound_tx: mpsc::Sender<PacketBuf>,
    inbound_rx: StdMutex<mpsc::Receiver<PacketBuf>>,
    mtu: watch::Sender<u16>,
    confirmed: AtomicBool,
    confirmed_notify: tokio::sync::Notify,
}

/// Bidirectional `DatagramLink` over a hole-punched direct UDP pinhole with
/// pairwise link AEAD (enabling stateless endpoint roaming across NAT rebinds!).
pub struct P2pPeerLink {
    state: Arc<P2pLinkState>,
}

impl P2pPeerLink {
    pub fn remote_addr(&self) -> SocketAddr {
        *self.state.remote_addr.lock().unwrap()
    }
}

impl DatagramLink for P2pPeerLink {
    fn caps(&self) -> ChannelCaps {
        ChannelCaps::dynamic(self.state.mtu.subscribe(), false)
    }

    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), ChannelErr>> {
        self.state
            .transport
            .poll_send_ready(cx)
            .map_err(|e| CoreErr::Carrier(e.to_string()))
    }

    fn try_send(&self, packet: PacketBuf) -> Result<(), ChannelErr> {
        let mtu = *self.state.mtu.borrow();
        if packet.len() > usize::from(mtu) {
            return Err(CoreErr::MtuTooSmall(mtu));
        }
        let mut sealed = self.state.tx.lock().unwrap().seal(0x01, packet)?;
        let mut hdr = [0u8; 5];
        hdr[0] = P2P_FRAME_DATA;
        // Deterministic 4B peer tag derived from sender's key so receiver locates session even after NAT rebind!
        let tag = peer_tag(self.state.peer_key);
        hdr[1..5].copy_from_slice(&tag);
        if !sealed.prepend_header(&hdr) {
            return Err(CoreErr::Malformed);
        }
        let dst = *self.state.remote_addr.lock().unwrap();
        match self.state.transport.try_send_to(sealed.as_slice(), dst) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(CoreErr::WouldBlock),
            Err(e) => Err(CoreErr::Carrier(e.to_string())),
        }
    }

    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<PacketBuf, ChannelErr>> {
        self.state
            .inbound_rx
            .lock()
            .unwrap()
            .poll_recv(cx)
            .map(|opt| opt.ok_or(CoreErr::Closed))
    }
}

fn peer_tag(key: PublicKey) -> [u8; 4] {
    blake3::derive_key("confluence-p2p-peer-tag", &key.0)[..4]
        .try_into()
        .unwrap()
}

/// Derives symmetric directional link keys for direct P2P hole-punching from the
/// shared scope `discovery_key` and both peers' static public keys (ordered
/// canonically so A and B derive complementary `(tx, rx)` keys with 0 extra RTTs).
fn derive_p2p_link_keys(
    discovery_key: &[u8; 32],
    local: PublicKey,
    remote: PublicKey,
) -> ([u8; 32], [u8; 32]) {
    let (low, high, local_is_low) = if local.0 <= remote.0 {
        (local.0, remote.0, true)
    } else {
        (remote.0, local.0, false)
    };
    let mut h1 = blake3::Hasher::new_keyed(discovery_key);
    h1.update(b"confluence-p2p-low-to-high");
    h1.update(&low);
    h1.update(&high);
    let k_lh = *h1.finalize().as_bytes();

    let mut h2 = blake3::Hasher::new_keyed(discovery_key);
    h2.update(b"confluence-p2p-high-to-low");
    h2.update(&low);
    h2.update(&high);
    let k_hl = *h2.finalize().as_bytes();

    if local_is_low {
        (k_lh, k_hl)
    } else {
        (k_hl, k_lh)
    }
}

struct RvLink {
    addr: SocketAddr,
    local_sid: u32,
    remote_sid: u32,
    tx: AsyncMutex<DatagramTx>,
    rx: AsyncMutex<DatagramRx>,
}

/// Single-socket UDP P2P node (`archived/docs/transport/udp-p2p.md`).
///
/// Owns ONE UDP socket (behind a real or simulated NAT), talks to Blind Rendezvous,
/// performs simultaneous hole-punching with zero service side effects, attaches
/// admitted peer links to `ScopeInstance`, and implements `DatagramChannel` so
/// outbound dials reuse the EXACT same punched `Arc<P2pPeerLink>`!
type RvHandshakeWaiter = Arc<StdMutex<Option<oneshot::Sender<(u32, Vec<u8>)>>>>;

#[derive(Clone)]
pub struct UdpP2pNode {
    transport: HostUdpTransport,
    local_key: Arc<ScopeKeypair>,
    topic_id: u64,
    discovery_key: [u8; 32],
    inner_mtu: u16,
    rv: Arc<AsyncMutex<Option<Arc<RvLink>>>>,
    rv_handshake: RvHandshakeWaiter,
    query_waiters: Arc<StdMutex<HashMap<PublicKey, oneshot::Sender<Option<DiscoveredPeer>>>>>,
    discovered: Arc<StdMutex<HashMap<PublicKey, DiscoveredPeer>>>,
    peers: Arc<StdMutex<HashMap<PublicKey, Arc<P2pPeerLink>>>>,
    by_local_tag: Arc<StdMutex<HashMap<[u8; 4], Arc<P2pPeerLink>>>>,
    pending_punches: Arc<StdMutex<HashMap<PublicKey, Instant>>>,
    next_sid: Arc<AtomicU32>,
    punch_timeout: Duration,
}

impl UdpP2pNode {
    pub fn new(
        transport: HostUdpTransport,
        local_key: Arc<ScopeKeypair>,
        topic_id: u64,
        discovery_key: [u8; 32],
        inner_mtu: u16,
    ) -> Result<Self, CoreErr> {
        if inner_mtu < DATAGRAM_MTU {
            return Err(CoreErr::MtuTooSmall(inner_mtu));
        }
        Ok(Self {
            transport,
            local_key,
            topic_id,
            discovery_key,
            inner_mtu,
            rv: Default::default(),
            rv_handshake: Default::default(),
            query_waiters: Default::default(),
            discovered: Default::default(),
            peers: Default::default(),
            by_local_tag: Default::default(),
            pending_punches: Default::default(),
            next_sid: Arc::new(AtomicU32::new(1)),
            punch_timeout: Duration::from_millis(800),
        })
    }

    pub fn with_punch_timeout(mut self, timeout: Duration) -> Self {
        self.punch_timeout = timeout;
        self
    }

    pub fn public_key(&self) -> PublicKey {
        self.local_key.public_key()
    }

    pub fn discovered_peer(&self, peer: &PublicKey) -> Option<DiscoveredPeer> {
        self.discovered.lock().unwrap().get(peer).cloned()
    }

    /// Starts the single-socket demux + PunchNotify loop, attaching punched links to `scope`.
    pub fn spawn_loop(&self, scope: ScopeInstance) -> tokio::task::JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let mut ingress_guards: Vec<DatagramIngress> = Vec::new();
            while let Ok((n, src)) = this.transport.recv_from(&mut buf).await {
                if n < 5 {
                    continue;
                }
                let data = &buf[..n];
                match data[0] {
                    RV_FRAME_REPLY if n == 9 + REPLY_LEN => {
                        let server_sid = u32::from_be_bytes(data[5..9].try_into().unwrap());
                        if let Some(tx) = this.rv_handshake.lock().unwrap().take() {
                            let _ = tx.send((server_sid, data[9..].to_vec()));
                        }
                    }
                    RV_FRAME_MSG if n >= 30 => {
                        let rv = this.rv.lock().await.clone();
                        let Some(rv) = rv else { continue };
                        if u32::from_be_bytes(data[1..5].try_into().unwrap()) != rv.local_sid {
                            continue;
                        }
                        let Ok((msg_type, plain)) =
                            rv.rx.lock().await.open(PacketBuf::from_slice(&data[5..]))
                        else {
                            continue;
                        };
                        let body = plain.as_slice();
                        match msg_type {
                            RV_MSG_QUERY_REPLY if body.len() >= 38 => {
                                let target = PublicKey(body[..32].try_into().unwrap());
                                let pub_addr = decode_v4(&body[32..38]);
                                if let Ok(metadata) = PeerMetadata::open(
                                    &this.discovery_key,
                                    this.topic_id,
                                    target,
                                    &body[38..],
                                ) {
                                    let info = DiscoveredPeer {
                                        peer: target,
                                        public_addr: pub_addr,
                                        metadata,
                                    };
                                    this.discovered.lock().unwrap().insert(target, info.clone());
                                    if let Some(w) =
                                        this.query_waiters.lock().unwrap().remove(&target)
                                    {
                                        let _ = w.send(Some(info));
                                    }
                                }
                            }
                            RV_MSG_NOT_FOUND if body.len() == 32 => {
                                let target = PublicKey(body[..32].try_into().unwrap());
                                if let Some(w) = this.query_waiters.lock().unwrap().remove(&target)
                                {
                                    let _ = w.send(None);
                                }
                            }
                            RV_MSG_PUNCH_NOTIFY if body.len() >= 38 => {
                                let requester = PublicKey(body[..32].try_into().unwrap());
                                let req_addr = decode_v4(&body[32..38]);
                                // Decrypt SealedEnvelope locally & enforce bounded pending table
                                let Ok(metadata) = PeerMetadata::open(
                                    &this.discovery_key,
                                    this.topic_id,
                                    requester,
                                    &body[38..],
                                ) else {
                                    continue;
                                };
                                {
                                    let mut pending = this.pending_punches.lock().unwrap();
                                    let now = Instant::now();
                                    pending.retain(|_, t| {
                                        now.duration_since(*t) < Duration::from_secs(10)
                                    });
                                    if pending.len() >= P2P_PENDING_MAX
                                        && !pending.contains_key(&requester)
                                    {
                                        continue;
                                    }
                                    pending.insert(requester, now);
                                }
                                this.discovered.lock().unwrap().insert(
                                    requester,
                                    DiscoveredPeer {
                                        peer: requester,
                                        public_addr: req_addr,
                                        metadata,
                                    },
                                );
                                // Ensure peer link is created & attached to ScopeInstance, then punch!
                                let (link, is_new) =
                                    this.get_or_create_peer_link(requester, req_addr);
                                if is_new && let Ok(guard) = scope.attach_datagram(link.clone()) {
                                    ingress_guards.push(guard);
                                }
                                let p_this = this.clone();
                                tokio::spawn(async move {
                                    for _ in 0..8 {
                                        if link.state.confirmed.load(Ordering::Acquire) {
                                            break;
                                        }
                                        let _ = p_this
                                            .send_punch(&link, P2P_FRAME_PING, req_addr)
                                            .await;
                                        tokio::time::sleep(Duration::from_millis(40)).await;
                                    }
                                });
                            }
                            _ => {}
                        }
                    }
                    P2P_FRAME_PING | P2P_FRAME_PONG if n >= P2P_OVERHEAD as usize => {
                        let remote_tag: [u8; 4] = data[1..5].try_into().unwrap();
                        let link = this.by_local_tag.lock().unwrap().get(&remote_tag).cloned();
                        let Some(link) = link else { continue };
                        let Ok((_, _)) = link
                            .state
                            .rx
                            .lock()
                            .unwrap()
                            .open(PacketBuf::from_slice(&data[5..]))
                        else {
                            continue;
                        };
                        // Authenticated hole-punch received! Update active endpoint & confirm.
                        *link.state.remote_addr.lock().unwrap() = src;
                        if data[0] == P2P_FRAME_PING {
                            let _ = this.send_punch(&link, P2P_FRAME_PONG, src).await;
                        }
                        if !link.state.confirmed.swap(true, Ordering::AcqRel) {
                            link.state.confirmed_notify.notify_waiters();
                        }
                    }
                    P2P_FRAME_DATA if n >= P2P_OVERHEAD as usize => {
                        let remote_tag: [u8; 4] = data[1..5].try_into().unwrap();
                        let link = this.by_local_tag.lock().unwrap().get(&remote_tag).cloned();
                        let Some(link) = link else { continue };
                        let Ok((_, plain)) = link
                            .state
                            .rx
                            .lock()
                            .unwrap()
                            .open(PacketBuf::from_slice(&data[5..]))
                        else {
                            continue;
                        };
                        // Stateless roaming: valid AEAD updates peer's active UDP addr!
                        if *link.state.remote_addr.lock().unwrap() != src {
                            *link.state.remote_addr.lock().unwrap() = src;
                        }
                        if !link.state.confirmed.swap(true, Ordering::AcqRel) {
                            link.state.confirmed_notify.notify_waiters();
                        }
                        let _ = link.state.inbound_tx.try_send(plain);
                    }
                    _ => {}
                }
            }
        })
    }

    /// Connects the persistent `AlwaysWarm` `Noise_IK` link to the Blind Rendezvous
    /// server and registers this peer's `XChaCha20-Poly1305` `SealedEnvelope`.
    pub async fn register_with_rendezvous(
        &self,
        rv_addr: SocketAddr,
        rv_pubkey: PublicKey,
        metadata: &PeerMetadata,
    ) -> Result<(), CoreErr> {
        // Connect Noise_IK session to RV if not yet connected
        if self.rv.lock().await.is_none() {
            let local_sid = self.next_sid.fetch_add(1, Ordering::Relaxed);
            let plain = now_ms().to_be_bytes();
            let (init, state) = noise_ik::initiate(&self.local_key, rv_pubkey, &RV_AAD, &plain)?;
            let (tx, rx) = oneshot::channel();
            *self.rv_handshake.lock().unwrap() = Some(tx);
            let mut pkt = Vec::with_capacity(5 + init.len());
            pkt.push(RV_FRAME_INIT);
            pkt.extend_from_slice(&local_sid.to_be_bytes());
            pkt.extend_from_slice(&init);

            let (remote_sid, reply) = tokio::time::timeout(Duration::from_secs(2), async {
                self.transport
                    .send_to(&pkt, rv_addr)
                    .await
                    .map_err(|e| CoreErr::Carrier(e.to_string()))?;
                rx.await.map_err(|_| CoreErr::Closed)
            })
            .await
            .map_err(|_| CoreErr::Timeout)??;
            let (_ack, keys) = state.finish(&self.local_key, &reply)?;
            *self.rv.lock().await = Some(Arc::new(RvLink {
                addr: rv_addr,
                local_sid,
                remote_sid,
                tx: AsyncMutex::new(DatagramTx::new(keys.tx)),
                rx: AsyncMutex::new(DatagramRx::new(keys.rx)),
            }));
        }

        let sealed = metadata.seal(
            &self.discovery_key,
            self.topic_id,
            self.local_key.public_key(),
        )?;
        let mut body = Vec::with_capacity(10 + sealed.len());
        body.extend_from_slice(&self.topic_id.to_be_bytes());
        body.extend_from_slice(&(sealed.len() as u16).to_be_bytes());
        body.extend_from_slice(&sealed);
        self.send_to_rv(RV_MSG_REGISTER, &body).await
    }

    async fn send_to_rv(&self, msg_type: u8, body: &[u8]) -> Result<(), CoreErr> {
        let rv = self
            .rv
            .lock()
            .await
            .clone()
            .ok_or(CoreErr::TargetUnreachable)?;
        let mut sealed = rv
            .tx
            .lock()
            .await
            .seal(msg_type, PacketBuf::from_slice(body))?;
        let mut hdr = [0u8; 5];
        hdr[0] = RV_FRAME_MSG;
        hdr[1..5].copy_from_slice(&rv.remote_sid.to_be_bytes());
        sealed.prepend_header(&hdr);
        self.transport
            .send_to(sealed.as_slice(), rv.addr)
            .await
            .map_err(|e| CoreErr::Carrier(e.to_string()))?;
        Ok(())
    }

    /// Queries the Blind Rendezvous server for `target` (also triggering
    /// `PunchNotify` to `target`), decrypting `target`'s `SealedEnvelope`.
    pub async fn query_peer(&self, target: PublicKey) -> Result<DiscoveredPeer, CoreErr> {
        let (tx, rx) = oneshot::channel();
        self.query_waiters.lock().unwrap().insert(target, tx);
        let mut body = Vec::with_capacity(40);
        body.extend_from_slice(&self.topic_id.to_be_bytes());
        body.extend_from_slice(&target.0);
        self.send_to_rv(RV_MSG_QUERY, &body).await?;
        let res = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .map_err(|_| CoreErr::Timeout)?
            .map_err(|_| CoreErr::Closed)?;
        res.ok_or(CoreErr::TargetUnreachable)
    }

    fn get_or_create_peer_link(
        &self,
        peer: PublicKey,
        addr: SocketAddr,
    ) -> (Arc<P2pPeerLink>, bool) {
        let mut map = self.peers.lock().unwrap();
        if let Some(existing) = map.get(&peer) {
            return (existing.clone(), false);
        }
        let (tx_key, rx_key) =
            derive_p2p_link_keys(&self.discovery_key, self.local_key.public_key(), peer);
        let (in_tx, in_rx) = mpsc::channel(64);
        let link = Arc::new(P2pPeerLink {
            state: Arc::new(P2pLinkState {
                peer_key: self.local_key.public_key(),
                remote_addr: StdMutex::new(addr),
                transport: self.transport.clone(),
                tx: StdMutex::new(DatagramTx::new(tx_key)),
                rx: StdMutex::new(DatagramRx::new(rx_key)),
                inbound_tx: in_tx,
                inbound_rx: StdMutex::new(in_rx),
                mtu: watch::channel(self.inner_mtu).0,
                confirmed: AtomicBool::new(false),
                confirmed_notify: tokio::sync::Notify::new(),
            }),
        });
        map.insert(peer, link.clone());
        self.by_local_tag
            .lock()
            .unwrap()
            .insert(peer_tag(peer), link.clone());
        (link, true)
    }

    async fn send_punch(
        &self,
        link: &P2pPeerLink,
        kind: u8,
        dst: SocketAddr,
    ) -> Result<(), CoreErr> {
        let mut sealed = link
            .state
            .tx
            .lock()
            .unwrap()
            .seal(0x02, PacketBuf::from_slice(&[]))?;
        let mut hdr = [0u8; 5];
        hdr[0] = kind;
        hdr[1..5].copy_from_slice(&peer_tag(self.local_key.public_key()));
        sealed.prepend_header(&hdr);
        self.transport
            .send_to(sealed.as_slice(), dst)
            .await
            .map_err(|e| CoreErr::Carrier(e.to_string()))?;
        Ok(())
    }

    /// Performs Blind Rendezvous discovery + simultaneous hole-punching to `target`.
    /// Returns the direct `Arc<P2pPeerLink>` on success, or `TargetUnreachable`
    /// (e.g. Symmetric NAT) while retaining decrypted `DiscoveredPeer` (including
    /// Home Relay info!) for `SmartPathSource` fallback.
    pub async fn punch_peer(&self, target: PublicKey) -> Result<Arc<P2pPeerLink>, CoreErr> {
        if let Some(existing) = self.peers.lock().unwrap().get(&target).cloned()
            && existing.state.confirmed.load(Ordering::Acquire)
        {
            return Ok(existing);
        }
        let info = self.query_peer(target).await?;
        let (link, _) = self.get_or_create_peer_link(target, info.public_addr);

        let puncher = {
            let this = self.clone();
            let link = link.clone();
            let dst = info.public_addr;
            tokio::spawn(async move {
                for _ in 0..16 {
                    if link.state.confirmed.load(Ordering::Acquire) {
                        break;
                    }
                    let _ = this.send_punch(&link, P2P_FRAME_PING, dst).await;
                    tokio::time::sleep(Duration::from_millis(40)).await;
                }
            })
        };

        let waited = tokio::time::timeout(self.punch_timeout, async {
            while !link.state.confirmed.load(Ordering::Acquire) {
                link.state.confirmed_notify.notified().await;
            }
        })
        .await;
        puncher.abort();

        if waited.is_ok() && link.state.confirmed.load(Ordering::Acquire) {
            Ok(link)
        } else {
            Err(CoreErr::TargetUnreachable)
        }
    }
}

/// Implements `DatagramChannel` where `locator` is the 32-byte `PublicKey` of the
/// target peer to discover & hole-punch via Blind Rendezvous.
impl DatagramChannel for UdpP2pNode {
    type Link = Arc<P2pPeerLink>;

    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(self.inner_mtu, false)
    }

    async fn open_link(&self, locator: &[u8]) -> Result<Arc<P2pPeerLink>, ChannelErr> {
        if locator.len() != 32 {
            return Err(CoreErr::Malformed);
        }
        let target = PublicKey(locator.try_into().unwrap());
        self.punch_peer(target).await
    }
}
