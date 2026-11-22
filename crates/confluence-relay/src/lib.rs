//! Out-of-core, zero-dialing Passive Relay plugin.
//!
//! Structurally incapable of outbound network dialing, with zero protocol support required inside
//! `confluence-core`:
//! - [`PassiveRelay`] provides the pure in-process passive presence store implementing
//!   [`StreamChannel`], [`DatagramChannel`], [`StreamTransitHandler`], and
//!   [`DatagramTransitHandler`].
//! - [`RelayService`] and [`RelayMux`] add authenticated single-port transport multiplexing
//!   (`RELAY_REG_REQ = 0x52` / `RELAY_REG_RESP = 0x53` / `RELAY_WAKE_BYTE = 0x57`) over any
//!   existing TCP/UDP or in-memory listener, cleanly separated from `confluence-core` wire frames.
//! - [`RelayClientDatagramLink`], [`register_datagram_presence`], and [`PassiveStreamPool`]
//!   provide NAT-side registration, live keepalives, and auto-replenishing parked stream pools.

#![forbid(unsafe_code)]

use confluence_core::{
    AsyncStream, BoxFut, ChannelCaps, CoreErr, DATAGRAM_MTU, DatagramChannel, DatagramLink,
    DatagramLinkExt, DatagramListener, DatagramTransitHandler, DynAsyncStream, IntoDynDatagramLink,
    LinkId, Node, PacketBuf, Plane, PublicKey, RejoinedStream, ScopeInstance, ScopeKeypair,
    SessionAuth, StreamChannel, StreamListener, StreamRead, StreamTransitHandler, StreamWriteExt,
    WeakScope,
    crypto::{
        noise_ik::{self, REPLY_LEN, Responder, parse_target, target_plaintext},
        replay::SetupReplay,
    },
    read_exact,
    wire::setup,
};
use confluence_net::{CustomUdpAttachment, TcpCarrier, TcpListenerSource, UdpIngress};
use parking_lot::Mutex;
use std::{
    collections::{HashMap, VecDeque},
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::TcpListener,
    sync::{Mutex as AsyncMutex, Semaphore, mpsc, oneshot, watch},
};

const MAX_PRESENCES: usize = 4096;
const MAX_IDLE_STREAMS: usize = 32;
const MAX_REG_PAYLOAD: usize = 4096;
const REG_HEADER_LEN: usize = 8;
const REG_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CONCURRENT_PEEK: usize = 256;
const LINK_CORE_QUEUE: usize = 64;

/// Out-of-core transport magic byte identifying an authenticated passive relay registration request.
/// Disjoint from all `confluence-core` wire frame kinds (`0x11`–`0x14`, `0x20`–`0x24`, `0x30`–`0x33`).
pub const RELAY_REG_REQ: u8 = 0x52;
/// Out-of-core transport magic byte identifying a passive relay registration response.
pub const RELAY_REG_RESP: u8 = 0x53;
/// Single byte written onto a parked stream by [`RelayService`] when an originator attaches.
pub const RELAY_WAKE_BYTE: u8 = 0x57;

type Streams = HashMap<Vec<u8>, VecDeque<Box<dyn DynAsyncStream>>>;
type Datagrams = HashMap<Vec<u8>, Arc<PresenceLink<Arc<dyn DatagramLink>>>>;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn relay_reg_aad(relay_pubkey: PublicKey) -> [u8; 32] {
    blake3::derive_key("confluence-v1-relay-register", &relay_pubkey.0)
}

fn validate(id: &[u8]) -> Result<(), CoreErr> {
    if id.is_empty() || id.len() > 255 {
        Err(CoreErr::Malformed)
    } else {
        Ok(())
    }
}

fn encode_reg_req(req_id: u32, seg: &[u8]) -> Result<Vec<u8>, CoreErr> {
    if seg.len() > MAX_REG_PAYLOAD {
        return Err(CoreErr::Malformed);
    }
    let mut out = Vec::with_capacity(REG_HEADER_LEN + seg.len());
    out.push(RELAY_REG_REQ);
    out.push(0);
    out.extend_from_slice(&(seg.len() as u16).to_be_bytes());
    out.extend_from_slice(&req_id.to_be_bytes());
    out.extend_from_slice(seg);
    Ok(out)
}

fn parse_reg_req(wire: &[u8]) -> Result<(u32, &[u8]), CoreErr> {
    if wire.len() < REG_HEADER_LEN || wire[0] != RELAY_REG_REQ || wire[1] != 0 {
        return Err(CoreErr::Malformed);
    }
    let len = u16::from_be_bytes([wire[2], wire[3]]) as usize;
    if len > MAX_REG_PAYLOAD || wire.len() != REG_HEADER_LEN + len {
        return Err(CoreErr::Malformed);
    }
    let req_id = u32::from_be_bytes([wire[4], wire[5], wire[6], wire[7]]);
    Ok((req_id, &wire[REG_HEADER_LEN..]))
}

fn encode_reg_resp(req_id: u32, status: u8, body: &[u8]) -> Result<Vec<u8>, CoreErr> {
    if body.len() > MAX_REG_PAYLOAD {
        return Err(CoreErr::Malformed);
    }
    let mut out = Vec::with_capacity(REG_HEADER_LEN + body.len());
    out.push(RELAY_REG_RESP);
    out.push(status);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&req_id.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

fn parse_reg_resp(wire: &[u8]) -> Result<(u8, u32, &[u8]), CoreErr> {
    if wire.len() < REG_HEADER_LEN || wire[0] != RELAY_REG_RESP {
        return Err(CoreErr::Malformed);
    }
    let status = wire[1];
    let len = u16::from_be_bytes([wire[2], wire[3]]) as usize;
    if len > MAX_REG_PAYLOAD || wire.len() != REG_HEADER_LEN + len {
        return Err(CoreErr::Malformed);
    }
    let req_id = u32::from_be_bytes([wire[4], wire[5], wire[6], wire[7]]);
    Ok((status, req_id, &wire[REG_HEADER_LEN..]))
}

// ============================================================================
// Pure in-process PassiveRelay store
// ============================================================================

/// Pure passive presence registry that only selects already-connected streams and datagram links.
///
/// Structurally incapable of outbound network dialing. Implements both pure channels
/// ([`StreamChannel`] / [`DatagramChannel`]) and named transit handlers
/// ([`StreamTransitHandler`] / [`DatagramTransitHandler`]) so it can be published directly on a
/// [`ScopeInstance`] via `publish_stream_transit_prefix` / `publish_datagram_transit_prefix`.
#[derive(Clone)]
pub struct PassiveRelay {
    streams: Arc<Mutex<Streams>>,
    datagrams: Arc<Mutex<Datagrams>>,
    datagram_mtu: u16,
    stream_mtu: u16,
}

/// RAII handle removing a registered datagram presence link when dropped.
pub struct DatagramPresence {
    id: Vec<u8>,
    links: Weak<Mutex<Datagrams>>,
    _registered: watch::Sender<()>,
}

impl Drop for DatagramPresence {
    fn drop(&mut self) {
        if let Some(links) = self.links.upgrade() {
            links.lock().remove(&self.id);
        }
    }
}

impl PassiveRelay {
    pub fn new(stream_mtu: u16, datagram_mtu: u16) -> Result<Self, CoreErr> {
        if datagram_mtu < DATAGRAM_MTU {
            return Err(CoreErr::MtuTooSmall(datagram_mtu));
        }
        Ok(Self {
            streams: Default::default(),
            datagrams: Default::default(),
            datagram_mtu,
            stream_mtu,
        })
    }

    /// Registers one pre-established stream, consumed by one circuit.
    pub fn register_stream<S: AsyncStream>(&self, id: &[u8], stream: S) -> Result<(), CoreErr> {
        validate(id)?;
        let mut streams = self.streams.lock();
        if streams.len() >= MAX_PRESENCES && !streams.contains_key(id) {
            return Err(CoreErr::Busy);
        }
        let queue = streams.entry(id.into()).or_default();
        if queue.len() >= MAX_IDLE_STREAMS {
            return Err(CoreErr::Busy);
        }
        queue.push_back(stream.into_dyn_stream());
        Ok(())
    }

    /// Removes all parked streams for `id`.
    pub fn remove_stream_presence(&self, id: &[u8]) {
        self.streams.lock().remove(id);
    }

    /// Registers an already-connected datagram link under `id`, returning an RAII guard.
    pub fn register_datagram<L: IntoDynDatagramLink>(
        &self,
        id: &[u8],
        link: L,
    ) -> Result<DatagramPresence, CoreErr> {
        validate(id)?;
        let mut datagrams = self.datagrams.lock();
        if datagrams.contains_key(id) {
            return Err(CoreErr::AlreadyPublished);
        }
        if datagrams.len() >= MAX_PRESENCES {
            return Err(CoreErr::Busy);
        }
        let (registration, released) = watch::channel(());
        datagrams.insert(
            id.into(),
            Arc::new(PresenceLink::new(link.into_dyn_link(), released)),
        );
        Ok(DatagramPresence {
            id: id.into(),
            links: Arc::downgrade(&self.datagrams),
            _registered: registration,
        })
    }

    /// Number of currently registered datagram presence slots.
    pub fn datagram_presence_count(&self) -> usize {
        self.datagrams.lock().len()
    }

    /// Number of currently parked streams for `id`.
    pub fn parked_stream_count(&self, id: &[u8]) -> usize {
        self.streams.lock().get(id).map_or(0, VecDeque::len)
    }
}

impl StreamChannel for PassiveRelay {
    type Stream = Box<dyn DynAsyncStream>;

    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(self.stream_mtu, true)
    }

    async fn dial_stream(&self, locator: &[u8]) -> Result<Box<dyn DynAsyncStream>, CoreErr> {
        let mut streams = self.streams.lock();
        let queue = streams.get_mut(locator).ok_or(CoreErr::TargetUnreachable)?;
        let stream = queue.pop_front().ok_or(CoreErr::TargetUnreachable)?;
        if queue.is_empty() {
            streams.remove(locator);
        }
        Ok(stream)
    }
}

impl DatagramChannel for PassiveRelay {
    type Link = Arc<PresenceLink<Arc<dyn DatagramLink>>>;

    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(self.datagram_mtu, false)
    }

    async fn open_link(&self, locator: &[u8]) -> Result<Self::Link, CoreErr> {
        self.datagrams
            .lock()
            .get(locator)
            .cloned()
            .ok_or(CoreErr::TargetUnreachable)
    }
}

impl StreamTransitHandler for PassiveRelay {
    type Stream = Box<dyn DynAsyncStream>;

    fn caps(&self) -> ChannelCaps {
        <Self as StreamChannel>::caps(self)
    }

    async fn open(&self, target: &str, _auth: SessionAuth) -> Result<Self::Stream, CoreErr> {
        self.dial_stream(target.as_bytes()).await
    }
}

impl DatagramTransitHandler for PassiveRelay {
    type Link = Arc<PresenceLink<Arc<dyn DatagramLink>>>;

    fn caps(&self) -> ChannelCaps {
        <Self as DatagramChannel>::caps(self)
    }

    async fn open(&self, target: &str, _auth: SessionAuth) -> Result<Self::Link, CoreErr> {
        self.open_link(target.as_bytes()).await
    }
}

/// Transparent revocation-aware presence link proxy preserving the underlying link's `link_id()`.
pub struct PresenceLink<L> {
    link: L,
    released: watch::Receiver<()>,
    recv_release_wait: Mutex<BoxFut<'static, ()>>,
    send_release_wait: Mutex<BoxFut<'static, ()>>,
}

impl<L> PresenceLink<L> {
    fn new(link: L, released: watch::Receiver<()>) -> Self {
        let mut r1 = released.clone();
        let mut r2 = released.clone();
        Self {
            link,
            released,
            recv_release_wait: Mutex::new(Box::pin(async move {
                let _ = r1.changed().await;
            })),
            send_release_wait: Mutex::new(Box::pin(async move {
                let _ = r2.changed().await;
            })),
        }
    }

    fn is_released(&self) -> bool {
        self.released.has_changed().unwrap_or(true)
    }
}

impl<L: DatagramLink> DatagramLink for PresenceLink<L> {
    fn caps(&self) -> ChannelCaps {
        self.link.caps()
    }

    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), CoreErr>> {
        if self.is_released() || self.send_release_wait.lock().as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(CoreErr::Closed));
        }
        self.link.poll_send_ready(cx)
    }

    fn try_send(&self, packet: PacketBuf) -> Result<(), CoreErr> {
        if self.is_released() {
            return Err(CoreErr::Closed);
        }
        self.link.try_send(packet)
    }

    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<PacketBuf, CoreErr>> {
        if self.is_released() || self.recv_release_wait.lock().as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(CoreErr::Closed));
        }
        self.link.poll_recv(cx)
    }

    fn source_tag(&self) -> [u8; 16] {
        self.link.source_tag()
    }

    fn link_id(&self) -> LinkId {
        self.link.link_id()
    }
}

// ============================================================================
// Registration Verification (out-of-core)
// ============================================================================

/// Inbound passive-relay presence registration request presented by a NATed peer.
#[derive(Clone, Copy, Debug)]
pub struct RelayRegistrationRequest<'a> {
    /// Cryptographically authenticated static public key of the registering peer.
    pub peer: PublicKey,
    /// Logical presence name requested by the peer (e.g., `"bob-slot"`).
    pub presence_id: &'a str,
    /// Plane being registered (`Plane::Stream` or `Plane::Datagram`).
    pub plane: Plane,
    /// Opaque caller-supplied registration credential.
    pub credential: &'a [u8],
}

/// Authorized lease for a registered passive presence slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistrationLease {
    pub ttl: Duration,
}

impl RegistrationLease {
    pub const fn new(ttl: Duration) -> Self {
        Self { ttl }
    }
}

/// Out-of-core verifier deciding which NATed peers may register which presence IDs on a
/// [`RelayService`].
///
/// Separate from `confluence-core`'s [`confluence_core::Authorizer`], which independently decides
/// which originators may transit through the published transit name (e.g., `"relay/bob-slot"`).
pub trait RelayRegistrationVerifier: Send + Sync + 'static {
    fn verify<'a>(
        &'a self,
        req: RelayRegistrationRequest<'a>,
    ) -> BoxFut<'a, Result<RegistrationLease, CoreErr>>;
}

/// Permits any authenticated peer to register any presence ID for `ttl`.
#[derive(Clone, Copy, Debug)]
pub struct AllowAllRegistrations(pub Duration);

impl RelayRegistrationVerifier for AllowAllRegistrations {
    fn verify<'a>(
        &'a self,
        _req: RelayRegistrationRequest<'a>,
    ) -> BoxFut<'a, Result<RegistrationLease, CoreErr>> {
        let ttl = self.0;
        Box::pin(async move { Ok(RegistrationLease::new(ttl)) })
    }
}

/// Closure-backed [`RelayRegistrationVerifier`] for custom or test policies.
pub struct FnRegistrationVerifier<F>(pub F);

impl<F> RelayRegistrationVerifier for FnRegistrationVerifier<F>
where
    F: Fn(RelayRegistrationRequest<'_>) -> Result<RegistrationLease, CoreErr>
        + Send
        + Sync
        + 'static,
{
    fn verify<'a>(
        &'a self,
        req: RelayRegistrationRequest<'a>,
    ) -> BoxFut<'a, Result<RegistrationLease, CoreErr>> {
        let res = (self.0)(req);
        Box::pin(async move { res })
    }
}

/// Declarative registration rule for [`StaticRegistrationRules`].
#[derive(Clone, Debug)]
pub struct RegistrationRule {
    /// Allowed peer hex public keys, or `"*"` for any peer.
    pub peers: Vec<String>,
    /// Optional presence pattern (`"*"` or `"prefix*"`).
    pub presence: Option<String>,
    /// Optional plane restriction.
    pub plane: Option<Plane>,
    /// Optional required UTF-8 credential.
    pub required_credential: Option<String>,
    /// Registration TTL.
    pub ttl: Duration,
}

/// Rule-list [`RelayRegistrationVerifier`] denying by default.
#[derive(Clone, Debug, Default)]
pub struct StaticRegistrationRules {
    rules: Vec<RegistrationRule>,
}

impl StaticRegistrationRules {
    pub fn new(rules: Vec<RegistrationRule>) -> Self {
        Self { rules }
    }
}

fn pattern_matches(pattern: &str, actual: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        actual.starts_with(prefix)
    } else {
        pattern == actual
    }
}

impl RelayRegistrationVerifier for StaticRegistrationRules {
    fn verify<'a>(
        &'a self,
        req: RelayRegistrationRequest<'a>,
    ) -> BoxFut<'a, Result<RegistrationLease, CoreErr>> {
        let peer_hex = req.peer.to_string();
        let matched = self.rules.iter().find(|r| {
            let peer_ok = r.peers.iter().any(|p| p == "*" || p == &peer_hex);
            let plane_ok = r.plane.is_none_or(|p| p == req.plane);
            let pres_ok = r
                .presence
                .as_deref()
                .is_none_or(|pat| pattern_matches(pat, req.presence_id));
            let cred_ok = r
                .required_credential
                .as_deref()
                .is_none_or(|c| req.credential == c.as_bytes());
            peer_ok && plane_ok && pres_ok && cred_ok
        });
        let res = matched
            .map(|r| RegistrationLease::new(r.ttl))
            .ok_or(CoreErr::Denied);
        Box::pin(async move { res })
    }
}

// ============================================================================
// Single-port RelayService & RelayMux
// ============================================================================

struct DatagramSlot {
    link: Arc<dyn DatagramLink>,
    registrant: PublicKey,
    expires_at: Instant,
    _guard: watch::Sender<()>,
}

struct StreamSlot {
    registrant: PublicKey,
    expires_at: Instant,
}

/// Out-of-core single-port Passive Relay service.
///
/// Publish it on a [`ScopeInstance`] as a named transit (exact or prefix, e.g. `"relay/"`) and
/// wrap the node's TCP/UDP or in-memory listeners with [`RelayService::wrap_stream_listener`],
/// [`RelayService::wrap_datagram_listener`], [`RelayService::serve_udp`], or [`RelayMux`].
///
/// - Inbound originator transits authenticate normally through `confluence-core` (`Authorizer`,
///   `MAC2` flood cookies, Noise_IK, live lease renewal).
/// - Inbound NATed presence registrations (`0x52` / `0x53`) are intercepted on the transport layer
///   before reaching `confluence-core` and verified by [`RelayRegistrationVerifier`].
#[derive(Clone)]
pub struct RelayService {
    inner: Arc<RelayServiceInner>,
}

struct RelayServiceInner {
    relay: PassiveRelay,
    identity: Arc<ScopeKeypair>,
    replay: SetupReplay,
    verifier: Arc<dyn RelayRegistrationVerifier>,
    scope: WeakScope,
    transit_prefix: String,
    datagram_slots: Mutex<HashMap<String, DatagramSlot>>,
    stream_slots: Mutex<HashMap<String, StreamSlot>>,
}

impl RelayService {
    /// Creates a [`RelayService`] bound to `scope`'s identity keypair.
    ///
    /// `transit_prefix` is the prefix under which this service will be published on `scope`
    /// (e.g., `"relay/"`, or `""` if published under exact names) so revocations can immediately
    /// tear down active transit circuits on `scope`.
    pub fn new(
        scope: &ScopeInstance,
        transit_prefix: impl Into<String>,
        verifier: Arc<dyn RelayRegistrationVerifier>,
        stream_mtu: u16,
        datagram_mtu: u16,
    ) -> Result<Self, CoreErr> {
        Ok(Self {
            inner: Arc::new(RelayServiceInner {
                relay: PassiveRelay::new(stream_mtu, datagram_mtu)?,
                identity: scope.identity(),
                replay: SetupReplay::default(),
                verifier,
                scope: scope.downgrade(),
                transit_prefix: transit_prefix.into(),
                datagram_slots: Default::default(),
                stream_slots: Default::default(),
            }),
        })
    }

    /// Returns the relay's public key used by NATed peers to authenticate registrations.
    pub fn public_key(&self) -> PublicKey {
        self.inner.identity.public_key()
    }

    /// Returns access to the underlying [`PassiveRelay`] storage for inspection or raw registration.
    pub fn relay(&self) -> &PassiveRelay {
        &self.inner.relay
    }

    /// Number of currently active single-port datagram presence slots.
    pub fn active_datagram_slots(&self) -> usize {
        self.inner.datagram_slots.lock().len()
    }

    /// Immediately removes `presence_id` and tears down all active transit circuits targeting it.
    pub fn remove_presence(&self, presence_id: &str) {
        self.inner.datagram_slots.lock().remove(presence_id);
        self.inner.stream_slots.lock().remove(presence_id);
        self.inner
            .relay
            .remove_stream_presence(presence_id.as_bytes());
        self.revoke_presence_circuits(presence_id);
    }

    /// Immediately removes all presences registered by `registrant` and tears down active circuits.
    pub fn revoke_registrant(&self, registrant: &PublicKey) {
        let mut names = Vec::new();
        {
            let mut slots = self.inner.datagram_slots.lock();
            slots.retain(|name, slot| {
                if slot.registrant == *registrant {
                    names.push(name.clone());
                    false
                } else {
                    true
                }
            });
        }
        {
            let mut slots = self.inner.stream_slots.lock();
            slots.retain(|name, slot| {
                if slot.registrant == *registrant {
                    self.inner.relay.remove_stream_presence(name.as_bytes());
                    names.push(name.clone());
                    false
                } else {
                    true
                }
            });
        }
        for name in names {
            self.revoke_presence_circuits(&name);
        }
    }

    fn revoke_presence_circuits(&self, presence_id: &str) {
        if let Some(scope) = self.inner.scope.upgrade() {
            let full = format!("{}{}", self.inner.transit_prefix, presence_id);
            scope.revoke_transit(&full);
        }
    }

    fn precheck_segment(&self, seg: &[u8]) -> bool {
        self.inner.identity.verify_mac1(seg)
    }

    /// Fast stack-only front-door check verifying whether `wire` is a valid `RELAY_REG_REQ`
    /// carrying a valid `MAC1` addressed to this relay's public key.
    pub fn precheck_datagram_register(&self, wire: &[u8]) -> bool {
        parse_reg_req(wire).is_ok_and(|(_, seg)| self.precheck_segment(seg))
    }

    async fn admit_registration(
        &self,
        seg: &[u8],
        plane: Plane,
    ) -> Result<(String, PublicKey, Duration, [u8; REPLY_LEN]), CoreErr> {
        let aad = relay_reg_aad(self.inner.identity.public_key());
        let opened = Responder::accept(
            &self.inner.identity,
            &self.inner.replay,
            seg,
            &aad,
            now_ms(),
        )?;
        let peer = opened.peer;
        let (presence_id, credential) = {
            let (id, cred) = parse_target(&opened.plaintext)?;
            validate(id.as_bytes())?;
            (id.to_owned(), cred.to_vec())
        };
        if let Some(scope) = self.inner.scope.upgrade()
            && scope.auth_gate().is_vetoed(&peer)
        {
            return Err(CoreErr::Revoked);
        }
        let lease = self
            .inner
            .verifier
            .verify(RelayRegistrationRequest {
                peer,
                presence_id: &presence_id,
                plane,
                credential: &credential,
            })
            .await?;
        if lease.ttl.is_zero() {
            return Err(CoreErr::Denied);
        }
        let mtu = match plane {
            Plane::Stream => self.inner.relay.stream_mtu,
            Plane::Datagram => self.inner.relay.datagram_mtu,
        };
        let mut ack = [0u8; 10];
        ack[..2].copy_from_slice(&mtu.to_be_bytes());
        ack[2..10].copy_from_slice(&(lease.ttl.as_millis() as u64).to_be_bytes());
        let (reply, _keys) = opened.reply(&ack)?;
        Ok((presence_id, peer, lease.ttl, reply))
    }

    async fn handle_stream_registration(
        &self,
        stream: Box<dyn DynAsyncStream>,
        req_id: u32,
        seg: &[u8],
    ) -> Result<(), CoreErr> {
        let caps = stream.caps();
        let source_tag = stream.source_tag();
        let (reader, mut writer) = stream.split();
        let (presence_id, registrant, ttl, reply) =
            match self.admit_registration(seg, Plane::Stream).await {
                Ok(ok) => ok,
                Err(err) => {
                    if let Ok(resp) = encode_reg_resp(req_id, 1, &[]) {
                        let _ = writer.write_all(&resp).await;
                    }
                    return Err(err);
                }
            };
        let resp = encode_reg_resp(req_id, 0, &reply)?;
        writer.write_all(&resp).await?;
        let expires_at = Instant::now() + ttl;
        self.inner.stream_slots.lock().insert(
            presence_id.clone(),
            StreamSlot {
                registrant,
                expires_at,
            },
        );
        self.inner.relay.register_stream(
            presence_id.as_bytes(),
            RejoinedStream {
                caps,
                source_tag,
                reader,
                writer,
            },
        )
    }

    async fn handle_datagram_registration(
        &self,
        mux_link: Arc<dyn DatagramLink>,
        seg: &[u8],
    ) -> Result<[u8; REPLY_LEN], CoreErr> {
        let (presence_id, registrant, ttl, reply) =
            self.admit_registration(seg, Plane::Datagram).await?;
        let expires_at = Instant::now() + ttl;
        let (guard, released) = watch::channel(());
        let wrapped: Arc<dyn DatagramLink> = Arc::new(PresenceLink::new(mux_link, released));
        let mut slots = self.inner.datagram_slots.lock();
        if slots.len() >= MAX_PRESENCES && !slots.contains_key(&presence_id) {
            return Err(CoreErr::Busy);
        }
        slots.insert(
            presence_id,
            DatagramSlot {
                link: wrapped,
                registrant,
                expires_at,
                _guard: guard,
            },
        );
        Ok(reply)
    }

    /// Wraps any [`StreamListener`] to handle out-of-core `0x52` registrations while passing all
    /// normal `confluence-core` streams through unchanged.
    pub fn wrap_stream_listener<L: StreamListener>(&self, listener: L) -> RelayStreamListener {
        RelayMux::new(vec![self.clone()]).wrap_stream_listener(listener)
    }

    /// Wraps any [`DatagramListener`] to handle out-of-core `0x52` registrations while passing all
    /// normal `confluence-core` datagram links through unchanged.
    pub fn wrap_datagram_listener<L: DatagramListener>(
        &self,
        listener: L,
    ) -> RelayDatagramListener<L> {
        RelayMux::new(vec![self.clone()]).wrap_datagram_listener(listener)
    }

    /// Serves a bound TCP listener for both this relay's registrations and `scope`'s Core traffic.
    pub async fn serve_tcp(
        &self,
        listener: TcpListener,
        scope: ScopeInstance,
        carrier: TcpCarrier,
    ) -> Result<(), CoreErr> {
        RelayMux::new(vec![self.clone()])
            .serve_tcp(listener, scope, carrier)
            .await
    }

    /// Serves a bound UDP ingress for both this relay's registrations and `scope`'s Core traffic.
    pub async fn serve_udp(
        &self,
        ingress: UdpIngress,
        scope: ScopeInstance,
    ) -> Result<(), CoreErr> {
        RelayMux::new(vec![self.clone()])
            .serve_udp(ingress, scope)
            .await
    }
}

impl StreamTransitHandler for RelayService {
    type Stream = Box<dyn DynAsyncStream>;

    fn caps(&self) -> ChannelCaps {
        <PassiveRelay as StreamChannel>::caps(&self.inner.relay)
    }

    async fn open(&self, target: &str, _auth: SessionAuth) -> Result<Self::Stream, CoreErr> {
        let is_registered_slot = {
            let mut slots = self.inner.stream_slots.lock();
            if let Some(slot) = slots.get(target) {
                let vetoed = self
                    .inner
                    .scope
                    .upgrade()
                    .is_some_and(|s| s.auth_gate().is_vetoed(&slot.registrant));
                if Instant::now() >= slot.expires_at || vetoed {
                    slots.remove(target);
                    self.inner.relay.remove_stream_presence(target.as_bytes());
                    return Err(CoreErr::TargetUnreachable);
                }
                true
            } else {
                false
            }
        };
        let stream = self.inner.relay.dial_stream(target.as_bytes()).await?;
        if !is_registered_slot {
            return Ok(stream);
        }
        let caps = stream.caps();
        let source_tag = stream.source_tag();
        let (reader, mut writer) = stream.split();
        writer.write_all(&[RELAY_WAKE_BYTE]).await?;
        Ok(RejoinedStream {
            caps,
            source_tag,
            reader,
            writer,
        }
        .into_dyn_stream())
    }
}

impl DatagramTransitHandler for RelayService {
    type Link = Arc<dyn DatagramLink>;

    fn caps(&self) -> ChannelCaps {
        <PassiveRelay as DatagramChannel>::caps(&self.inner.relay)
    }

    async fn open(&self, target: &str, _auth: SessionAuth) -> Result<Self::Link, CoreErr> {
        let found = {
            let mut slots = self.inner.datagram_slots.lock();
            if let Some(slot) = slots.get(target) {
                let vetoed = self
                    .inner
                    .scope
                    .upgrade()
                    .is_some_and(|s| s.auth_gate().is_vetoed(&slot.registrant));
                if Instant::now() >= slot.expires_at || vetoed {
                    slots.remove(target);
                    return Err(CoreErr::TargetUnreachable);
                }
                Some(slot.link.clone())
            } else {
                None
            }
        };
        if let Some(link) = found {
            return Ok(link);
        }
        Ok(self
            .inner
            .relay
            .open_link(target.as_bytes())
            .await?
            .into_dyn_link())
    }
}

/// Multi-service single-port multiplexer allowing one or more [`RelayService`] instances (e.g.,
/// across multiple isolated scopes on a single [`Node`]) to share one TCP and/or UDP port.
#[derive(Clone, Default)]
pub struct RelayMux {
    services: Arc<Vec<RelayService>>,
}

impl RelayMux {
    pub fn new(services: Vec<RelayService>) -> Self {
        Self {
            services: Arc::new(services),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    fn find_for_segment(&self, seg: &[u8]) -> Option<RelayService> {
        self.services
            .iter()
            .find(|svc| svc.precheck_segment(seg))
            .cloned()
    }

    /// Stack-only precheck returning `true` if `wire` is a valid `RELAY_REG_REQ` addressed to any
    /// mounted [`RelayService`].
    pub fn precheck_datagram_register(&self, wire: &[u8]) -> bool {
        parse_reg_req(wire).is_ok_and(|(_, seg)| self.find_for_segment(seg).is_some())
    }

    /// Wraps any [`StreamListener`], intercepting `RELAY_REG_REQ` streams for the matching
    /// [`RelayService`] and yielding all other streams (with their first byte preserved) to Core.
    pub fn wrap_stream_listener<L: StreamListener>(&self, listener: L) -> RelayStreamListener {
        let (core_tx, core_rx) = mpsc::channel(MAX_CONCURRENT_PEEK);
        let (stop, mut stop_rx) = watch::channel(false);
        let services = self.clone();
        let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_PEEK));
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = stop_rx.changed() => break,
                    res = listener.accept() => res,
                };
                let Ok(stream) = accepted else {
                    break;
                };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    continue;
                };
                let services = services.clone();
                let core_tx = core_tx.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let dyn_stream = stream.into_dyn_stream();
                    let caps = dyn_stream.caps();
                    let source_tag = dyn_stream.source_tag();
                    let (mut reader, mut writer) = dyn_stream.split();
                    let mut first = [0u8; 1];
                    if !matches!(
                        tokio::time::timeout(REG_TIMEOUT, read_exact(&mut reader, &mut first))
                            .await,
                        Ok(Ok(()))
                    ) {
                        return;
                    }
                    if first[0] != RELAY_REG_REQ {
                        let prefixed = RejoinedStream {
                            caps,
                            source_tag,
                            reader: PrefixedRead {
                                first: Some(first[0]),
                                inner: reader,
                            },
                            writer,
                        }
                        .into_dyn_stream();
                        let _ = core_tx.send(prefixed).await;
                        return;
                    }
                    let mut rest = [0u8; REG_HEADER_LEN - 1];
                    if !matches!(
                        tokio::time::timeout(REG_TIMEOUT, read_exact(&mut reader, &mut rest)).await,
                        Ok(Ok(()))
                    ) {
                        return;
                    }
                    if rest[0] != 0 {
                        return;
                    }
                    let len = u16::from_be_bytes([rest[1], rest[2]]) as usize;
                    if len > MAX_REG_PAYLOAD {
                        return;
                    }
                    let req_id = u32::from_be_bytes([rest[3], rest[4], rest[5], rest[6]]);
                    let mut seg = vec![0u8; len];
                    if !matches!(
                        tokio::time::timeout(REG_TIMEOUT, read_exact(&mut reader, &mut seg)).await,
                        Ok(Ok(()))
                    ) {
                        return;
                    }
                    let Some(svc) = services.find_for_segment(&seg) else {
                        if let Ok(resp) = encode_reg_resp(req_id, 1, &[]) {
                            let _ = writer.write_all(&resp).await;
                        }
                        return;
                    };
                    let rejoined = RejoinedStream {
                        caps,
                        source_tag,
                        reader,
                        writer,
                    }
                    .into_dyn_stream();
                    let _ = svc.handle_stream_registration(rejoined, req_id, &seg).await;
                });
            }
        });
        RelayStreamListener {
            core_rx: AsyncMutex::new(core_rx),
            stop,
        }
    }

    /// Wraps an inbound [`DatagramLink`], returning a multiplexed link for Core and an
    /// `extra_admitted` flag flipped to `true` upon any verified `RELAY_REG_REQ` on this link.
    pub fn wrap_datagram_link<L: IntoDynDatagramLink>(
        &self,
        link: L,
    ) -> (Arc<RelayServerDatagramLink>, Arc<AtomicBool>) {
        let inner = link.into_dyn_link();
        let extra_admitted = Arc::new(AtomicBool::new(false));
        let (core_tx, core_rx) = mpsc::channel(LINK_CORE_QUEUE);
        let mux_link = Arc::new(RelayServerDatagramLink {
            inner: inner.clone(),
            id: LinkId::allocate(),
            core_rx: Mutex::new(core_rx),
        });
        let weak_link = Arc::downgrade(&mux_link);
        let services = self.clone();
        let admitted = extra_admitted.clone();
        tokio::spawn(async move {
            loop {
                let pkt = tokio::select! {
                    _ = core_tx.closed() => break,
                    res = inner.recv() => match res {
                        Ok(pkt) => pkt,
                        Err(_) => break,
                    }
                };
                if pkt.as_slice().first() == Some(&RELAY_REG_REQ) {
                    if let Ok((req_id, seg)) = parse_reg_req(pkt.as_slice()) {
                        let resp = match services.find_for_segment(seg) {
                            Some(svc) => {
                                if let Some(link_arc) = weak_link.upgrade() {
                                    let dyn_link: Arc<dyn DatagramLink> = link_arc;
                                    match svc.handle_datagram_registration(dyn_link, seg).await {
                                        Ok(reply) => {
                                            admitted.store(true, Ordering::Release);
                                            encode_reg_resp(req_id, 0, &reply)
                                        }
                                        Err(_) => encode_reg_resp(req_id, 1, &[]),
                                    }
                                } else {
                                    break;
                                }
                            }
                            None => encode_reg_resp(req_id, 1, &[]),
                        };
                        if let Ok(resp) = resp {
                            let _ = inner.send(PacketBuf::from_slice(&resp)).await;
                        }
                    }
                    continue;
                }
                let _ = core_tx.try_send(pkt);
            }
        });
        (mux_link, extra_admitted)
    }

    /// Wraps any [`DatagramListener`] so accepted links transparently handle `RELAY_REG_REQ`.
    pub fn wrap_datagram_listener<L: DatagramListener>(
        &self,
        listener: L,
    ) -> RelayDatagramListener<L> {
        RelayDatagramListener {
            inner: listener,
            mux: self.clone(),
        }
    }

    /// Serves a bound TCP listener for both relay registrations and a single [`ScopeInstance`].
    pub async fn serve_tcp(
        &self,
        listener: TcpListener,
        scope: ScopeInstance,
        carrier: TcpCarrier,
    ) -> Result<(), CoreErr> {
        let mux = self.wrap_stream_listener(TcpListenerSource::new(listener, carrier));
        scope.serve_stream_listener(&mux).await
    }

    /// Serves a bound TCP listener for both relay registrations and a multi-scope [`Node`].
    pub async fn serve_tcp_node(
        &self,
        listener: TcpListener,
        node: Node,
        carrier: TcpCarrier,
    ) -> Result<(), CoreErr> {
        let mux = self.wrap_stream_listener(TcpListenerSource::new(listener, carrier));
        node.serve_stream_listener(&mux).await
    }

    /// Serves a bound [`UdpIngress`] for both relay registrations and a single [`ScopeInstance`].
    pub async fn serve_udp(
        &self,
        ingress: UdpIngress,
        scope: ScopeInstance,
    ) -> Result<(), CoreErr> {
        let pre_scope = scope.clone();
        let pre_mux = self.clone();
        let attach_mux = self.clone();
        ingress
            .serve_custom(
                move |pkt| {
                    (pkt[0] == setup::FWD && pre_scope.precheck_datagram_setup(pkt))
                        || pre_mux.precheck_datagram_register(pkt)
                },
                move |link| {
                    let (mux_link, extra_admitted) = attach_mux.wrap_datagram_link(link);
                    Ok(CustomUdpAttachment {
                        ingress: scope.attach_datagram(mux_link)?,
                        extra_admitted: Some(extra_admitted),
                    })
                },
            )
            .await
    }

    /// Serves a bound [`UdpIngress`] for both relay registrations and a multi-scope [`Node`].
    pub async fn serve_udp_node(&self, ingress: UdpIngress, node: Node) -> Result<(), CoreErr> {
        let pre_node = node.clone();
        let pre_mux = self.clone();
        let attach_mux = self.clone();
        ingress
            .serve_custom(
                move |pkt| {
                    (pkt[0] == setup::FWD && pre_node.precheck_datagram_setup(pkt))
                        || pre_mux.precheck_datagram_register(pkt)
                },
                move |link| {
                    let (mux_link, extra_admitted) = attach_mux.wrap_datagram_link(link);
                    Ok(CustomUdpAttachment {
                        ingress: node.attach_datagram(mux_link)?,
                        extra_admitted: Some(extra_admitted),
                    })
                },
            )
            .await
    }
}

/// [`StreamRead`] prefixing one already-peeked byte back onto an underlying reader.
struct PrefixedRead<R> {
    first: Option<u8>,
    inner: R,
}

impl<R: StreamRead> StreamRead for PrefixedRead<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, CoreErr>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Some(byte) = self.first.take() {
            buf[0] = byte;
            return Poll::Ready(Ok(1));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

/// [`StreamListener`] produced by [`RelayService::wrap_stream_listener`] or [`RelayMux`].
pub struct RelayStreamListener {
    core_rx: AsyncMutex<mpsc::Receiver<Box<dyn DynAsyncStream>>>,
    stop: watch::Sender<bool>,
}

impl Drop for RelayStreamListener {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

impl StreamListener for RelayStreamListener {
    type Stream = Box<dyn DynAsyncStream>;

    async fn accept(&self) -> Result<Box<dyn DynAsyncStream>, CoreErr> {
        self.core_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(CoreErr::Closed)
    }
}

/// Server-side multiplexed [`DatagramLink`] intercepting `0x52` registrations while passing all
/// `confluence-core` packets cleanly to `DatagramPort`.
pub struct RelayServerDatagramLink {
    inner: Arc<dyn DatagramLink>,
    id: LinkId,
    core_rx: Mutex<mpsc::Receiver<PacketBuf>>,
}

impl DatagramLink for RelayServerDatagramLink {
    fn caps(&self) -> ChannelCaps {
        self.inner.caps()
    }

    fn current_mtu(&self) -> u16 {
        self.inner.current_mtu()
    }

    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), CoreErr>> {
        self.inner.poll_send_ready(cx)
    }

    fn try_send(&self, packet: PacketBuf) -> Result<(), CoreErr> {
        self.inner.try_send(packet)
    }

    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<PacketBuf, CoreErr>> {
        self.core_rx
            .lock()
            .poll_recv(cx)
            .map(|opt| opt.ok_or(CoreErr::Closed))
    }

    fn source_tag(&self) -> [u8; 16] {
        self.inner.source_tag()
    }

    fn link_id(&self) -> LinkId {
        self.id
    }
}

/// [`DatagramListener`] produced by [`RelayService::wrap_datagram_listener`] or [`RelayMux`].
pub struct RelayDatagramListener<L> {
    inner: L,
    mux: RelayMux,
}

impl<L: DatagramListener> DatagramListener for RelayDatagramListener<L> {
    type Link = Arc<RelayServerDatagramLink>;

    async fn accept_link(&self) -> Result<Self::Link, CoreErr> {
        let link = self.inner.accept_link().await?;
        Ok(self.mux.wrap_datagram_link(link).0)
    }
}

// ============================================================================
// NAT-side client helpers (Datagram registration & PassiveStreamPool)
// ============================================================================

type PendingReplies = Arc<Mutex<HashMap<u32, oneshot::Sender<(u8, Vec<u8>)>>>>;

/// NAT-side multiplexed [`DatagramLink`] supporting initial presence registration AND periodic
/// keepalive re-registrations while attached to a [`ScopeInstance`] or [`Node`].
pub struct RelayClientDatagramLink {
    inner: Arc<dyn DatagramLink>,
    id: LinkId,
    core_rx: Mutex<mpsc::Receiver<PacketBuf>>,
    pending: PendingReplies,
    next_req_id: AtomicU32,
}

impl RelayClientDatagramLink {
    /// Wraps an outbound link dialed to a relay's single UDP/datagram port.
    pub fn new<L: IntoDynDatagramLink>(link: L) -> Arc<Self> {
        let inner = link.into_dyn_link();
        let (core_tx, core_rx) = mpsc::channel(LINK_CORE_QUEUE);
        let pending: PendingReplies = Default::default();
        let reader_link = inner.clone();
        let reader_pending = pending.clone();
        tokio::spawn(async move {
            loop {
                let pkt = tokio::select! {
                    _ = core_tx.closed() => break,
                    res = reader_link.recv() => match res {
                        Ok(pkt) => pkt,
                        Err(_) => break,
                    }
                };
                if pkt.as_slice().first() == Some(&RELAY_REG_RESP) {
                    if let Ok((status, req_id, body)) = parse_reg_resp(pkt.as_slice())
                        && let Some(tx) = reader_pending.lock().remove(&req_id)
                    {
                        let _ = tx.send((status, body.to_vec()));
                    }
                    continue;
                }
                let _ = core_tx.try_send(pkt);
            }
        });
        Arc::new(Self {
            inner,
            id: LinkId::allocate(),
            core_rx: Mutex::new(core_rx),
            pending,
            next_req_id: AtomicU32::new(1),
        })
    }

    /// Authenticates and registers (or refreshes) `presence_id` on the remote [`RelayService`].
    /// Safe to call both before attaching this link to a scope and repeatedly as a live keepalive.
    pub async fn register_presence(
        &self,
        identity: &ScopeKeypair,
        relay_pubkey: PublicKey,
        presence_id: &str,
        credential: &[u8],
    ) -> Result<RegistrationLease, CoreErr> {
        validate(presence_id.as_bytes())?;
        let plain = target_plaintext(now_ms(), presence_id, credential)?;
        let aad = relay_reg_aad(relay_pubkey);
        let (seg, initiator) = noise_ik::initiate(identity, relay_pubkey, &aad, &plain)?;
        let req_id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        let frame = encode_reg_req(req_id, &seg)?;

        let (tx, rx) = oneshot::channel();
        self.pending.lock().insert(req_id, tx);
        if let Err(err) = self.inner.send(PacketBuf::from_slice(&frame)).await {
            self.pending.lock().remove(&req_id);
            return Err(err);
        }
        let (status, body) = match tokio::time::timeout(REG_TIMEOUT, rx).await {
            Ok(Ok(reply)) => reply,
            _ => {
                self.pending.lock().remove(&req_id);
                return Err(CoreErr::Timeout);
            }
        };
        if status != 0 {
            return Err(CoreErr::Denied);
        }
        let (ack, _keys) = initiator.finish(identity, &body)?;
        let ttl_ms = u64::from_be_bytes(ack[2..10].try_into().unwrap());
        Ok(RegistrationLease::new(Duration::from_millis(ttl_ms)))
    }
}

impl DatagramLink for RelayClientDatagramLink {
    fn caps(&self) -> ChannelCaps {
        self.inner.caps()
    }

    fn current_mtu(&self) -> u16 {
        self.inner.current_mtu()
    }

    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), CoreErr>> {
        self.inner.poll_send_ready(cx)
    }

    fn try_send(&self, packet: PacketBuf) -> Result<(), CoreErr> {
        self.inner.try_send(packet)
    }

    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<PacketBuf, CoreErr>> {
        self.core_rx
            .lock()
            .poll_recv(cx)
            .map(|opt| opt.ok_or(CoreErr::Closed))
    }

    fn source_tag(&self) -> [u8; 16] {
        self.inner.source_tag()
    }

    fn link_id(&self) -> LinkId {
        self.id
    }
}

/// One-shot helper registering a NATed destination's datagram presence link before attaching it to
/// a [`ScopeInstance`] or [`Node`].
///
/// For periodic keepalive re-registrations on an already-attached link, wrap the link in
/// [`RelayClientDatagramLink`] instead.
pub async fn register_datagram_presence<L: DatagramLink>(
    identity: &ScopeKeypair,
    link: &L,
    relay_pubkey: PublicKey,
    presence_id: &str,
    credential: &[u8],
) -> Result<RegistrationLease, CoreErr> {
    validate(presence_id.as_bytes())?;
    let plain = target_plaintext(now_ms(), presence_id, credential)?;
    let aad = relay_reg_aad(relay_pubkey);
    let (seg, initiator) = noise_ik::initiate(identity, relay_pubkey, &aad, &plain)?;
    let req_id = 1u32;
    let frame = encode_reg_req(req_id, &seg)?;
    link.send(PacketBuf::from_slice(&frame)).await?;

    let body = tokio::time::timeout(REG_TIMEOUT, async {
        loop {
            let pkt = link.recv().await?;
            if let Ok((status, rid, body)) = parse_reg_resp(pkt.as_slice())
                && rid == req_id
            {
                if status != 0 {
                    return Err(CoreErr::Denied);
                }
                return Ok(body.to_vec());
            }
        }
    })
    .await
    .map_err(|_| CoreErr::Timeout)??;

    let (ack, _keys) = initiator.finish(identity, &body)?;
    let ttl_ms = u64::from_be_bytes(ack[2..10].try_into().unwrap());
    Ok(RegistrationLease::new(Duration::from_millis(ttl_ms)))
}

/// NAT-side passive stream pool that parks `pool_size` outbound streams on a single-port
/// [`RelayService`], wakes them on [`RELAY_WAKE_BYTE`], auto-replenishes in the background,
/// and implements [`StreamListener`] for plug-and-play attachment to [`ScopeInstance`] or [`Node`].
pub struct PassiveStreamPool {
    activated: AsyncMutex<mpsc::Receiver<Box<dyn DynAsyncStream>>>,
    stop: watch::Sender<bool>,
}

impl PassiveStreamPool {
    /// Connects and parks `pool_size` initial streams on `relay_locator` via `carrier`.
    #[allow(clippy::too_many_arguments)]
    pub async fn start<C: StreamChannel>(
        carrier: Arc<C>,
        identity: Arc<ScopeKeypair>,
        relay_locator: Vec<u8>,
        relay_pubkey: PublicKey,
        presence_id: impl Into<String>,
        credential: Vec<u8>,
        pool_size: usize,
    ) -> Result<Arc<Self>, CoreErr> {
        let presence_id = presence_id.into();
        validate(presence_id.as_bytes())?;
        let pool_size = pool_size.clamp(1, MAX_IDLE_STREAMS);
        let (tx, rx) = mpsc::channel(pool_size * 2);
        let (stop, stop_rx) = watch::channel(false);

        for _ in 0..pool_size {
            let parked = park_one_stream(
                &carrier,
                &identity,
                &relay_locator,
                relay_pubkey,
                &presence_id,
                &credential,
            )
            .await?;
            spawn_parked_watcher(
                parked,
                carrier.clone(),
                identity.clone(),
                relay_locator.clone(),
                relay_pubkey,
                presence_id.clone(),
                credential.clone(),
                tx.clone(),
                stop_rx.clone(),
            );
        }

        Ok(Arc::new(Self {
            activated: AsyncMutex::new(rx),
            stop,
        }))
    }

    /// Stops parking new streams and shuts down idle watchers.
    pub fn close(&self) {
        let _ = self.stop.send(true);
    }
}

impl Drop for PassiveStreamPool {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

impl StreamListener for PassiveStreamPool {
    type Stream = Box<dyn DynAsyncStream>;

    async fn accept(&self) -> Result<Box<dyn DynAsyncStream>, CoreErr> {
        self.activated
            .lock()
            .await
            .recv()
            .await
            .ok_or(CoreErr::Closed)
    }
}

async fn park_one_stream<C: StreamChannel>(
    carrier: &Arc<C>,
    identity: &Arc<ScopeKeypair>,
    relay_locator: &[u8],
    relay_pubkey: PublicKey,
    presence_id: &str,
    credential: &[u8],
) -> Result<
    RejoinedStream<<C::Stream as AsyncStream>::Read, <C::Stream as AsyncStream>::Write>,
    CoreErr,
> {
    let stream = carrier.dial_stream(relay_locator).await?;
    let caps = stream.caps();
    let source_tag = stream.source_tag();
    let (mut reader, mut writer) = stream.split();

    let plain = target_plaintext(now_ms(), presence_id, credential)?;
    let aad = relay_reg_aad(relay_pubkey);
    let (seg, initiator) = noise_ik::initiate(identity, relay_pubkey, &aad, &plain)?;
    let frame = encode_reg_req(1, &seg)?;
    writer.write_all(&frame).await?;

    let mut hdr = [0u8; REG_HEADER_LEN];
    read_exact(&mut reader, &mut hdr).await?;
    if hdr[0] != RELAY_REG_RESP || hdr[1] != 0 {
        return Err(CoreErr::Denied);
    }
    let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    if len > MAX_REG_PAYLOAD {
        return Err(CoreErr::Malformed);
    }
    let mut body = vec![0u8; len];
    read_exact(&mut reader, &mut body).await?;
    let _ = initiator.finish(identity, &body)?;

    Ok(RejoinedStream {
        caps,
        source_tag,
        reader,
        writer,
    })
}

#[allow(clippy::too_many_arguments)]
fn spawn_parked_watcher<C: StreamChannel>(
    stream: RejoinedStream<<C::Stream as AsyncStream>::Read, <C::Stream as AsyncStream>::Write>,
    carrier: Arc<C>,
    identity: Arc<ScopeKeypair>,
    relay_locator: Vec<u8>,
    relay_pubkey: PublicKey,
    presence_id: String,
    credential: Vec<u8>,
    activated_tx: mpsc::Sender<Box<dyn DynAsyncStream>>,
    mut stop_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        if *stop_rx.borrow() {
            return;
        }
        let caps = stream.caps();
        let source_tag = stream.source_tag();
        let (mut reader, writer) = stream.split();
        let mut wake = [0u8; 1];
        tokio::select! {
            _ = stop_rx.changed() => {}
            res = read_exact(&mut reader, &mut wake) => {
                if res.is_ok() && wake[0] == RELAY_WAKE_BYTE {
                    let c2 = carrier.clone();
                    let id2 = identity.clone();
                    let loc2 = relay_locator.clone();
                    let pres2 = presence_id.clone();
                    let cred2 = credential.clone();
                    let tx2 = activated_tx.clone();
                    let stop2 = stop_rx.clone();
                    tokio::spawn(async move {
                        if !*stop2.borrow()
                            && let Ok(next) = park_one_stream(
                                &c2, &id2, &loc2, relay_pubkey, &pres2, &cred2,
                            ).await
                        {
                            spawn_parked_watcher(
                                next, c2, id2, loc2, relay_pubkey, pres2, cred2, tx2, stop2,
                            );
                        }
                    });
                    let _ = activated_tx.send(RejoinedStream {
                        caps,
                        source_tag,
                        reader,
                        writer,
                    }.into_dyn_stream()).await;
                }
            }
        }
    });
}
