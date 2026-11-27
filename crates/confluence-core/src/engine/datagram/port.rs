//! Datagram link multiplexing (`DatagramPort`, `Binding`, `PortRegistry`, `PortSlot`,
//! `SetupReplies`, `hold_for_cookie_retry`, Spec §5.6, §6.2, §6.5, §8.2).
//!
//! Strictly acyclic: NEVER imports `engine::admission` (hands off inbound setups through
//! the [`DatagramSetupHandler`] trait implemented by `engine::datagram::inbound`).

use core::future::{Future, poll_fn};
use core::task::Poll;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};

use crate::constants::{
    CLOSE_SEND_TIMEOUT, DATAGRAM_MAILBOX_CAP, FWD_HEADER, MAX_SEGMENT, SETUP_TIMEOUT,
};
use crate::crypto::cookie::CookieDecision;
use crate::engine::context::{
    Either, NodePendingGate, NodePendingPermit, PendingPermit, ScopeCore, ScopeResolver, race2,
    sleep_optional, with_deadline,
};
use crate::error::CoreError;
use crate::packet::PacketBuf;
use crate::protocol::fragment::{
    FeedOutcome, FragmentBurst, FragmentReassembler, FragmentReceipt, OpeningVerdict,
    PreparedFlight,
};
use crate::protocol::slab::SlabTable;
use crate::runtime::sync::{CloseableSemaphore, SemaphorePermit, Watch, WatchReceiver};
use crate::runtime::{Clock, MonotonicTime, TaskSpawner};
use crate::seam::channel::{
    AdmissionAttempt, AdmissionTracker, DatagramIngress, DatagramLink, DatagramLinkExt, MtuWatch,
};
use crate::stats::{NodeMetrics, ScopeMetrics, should_warn_pow2};
use crate::types::{Cid, LinkId, Plane, ScopeKid};
use crate::wire::opcodes::outer;
use crate::wire::setup::{
    ForwardHeader, ParsedSegment, SetupCookieFrame, SetupFragAck, route_cid,
};

fn lock_unpoisoned<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn read_unpoisoned<T>(rw: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    rw.read().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_unpoisoned<T>(rw: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    rw.write().unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Acyclic Setup Handoff Trait (implemented by `datagram::inbound`)
// ---------------------------------------------------------------------------

/// Decouples [`DatagramPort`] packet pumping from inbound setup admission (`datagram::inbound`).
pub(crate) trait DatagramSetupHandler: Send + Sync + 'static {
    #[allow(clippy::too_many_arguments)]
    fn spawn_setup(
        &self,
        scope: Arc<ScopeCore>,
        port: Arc<DatagramPort>,
        wire: Vec<u8>,
        receipt: Option<FragmentReceipt>,
        attempt: AdmissionAttempt,
        pending_permit: PendingPermit,
        node_pending_permit: Option<NodePendingPermit>,
    );
}

// ---------------------------------------------------------------------------
// PortPermit & Metric Accounting
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) enum PortMetricOwner {
    Scope(Arc<ScopeMetrics>),
    Node(Arc<NodeMetrics>),
}

impl PortMetricOwner {
    fn inc_ports(&self) {
        match self {
            Self::Scope(m) => {
                m.active_datagram_ports.fetch_add(1, Ordering::Relaxed);
            }
            Self::Node(m) => {
                m.active_datagram_ports.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn dec_ports(&self) {
        match self {
            Self::Scope(m) => {
                m.active_datagram_ports.fetch_sub(1, Ordering::Relaxed);
            }
            Self::Node(m) => {
                m.active_datagram_ports.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    fn record_capacity_drop(&self) {
        let count = match self {
            Self::Scope(m) => m.record_capacity_drop(),
            Self::Node(m) => m
                .capacity_drops_total
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1),
        };
        if should_warn_pow2(count) {
            tracing::warn!(
                count,
                error = CoreError::Busy.static_code(),
                "datagram port capacity saturated"
            );
        }
    }
}

pub(crate) struct PortPermit {
    owner: PortMetricOwner,
    _permit: SemaphorePermit,
}

impl PortPermit {
    fn acquire(sem: &Arc<CloseableSemaphore>, owner: &PortMetricOwner) -> Result<Self, CoreError> {
        match sem.try_acquire() {
            Ok(permit) => {
                owner.inc_ports();
                Ok(Self {
                    owner: owner.clone(),
                    _permit: permit,
                })
            }
            Err(CoreError::Busy) => {
                owner.record_capacity_drop();
                Err(CoreError::Busy)
            }
            Err(err) => Err(err),
        }
    }
}

impl Drop for PortPermit {
    fn drop(&mut self) {
        self.owner.dec_ports();
    }
}

// ---------------------------------------------------------------------------
// DatagramPort & Per-Circuit Mailbox Entry
// ---------------------------------------------------------------------------

struct MailboxEntry {
    tx: async_channel::Sender<PacketBuf>,
    metrics: Option<Arc<ScopeMetrics>>,
}

struct PortRouting {
    node_wide: bool,
    scopes: HashMap<ScopeKid, Arc<ScopeCore>>,
    resolver: Arc<dyn ScopeResolver>,
    setup_handler: Arc<dyn DatagramSetupHandler>,
    owner: Weak<PortRegistry>,
    node_pending: Option<Arc<NodePendingGate>>,
}

/// Shared per-`DatagramLink` multiplexer owning one generational [`SlabTable`] (`4096` cap),
/// one [`FragmentReassembler`], one [`AdmissionTracker`], and one background receive pump.
pub(crate) struct DatagramPort {
    link: Arc<dyn DatagramLink>,
    link_id: LinkId,
    clock: Arc<dyn Clock>,
    slab: Mutex<SlabTable<MailboxEntry>>,
    reassembler: Arc<Mutex<FragmentReassembler>>,
    admission: Arc<AdmissionTracker>,
    closed_tx: Watch<Option<CoreError>>,
    has_inbound: AtomicBool,
    outbound_refs: AtomicUsize,
    stop_tx: Watch<bool>,
    routing: RwLock<PortRouting>,
    port_permit: Mutex<Option<PortPermit>>,
}

/// RAII keep-alive reference for outbound-only [`DatagramPort`] usage (bindings and cookie-retry holds).
pub(crate) struct OutboundPortHold {
    port: Arc<DatagramPort>,
}

impl Drop for OutboundPortHold {
    fn drop(&mut self) {
        let prev = self.port.outbound_refs.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 && !self.port.has_inbound.load(Ordering::Acquire) {
            self.port.stop_tx.send(true);
        }
    }
}

impl DatagramPort {
    /// Returns the link's current live effective MTU.
    pub fn mtu(&self) -> u16 {
        self.link.current_mtu()
    }

    /// Returns a cloned live [`MtuWatch`] for this link.
    pub fn mtu_watch(&self) -> MtuWatch {
        self.link.caps().mtu_watch()
    }

    /// Returns this link's 16-byte peer source tag for flood-cookie binding.
    pub fn source_tag(&self) -> [u8; 16] {
        self.link.source_tag()
    }

    /// Creates a [`DatagramIngress`] lifecycle handle observing this port's admission and closure.
    pub fn ingress(&self) -> DatagramIngress {
        DatagramIngress::new(Arc::clone(&self.admission), self.closed_tx.subscribe())
    }

    /// Returns the currently owning [`PortRegistry`], if still alive.
    pub fn owner_registry(&self) -> Option<Arc<PortRegistry>> {
        read_unpoisoned(&self.routing).owner.upgrade()
    }

    /// Acquires an RAII keep-alive hold on this port.
    pub fn acquire_outbound_hold(self: &Arc<Self>) -> OutboundPortHold {
        self.outbound_refs.fetch_add(1, Ordering::AcqRel);
        OutboundPortHold {
            port: Arc::clone(self),
        }
    }

    /// Allocates a unique bound [`Cid`] and 32-slot circuit mailbox on this port's [`SlabTable`].
    pub fn bind(
        self: &Arc<Self>,
        metrics: Option<Arc<ScopeMetrics>>,
    ) -> Result<Binding, CoreError> {
        if self.closed_tx.borrow_cloned().is_some() {
            return Err(CoreError::Closed);
        }
        let hold = self.acquire_outbound_hold();
        let (tx, rx) = async_channel::bounded::<PacketBuf>(DATAGRAM_MAILBOX_CAP);
        let cid = {
            let mut slab = lock_unpoisoned(&self.slab);
            slab.insert(MailboxEntry { tx, metrics }, self.clock.now())?
        };
        Ok(Binding {
            port: Arc::clone(self),
            cid,
            rx,
            _hold: hold,
        })
    }

    /// Best-effort bounded send (`50 ms`) directly on the underlying link.
    pub async fn send_best_effort(&self, packet: PacketBuf) {
        let deadline = self.clock.now().saturating_add(CLOSE_SEND_TIMEOUT);
        let _ = with_deadline(&*self.clock, deadline, self.link.send(packet)).await;
    }

    /// Resolves `kid` according to this port's explicit scope list / `node_wide` policy.
    fn resolve_scope_for_setup(&self, kid: ScopeKid) -> Option<Arc<ScopeCore>> {
        let routing = read_unpoisoned(&self.routing);
        if routing.node_wide {
            routing.resolver.resolve(kid)
        } else {
            routing.scopes.get(&kid).cloned()
        }
    }

    fn record_unknown_scope(&self) {
        read_unpoisoned(&self.routing).resolver.record_unknown_scope();
    }

    fn record_mac1_drop(&self, matched: Option<&ScopeCore>) {
        read_unpoisoned(&self.routing)
            .resolver
            .record_mac1_drop(matched);
    }

    /// Background receive pump driving O(1) CID dispatch, fragment reassembly, and setup handoff.
    async fn run_pump(self: Arc<Self>) {
        let mut stop_rx = self.stop_tx.subscribe();
        let close_reason = loop {
            if !self.has_inbound.load(Ordering::Acquire)
                && self.outbound_refs.load(Ordering::Acquire) == 0
                && self.try_retire_if_idle()
            {
                break CoreError::Closed;
            }
            let pkt = match race2(self.link.recv(), wait_stop(&mut stop_rx)).await {
                Either::Left(Ok(p)) => p,
                Either::Left(Err(err)) => break err,
                Either::Right(()) => {
                    if self.try_retire_if_idle() {
                        break CoreError::Closed;
                    }
                    self.stop_tx.send(false);
                    stop_rx.mark_seen();
                    continue;
                }
            };
            self.dispatch_inbound_packet(pkt);
        };

        // Remove ourselves from current owner registry (only if pointer matches).
        if let Some(reg) = self.owner_registry() {
            reg.remove_if_same(self.link_id, &self);
        }

        // Clear all circuit mailboxes so active sessions/transits immediately observe closure.
        {
            let mut slab = lock_unpoisoned(&self.slab);
            *slab = SlabTable::new();
        }

        self.closed_tx.send(Some(close_reason));
        let _ = lock_unpoisoned(&self.port_permit).take();
    }

    /// Atomically removes this port from its owner registry iff still idle (`!has_inbound && outbound_refs == 0`).
    fn try_retire_if_idle(self: &Arc<Self>) -> bool {
        let Some(reg) = self.owner_registry() else {
            return !self.has_inbound.load(Ordering::Acquire)
                && self.outbound_refs.load(Ordering::Acquire) == 0;
        };
        let mut map = lock_unpoisoned(&reg.ports);
        if self.has_inbound.load(Ordering::Acquire) || self.outbound_refs.load(Ordering::Acquire) > 0
        {
            return false;
        }
        if map
            .get(&self.link_id)
            .is_some_and(|existing| Arc::ptr_eq(existing, self))
        {
            map.remove(&self.link_id);
        }
        true
    }

    fn dispatch_inbound_packet(self: &Arc<Self>, pkt: PacketBuf) {
        let bytes = pkt.payload();
        let Some(cid) = route_cid(bytes) else {
            return;
        };

        if !cid.is_unbound() {
            // O(1) SlabTable lookup & non-blocking 32-slot mailbox enqueue (Spec §6.2).
            let send_res = {
                let slab = lock_unpoisoned(&self.slab);
                slab.get(cid).map(|entry| (entry.tx.clone(), entry.metrics.clone()))
            };
            if let Some((tx, metrics)) = send_res {
                if let Err(async_channel::TrySendError::Full(_)) = tx.try_send(pkt) {
                    if let Some(m) = metrics {
                        m.queue_drops_total.fetch_add(1, Ordering::Relaxed);
                        m.datagram_mailbox_drops_total
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            return;
        }

        // Cid::UNBOUND: SETUP_FWD (0x11) or SETUP_FRAG (0x15).
        let Some(&op) = bytes.first() else {
            return;
        };
        match op {
            outer::SETUP_FRAG => self.handle_setup_frag(bytes),
            outer::SETUP_FWD => self.handle_setup_fwd(bytes, None),
            _ => {}
        }
    }

    fn handle_setup_frag(self: &Arc<Self>, packet: &[u8]) {
        let now = self.clock.now();
        let source_tag = self.link.source_tag();
        let outcome = {
            let mut reasm = lock_unpoisoned(&self.reassembler);
            reasm.feed(packet, now, |kid, seg, has_mac2| {
                let Some(scope) = self.resolve_scope_for_setup(kid) else {
                    self.record_unknown_scope();
                    return OpeningVerdict::DropMac1;
                };
                if scope.pending.is_closed() {
                    return OpeningVerdict::NotAccepting;
                }
                let _ = scope.update_load();
                match scope.cookies.verify_segment(&source_tag, seg, has_mac2, now) {
                    CookieDecision::Drop => {
                        self.record_mac1_drop(Some(&scope));
                        OpeningVerdict::DropMac1
                    }
                    CookieDecision::Challenge(challenge) => {
                        scope
                            .metrics
                            .mac2_challenges_total
                            .fetch_add(1, Ordering::Relaxed);
                        OpeningVerdict::Challenge(challenge)
                    }
                    CookieDecision::Verified(_) => OpeningVerdict::Verified,
                }
            })
        };

        match outcome {
            FeedOutcome::Ignore | FeedOutcome::NeedMore | FeedOutcome::DropMac1 => {}
            FeedOutcome::ReAck(ack) => {
                let _ = self.link.try_send(PacketBuf::from_payload(&ack.encode()));
            }
            FeedOutcome::Challenge {
                upstream_cid,
                challenge,
            } => {
                let frame = SetupCookieFrame {
                    distance: 0,
                    target_cid: upstream_cid,
                    challenge,
                }
                .encode();
                let _ = self.link.try_send(PacketBuf::from_payload(&frame));
            }
            FeedOutcome::Complete { wire, key } => {
                let receipt = FragmentReceipt::new(Arc::clone(&self.reassembler), key);
                self.handle_setup_fwd(&wire, Some(receipt));
            }
        }
    }

    fn handle_setup_fwd(
        self: &Arc<Self>,
        wire: &[u8],
        receipt: Option<FragmentReceipt>,
    ) {
        // Zero-allocation pre-validation on `&[u8]` before allocating `Vec<u8>` or spawning!
        let Ok(hdr) = ForwardHeader::parse(wire) else {
            return;
        };
        if hdr.upstream.is_unbound() {
            return;
        }
        let Ok(seg) = ParsedSegment::parse_full(&wire[FWD_HEADER..]) else {
            return;
        };
        if seg.prefix.plane != Plane::Datagram || seg.encrypted.len() > MAX_SEGMENT {
            return;
        }
        let Some(scope) = self.resolve_scope_for_setup(seg.scope_kid()) else {
            self.record_unknown_scope();
            return;
        };
        if !scope
            .cookies
            .verify_mac1_only(seg.encrypted, seg.prefix.has_mac2)
        {
            self.record_mac1_drop(Some(&scope));
            return;
        }

        // Track AdmissionAttempt (Idle/Rejected -> Pending; sticky Admitted unaffected).
        let attempt = self.admission.begin_attempt();

        let (setup_handler, node_pending_gate) = {
            let r = read_unpoisoned(&self.routing);
            (Arc::clone(&r.setup_handler), r.node_pending.clone())
        };

        let node_pending_permit = match node_pending_gate {
            Some(ref gate) => match gate.try_acquire() {
                Ok(p) => Some(p),
                Err(_) => return,
            },
            None => None,
        };

        let Ok(pending_permit) = scope.try_acquire_pending() else {
            return;
        };

        setup_handler.spawn_setup(
            scope,
            Arc::clone(self),
            wire.to_vec(),
            receipt,
            attempt,
            pending_permit,
            node_pending_permit,
        );
    }
}

async fn wait_stop(rx: &mut WatchReceiver<bool>) {
    loop {
        if rx.borrow_cloned() {
            return;
        }
        if !rx.changed().await {
            if rx.borrow_cloned() {
                return;
            }
            core::future::pending::<()>().await;
        }
    }
}

// ---------------------------------------------------------------------------
// Binding RAII Guard
// ---------------------------------------------------------------------------

/// RAII circuit CID binding on a [`DatagramPort`] with a 32-slot inbound mailbox.
pub(crate) struct Binding {
    port: Arc<DatagramPort>,
    cid: Cid,
    rx: async_channel::Receiver<PacketBuf>,
    _hold: OutboundPortHold,
}

impl Binding {
    #[must_use]
    pub const fn cid(&self) -> Cid {
        self.cid
    }

    #[must_use]
    pub fn mtu(&self) -> u16 {
        self.port.mtu()
    }

    #[must_use]
    pub fn mtu_watch(&self) -> MtuWatch {
        self.port.mtu_watch()
    }

    pub async fn recv(&self) -> Result<PacketBuf, CoreError> {
        self.rx.recv().await.map_err(|_| CoreError::Closed)
    }

    pub fn send_now(&self, packet: PacketBuf) -> Result<(), CoreError> {
        self.port.link.try_send(packet)
    }

    pub async fn send_wait(&self, packet: PacketBuf) -> Result<(), CoreError> {
        self.port.link.send(packet).await
    }

    pub async fn send_best_effort(&self, packet: PacketBuf) {
        self.port.send_best_effort(packet).await;
    }
}

impl Drop for Binding {
    fn drop(&mut self) {
        let mut slab = lock_unpoisoned(&self.port.slab);
        let _ = slab.remove(self.cid, self.port.clock.now());
    }
}

// ---------------------------------------------------------------------------
// hold_for_cookie_retry (Spec §6.2 Datagram Step 4)
// ---------------------------------------------------------------------------

/// Retains an outbound [`DatagramPort`] alive for `SETUP_TIMEOUT` (`3 s`) after forwarding
/// a `SETUP_COOKIE` upstream so the link's `source_tag` remains stable across Origin's retry.
pub(crate) fn hold_for_cookie_retry(
    port: Arc<DatagramPort>,
    clock: Arc<dyn Clock>,
    spawner: &dyn TaskSpawner,
) {
    let hold = port.acquire_outbound_hold();
    spawner.spawn(Box::pin(async move {
        clock.sleep(SETUP_TIMEOUT).await;
        drop(hold);
    }));
}

// ---------------------------------------------------------------------------
// SetupReplies — Auto-Fragmenting Datagram Setup Sender/Receiver (Spec §5.6 & §6.1)
// ---------------------------------------------------------------------------

/// Sends a datagram `SETUP_FWD` flight (automatically fragmenting into `2..=8` `SETUP_FRAG`
/// packets if `wire.len() > binding.mtu()`), drives `[150, 300, 600]` ms burst retries until
/// `SETUP_FRAG_ACK`, and yields raw candidate setup reply packets for caller verification.
pub(crate) struct SetupReplies<'a> {
    binding: &'a Binding,
    clock: &'a dyn Clock,
    burst: Option<FragmentBurst>,
    next_retry: Option<MonotonicTime>,
}

impl<'a> SetupReplies<'a> {
    pub fn send(
        binding: &'a Binding,
        wire: &[u8],
        clock: &'a dyn Clock,
    ) -> Result<Self, CoreError> {
        let prepared = FragmentBurst::prepare(wire, binding.mtu(), binding.cid())?;
        match prepared {
            PreparedFlight::Single(pkt) => {
                send_ignoring_would_block(binding, pkt)?;
                Ok(Self {
                    binding,
                    clock,
                    burst: None,
                    next_retry: None,
                })
            }
            PreparedFlight::Fragmented(burst) => {
                for frame in burst.frames() {
                    send_ignoring_would_block(binding, frame.clone())?;
                }
                let next_retry = burst.next_retry_deadline(clock.now());
                Ok(Self {
                    binding,
                    clock,
                    burst: Some(burst),
                    next_retry,
                })
            }
        }
    }

    /// Waits for the next non-`SETUP_FRAG_ACK` packet on `binding` within `deadline`,
    /// automatically retransmitting unacknowledged fragment bursts along `[150, 300, 600]` ms.
    pub async fn next_reply(&mut self, deadline: MonotonicTime) -> Result<PacketBuf, CoreError> {
        loop {
            if self.clock.now() >= deadline {
                return Err(CoreError::Timeout);
            }

            let retry_at = self.next_retry;
            enum Ev {
                Recv(Result<PacketBuf, CoreError>),
                Retry,
                Deadline,
            }

            let ev = {
                let mut recv_fut = Box::pin(self.binding.recv());
                let mut retry_fut = Box::pin(sleep_optional(self.clock, retry_at));
                let mut dl_fut = Box::pin(self.clock.sleep_until(deadline));
                poll_fn(|cx| {
                    if let Poll::Ready(res) = recv_fut.as_mut().poll(cx) {
                        return Poll::Ready(Ev::Recv(res));
                    }
                    if let Poll::Ready(()) = dl_fut.as_mut().poll(cx) {
                        return Poll::Ready(Ev::Deadline);
                    }
                    if let Poll::Ready(()) = retry_fut.as_mut().poll(cx) {
                        return Poll::Ready(Ev::Retry);
                    }
                    Poll::Pending
                })
                .await
            };

            match ev {
                Ev::Deadline => return Err(CoreError::Timeout),
                Ev::Retry => {
                    if let Some(ref mut burst) = self.burst {
                        if !burst.is_acked() {
                            for frame in burst.frames() {
                                send_ignoring_would_block(self.binding, frame.clone())?;
                            }
                            burst.mark_retry_sent();
                            self.next_retry = burst.next_retry_deadline(self.clock.now());
                        } else {
                            self.next_retry = None;
                        }
                    } else {
                        self.next_retry = None;
                    }
                }
                Ev::Recv(Err(err)) => return Err(err),
                Ev::Recv(Ok(pkt)) => {
                    if pkt.payload().first() == Some(&outer::SETUP_FRAG_ACK) {
                        if let (Some(burst), Ok(ack)) =
                            (self.burst.as_mut(), SetupFragAck::parse(pkt.payload()))
                        {
                            if burst.on_ack(&ack) {
                                self.next_retry = None;
                            }
                        }
                        continue;
                    }
                    return Ok(pkt);
                }
            }
        }
    }
}

fn send_ignoring_would_block(binding: &Binding, pkt: PacketBuf) -> Result<(), CoreError> {
    match binding.send_now(pkt) {
        Ok(()) | Err(CoreError::WouldBlock) => Ok(()),
        Err(err) => Err(err),
    }
}

// ---------------------------------------------------------------------------
// PortRegistry & PortSlot (Deduplication & Atomic Node Adoption, Spec §8.2)
// ---------------------------------------------------------------------------

/// Registry deduplicating active [`DatagramPort`]s by [`LinkId`] (Lock Level 2).
pub(crate) struct PortRegistry {
    ports: Mutex<HashMap<LinkId, Arc<DatagramPort>>>,
    port_sem: Arc<CloseableSemaphore>,
    metric_owner: PortMetricOwner,
    clock: Arc<dyn Clock>,
    spawner: Arc<dyn TaskSpawner>,
    resolver: Arc<dyn ScopeResolver>,
    setup_handler: Arc<dyn DatagramSetupHandler>,
    node_pending: Option<Arc<NodePendingGate>>,
}

impl PortRegistry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        max_ports: usize,
        metric_owner: PortMetricOwner,
        clock: Arc<dyn Clock>,
        spawner: Arc<dyn TaskSpawner>,
        resolver: Arc<dyn ScopeResolver>,
        setup_handler: Arc<dyn DatagramSetupHandler>,
        node_pending: Option<Arc<NodePendingGate>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            ports: Mutex::new(HashMap::new()),
            port_sem: CloseableSemaphore::new(max_ports.max(1)),
            metric_owner,
            clock,
            spawner,
            resolver,
            setup_handler,
            node_pending,
        })
    }

    /// Attaches an inbound `DatagramLink` (deduplicating by `LinkId` into one `DatagramPort`/`SlabTable`).
    pub fn attach_inbound(
        self: &Arc<Self>,
        link: Arc<dyn DatagramLink>,
        scope: Option<Arc<ScopeCore>>,
        node_wide: bool,
    ) -> Result<DatagramIngress, CoreError> {
        let link_id = link.link_id();
        let mut map = lock_unpoisoned(&self.ports);

        if let Some(existing) = map.get(&link_id) {
            existing.has_inbound.store(true, Ordering::Release);
            {
                let mut routing = write_unpoisoned(&existing.routing);
                if node_wide {
                    routing.node_wide = true;
                }
                if let Some(sc) = scope {
                    routing.scopes.insert(sc.keypair.scope_kid(), sc);
                }
            }
            return Ok(existing.ingress());
        }

        let permit = PortPermit::acquire(&self.port_sem, &self.metric_owner)?;
        let mut scopes = HashMap::new();
        if let Some(sc) = scope {
            scopes.insert(sc.keypair.scope_kid(), sc);
        }

        let (closed_tx, _) = Watch::new(None::<CoreError>);
        let (stop_tx, _) = Watch::new(false);
        let port = Arc::new(DatagramPort {
            link,
            link_id,
            clock: Arc::clone(&self.clock),
            slab: Mutex::new(SlabTable::new()),
            reassembler: Arc::new(Mutex::new(FragmentReassembler::new())),
            admission: Arc::new(AdmissionTracker::new()),
            closed_tx,
            has_inbound: AtomicBool::new(true),
            outbound_refs: AtomicUsize::new(0),
            stop_tx,
            routing: RwLock::new(PortRouting {
                node_wide,
                scopes,
                resolver: Arc::clone(&self.resolver),
                setup_handler: Arc::clone(&self.setup_handler),
                owner: Arc::downgrade(self),
                node_pending: self.node_pending.clone(),
            }),
            port_permit: Mutex::new(Some(permit)),
        });
        let ingress = port.ingress();
        map.insert(link_id, Arc::clone(&port));
        drop(map);

        self.spawner.spawn(Box::pin(port.run_pump()));
        Ok(ingress)
    }

    /// Attaches an outbound `DatagramLink` (sharing an existing `DatagramPort` if `LinkId` matches).
    pub fn attach_outbound(
        self: &Arc<Self>,
        link: Arc<dyn DatagramLink>,
    ) -> Result<(Arc<DatagramPort>, OutboundPortHold), CoreError> {
        let link_id = link.link_id();
        let mut map = lock_unpoisoned(&self.ports);

        if let Some(existing) = map.get(&link_id) {
            let hold = existing.acquire_outbound_hold();
            return Ok((Arc::clone(existing), hold));
        }

        let permit = PortPermit::acquire(&self.port_sem, &self.metric_owner)?;
        let (closed_tx, _) = Watch::new(None::<CoreError>);
        let (stop_tx, _) = Watch::new(false);
        let port = Arc::new(DatagramPort {
            link,
            link_id,
            clock: Arc::clone(&self.clock),
            slab: Mutex::new(SlabTable::new()),
            reassembler: Arc::new(Mutex::new(FragmentReassembler::new())),
            admission: Arc::new(AdmissionTracker::new()),
            closed_tx,
            has_inbound: AtomicBool::new(false),
            outbound_refs: AtomicUsize::new(0),
            stop_tx,
            routing: RwLock::new(PortRouting {
                node_wide: false,
                scopes: HashMap::new(),
                resolver: Arc::clone(&self.resolver),
                setup_handler: Arc::clone(&self.setup_handler),
                owner: Arc::downgrade(self),
                node_pending: self.node_pending.clone(),
            }),
            port_permit: Mutex::new(Some(permit)),
        });
        let hold = port.acquire_outbound_hold();
        map.insert(link_id, Arc::clone(&port));
        drop(map);

        self.spawner.spawn(Box::pin(Arc::clone(&port).run_pump()));
        Ok((port, hold))
    }

    fn remove_if_same(&self, link_id: LinkId, target: &Arc<DatagramPort>) {
        let mut map = lock_unpoisoned(&self.ports);
        if map
            .get(&link_id)
            .is_some_and(|existing| Arc::ptr_eq(existing, target))
        {
            map.remove(&link_id);
        }
    }

    /// Atomically adopts all live ports from a standalone scope's `PortRegistry` into `self`
    /// (`Node`'s `PortRegistry`, Spec §8.2 Rule 4).
    ///
    /// Validates BOTH non-conflicting `LinkId`s (`AlreadyPublished`) and `max_datagram_ports`
    /// capacity (`Busy`) BEFORE mutating either registry, ensuring zero partial mutation on error.
    pub fn adopt_from(self: &Arc<Self>, source: &PortRegistry) -> Result<(), CoreError> {
        // Lock order: Node's `self.ports` FIRST, then standalone `source.ports` SECOND.
        let mut dst = lock_unpoisoned(&self.ports);
        let mut src = lock_unpoisoned(&source.ports);

        if src.is_empty() {
            return Ok(());
        }

        // Step 1: Check for conflicting LinkIds (Spec §8.2 Rule 4 -> AlreadyPublished).
        for link_id in src.keys() {
            if dst.contains_key(link_id) {
                return Err(CoreError::AlreadyPublished);
            }
        }

        // Step 2: Atomically acquire all required node port permits BEFORE moving any port.
        let mut new_permits = Vec::with_capacity(src.len());
        for _ in 0..src.len() {
            match PortPermit::acquire(&self.port_sem, &self.metric_owner) {
                Ok(p) => new_permits.push(p),
                Err(err) => {
                    // Roll back all acquired permits automatically on drop; ZERO mutation!
                    drop(new_permits);
                    return Err(err);
                }
            }
        }

        // Step 3: Commit adoption (cannot fail!).
        for ((link_id, port), new_permit) in src.drain().zip(new_permits) {
            {
                let mut routing = write_unpoisoned(&port.routing);
                // Adopted ports keep `node_wide = false` and their explicit scope list!
                routing.node_wide = false;
                routing.resolver = Arc::clone(&self.resolver);
                routing.setup_handler = Arc::clone(&self.setup_handler);
                routing.owner = Arc::downgrade(self);
                routing.node_pending = self.node_pending.clone();
            }
            {
                // Replace scope PortPermit with node PortPermit (transfers active_datagram_ports count!).
                let mut slot = lock_unpoisoned(&port.port_permit);
                *slot = Some(new_permit);
            }
            dst.insert(link_id, port);
        }

        Ok(())
    }

    /// Removes `kid` from every port's explicit scope list (called by `Node::remove_scope`, Spec §8.2).
    pub fn detach_scope(&self, kid: ScopeKid) {
        let map = lock_unpoisoned(&self.ports);
        for port in map.values() {
            let mut routing = write_unpoisoned(&port.routing);
            routing.scopes.remove(&kid);
        }
    }
}

/// Indirection slot pointing to a scope's currently active [`PortRegistry`]
/// (its own standalone registry when unmounted, or its hosting `Node`'s registry when mounted).
pub(crate) struct PortSlot {
    standalone: Arc<PortRegistry>,
    current: RwLock<Arc<PortRegistry>>,
}

impl PortSlot {
    pub fn new(standalone: Arc<PortRegistry>) -> Arc<Self> {
        Arc::new(Self {
            current: RwLock::new(Arc::clone(&standalone)),
            standalone,
        })
    }

    pub fn current(&self) -> Arc<PortRegistry> {
        Arc::clone(&read_unpoisoned(&self.current))
    }

    pub fn standalone(&self) -> &Arc<PortRegistry> {
        &self.standalone
    }

    pub fn switch_to(&self, target: Arc<PortRegistry>) {
        *write_unpoisoned(&self.current) = target;
    }

    pub fn restore_standalone(&self) {
        *write_unpoisoned(&self.current) = Arc::clone(&self.standalone);
    }
}
