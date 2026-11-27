//! Datagram link multiplexing (`DatagramPort`, `Binding`, `PortRegistry`, `PortSlot`,
//! `SetupReplies`, `hold_for_cookie_retry`, Spec §5.6, §6.2, §6.5, §8.2).
//!
//! Strictly acyclic: NEVER imports `engine::admission` (hands off inbound setups through
//! the [`DatagramSetupHandler`] trait implemented by `engine::datagram::inbound`).
//!
//! # Lock Hierarchy
//! - Level 1: `Node::membership` (in `host::node`)
//! - Level 1.5: `PortSlot::state`
//! - Level 2: `PortRegistry::inner` (in `adopt_from`: Node `dst` first, standalone `src` second)
//! - Level 2.5 (standalone leaf, NEVER nested with `inner`): `PortRegistry::prior_registries`
//! - Level 3: `DatagramPort::state`
//! - Level 4: `DatagramPort::slab` (leaf lock)
//!
//! Never invoke `TaskSpawner::spawn`, `ScopeResolver`, or drop `PortPermit`/`Arc<ScopeCore>`
//! while holding registry or port locks.

use core::cmp::Reverse;
use core::future::{Future, poll_fn};
use core::task::Poll;
use core::time::Duration;
use std::collections::{BinaryHeap, HashMap};
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
use crate::protocol::slab::{SlabHistory, SlabTable};
use crate::runtime::sync::{CloseableSemaphore, SemaphorePermit, Watch};
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

type SpawnPump = (Arc<dyn TaskSpawner>, Arc<DatagramPort>);
type OutboundAttachment = (Arc<DatagramPort>, OutboundPortHold);

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

struct PortState {
    node_wide: bool,
    scopes: HashMap<ScopeKid, Arc<ScopeCore>>,
    resolver: Arc<dyn ScopeResolver>,
    setup_handler: Arc<dyn DatagramSetupHandler>,
    owner: Weak<PortRegistry>,
    node_pending: Option<Arc<NodePendingGate>>,
    closing: bool,
    close_reason: Option<CoreError>,
    port_permit: Option<PortPermit>,
}

impl PortState {
    fn has_inbound_ownership(&self) -> bool {
        self.node_wide || !self.scopes.is_empty()
    }
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
    /// Lock-free SeqCst mirror of `state.has_inbound_ownership()`, paired with `outbound_refs`.
    has_inbound: AtomicBool,
    outbound_refs: AtomicUsize,
    /// Monotonic wakeup generation counter (pump never writes back -> zero lost wakeups).
    stop_tx: Watch<u64>,
    state: Mutex<PortState>,
}

/// RAII keep-alive reference for outbound-only [`DatagramPort`] usage (bindings and cookie-retry holds).
pub(crate) struct OutboundPortHold {
    port: Arc<DatagramPort>,
}

impl Drop for OutboundPortHold {
    fn drop(&mut self) {
        let prev = self.port.outbound_refs.fetch_sub(1, Ordering::SeqCst);
        if prev == 1 && !self.port.has_inbound.load(Ordering::SeqCst) {
            self.port.wake_pump();
        }
    }
}

impl DatagramPort {
    /// Returns this port's stable logical [`LinkId`].
    #[must_use]
    pub const fn link_id(&self) -> LinkId {
        self.link_id
    }

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
        lock_unpoisoned(&self.state).owner.upgrade()
    }

    /// Returns the port's recorded terminal error (or [`CoreError::Closed`] if closed cleanly).
    pub(crate) fn terminal_err(&self) -> CoreError {
        if let Some(err) = lock_unpoisoned(&self.state).close_reason.clone() {
            return err;
        }
        self.closed_tx.borrow_cloned().unwrap_or(CoreError::Closed)
    }

    fn is_closing(&self) -> bool {
        lock_unpoisoned(&self.state).closing
    }

    fn wake_pump(&self) {
        self.stop_tx.send_if_modified(|v| {
            *v = v.wrapping_add(1);
            true
        });
    }

    /// Acquires an RAII keep-alive hold on this port unless it is already closing.
    pub fn try_acquire_outbound_hold(self: &Arc<Self>) -> Result<OutboundPortHold, CoreError> {
        let st = lock_unpoisoned(&self.state);
        if st.closing {
            return Err(st.close_reason.clone().unwrap_or(CoreError::Closed));
        }
        self.outbound_refs.fetch_add(1, Ordering::SeqCst);
        Ok(OutboundPortHold {
            port: Arc::clone(self),
        })
    }

    /// Allocates a unique bound [`Cid`] and 32-slot circuit mailbox on this port's [`SlabTable`].
    ///
    /// Acquires locks strictly in monotonic hierarchy order: Level 3 (`self.state`) -> Level 4
    /// (`self.slab`) so `bind()` can never invert locks against teardown (R2-DG-01).
    pub fn bind(
        self: &Arc<Self>,
        metrics: Option<Arc<ScopeMetrics>>,
    ) -> Result<Binding, CoreError> {
        let (tx, rx) = async_channel::bounded::<PacketBuf>(DATAGRAM_MAILBOX_CAP);
        let (cid, hold) = {
            let st = lock_unpoisoned(&self.state);
            if st.closing {
                return Err(st.close_reason.clone().unwrap_or(CoreError::Closed));
            }
            let cid = {
                let mut slab = lock_unpoisoned(&self.slab);
                slab.insert(MailboxEntry { tx, metrics }, self.clock.now())?
            };
            self.outbound_refs.fetch_add(1, Ordering::SeqCst);
            let hold = OutboundPortHold {
                port: Arc::clone(self),
            };
            (cid, hold)
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
        let lookup = {
            let st = lock_unpoisoned(&self.state);
            if st.closing {
                return None;
            }
            if st.node_wide {
                Ok(Arc::clone(&st.resolver))
            } else {
                Err(st.scopes.get(&kid).cloned())
            }
        };
        match lookup {
            Ok(resolver) => resolver.resolve(kid),
            Err(scope) => scope,
        }
    }

    fn record_unknown_scope(&self) {
        let resolver = Arc::clone(&lock_unpoisoned(&self.state).resolver);
        resolver.record_unknown_scope();
    }

    fn record_mac1_drop(&self, matched: Option<&ScopeCore>) {
        let resolver = Arc::clone(&lock_unpoisoned(&self.state).resolver);
        resolver.record_mac1_drop(matched);
    }

    /// Background receive pump driving O(1) CID dispatch, fragment reassembly, and setup handoff.
    async fn run_pump(self: Arc<Self>) {
        let mut stop_rx = self.stop_tx.subscribe();
        let close_reason = loop {
            let _ = stop_rx.borrow_and_mark_seen();
            if self.is_closing() {
                break self.terminal_err();
            }
            if !self.has_inbound.load(Ordering::SeqCst)
                && self.outbound_refs.load(Ordering::SeqCst) == 0
                && self.try_retire_if_idle()
            {
                break CoreError::Closed;
            }
            let pkt = match race2(stop_rx.changed(), self.link.recv()).await {
                Either::Left(_) => continue,
                Either::Right(Ok(p)) => p,
                Either::Right(Err(err)) => break err,
            };
            self.dispatch_inbound_packet(pkt);
        };

        // Synchronized teardown (DG-04, DG-07, DG-16):
        // 1. Mark `closing = true` and record `close_reason` BEFORE closing circuit mailboxes so
        //    every `Binding::recv()` immediately sees the real carrier error.
        // 2. Synchronize registry removal with any concurrent `adopt_from` owner transfer.
        // 3. Extract `SlabHistory` into the owning registry's quarantine cache.
        // 4. Drop `PortPermit` and scope references outside locks BEFORE waking `DatagramIngress::closed()`.
        let mut dropped_permit: Option<PortPermit> = None;
        let mut dropped_scopes: Vec<Arc<ScopeCore>> = Vec::new();
        loop {
            let owner_opt = {
                let mut st = lock_unpoisoned(&self.state);
                st.closing = true;
                if st.close_reason.is_none() {
                    st.close_reason = Some(close_reason.clone());
                }
                st.owner.upgrade()
            };

            let Some(reg) = owner_opt else {
                // Strict lock order: Level 3 (`self.state`) -> Level 4 (`self.slab`).
                let mut st = lock_unpoisoned(&self.state);
                let _ = lock_unpoisoned(&self.slab).drain_to_history(self.clock.now());
                st.node_wide = false;
                dropped_scopes.extend(st.scopes.drain().map(|(_, sc)| sc));
                self.has_inbound.store(false, Ordering::SeqCst);
                if dropped_permit.is_none() {
                    dropped_permit = st.port_permit.take();
                }
                break;
            };

            let mut reg_inner = lock_unpoisoned(&reg.inner);
            let mut st = lock_unpoisoned(&self.state);
            let still_owned = st
                .owner
                .upgrade()
                .is_some_and(|cur| Arc::ptr_eq(&cur, &reg));
            if !still_owned {
                drop(st);
                drop(reg_inner);
                continue;
            }
            let now = self.clock.now();
            let history = lock_unpoisoned(&self.slab).drain_to_history(now);
            if reg_inner
                .ports
                .get(&self.link_id)
                .is_some_and(|existing| Arc::ptr_eq(existing, &self))
            {
                reg_inner.ports.remove(&self.link_id);
                reg_inner.retired_slabs.insert(self.link_id, history, now);
            }
            st.owner = Weak::new();
            st.node_wide = false;
            dropped_scopes.extend(st.scopes.drain().map(|(_, sc)| sc));
            self.has_inbound.store(false, Ordering::SeqCst);
            if dropped_permit.is_none() {
                dropped_permit = st.port_permit.take();
            }
            break;
        }

        drop(dropped_permit);
        drop(dropped_scopes);
        let final_reason = self.terminal_err();
        self.closed_tx.send(Some(final_reason));
    }

    /// Atomically removes this port from its owner registry iff still idle
    /// (`!has_inbound_ownership && outbound_refs == 0`), preserving CID generation history.
    fn try_retire_if_idle(self: &Arc<Self>) -> bool {
        let mut dropped_permit: Option<PortPermit> = None;
        let retired = loop {
            let owner_opt = {
                let st = lock_unpoisoned(&self.state);
                if st.closing {
                    break true;
                }
                if st.has_inbound_ownership() || self.outbound_refs.load(Ordering::SeqCst) > 0 {
                    break false;
                }
                st.owner.upgrade()
            };

            let Some(reg) = owner_opt else {
                let mut st = lock_unpoisoned(&self.state);
                if st.closing {
                    break true;
                }
                if st.has_inbound_ownership() || self.outbound_refs.load(Ordering::SeqCst) > 0 {
                    break false;
                }
                st.closing = true;
                if st.close_reason.is_none() {
                    st.close_reason = Some(CoreError::Closed);
                }
                dropped_permit = st.port_permit.take();
                break true;
            };

            let mut reg_inner = lock_unpoisoned(&reg.inner);
            let mut st = lock_unpoisoned(&self.state);
            if st.closing {
                break true;
            }
            let still_owned = st
                .owner
                .upgrade()
                .is_some_and(|cur| Arc::ptr_eq(&cur, &reg));
            if !still_owned {
                drop(st);
                drop(reg_inner);
                continue;
            }
            if st.has_inbound_ownership() || self.outbound_refs.load(Ordering::SeqCst) > 0 {
                break false;
            }
            let now = self.clock.now();
            let history = lock_unpoisoned(&self.slab).drain_to_history(now);
            if reg_inner
                .ports
                .get(&self.link_id)
                .is_some_and(|existing| Arc::ptr_eq(existing, self))
            {
                reg_inner.ports.remove(&self.link_id);
                reg_inner.retired_slabs.insert(self.link_id, history, now);
            }
            st.closing = true;
            if st.close_reason.is_none() {
                st.close_reason = Some(CoreError::Closed);
            }
            st.owner = Weak::new();
            dropped_permit = st.port_permit.take();
            break true;
        };
        drop(dropped_permit);
        retired
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
                slab.get(cid)
                    .map(|entry| (entry.tx.clone(), entry.metrics.clone()))
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

        // Ignore inbound setups on outbound-only / detached ports.
        if !self.has_inbound.load(Ordering::Acquire) {
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

    fn handle_setup_fwd(self: &Arc<Self>, wire: &[u8], receipt: Option<FragmentReceipt>) {
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
            let st = lock_unpoisoned(&self.state);
            if st.closing {
                return;
            }
            (Arc::clone(&st.setup_handler), st.node_pending.clone())
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
    pub fn port_arc(&self) -> Arc<DatagramPort> {
        Arc::clone(&self.port)
    }

    #[must_use]
    pub fn is_port_closing(&self) -> bool {
        self.port.is_closing()
    }

    /// Discards any queued stale packets from this binding's mailbox before reusing it on retry.
    pub fn drain_rx(&self) {
        while self.rx.try_recv().is_ok() {}
    }

    #[must_use]
    pub fn mtu(&self) -> u16 {
        self.port.mtu()
    }

    #[must_use]
    pub fn mtu_watch(&self) -> MtuWatch {
        self.port.mtu_watch()
    }

    /// Receives the next packet routed to this binding's CID, propagating the port's real
    /// terminal carrier error if the underlying link failed (DG-16).
    pub async fn recv(&self) -> Result<PacketBuf, CoreError> {
        self.rx
            .recv()
            .await
            .map_err(|_| self.port.terminal_err())
    }

    pub fn send_now(&self, packet: PacketBuf) -> Result<(), CoreError> {
        self.port.link.try_send(packet)
    }

    /// Waits for link send readiness and retries transient [`CoreError::WouldBlock`] until
    /// accepted, a fatal error occurs, or `deadline` expires (DG-09).
    pub async fn send_reliable_until(
        &self,
        packet: PacketBuf,
        clock: &dyn Clock,
        deadline: MonotonicTime,
    ) -> Result<(), CoreError> {
        with_deadline(clock, deadline, async {
            let mut consecutive_would_block = 0u32;
            loop {
                self.port.link.send_ready().await?;
                match self.port.link.try_send(packet.clone()) {
                    Ok(()) => return Ok(()),
                    Err(CoreError::WouldBlock) => {
                        consecutive_would_block = consecutive_would_block.saturating_add(1);
                        if consecutive_would_block < 4 {
                            yield_once().await;
                        } else {
                            clock.sleep(Duration::from_millis(10)).await;
                        }
                    }
                    Err(err) => return Err(err),
                }
            }
        })
        .await
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

async fn yield_once() {
    let mut yielded = false;
    poll_fn(|cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
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
    let Ok(hold) = port.try_acquire_outbound_hold() else {
        return;
    };
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
    /// Transmits a datagram setup flight:
    /// - Single-packet unfragmented `SETUP_FWD`: waits for link readiness and retries `WouldBlock`
    ///   within `deadline` (DG-09).
    /// - Fragmented `SETUP_FRAG` burst: transmits all fragments ignoring per-fragment `WouldBlock`
    ///   and schedules `[150, 300, 600]` ms retries (Spec §5.6).
    pub async fn send(
        binding: &'a Binding,
        wire: &[u8],
        clock: &'a dyn Clock,
        deadline: MonotonicTime,
    ) -> Result<Self, CoreError> {
        let prepared = FragmentBurst::prepare(wire, binding.mtu(), binding.cid())?;
        match prepared {
            PreparedFlight::Single(pkt) => {
                binding.send_reliable_until(pkt, clock, deadline).await?;
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
// Bounded Per-LinkId Retired Slab Generation Cache (DG-07, R2-DG-03, Spec §6.5)
// ---------------------------------------------------------------------------

struct RetiredCacheEntry {
    history: SlabHistory,
    seq: u64,
}

struct RetiredSlabCache {
    entries: HashMap<LinkId, RetiredCacheEntry>,
    expiry_heap: BinaryHeap<Reverse<(MonotonicTime, u64, LinkId)>>,
    next_seq: u64,
    max_entries: usize,
}

impl RetiredSlabCache {
    fn new(max_ports: usize) -> Self {
        Self {
            entries: HashMap::new(),
            expiry_heap: BinaryHeap::new(),
            next_seq: 1,
            max_entries: max_ports.saturating_mul(4).clamp(64, 16_384),
        }
    }

    fn prune(&mut self, now: MonotonicTime) {
        while let Some(&Reverse((_, seq, id))) = self.expiry_heap.peek() {
            match self.entries.get(&id) {
                None => {
                    self.expiry_heap.pop();
                }
                Some(entry) if entry.seq != seq => {
                    self.expiry_heap.pop();
                }
                Some(entry) if entry.history.is_expired(now) => {
                    self.expiry_heap.pop();
                    self.entries.remove(&id);
                }
                Some(_) => break,
            }
        }
    }

    /// Returns `true` if attaching a brand-new unrelated `link_id` would exceed the quarantine
    /// history budget (applying `CoreError::Busy` backpressure instead of evicting unexpired
    /// 60-second CID wrap quarantine histories, R2-DG-03).
    ///
    /// Reattaching a `link_id` that already has an entry in this cache is ALWAYS allowed because
    /// it consumes its existing entry rather than increasing cache occupancy.
    fn is_saturated_for(&mut self, link_id: LinkId, now: MonotonicTime) -> bool {
        self.prune(now);
        if self.entries.contains_key(&link_id) {
            return false;
        }
        self.entries.len() >= self.max_entries
    }

    /// Inserts a non-empty, unexpired `SlabHistory`, NEVER evicting any unexpired entry (R2-DG-03).
    fn insert(&mut self, link_id: LinkId, history: SlabHistory, now: MonotonicTime) {
        if history.is_empty() || history.is_expired(now) {
            return;
        }
        self.prune(now);
        if let Some(existing) = self.entries.get(&link_id) {
            if !existing.history.is_expired(now)
                && existing.history.retired_at() > history.retired_at()
            {
                return;
            }
        }
        let retired_at = history.retired_at();
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1).max(1);
        self.entries
            .insert(link_id, RetiredCacheEntry { history, seq });
        self.expiry_heap.push(Reverse((retired_at, seq, link_id)));

        // Compact superseded/removed heap tombstones only (never evict live unexpired entries).
        let compact_threshold = self.entries.len().saturating_mul(2).max(64);
        if self.expiry_heap.len() > compact_threshold {
            self.expiry_heap.clear();
            for (&id, entry) in &self.entries {
                self.expiry_heap
                    .push(Reverse((entry.history.retired_at(), entry.seq, id)));
            }
        }
    }

    fn take(&mut self, link_id: LinkId, now: MonotonicTime) -> Option<SlabHistory> {
        self.prune(now);
        self.entries
            .remove(&link_id)
            .map(|e| e.history)
            .filter(|h| !h.is_expired(now))
    }

    fn snapshot_unexpired(&mut self, now: MonotonicTime) -> Vec<(LinkId, SlabHistory)> {
        self.prune(now);
        self.entries
            .iter()
            .filter(|(_, e)| !e.history.is_expired(now))
            .map(|(&id, e)| (id, e.history.clone()))
            .collect()
    }

    fn drain_into(
        &mut self,
        dst: &mut Self,
        active_in_dst: &HashMap<LinkId, Arc<DatagramPort>>,
        now: MonotonicTime,
    ) {
        self.prune(now);
        dst.prune(now);
        self.expiry_heap.clear();
        for (link_id, entry) in self.entries.drain() {
            if !entry.history.is_expired(now) && !active_in_dst.contains_key(&link_id) {
                dst.insert(link_id, entry.history, now);
            }
        }
    }
}

fn pick_newer_history(a: Option<SlabHistory>, b: Option<SlabHistory>) -> Option<SlabHistory> {
    match (a, b) {
        (Some(ha), Some(hb)) => {
            if ha.retired_at() >= hb.retired_at() {
                Some(ha)
            } else {
                Some(hb)
            }
        }
        (Some(h), None) | (None, Some(h)) => Some(h),
        (None, None) => None,
    }
}

// ---------------------------------------------------------------------------
// PortRegistry & PortSlot (Deduplication & Atomic Node Adoption, Spec §8.2)
// ---------------------------------------------------------------------------

struct RegistryInner {
    ports: HashMap<LinkId, Arc<DatagramPort>>,
    retired_slabs: RetiredSlabCache,
    /// Weak references to ports still owned/kept alive by a prior Node across unmount or Node
    /// drop (R2-DG-02), ensuring one logical `LinkId` never runs two concurrent receive pumps.
    observed_live_ports: HashMap<LinkId, Weak<DatagramPort>>,
    adopted_by: Option<Weak<PortRegistry>>,
    ingress_closed: bool,
}

impl RegistryInner {
    /// Prunes any `closing` ports still sitting in `self.ports`, preserving their `SlabHistory`
    /// and returning any `PortPermit`s so the caller can drop them immediately.
    fn prune_closing_ports(
        &mut self,
        now: MonotonicTime,
        dropped_permits: &mut Vec<PortPermit>,
        dropped_scopes: &mut Vec<Arc<ScopeCore>>,
    ) {
        let closing_ids: Vec<LinkId> = self
            .ports
            .iter()
            .filter_map(|(&id, port)| lock_unpoisoned(&port.state).closing.then_some(id))
            .collect();
        for id in closing_ids {
            if let Some(port) = self.ports.remove(&id) {
                let mut st = lock_unpoisoned(&port.state);
                let hist = lock_unpoisoned(&port.slab).drain_to_history(now);
                self.retired_slabs.insert(id, hist, now);
                st.owner = Weak::new();
                st.node_wide = false;
                dropped_scopes.extend(st.scopes.drain().map(|(_, sc)| sc));
                port.has_inbound.store(false, Ordering::SeqCst);
                if let Some(p) = st.port_permit.take() {
                    dropped_permits.push(p);
                }
            }
        }
    }

    /// Checks whether a port recorded across unmount is still live (`!closing`), lazily pruning
    /// dead or already-closing entries (Lock Level 2 -> Level 3).
    fn find_observed_live_port(&mut self, link_id: LinkId) -> Option<Arc<DatagramPort>> {
        let weak = self.observed_live_ports.get(&link_id)?;
        let Some(port) = weak.upgrade() else {
            self.observed_live_ports.remove(&link_id);
            return None;
        };
        if lock_unpoisoned(&port.state).closing {
            self.observed_live_ports.remove(&link_id);
            return None;
        }
        Some(port)
    }

    fn prune_dead_observed_ports(&mut self) {
        self.observed_live_ports
            .retain(|_, weak| weak.strong_count() > 0);
    }
}

pub(crate) struct DropHandoffSnapshot {
    live_ports: Vec<(LinkId, Weak<DatagramPort>)>,
    retired_slabs: Vec<(LinkId, SlabHistory)>,
}

enum PriorLookup {
    None(Option<(Arc<PortRegistry>, SlabHistory)>),
    LivePort(Arc<DatagramPort>, Option<(Arc<PortRegistry>, SlabHistory)>),
}

/// Registry deduplicating active [`DatagramPort`]s by [`LinkId`] (Lock Level 2).
pub(crate) struct PortRegistry {
    inner: Mutex<RegistryInner>,
    /// Weak references to former hosting `Node` registries seen across unmount transitions
    /// (independent leaf mutex; NEVER locked while holding `inner`, R2-DG-02).
    prior_registries: Mutex<Vec<Weak<PortRegistry>>>,
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
        let cap = max_ports.max(1);
        Arc::new(Self {
            inner: Mutex::new(RegistryInner {
                ports: HashMap::new(),
                retired_slabs: RetiredSlabCache::new(cap),
                observed_live_ports: HashMap::new(),
                adopted_by: None,
                ingress_closed: false,
            }),
            prior_registries: Mutex::new(Vec::new()),
            port_sem: CloseableSemaphore::new(cap),
            metric_owner,
            clock,
            spawner,
            resolver,
            setup_handler,
            node_pending,
        })
    }

    fn live_prior_registries(self: &Arc<Self>) -> Vec<Arc<PortRegistry>> {
        let mut priors = lock_unpoisoned(&self.prior_registries);
        let mut live = Vec::new();
        priors.retain(|w| match w.upgrade() {
            Some(arc) if !Arc::ptr_eq(&arc, self) => {
                live.push(arc);
                true
            }
            _ => false,
        });
        live
    }

    fn record_prior_registry(self: &Arc<Self>, prior: &Arc<PortRegistry>) {
        if Arc::ptr_eq(self, prior) {
            return;
        }
        let mut priors = lock_unpoisoned(&self.prior_registries);
        priors.retain(|w| w.strong_count() > 0);
        if !priors
            .iter()
            .any(|w| w.upgrade().is_some_and(|p| Arc::ptr_eq(&p, prior)))
        {
            priors.push(Arc::downgrade(prior));
        }
    }

    fn record_observed_live_ports(&self, live_ports: Vec<(LinkId, Weak<DatagramPort>)>) {
        if live_ports.is_empty() {
            return;
        }
        let mut reg = lock_unpoisoned(&self.inner);
        reg.prune_dead_observed_ports();
        for (link_id, weak) in live_ports {
            if !reg.ports.contains_key(&link_id) {
                reg.observed_live_ports.insert(link_id, weak);
            }
        }
    }

    fn merge_retired_slabs(&self, slabs: Vec<(LinkId, SlabHistory)>, now: MonotonicTime) {
        if slabs.is_empty() {
            return;
        }
        let mut reg = lock_unpoisoned(&self.inner);
        for (link_id, hist) in slabs {
            if !reg.ports.contains_key(&link_id) {
                reg.retired_slabs.insert(link_id, hist, now);
            }
        }
    }

    /// Inspects prior hosting registries ONE AT A TIME (never nesting Level 2 locks) to detect
    /// a still-live port for `link_id` or inherit its unexpired retired `SlabHistory` (R2-DG-02).
    fn check_prior_registries(self: &Arc<Self>, link_id: LinkId, now: MonotonicTime) -> PriorLookup {
        let mut inherited: Option<(Arc<PortRegistry>, SlabHistory)> = None;
        for prior in self.live_prior_registries() {
            let mut dropped_permits = Vec::new();
            let mut dropped_scopes = Vec::new();
            let live_port = {
                let mut preg = lock_unpoisoned(&prior.inner);
                if let Some(existing) = preg.ports.get(&link_id).cloned() {
                    let mut st = lock_unpoisoned(&existing.state);
                    if st.closing {
                        let hist = lock_unpoisoned(&existing.slab).drain_to_history(now);
                        preg.ports.remove(&link_id);
                        preg.retired_slabs.insert(link_id, hist, now);
                        st.owner = Weak::new();
                        st.node_wide = false;
                        dropped_scopes.extend(st.scopes.drain().map(|(_, sc)| sc));
                        existing.has_inbound.store(false, Ordering::SeqCst);
                        if let Some(p) = st.port_permit.take() {
                            dropped_permits.push(p);
                        }
                        None
                    } else {
                        drop(st);
                        Some(existing)
                    }
                } else {
                    None
                }
            };
            drop(dropped_permits);
            drop(dropped_scopes);

            if let Some(port) = live_port {
                return PriorLookup::LivePort(port, inherited);
            }

            if inherited.is_none() {
                let hist = lock_unpoisoned(&prior.inner)
                    .retired_slabs
                    .take(link_id, now);
                if let Some(hist) = hist {
                    inherited = Some((prior, hist));
                }
            }
        }
        PriorLookup::None(inherited)
    }

    fn restore_inherited_history(
        inherited: Option<(Arc<PortRegistry>, SlabHistory)>,
        link_id: LinkId,
        now: MonotonicTime,
    ) {
        if let Some((prior, hist)) = inherited {
            lock_unpoisoned(&prior.inner)
                .retired_slabs
                .insert(link_id, hist, now);
        }
    }

    /// Attaches an inbound `DatagramLink` (deduplicating by `LinkId` into one `DatagramPort`/`SlabTable`),
    /// spawning any new pump task strictly AFTER releasing all locks.
    pub fn attach_inbound(
        self: &Arc<Self>,
        link: Arc<dyn DatagramLink>,
        scope: Option<Arc<ScopeCore>>,
        node_wide: bool,
    ) -> Result<DatagramIngress, CoreError> {
        let (ingress, to_spawn) = self.attach_inbound_prepared(link, scope, node_wide)?;
        if let Some((spawner, port)) = to_spawn {
            spawner.spawn(Box::pin(port.run_pump()));
        }
        Ok(ingress)
    }

    fn attach_inbound_prepared(
        self: &Arc<Self>,
        link: Arc<dyn DatagramLink>,
        scope: Option<Arc<ScopeCore>>,
        node_wide: bool,
    ) -> Result<(DatagramIngress, Option<SpawnPump>), CoreError> {
        let link_id = link.link_id();
        let now = self.clock.now();

        // Fast redirect check when already adopted by a Node.
        if let Some(target) = {
            let reg = lock_unpoisoned(&self.inner);
            reg.adopted_by.as_ref().and_then(Weak::upgrade)
        } {
            return target.attach_inbound_prepared(link, scope, node_wide);
        }

        // Coordinate live `LinkId` ownership across unmount transitions (R2-DG-02):
        // never spawn a second receive pump while a prior Node registry still holds a live port.
        let mut inherited = match self.check_prior_registries(link_id, now) {
            PriorLookup::LivePort(_, inh) => {
                Self::restore_inherited_history(inh, link_id, now);
                return Err(CoreError::Busy);
            }
            PriorLookup::None(inh) => inh,
        };

        let mut stale_scopes: Vec<Arc<ScopeCore>> = Vec::new();

        enum InboundStep {
            Done(Result<(DatagramIngress, Option<SpawnPump>), CoreError>),
            Redirect(Arc<PortRegistry>),
        }

        let step = {
            let mut reg = lock_unpoisoned(&self.inner);
            if let Some(target) = reg.adopted_by.as_ref().and_then(Weak::upgrade) {
                InboundStep::Redirect(target)
            } else if reg.ingress_closed {
                InboundStep::Done(Err(CoreError::Closed))
            } else {
                let mut existing_res = None;
                if let Some(existing) = reg.ports.get(&link_id).cloned() {
                    let mut st = lock_unpoisoned(&existing.state);
                    if st.closing {
                        let hist = lock_unpoisoned(&existing.slab).drain_to_history(now);
                        reg.ports.remove(&link_id);
                        reg.retired_slabs.insert(link_id, hist, now);
                        st.owner = Weak::new();
                        st.node_wide = false;
                        stale_scopes.extend(st.scopes.drain().map(|(_, sc)| sc));
                        existing.has_inbound.store(false, Ordering::SeqCst);
                        if let Some(p) = st.port_permit.take() {
                            drop(p);
                        }
                    } else {
                        if node_wide {
                            st.node_wide = true;
                        }
                        if let Some(sc) = scope.as_ref() {
                            st.scopes.insert(sc.keypair.scope_kid(), Arc::clone(sc));
                        }
                        existing
                            .has_inbound
                            .store(st.has_inbound_ownership(), Ordering::SeqCst);
                        existing_res = Some(Ok((existing.ingress(), None)));
                    }
                }

                if let Some(res) = existing_res {
                    InboundStep::Done(res)
                } else if reg.find_observed_live_port(link_id).is_some() {
                    // Live port from an unmounted/dropped Node is still running its receive pump!
                    InboundStep::Done(Err(CoreError::Busy))
                } else if reg.retired_slabs.is_saturated_for(link_id, now) {
                    // Quarantine history budget saturated: apply Busy backpressure instead of
                    // evicting unexpired 60 s CID wrap histories (R2-DG-03).
                    self.metric_owner.record_capacity_drop();
                    InboundStep::Done(Err(CoreError::Busy))
                } else {
                    match PortPermit::acquire(&self.port_sem, &self.metric_owner) {
                        Err(err) => InboundStep::Done(Err(err)),
                        Ok(permit) => {
                            let mut scopes = HashMap::new();
                            if let Some(sc) = scope.as_ref() {
                                scopes.insert(sc.keypair.scope_kid(), Arc::clone(sc));
                            }
                            let has_inbound_now = node_wide || !scopes.is_empty();
                            let local_hist = reg.retired_slabs.take(link_id, now);
                            let prior_hist = inherited.take().map(|(_, h)| h);
                            let slab = match pick_newer_history(local_hist, prior_hist) {
                                Some(hist) => SlabTable::from_history(hist),
                                None => SlabTable::new(),
                            };

                            let (closed_tx, _) = Watch::new(None::<CoreError>);
                            let (stop_tx, _) = Watch::new(0u64);
                            let port = Arc::new(DatagramPort {
                                link: Arc::clone(&link),
                                link_id,
                                clock: Arc::clone(&self.clock),
                                slab: Mutex::new(slab),
                                reassembler: Arc::new(Mutex::new(FragmentReassembler::new())),
                                admission: Arc::new(AdmissionTracker::new()),
                                closed_tx,
                                has_inbound: AtomicBool::new(has_inbound_now),
                                outbound_refs: AtomicUsize::new(0),
                                stop_tx,
                                state: Mutex::new(PortState {
                                    node_wide,
                                    scopes,
                                    resolver: Arc::clone(&self.resolver),
                                    setup_handler: Arc::clone(&self.setup_handler),
                                    owner: Arc::downgrade(self),
                                    node_pending: self.node_pending.clone(),
                                    closing: false,
                                    close_reason: None,
                                    port_permit: Some(permit),
                                }),
                            });
                            let ingress = port.ingress();
                            reg.observed_live_ports.remove(&link_id);
                            reg.ports.insert(link_id, Arc::clone(&port));
                            InboundStep::Done(Ok((
                                ingress,
                                Some((Arc::clone(&self.spawner), port)),
                            )))
                        }
                    }
                }
            }
        };

        drop(stale_scopes);
        Self::restore_inherited_history(inherited, link_id, now);

        match step {
            InboundStep::Done(res) => res,
            InboundStep::Redirect(target) => target.attach_inbound_prepared(link, scope, node_wide),
        }
    }

    /// Attaches an outbound `DatagramLink` (sharing an existing `DatagramPort` if `LinkId` matches),
    /// spawning any new pump task strictly AFTER releasing all locks.
    pub fn attach_outbound(
        self: &Arc<Self>,
        link: Arc<dyn DatagramLink>,
    ) -> Result<(Arc<DatagramPort>, OutboundPortHold), CoreError> {
        let (res, to_spawn) = self.attach_outbound_prepared(link)?;
        if let Some((spawner, port)) = to_spawn {
            spawner.spawn(Box::pin(port.run_pump()));
        }
        Ok(res)
    }

    fn attach_outbound_prepared(
        self: &Arc<Self>,
        link: Arc<dyn DatagramLink>,
    ) -> Result<(OutboundAttachment, Option<SpawnPump>), CoreError> {
        let link_id = link.link_id();
        let now = self.clock.now();

        if let Some(target) = {
            let reg = lock_unpoisoned(&self.inner);
            reg.adopted_by.as_ref().and_then(Weak::upgrade)
        } {
            return target.attach_outbound_prepared(link);
        }

        // Coordinate live `LinkId` ownership across unmount transitions (R2-DG-02):
        // reuse any still-live port owned by a prior Node registry instead of spawning a duplicate pump!
        let mut inherited = match self.check_prior_registries(link_id, now) {
            PriorLookup::LivePort(live_port, inh) => {
                Self::restore_inherited_history(inh, link_id, now);
                if let Ok(hold) = live_port.try_acquire_outbound_hold() {
                    return Ok(((live_port, hold), None));
                }
                // `live_port` entered closing concurrently; re-run once so its retired history is preserved.
                return self.attach_outbound_prepared(link);
            }
            PriorLookup::None(inh) => inh,
        };

        let mut stale_scopes: Vec<Arc<ScopeCore>> = Vec::new();

        enum OutboundStep {
            Done(Result<(OutboundAttachment, Option<SpawnPump>), CoreError>),
            Redirect(Arc<PortRegistry>),
        }

        let step = {
            let mut reg = lock_unpoisoned(&self.inner);
            if let Some(target) = reg.adopted_by.as_ref().and_then(Weak::upgrade) {
                OutboundStep::Redirect(target)
            } else if reg.ingress_closed {
                OutboundStep::Done(Err(CoreError::Closed))
            } else {
                let mut existing_res = None;
                if let Some(existing) = reg.ports.get(&link_id).cloned() {
                    let mut st = lock_unpoisoned(&existing.state);
                    if st.closing {
                        let hist = lock_unpoisoned(&existing.slab).drain_to_history(now);
                        reg.ports.remove(&link_id);
                        reg.retired_slabs.insert(link_id, hist, now);
                        st.owner = Weak::new();
                        st.node_wide = false;
                        stale_scopes.extend(st.scopes.drain().map(|(_, sc)| sc));
                        existing.has_inbound.store(false, Ordering::SeqCst);
                        if let Some(p) = st.port_permit.take() {
                            drop(p);
                        }
                    } else {
                        existing.outbound_refs.fetch_add(1, Ordering::SeqCst);
                        let hold = OutboundPortHold {
                            port: Arc::clone(&existing),
                        };
                        drop(st);
                        existing_res = Some(Ok(((existing, hold), None)));
                    }
                }

                if let Some(res) = existing_res {
                    OutboundStep::Done(res)
                } else if let Some(observed) = reg.find_observed_live_port(link_id) {
                    // Reuse live port kept alive across unmount / Node drop (Lock Level 2 -> Level 3).
                    if let Ok(hold) = observed.try_acquire_outbound_hold() {
                        OutboundStep::Done(Ok(((observed, hold), None)))
                    } else {
                        reg.observed_live_ports.remove(&link_id);
                        OutboundStep::Done(Err(CoreError::Busy))
                    }
                } else if reg.retired_slabs.is_saturated_for(link_id, now) {
                    // Quarantine history budget saturated (R2-DG-03).
                    self.metric_owner.record_capacity_drop();
                    OutboundStep::Done(Err(CoreError::Busy))
                } else {
                    match PortPermit::acquire(&self.port_sem, &self.metric_owner) {
                        Err(err) => OutboundStep::Done(Err(err)),
                        Ok(permit) => {
                            let local_hist = reg.retired_slabs.take(link_id, now);
                            let prior_hist = inherited.take().map(|(_, h)| h);
                            let slab = match pick_newer_history(local_hist, prior_hist) {
                                Some(hist) => SlabTable::from_history(hist),
                                None => SlabTable::new(),
                            };
                            let (closed_tx, _) = Watch::new(None::<CoreError>);
                            let (stop_tx, _) = Watch::new(0u64);
                            let port = Arc::new(DatagramPort {
                                link: Arc::clone(&link),
                                link_id,
                                clock: Arc::clone(&self.clock),
                                slab: Mutex::new(slab),
                                reassembler: Arc::new(Mutex::new(FragmentReassembler::new())),
                                admission: Arc::new(AdmissionTracker::new()),
                                closed_tx,
                                has_inbound: AtomicBool::new(false),
                                outbound_refs: AtomicUsize::new(1),
                                stop_tx,
                                state: Mutex::new(PortState {
                                    node_wide: false,
                                    scopes: HashMap::new(),
                                    resolver: Arc::clone(&self.resolver),
                                    setup_handler: Arc::clone(&self.setup_handler),
                                    owner: Arc::downgrade(self),
                                    node_pending: self.node_pending.clone(),
                                    closing: false,
                                    close_reason: None,
                                    port_permit: Some(permit),
                                }),
                            });
                            let hold = OutboundPortHold {
                                port: Arc::clone(&port),
                            };
                            reg.observed_live_ports.remove(&link_id);
                            reg.ports.insert(link_id, Arc::clone(&port));
                            OutboundStep::Done(Ok((
                                (Arc::clone(&port), hold),
                                Some((Arc::clone(&self.spawner), port)),
                            )))
                        }
                    }
                }
            }
        };

        drop(stale_scopes);
        Self::restore_inherited_history(inherited, link_id, now);

        match step {
            OutboundStep::Done(res) => res,
            OutboundStep::Redirect(target) => target.attach_outbound_prepared(link),
        }
    }

    /// Atomically adopts all live ports from a standalone scope's `PortRegistry` into `self`
    /// (`Node`'s `PortRegistry`, Spec §8.2 Rule 4, DG-04, DG-07, R2-DG-02).
    ///
    /// Prunes closing ports, validates non-conflicting `LinkId`s (`AlreadyPublished`) and
    /// `max_datagram_ports` capacity (`Busy`) BEFORE mutating either registry, ensuring zero
    /// partial mutation on error.
    pub fn adopt_from(self: &Arc<Self>, source: &Arc<PortRegistry>) -> Result<(), CoreError> {
        let now = self.clock.now();
        let mut dropped_permits: Vec<PortPermit> = Vec::new();
        let mut dropped_scopes: Vec<Arc<ScopeCore>> = Vec::new();

        let res = {
            // Lock order: Node's `self.inner` (2a) FIRST, standalone `source.inner` (2b) SECOND.
            let mut dst = lock_unpoisoned(&self.inner);
            let mut src = lock_unpoisoned(&source.inner);

            if dst.ingress_closed {
                return Err(CoreError::Closed);
            }

            // Prune any closing ports from both registries before conflict/capacity checks (DG-04).
            dst.prune_closing_ports(now, &mut dropped_permits, &mut dropped_scopes);
            src.prune_closing_ports(now, &mut dropped_permits, &mut dropped_scopes);
            // Release pruned permits immediately so semaphore capacity is up to date!
            dropped_permits.clear();

            // Step 1: Check for conflicting live LinkIds (Spec §8.2 Rule 4 -> AlreadyPublished).
            for link_id in src.ports.keys() {
                if dst.ports.contains_key(link_id) {
                    return Err(CoreError::AlreadyPublished);
                }
            }

            // Step 2: Atomically acquire all required node port permits BEFORE moving any port.
            let mut new_permits = Vec::with_capacity(src.ports.len());
            for _ in 0..src.ports.len() {
                match PortPermit::acquire(&self.port_sem, &self.metric_owner) {
                    Ok(p) => new_permits.push(p),
                    Err(err) => {
                        drop(new_permits);
                        return Err(err);
                    }
                }
            }

            // Step 3: Commit adoption (rejecting any port whose pump entered closing concurrently).
            for ((link_id, port), new_permit) in src.ports.drain().zip(new_permits) {
                let mut st = lock_unpoisoned(&port.state);
                if st.closing {
                    let hist = lock_unpoisoned(&port.slab).drain_to_history(now);
                    dst.retired_slabs.insert(link_id, hist, now);
                    st.owner = Weak::new();
                    st.node_wide = false;
                    dropped_scopes.extend(st.scopes.drain().map(|(_, sc)| sc));
                    port.has_inbound.store(false, Ordering::SeqCst);
                    if let Some(old) = st.port_permit.take() {
                        dropped_permits.push(old);
                    }
                    dropped_permits.push(new_permit);
                    continue;
                }
                // Adopted ports keep `node_wide = false` and their explicit scope list!
                st.node_wide = false;
                st.resolver = Arc::clone(&self.resolver);
                st.setup_handler = Arc::clone(&self.setup_handler);
                st.owner = Arc::downgrade(self);
                st.node_pending = self.node_pending.clone();
                if let Some(old_permit) = st.port_permit.replace(new_permit) {
                    dropped_permits.push(old_permit);
                }
                drop(st);
                dst.observed_live_ports.remove(&link_id);
                dst.ports.insert(link_id, port);
            }

            // Preserve any recent retired-CID histories and unmount-observed live ports (DG-07, R2-DG-02).
            let dst_inner = &mut *dst;
            src.retired_slabs
                .drain_into(&mut dst_inner.retired_slabs, &dst_inner.ports, now);
            dst_inner.prune_dead_observed_ports();
            for (link_id, weak) in src.observed_live_ports.drain() {
                if weak.strong_count() > 0 && !dst_inner.ports.contains_key(&link_id) {
                    dst_inner.observed_live_ports.insert(link_id, weak);
                }
            }
            src.adopted_by = Some(Arc::downgrade(self));
            Ok(())
        };

        drop(dropped_permits);
        drop(dropped_scopes);

        if res.is_ok() {
            // Propagate prior-Node coordination references strictly OUTSIDE Level 2 locks.
            for prior in source.live_prior_registries() {
                self.record_prior_registry(&prior);
            }
        }
        res
    }

    /// Clears the standalone registry's adoption redirect (called on unmount / `Node` drop).
    pub fn clear_adopted_by(&self) {
        lock_unpoisoned(&self.inner).adopted_by = None;
    }

    /// Removes `kid` from every port's explicit scope list (called by `Node::remove_scope`,
    /// Spec §8.2), immediately retires any unowned idle port (DG-06), and returns weak references
    /// to every port that remains live so the unmounted scope coordinates `LinkId` ownership
    /// without ever spawning a duplicate receive pump (R2-DG-02).
    pub fn detach_scope_and_snapshot(&self, kid: ScopeKid) -> Vec<(LinkId, Weak<DatagramPort>)> {
        let now = self.clock.now();
        let mut dropped_permits: Vec<PortPermit> = Vec::new();
        let mut dropped_scopes: Vec<Arc<ScopeCore>> = Vec::new();
        let mut to_wake: Vec<Arc<DatagramPort>> = Vec::new();
        let mut remaining_live: Vec<(LinkId, Weak<DatagramPort>)> = Vec::new();

        {
            let mut reg = lock_unpoisoned(&self.inner);
            let mut to_remove: Vec<LinkId> = Vec::new();

            for (&link_id, port) in &reg.ports {
                let mut st = lock_unpoisoned(&port.state);
                if let Some(removed) = st.scopes.remove(&kid) {
                    dropped_scopes.push(removed);
                }
                let has_inbound_now = st.has_inbound_ownership();
                port.has_inbound.store(has_inbound_now, Ordering::SeqCst);

                if st.closing {
                    to_remove.push(link_id);
                    st.owner = Weak::new();
                    if let Some(p) = st.port_permit.take() {
                        dropped_permits.push(p);
                    }
                    continue;
                }

                if !has_inbound_now && port.outbound_refs.load(Ordering::SeqCst) == 0 {
                    st.closing = true;
                    if st.close_reason.is_none() {
                        st.close_reason = Some(CoreError::Closed);
                    }
                    st.owner = Weak::new();
                    if let Some(p) = st.port_permit.take() {
                        dropped_permits.push(p);
                    }
                    to_remove.push(link_id);
                    to_wake.push(Arc::clone(port));
                } else {
                    remaining_live.push((link_id, Arc::downgrade(port)));
                }
            }

            for link_id in to_remove {
                if let Some(port) = reg.ports.remove(&link_id) {
                    let hist = lock_unpoisoned(&port.slab).drain_to_history(now);
                    reg.retired_slabs.insert(link_id, hist, now);
                }
            }
        }

        drop(dropped_permits);
        drop(dropped_scopes);
        for port in to_wake {
            port.wake_pump();
        }
        remaining_live
    }

    /// Snapshots all currently live non-closing ports plus unexpired retired CID histories
    /// (used during `Node::drop` after `shutdown_ingress()` to hand off active `outbound_refs > 0`
    /// ports and quarantine state to unmounted scopes, R2-DG-02 / R2-DG-03).
    pub fn snapshot_live_and_retired(&self) -> DropHandoffSnapshot {
        let now = self.clock.now();
        let mut reg = lock_unpoisoned(&self.inner);
        let live_ports = reg
            .ports
            .iter()
            .filter(|(_, port)| !lock_unpoisoned(&port.state).closing)
            .map(|(&id, port)| (id, Arc::downgrade(port)))
            .collect();
        let retired_slabs = reg.retired_slabs.snapshot_unexpired(now);
        DropHandoffSnapshot {
            live_ports,
            retired_slabs,
        }
    }

    /// Disables all inbound ownership on every port in this registry and wakes/retires idle pumps.
    ///
    /// Called on final `Drop` of a standalone `ScopeInstance` or `Node` so background receive
    /// pumps never leak indefinitely in `link.recv()` (DG-05).
    pub fn shutdown_ingress(&self) {
        let now = self.clock.now();
        let mut dropped_permits: Vec<PortPermit> = Vec::new();
        let mut dropped_scopes: Vec<Arc<ScopeCore>> = Vec::new();
        let mut to_wake: Vec<Arc<DatagramPort>> = Vec::new();

        {
            let mut reg = lock_unpoisoned(&self.inner);
            reg.ingress_closed = true;
            reg.adopted_by = None;

            let mut to_remove: Vec<LinkId> = Vec::new();
            for (&link_id, port) in &reg.ports {
                let mut st = lock_unpoisoned(&port.state);
                st.node_wide = false;
                dropped_scopes.extend(st.scopes.drain().map(|(_, sc)| sc));
                port.has_inbound.store(false, Ordering::SeqCst);

                if st.closing || port.outbound_refs.load(Ordering::SeqCst) == 0 {
                    st.closing = true;
                    if st.close_reason.is_none() {
                        st.close_reason = Some(CoreError::Closed);
                    }
                    st.owner = Weak::new();
                    if let Some(p) = st.port_permit.take() {
                        dropped_permits.push(p);
                    }
                    to_remove.push(link_id);
                    to_wake.push(Arc::clone(port));
                }
            }

            for link_id in to_remove {
                if let Some(port) = reg.ports.remove(&link_id) {
                    let hist = lock_unpoisoned(&port.slab).drain_to_history(now);
                    reg.retired_slabs.insert(link_id, hist, now);
                }
            }
        }

        drop(dropped_permits);
        drop(dropped_scopes);
        for port in to_wake {
            port.wake_pump();
        }
    }
}

struct PortSlotState {
    owner_node: Option<u64>,
    registry: Arc<PortRegistry>,
}

/// Synchronized indirection slot pointing to a scope's currently active [`PortRegistry`]
/// (its own standalone registry when unmounted, or its hosting `Node`'s registry when mounted).
///
/// Lock Level 1.5: read-locked during `attach_inbound`/`attach_outbound`, write-locked during
/// `mount_onto`/`unmount_from` so concurrent attachments can never land in the wrong registry
/// or reinsert an unmounted `ScopeKid` (DG-03).
pub(crate) struct PortSlot {
    standalone: Arc<PortRegistry>,
    state: RwLock<PortSlotState>,
}

impl PortSlot {
    pub fn new(standalone: Arc<PortRegistry>) -> Arc<Self> {
        Arc::new(Self {
            state: RwLock::new(PortSlotState {
                owner_node: None,
                registry: Arc::clone(&standalone),
            }),
            standalone,
        })
    }

    pub fn standalone(&self) -> &Arc<PortRegistry> {
        &self.standalone
    }

    /// Serializes inbound attachment against concurrent mount/unmount transitions (DG-03),
    /// spawning any newly created receive pump strictly AFTER releasing all locks.
    pub fn attach_inbound(
        &self,
        link: Arc<dyn DatagramLink>,
        scope: Arc<ScopeCore>,
    ) -> Result<DatagramIngress, CoreError> {
        let (ingress, to_spawn) = {
            let st = read_unpoisoned(&self.state);
            if scope.pending.is_closed() {
                return Err(CoreError::Closed);
            }
            st.registry
                .attach_inbound_prepared(link, Some(scope), false)?
        };
        if let Some((spawner, port)) = to_spawn {
            spawner.spawn(Box::pin(port.run_pump()));
        }
        Ok(ingress)
    }

    /// Serializes outbound attachment against concurrent mount/unmount transitions (DG-03),
    /// spawning any newly created receive pump strictly AFTER releasing all locks.
    pub fn attach_outbound(
        &self,
        link: Arc<dyn DatagramLink>,
    ) -> Result<(Arc<DatagramPort>, OutboundPortHold), CoreError> {
        let (res, to_spawn) = {
            let st = read_unpoisoned(&self.state);
            st.registry.attach_outbound_prepared(link)?
        };
        if let Some((spawner, port)) = to_spawn {
            spawner.spawn(Box::pin(port.run_pump()));
        }
        Ok(res)
    }

    /// Atomically adopts standalone ports into `target`, switches this slot to `target`,
    /// and invokes `on_committed` under the exclusive write lock (DG-03).
    pub fn mount_onto(
        &self,
        node_id: u64,
        target: &Arc<PortRegistry>,
        on_committed: impl FnOnce(),
    ) -> Result<(), CoreError> {
        let mut st = write_unpoisoned(&self.state);
        if st.owner_node.is_some() {
            return Err(CoreError::AlreadyPublished);
        }
        target.adopt_from(&self.standalone)?;
        st.owner_node = Some(node_id);
        st.registry = Arc::clone(target);
        on_committed();
        Ok(())
    }

    /// Atomically detaches `kid` from `node_ports`, records weak ownership handoff for any
    /// still-live `Node` ports (R2-DG-02), clears the standalone adoption redirect, and restores
    /// standalone routing under the exclusive write lock (DG-03/05/06).
    pub fn unmount_from(&self, node_id: u64, kid: ScopeKid, node_ports: &Arc<PortRegistry>) {
        let mut st = write_unpoisoned(&self.state);
        if st.owner_node != Some(node_id) {
            return;
        }
        let live_ports = node_ports.detach_scope_and_snapshot(kid);
        self.standalone.record_prior_registry(node_ports);
        self.standalone.record_observed_live_ports(live_ports);
        self.standalone.clear_adopted_by();
        st.owner_node = None;
        st.registry = Arc::clone(&self.standalone);
    }

    /// Restores standalone routing during `Node::drop` (after `node_ports.shutdown_ingress()`),
    /// preserving live `outbound_refs > 0` port coordination and unexpired CID quarantine histories.
    pub fn unmount_from_dropped_node(&self, node_id: u64, node_ports: &Arc<PortRegistry>) {
        let mut st = write_unpoisoned(&self.state);
        if st.owner_node != Some(node_id) {
            return;
        }
        let snapshot = node_ports.snapshot_live_and_retired();
        let now = self.standalone.clock.now();
        self.standalone.record_observed_live_ports(snapshot.live_ports);
        self.standalone.merge_retired_slabs(snapshot.retired_slabs, now);
        self.standalone.clear_adopted_by();
        st.owner_node = None;
        st.registry = Arc::clone(&self.standalone);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use core::task::Context;
    use std::sync::Barrier;
    use std::thread;

    use super::*;
    use crate::seam::channel::ChannelCaps;
    use crate::testing::{MemoryDatagramPair, TestRuntime};

    struct NoopResolver;
    impl ScopeResolver for NoopResolver {
        fn resolve(&self, _kid: ScopeKid) -> Option<Arc<ScopeCore>> {
            None
        }
        fn record_unknown_scope(&self) {}
        fn record_mac1_drop(&self, _matched_scope: Option<&ScopeCore>) {}
    }

    struct NoopSetupHandler;
    impl DatagramSetupHandler for NoopSetupHandler {
        fn spawn_setup(
            &self,
            _scope: Arc<ScopeCore>,
            _port: Arc<DatagramPort>,
            _wire: Vec<u8>,
            _receipt: Option<FragmentReceipt>,
            _attempt: AdmissionAttempt,
            _pending_permit: PendingPermit,
            _node_pending_permit: Option<NodePendingPermit>,
        ) {
        }
    }

    struct ThreadWaker(thread::Thread);
    impl std::task::Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }

    fn thread_block_on<F: Future>(fut: F) -> F::Output {
        let mut fut = core::pin::pin!(fut);
        let waker = std::task::Waker::from(Arc::new(ThreadWaker(thread::current())));
        let mut cx = Context::from_waker(&waker);
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(out) => return out,
                Poll::Pending => thread::park(),
            }
        }
    }

    /// Minimal thread-safe spawner executing tasks on real OS threads for true parallel
    /// lock-contention stress testing (`R2-DG-01`).
    struct ThreadSpawner;
    impl TaskSpawner for ThreadSpawner {
        fn spawn(&self, fut: crate::runtime::BoxFuture<'static, ()>) {
            thread::spawn(move || {
                thread_block_on(fut);
            });
        }
    }

    struct TriggerFailLink {
        id: LinkId,
        state: Mutex<(Option<CoreError>, Option<core::task::Waker>)>,
    }

    impl TriggerFailLink {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                id: LinkId::allocate(),
                state: Mutex::new((None, None)),
            })
        }

        fn trigger_fail(&self, err: CoreError) {
            let waker = {
                let mut st = lock_unpoisoned(&self.state);
                st.0 = Some(err);
                st.1.take()
            };
            if let Some(w) = waker {
                w.wake();
            }
        }
    }

    impl DatagramLink for TriggerFailLink {
        fn caps(&self) -> ChannelCaps {
            ChannelCaps::fixed(1_500, false)
        }

        fn poll_send_ready(&self, _cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
            Poll::Ready(Ok(()))
        }

        fn try_send(&self, _packet: PacketBuf) -> Result<(), CoreError> {
            Ok(())
        }

        fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<PacketBuf, CoreError>> {
            let mut st = lock_unpoisoned(&self.state);
            if let Some(err) = st.0.clone() {
                return Poll::Ready(Err(err));
            }
            st.1 = Some(cx.waker().clone());
            Poll::Pending
        }

        fn link_id(&self) -> LinkId {
            self.id
        }
    }

    /// R2-DG-01: Racing `DatagramPort::bind()` against fatal carrier teardown across real OS
    /// threads MUST NEVER AB/BA deadlock (`state` Level 3 -> `slab` Level 4 everywhere!).
    #[test]
    fn regression_r2_dg01_bind_racing_carrier_teardown_never_deadlocks() {
        let tr = TestRuntime::new();
        let metrics = Arc::new(ScopeMetrics::new());
        let reg = PortRegistry::new(
            64,
            PortMetricOwner::Scope(metrics),
            Arc::clone(&tr.runtime.clock),
            Arc::new(ThreadSpawner),
            Arc::new(NoopResolver),
            Arc::new(NoopSetupHandler),
            None,
        );

        for iter in 0..150 {
            let link = TriggerFailLink::new();
            let (port, hold) = reg.attach_outbound(Arc::clone(&link) as Arc<dyn DatagramLink>).unwrap();
            let ing = port.ingress();
            let barrier = Arc::new(Barrier::new(2));

            let b1 = Arc::clone(&barrier);
            let p1 = Arc::clone(&port);
            let t_bind = thread::spawn(move || {
                b1.wait();
                let mut saw_fatal = false;
                for _ in 0..256 {
                    match p1.bind(None) {
                        Ok(binding) => drop(binding),
                        Err(err) => {
                            assert_eq!(err, CoreError::Carrier("r2-dg01-fail".into()));
                            saw_fatal = true;
                            break;
                        }
                    }
                }
                saw_fatal
            });

            let b2 = Arc::clone(&barrier);
            let l2 = Arc::clone(&link);
            let t_fail = thread::spawn(move || {
                b2.wait();
                if iter % 2 == 0 {
                    thread::yield_now();
                }
                l2.trigger_fail(CoreError::Carrier("r2-dg01-fail".into()));
            });

            t_fail.join().unwrap();
            let _ = t_bind.join().unwrap();
            let close_err = thread_block_on(ing.closed());
            drop(hold);
            assert_eq!(close_err, CoreError::Carrier("r2-dg01-fail".into()));
        }
    }

    /// R2-DG-03: With a 1-port limit (`max_entries = 64`), retiring 63+ other used links MUST
    /// NEVER evict a recently retired link's unexpired 60-second CID wrap quarantine history.
    /// Instead, new unrelated LinkIds experience `CoreError::Busy` backpressure until expired,
    /// while reattaching the original link restores its exact quarantined slab!
    #[test]
    fn regression_r2_dg03_retired_slab_cache_never_evicts_unexpired_quarantine() {
        let tr = TestRuntime::new();
        let metrics = Arc::new(ScopeMetrics::new());
        let reg = PortRegistry::new(
            1,
            PortMetricOwner::Scope(Arc::clone(&metrics)),
            Arc::clone(&tr.runtime.clock),
            Arc::clone(&tr.runtime.spawner),
            Arc::new(NoopResolver),
            Arc::new(NoopSetupHandler),
            None,
        );

        // 1. Attach `link_0`, wrap slot 0 through all 255 generations (1..=255 -> 60 s quarantine),
        //    and retire `link_0` at t = 0.
        let link_0 = MemoryDatagramPair::pair(1_500).a;
        {
            let (port0, hold0) = reg
                .attach_outbound(Arc::clone(&link_0) as Arc<dyn DatagramLink>)
                .unwrap();
            for generation in 1..=255u8 {
                let b = port0.bind(None).unwrap();
                assert_eq!((b.cid().slot(), b.cid().generation()), (0, generation));
                drop(b);
            }
            drop(hold0);
        }
        tr.drive_until_idle();
        assert_eq!(metrics.snapshot().active_datagram_ports, 0);

        // 2. At t = 1 s, attach, bind once, and retire 63 other distinct links (filling all 64
        //    slots of the retired history budget without expiring `link_0`).
        tr.advance_and_drive(Duration::from_secs(1));
        for _ in 0..63 {
            let other = MemoryDatagramPair::pair(1_500).a;
            let (port, hold) = reg
                .attach_outbound(Arc::clone(&other) as Arc<dyn DatagramLink>)
                .unwrap();
            let b = port.bind(None).unwrap();
            drop(b);
            drop(hold);
            tr.drive_until_idle();
        }
        assert_eq!(metrics.snapshot().active_datagram_ports, 0);

        // 3. At t = 2 s, attaching a 65th brand-new unrelated LinkId MUST fail with `Busy`
        //    rather than evicting `link_0`'s unexpired 60 s quarantine history!
        tr.advance_and_drive(Duration::from_secs(1));
        let link_64 = MemoryDatagramPair::pair(1_500).a;
        let err = reg
            .attach_outbound(Arc::clone(&link_64) as Arc<dyn DatagramLink>)
            .err();
        assert_eq!(
            err,
            Some(CoreError::Busy),
            "R2-DG-03: saturated unexpired quarantine cache MUST return Busy instead of evicting"
        );

        // 4. At t = 30 s (still inside 60 s quarantine!), reattaching `link_0` MUST SUCCEED
        //    (consuming its own entry) AND allocate `slot = 1`, NEVER reissuing quarantined slot 0!
        tr.advance_and_drive(Duration::from_secs(28));
        {
            let (port0_reattached, hold0) = reg
                .attach_outbound(Arc::clone(&link_0) as Arc<dyn DatagramLink>)
                .expect("R2-DG-03: reattaching cached LinkId MUST succeed");
            let b = port0_reattached.bind(None).unwrap();
            assert_eq!(
                (b.cid().slot(), b.cid().generation()),
                (1, 1),
                "R2-DG-03: quarantined slot 0 MUST NOT be reissued before 60 s elapses!"
            );
            drop(b);
            drop(hold0);
        }
        tr.drive_until_idle();

        // 5. After t = 62 s (> 60 s after the 63 other links retired at t = 1 s), expired entries
        //    are pruned and brand-new `link_64` now attaches cleanly!
        tr.advance_and_drive(Duration::from_secs(32));
        let (_port64, hold64) = reg
            .attach_outbound(Arc::clone(&link_64) as Arc<dyn DatagramLink>)
            .expect("R2-DG-03: unrelated LinkId MUST succeed once prior quarantine histories expire");
        drop(hold64);
        tr.drive_until_idle();
    }
}
