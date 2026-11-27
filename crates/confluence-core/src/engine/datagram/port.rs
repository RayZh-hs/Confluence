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
//! - Level 3: `DatagramPort::state`
//! - Level 4: `DatagramPort::slab` (leaf lock)
//!
//! Never invoke `TaskSpawner::spawn`, `ScopeResolver`, or drop `PortPermit`/`Arc<ScopeCore>`
//! while holding registry or port locks.

use core::future::{Future, poll_fn};
use core::task::Poll;
use core::time::Duration;
use std::collections::{HashMap, VecDeque};
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
    pub fn bind(
        self: &Arc<Self>,
        metrics: Option<Arc<ScopeMetrics>>,
    ) -> Result<Binding, CoreError> {
        let hold = self.try_acquire_outbound_hold()?;
        let (tx, rx) = async_channel::bounded::<PacketBuf>(DATAGRAM_MAILBOX_CAP);
        let cid = {
            let mut slab = lock_unpoisoned(&self.slab);
            slab.insert(MailboxEntry { tx, metrics }, self.clock.now())?
        };
        // Re-check closing in case a fatal carrier error raced between acquiring `hold` and inserting.
        if self.is_closing() {
            let mut slab = lock_unpoisoned(&self.slab);
            let _ = slab.remove(cid, self.clock.now());
            return Err(self.terminal_err());
        }
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
                let _ = lock_unpoisoned(&self.slab).drain_to_history(self.clock.now());
                let mut st = lock_unpoisoned(&self.state);
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
// Bounded Per-LinkId Retired Slab Generation Cache (DG-07, Spec §6.5)
// ---------------------------------------------------------------------------

struct RetiredSlabCache {
    entries: HashMap<LinkId, SlabHistory>,
    order: VecDeque<(LinkId, MonotonicTime)>,
    max_entries: usize,
}

impl RetiredSlabCache {
    fn new(max_ports: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            max_entries: max_ports.saturating_mul(4).clamp(64, 16_384),
        }
    }

    fn prune(&mut self, now: MonotonicTime) {
        while let Some((_, ts)) = self.order.front() {
            let expired = self
                .entries
                .get(&self.order[0].0)
                .is_none_or(|h| h.retired_at() != *ts || h.is_expired(now));
            if expired {
                if let Some((id, retired_at)) = self.order.pop_front() {
                    if self
                        .entries
                        .get(&id)
                        .is_some_and(|h| h.retired_at() == retired_at && h.is_expired(now))
                    {
                        self.entries.remove(&id);
                    }
                }
            } else {
                break;
            }
        }
    }

    fn insert(&mut self, link_id: LinkId, history: SlabHistory, now: MonotonicTime) {
        if history.is_empty() {
            return;
        }
        self.prune(now);
        let ts = history.retired_at();
        self.entries.insert(link_id, history);
        self.order.push_back((link_id, ts));

        while self.entries.len() > self.max_entries
            || self.order.len() > self.max_entries.saturating_mul(2)
        {
            let Some((old_id, old_ts)) = self.order.pop_front() else {
                break;
            };
            if self
                .entries
                .get(&old_id)
                .is_some_and(|h| h.retired_at() == old_ts)
            {
                self.entries.remove(&old_id);
            }
        }
    }

    fn take(&mut self, link_id: LinkId, now: MonotonicTime) -> Option<SlabHistory> {
        self.prune(now);
        self.entries
            .remove(&link_id)
            .filter(|h| !h.is_expired(now))
    }

    fn drain_into(
        &mut self,
        dst: &mut Self,
        active_in_dst: &HashMap<LinkId, Arc<DatagramPort>>,
        now: MonotonicTime,
    ) {
        self.prune(now);
        dst.prune(now);
        self.order.clear();
        for (link_id, hist) in self.entries.drain() {
            if !hist.is_expired(now)
                && !active_in_dst.contains_key(&link_id)
                && !dst.entries.contains_key(&link_id)
            {
                dst.insert(link_id, hist, now);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PortRegistry & PortSlot (Deduplication & Atomic Node Adoption, Spec §8.2)
// ---------------------------------------------------------------------------

struct RegistryInner {
    ports: HashMap<LinkId, Arc<DatagramPort>>,
    retired_slabs: RetiredSlabCache,
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
}

/// Registry deduplicating active [`DatagramPort`]s by [`LinkId`] (Lock Level 2).
pub(crate) struct PortRegistry {
    inner: Mutex<RegistryInner>,
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
                adopted_by: None,
                ingress_closed: false,
            }),
            port_sem: CloseableSemaphore::new(cap),
            metric_owner,
            clock,
            spawner,
            resolver,
            setup_handler,
            node_pending,
        })
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
        let redirect = {
            let mut reg = lock_unpoisoned(&self.inner);
            if let Some(target) = reg.adopted_by.as_ref().and_then(Weak::upgrade) {
                Some(target)
            } else {
                if reg.ingress_closed {
                    return Err(CoreError::Closed);
                }

                let now = self.clock.now();
                if let Some(existing) = reg.ports.get(&link_id).cloned() {
                    let mut st = lock_unpoisoned(&existing.state);
                    if st.closing {
                        let hist = lock_unpoisoned(&existing.slab).drain_to_history(now);
                        reg.ports.remove(&link_id);
                        reg.retired_slabs.insert(link_id, hist, now);
                        st.owner = Weak::new();
                        let stale_permit = st.port_permit.take();
                        drop(st);
                        drop(stale_permit);
                    } else {
                        if node_wide {
                            st.node_wide = true;
                        }
                        if let Some(sc) = scope {
                            st.scopes.insert(sc.keypair.scope_kid(), sc);
                        }
                        existing
                            .has_inbound
                            .store(st.has_inbound_ownership(), Ordering::SeqCst);
                        return Ok((existing.ingress(), None));
                    }
                }

                let permit = PortPermit::acquire(&self.port_sem, &self.metric_owner)?;
                let mut scopes = HashMap::new();
                if let Some(sc) = scope {
                    scopes.insert(sc.keypair.scope_kid(), sc);
                }
                let has_inbound_now = node_wide || !scopes.is_empty();
                let slab = match reg.retired_slabs.take(link_id, now) {
                    Some(hist) => SlabTable::from_history(hist),
                    None => SlabTable::new(),
                };

                let (closed_tx, _) = Watch::new(None::<CoreError>);
                let (stop_tx, _) = Watch::new(0u64);
                let port = Arc::new(DatagramPort {
                    link,
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
                reg.ports.insert(link_id, Arc::clone(&port));
                return Ok((ingress, Some((Arc::clone(&self.spawner), port))));
            }
        };

        match redirect {
            Some(target) => target.attach_inbound_prepared(link, scope, node_wide),
            None => Err(CoreError::Closed),
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
        let redirect = {
            let mut reg = lock_unpoisoned(&self.inner);
            if let Some(target) = reg.adopted_by.as_ref().and_then(Weak::upgrade) {
                Some(target)
            } else {
                if reg.ingress_closed {
                    return Err(CoreError::Closed);
                }

                let now = self.clock.now();
                if let Some(existing) = reg.ports.get(&link_id).cloned() {
                    let mut st = lock_unpoisoned(&existing.state);
                    if st.closing {
                        let hist = lock_unpoisoned(&existing.slab).drain_to_history(now);
                        reg.ports.remove(&link_id);
                        reg.retired_slabs.insert(link_id, hist, now);
                        st.owner = Weak::new();
                        let stale_permit = st.port_permit.take();
                        drop(st);
                        drop(stale_permit);
                    } else {
                        existing.outbound_refs.fetch_add(1, Ordering::SeqCst);
                        let hold = OutboundPortHold {
                            port: Arc::clone(&existing),
                        };
                        drop(st);
                        return Ok(((existing, hold), None));
                    }
                }

                let permit = PortPermit::acquire(&self.port_sem, &self.metric_owner)?;
                let slab = match reg.retired_slabs.take(link_id, now) {
                    Some(hist) => SlabTable::from_history(hist),
                    None => SlabTable::new(),
                };
                let (closed_tx, _) = Watch::new(None::<CoreError>);
                let (stop_tx, _) = Watch::new(0u64);
                let port = Arc::new(DatagramPort {
                    link,
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
                reg.ports.insert(link_id, Arc::clone(&port));
                return Ok(((Arc::clone(&port), hold), Some((Arc::clone(&self.spawner), port))));
            }
        };

        match redirect {
            Some(target) => target.attach_outbound_prepared(link),
            None => Err(CoreError::Closed),
        }
    }

    /// Acquires an existing LIVE [`DatagramPort`] by `link_id` without invoking `handler.open()`.
    ///
    /// Used by Datagram Transit cookie-retry link reuse (DG-10) so carriers that mint a fresh
    /// `source_tag` per `open()` call still reuse the exact challenged link held by
    /// [`hold_for_cookie_retry`].
    pub fn acquire_live_outbound(
        self: &Arc<Self>,
        link_id: LinkId,
    ) -> Option<(Arc<DatagramPort>, OutboundPortHold)> {
        let redirect = {
            let reg = lock_unpoisoned(&self.inner);
            if let Some(target) = reg.adopted_by.as_ref().and_then(Weak::upgrade) {
                Some(target)
            } else if reg.ingress_closed {
                return None;
            } else if let Some(existing) = reg.ports.get(&link_id) {
                let st = lock_unpoisoned(&existing.state);
                if st.closing {
                    return None;
                }
                existing.outbound_refs.fetch_add(1, Ordering::SeqCst);
                return Some((
                    Arc::clone(existing),
                    OutboundPortHold {
                        port: Arc::clone(existing),
                    },
                ));
            } else {
                return None;
            }
        };
        redirect.and_then(|target| target.acquire_live_outbound(link_id))
    }

    /// Atomically adopts all live ports from a standalone scope's `PortRegistry` into `self`
    /// (`Node`'s `PortRegistry`, Spec §8.2 Rule 4, DG-04, DG-07).
    ///
    /// Prunes closing ports, validates non-conflicting `LinkId`s (`AlreadyPublished`) and
    /// `max_datagram_ports` capacity (`Busy`) BEFORE mutating either registry, ensuring zero
    /// partial mutation on error.
    pub fn adopt_from(self: &Arc<Self>, source: &PortRegistry) -> Result<(), CoreError> {
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
                dst.ports.insert(link_id, port);
            }

            // Preserve any recent retired-CID histories across scope adoption (DG-07).
            let dst_inner = &mut *dst;
            src.retired_slabs
                .drain_into(&mut dst_inner.retired_slabs, &dst_inner.ports, now);
            src.adopted_by = Some(Arc::downgrade(self));
            Ok(())
        };

        drop(dropped_permits);
        drop(dropped_scopes);
        res
    }

    /// Clears the standalone registry's adoption redirect (called on unmount / `Node` drop).
    pub fn clear_adopted_by(&self) {
        lock_unpoisoned(&self.inner).adopted_by = None;
    }

    /// Removes `kid` from every port's explicit scope list (called by `Node::remove_scope`,
    /// Spec §8.2) and immediately retires any port that no longer has inbound ownership or
    /// active outbound holds so port capacity is never stranded (DG-06).
    pub fn detach_scope(&self, kid: ScopeKid) {
        let now = self.clock.now();
        let mut dropped_permits: Vec<PortPermit> = Vec::new();
        let mut dropped_scopes: Vec<Arc<ScopeCore>> = Vec::new();
        let mut to_wake: Vec<Arc<DatagramPort>> = Vec::new();

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

    /// Atomically detaches `kid` from `node_ports` (if provided), clears the standalone
    /// adoption redirect, and restores standalone routing under the exclusive write lock (DG-03/05/06).
    pub fn unmount_from(&self, node_id: u64, kid: ScopeKid, node_ports: Option<&PortRegistry>) {
        let mut st = write_unpoisoned(&self.state);
        if st.owner_node != Some(node_id) {
            return;
        }
        if let Some(ports) = node_ports {
            ports.detach_scope(kid);
        }
        self.standalone.clear_adopted_by();
        st.owner_node = None;
        st.registry = Arc::clone(&self.standalone);
    }
}
