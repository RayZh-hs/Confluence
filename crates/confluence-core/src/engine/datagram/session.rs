//! End-to-end encrypted Datagram session (`E2eDatagram`) and steady-state worker
//! driving live Path MTU agreement, idempotent in-band lease renewal, and `TrafficGate` (Spec §5.7.1, §5.8.1, §6.5–6.7).

use core::fmt;
use core::future::{Future, poll_fn};
use core::pin::Pin;
use core::task::Poll;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};

use futures_core::Stream as FuturesStream;
use futures_util::stream::FuturesUnordered;
use rand_core::OsRng;

use crate::constants::{
    CREDENTIAL_MAX, DATAGRAM_SESSION_QUEUE_CAP, DG_OVERHEAD, MAX_WIRE_LEASE_TTL,
};
use crate::crypto::cipher::{ControlCipher, DatagramRx, DatagramTx};
use crate::engine::context::{
    CredFetchFut, RenewalAuthFut, ScopeCore, SessionPermit, poll_optional, sleep_optional,
    wait_mtu_change, wait_shutdown, with_deadline,
};
use crate::engine::datagram::port::Binding;
use crate::error::CoreError;
use crate::packet::PacketBuf;
use crate::protocol::mtu::{DestPathMtu, MtuChange, MtuReporter, OriginPathMtu};
use crate::protocol::renewal::{
    CredentialFetchOutcome, RenewalAction, RenewalDriver, RenewalSlot, RenewalVerifierState,
    VerifierRenewalAction,
};
use crate::runtime::sync::{CloseableSemaphore, SemaphorePermit, Watch, WatchReceiver};
use crate::seam::auth::{AuthRequest, CredentialRequest, DatagramAction, Lease};
use crate::seam::channel::MtuWatch;
use crate::seam::path::PathOutcome;
use crate::trust::lease::{LeaseHandle, TrafficGateCache};
use crate::types::{Cid, Credential, Direction, Plane, PublicKey, Role, TargetRef};
use crate::wire::datagram::{
    DgHopControlHeader, decode_mtu_ack_payload, decode_mtu_payload, decode_renew_ok_payload,
    decode_renew_payload, encode_mtu_ack_payload, encode_mtu_payload, encode_renew_ok_payload,
    encode_renew_payload, prepend_dg_data_header, strip_dg_data_header,
};
use crate::wire::opcodes::{decode_wire_error_bytes, e2e_dg, encode_wire_error_bytes, outer};

// ---------------------------------------------------------------------------
// Public `E2eDatagram` Handle
// ---------------------------------------------------------------------------

struct QueuedOutbound {
    pkt: PacketBuf,
    _permit: SemaphorePermit,
}

/// Established end-to-end encrypted discrete datagram session (Datagram Plane).
///
/// Oversized outbound sends fail synchronously with [`CoreError::MessageTooLarge`] without
/// transmitting on the wire or closing the session (Spec §6.5).
#[derive(Clone)]
pub struct E2eDatagram {
    tx_sem: Arc<CloseableSemaphore>,
    tx_queue: async_channel::Sender<QueuedOutbound>,
    rx_queue: async_channel::Receiver<PacketBuf>,
    current_mtu: Arc<AtomicU16>,
    max_payload: Arc<AtomicUsize>,
    closed_rx: WatchReceiver<Option<CoreError>>,
    close_req: Watch<bool>,
    peer: PublicKey,
}

impl E2eDatagram {
    /// Returns the authenticated remote peer's static public key.
    #[must_use]
    pub const fn peer(&self) -> PublicKey {
        self.peer
    }

    /// Returns the live authenticated wire path MTU across all legs.
    #[must_use]
    pub fn mtu(&self) -> u16 {
        self.current_mtu.load(Ordering::Acquire)
    }

    /// Returns the live maximum application payload bytes (`mtu.saturating_sub(30)`).
    #[must_use]
    pub fn max_payload(&self) -> usize {
        self.max_payload.load(Ordering::Acquire)
    }

    fn terminal_err(&self) -> CoreError {
        self.closed_rx.borrow_cloned().unwrap_or(CoreError::Closed)
    }

    /// Non-blocking datagram send (Spec §6.5).
    ///
    /// - Fails synchronously with [`CoreError::MessageTooLarge`] if `pkt.len() > max_payload`
    ///   without transmitting or closing the session.
    /// - Fails with [`CoreError::WouldBlock`] if the 16-packet outbound queue is full.
    pub fn send(&self, pkt: PacketBuf) -> Result<(), CoreError> {
        let max = self.max_payload();
        if pkt.len() > max {
            return Err(CoreError::MessageTooLarge(max));
        }
        let permit = match self.tx_sem.try_acquire() {
            Ok(p) => p,
            Err(CoreError::Busy) => return Err(CoreError::WouldBlock),
            Err(_) => return Err(self.terminal_err()),
        };
        self.tx_queue
            .try_send(QueuedOutbound {
                pkt,
                _permit: permit,
            })
            .map_err(|_| self.terminal_err())
    }

    /// Awaits outbound queue capacity, re-checks live `max_payload`, and enqueues `pkt` (Spec §6.5).
    pub async fn send_wait(&self, pkt: PacketBuf) -> Result<(), CoreError> {
        let max = self.max_payload();
        if pkt.len() > max {
            return Err(CoreError::MessageTooLarge(max));
        }
        let permit = self
            .tx_sem
            .acquire()
            .await
            .map_err(|_| self.terminal_err())?;
        // Re-check live max_payload after awaiting capacity (Spec §6.5).
        let max_after = self.max_payload();
        if pkt.len() > max_after {
            return Err(CoreError::MessageTooLarge(max_after));
        }
        self.tx_queue
            .try_send(QueuedOutbound {
                pkt,
                _permit: permit,
            })
            .map_err(|_| self.terminal_err())
    }

    /// Receives the next authenticated inbound application datagram.
    pub async fn recv(&self) -> Result<PacketBuf, CoreError> {
        self.rx_queue
            .recv()
            .await
            .map_err(|_| self.terminal_err())
    }

    /// Cleanly initiates session teardown with [`CoreError::Closed`].
    pub fn close(&self) {
        self.tx_sem.close();
        self.close_req.send(true);
    }

    pub(crate) fn subscribe_closed(&self) -> WatchReceiver<Option<CoreError>> {
        self.closed_rx.clone()
    }
}

impl fmt::Debug for E2eDatagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("E2eDatagram")
            .field("peer", &self.peer)
            .field("mtu", &self.mtu())
            .field("max_payload", &self.max_payload())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Datagram Session Role Configuration & Spawner
// ---------------------------------------------------------------------------

pub(crate) struct OriginDatagramMeta {
    pub path_id: u64,
    pub endpoint: String,
    pub hops: Vec<(PublicKey, String, ControlCipher)>,
    pub renewals: RenewalDriver,
    pub path_mtu: OriginPathMtu,
}

pub(crate) struct DestDatagramMeta {
    pub endpoint: String,
    pub path_mtu: DestPathMtu,
    pub initial_local_mtu: u16,
    pub first_packet: Option<PacketBuf>,
}

pub(crate) enum DatagramSessionRole {
    Origin(OriginDatagramMeta),
    Destination(DestDatagramMeta),
}

pub(crate) struct DatagramSessionParams {
    pub scope: Arc<ScopeCore>,
    pub peer: PublicKey,
    pub binding: Binding,
    pub remote_cid: Cid,
    pub mtu_watch: MtuWatch,
    pub tx: DatagramTx,
    pub rx: DatagramRx,
    pub lease: Arc<LeaseHandle>,
    pub session_permit: SessionPermit,
    pub role: DatagramSessionRole,
}

/// Spawns the steady-state E2E Datagram worker and returns the [`E2eDatagram`] handle.
pub(crate) fn spawn_datagram_session(params: DatagramSessionParams) -> E2eDatagram {
    let initial_mtu = match &params.role {
        DatagramSessionRole::Origin(o) => o.path_mtu.current_mtu(),
        DatagramSessionRole::Destination(d) => d.path_mtu.current_mtu(),
    };
    let initial_max_payload = usize::from(initial_mtu).saturating_sub(DG_OVERHEAD);

    let tx_sem = CloseableSemaphore::new(DATAGRAM_SESSION_QUEUE_CAP);
    let (tx_queue, tx_rx) = async_channel::bounded::<QueuedOutbound>(DATAGRAM_SESSION_QUEUE_CAP);
    let (rx_tx, rx_queue) = async_channel::bounded::<PacketBuf>(DATAGRAM_SESSION_QUEUE_CAP);
    let current_mtu = Arc::new(AtomicU16::new(initial_mtu));
    let max_payload = Arc::new(AtomicUsize::new(initial_max_payload));
    let (closed_tx, closed_rx) = Watch::new(None::<CoreError>);
    let (close_req, close_req_rx) = Watch::new(false);

    let peer = params.peer;
    let spawner = Arc::clone(&params.scope.runtime.spawner);
    let handle = E2eDatagram {
        tx_sem: Arc::clone(&tx_sem),
        tx_queue,
        rx_queue,
        current_mtu: Arc::clone(&current_mtu),
        max_payload: Arc::clone(&max_payload),
        closed_rx,
        close_req,
        peer,
    };

    spawner.spawn(Box::pin(async move {
        run_datagram_session(
            params,
            tx_sem,
            tx_rx,
            rx_tx,
            current_mtu,
            max_payload,
            closed_tx,
            close_req_rx,
        )
        .await;
    }));

    handle
}

#[allow(clippy::too_many_arguments)]
async fn run_datagram_session(
    params: DatagramSessionParams,
    tx_sem: Arc<CloseableSemaphore>,
    tx_rx: async_channel::Receiver<QueuedOutbound>,
    rx_tx: async_channel::Sender<PacketBuf>,
    current_mtu: Arc<AtomicU16>,
    max_payload: Arc<AtomicUsize>,
    closed_tx: Watch<Option<CoreError>>,
    mut close_req_rx: WatchReceiver<bool>,
) {
    let DatagramSessionParams {
        scope,
        peer,
        binding,
        remote_cid,
        mut mtu_watch,
        mut tx,
        mut rx,
        lease,
        session_permit: _session_permit,
        mut role,
    } = params;

    let clock = Arc::clone(&scope.runtime.clock);
    let role_enum = match &role {
        DatagramSessionRole::Origin(_) => Role::Origin,
        DatagramSessionRole::Destination(_) => Role::Destination,
    };
    let span = scope.session_span(Plane::Datagram, role_enum);

    // Pre-seed Destination's 1.0 RTT initial datagram (already TrafficGate-checked in serve.rs).
    if let DatagramSessionRole::Destination(ref mut dest) = role {
        if let Some(first) = dest.first_packet.take() {
            scope
                .metrics
                .record_rx(Plane::Datagram, first.len() as u64, true);
            if rx_tx.try_send(first).is_err() {
                scope
                    .metrics
                    .queue_drops_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    // DG-12: Origin starts with an unadvertised `MtuReporter::new()` because Destination only
    // observed cleartext `ForwardHeader.max_mtu` on the forward flight, not the authenticated
    // reverse `SETUP_OK` hop trailers. Origin reliably advertises its authenticated path minimum
    // on startup (with `[150, 300, 600, 1200, 2400]` ms retries until ACKed).
    let mut e2e_mtu_reporter = match &role {
        DatagramSessionRole::Origin(_) => MtuReporter::new(),
        DatagramSessionRole::Destination(d) => MtuReporter::with_initial(d.initial_local_mtu),
    };

    let mut shutdown_rx = scope.subscribe_shutdown();
    let mut gate_cache = TrafficGateCache::new();
    let mut cred_futs: FuturesUnordered<CredFetchFut> = FuturesUnordered::new();
    let mut dest_verifier = RenewalVerifierState::new();
    let mut dest_auth_fut: Option<RenewalAuthFut> = None;

    // Startup live MtuWatch sample catching link shifts between SETUP_OK and confirm (Spec §6.6, DG-12/13).
    let startup_err: Option<CoreError> = {
        let now = clock.now();
        let live_local = mtu_watch.sample();
        match &mut role {
            DatagramSessionRole::Origin(orig) => {
                let change = orig.path_mtu.update_local(live_local);
                match change {
                    MtuChange::BelowFloor(m) => Some(CoreError::MtuTooSmall(m)),
                    MtuChange::Changed(m) => {
                        apply_effective_mtu(&current_mtu, &max_payload, m, &scope);
                        scope
                            .path_source
                            .report_outcome(orig.path_id, PathOutcome::MtuChanged { mtu: m });
                        if let Some((ep, advertised)) = e2e_mtu_reporter.publish(m, now) {
                            match send_e2e_control(
                                &binding,
                                remote_cid,
                                &mut tx,
                                e2e_dg::DG_MTU,
                                &encode_mtu_payload(ep, advertised),
                            ) {
                                Err(err) if !err.is_retryable() => Some(err),
                                _ => None,
                            }
                        } else {
                            None
                        }
                    }
                    MtuChange::Unchanged => {
                        let effective = orig.path_mtu.current_mtu();
                        if let Some((ep, advertised)) = e2e_mtu_reporter.publish(effective, now) {
                            match send_e2e_control(
                                &binding,
                                remote_cid,
                                &mut tx,
                                e2e_dg::DG_MTU,
                                &encode_mtu_payload(ep, advertised),
                            ) {
                                Err(err) if !err.is_retryable() => Some(err),
                                _ => None,
                            }
                        } else {
                            None
                        }
                    }
                }
            }
            DatagramSessionRole::Destination(dest) => {
                let change = dest.path_mtu.update_local(live_local);
                let mut send_fatal = None;
                if let Some((ep, advertised)) = e2e_mtu_reporter.publish(live_local, now) {
                    if let Err(err) = send_e2e_control(
                        &binding,
                        remote_cid,
                        &mut tx,
                        e2e_dg::DG_MTU,
                        &encode_mtu_payload(ep, advertised),
                    ) {
                        if !err.is_retryable() {
                            send_fatal = Some(err);
                        }
                    }
                }
                match change {
                    MtuChange::BelowFloor(m) => Some(CoreError::MtuTooSmall(m)),
                    MtuChange::Changed(m) => {
                        apply_effective_mtu(&current_mtu, &max_payload, m, &scope);
                        send_fatal
                    }
                    MtuChange::Unchanged => send_fatal,
                }
            }
        }
    };

    let terminal_reason: CoreError = if let Some(err) = startup_err {
        err
    } else {
        let mut prefer_outbound = false;
        loop {
            let renewal_dl = match &role {
                DatagramSessionRole::Origin(o) => o.renewals.next_deadline(),
                DatagramSessionRole::Destination(_) => None,
            };
            let mtu_retry_dl = e2e_mtu_reporter.next_deadline();
            let next_timer = [renewal_dl, mtu_retry_dl].into_iter().flatten().min();

            enum Ev {
                LeaseCancelled(CoreError),
                Shutdown,
                LocalClose,
                MtuChanged(u16),
                Inbound(Result<PacketBuf, CoreError>),
                Outbound(Result<QueuedOutbound, async_channel::RecvError>),
                CredFetched(RenewalSlot, Result<Credential, CoreError>),
                DestAuthDone(u64, Result<Lease, CoreError>),
                TimerFired,
            }

            let ev = {
                let mut l_fut = Box::pin(lease.cancelled());
                let mut sh_fut = Box::pin(wait_shutdown(&mut shutdown_rx));
                let mut cl_fut = Box::pin(wait_shutdown(&mut close_req_rx));
                let mut mtu_fut = Box::pin(wait_mtu_change(&mut mtu_watch));
                let mut in_fut = Box::pin(binding.recv());
                let mut out_fut = Box::pin(tx_rx.recv());
                let mut timer_fut = Box::pin(sleep_optional(&*clock, next_timer));

                poll_fn(|cx| {
                    if let Poll::Ready(err) = l_fut.as_mut().poll(cx) {
                        return Poll::Ready(Ev::LeaseCancelled(err));
                    }
                    if let Poll::Ready(()) = sh_fut.as_mut().poll(cx) {
                        return Poll::Ready(Ev::Shutdown);
                    }
                    if let Poll::Ready(()) = cl_fut.as_mut().poll(cx) {
                        return Poll::Ready(Ev::LocalClose);
                    }
                    if let Poll::Ready((id, res)) = poll_optional(&mut dest_auth_fut, cx) {
                        return Poll::Ready(Ev::DestAuthDone(id, res));
                    }
                    if !cred_futs.is_empty() {
                        if let Poll::Ready(Some((slot, res))) =
                            Pin::new(&mut cred_futs).poll_next(cx)
                        {
                            return Poll::Ready(Ev::CredFetched(slot, res));
                        }
                    }
                    if let Poll::Ready(mtu) = mtu_fut.as_mut().poll(cx) {
                        return Poll::Ready(Ev::MtuChanged(mtu));
                    }
                    if let Poll::Ready(()) = timer_fut.as_mut().poll(cx) {
                        return Poll::Ready(Ev::TimerFired);
                    }
                    // DG-15: Alternate inbound/outbound polling so continuous inbound traffic
                    // cannot starve the application outbound send queue (or vice versa).
                    if prefer_outbound {
                        if let Poll::Ready(item) = out_fut.as_mut().poll(cx) {
                            return Poll::Ready(Ev::Outbound(item));
                        }
                        if let Poll::Ready(pkt) = in_fut.as_mut().poll(cx) {
                            return Poll::Ready(Ev::Inbound(pkt));
                        }
                    } else {
                        if let Poll::Ready(pkt) = in_fut.as_mut().poll(cx) {
                            return Poll::Ready(Ev::Inbound(pkt));
                        }
                        if let Poll::Ready(item) = out_fut.as_mut().poll(cx) {
                            return Poll::Ready(Ev::Outbound(item));
                        }
                    }
                    Poll::Pending
                })
                .await
            };

            match &ev {
                Ev::Inbound(_) => prefer_outbound = true,
                Ev::Outbound(_) => prefer_outbound = false,
                _ => {}
            }

            match ev {
                Ev::LeaseCancelled(err) => break err,
                Ev::Shutdown | Ev::LocalClose => break CoreError::Closed,
                Ev::MtuChanged(new_local_mtu) => {
                    let now = clock.now();
                    match &mut role {
                        DatagramSessionRole::Origin(orig) => {
                            match orig.path_mtu.update_local(new_local_mtu) {
                                MtuChange::BelowFloor(m) => break CoreError::MtuTooSmall(m),
                                MtuChange::Changed(m) => {
                                    apply_effective_mtu(&current_mtu, &max_payload, m, &scope);
                                    scope.path_source.report_outcome(
                                        orig.path_id,
                                        PathOutcome::MtuChanged { mtu: m },
                                    );
                                    if let Some((ep, advertised)) =
                                        e2e_mtu_reporter.publish(m, now)
                                    {
                                        if let Err(err) = send_e2e_control(
                                            &binding,
                                            remote_cid,
                                            &mut tx,
                                            e2e_dg::DG_MTU,
                                            &encode_mtu_payload(ep, advertised),
                                        ) {
                                            if !err.is_retryable() {
                                                break err;
                                            }
                                        }
                                    }
                                }
                                MtuChange::Unchanged => {}
                            }
                        }
                        DatagramSessionRole::Destination(dest) => {
                            let change = dest.path_mtu.update_local(new_local_mtu);
                            if let Some((ep, advertised)) =
                                e2e_mtu_reporter.publish(new_local_mtu, now)
                            {
                                if let Err(err) = send_e2e_control(
                                    &binding,
                                    remote_cid,
                                    &mut tx,
                                    e2e_dg::DG_MTU,
                                    &encode_mtu_payload(ep, advertised),
                                ) {
                                    if !err.is_retryable() {
                                        break err;
                                    }
                                }
                            }
                            match change {
                                MtuChange::BelowFloor(m) => break CoreError::MtuTooSmall(m),
                                MtuChange::Changed(m) => {
                                    apply_effective_mtu(&current_mtu, &max_payload, m, &scope);
                                }
                                MtuChange::Unchanged => {}
                            }
                        }
                    }
                }
                Ev::Inbound(Err(err)) => break err,
                Ev::Inbound(Ok(mut pkt)) => {
                    let Some(&op) = pkt.payload().first() else {
                        continue;
                    };
                    if op == outer::DG_DATA {
                        if strip_dg_data_header(&mut pkt).is_err() {
                            continue;
                        }
                        let Ok((seq, e2e_op)) = rx.open(&mut pkt) else {
                            // Spec §5.8.1: Invalid length, replay, or bad AEAD silently discarded.
                            continue;
                        };
                        match e2e_op {
                            e2e_dg::DG_DATA => {
                                // Spec §5.8.1: Destination suppresses originator `seq == 0 && body.is_empty()`
                                // in BOTH AwaitingConfirm AND steady state!
                                if matches!(role, DatagramSessionRole::Destination(_))
                                    && seq == 0
                                    && pkt.is_empty()
                                {
                                    continue;
                                }
                                if matches!(role, DatagramSessionRole::Destination(_)) {
                                    if let Some(gate) = gate_cache.get(&lease) {
                                        match gate.check_datagram(Direction::Ingress, pkt.len()) {
                                            DatagramAction::Allow => {}
                                            DatagramAction::Drop => {
                                                scope
                                                    .metrics
                                                    .traffic_gate_drops_total
                                                    .fetch_add(1, Ordering::Relaxed);
                                                continue;
                                            }
                                            DatagramAction::Close(err) => break err,
                                        }
                                    }
                                }
                                scope
                                    .metrics
                                    .record_rx(Plane::Datagram, pkt.len() as u64, true);
                                if rx_tx.try_send(pkt).is_err() {
                                    scope
                                        .metrics
                                        .queue_drops_total
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            e2e_dg::DG_CLOSE => {
                                let err = match decode_wire_error_bytes(pkt.payload()) {
                                    Ok(e) => e,
                                    Err(e) => e,
                                };
                                break err;
                            }
                            e2e_dg::DG_MTU => {
                                let Ok((epoch, mtu)) = decode_mtu_payload(pkt.payload()) else {
                                    continue;
                                };
                                // Always ACK even for stale/duplicate epochs (Spec §6.6).
                                let _ = send_e2e_control(
                                    &binding,
                                    remote_cid,
                                    &mut tx,
                                    e2e_dg::DG_MTU_ACK,
                                    &encode_mtu_ack_payload(epoch),
                                );
                                let now = clock.now();
                                match &mut role {
                                    DatagramSessionRole::Origin(orig) => {
                                        match orig.path_mtu.on_dest_mtu(epoch, mtu) {
                                            MtuChange::BelowFloor(m) => {
                                                break CoreError::MtuTooSmall(m);
                                            }
                                            MtuChange::Changed(m) => {
                                                apply_effective_mtu(
                                                    &current_mtu,
                                                    &max_payload,
                                                    m,
                                                    &scope,
                                                );
                                                scope.path_source.report_outcome(
                                                    orig.path_id,
                                                    PathOutcome::MtuChanged { mtu: m },
                                                );
                                                if let Some((ep, advertised)) =
                                                    e2e_mtu_reporter.publish(m, now)
                                                {
                                                    let _ = send_e2e_control(
                                                        &binding,
                                                        remote_cid,
                                                        &mut tx,
                                                        e2e_dg::DG_MTU,
                                                        &encode_mtu_payload(ep, advertised),
                                                    );
                                                }
                                            }
                                            MtuChange::Unchanged => {}
                                        }
                                    }
                                    DatagramSessionRole::Destination(dest) => {
                                        match dest.path_mtu.on_origin_mtu(epoch, mtu) {
                                            MtuChange::BelowFloor(m) => {
                                                break CoreError::MtuTooSmall(m);
                                            }
                                            MtuChange::Changed(m) => {
                                                apply_effective_mtu(
                                                    &current_mtu,
                                                    &max_payload,
                                                    m,
                                                    &scope,
                                                );
                                            }
                                            MtuChange::Unchanged => {}
                                        }
                                    }
                                }
                            }
                            e2e_dg::DG_MTU_ACK => {
                                if let Ok(epoch) = decode_mtu_ack_payload(pkt.payload()) {
                                    e2e_mtu_reporter.on_ack(epoch);
                                }
                            }
                            e2e_dg::DG_RENEW => {
                                let renew_plan = if let DatagramSessionRole::Destination(dest) =
                                    &role
                                {
                                    match decode_renew_payload(pkt.payload()) {
                                        Ok((id, cred)) => match dest_verifier.classify(id) {
                                            VerifierRenewalAction::AuthorizeNew(new_id) => {
                                                Credential::from_slice(cred).ok().map(|c| {
                                                    (
                                                        VerifierRenewalAction::AuthorizeNew(new_id),
                                                        Some((c, dest.endpoint.clone())),
                                                    )
                                                })
                                            }
                                            other => Some((other, None)),
                                        },
                                        Err(_) => None,
                                    }
                                } else {
                                    None
                                };
                                // Wipe decrypted renewal credential bytes in place immediately
                                // before reuse or drop (Spec §1.4 & §6.7).
                                pkt.zeroize_payload();
                                if let Some((action, auth_args)) = renew_plan {
                                    match action {
                                        VerifierRenewalAction::Malformed
                                        | VerifierRenewalAction::Ignore => {}
                                        VerifierRenewalAction::ReplyIdempotent(ack_id) => {
                                            let rem = match lease.remaining() {
                                                Ok(d) => d,
                                                Err(err) => break err,
                                            };
                                            let rem_ms = u64::try_from(rem.as_millis())
                                                .unwrap_or(u64::MAX)
                                                .max(1);
                                            let _ = send_e2e_control(
                                                &binding,
                                                remote_cid,
                                                &mut tx,
                                                e2e_dg::DG_RENEW_OK,
                                                &encode_renew_ok_payload(ack_id, rem_ms),
                                            );
                                        }
                                        VerifierRenewalAction::AuthorizeNew(new_id) => {
                                            if let Some((cred_owned, ep_name)) = auth_args {
                                                let scope_c = Arc::clone(&scope);
                                                dest_auth_fut = Some(Box::pin(async move {
                                                    let res = scope_c
                                                        .auth_gate
                                                        .authorize(AuthRequest {
                                                            peer,
                                                            target: TargetRef::Endpoint {
                                                                name: &ep_name,
                                                                plane: Plane::Datagram,
                                                            },
                                                            credential: cred_owned.as_bytes(),
                                                            is_renewal: true,
                                                        })
                                                        .await;
                                                    (new_id, res)
                                                }));
                                            }
                                        }
                                    }
                                }
                            }
                            e2e_dg::DG_RENEW_OK => {
                                let DatagramSessionRole::Origin(orig) = &mut role else {
                                    continue;
                                };
                                let (id, ttl) = match decode_renew_ok_payload(pkt.payload()) {
                                    Ok(v) => v,
                                    Err(err) => break err,
                                };
                                match orig.renewals.on_ack(
                                    RenewalSlot::Endpoint,
                                    id,
                                    ttl,
                                    clock.now(),
                                    &mut OsRng,
                                ) {
                                    Ok(true) => {
                                        if let Err(err) =
                                            lease.renew_ttl_only(ttl, MAX_WIRE_LEASE_TTL)
                                        {
                                            break err;
                                        }
                                        scope
                                            .metrics
                                            .auth_endpoint
                                            .renewed
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                    Ok(false) => {}
                                    Err(err) => {
                                        scope
                                            .metrics
                                            .auth_endpoint
                                            .renewal_failures
                                            .fetch_add(1, Ordering::Relaxed);
                                        break err;
                                    }
                                }
                            }
                            _ => {
                                // Unknown E2E opcodes in authenticated datagram records are ignored (Spec §5.8.1).
                            }
                        }
                    } else if outer::is_dg_control(op) {
                        // Spec §5.7.1: Destination silently ignores ALL 0x23..=0x27!
                        let DatagramSessionRole::Origin(orig) = &mut role else {
                            continue;
                        };
                        let Ok((hdr, body)) = DgHopControlHeader::parse(pkt.payload()) else {
                            continue;
                        };
                        let dist = usize::from(hdr.ttl_or_dist);
                        if dist >= orig.hops.len() {
                            continue;
                        }
                        if !matches!(hdr.kind, outer::DG_CLOSE | outer::DG_MTU | outer::DG_RENEW_OK)
                        {
                            continue;
                        }
                        let Ok(pt) = orig.hops[dist].2.open(hdr.kind, body) else {
                            continue;
                        };
                        match hdr.kind {
                            outer::DG_CLOSE => {
                                let err = match decode_wire_error_bytes(&pt) {
                                    Ok(e) => e,
                                    Err(e) => break e,
                                };
                                break CoreError::hop_rejected(hdr.ttl_or_dist, err);
                            }
                            outer::DG_MTU => {
                                let Ok((epoch, mtu)) = decode_mtu_payload(&pt) else {
                                    continue;
                                };
                                // Always reply hop::DG_MTU_ACK(ttl = dist, cid = remote_cid, epoch).
                                if let (Ok(ttl), Ok(sealed)) = (
                                    u8::try_from(dist),
                                    orig.hops[dist]
                                        .2
                                        .seal(outer::DG_MTU_ACK, &encode_mtu_ack_payload(epoch)),
                                ) {
                                    let ack_pkt = DgHopControlHeader {
                                        kind: outer::DG_MTU_ACK,
                                        ttl_or_dist: ttl,
                                        cid: remote_cid,
                                    }
                                    .encode_packet(&sealed);
                                    let _ = binding.send_now(ack_pkt);
                                }
                                let now = clock.now();
                                match orig.path_mtu.on_hop_mtu(dist, epoch, mtu) {
                                    MtuChange::BelowFloor(m) => break CoreError::MtuTooSmall(m),
                                    MtuChange::Changed(m) => {
                                        apply_effective_mtu(&current_mtu, &max_payload, m, &scope);
                                        scope.path_source.report_outcome(
                                            orig.path_id,
                                            PathOutcome::MtuChanged { mtu: m },
                                        );
                                        if let Some((ep, advertised)) =
                                            e2e_mtu_reporter.publish(m, now)
                                        {
                                            let _ = send_e2e_control(
                                                &binding,
                                                remote_cid,
                                                &mut tx,
                                                e2e_dg::DG_MTU,
                                                &encode_mtu_payload(ep, advertised),
                                            );
                                        }
                                    }
                                    MtuChange::Unchanged => {}
                                }
                            }
                            outer::DG_RENEW_OK => {
                                let (id, ttl) = match decode_renew_ok_payload(&pt) {
                                    Ok(v) => v,
                                    Err(err) => break err,
                                };
                                match orig.renewals.on_ack(
                                    RenewalSlot::Hop(dist),
                                    id,
                                    ttl,
                                    clock.now(),
                                    &mut OsRng,
                                ) {
                                    Ok(true) => {
                                        scope
                                            .metrics
                                            .auth_transit
                                            .renewed
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                    Ok(false) => {}
                                    Err(err) => {
                                        scope
                                            .metrics
                                            .auth_transit
                                            .renewal_failures
                                            .fetch_add(1, Ordering::Relaxed);
                                        break err;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Ev::Outbound(Err(_)) => break CoreError::Closed,
                Ev::Outbound(Ok(QueuedOutbound { mut pkt, _permit })) => {
                    let max = max_payload.load(Ordering::Acquire);
                    if pkt.len() > max {
                        continue;
                    }
                    if matches!(role, DatagramSessionRole::Destination(_)) {
                        if let Some(gate) = gate_cache.get(&lease) {
                            match gate.check_datagram(Direction::Egress, pkt.len()) {
                                DatagramAction::Allow => {}
                                DatagramAction::Drop => {
                                    scope
                                        .metrics
                                        .traffic_gate_drops_total
                                        .fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                                DatagramAction::Close(err) => break err,
                            }
                        }
                    }
                    let payload_len = pkt.len();
                    if let Err(err) = tx.seal(e2e_dg::DG_DATA, &mut pkt) {
                        break err;
                    }
                    if let Err(err) = prepend_dg_data_header(&mut pkt, remote_cid) {
                        break err;
                    }
                    match binding.send_now(pkt) {
                        Ok(()) => {
                            scope
                                .metrics
                                .record_tx(Plane::Datagram, payload_len as u64, true);
                        }
                        Err(CoreError::MtuTooSmall(bound)) => {
                            mtu_watch.clamp_seen(bound);
                            let now = clock.now();
                            match &mut role {
                                DatagramSessionRole::Origin(orig) => {
                                    match orig.path_mtu.clamp_local(bound) {
                                        MtuChange::BelowFloor(m) => {
                                            break CoreError::MtuTooSmall(m);
                                        }
                                        MtuChange::Changed(m) => {
                                            apply_effective_mtu(
                                                &current_mtu,
                                                &max_payload,
                                                m,
                                                &scope,
                                            );
                                            scope.path_source.report_outcome(
                                                orig.path_id,
                                                PathOutcome::MtuChanged { mtu: m },
                                            );
                                            if let Some((ep, advertised)) =
                                                e2e_mtu_reporter.publish(m, now)
                                            {
                                                let _ = send_e2e_control(
                                                    &binding,
                                                    remote_cid,
                                                    &mut tx,
                                                    e2e_dg::DG_MTU,
                                                    &encode_mtu_payload(ep, advertised),
                                                );
                                            }
                                        }
                                        MtuChange::Unchanged => {
                                            if let Some((ep, advertised)) = e2e_mtu_reporter
                                                .reassert(orig.path_mtu.current_mtu(), now)
                                            {
                                                let _ = send_e2e_control(
                                                    &binding,
                                                    remote_cid,
                                                    &mut tx,
                                                    e2e_dg::DG_MTU,
                                                    &encode_mtu_payload(ep, advertised),
                                                );
                                            }
                                        }
                                    }
                                }
                                DatagramSessionRole::Destination(dest) => {
                                    let change = dest.path_mtu.clamp_local(bound);
                                    let advertised_local = dest.path_mtu.local_mtu();
                                    if let Some((ep, adv)) = e2e_mtu_reporter
                                        .publish(advertised_local, now)
                                        .or_else(|| {
                                            e2e_mtu_reporter.reassert(advertised_local, now)
                                        })
                                    {
                                        let _ = send_e2e_control(
                                            &binding,
                                            remote_cid,
                                            &mut tx,
                                            e2e_dg::DG_MTU,
                                            &encode_mtu_payload(ep, adv),
                                        );
                                    }
                                    match change {
                                        MtuChange::BelowFloor(m) => {
                                            break CoreError::MtuTooSmall(m);
                                        }
                                        MtuChange::Changed(m) => {
                                            apply_effective_mtu(
                                                &current_mtu,
                                                &max_payload,
                                                m,
                                                &scope,
                                            );
                                        }
                                        MtuChange::Unchanged => {}
                                    }
                                }
                            }
                        }
                        Err(err) if err.is_retryable() => {
                            scope
                                .metrics
                                .queue_drops_total
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        Err(fatal) => break fatal,
                    }
                }
                Ev::DestAuthDone(id, res) => match res {
                    Ok(new_lease) => {
                        if let Err(err) = lease
                            .renew_lease_with_max_ttl(new_lease, scope.auth_limits.max_lease_ttl)
                        {
                            scope
                                .metrics
                                .auth_endpoint
                                .renewal_failures
                                .fetch_add(1, Ordering::Relaxed);
                            break err;
                        }
                        dest_verifier.complete(id, true);
                        scope
                            .metrics
                            .auth_endpoint
                            .renewed
                            .fetch_add(1, Ordering::Relaxed);
                        let rem = match lease.remaining() {
                            Ok(d) => d,
                            Err(err) => break err,
                        };
                        let rem_ms = u64::try_from(rem.as_millis()).unwrap_or(u64::MAX).max(1);
                        let _ = send_e2e_control(
                            &binding,
                            remote_cid,
                            &mut tx,
                            e2e_dg::DG_RENEW_OK,
                            &encode_renew_ok_payload(id, rem_ms),
                        );
                    }
                    Err(err) if err.is_retryable() => {
                        dest_verifier.complete(id, false);
                    }
                    Err(err) => {
                        dest_verifier.complete(id, false);
                        scope
                            .metrics
                            .auth_endpoint
                            .renewal_failures
                            .fetch_add(1, Ordering::Relaxed);
                        break err;
                    }
                },
                Ev::CredFetched(slot, res) => {
                    let DatagramSessionRole::Origin(orig) = &mut role else {
                        continue;
                    };
                    match orig
                        .renewals
                        .on_credential_fetched(slot, res, clock.now(), &mut OsRng)
                    {
                        CredentialFetchOutcome::Send {
                            slot,
                            renewal_id,
                            credential,
                        } => {
                            if let Err(err) = send_origin_dg_renewal(
                                &binding,
                                remote_cid,
                                slot,
                                renewal_id,
                                &credential,
                                &mut tx,
                                &mut orig.hops,
                            ) {
                                if !err.is_retryable() {
                                    break err;
                                }
                            }
                        }
                        CredentialFetchOutcome::RetryScheduled => {}
                        CredentialFetchOutcome::Fatal(err) => {
                            let is_transit = matches!(slot, RenewalSlot::Hop(_));
                            scope
                                .metrics
                                .auth(is_transit)
                                .renewal_failures
                                .fetch_add(1, Ordering::Relaxed);
                            break err;
                        }
                    }
                }
                Ev::TimerFired => {
                    let now = clock.now();
                    // 1. Poll E2E MTU reporter retries.
                    if let Some((epoch, mtu)) = e2e_mtu_reporter.poll_retry(now) {
                        let _ = send_e2e_control(
                            &binding,
                            remote_cid,
                            &mut tx,
                            e2e_dg::DG_MTU,
                            &encode_mtu_payload(epoch, mtu),
                        );
                    }
                    // 2. Poll Originator RenewalDriver actions.
                    if let DatagramSessionRole::Origin(orig) = &mut role {
                        let actions = orig.renewals.poll_actions(now, &mut OsRng);
                        let mut fatal_err: Option<CoreError> = None;
                        for act in actions {
                            match act {
                                RenewalAction::Expired(slot) => {
                                    let is_transit = matches!(slot, RenewalSlot::Hop(_));
                                    scope
                                        .metrics
                                        .auth(is_transit)
                                        .renewal_failures
                                        .fetch_add(1, Ordering::Relaxed);
                                    fatal_err = Some(RenewalDriver::expiry_error(slot));
                                    break;
                                }
                                RenewalAction::FetchCredential {
                                    slot,
                                    prior,
                                    remaining,
                                    is_retry,
                                } => {
                                    let is_transit = matches!(slot, RenewalSlot::Hop(_));
                                    if is_retry {
                                        scope
                                            .metrics
                                            .auth(is_transit)
                                            .renewal_retries
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                    let (verifier, target_name) = match slot {
                                        RenewalSlot::Endpoint => (peer, orig.endpoint.clone()),
                                        RenewalSlot::Hop(i) => {
                                            (orig.hops[i].0, orig.hops[i].1.clone())
                                        }
                                    };
                                    let timeout =
                                        scope.auth_limits.auth_timeout.min(remaining / 2);
                                    let deadline = clock.now().saturating_add(timeout);
                                    let creds = Arc::clone(&scope.credentials);
                                    let clk = Arc::clone(&clock);
                                    let ep_name = orig.endpoint.clone();
                                    let path_id = orig.path_id;
                                    cred_futs.push(Box::pin(async move {
                                        let target = if is_transit {
                                            TargetRef::Transit {
                                                name: &target_name,
                                                plane: Plane::Datagram,
                                            }
                                        } else {
                                            TargetRef::Endpoint {
                                                name: &target_name,
                                                plane: Plane::Datagram,
                                            }
                                        };
                                        let fut = creds.credential(CredentialRequest {
                                            verifier,
                                            target,
                                            destination: peer,
                                            endpoint: &ep_name,
                                            path_id,
                                            is_refresh: true,
                                            prior: prior.as_bytes(),
                                        });
                                        let res = match with_deadline(&*clk, deadline, fut).await {
                                            Ok(c) if c.len() <= CREDENTIAL_MAX => Ok(c),
                                            Ok(_) => Err(CoreError::credential(
                                                CoreError::InvalidParameter,
                                            )),
                                            Err(e) => Err(CoreError::credential(e)),
                                        };
                                        (slot, res)
                                    }));
                                }
                                RenewalAction::Send {
                                    slot,
                                    renewal_id,
                                    credential,
                                    is_retry,
                                } => {
                                    if is_retry {
                                        let is_transit = matches!(slot, RenewalSlot::Hop(_));
                                        scope
                                            .metrics
                                            .auth(is_transit)
                                            .renewal_retries
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                    if let Err(err) = send_origin_dg_renewal(
                                        &binding,
                                        remote_cid,
                                        slot,
                                        renewal_id,
                                        &credential,
                                        &mut tx,
                                        &mut orig.hops,
                                    ) {
                                        if !err.is_retryable() {
                                            fatal_err = Some(err);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(err) = fatal_err {
                            break err;
                        }
                    }
                }
            }
        }
    };

    tracing::debug!(
        parent: &span,
        error = terminal_reason.static_code(),
        "datagram session terminating"
    );

    closed_tx.send(Some(terminal_reason.clone()));
    tx_sem.close();
    tx_rx.close();
    rx_tx.close();

    // Teardown per Spec §6.5:
    // Best-effort (50 ms) e2e::DG_CLOSE(reason), plus (if Origin) hop::DG_CLOSE(reason) N-1..0.
    let err_bytes = encode_wire_error_bytes(&terminal_reason);
    if let Ok(mut close_pkt) = build_e2e_packet(&mut tx, e2e_dg::DG_CLOSE, &err_bytes, remote_cid) {
        let _ = &mut close_pkt;
        binding.send_best_effort(close_pkt).await;
    }

    if let DatagramSessionRole::Origin(orig) = &mut role {
        for i in (0..orig.hops.len()).rev() {
            if let (Ok(ttl), Ok(sealed)) = (
                u8::try_from(i),
                orig.hops[i].2.seal(outer::DG_CLOSE, &err_bytes),
            ) {
                let pkt = DgHopControlHeader {
                    kind: outer::DG_CLOSE,
                    ttl_or_dist: ttl,
                    cid: remote_cid,
                }
                .encode_packet(&sealed);
                binding.send_best_effort(pkt).await;
            }
        }
        let outcome = if terminal_reason == CoreError::Closed {
            PathOutcome::Closed
        } else {
            PathOutcome::Failed(terminal_reason)
        };
        scope.path_source.report_outcome(orig.path_id, outcome);
    }
}

fn apply_effective_mtu(
    current_mtu: &AtomicU16,
    max_payload: &AtomicUsize,
    mtu: u16,
    scope: &ScopeCore,
) {
    current_mtu.store(mtu, Ordering::Release);
    max_payload.store(usize::from(mtu).saturating_sub(DG_OVERHEAD), Ordering::Release);
    scope
        .metrics
        .mtu_updates_total
        .fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn build_e2e_packet(
    tx: &mut DatagramTx,
    opcode: u8,
    body: &[u8],
    remote_cid: Cid,
) -> Result<PacketBuf, CoreError> {
    let mut pkt = PacketBuf::from_payload(body);
    if let Err(err) = tx.seal(opcode, &mut pkt) {
        pkt.zeroize_payload();
        return Err(err);
    }
    prepend_dg_data_header(&mut pkt, remote_cid)?;
    Ok(pkt)
}

fn send_e2e_control(
    binding: &Binding,
    remote_cid: Cid,
    tx: &mut DatagramTx,
    opcode: u8,
    body: &[u8],
) -> Result<(), CoreError> {
    let pkt = build_e2e_packet(tx, opcode, body, remote_cid)?;
    match binding.send_now(pkt) {
        Ok(()) | Err(CoreError::WouldBlock) => Ok(()),
        Err(err) => Err(err),
    }
}

fn send_origin_dg_renewal(
    binding: &Binding,
    remote_cid: Cid,
    slot: RenewalSlot,
    renewal_id: u64,
    credential: &Credential,
    tx: &mut DatagramTx,
    hops: &mut [(PublicKey, String, ControlCipher)],
) -> Result<(), CoreError> {
    let payload = encode_renew_payload(renewal_id, credential.as_bytes())?;
    match slot {
        RenewalSlot::Endpoint => {
            send_e2e_control(binding, remote_cid, tx, e2e_dg::DG_RENEW, &payload)
        }
        RenewalSlot::Hop(i) => {
            let ttl = u8::try_from(i).map_err(|_| CoreError::Malformed)?;
            let sealed = hops
                .get_mut(i)
                .ok_or(CoreError::Malformed)?
                .2
                .seal(outer::DG_RENEW, &payload)?;
            let pkt = DgHopControlHeader {
                kind: outer::DG_RENEW,
                ttl_or_dist: ttl,
                cid: remote_cid,
            }
            .encode_packet(&sealed);
            match binding.send_now(pkt) {
                Ok(()) | Err(CoreError::WouldBlock) => Ok(()),
                Err(err) => Err(err),
            }
        }
    }
}

/// Helper used by `StagedDatagram` drop-abort: sends best-effort `e2e::DG_CLOSE(Closed)`
/// followed by reverse `hop::DG_CLOSE(Closed)` (`N-1..0`).
pub(crate) async fn abort_datagram_staged(
    binding: Binding,
    remote_cid: Cid,
    mut tx: DatagramTx,
    mut hop_ctrls: Vec<ControlCipher>,
) {
    let err_bytes = encode_wire_error_bytes(&CoreError::Closed);
    if let Ok(close_pkt) = build_e2e_packet(&mut tx, e2e_dg::DG_CLOSE, &err_bytes, remote_cid) {
        binding.send_best_effort(close_pkt).await;
    }
    for (i, ctrl) in hop_ctrls.iter_mut().enumerate().rev() {
        if let (Ok(ttl), Ok(sealed)) = (u8::try_from(i), ctrl.seal(outer::DG_CLOSE, &err_bytes)) {
            let pkt = DgHopControlHeader {
                kind: outer::DG_CLOSE,
                ttl_or_dist: ttl,
                cid: remote_cid,
            }
            .encode_packet(&sealed);
            binding.send_best_effort(pkt).await;
        }
    }
}
