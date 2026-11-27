//! Datagram Transit zero-copy in-place CID switcher, direction-filtered control relay,
//! 5 s floor-violation drain window, and in-band renewal verifier (Spec §5.7.1, §6.5–6.7).

use core::future::{Future, poll_fn};
use core::task::Poll;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::constants::DG_OVERHEAD;
use crate::crypto::cipher::ControlCipher;
use crate::engine::context::{
    RenewalAuthFut, ScopeCore, SessionPermit, poll_optional, sleep_optional, wait_mtu_change,
    wait_shutdown,
};
use crate::engine::datagram::port::Binding;
use crate::error::CoreError;
use crate::packet::PacketBuf;
use crate::protocol::mtu::{MtuReporter, TransitMtuEvent, TransitPathMtu};
use crate::protocol::renewal::{RenewalVerifierState, VerifierRenewalAction};
use crate::seam::auth::{AuthRequest, DatagramAction, Lease};
use crate::trust::lease::{LeaseHandle, TrafficGateCache};
use crate::types::{Cid, Credential, Direction, Plane, PublicKey, Role, TargetRef};
use crate::wire::datagram::{
    DgHopControlHeader, decode_mtu_ack_payload, decode_renew_payload, encode_mtu_payload,
    encode_renew_ok_payload, rewrite_dg_data_cid,
};
use crate::wire::opcodes::{decode_wire_error_bytes, encode_wire_error_bytes, outer};

/// Parameters for running an established Datagram Transit circuit.
pub(crate) struct DatagramTransitParams {
    pub scope: Arc<ScopeCore>,
    pub peer: PublicKey,
    pub full_name: String,
    pub floor: u16,
    pub initial_physical_mtu: u16,
    pub left: Binding,
    pub right: Binding,
    pub caller_cid: Cid,
    pub next_cid: Cid,
    pub ctrl: ControlCipher,
    pub lease: Arc<LeaseHandle>,
    pub session_permit: SessionPermit,
}

/// Runs the steady-state Datagram Transit switcher until clean close, revocation, expiry,
/// shutdown, or 5 s MTU floor-violation drain expiry.
pub(crate) async fn run_datagram_transit(params: DatagramTransitParams) {
    let DatagramTransitParams {
        scope,
        peer,
        full_name,
        floor,
        initial_physical_mtu,
        left,
        right,
        caller_cid,
        next_cid,
        mut ctrl,
        lease,
        session_permit: _session_permit,
    } = params;

    let clock = Arc::clone(&scope.runtime.clock);
    let span = scope.session_span(Plane::Datagram, Role::Transit);

    let mut left_mtu_watch = left.mtu_watch();
    let mut right_mtu_watch = right.mtu_watch();
    let initial_left = left_mtu_watch.sample();
    let initial_right = right_mtu_watch.sample();
    let mut path_mtu = TransitPathMtu::new(initial_physical_mtu, initial_physical_mtu, floor);
    let mut mtu_reporter = MtuReporter::with_initial(initial_physical_mtu);
    let mut gate_cache = TrafficGateCache::new();
    let mut verifier = RenewalVerifierState::new();
    let mut auth_fut: Option<RenewalAuthFut> = None;
    let mut shutdown_rx = scope.subscribe_shutdown();

    // Startup check comparing first live sampled legs against the exact `physical` MTU sent in
    // the `SETUP_OK` hop trailer while synchronizing watch baselines atomically (DG-11, DG-13).
    {
        let now = clock.now();
        let ev = path_mtu.update_both(initial_left, initial_right, now);
        handle_transit_mtu_event(ev, &mut mtu_reporter, &mut ctrl, &left, caller_cid, now);
    }

    let mut prefer_reverse = false;
    let exit_result: Result<(), CoreError> = loop {
        let mtu_retry_dl = mtu_reporter.next_deadline();
        let drain_dl = path_mtu.drain_deadline();
        let next_timer = [mtu_retry_dl, drain_dl].into_iter().flatten().min();

        enum Ev {
            LeaseCancelled(CoreError),
            Shutdown,
            LeftMtu(u16),
            RightMtu(u16),
            LeftPkt(Result<PacketBuf, CoreError>),
            RightPkt(Result<PacketBuf, CoreError>),
            AuthDone(u64, Result<Lease, CoreError>),
            TimerFired,
        }

        let ev = {
            let mut l_fut = Box::pin(lease.cancelled());
            let mut sh_fut = Box::pin(wait_shutdown(&mut shutdown_rx));
            let mut lm_fut = Box::pin(wait_mtu_change(&mut left_mtu_watch));
            let mut rm_fut = Box::pin(wait_mtu_change(&mut right_mtu_watch));
            let mut lp_fut = Box::pin(left.recv());
            let mut rp_fut = Box::pin(right.recv());
            let mut t_fut = Box::pin(sleep_optional(&*clock, next_timer));

            poll_fn(|cx| {
                if let Poll::Ready(err) = l_fut.as_mut().poll(cx) {
                    return Poll::Ready(Ev::LeaseCancelled(err));
                }
                if let Poll::Ready(()) = sh_fut.as_mut().poll(cx) {
                    return Poll::Ready(Ev::Shutdown);
                }
                if let Poll::Ready((id, res)) = poll_optional(&mut auth_fut, cx) {
                    return Poll::Ready(Ev::AuthDone(id, res));
                }
                if let Poll::Ready(mtu) = lm_fut.as_mut().poll(cx) {
                    return Poll::Ready(Ev::LeftMtu(mtu));
                }
                if let Poll::Ready(mtu) = rm_fut.as_mut().poll(cx) {
                    return Poll::Ready(Ev::RightMtu(mtu));
                }
                if let Poll::Ready(()) = t_fut.as_mut().poll(cx) {
                    return Poll::Ready(Ev::TimerFired);
                }
                // DG-15: Alternate forward/reverse mailbox polling so sustained forward floods
                // cannot starve reverse DG_RENEW_OK, DG_MTU, or reverse traffic.
                if prefer_reverse {
                    if let Poll::Ready(pkt) = rp_fut.as_mut().poll(cx) {
                        return Poll::Ready(Ev::RightPkt(pkt));
                    }
                    if let Poll::Ready(pkt) = lp_fut.as_mut().poll(cx) {
                        return Poll::Ready(Ev::LeftPkt(pkt));
                    }
                } else {
                    if let Poll::Ready(pkt) = lp_fut.as_mut().poll(cx) {
                        return Poll::Ready(Ev::LeftPkt(pkt));
                    }
                    if let Poll::Ready(pkt) = rp_fut.as_mut().poll(cx) {
                        return Poll::Ready(Ev::RightPkt(pkt));
                    }
                }
                Poll::Pending
            })
            .await
        };

        match &ev {
            Ev::LeftPkt(_) => prefer_reverse = true,
            Ev::RightPkt(_) => prefer_reverse = false,
            _ => {}
        }

        match ev {
            Ev::LeaseCancelled(err) => break Err(err),
            Ev::Shutdown => break Err(CoreError::Closed),
            Ev::LeftMtu(mtu) => {
                let now = clock.now();
                let change = path_mtu.update_left(mtu, now);
                handle_transit_mtu_event(change, &mut mtu_reporter, &mut ctrl, &left, caller_cid, now);
            }
            Ev::RightMtu(mtu) => {
                let now = clock.now();
                let change = path_mtu.update_right(mtu, now);
                handle_transit_mtu_event(change, &mut mtu_reporter, &mut ctrl, &left, caller_cid, now);
            }
            Ev::TimerFired => {
                let now = clock.now();
                if let (Some(dl), Some(bound)) = (path_mtu.drain_deadline(), path_mtu.drain_bound())
                {
                    if now >= dl {
                        break Err(CoreError::MtuTooSmall(bound));
                    }
                }
                if let Some((epoch, mtu)) = mtu_reporter.poll_retry(now) {
                    emit_hop_mtu(&mut ctrl, &left, caller_cid, epoch, mtu);
                }
            }
            Ev::LeftPkt(Err(err)) | Ev::RightPkt(Err(err)) => break Err(err),
            Ev::LeftPkt(Ok(mut pkt)) => {
                let Some(&op) = pkt.payload().first() else {
                    continue;
                };
                if op == outer::DG_DATA {
                    let wire_len = pkt.len();
                    if wire_len < DG_OVERHEAD || !lease.is_active() {
                        continue;
                    }
                    let out_limit = usize::from(path_mtu.right_mtu());
                    if wire_len > out_limit {
                        let now = clock.now();
                        if let Some((ep, m)) = mtu_reporter.reassert(path_mtu.effective(), now) {
                            emit_hop_mtu(&mut ctrl, &left, caller_cid, ep, m);
                        }
                        continue;
                    }
                    // Spec §7.3: TrafficGate strictly on DG_DATA (full wire packet length!).
                    if let Some(gate) = gate_cache.get(&lease) {
                        match gate.check_datagram(Direction::Ingress, wire_len) {
                            DatagramAction::Allow => {}
                            DatagramAction::Drop => {
                                scope
                                    .metrics
                                    .traffic_gate_drops_total
                                    .fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            DatagramAction::Close(err) => break Err(err),
                        }
                    }
                    // Zero-copy in-place CID rewrite!
                    if rewrite_dg_data_cid(&mut pkt, next_cid).is_err() {
                        continue;
                    }
                    match right.send_now(pkt) {
                        Ok(()) => {
                            scope
                                .metrics
                                .record_rx(Plane::Datagram, wire_len as u64, true);
                        }
                        Err(CoreError::MtuTooSmall(bound)) => {
                            right_mtu_watch.clamp_seen(bound);
                            let now = clock.now();
                            let change = path_mtu.clamp_leg(true, bound, now);
                            if matches!(change, TransitMtuEvent::Unchanged) {
                                if let Some((ep, m)) =
                                    mtu_reporter.reassert(path_mtu.effective(), now)
                                {
                                    emit_hop_mtu(&mut ctrl, &left, caller_cid, ep, m);
                                }
                            } else {
                                handle_transit_mtu_event(
                                    change,
                                    &mut mtu_reporter,
                                    &mut ctrl,
                                    &left,
                                    caller_cid,
                                    now,
                                );
                            }
                        }
                        Err(err) if err.is_retryable() => {
                            scope
                                .metrics
                                .queue_drops_total
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        Err(fatal) => break Err(fatal),
                    }
                } else if outer::is_dg_control(op) {
                    // Direction filter (Spec §5.7.1): DG_MTU (0x24) MUST be dropped on forward path!
                    if op == outer::DG_MTU {
                        continue;
                    }
                    let Ok((hdr, body)) = DgHopControlHeader::parse(pkt.payload()) else {
                        continue;
                    };
                    if hdr.ttl_or_dist == 0 {
                        let Ok(pt) = ctrl.open(hdr.kind, body) else {
                            continue;
                        };
                        match hdr.kind {
                            outer::DG_CLOSE => {
                                if decode_wire_error_bytes(&pt).is_ok() {
                                    // DG-14 / Spec §6.6: An authenticated hop close during
                                    // floor-violation drain terminates with the latched
                                    // `MtuTooSmall(bound)` rather than generic `Ok(())`.
                                    if let Some(bound) = path_mtu.drain_bound() {
                                        break Err(CoreError::MtuTooSmall(bound));
                                    }
                                    break Ok(());
                                }
                            }
                            outer::DG_MTU_ACK => {
                                if let Ok(epoch) = decode_mtu_ack_payload(&pt) {
                                    mtu_reporter.on_ack(epoch);
                                }
                            }
                            outer::DG_RENEW => {
                                let Ok((id, cred)) = decode_renew_payload(&pt) else {
                                    continue;
                                };
                                match verifier.classify(id) {
                                    VerifierRenewalAction::Malformed
                                    | VerifierRenewalAction::Ignore => {}
                                    VerifierRenewalAction::ReplyIdempotent(ack_id) => {
                                        let rem = match lease.remaining() {
                                            Ok(d) => d,
                                            Err(err) => break Err(err),
                                        };
                                        let rem_ms = u64::try_from(rem.as_millis())
                                            .unwrap_or(u64::MAX)
                                            .max(1);
                                        emit_hop_renew_ok(&mut ctrl, &left, caller_cid, ack_id, rem_ms);
                                    }
                                    VerifierRenewalAction::AuthorizeNew(new_id) => {
                                        let Ok(cred_owned) = Credential::from_slice(cred) else {
                                            continue;
                                        };
                                        let scope_c = Arc::clone(&scope);
                                        let target_name = full_name.clone();
                                        auth_fut = Some(Box::pin(async move {
                                            let res = scope_c
                                                .auth_gate
                                                .authorize(AuthRequest {
                                                    peer,
                                                    target: TargetRef::Transit {
                                                        name: &target_name,
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
                            _ => {
                                // DG_RENEW_OK or other unexpected opcodes at ttl == 0 forward ignored.
                            }
                        }
                    } else {
                        // Forward control frame downstream: decrement ttl, rewrite CID in place.
                        let bytes = pkt.payload_mut();
                        bytes[1] = hdr.ttl_or_dist - 1;
                        bytes[2..6].copy_from_slice(&next_cid.raw().to_be_bytes());
                        let _ = right.send_now(pkt);
                    }
                }
            }
            Ev::RightPkt(Ok(mut pkt)) => {
                let Some(&op) = pkt.payload().first() else {
                    continue;
                };
                if op == outer::DG_DATA {
                    let wire_len = pkt.len();
                    if wire_len < DG_OVERHEAD || !lease.is_active() {
                        continue;
                    }
                    let out_limit = usize::from(path_mtu.left_mtu());
                    if wire_len > out_limit {
                        let now = clock.now();
                        if let Some((ep, m)) = mtu_reporter.reassert(path_mtu.effective(), now) {
                            emit_hop_mtu(&mut ctrl, &left, caller_cid, ep, m);
                        }
                        continue;
                    }
                    if let Some(gate) = gate_cache.get(&lease) {
                        match gate.check_datagram(Direction::Egress, wire_len) {
                            DatagramAction::Allow => {}
                            DatagramAction::Drop => {
                                scope
                                    .metrics
                                    .traffic_gate_drops_total
                                    .fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            DatagramAction::Close(err) => break Err(err),
                        }
                    }
                    if rewrite_dg_data_cid(&mut pkt, caller_cid).is_err() {
                        continue;
                    }
                    match left.send_now(pkt) {
                        Ok(()) => {
                            scope
                                .metrics
                                .record_tx(Plane::Datagram, wire_len as u64, true);
                        }
                        Err(CoreError::MtuTooSmall(bound)) => {
                            left_mtu_watch.clamp_seen(bound);
                            let now = clock.now();
                            let change = path_mtu.clamp_leg(false, bound, now);
                            if matches!(change, TransitMtuEvent::Unchanged) {
                                if let Some((ep, m)) =
                                    mtu_reporter.reassert(path_mtu.effective(), now)
                                {
                                    emit_hop_mtu(&mut ctrl, &left, caller_cid, ep, m);
                                }
                            } else {
                                handle_transit_mtu_event(
                                    change,
                                    &mut mtu_reporter,
                                    &mut ctrl,
                                    &left,
                                    caller_cid,
                                    now,
                                );
                            }
                        }
                        Err(err) if err.is_retryable() => {
                            scope
                                .metrics
                                .queue_drops_total
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        Err(fatal) => break Err(fatal),
                    }
                } else if outer::is_dg_control(op) {
                    // Direction filter (Spec §5.7.1): DG_MTU_ACK (0x27) MUST be dropped on reverse path!
                    if op == outer::DG_MTU_ACK {
                        continue;
                    }
                    let Ok((hdr, _)) = DgHopControlHeader::parse(pkt.payload()) else {
                        continue;
                    };
                    let Some(distance) = hdr.ttl_or_dist.checked_add(1) else {
                        continue;
                    };
                    let bytes = pkt.payload_mut();
                    bytes[1] = distance;
                    bytes[2..6].copy_from_slice(&caller_cid.raw().to_be_bytes());
                    let _ = left.send_now(pkt);
                }
            }
            Ev::AuthDone(id, res) => match res {
                Ok(new_lease) => {
                    if let Err(err) =
                        lease.renew_lease_with_max_ttl(new_lease, scope.auth_limits.max_lease_ttl)
                    {
                        scope
                            .metrics
                            .auth_transit
                            .renewal_failures
                            .fetch_add(1, Ordering::Relaxed);
                        break Err(err);
                    }
                    verifier.complete(id, true);
                    scope
                        .metrics
                        .auth_transit
                        .renewed
                        .fetch_add(1, Ordering::Relaxed);
                    let rem = match lease.remaining() {
                        Ok(d) => d,
                        Err(err) => break Err(err),
                    };
                    let rem_ms = u64::try_from(rem.as_millis()).unwrap_or(u64::MAX).max(1);
                    emit_hop_renew_ok(&mut ctrl, &left, caller_cid, id, rem_ms);
                }
                Err(err) if err.is_retryable() => {
                    verifier.complete(id, false);
                }
                Err(err) => {
                    verifier.complete(id, false);
                    scope
                        .metrics
                        .auth_transit
                        .renewal_failures
                        .fetch_add(1, Ordering::Relaxed);
                    break Err(err);
                }
            },
        }
    };

    if let Err(ref err) = exit_result {
        tracing::debug!(
            parent: &span,
            error = err.static_code(),
            "datagram transit terminating abnormally"
        );
        let payload = encode_wire_error_bytes(err);
        if let Ok(sealed) = ctrl.seal(outer::DG_CLOSE, &payload) {
            let close_pkt = DgHopControlHeader {
                kind: outer::DG_CLOSE,
                ttl_or_dist: 0,
                cid: caller_cid,
            }
            .encode_packet(&sealed);
            left.send_best_effort(close_pkt).await;
        }
    }
}

fn handle_transit_mtu_event(
    event: TransitMtuEvent,
    reporter: &mut MtuReporter,
    ctrl: &mut ControlCipher,
    left: &Binding,
    caller_cid: Cid,
    now: crate::runtime::MonotonicTime,
) {
    match event {
        TransitMtuEvent::Unchanged => {}
        TransitMtuEvent::Updated(mtu) | TransitMtuEvent::FloorViolation { mtu, .. } => {
            if let Some((epoch, adv)) = reporter.publish(mtu, now) {
                emit_hop_mtu(ctrl, left, caller_cid, epoch, adv);
            }
        }
    }
}

fn emit_hop_mtu(
    ctrl: &mut ControlCipher,
    left: &Binding,
    caller_cid: Cid,
    epoch: u32,
    mtu: u16,
) {
    if let Ok(sealed) = ctrl.seal(outer::DG_MTU, &encode_mtu_payload(epoch, mtu)) {
        let pkt = DgHopControlHeader {
            kind: outer::DG_MTU,
            ttl_or_dist: 0,
            cid: caller_cid,
        }
        .encode_packet(&sealed);
        let _ = left.send_now(pkt);
    }
}

fn emit_hop_renew_ok(
    ctrl: &mut ControlCipher,
    left: &Binding,
    caller_cid: Cid,
    renewal_id: u64,
    rem_ms: u64,
) {
    if let Ok(sealed) = ctrl.seal(
        outer::DG_RENEW_OK,
        &encode_renew_ok_payload(renewal_id, rem_ms),
    ) {
        let pkt = DgHopControlHeader {
            kind: outer::DG_RENEW_OK,
            ttl_or_dist: 0,
            cid: caller_cid,
        }
        .encode_packet(&sealed);
        let _ = left.send_now(pkt);
    }
}
