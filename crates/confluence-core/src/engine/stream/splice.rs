//! Stream Transit setup forwarding and bidirectional `st_splice` (Spec §6.2 & §6.4).
//!
//! Forwards opaque `ST_DATA` in quanta of up to `4096 B` with `TrafficGate::charge_stream`
//! pacing, keeps hop control frames immune to `TrafficGate`, uses a single-owner `left` writer
//! (zero async mutexes!), and emits best-effort upstream `hop::ST_CLOSE(UnexpectedEof)` when
//! the downstream (`right`) carrier drops unexpectedly.

use core::future::{Future, poll_fn};
use core::pin::Pin;
use core::task::Poll;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::constants::{
    CLOSE_SEND_TIMEOUT, MAX_CONTROL, SETUP_TIMEOUT, ST_HOP_HEADER, STREAM_CHUNK,
    STREAM_SPLICE_QUANTUM,
};
use crate::crypto::cipher::ControlCipher;
use crate::engine::admission::AdmittedTransit;
use crate::engine::context::{
    Either, NodePendingPermit, PendingPermit, RenewalAuthFut, ScopeCore, SessionPermit,
    poll_optional, race2, wait_mtu_below_floor, wait_shutdown, wait_signal, with_deadline,
    with_deadline_val,
};
use crate::engine::stream::framing::{
    PriorityCtrlFrame, StreamSetupReply, StreamWriterHandle, TryWriterSend, read_hop_header,
    read_setup_reply, sleep_paced, write_frame, write_frame_best_effort,
};
use crate::error::CoreError;
use crate::protocol::renewal::{RenewalVerifierState, VerifierRenewalAction};
use crate::protocol::setup::{HopOkRewriteParams, HopSetupRewrite};
use crate::runtime::sync::Watch;
use crate::seam::auth::{AuthRequest, Lease, StreamAction};
use crate::seam::channel::{
    IntoStreamHalves, MtuWatch, StreamRead, StreamReadExt, StreamWrite, StreamWriteExt,
};
use crate::seam::handler::StreamTransitHandler;
use crate::trust::lease::{LeaseHandle, TrafficGateCache};
use crate::types::{Cid, Credential, Direction, Plane, PublicKey, Role, TargetRef};
use crate::wire::datagram::{decode_renew_payload, encode_renew_ok_payload};
use crate::wire::opcodes::{
    decode_wire_error_bytes, encode_wire_error, encode_wire_error_bytes, outer,
};
use crate::wire::setup::SetupErrFrame;
use crate::wire::stream::StHopHeader;

/// Completes Stream Transit setup (opens downstream stream, forwards `SETUP_FWD`, rewrites
/// `SETUP_OK`/`SETUP_ERR`/`SETUP_COOKIE`) and enters steady-state bidirectional `st_splice`.
///
/// Emits best-effort `50 ms` `SETUP_ERR` upstream on any failure prior to sending `SETUP_OK`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_stream_transit(
    scope: Arc<ScopeCore>,
    admitted: AdmittedTransit,
    handler: Arc<dyn StreamTransitHandler>,
    hdr_max_mtu: u16,
    tail: &[u8],
    left_r: Box<dyn StreamRead>,
    mut left_w: Box<dyn StreamWrite>,
    mut left_mtu_watch: MtuWatch,
    inbound_mtu: u16,
    pending_permit: PendingPermit,
    node_pending_permit: Option<NodePendingPermit>,
) -> Result<(), CoreError> {
    let clock = Arc::clone(&scope.runtime.clock);
    let setup_deadline = clock.now().saturating_add(SETUP_TIMEOUT);

    let AdmittedTransit {
        peer,
        full_name,
        subtarget,
        floor,
        hop_key,
        lease,
        pending_setup,
        handler: _,
    } = admitted;

    type EstablishedDownstream = (
        Box<dyn StreamRead>,
        Box<dyn StreamWrite>,
        MtuWatch,
        SessionPermit,
    );
    let pre_ok: Result<Option<EstablishedDownstream>, CoreError> = async {
        // Step 1: Open downstream stream racing lease.cancelled(), SETUP_TIMEOUT, and left MTU floor.
        let right_stream = match with_deadline_val(
            &*clock,
            setup_deadline,
            race2(
                handler.open(&subtarget, lease.session_auth()),
                race2(
                    lease.cancelled(),
                    wait_mtu_below_floor(&mut left_mtu_watch, floor),
                ),
            ),
        )
        .await
        {
            Ok(Either::Left(Ok(stream))) => stream,
            Ok(Either::Left(Err(err))) => return Err(err),
            Ok(Either::Right(Either::Left(err))) => return Err(err),
            Ok(Either::Right(Either::Right(mtu))) => return Err(CoreError::MtuTooSmall(mtu)),
            Err(err) => return Err(err),
        };

        lease.remaining()?;

        let right_caps = right_stream.caps();
        let outbound_mtu = right_caps.mtu();
        let right_mtu_watch = right_caps.mtu_watch();
        let cur_inbound_mtu = left_mtu_watch.current().min(inbound_mtu);
        let physical_mtu = cur_inbound_mtu.min(outbound_mtu);
        if physical_mtu < floor {
            return Err(CoreError::MtuTooSmall(physical_mtu));
        }

        let (mut right_r, mut right_w) = right_stream.into_halves();

        // Step 2: Forward rewritten SETUP_FWD downstream and read reply racing lease + SETUP_TIMEOUT.
        let fwd = HopSetupRewrite::rewrite_forward(
            hdr_max_mtu,
            cur_inbound_mtu,
            outbound_mtu,
            Cid::UNBOUND,
            tail,
        );
        let reply = match with_deadline_val(
            &*clock,
            setup_deadline,
            race2(
                async {
                    write_frame(&mut *right_w, &fwd, &*clock).await?;
                    read_setup_reply(&mut *right_r, &*clock, setup_deadline).await
                },
                lease.cancelled(),
            ),
        )
        .await
        {
            Ok(Either::Left(Ok(reply))) => reply,
            Ok(Either::Left(Err(err))) => return Err(err),
            Ok(Either::Right(err)) => return Err(err),
            Err(err) => return Err(err),
        };

        match reply {
            StreamSetupReply::Err(err_frame) => {
                let rewritten = HopSetupRewrite::rewrite_err(&err_frame, Cid::UNBOUND)?;
                let _ = with_deadline(
                    &*clock,
                    setup_deadline,
                    write_frame(&mut *left_w, &rewritten, &*clock),
                )
                .await;
                Ok(None)
            }
            StreamSetupReply::Cookie(cookie_frame) => {
                let rewritten = HopSetupRewrite::rewrite_cookie(&cookie_frame, Cid::UNBOUND)?;
                let _ = with_deadline(
                    &*clock,
                    setup_deadline,
                    write_frame(&mut *left_w, &rewritten, &*clock),
                )
                .await;
                Ok(None)
            }
            StreamSetupReply::Ok(mut ok_wire) => {
                let ttl_ms = u64::try_from(lease.remaining()?.as_millis())
                    .unwrap_or(u64::MAX)
                    .max(1);
                let live_physical = left_mtu_watch.current().min(right_mtu_watch.current());
                if live_physical < floor {
                    return Err(CoreError::MtuTooSmall(live_physical));
                }
                HopSetupRewrite::rewrite_ok(
                    &mut ok_wire,
                    &HopOkRewriteParams {
                        plane: Plane::Stream,
                        expected_right_cid: Cid::UNBOUND,
                        inbound_upstream_cid: Cid::UNBOUND,
                        left_binding_cid: Cid::UNBOUND,
                        physical_mtu: live_physical,
                        hop_lease_ttl_ms: ttl_ms,
                        hop_key: &hop_key,
                        max_wire_len: STREAM_CHUNK,
                    },
                )?;

                let session_permit = scope.try_acquire_session(Plane::Stream, Role::Transit)?;

                with_deadline(
                    &*clock,
                    setup_deadline,
                    write_frame(&mut *left_w, &ok_wire, &*clock),
                )
                .await?;

                Ok(Some((right_r, right_w, right_mtu_watch, session_permit)))
            }
        }
    }
    .await;

    let Some((right_r, right_w, right_mtu_watch, session_permit)) = (match pre_ok {
        Ok(opt) => opt,
        Err(err) => {
            let (code, arg) = encode_wire_error(&err);
            let frame = SetupErrFrame {
                distance: 0,
                target_cid: Cid::UNBOUND,
                body: hop_key.seal_setup_error(code, arg),
            }
            .encode();
            write_frame_best_effort(&mut *left_w, &frame, &*clock).await;
            return Err(err);
        }
    }) else {
        return Ok(());
    };

    // Release setup permits BEFORE entering steady-state splice.
    drop(pending_setup);
    drop(pending_permit);
    drop(node_pending_permit);

    scope
        .metrics
        .record_setup_established(Plane::Stream, Role::Transit);

    run_stream_splice(
        scope,
        peer,
        full_name,
        floor,
        hop_key.control_cipher(false),
        lease,
        session_permit,
        left_r,
        left_w,
        left_mtu_watch,
        right_r,
        right_w,
        right_mtu_watch,
    )
    .await;
    Ok(())
}

enum SpliceCtrlEvent {
    CloseClean,
    Fatal(CoreError),
}

#[allow(clippy::too_many_arguments)]
async fn run_stream_splice(
    scope: Arc<ScopeCore>,
    peer: PublicKey,
    full_name: String,
    floor: u16,
    mut ctrl: ControlCipher,
    lease: Arc<LeaseHandle>,
    _session_permit: SessionPermit,
    mut left_r: Box<dyn StreamRead>,
    left_w: Box<dyn StreamWrite>,
    mut left_mtu_watch: MtuWatch,
    mut right_r: Box<dyn StreamRead>,
    mut right_w: Box<dyn StreamWrite>,
    mut right_mtu_watch: MtuWatch,
) {
    let clock = Arc::clone(&scope.runtime.clock);
    let span = scope.session_span(Plane::Stream, Role::Transit);

    // Single-owner `left_w` task: receives right->left data/control + transit's own control replies (zero async locks!).
    let left_writer = StreamWriterHandle::spawn(
        left_w,
        left_mtu_watch.clone(),
        floor,
        Arc::clone(&clock),
        &*scope.runtime.spawner,
    );

    // Shared control channel from left->right and right->left tasks to coordinator.
    let (ev_tx, ev_rx) = async_channel::bounded::<SpliceCtrlEvent>(16);

    // Coordinator is the SINGLE owner of `ControlCipher` (zero mutexes!).
    let (fwd_ctrl_tx, fwd_ctrl_rx) =
        async_channel::bounded::<(StHopHeader, [u8; MAX_CONTROL], usize)>(16);

    // Circuit-wide cancellation & clean completion barriers for both forwarding tasks (ST-07).
    let (cancel_tx, cancel_rx) = Watch::new(false);
    let (l2r_done_tx, mut l2r_done_rx) = Watch::new(false);
    let (r2l_done_tx, mut r2l_done_rx) = Watch::new(false);

    // Spawn left -> right (Ingress) forwarding task, racing the ENTIRE loop against cancellation.
    {
        let scope_c = Arc::clone(&scope);
        let lease_c = Arc::clone(&lease);
        let clock_c = Arc::clone(&clock);
        let mut right_mtu_c = right_mtu_watch.clone();
        let ev_tx_c = ev_tx.clone();
        let fwd_ctrl_tx_c = fwd_ctrl_tx.clone();
        let mut cancel_rx_c = cancel_rx.clone();
        let mut shut_rx = scope.subscribe_shutdown();
        scope.runtime.spawner.spawn(Box::pin(async move {
            let mut gate_cache = TrafficGateCache::new();
            let mut buf = vec![0u8; ST_HOP_HEADER + STREAM_SPLICE_QUANTUM];
            let res: Result<(), CoreError> = {
                let forward = async {
                    loop {
                        let Some(mut hdr) = read_hop_header(&mut *left_r).await? else {
                            // Upstream closed cleanly without ST_CLOSE.
                            return Ok(());
                        };

                        if hdr.kind == outer::ST_DATA {
                            let mut remaining = usize::from(hdr.len);
                            while remaining > 0 {
                                let out_mtu = usize::from(right_mtu_c.current());
                                if out_mtu < usize::from(floor) {
                                    return Err(CoreError::MtuTooSmall(right_mtu_c.current()));
                                }
                                let quantum =
                                    remaining.min(out_mtu.max(1)).min(STREAM_SPLICE_QUANTUM);
                                left_r
                                    .read_exact(&mut buf[ST_HOP_HEADER..ST_HOP_HEADER + quantum])
                                    .await?;

                                lease_c.remaining()?;
                                if let Some(gate) = gate_cache.get(&lease_c) {
                                    match gate.charge_stream(Direction::Ingress, quantum) {
                                        StreamAction::Allow => {}
                                        StreamAction::Delay(d) => {
                                            sleep_paced(
                                                d,
                                                &*clock_c,
                                                &lease_c,
                                                &mut right_mtu_c,
                                                floor,
                                            )
                                            .await?;
                                        }
                                        StreamAction::Close(err) => return Err(err),
                                    }
                                }

                                let q_len =
                                    u16::try_from(quantum).map_err(|_| CoreError::Malformed)?;
                                let out_hdr = StHopHeader {
                                    kind: outer::ST_DATA,
                                    ttl_or_dist: 0,
                                    len: q_len,
                                };
                                buf[..ST_HOP_HEADER].copy_from_slice(&out_hdr.encode());
                                write_frame(
                                    &mut *right_w,
                                    &buf[..ST_HOP_HEADER + quantum],
                                    &*clock_c,
                                )
                                .await?;
                                scope_c
                                    .metrics
                                    .record_rx(Plane::Stream, quantum as u64, false);
                                remaining -= quantum;
                            }
                        } else {
                            // Hop control frame bypasses TrafficGate (Spec §6.4).
                            let body_len = usize::from(hdr.len);
                            let mut body = [0u8; MAX_CONTROL];
                            left_r.read_exact(&mut body[..body_len]).await?;
                            if hdr.ttl_or_dist == 0 {
                                if fwd_ctrl_tx_c.send((hdr, body, body_len)).await.is_err() {
                                    return Ok(());
                                }
                            } else {
                                hdr.ttl_or_dist -= 1;
                                let mut frame = [0u8; ST_HOP_HEADER + MAX_CONTROL];
                                frame[..ST_HOP_HEADER].copy_from_slice(&hdr.encode());
                                frame[ST_HOP_HEADER..ST_HOP_HEADER + body_len]
                                    .copy_from_slice(&body[..body_len]);
                                write_frame(
                                    &mut *right_w,
                                    &frame[..ST_HOP_HEADER + body_len],
                                    &*clock_c,
                                )
                                .await?;
                            }
                        }
                    }
                };
                let cancel = async {
                    match race2(
                        wait_signal(&mut cancel_rx_c),
                        race2(lease_c.cancelled(), wait_shutdown(&mut shut_rx)),
                    )
                    .await
                    {
                        Either::Left(()) => CoreError::Closed,
                        Either::Right(Either::Left(err)) => err,
                        Either::Right(Either::Right(())) => CoreError::Closed,
                    }
                };
                match race2(forward, cancel).await {
                    Either::Left(r) => r,
                    Either::Right(err) => Err(err),
                }
            };

            let _ = with_deadline(
                &*clock_c,
                clock_c.now().saturating_add(CLOSE_SEND_TIMEOUT),
                right_w.shutdown(),
            )
            .await;
            match res {
                Ok(()) => {
                    let _ = ev_tx_c.try_send(SpliceCtrlEvent::CloseClean);
                }
                Err(err) => {
                    let _ = ev_tx_c.try_send(SpliceCtrlEvent::Fatal(err));
                }
            }
            // Drop all carrier halves, lease/SessionGuards, and scope refs BEFORE signalling done (ST-07).
            drop(left_r);
            drop(right_w);
            drop(fwd_ctrl_tx_c);
            drop(ev_tx_c);
            drop(lease_c);
            drop(scope_c);
            l2r_done_tx.send(true);
        }));
    }

    // Spawn right -> left (Egress) forwarding task, racing the ENTIRE loop against cancellation.
    {
        let scope_c = Arc::clone(&scope);
        let lease_c = Arc::clone(&lease);
        let clock_c = Arc::clone(&clock);
        let mut left_mtu_c = left_mtu_watch.clone();
        let left_w_handle = left_writer.clone();
        let ev_tx_c = ev_tx.clone();
        let mut cancel_rx_c = cancel_rx;
        let mut shut_rx = scope.subscribe_shutdown();
        scope.runtime.spawner.spawn(Box::pin(async move {
            let mut gate_cache = TrafficGateCache::new();
            let res: Result<(), CoreError> = {
                let forward = async {
                    loop {
                        let Some(mut hdr) = read_hop_header(&mut *right_r).await? else {
                            // Spec §6.4 + ST-05: Preserve FIFO barrier so all previously accepted
                            // reverse ST_DATA bytes (e.g. final response + ST_FIN) reach upstream
                            // before EOF-triggered hop::ST_CLOSE(UnexpectedEof) & teardown!
                            left_w_handle.flush_fifo().await?;
                            return Err(CoreError::UnexpectedEof);
                        };

                        if hdr.kind == outer::ST_DATA {
                            let mut remaining = usize::from(hdr.len);
                            while remaining > 0 {
                                let out_mtu = usize::from(left_mtu_c.current());
                                if out_mtu < usize::from(floor) {
                                    return Err(CoreError::MtuTooSmall(left_mtu_c.current()));
                                }
                                let quantum =
                                    remaining.min(out_mtu.max(1)).min(STREAM_SPLICE_QUANTUM);
                                let mut chunk = vec![0u8; ST_HOP_HEADER + quantum];
                                right_r
                                    .read_exact(&mut chunk[ST_HOP_HEADER..ST_HOP_HEADER + quantum])
                                    .await?;

                                lease_c.remaining()?;
                                if let Some(gate) = gate_cache.get(&lease_c) {
                                    match gate.charge_stream(Direction::Egress, quantum) {
                                        StreamAction::Allow => {}
                                        StreamAction::Delay(d) => {
                                            sleep_paced(
                                                d,
                                                &*clock_c,
                                                &lease_c,
                                                &mut left_mtu_c,
                                                floor,
                                            )
                                            .await?;
                                        }
                                        StreamAction::Close(err) => return Err(err),
                                    }
                                }

                                let q_len =
                                    u16::try_from(quantum).map_err(|_| CoreError::Malformed)?;
                                let out_hdr = StHopHeader {
                                    kind: outer::ST_DATA,
                                    ttl_or_dist: 0,
                                    len: q_len,
                                };
                                chunk[..ST_HOP_HEADER].copy_from_slice(&out_hdr.encode());
                                left_w_handle.send_preframed(chunk).await?;
                                scope_c
                                    .metrics
                                    .record_tx(Plane::Stream, quantum as u64, false);
                                remaining -= quantum;
                            }
                        } else {
                            // Reverse control frame: increment distance, bypass TrafficGate.
                            // Forward reverse ST_CLOSE in FIFO order after already-accepted reverse
                            // ST_DATA chunks (ST-05), while keeping renewal controls prioritized.
                            let body_len = usize::from(hdr.len);
                            let mut body = [0u8; MAX_CONTROL];
                            right_r.read_exact(&mut body[..body_len]).await?;
                            hdr.ttl_or_dist = hdr
                                .ttl_or_dist
                                .checked_add(1)
                                .ok_or(CoreError::Malformed)?;
                            let frame = PriorityCtrlFrame::from_slice(
                                hdr.kind,
                                hdr.ttl_or_dist,
                                &body[..body_len],
                            )?;
                            if hdr.kind == outer::ST_CLOSE {
                                left_w_handle.send_fifo_hop_control(frame).await?;
                            } else {
                                left_w_handle.send_hop_control(frame).await?;
                            }
                        }
                    }
                };
                let cancel = async {
                    match race2(
                        wait_signal(&mut cancel_rx_c),
                        race2(lease_c.cancelled(), wait_shutdown(&mut shut_rx)),
                    )
                    .await
                    {
                        Either::Left(()) => CoreError::Closed,
                        Either::Right(Either::Left(err)) => err,
                        Either::Right(Either::Right(())) => CoreError::Closed,
                    }
                };
                match race2(forward, cancel).await {
                    Either::Left(r) => r,
                    Either::Right(err) => Err(err),
                }
            };

            match res {
                Ok(()) => {
                    let _ = ev_tx_c.try_send(SpliceCtrlEvent::CloseClean);
                }
                Err(err) => {
                    let _ = ev_tx_c.try_send(SpliceCtrlEvent::Fatal(err));
                }
            }
            // Drop all carrier halves, lease/SessionGuards, and scope refs BEFORE signalling done (ST-07).
            drop(right_r);
            drop(left_w_handle);
            drop(ev_tx_c);
            drop(lease_c);
            drop(scope_c);
            r2l_done_tx.send(true);
        }));
    }

    drop(ev_tx);
    drop(fwd_ctrl_tx);

    type UnitResultFut = Pin<Box<dyn Future<Output = Result<(), CoreError>> + Send>>;

    // Coordinator loop: single owner of `ControlCipher`, `RenewalVerifierState`, MTU floor monitors,
    // lease cancellation, non-blocking control reply sends, and shutdown signal.
    let mut shutdown_rx = scope.subscribe_shutdown();
    let mut verifier = RenewalVerifierState::new();
    let mut auth_fut: Option<RenewalAuthFut> = None;
    let mut fwd_ctrl_closed = false;
    let mut pending_ctrl_frames: VecDeque<PriorityCtrlFrame> = VecDeque::new();
    let mut pending_ctrl_send: Option<UnitResultFut> = None;

    let queue_ctrl = |frame: PriorityCtrlFrame,
                      pending_frames: &mut VecDeque<PriorityCtrlFrame>,
                      in_flight: &mut Option<UnitResultFut>|
     -> Result<(), CoreError> {
        if in_flight.is_none() && pending_frames.is_empty() {
            match left_writer.try_send_hop_control(frame) {
                TryWriterSend::Sent => Ok(()),
                TryWriterSend::Full(frame) => {
                    let wh = left_writer.clone();
                    *in_flight = Some(Box::pin(async move { wh.send_hop_control(frame).await }));
                    Ok(())
                }
                TryWriterSend::Closed(err) => Err(err),
            }
        } else {
            pending_frames.push_back(frame);
            Ok(())
        }
    };

    let exit_result: Result<(), CoreError> = loop {
        enum Ev {
            LeaseCancelled(CoreError),
            LeftFloor(u16),
            RightFloor(u16),
            LeftWriteFail(CoreError),
            Shutdown,
            CtrlSent(Result<(), CoreError>),
            FwdCtrl(Result<(StHopHeader, [u8; MAX_CONTROL], usize), async_channel::RecvError>),
            Subtask(Result<SpliceCtrlEvent, async_channel::RecvError>),
            AuthDone(u64, Result<Lease, CoreError>),
        }

        let ev = {
            let mut l_fut = Box::pin(lease.cancelled());
            let mut lm_fut = Box::pin(wait_mtu_below_floor(&mut left_mtu_watch, floor));
            let mut rm_fut = Box::pin(wait_mtu_below_floor(&mut right_mtu_watch, floor));
            let mut wf_fut = Box::pin(left_writer.failed());
            let mut sh_fut = Box::pin(wait_shutdown(&mut shutdown_rx));
            let mut fc_fut = Box::pin(async {
                if fwd_ctrl_closed {
                    core::future::pending().await
                } else {
                    fwd_ctrl_rx.recv().await
                }
            });
            let mut sub_fut = Box::pin(ev_rx.recv());

            poll_fn(|cx| {
                if let Poll::Ready(err) = l_fut.as_mut().poll(cx) {
                    return Poll::Ready(Ev::LeaseCancelled(err));
                }
                if let Poll::Ready(mtu) = lm_fut.as_mut().poll(cx) {
                    return Poll::Ready(Ev::LeftFloor(mtu));
                }
                if let Poll::Ready(mtu) = rm_fut.as_mut().poll(cx) {
                    return Poll::Ready(Ev::RightFloor(mtu));
                }
                if let Poll::Ready(err) = wf_fut.as_mut().poll(cx) {
                    return Poll::Ready(Ev::LeftWriteFail(err));
                }
                if let Poll::Ready(()) = sh_fut.as_mut().poll(cx) {
                    return Poll::Ready(Ev::Shutdown);
                }
                if let Poll::Ready(res) = poll_optional(&mut pending_ctrl_send, cx) {
                    return Poll::Ready(Ev::CtrlSent(res));
                }
                if let Poll::Ready((id, res)) = poll_optional(&mut auth_fut, cx) {
                    return Poll::Ready(Ev::AuthDone(id, res));
                }
                if let Poll::Ready(m) = fc_fut.as_mut().poll(cx) {
                    return Poll::Ready(Ev::FwdCtrl(m));
                }
                if let Poll::Ready(m) = sub_fut.as_mut().poll(cx) {
                    return Poll::Ready(Ev::Subtask(m));
                }
                Poll::Pending
            })
            .await
        };

        match ev {
            Ev::LeaseCancelled(err) => break Err(err),
            Ev::LeftFloor(mtu) | Ev::RightFloor(mtu) => break Err(CoreError::MtuTooSmall(mtu)),
            Ev::LeftWriteFail(err) => break Err(err),
            Ev::Shutdown => break Err(CoreError::Closed),
            Ev::CtrlSent(Ok(())) => {
                let mut err_out = None;
                while pending_ctrl_send.is_none() {
                    let Some(frame) = pending_ctrl_frames.pop_front() else {
                        break;
                    };
                    match left_writer.try_send_hop_control(frame) {
                        TryWriterSend::Sent => {}
                        TryWriterSend::Full(frame) => {
                            let wh = left_writer.clone();
                            pending_ctrl_send =
                                Some(Box::pin(async move { wh.send_hop_control(frame).await }));
                            break;
                        }
                        TryWriterSend::Closed(err) => {
                            err_out = Some(err);
                            break;
                        }
                    }
                }
                if let Some(err) = err_out {
                    break Err(err);
                }
            }
            Ev::CtrlSent(Err(err)) => break Err(err),
            Ev::FwdCtrl(Err(_)) => {
                fwd_ctrl_closed = true;
            }
            Ev::FwdCtrl(Ok((hdr, body, len))) => {
                match hdr.kind {
                    outer::ST_CLOSE => {
                        let pt = match ctrl.open(outer::ST_CLOSE, &body[..len]) {
                            Ok(pt) => pt,
                            Err(err) => break Err(err),
                        };
                        let _ = match decode_wire_error_bytes(&pt) {
                            Ok(e) => e,
                            Err(e) => break Err(e),
                        };
                        // Spec §6.4: Authentic hop::ST_CLOSE(ttl == 0) terminates splice cleanly!
                        break Ok(());
                    }
                    outer::ST_RENEW => {
                        let pt = match ctrl.open(outer::ST_RENEW, &body[..len]) {
                            Ok(pt) => pt,
                            Err(err) => break Err(err),
                        };
                        let (id, cred_slice) = match decode_renew_payload(&pt) {
                            Ok(v) => v,
                            Err(err) => break Err(err),
                        };
                        match verifier.classify(id) {
                            VerifierRenewalAction::Malformed => break Err(CoreError::Malformed),
                            VerifierRenewalAction::Ignore => {}
                            VerifierRenewalAction::ReplyIdempotent(ack_id) => {
                                let rem = match lease.remaining() {
                                    Ok(d) => d,
                                    Err(err) => break Err(err),
                                };
                                let rem_ms =
                                    u64::try_from(rem.as_millis()).unwrap_or(u64::MAX).max(1);
                                let payload = encode_renew_ok_payload(ack_id, rem_ms);
                                let sealed = match ctrl.seal(outer::ST_RENEW_OK, &payload) {
                                    Ok(s) => s,
                                    Err(err) => break Err(err),
                                };
                                if let Ok(frame) =
                                    PriorityCtrlFrame::from_slice(outer::ST_RENEW_OK, 0, &sealed)
                                {
                                    if let Err(err) = queue_ctrl(
                                        frame,
                                        &mut pending_ctrl_frames,
                                        &mut pending_ctrl_send,
                                    ) {
                                        break Err(err);
                                    }
                                }
                            }
                            VerifierRenewalAction::AuthorizeNew(new_id) => {
                                let cred = match Credential::from_slice(cred_slice) {
                                    Ok(c) => c,
                                    Err(_) => break Err(CoreError::Malformed),
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
                                                plane: Plane::Stream,
                                            },
                                            credential: cred.as_bytes(),
                                            is_renewal: true,
                                        })
                                        .await;
                                    (new_id, res)
                                }));
                            }
                        }
                    }
                    outer::ST_RENEW_OK => {
                        // Spec §5.7.2: at ttl == 0 on forward path, ST_RENEW_OK is ignored.
                    }
                    _ => break Err(CoreError::Malformed),
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
                    let payload = encode_renew_ok_payload(id, rem_ms);
                    let sealed = match ctrl.seal(outer::ST_RENEW_OK, &payload) {
                        Ok(s) => s,
                        Err(err) => break Err(err),
                    };
                    if let Ok(frame) = PriorityCtrlFrame::from_slice(outer::ST_RENEW_OK, 0, &sealed)
                    {
                        if let Err(err) = queue_ctrl(
                            frame,
                            &mut pending_ctrl_frames,
                            &mut pending_ctrl_send,
                        ) {
                            break Err(err);
                        }
                    }
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
            Ev::Subtask(Ok(SpliceCtrlEvent::CloseClean)) | Ev::Subtask(Err(_)) => break Ok(()),
            Ev::Subtask(Ok(SpliceCtrlEvent::Fatal(err))) => break Err(err),
        }
    };

    // 1. Cancel both forwarding tasks immediately (interrupting mid-body reads/writes, ST-07).
    cancel_tx.send(true);
    lease.revoke(exit_result.as_ref().err().cloned().unwrap_or(CoreError::Closed));
    fwd_ctrl_rx.close();
    ev_rx.close();
    drop(pending_ctrl_send);
    pending_ctrl_frames.clear();

    // 2. On Err(e) emit best-effort upstream hop::ST_CLOSE(e) and tear down left_writer.
    let mut close_frames = Vec::new();
    if let Err(ref err) = exit_result {
        tracing::debug!(
            parent: &span,
            error = err.static_code(),
            "stream transit terminating abnormally"
        );
        let payload = encode_wire_error_bytes(err);
        if let Ok(sealed) = ctrl.seal(outer::ST_CLOSE, &payload) {
            if let Ok(frame) = PriorityCtrlFrame::from_slice(outer::ST_CLOSE, 0, &sealed) {
                close_frames.push(frame);
            }
        }
    }
    left_writer.teardown(close_frames, true).await;

    // 3. Await BOTH forwarding tasks' clean completion BEFORE dropping `_session_permit`,
    //    `LeaseHandle`, `SessionGuard`s, and carrier halves (ST-07).
    wait_signal(&mut l2r_done_rx).await;
    wait_signal(&mut r2l_done_rx).await;
}
