//! Stream Destination 1.0 RTT deferred open (`AwaitingConfirm` -> `EndpointHandler::open`
//! -> `OPEN_OK` / `TARGET_*` -> bidirectional local application bridge, Spec §6.3).

use core::future::{Future, poll_fn};
use core::task::Poll;
use std::sync::Arc;

use crate::constants::{CLOSE_SEND_TIMEOUT, SETUP_TIMEOUT, ST_OVERHEAD, STREAM_CHUNK};
use crate::crypto::cipher::StreamCipher;
use crate::engine::admission::AdmittedEndpoint;
use crate::engine::context::{
    BridgeGuard, Either, NodePendingPermit, PendingPermit, ScopeCore, race2, wait_shutdown,
    with_deadline, with_deadline_val,
};
use crate::engine::stream::framing::{
    InboundStreamFrame, StreamFrameReader, sleep_paced, write_e2e_record, write_frame,
    write_hop_control,
};
use crate::engine::stream::session::{
    DestStreamMeta, E2eStream, StreamSessionParams, StreamSessionRole, race_session_guards,
    spawn_stream_session,
};
use crate::error::CoreError;
use crate::runtime::sync::WatchReceiver;
use crate::seam::auth::StreamAction;
use crate::seam::channel::{
    BoxedStream, IntoStreamHalves, MtuWatch, StreamRead, StreamReadExt, StreamWrite,
    StreamWriteExt,
};
use crate::seam::handler::StreamEndpointHandler;
use crate::trust::lease::TrafficGateCache;
use crate::types::{Cid, Direction, Plane, Role};
use crate::wire::opcodes::{StreamOpenStatus, e2e_st, encode_wire_error_bytes, outer};
use crate::wire::setup::SetupOkHeader;

/// Executes Stream Destination 1.0 RTT admission after `admit_endpoint`:
/// emits `SETUP_OK`, holds `pending_permit` + `pending_setup` through `AwaitingConfirm`,
/// invokes `StreamEndpointHandler::open` strictly after confirmation, sends `OPEN_OK` / `TARGET_*`,
/// and spawns the bidirectional application bridge holding [`BridgeGuard`].
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_stream_destination(
    scope: Arc<ScopeCore>,
    admitted: AdmittedEndpoint,
    handler: Arc<dyn StreamEndpointHandler>,
    mut reader: Box<dyn StreamRead>,
    mut writer: Box<dyn StreamWrite>,
    mut mtu_watch: MtuWatch,
    inbound_mtu: u16,
    pending_permit: PendingPermit,
    node_pending_permit: Option<NodePendingPermit>,
) -> Result<(), CoreError> {
    let clock = Arc::clone(&scope.runtime.clock);
    let span = scope.session_span(Plane::Stream, Role::Destination);

    let AdmittedEndpoint {
        peer,
        endpoint,
        floor,
        forwarded_mtu,
        responder,
        lease,
        pending_setup,
        session_permit,
        kind: _,
    } = admitted;

    let ttl_ms = u64::try_from(lease.remaining()?.as_millis())
        .unwrap_or(u64::MAX)
        .max(1);
    let (reply, session_keys, terminal_hop_key) = responder.build_message2(inbound_mtu, ttl_ms)?;
    let ok_wire = SetupOkHeader {
        hop_acks: 0,
        reverse_mtu: inbound_mtu,
        target_cid: Cid::UNBOUND,
        responder_cid: Cid::UNBOUND,
    }
    .encode_base(&reply);

    let confirm_deadline = clock.now().saturating_add(SETUP_TIMEOUT);
    with_deadline(
        &*clock,
        confirm_deadline,
        write_frame(&mut *writer, &ok_wire, &*clock),
    )
    .await?;

    let mut tx_cipher = StreamCipher::new(session_keys.tx_key());
    let mut rx_cipher = StreamCipher::new(session_keys.rx_key());
    let mut terminal_ctrl = terminal_hop_key.control_cipher(false);
    let mut frame_reader = StreamFrameReader::new();
    let mut e2e_scratch = Vec::with_capacity(64);
    let mut chunk_scratch = Vec::with_capacity(64);
    let mut shutdown_rx = scope.subscribe_shutdown();

    let negotiated_mtu = forwarded_mtu;
    let max_write_size =
        usize::from(negotiated_mtu.min(STREAM_CHUNK as u16)).saturating_sub(ST_OVERHEAD);

    // Phase 1: AwaitingConfirm (holding pending_permit, node_pending_permit, pending_setup!).
    let confirm_res: Result<Option<Vec<u8>>, CoreError> = async {
        if scope.is_shutting_down() {
            return Err(CoreError::Closed);
        }
        let step = with_deadline_val(
            &*clock,
            confirm_deadline,
            race2(
                wait_shutdown(&mut shutdown_rx),
                race_session_guards(
                    frame_reader.next_frame(&mut *reader, &mut rx_cipher),
                    &lease,
                    &mut mtu_watch,
                    floor,
                ),
            ),
        )
        .await?;

        let frame = match step {
            Either::Left(()) => return Err(CoreError::Closed),
            Either::Right(Ok(f)) => f,
            Either::Right(Err(err)) => return Err(err),
        };

        match frame {
            InboundStreamFrame::Eof => Err(CoreError::UnexpectedEof),
            InboundStreamFrame::HopControl { hdr, body, len } => {
                if hdr.kind == outer::ST_CLOSE && hdr.ttl_or_dist == 0 {
                    let _ = terminal_ctrl.open(outer::ST_CLOSE, &body[..len])?;
                    return Err(CoreError::Closed);
                }
                Err(CoreError::Authentication)
            }
            InboundStreamFrame::E2eRenew(_) => {
                // Spec §6.3 Step 1: First E2E record MUST be ST_DATA (Zeroizing body wipes on drop).
                Err(CoreError::Authentication)
            }
            InboundStreamFrame::E2eRecord { opcode, body } => {
                // Spec §6.3 Step 1: First E2E record MUST be ST_DATA (any other fails Authentication).
                if opcode != e2e_st::ST_DATA {
                    return Err(CoreError::Authentication);
                }
                if body.len() > max_write_size {
                    return Err(CoreError::Malformed);
                }
                Ok(if body.is_empty() { None } else { Some(body) })
            }
        }
    }
    .await;

    let first_data = match confirm_res {
        Ok(d) => d,
        Err(err) => {
            tracing::debug!(
                parent: &span,
                error = err.static_code(),
                "stream destination aborted before confirmation"
            );
            return Err(err);
        }
    };

    // Step 2: Re-check lease & live MTU, then release AwaitingConfirm permits!
    lease.remaining()?;
    let cur_mtu = mtu_watch.current();
    if cur_mtu < floor {
        return Err(CoreError::MtuTooSmall(cur_mtu));
    }
    drop(pending_setup);
    drop(pending_permit);
    drop(node_pending_permit);

    // Step 3: If 1.0 RTT initial ST_DATA carried non-empty bytes, charge TrafficGate(Ingress).
    if let Some(ref data) = first_data {
        let mut gate_cache = TrafficGateCache::new();
        if let Some(gate) = gate_cache.get(&lease) {
            match gate.charge_stream(Direction::Ingress, data.len()) {
                StreamAction::Allow => {}
                StreamAction::Delay(d) => {
                    if let Err(err) = sleep_paced(d, &*clock, &lease, &mut mtu_watch, floor).await {
                        send_best_effort_terminal_close(
                            &mut *writer,
                            &mut terminal_ctrl,
                            &err,
                            &*clock,
                        )
                        .await;
                        return Err(err);
                    }
                }
                StreamAction::Close(err) => {
                    send_best_effort_terminal_close(
                        &mut *writer,
                        &mut terminal_ctrl,
                        &err,
                        &*clock,
                    )
                    .await;
                    return Err(err);
                }
            }
        }
    }

    // Step 4: Invoke EndpointHandler::open strictly AFTER confirmation, bounded by SETUP_TIMEOUT,
    // lease.cancelled(), and mtu < floor (Spec §6.3 Step 4).
    let open_deadline = clock.now().saturating_add(SETUP_TIMEOUT);
    let open_res = with_deadline(
        &*clock,
        open_deadline,
        race_session_guards(
            handler.open(lease.session_auth()),
            &lease,
            &mut mtu_watch,
            floor,
        ),
    )
    .await;

    let app_stream = match open_res {
        Ok(s) => s,
        Err(err) => {
            // Map lease cancel / MTU floor / timeout / handler errors to TARGET_* (Spec §6.3 Step 4).
            let status = if !lease.is_active() || mtu_watch.current() < floor {
                StreamOpenStatus::TargetUnreachable
            } else {
                StreamOpenStatus::from_handler_error(&err)
            };
            let dl = clock.now().saturating_add(CLOSE_SEND_TIMEOUT);
            let _ = with_deadline(
                &*clock,
                dl,
                write_e2e_record(
                    &mut *writer,
                    &mut tx_cipher,
                    status.opcode(),
                    &[],
                    mtu_watch.current(),
                    floor,
                    &*clock,
                    &mut e2e_scratch,
                    &mut chunk_scratch,
                ),
            )
            .await;
            let _ = with_deadline(&*clock, clock.now().saturating_add(CLOSE_SEND_TIMEOUT), writer.shutdown()).await;
            return Err(err);
        }
    };

    // Step 5: Send OPEN_OK (empty body, bounded by SETUP_TIMEOUT).
    let ok_send_deadline = clock.now().saturating_add(SETUP_TIMEOUT);
    with_deadline(
        &*clock,
        ok_send_deadline,
        race_session_guards(
            write_e2e_record(
                &mut *writer,
                &mut tx_cipher,
                e2e_st::OPEN_OK,
                &[],
                mtu_watch.current(),
                floor,
                &*clock,
                &mut e2e_scratch,
                &mut chunk_scratch,
            ),
            &lease,
            &mut mtu_watch,
            floor,
        ),
    )
    .await?;

    scope
        .metrics
        .record_setup_established(Plane::Stream, Role::Destination);

    // Acquire BridgeGuard BEFORE spawning the Stream session worker so `is_drained()` can never
    // transiently observe `true` if the worker exits before the bridge takes ownership of `app_stream`.
    let bridge_guard = BridgeGuard::acquire(Arc::clone(&scope));

    let e2e = spawn_stream_session(StreamSessionParams {
        scope: Arc::clone(&scope),
        peer,
        negotiated_mtu,
        floor,
        reader,
        frame_reader,
        writer,
        mtu_watch,
        tx_cipher,
        rx_cipher,
        lease,
        session_permit,
        role: StreamSessionRole::Destination(DestStreamMeta {
            endpoint,
            terminal_ctrl,
            first_data,
        }),
    });

    // Spawn bidirectional application bridge taking ownership of `bridge_guard` for `is_drained()`.
    spawn_stream_bridge(scope, e2e, app_stream, bridge_guard);
    Ok(())
}

async fn send_best_effort_terminal_close<W: StreamWrite + ?Sized>(
    writer: &mut W,
    terminal_ctrl: &mut crate::crypto::cipher::ControlCipher,
    err: &CoreError,
    clock: &dyn crate::runtime::Clock,
) {
    if *err != CoreError::Closed {
        let payload = encode_wire_error_bytes(err);
        if let Ok(sealed) = terminal_ctrl.seal(outer::ST_CLOSE, &payload) {
            let dl = clock.now().saturating_add(CLOSE_SEND_TIMEOUT);
            let _ = with_deadline(
                clock,
                dl,
                write_hop_control(writer, outer::ST_CLOSE, 0, &sealed, clock),
            )
            .await;
        }
    }
    let _ = with_deadline(
        clock,
        clock.now().saturating_add(CLOSE_SEND_TIMEOUT),
        writer.shutdown(),
    )
    .await;
}

enum AppToE2eExit {
    CleanOrHalfClosed,
    Fatal,
}

async fn wait_session_closed(rx: &mut WatchReceiver<Option<CoreError>>) -> CoreError {
    loop {
        if let Some(err) = rx.borrow_cloned() {
            return err;
        }
        if !rx.changed().await {
            return rx.borrow_cloned().unwrap_or(CoreError::Closed);
        }
    }
}

fn spawn_stream_bridge(
    scope: Arc<ScopeCore>,
    e2e: E2eStream,
    app: BoxedStream,
    guard: BridgeGuard,
) {
    let mut session_closed = e2e.subscribe_closed();
    let session_closed_dir2 = session_closed.clone();
    let spawner = Arc::clone(&scope.runtime.spawner);
    spawner.spawn(Box::pin(async move {
        let _guard = guard;
        let (mut e2e_r, mut e2e_w) = e2e.split();
        let (mut app_r, mut app_w) = app.into_halves();

        // Direction 1: e2e -> app (clean e2e ST_FIN -> app.shutdown(); fatal error aborts bridge).
        let mut dir1 = Some(Box::pin(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                match e2e_r.read(&mut buf).await {
                    Ok(0) => {
                        let _ = app_w.shutdown().await;
                        return Ok::<(), CoreError>(());
                    }
                    Ok(n) => {
                        app_w.write_all(&buf[..n]).await?;
                    }
                    Err(err) => return Err(err),
                }
            }
        }));

        // Direction 2: app -> e2e (clean app EOF -> e2e.shutdown(); fatal error aborts bridge).
        let mut dir2 = Some(Box::pin(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                match app_r.read(&mut buf).await {
                    Ok(0) => {
                        let _ = e2e_w.shutdown().await;
                        return AppToE2eExit::CleanOrHalfClosed;
                    }
                    Ok(n) => match e2e_w.write_all(&buf[..n]).await {
                        Ok(()) => {}
                        Err(CoreError::Closed) => {
                            // If outbound ST_FIN was initiated by scope `begin_shutdown()` while
                            // the session is still alive (or completed cleanly), preserve dir1!
                            let fatal = session_closed_dir2
                                .borrow_cloned()
                                .is_some_and(|err| err != CoreError::Closed);
                            return if fatal {
                                AppToE2eExit::Fatal
                            } else {
                                AppToE2eExit::CleanOrHalfClosed
                            };
                        }
                        Err(_) => return AppToE2eExit::Fatal,
                    },
                    Err(_) => return AppToE2eExit::Fatal,
                }
            }
        }));

        let mut closed_fut = Box::pin(wait_session_closed(&mut session_closed));
        let mut session_terminated = false;

        // Supervise both directions in one task (ST-09): preserve independent clean half-closes,
        // while cancelling any blocked/idle opposite half immediately on fatal session termination
        // or fatal bridge I/O errors so `BridgeGuard` drops promptly.
        poll_fn(|cx| {
            if let Some(f1) = dir1.as_mut() {
                if let Poll::Ready(res) = f1.as_mut().poll(cx) {
                    dir1 = None;
                    if res.is_err() {
                        dir2 = None;
                        return Poll::Ready(());
                    }
                }
            }
            if let Some(f2) = dir2.as_mut() {
                if let Poll::Ready(exit) = f2.as_mut().poll(cx) {
                    dir2 = None;
                    if matches!(exit, AppToE2eExit::Fatal) {
                        dir1 = None;
                        return Poll::Ready(());
                    }
                }
            }
            if dir1.is_none() && dir2.is_none() {
                return Poll::Ready(());
            }
            if !session_terminated {
                if let Poll::Ready(reason) = closed_fut.as_mut().poll(cx) {
                    session_terminated = true;
                    if reason != CoreError::Closed {
                        dir1 = None;
                        dir2 = None;
                        return Poll::Ready(());
                    }
                    // Clean two-way session completion: outbound half is already closed, so cancel
                    // any idle app read while letting `dir1` finish flushing buffered E2E data/EOF.
                    dir2 = None;
                    if dir1.is_none() {
                        return Poll::Ready(());
                    }
                }
            }
            Poll::Pending
        })
        .await;
    }));
}
