//! Datagram Destination 1.0 RTT deferred open (`AwaitingConfirm` -> `EndpointHandler::open`
//! -> bidirectional local `DatagramLink` bridge, Spec §6.3).

use core::future::{Future, poll_fn};
use core::task::Poll;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::constants::SETUP_TIMEOUT;
use crate::crypto::cipher::{DatagramRx, DatagramTx};
use crate::engine::admission::AdmittedEndpoint;
use crate::engine::context::{
    BridgeGuard, Either, NodePendingPermit, PendingPermit, ScopeCore, race2, wait_shutdown,
    with_deadline_val,
};
use crate::engine::datagram::port::Binding;
use crate::engine::datagram::session::{
    DatagramSessionParams, DatagramSessionRole, DestDatagramMeta, E2eDatagram, build_e2e_packet,
    spawn_datagram_session,
};
use crate::error::CoreError;
use crate::packet::PacketBuf;
use crate::protocol::mtu::DestPathMtu;
use crate::runtime::sync::WatchReceiver;
use crate::seam::auth::DatagramAction;
use crate::seam::channel::{DatagramLink, DatagramLinkExt};
use crate::seam::handler::DatagramEndpointHandler;
use crate::trust::lease::TrafficGateCache;
use crate::types::{Cid, Direction, Plane, Role};
use crate::wire::datagram::strip_dg_data_header;
use crate::wire::opcodes::{e2e_dg, encode_wire_error_bytes, outer};
use crate::wire::setup::SetupOkHeader;

/// Executes Datagram Destination 1.0 RTT admission after `admit_endpoint` + CID `binding`:
/// emits `SETUP_OK`, holds `pending_permit` + `pending_setup` through `AwaitingConfirm`,
/// suppresses originator `seq == 0 && body.is_empty()`, ignores all `0x23..=0x27`, invokes
/// `DatagramEndpointHandler::open` strictly after confirmation, and bridges `DatagramLink`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_datagram_destination(
    scope: Arc<ScopeCore>,
    admitted: AdmittedEndpoint,
    handler: Arc<dyn DatagramEndpointHandler>,
    binding: Binding,
    upstream_cid: Cid,
    inbound_mtu: u16,
    pending_permit: PendingPermit,
    node_pending_permit: Option<NodePendingPermit>,
) -> Result<(), CoreError> {
    let clock = Arc::clone(&scope.runtime.clock);
    let span = scope.session_span(Plane::Datagram, Role::Destination);

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
    let (reply, session_keys, _terminal_hop_key) = responder.build_message2(inbound_mtu, ttl_ms)?;
    let ok_wire = SetupOkHeader {
        hop_acks: 0,
        reverse_mtu: inbound_mtu,
        target_cid: upstream_cid,
        responder_cid: binding.cid(),
    }
    .encode_base(&reply);

    let confirm_deadline = clock.now().saturating_add(SETUP_TIMEOUT);
    binding
        .send_reliable_until(PacketBuf::from_payload(&ok_wire), &*clock, confirm_deadline)
        .await?;

    let mut tx = DatagramTx::new(session_keys.tx_key());
    let mut rx = DatagramRx::new(session_keys.rx_key());
    let mut shutdown_rx = scope.subscribe_shutdown();

    // Phase 1: AwaitingConfirm (retaining pending_permit, node_pending_permit, pending_setup!).
    // Prioritize lease cancellation and scope shutdown over queued receive packets (DG-01).
    let confirm_res: Result<Option<PacketBuf>, (CoreError, bool)> = async {
        loop {
            if let Err(err) = lease.remaining() {
                return Err((err, true));
            }
            if scope.is_shutting_down() {
                return Err((CoreError::Closed, true));
            }

            let step = with_deadline_val(
                &*clock,
                confirm_deadline,
                race2(
                    race2(lease.cancelled(), wait_shutdown(&mut shutdown_rx)),
                    binding.recv(),
                ),
            )
            .await
            .map_err(|err| (err, false))?;

            let mut pkt = match step {
                Either::Left(Either::Left(err)) => return Err((err, true)),
                Either::Left(Either::Right(())) => return Err((CoreError::Closed, true)),
                Either::Right(Ok(p)) => p,
                Either::Right(Err(err)) => return Err((err, false)),
            };

            // Spec §5.7.1 & §6.3: Silently ignore all non-DG_DATA packets (including 0x23..=0x27)
            // and undecryptable packets!
            if pkt.payload().first() != Some(&outer::DG_DATA) {
                continue;
            }
            if strip_dg_data_header(&mut pkt).is_err() {
                continue;
            }
            let Ok((seq, opcode)) = rx.open(&mut pkt) else {
                continue;
            };

            match opcode {
                e2e_dg::DG_CLOSE => {
                    // Authenticated e2e::DG_CLOSE aborts AwaitingConfirm WITHOUT invoking handler!
                    return Err((CoreError::Closed, false));
                }
                e2e_dg::DG_DATA => {
                    // DG-01: Verify active lease AND non-shutdown even on empty seq == 0 marker!
                    if let Err(err) = lease.remaining() {
                        return Err((err, true));
                    }
                    if scope.is_shutting_down() {
                        return Err((CoreError::Closed, true));
                    }
                    if seq == 0 && pkt.is_empty() {
                        // Spec §5.8.1 & §6.3: Confirmed with first = None (suppressed!).
                        return Ok(None);
                    }
                    return Ok(Some(pkt));
                }
                e2e_dg::DG_RENEW => {
                    pkt.zeroize_payload();
                    continue;
                }
                _ => continue,
            }
        }
    }
    .await;

    let mut first_packet = match confirm_res {
        Ok(pkt) => pkt,
        Err((err, notify_peer)) => {
            tracing::debug!(
                parent: &span,
                error = err.static_code(),
                "datagram destination aborted before confirmation"
            );
            if notify_peer {
                send_dest_e2e_close(&binding, &mut tx, upstream_cid, &err).await;
            }
            return Err(err);
        }
    };

    // Release AwaitingConfirm permits BEFORE calling EndpointHandler::open.
    drop(pending_setup);
    drop(pending_permit);
    drop(node_pending_permit);

    // Step 3: If first_packet is Some, check TrafficGate(Ingress) (Spec §6.3 Step 3).
    if let Some(ref pkt) = first_packet {
        let mut gate_cache = TrafficGateCache::new();
        if let Some(gate) = gate_cache.get(&lease) {
            match gate.check_datagram(Direction::Ingress, pkt.len()) {
                DatagramAction::Allow => {}
                DatagramAction::Drop => {
                    scope
                        .metrics
                        .traffic_gate_drops_total
                        .fetch_add(1, Ordering::Relaxed);
                    first_packet = None;
                }
                DatagramAction::Close(err) => {
                    send_dest_e2e_close(&binding, &mut tx, upstream_cid, &err).await;
                    return Err(err);
                }
            }
        }
    }

    // DG-01: Re-check lease and scope shutdown BEFORE invoking `handler.open()`.
    if let Err(err) = lease.remaining() {
        send_dest_e2e_close(&binding, &mut tx, upstream_cid, &err).await;
        return Err(err);
    }
    if scope.is_shutting_down() {
        send_dest_e2e_close(&binding, &mut tx, upstream_cid, &CoreError::Closed).await;
        return Err(CoreError::Closed);
    }

    // Step 4: Invoke DatagramEndpointHandler::open strictly AFTER confirmation,
    // bounded by SETUP_TIMEOUT and raced against BOTH lease.cancelled() and scope shutdown (DG-01).
    let open_deadline = clock.now().saturating_add(SETUP_TIMEOUT);
    let open_res = with_deadline_val(
        &*clock,
        open_deadline,
        race2(
            race2(lease.cancelled(), wait_shutdown(&mut shutdown_rx)),
            handler.open(lease.session_auth()),
        ),
    )
    .await;

    let app_link = match open_res {
        Ok(Either::Right(Ok(link))) => link,
        Ok(Either::Right(Err(err))) => {
            send_dest_e2e_close(&binding, &mut tx, upstream_cid, &err).await;
            return Err(err);
        }
        Ok(Either::Left(Either::Left(err))) => {
            send_dest_e2e_close(&binding, &mut tx, upstream_cid, &err).await;
            return Err(err);
        }
        Ok(Either::Left(Either::Right(()))) => {
            send_dest_e2e_close(&binding, &mut tx, upstream_cid, &CoreError::Closed).await;
            return Err(CoreError::Closed);
        }
        Err(err) => {
            send_dest_e2e_close(&binding, &mut tx, upstream_cid, &err).await;
            return Err(err);
        }
    };

    // Final re-check after `handler.open()` returned before recording established.
    if let Err(err) = lease.remaining() {
        drop(app_link);
        send_dest_e2e_close(&binding, &mut tx, upstream_cid, &err).await;
        return Err(err);
    }
    if scope.is_shutting_down() {
        drop(app_link);
        send_dest_e2e_close(&binding, &mut tx, upstream_cid, &CoreError::Closed).await;
        return Err(CoreError::Closed);
    }

    scope
        .metrics
        .record_setup_established(Plane::Datagram, Role::Destination);

    let mtu_watch = binding.mtu_watch();
    let path_mtu = DestPathMtu::new(forwarded_mtu, inbound_mtu, floor);

    // Acquire BridgeGuard BEFORE spawning the Datagram session worker so `is_drained()` can NEVER
    // transiently observe `true` during concurrent shutdown if the worker exits and releases
    // `session_permit` before the bridge task takes ownership of `app_link` (R2-DG-06).
    let bridge_guard = BridgeGuard::acquire(Arc::clone(&scope));

    let e2e = spawn_datagram_session(DatagramSessionParams {
        scope: Arc::clone(&scope),
        peer,
        binding,
        remote_cid: upstream_cid,
        mtu_watch,
        tx,
        rx,
        lease,
        session_permit,
        role: DatagramSessionRole::Destination(DestDatagramMeta {
            endpoint,
            path_mtu,
            initial_local_mtu: inbound_mtu,
            first_packet,
        }),
    });

    spawn_datagram_bridge(scope, e2e, app_link, bridge_guard);
    Ok(())
}

async fn send_dest_e2e_close(
    binding: &Binding,
    tx: &mut DatagramTx,
    upstream_cid: Cid,
    err: &CoreError,
) {
    let bytes = encode_wire_error_bytes(err);
    if let Ok(close_pkt) = build_e2e_packet(tx, e2e_dg::DG_CLOSE, &bytes, upstream_cid) {
        binding.send_best_effort(close_pkt).await;
    }
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

/// Maximum consecutive packets forwarded in one bridge direction per poll before yielding
/// back to the supervisor (preventing always-ready app links from starving reverse traffic,
/// session closure, or scope shutdown, R2-DG-05).
const BRIDGE_POLL_BURST: usize = 16;

fn spawn_datagram_bridge(
    scope: Arc<ScopeCore>,
    e2e: E2eDatagram,
    app_link: Arc<dyn DatagramLink>,
    guard: BridgeGuard,
) {
    let mut session_closed = e2e.subscribe_closed();
    let mut shutdown_rx = scope.subscribe_shutdown();
    let spawner = Arc::clone(&scope.runtime.spawner);

    spawner.spawn(Box::pin(async move {
        let _guard = guard;
        {
            let e2e_in = e2e.clone();
            let app_out = Arc::clone(&app_link);
            let dir1 = async move {
                let mut burst = 0usize;
                while let Ok(pkt) = e2e_in.recv().await {
                    match app_out.send(pkt).await {
                        Ok(()) => {
                            burst += 1;
                            if burst >= BRIDGE_POLL_BURST {
                                burst = 0;
                                yield_once().await;
                            }
                        }
                        Err(err)
                            if err.is_retryable() || matches!(err, CoreError::MtuTooSmall(_)) =>
                        {
                            burst = 0;
                            yield_once().await;
                        }
                        Err(err) => {
                            // Propagate fatal app-link failure through authenticated e2e::DG_CLOSE (R2-DG-07).
                            e2e_in.close_with_error(err);
                            break;
                        }
                    }
                }
            };

            let e2e_out = e2e.clone();
            let app_in = Arc::clone(&app_link);
            let dir2 = async move {
                let mut burst = 0usize;
                loop {
                    let pkt = match app_in.recv().await {
                        Ok(p) => p,
                        Err(err) => {
                            // Propagate fatal app-link failure through authenticated e2e::DG_CLOSE (R2-DG-07).
                            e2e_out.close_with_error(err);
                            break;
                        }
                    };
                    match e2e_out.send_wait(pkt).await {
                        Ok(()) => {
                            burst += 1;
                            if burst >= BRIDGE_POLL_BURST {
                                burst = 0;
                                yield_once().await;
                            }
                        }
                        Err(CoreError::MessageTooLarge(_)) => {
                            // Yield after dropping an oversized app packet so an always-ready app
                            // link cannot spin inside a single poll and starve `dir1` or shutdown (R2-DG-05).
                            burst = 0;
                            yield_once().await;
                        }
                        Err(_) => break,
                    }
                }
            };

            let mut d1 = core::pin::pin!(dir1);
            let mut d2 = core::pin::pin!(dir2);
            let mut closed_fut = core::pin::pin!(wait_session_closed(&mut session_closed));
            let mut shutdown_fut = core::pin::pin!(wait_shutdown(&mut shutdown_rx));
            let mut prefer_d2 = false;

            // Supervise BOTH directions against session closure and scope shutdown (DG-08, R2-DG-05):
            // - Scope shutdown or non-clean revocation/error aborts immediately.
            // - Clean peer close lets `dir1` drain any immediately deliverable queued packets
            //   (bounded by `BRIDGE_POLL_BURST`), then aborts idle `dir2` / stalled `dir1`
            //   immediately so `app_link` and `_guard` always drop promptly!
            poll_fn(|cx| {
                if shutdown_fut.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(());
                }
                if let Poll::Ready(reason) = closed_fut.as_mut().poll(cx) {
                    if reason != CoreError::Closed {
                        return Poll::Ready(());
                    }
                    let _ = d1.as_mut().poll(cx);
                    return Poll::Ready(());
                }
                if prefer_d2 {
                    if d2.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(());
                    }
                    if d1.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(());
                    }
                } else {
                    if d1.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(());
                    }
                    if d2.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(());
                    }
                }
                prefer_d2 = !prefer_d2;
                Poll::Pending
            })
            .await;

            e2e.close();
            drop(app_link);
        }
        // `d1`, `d2`, `app_link`, and `e2e` are all dropped strictly BEFORE `_guard` drops!
    }));
}
