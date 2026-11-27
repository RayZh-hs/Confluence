//! Datagram Destination 1.0 RTT deferred open (`AwaitingConfirm` -> `EndpointHandler::open`
//! -> bidirectional local `DatagramLink` bridge, Spec §6.3).

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::constants::SETUP_TIMEOUT;
use crate::crypto::cipher::{DatagramRx, DatagramTx};
use crate::engine::admission::AdmittedEndpoint;
use crate::engine::context::{
    Either, NodePendingPermit, PendingPermit, ScopeCore, race2, wait_shutdown, with_deadline,
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
    with_deadline(
        &*clock,
        confirm_deadline,
        binding.send_wait(PacketBuf::from_payload(&ok_wire)),
    )
    .await?;

    let mut tx = DatagramTx::new(session_keys.tx_key());
    let mut rx = DatagramRx::new(session_keys.rx_key());
    let mut shutdown_rx = scope.subscribe_shutdown();

    // Phase 1: AwaitingConfirm (retaining pending_permit, node_pending_permit, pending_setup!).
    let confirm_res: Result<Option<PacketBuf>, CoreError> = async {
        loop {
            let step = with_deadline_val(
                &*clock,
                confirm_deadline,
                race2(
                    binding.recv(),
                    race2(lease.cancelled(), wait_shutdown(&mut shutdown_rx)),
                ),
            )
            .await?;

            let mut pkt = match step {
                Either::Left(Ok(p)) => p,
                Either::Left(Err(err)) => return Err(err),
                Either::Right(Either::Left(err)) => return Err(err),
                Either::Right(Either::Right(())) => return Err(CoreError::Closed),
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
                    return Err(CoreError::Closed);
                }
                e2e_dg::DG_DATA => {
                    if seq == 0 && pkt.is_empty() {
                        // Spec §5.8.1 & §6.3: Confirmed with first = None (suppressed!).
                        return Ok(None);
                    }
                    if lease.is_active() {
                        return Ok(Some(pkt));
                    }
                    return Err(lease.remaining().err().unwrap_or(CoreError::Expired));
                }
                _ => continue,
            }
        }
    }
    .await;

    let mut first_packet = match confirm_res {
        Ok(pkt) => pkt,
        Err(err) => {
            tracing::debug!(
                parent: &span,
                error = err.static_code(),
                "datagram destination aborted before confirmation"
            );
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
                    let bytes = encode_wire_error_bytes(&err);
                    if let Ok(close_pkt) =
                        build_e2e_packet(&mut tx, e2e_dg::DG_CLOSE, &bytes, upstream_cid)
                    {
                        binding.send_best_effort(close_pkt).await;
                    }
                    return Err(err);
                }
            }
        }
    }

    // Step 4: Invoke DatagramEndpointHandler::open strictly AFTER confirmation,
    // bounded by SETUP_TIMEOUT and lease.cancelled() (Spec §6.3 Step 4).
    let open_deadline = clock.now().saturating_add(SETUP_TIMEOUT);
    let open_res = with_deadline_val(
        &*clock,
        open_deadline,
        race2(handler.open(lease.session_auth()), lease.cancelled()),
    )
    .await;

    let app_link = match open_res {
        Ok(Either::Left(Ok(link))) => link,
        Ok(Either::Left(Err(err))) => {
            send_dest_e2e_close(&binding, &mut tx, upstream_cid, &err).await;
            return Err(err);
        }
        Ok(Either::Right(err)) => {
            send_dest_e2e_close(&binding, &mut tx, upstream_cid, &err).await;
            return Err(err);
        }
        Err(err) => {
            send_dest_e2e_close(&binding, &mut tx, upstream_cid, &err).await;
            return Err(err);
        }
    };

    scope
        .metrics
        .record_setup_established(Plane::Datagram, Role::Destination);

    let mtu_watch = binding.mtu_watch();
    let path_mtu = DestPathMtu::new(forwarded_mtu, inbound_mtu, floor);

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

    spawn_datagram_bridge(scope, e2e, app_link);
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

fn spawn_datagram_bridge(
    scope: Arc<ScopeCore>,
    e2e: E2eDatagram,
    app_link: Arc<dyn DatagramLink>,
) {
    // Direction 1: e2e -> app_link.
    let e2e_in = e2e.clone();
    let app_out = Arc::clone(&app_link);
    scope.runtime.spawner.spawn(Box::pin(async move {
        while let Ok(pkt) = e2e_in.recv().await {
            match app_out.send(pkt).await {
                Ok(()) => {}
                Err(err) if err.is_retryable() || matches!(err, CoreError::MtuTooSmall(_)) => {}
                Err(_) => {
                    e2e_in.close();
                    break;
                }
            }
        }
    }));

    // Direction 2: app_link -> e2e (Spec §6.3 Step 5: drop MessageTooLarge without closing!).
    scope.runtime.spawner.spawn(Box::pin(async move {
        loop {
            let pkt = match app_link.recv().await {
                Ok(p) => p,
                Err(_) => {
                    e2e.close();
                    break;
                }
            };
            match e2e.send_wait(pkt).await {
                Ok(()) | Err(CoreError::MessageTooLarge(_)) => {}
                Err(_) => break,
            }
        }
    }));
}
