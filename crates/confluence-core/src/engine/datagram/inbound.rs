//! Inbound Datagram setup task dispatcher implementing [`DatagramSetupHandler`] (Spec §5.6 & §6.2).
//!
//! Re-evaluates `update_load()` + `CookieProtector::verify_segment` mid-reassembly before
//! `Responder::authenticate`, acknowledges `FragmentReceipt` (`SETUP_FRAG_ACK`) strictly
//! post-`authenticate`, and drives Datagram Transit setup + `hold_for_cookie_retry` (3 s)
//! or Datagram Destination 1.0 RTT `serve`.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::constants::{FWD_HEADER, SETUP_TIMEOUT};
use crate::crypto::cookie::CookieDecision;
use crate::crypto::noise::{HopKey, Responder};
use crate::engine::admission::{admit_endpoint, admit_transit};
use crate::engine::context::{
    Either, NodePendingPermit, PendingPermit, ScopeCore, race2, with_deadline, with_deadline_val,
};
use crate::engine::datagram::port::{
    DatagramPort, DatagramSetupHandler, SetupReplies, hold_for_cookie_retry,
};
use crate::engine::datagram::serve::serve_datagram_destination;
use crate::engine::datagram::transit::{DatagramTransitParams, run_datagram_transit};
use crate::error::CoreError;
use crate::packet::PacketBuf;
use crate::protocol::fragment::FragmentReceipt;
use crate::protocol::setup::{HopOkRewriteParams, HopSetupRewrite, compute_tail_aad};
use crate::seam::channel::AdmissionAttempt;
use crate::trust::registry::{EndpointHandlerKind, ResolvedTransitHandler};
use crate::types::{Cid, Plane, Role};
use crate::wire::opcodes::{encode_wire_error, outer};
use crate::wire::setup::{
    ForwardHeader, ParsedSegment, SetupCookieFrame, SetupErrFrame, SetupOkHeader,
};

/// Stateless dispatcher handed to [`crate::engine::datagram::port::PortRegistry`].
#[derive(Default)]
pub(crate) struct InboundDatagramDispatcher;

impl InboundDatagramDispatcher {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl DatagramSetupHandler for InboundDatagramDispatcher {
    fn spawn_setup(
        &self,
        scope: Arc<ScopeCore>,
        port: Arc<DatagramPort>,
        wire: Vec<u8>,
        receipt: Option<FragmentReceipt>,
        attempt: AdmissionAttempt,
        pending_permit: PendingPermit,
        node_pending_permit: Option<NodePendingPermit>,
    ) {
        let spawner = Arc::clone(&scope.runtime.spawner);
        spawner.spawn(Box::pin(async move {
            handle_datagram_setup(
                scope,
                port,
                wire,
                receipt,
                attempt,
                pending_permit,
                node_pending_permit,
            )
            .await;
        }));
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_datagram_setup(
    scope: Arc<ScopeCore>,
    port: Arc<DatagramPort>,
    wire: Vec<u8>,
    receipt: Option<FragmentReceipt>,
    mut attempt: AdmissionAttempt,
    pending_permit: PendingPermit,
    node_pending_permit: Option<NodePendingPermit>,
) {
    let clock = Arc::clone(&scope.runtime.clock);
    let Ok(hdr) = ForwardHeader::parse(&wire) else {
        return;
    };
    if hdr.upstream.is_unbound() {
        return;
    }
    let Ok(seg) = ParsedSegment::parse_full(&wire[FWD_HEADER..]) else {
        return;
    };

    // Spec §5.6 Rule 6 & §6.2 Step 2: Re-evaluate update_load() + CookieProtector::verify_segment
    // BEFORE Responder::authenticate and BEFORE acknowledging FragmentReceipt!
    let _ = scope.update_load();
    let source_tag = port.source_tag();
    let base_seg = match scope.cookies.verify_segment(
        &source_tag,
        seg.encrypted,
        seg.prefix.has_mac2,
        clock.now(),
    ) {
        CookieDecision::Drop => {
            scope
                .metrics
                .mac1_drops_total
                .fetch_add(1, Ordering::Relaxed);
            // Dropping `receipt` removes active slot without SETUP_FRAG_ACK.
            return;
        }
        CookieDecision::Challenge(challenge) => {
            scope
                .metrics
                .mac2_challenges_total
                .fetch_add(1, Ordering::Relaxed);
            let frame = SetupCookieFrame {
                distance: 0,
                target_cid: hdr.upstream,
                challenge,
            }
            .encode();
            port.send_best_effort(PacketBuf::from_payload(&frame)).await;
            // Dropping `receipt` removes active slot without adding to completed or sending ACK!
            return;
        }
        CookieDecision::Verified(base) => base,
    };

    // Responder::authenticate — ANY failure MUST silently drop WITHOUT SETUP_ERR and WITHOUT SETUP_FRAG_ACK!
    let tail_aad = compute_tail_aad(seg.prefix_bytes, seg.tail);
    let (responder, plaintext) = match Responder::authenticate(
        &scope.keypair,
        &scope.replay,
        base_seg,
        &tail_aad,
        clock.now(),
        scope.runtime.wall_time_ms(),
    ) {
        Ok(ok) => ok,
        Err(err) => {
            match err {
                CoreError::Replay => {
                    scope
                        .metrics
                        .replay_rejects_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                CoreError::BadMac => {
                    scope
                        .metrics
                        .mac1_drops_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
            return;
        }
    };

    // Spec §5.6 Rule 6 & §6.2 Step 3: Acknowledge FragmentReceipt strictly AFTER Responder::authenticate!
    if let Some(rcpt) = receipt {
        if let Some(ack) = rcpt.acknowledge(clock.now()) {
            port.send_best_effort(PacketBuf::from_payload(&ack.encode()))
                .await;
        }
    }

    let hop_key = responder.hop_key().clone();
    let inbound_mtu = port.mtu();

    if seg.prefix.is_hop {
        scope
            .metrics
            .record_setup_attempt(Plane::Datagram, Role::Transit);
        let admitted = match admit_transit(
            &scope,
            Plane::Datagram,
            &seg.prefix,
            responder,
            &plaintext,
            inbound_mtu,
        )
        .await
        {
            Ok(a) => a,
            Err(err) => {
                send_dg_setup_err(&scope, &port, Role::Transit, hdr.upstream, &hop_key, &err).await;
                return;
            }
        };

        let ResolvedTransitHandler::Datagram(handler) = admitted.handler.clone() else {
            send_dg_setup_err(
                &scope,
                &port,
                Role::Transit,
                hdr.upstream,
                &hop_key,
                &CoreError::WrongPlane,
            )
            .await;
            return;
        };

        let setup_deadline = clock.now().saturating_add(SETUP_TIMEOUT);

        // Open outbound DatagramLink racing lease.cancelled() and SETUP_TIMEOUT.
        let out_link = match with_deadline_val(
            &*clock,
            setup_deadline,
            race2(
                handler.open(&admitted.subtarget, admitted.lease.session_auth()),
                admitted.lease.cancelled(),
            ),
        )
        .await
        {
            Ok(Either::Left(Ok(link))) => link,
            Ok(Either::Left(Err(err))) => {
                send_dg_setup_err(&scope, &port, Role::Transit, hdr.upstream, &hop_key, &err).await;
                return;
            }
            Ok(Either::Right(err)) => {
                send_dg_setup_err(&scope, &port, Role::Transit, hdr.upstream, &hop_key, &err).await;
                return;
            }
            Err(err) => {
                send_dg_setup_err(&scope, &port, Role::Transit, hdr.upstream, &hop_key, &err).await;
                return;
            }
        };

        if let Err(err) = admitted.lease.remaining() {
            send_dg_setup_err(&scope, &port, Role::Transit, hdr.upstream, &hop_key, &err).await;
            return;
        }

        let Some(registry) = port.owner_registry() else {
            send_dg_setup_err(
                &scope,
                &port,
                Role::Transit,
                hdr.upstream,
                &hop_key,
                &CoreError::Closed,
            )
            .await;
            return;
        };

        let (out_port, _out_hold) = match registry.attach_outbound(out_link) {
            Ok(v) => v,
            Err(err) => {
                send_dg_setup_err(&scope, &port, Role::Transit, hdr.upstream, &hop_key, &err).await;
                return;
            }
        };

        let left = match port.bind(Some(Arc::clone(&scope.metrics))) {
            Ok(b) => b,
            Err(err) => {
                send_dg_setup_err(&scope, &port, Role::Transit, hdr.upstream, &hop_key, &err).await;
                return;
            }
        };
        let right = match out_port.bind(Some(Arc::clone(&scope.metrics))) {
            Ok(b) => b,
            Err(err) => {
                send_dg_setup_err(&scope, &port, Role::Transit, hdr.upstream, &hop_key, &err).await;
                return;
            }
        };

        let physical = left.mtu().min(right.mtu());
        if physical < admitted.floor {
            let err = CoreError::MtuTooSmall(physical);
            send_dg_setup_err(&scope, &port, Role::Transit, hdr.upstream, &hop_key, &err).await;
            return;
        }

        // Transit admission + CID binding succeeded -> permanently Admitted (Spec §6.2).
        attempt.mark_admitted();

        let fwd = HopSetupRewrite::rewrite_forward(
            hdr.max_mtu,
            left.mtu(),
            right.mtu(),
            right.cid(),
            seg.tail,
        );
        let mut replies = match SetupReplies::send(&right, &fwd, &*clock) {
            Ok(r) => r,
            Err(err) => {
                send_dg_setup_err(&scope, &port, Role::Transit, hdr.upstream, &hop_key, &err).await;
                return;
            }
        };

        loop {
            let pkt = match race2(
                replies.next_reply(setup_deadline),
                admitted.lease.cancelled(),
            )
            .await
            {
                Either::Left(Ok(p)) => p,
                Either::Left(Err(err)) => {
                    send_dg_setup_err(&scope, &port, Role::Transit, hdr.upstream, &hop_key, &err)
                        .await;
                    return;
                }
                Either::Right(err) => {
                    send_dg_setup_err(&scope, &port, Role::Transit, hdr.upstream, &hop_key, &err)
                        .await;
                    return;
                }
            };

            let Some(&op) = pkt.payload().first() else {
                continue;
            };
            match op {
                outer::SETUP_OK => {
                    let Ok((ok_hdr, _, _)) = SetupOkHeader::parse(pkt.payload()) else {
                        continue;
                    };
                    if ok_hdr.target_cid != right.cid() || ok_hdr.responder_cid.is_unbound() {
                        continue;
                    }
                    let ttl_ms = match admitted.lease.remaining() {
                        Ok(d) => u64::try_from(d.as_millis()).unwrap_or(u64::MAX).max(1),
                        Err(err) => {
                            send_dg_setup_err(
                                &scope,
                                &port,
                                Role::Transit,
                                hdr.upstream,
                                &hop_key,
                                &err,
                            )
                            .await;
                            return;
                        }
                    };
                    let live_physical = left.mtu().min(right.mtu());
                    if live_physical < admitted.floor {
                        let err = CoreError::MtuTooSmall(live_physical);
                        send_dg_setup_err(
                            &scope,
                            &port,
                            Role::Transit,
                            hdr.upstream,
                            &hop_key,
                            &err,
                        )
                        .await;
                        return;
                    }
                    let mut ok_wire = pkt.payload().to_vec();
                    let next_cid = match HopSetupRewrite::rewrite_ok(
                        &mut ok_wire,
                        &HopOkRewriteParams {
                            plane: Plane::Datagram,
                            expected_right_cid: right.cid(),
                            inbound_upstream_cid: hdr.upstream,
                            left_binding_cid: left.cid(),
                            physical_mtu: live_physical,
                            hop_lease_ttl_ms: ttl_ms,
                            hop_key: &hop_key,
                            max_wire_len: usize::from(live_physical),
                        },
                    ) {
                        Ok(cid) => cid,
                        Err(err) => {
                            send_dg_setup_err(
                                &scope,
                                &port,
                                Role::Transit,
                                hdr.upstream,
                                &hop_key,
                                &err,
                            )
                            .await;
                            return;
                        }
                    };

                    let session_permit =
                        match scope.try_acquire_session(Plane::Datagram, Role::Transit) {
                            Ok(p) => p,
                            Err(err) => {
                                send_dg_setup_err(
                                    &scope,
                                    &port,
                                    Role::Transit,
                                    hdr.upstream,
                                    &hop_key,
                                    &err,
                                )
                                .await;
                                return;
                            }
                        };

                    if let Err(err) = with_deadline(
                        &*clock,
                        setup_deadline,
                        left.send_wait(PacketBuf::from_payload(&ok_wire)),
                    )
                    .await
                    {
                        scope.metrics.record_setup_failure(
                            Plane::Datagram,
                            Role::Transit,
                            err.failure_class(),
                        );
                        return;
                    }

                    // Release setup permits and SetupReplies borrow BEFORE entering steady-state transit!
                    drop(replies);
                    drop(admitted.pending_setup);
                    drop(pending_permit);
                    drop(node_pending_permit);
                    drop(attempt);

                    scope
                        .metrics
                        .record_setup_established(Plane::Datagram, Role::Transit);

                    let ctrl = hop_key.control_cipher(false);
                    run_datagram_transit(DatagramTransitParams {
                        scope,
                        peer: admitted.peer,
                        full_name: admitted.full_name,
                        floor: admitted.floor,
                        initial_physical_mtu: live_physical,
                        left,
                        right,
                        caller_cid: hdr.upstream,
                        next_cid,
                        ctrl,
                        lease: admitted.lease,
                        session_permit,
                    })
                    .await;
                    return;
                }
                outer::SETUP_ERR => {
                    let Ok(err_frame) = SetupErrFrame::parse(pkt.payload()) else {
                        continue;
                    };
                    if err_frame.target_cid != right.cid() {
                        continue;
                    }
                    if let Ok(rewritten) = HopSetupRewrite::rewrite_err(&err_frame, hdr.upstream) {
                        left.send_best_effort(PacketBuf::from_payload(&rewritten))
                            .await;
                    }
                    return;
                }
                outer::SETUP_COOKIE => {
                    let Ok(cookie_frame) = SetupCookieFrame::parse(pkt.payload()) else {
                        continue;
                    };
                    if cookie_frame.target_cid != right.cid() {
                        continue;
                    }
                    // Spec §6.2 Step 4: retain Arc<DatagramPort> for 3 s so outbound source_tag stays stable!
                    hold_for_cookie_retry(
                        Arc::clone(&out_port),
                        Arc::clone(&clock),
                        &*scope.runtime.spawner,
                    );
                    if let Ok(rewritten) =
                        HopSetupRewrite::rewrite_cookie(&cookie_frame, hdr.upstream)
                    {
                        left.send_best_effort(PacketBuf::from_payload(&rewritten))
                            .await;
                    }
                    return;
                }
                _ => continue,
            }
        }
    } else {
        // Destination endpoint setup.
        scope
            .metrics
            .record_setup_attempt(Plane::Datagram, Role::Destination);
        let admitted = match admit_endpoint(
            &scope,
            Plane::Datagram,
            hdr.max_mtu,
            &seg.prefix,
            responder,
            &plaintext,
            inbound_mtu,
        )
        .await
        {
            Ok(a) => a,
            Err(err) => {
                send_dg_setup_err(
                    &scope,
                    &port,
                    Role::Destination,
                    hdr.upstream,
                    &hop_key,
                    &err,
                )
                .await;
                return;
            }
        };

        let EndpointHandlerKind::Datagram { handler, .. } = admitted.kind.clone() else {
            send_dg_setup_err(
                &scope,
                &port,
                Role::Destination,
                hdr.upstream,
                &hop_key,
                &CoreError::WrongPlane,
            )
            .await;
            return;
        };

        let binding = match port.bind(Some(Arc::clone(&scope.metrics))) {
            Ok(b) => b,
            Err(err) => {
                send_dg_setup_err(
                    &scope,
                    &port,
                    Role::Destination,
                    hdr.upstream,
                    &hop_key,
                    &err,
                )
                .await;
                return;
            }
        };

        // Destination admission + session permit + CID binding succeeded -> permanently Admitted!
        attempt.mark_admitted();
        drop(attempt);

        if let Err(err) = serve_datagram_destination(
            Arc::clone(&scope),
            admitted,
            handler,
            binding,
            hdr.upstream,
            inbound_mtu,
            pending_permit,
            node_pending_permit,
        )
        .await
        {
            scope.metrics.record_setup_failure(
                Plane::Datagram,
                Role::Destination,
                err.failure_class(),
            );
        }
    }
}

async fn send_dg_setup_err(
    scope: &ScopeCore,
    port: &DatagramPort,
    role: Role,
    target_cid: Cid,
    hop_key: &HopKey,
    err: &CoreError,
) {
    scope
        .metrics
        .record_setup_failure(Plane::Datagram, role, err.failure_class());
    let (code, arg) = encode_wire_error(err);
    let frame = SetupErrFrame {
        distance: 0,
        target_cid,
        body: hop_key.seal_setup_error(code, arg),
    }
    .encode();
    port.send_best_effort(PacketBuf::from_payload(&frame)).await;
}
