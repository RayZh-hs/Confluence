//! Stream Plane Engine: stack-precheck inbound accept, 1.0 RTT Destination `serve`,
//! bidirectional Transit `splice`, and `E2eStream` steady-state sessions.

pub(crate) mod framing;
pub(crate) mod serve;
pub(crate) mod session;
pub(crate) mod splice;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::constants::SETUP_TIMEOUT;
use crate::crypto::cookie::CookieDecision;
use crate::crypto::noise::Responder;
use crate::engine::admission::{admit_endpoint, admit_transit};
use crate::engine::context::{NodePendingPermit, PendingPermit, ScopeCore, ScopeResolver};
use crate::engine::stream::framing::{read_setup_fwd, write_frame_best_effort};
use crate::error::CoreError;
use crate::protocol::setup::compute_tail_aad;
use crate::seam::channel::{BoxedStream, IntoStreamHalves, StreamWrite};
use crate::trust::registry::{EndpointHandlerKind, ResolvedTransitHandler};
use crate::types::{Cid, Plane, Role};
use crate::wire::opcodes::encode_wire_error;
use crate::wire::setup::{SetupCookieFrame, SetupErrFrame};

/// Accepts an inbound Stream connection using `resolver` (single-scope or multi-scope `Node`),
/// enforcing Spec §6.2 Stream Inbound Flow.
pub(crate) fn spawn_inbound_stream(
    resolver: Arc<dyn ScopeResolver>,
    clock: Arc<dyn crate::runtime::Clock>,
    spawner: Arc<dyn crate::runtime::TaskSpawner>,
    stream: BoxedStream,
    preacquired_scope_permit: Option<PendingPermit>,
    node_pending_permit: Option<NodePendingPermit>,
) {
    spawner.spawn(Box::pin(async move {
        let caps = stream.caps();
        let inbound_mtu = caps.mtu();
        let mtu_watch = caps.mtu_watch();
        let source_tag = stream.source_tag();
        let (mut reader, mut writer) = stream.into_halves();

        let deadline = clock.now().saturating_add(SETUP_TIMEOUT);

        // Step 2: Stack-only ScopeKid + mac1 precheck before heap-allocating `tail`.
        let parsed = match read_setup_fwd(&mut *reader, &*resolver, &*clock, deadline).await {
            Ok(p) => p,
            Err(_) => return,
        };

        let scope = parsed.scope;

        // Acquire scope pending permit (unless already acquired on single-scope accept).
        let pending_permit = match preacquired_scope_permit {
            Some(p) => p,
            None => match scope.try_acquire_pending() {
                Ok(p) => p,
                Err(_) => return,
            },
        };

        // Step 3: Update load state & verify MAC1/MAC2 flood cookie.
        let _ = scope.update_load();
        let base_seg = match scope.cookies.verify_segment(
            &source_tag,
            &parsed.encrypted,
            parsed.prefix.has_mac2,
            clock.now(),
        ) {
            CookieDecision::Drop => {
                scope
                    .metrics
                    .mac1_drops_total
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            CookieDecision::Challenge(challenge) => {
                scope
                    .metrics
                    .mac2_challenges_total
                    .fetch_add(1, Ordering::Relaxed);
                let frame = SetupCookieFrame {
                    distance: 0,
                    target_cid: Cid::UNBOUND,
                    challenge,
                }
                .encode();
                write_frame_best_effort(&mut *writer, &frame, &*clock).await;
                return;
            }
            CookieDecision::Verified(base) => base,
        };

        // Step 4: Responder::authenticate — ANY failure MUST drop silently without SETUP_ERR!
        let tail_aad = compute_tail_aad(&parsed.prefix_bytes[..parsed.prefix_len], &parsed.tail);
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

        let hop_key = responder.hop_key().clone();

        if parsed.prefix.is_hop {
            scope
                .metrics
                .record_setup_attempt(Plane::Stream, Role::Transit);
            let admitted = match admit_transit(
                &scope,
                Plane::Stream,
                &parsed.prefix,
                responder,
                &plaintext,
                inbound_mtu,
            )
            .await
            {
                Ok(a) => a,
                Err(err) => {
                    record_and_send_stream_setup_err(
                        &scope,
                        Role::Transit,
                        &hop_key,
                        &err,
                        &mut *writer,
                    )
                    .await;
                    return;
                }
            };

            let ResolvedTransitHandler::Stream(handler) = admitted.handler.clone() else {
                record_and_send_stream_setup_err(
                    &scope,
                    Role::Transit,
                    &hop_key,
                    &CoreError::WrongPlane,
                    &mut *writer,
                )
                .await;
                return;
            };

            // Pass ownership of writer via helper; if handle_stream_transit fails BEFORE forwarding
            // SETUP_OK, it can still send SETUP_ERR? Wait: splice needs writer; so send SETUP_ERR
            // inside splice or return writer! Let's wrap cleanly in splice!
            // Actually handle_stream_transit owns left_w: let's have splice send SETUP_ERR on pre-OK error!
            let res = splice::handle_stream_transit(
                Arc::clone(&scope),
                admitted,
                handler,
                parsed.hdr.max_mtu,
                &parsed.tail,
                reader,
                writer,
                mtu_watch,
                inbound_mtu,
                pending_permit,
                node_pending_permit,
            )
            .await;
            if let Err(err) = res {
                scope.metrics.record_setup_failure(
                    Plane::Stream,
                    Role::Transit,
                    err.failure_class(),
                );
            }
        } else {
            scope
                .metrics
                .record_setup_attempt(Plane::Stream, Role::Destination);
            let admitted = match admit_endpoint(
                &scope,
                Plane::Stream,
                parsed.hdr.max_mtu,
                &parsed.prefix,
                responder,
                &plaintext,
                inbound_mtu,
            )
            .await
            {
                Ok(a) => a,
                Err(err) => {
                    record_and_send_stream_setup_err(
                        &scope,
                        Role::Destination,
                        &hop_key,
                        &err,
                        &mut *writer,
                    )
                    .await;
                    return;
                }
            };

            let EndpointHandlerKind::Stream(handler) = admitted.kind.clone() else {
                record_and_send_stream_setup_err(
                    &scope,
                    Role::Destination,
                    &hop_key,
                    &CoreError::WrongPlane,
                    &mut *writer,
                )
                .await;
                return;
            };

            if let Err(err) = serve::serve_stream_destination(
                Arc::clone(&scope),
                admitted,
                handler,
                reader,
                writer,
                mtu_watch,
                inbound_mtu,
                pending_permit,
                node_pending_permit,
            )
            .await
            {
                scope.metrics.record_setup_failure(
                    Plane::Stream,
                    Role::Destination,
                    err.failure_class(),
                );
            }
        }
    }));
}

async fn record_and_send_stream_setup_err<W: StreamWrite + ?Sized>(
    scope: &ScopeCore,
    role: Role,
    hop_key: &crate::crypto::noise::HopKey,
    err: &CoreError,
    writer: &mut W,
) {
    scope
        .metrics
        .record_setup_failure(Plane::Stream, role, err.failure_class());
    let (code, arg) = encode_wire_error(err);
    let frame = SetupErrFrame {
        distance: 0,
        target_cid: Cid::UNBOUND,
        body: hop_key.seal_setup_error(code, arg),
    }
    .encode();
    write_frame_best_effort(writer, &frame, &*scope.runtime.clock).await;
}
