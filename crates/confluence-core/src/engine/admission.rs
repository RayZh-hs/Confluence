//! Unified Stream and Datagram inbound Transit and Endpoint admission pipeline (Spec §6.2).
//!
//! Enforces strict plane matching, per-peer pending quotas, TOCTOU-free revocation epochs,
//! publication verification, `AuthGate` fail-closed authorization, and two-phase `Responder::commit`.

use std::sync::Arc;

use crate::constants::{DATAGRAM_MIN_MTU, STREAM_MIN_MTU};
use crate::crypto::noise::{HopKey, Responder};
use crate::engine::context::{ScopeCore, SessionPermit};
use crate::error::CoreError;
use crate::seam::auth::AuthRequest;
use crate::trust::gate::PendingSetup;
use crate::trust::lease::LeaseHandle;
use crate::trust::registry::{EndpointHandlerKind, ResolvedTransitHandler};
use crate::trust::revocation::TransitEpochTarget;
use crate::types::{Plane, PublicationId, PublicKey, Role, TargetRef};
use crate::wire::setup::{DispatchPrefix, SetupPlaintext};

/// Admitted inbound Transit circuit ready for downstream `TransitHandler::open` and forwarding.
pub(crate) struct AdmittedTransit {
    pub peer: PublicKey,
    pub pub_id: PublicationId,
    pub full_name: String,
    pub subtarget: String,
    pub floor: u16,
    pub hop_key: HopKey,
    pub lease: Arc<LeaseHandle>,
    pub pending_setup: PendingSetup,
    pub handler: ResolvedTransitHandler,
}

/// Admitted inbound Destination endpoint ready for `SETUP_OK` and 1.0 RTT `AwaitingConfirm`.
pub(crate) struct AdmittedEndpoint {
    pub peer: PublicKey,
    pub endpoint: String,
    pub floor: u16,
    pub forwarded_mtu: u16,
    pub responder: Responder,
    pub lease: Arc<LeaseHandle>,
    pub pending_setup: PendingSetup,
    pub session_permit: SessionPermit,
    pub kind: EndpointHandlerKind,
}

/// Unified inbound Transit admission shared by Stream and Datagram planes (Spec §6.2).
///
/// Tracks the transit lease in `RevocationIndex` BEFORE `Responder::commit()` and BEFORE
/// `handler.open()` so concurrent revocations cancel in-flight downstream opens immediately.
pub(crate) async fn admit_transit(
    scope: &Arc<ScopeCore>,
    expected_plane: Plane,
    prefix: &DispatchPrefix,
    mut responder: Responder,
    plaintext: &[u8],
    inbound_mtu: u16,
) -> Result<AdmittedTransit, CoreError> {
    if prefix.plane != expected_plane {
        return Err(CoreError::WrongPlane);
    }

    let (_ts_ms, target_name, credential) = SetupPlaintext::parse(plaintext)?;
    let peer = responder.peer_static();
    let pending_setup = scope.auth_gate.acquire_pending(peer)?;
    let resolved = scope.registry.resolve_transit(target_name, expected_plane)?;

    let floor = prefix.min_mtu.max(expected_plane.minimum_mtu());
    let handler_mtu = match &resolved.handler {
        ResolvedTransitHandler::Stream(h) => h.caps().mtu(),
        ResolvedTransitHandler::Datagram(h) => h.caps().mtu(),
    };
    if handler_mtu < floor {
        return Err(CoreError::MtuTooSmall(handler_mtu));
    }
    if inbound_mtu < floor {
        return Err(CoreError::MtuTooSmall(inbound_mtu));
    }

    let epoch_target = TransitEpochTarget {
        peer,
        plane: expected_plane,
        full_name: target_name,
        matched_prefix: resolved.matched_prefix.as_deref(),
        pub_id: resolved.pub_id,
        subtarget: &resolved.subtarget,
    };
    let epoch = scope.registry.epoch_for_transit(&epoch_target);

    // Authorizer ALWAYS evaluates the FULL requested transit target name (Spec §7.4).
    let lease = scope
        .auth_gate
        .authorize(AuthRequest {
            peer,
            target: TargetRef::Transit {
                name: target_name,
                plane: expected_plane,
            },
            credential,
            is_renewal: false,
        })
        .await?;

    let lease_handle = LeaseHandle::new(
        peer,
        lease,
        scope.auth_limits.max_lease_ttl,
        Arc::clone(&scope.runtime.clock),
    )?;

    // TOCTOU epoch + veto + publication active check + RevocationIndex registration BEFORE commit().
    scope
        .registry
        .track_transit(&epoch, &epoch_target, &resolved.active, &lease_handle)?;

    // Phase 2 replay commit (re-checks wall-clock freshness & atomically inserts E_i).
    if let Err(err) = responder.commit(
        &scope.replay,
        scope.runtime.clock.now(),
        scope.runtime.wall_time_ms(),
    ) {
        if err == CoreError::Replay {
            scope
                .metrics
                .replay_rejects_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        return Err(err);
    }

    Ok(AdmittedTransit {
        peer,
        pub_id: resolved.pub_id,
        full_name: target_name.to_owned(),
        subtarget: resolved.subtarget,
        floor,
        hop_key: responder.hop_key().clone(),
        lease: lease_handle,
        pending_setup,
        handler: resolved.handler,
    })
}

/// Unified inbound Destination endpoint admission shared by Stream and Datagram planes (Spec §6.2).
pub(crate) async fn admit_endpoint(
    scope: &Arc<ScopeCore>,
    expected_plane: Plane,
    hdr_max_mtu: u16,
    prefix: &DispatchPrefix,
    mut responder: Responder,
    plaintext: &[u8],
    inbound_mtu: u16,
) -> Result<AdmittedEndpoint, CoreError> {
    if prefix.plane != expected_plane {
        return Err(CoreError::WrongPlane);
    }

    let (_ts_ms, ep_name, credential) = SetupPlaintext::parse(plaintext)?;
    let peer = responder.peer_static();
    let pending_setup = scope.auth_gate.acquire_pending(peer)?;
    let epoch = scope.registry.epoch_for_endpoint(peer, Some(ep_name));
    let resolved = scope.registry.resolve_endpoint(ep_name, expected_plane)?;

    let floor = match (&resolved.kind, expected_plane) {
        (EndpointHandlerKind::Stream(_), Plane::Stream) => prefix.min_mtu.max(STREAM_MIN_MTU),
        (EndpointHandlerKind::Datagram { min_mtu, .. }, Plane::Datagram) => {
            (*min_mtu).max(prefix.min_mtu).max(DATAGRAM_MIN_MTU)
        }
        _ => return Err(CoreError::WrongPlane),
    };

    let forwarded_mtu = hdr_max_mtu.min(inbound_mtu);
    if forwarded_mtu < floor {
        return Err(CoreError::MtuTooSmall(forwarded_mtu));
    }

    let lease = scope
        .auth_gate
        .authorize(AuthRequest {
            peer,
            target: TargetRef::Endpoint {
                name: ep_name,
                plane: expected_plane,
            },
            credential,
            is_renewal: false,
        })
        .await?;

    let lease_handle = LeaseHandle::new(
        peer,
        lease,
        scope.auth_limits.max_lease_ttl,
        Arc::clone(&scope.runtime.clock),
    )?;

    // TOCTOU epoch + veto + exact endpoint publication identity + RevocationIndex registration BEFORE commit().
    scope.registry.track_endpoint(
        &epoch,
        peer,
        Some((ep_name, resolved.pub_id)),
        &lease_handle,
    )?;

    // Phase 2 replay commit.
    if let Err(err) = responder.commit(
        &scope.replay,
        scope.runtime.clock.now(),
        scope.runtime.wall_time_ms(),
    ) {
        if err == CoreError::Replay {
            scope
                .metrics
                .replay_rejects_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        return Err(err);
    }

    let session_permit = scope.try_acquire_session(expected_plane, Role::Destination)?;

    Ok(AdmittedEndpoint {
        peer,
        endpoint: ep_name.to_owned(),
        floor,
        forwarded_mtu,
        responder,
        lease: lease_handle,
        pending_setup,
        session_permit,
        kind: resolved.kind,
    })
}
