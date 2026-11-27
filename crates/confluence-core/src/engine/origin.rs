//! Originator dial staging, multi-hop cookie-retry loop, `StagedStream`, and `StagedDatagram` (Spec §6.1).
//!
//! Strictly acyclic: depends on `engine::context`, `engine::stream::{framing, session}`, and
//! `engine::datagram::{port, session}` — NEVER imports `engine::datagram::inbound` or `engine::admission`.

use core::fmt;
use std::collections::HashMap;
use std::sync::Arc;

use rand_core::OsRng;
use zeroize::Zeroizing;

use crate::constants::{
    COOKIE_LEN, CREDENTIAL_MAX, DATAGRAM_MIN_MTU, DG_OVERHEAD, MAX_HOPS, MAX_WIRE_LEASE_TTL,
    SETUP_TIMEOUT, STREAM_MIN_MTU,
};
use crate::crypto::cipher::{ControlCipher, DatagramRx, DatagramTx, StreamCipher};
use crate::engine::context::{ScopeCore, SessionPermit, with_deadline};
use crate::engine::datagram::port::{Binding, PortSlot, SetupReplies};
use crate::engine::datagram::session::{
    DatagramSessionParams, DatagramSessionRole, E2eDatagram, OriginDatagramMeta,
    abort_datagram_staged, build_e2e_packet, spawn_datagram_session,
};
use crate::engine::stream::framing::{
    InboundStreamFrame, StreamFrameReader, StreamSetupReply, read_setup_reply, write_e2e_record,
    write_frame,
};
use crate::engine::stream::session::{
    E2eStream, OriginStreamMeta, StreamSessionParams, StreamSessionRole, abort_stream_hops,
    race_session_guards, spawn_stream_session,
};
use crate::error::CoreError;
use crate::protocol::mtu::OriginPathMtu;
use crate::protocol::renewal::RenewalDriver;
use crate::protocol::setup::{
    HopFlightInput, OriginEstablished, OriginSetupState, SetupFlightBuilder, SetupFlightParams,
};
use crate::seam::auth::CredentialRequest;
use crate::seam::channel::{IntoStreamHalves, MtuWatch, StreamRead, StreamWrite};
use crate::seam::path::{ExplicitPath, PathOutcome};
use crate::trust::lease::LeaseHandle;
use crate::types::{Cid, Credential, Plane, PublicKey, Role, TargetRef, ValidatedName};
use crate::wire::opcodes::{StreamOpenStatus, decode_wire_error_bytes, e2e_dg, e2e_st, outer};
use crate::wire::setup::{SetupCookieFrame, SetupErrFrame};

// ---------------------------------------------------------------------------
// Staged 1.0 RTT Handles (`StagedStream` & `StagedDatagram`)
// ---------------------------------------------------------------------------

struct StagedStreamInner {
    scope: Arc<ScopeCore>,
    peer: PublicKey,
    endpoint: String,
    path_id: u64,
    path_mtu: u16,
    floor: u16,
    reader: Box<dyn StreamRead>,
    writer: Box<dyn StreamWrite>,
    mtu_watch: MtuWatch,
    tx_cipher: StreamCipher,
    rx_cipher: StreamCipher,
    hops: Vec<(PublicKey, String, ControlCipher)>,
    terminal_ctrl: ControlCipher,
    renewals: RenewalDriver,
    lease: Arc<LeaseHandle>,
    session_permit: SessionPermit,
}

/// Completed 1-RTT Stream handshake paused prior to 1.0 RTT confirmation (Spec §6.1).
///
/// Destination `B` has NOT invoked `StreamEndpointHandler::open` yet. Call [`Self::confirm`]
/// to send confirmation and receive [`E2eStream`], or drop this handle to abort cleanly with
/// zero destination side effects.
pub struct StagedStream {
    inner: Option<StagedStreamInner>,
}

impl StagedStream {
    /// Returns the authenticated wire MTU across all legs.
    #[must_use]
    pub fn mtu(&self) -> u16 {
        self.inner.as_ref().map_or(0, |i| i.path_mtu)
    }

    /// Returns the destination peer's static public key.
    #[must_use]
    pub fn peer(&self) -> PublicKey {
        self.inner
            .as_ref()
            .map_or(PublicKey::from_bytes([0u8; 32]), |i| i.peer)
    }

    /// Returns the `ExplicitPath::id` for this staged connection.
    #[must_use]
    pub fn path_id(&self) -> u64 {
        self.inner.as_ref().map_or(0, |i| i.path_id)
    }

    /// Sends 1.0 RTT confirmation (`e2e::ST_DATA(seq = 0)`), awaits Destination `OPEN_OK` /
    /// `TARGET_*`, spawns the steady-state worker, and reports `PathOutcome::Established`.
    pub async fn confirm(mut self) -> Result<E2eStream, CoreError> {
        let Some(inner) = self.inner.take() else {
            return Err(CoreError::Closed);
        };
        let StagedStreamInner {
            scope,
            peer,
            endpoint,
            path_id,
            path_mtu,
            floor,
            mut reader,
            mut writer,
            mut mtu_watch,
            mut tx_cipher,
            mut rx_cipher,
            mut hops,
            mut terminal_ctrl,
            renewals,
            lease,
            session_permit,
        } = inner;

        let clock = Arc::clone(&scope.runtime.clock);

        if scope.sessions.is_closed() {
            scope
                .path_source
                .report_outcome(path_id, PathOutcome::Failed(CoreError::Closed));
            scope.metrics.record_setup_failure(
                Plane::Stream,
                Role::Origin,
                CoreError::Closed.failure_class(),
            );
            let hop_ctrls = hops.into_iter().map(|(_, _, c)| c).collect();
            scope
                .runtime
                .spawner
                .spawn(Box::pin(abort_stream_hops(writer, hop_ctrls, clock)));
            return Err(CoreError::Closed);
        }

        let confirm_deadline = clock.now().saturating_add(SETUP_TIMEOUT);
        let mut frame_reader = StreamFrameReader::new();
        let mut e2e_scratch = Vec::with_capacity(64);
        let mut chunk_scratch = Vec::with_capacity(64);

        let confirm_res: Result<(), CoreError> = async {
            // Transmit empty e2e::ST_DATA (seq = 0).
            with_deadline(
                &*clock,
                confirm_deadline,
                race_session_guards(
                    write_e2e_record(
                        &mut *writer,
                        &mut tx_cipher,
                        e2e_st::ST_DATA,
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

            // Wait for OPEN_OK, TARGET_*, or authenticated hop::ST_CLOSE.
            let frame = with_deadline(
                &*clock,
                confirm_deadline,
                race_session_guards(
                    frame_reader.next_frame(&mut *reader, &mut rx_cipher),
                    &lease,
                    &mut mtu_watch,
                    floor,
                ),
            )
            .await?;

            match frame {
                InboundStreamFrame::Eof => Err(CoreError::UnexpectedEof),
                InboundStreamFrame::HopControl { hdr, body, len } => {
                    if hdr.kind != outer::ST_CLOSE {
                        return Err(CoreError::Malformed);
                    }
                    let dist = usize::from(hdr.ttl_or_dist);
                    let n = hops.len();
                    if dist == n {
                        let pt = terminal_ctrl.open(outer::ST_CLOSE, &body[..len])?;
                        Err(decode_wire_error_bytes(&pt)?)
                    } else if dist < n {
                        let pt = hops[dist].2.open(outer::ST_CLOSE, &body[..len])?;
                        let reason = decode_wire_error_bytes(&pt)?;
                        Err(CoreError::hop_rejected(hdr.ttl_or_dist, reason))
                    } else {
                        Err(CoreError::Authentication)
                    }
                }
                InboundStreamFrame::E2eRenew(_) => Err(CoreError::Malformed),
                InboundStreamFrame::E2eRecord { opcode, body } => {
                    if !body.is_empty() {
                        return Err(CoreError::Malformed);
                    }
                    StreamOpenStatus::from_opcode(opcode)?.into_result()
                }
            }
        }
        .await;

        if let Err(err) = confirm_res {
            scope
                .path_source
                .report_outcome(path_id, PathOutcome::Failed(err.clone()));
            scope
                .metrics
                .record_setup_failure(Plane::Stream, Role::Origin, err.failure_class());
            let hop_ctrls = hops.into_iter().map(|(_, _, c)| c).collect();
            scope
                .runtime
                .spawner
                .spawn(Box::pin(abort_stream_hops(writer, hop_ctrls, clock)));
            return Err(err);
        }

        scope
            .metrics
            .record_setup_established(Plane::Stream, Role::Origin);
        scope
            .path_source
            .report_outcome(path_id, PathOutcome::Established { mtu: path_mtu });

        Ok(spawn_stream_session(StreamSessionParams {
            scope,
            peer,
            negotiated_mtu: path_mtu,
            floor,
            reader,
            frame_reader,
            writer,
            mtu_watch,
            tx_cipher,
            rx_cipher,
            lease,
            session_permit,
            role: StreamSessionRole::Origin(OriginStreamMeta {
                path_id,
                endpoint,
                hops,
                terminal_ctrl,
                renewals,
            }),
        }))
    }
}

impl Drop for StagedStream {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            inner
                .scope
                .path_source
                .report_outcome(inner.path_id, PathOutcome::Closed);
            let hop_ctrls = inner.hops.into_iter().map(|(_, _, c)| c).collect();
            let clock = Arc::clone(&inner.scope.runtime.clock);
            inner
                .scope
                .runtime
                .spawner
                .spawn(Box::pin(abort_stream_hops(inner.writer, hop_ctrls, clock)));
        }
    }
}

impl fmt::Debug for StagedStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StagedStream")
            .field("mtu", &self.mtu())
            .field("path_id", &self.path_id())
            .finish()
    }
}

struct StagedDatagramInner {
    scope: Arc<ScopeCore>,
    peer: PublicKey,
    endpoint: String,
    path_id: u64,
    path_mtu: OriginPathMtu,
    binding: Binding,
    remote_cid: Cid,
    tx: DatagramTx,
    rx: DatagramRx,
    hops: Vec<(PublicKey, String, ControlCipher)>,
    renewals: RenewalDriver,
    lease: Arc<LeaseHandle>,
    session_permit: SessionPermit,
}

/// Completed 1-RTT Datagram handshake paused prior to 1.0 RTT confirmation (Spec §6.1).
///
/// Destination `B` has NOT invoked `DatagramEndpointHandler::open` yet. Call [`Self::confirm`]
/// to transmit empty `e2e::DG_DATA(seq = 0)` once and immediately receive [`E2eDatagram`], or
/// drop this handle to abort cleanly with zero destination side effects.
pub struct StagedDatagram {
    inner: Option<StagedDatagramInner>,
}

impl StagedDatagram {
    /// Returns the authenticated wire MTU across all legs.
    #[must_use]
    pub fn mtu(&self) -> u16 {
        self.inner
            .as_ref()
            .map_or(0, |i| i.path_mtu.current_mtu())
    }

    /// Returns the initial maximum application payload bytes (`mtu.saturating_sub(30)`).
    #[must_use]
    pub fn max_payload(&self) -> usize {
        usize::from(self.mtu()).saturating_sub(DG_OVERHEAD)
    }

    /// Returns the destination peer's static public key.
    #[must_use]
    pub fn peer(&self) -> PublicKey {
        self.inner
            .as_ref()
            .map_or(PublicKey::from_bytes([0u8; 32]), |i| i.peer)
    }

    /// Returns the `ExplicitPath::id` for this staged connection.
    #[must_use]
    pub fn path_id(&self) -> u64 {
        self.inner.as_ref().map_or(0, |i| i.path_id)
    }

    /// Transmits empty `e2e::DG_DATA(seq = 0)` once within `SETUP_TIMEOUT` (no retransmission),
    /// immediately spawns the steady-state Datagram worker, and reports `PathOutcome::Established`.
    pub async fn confirm(mut self) -> Result<E2eDatagram, CoreError> {
        let Some(inner) = self.inner.take() else {
            return Err(CoreError::Closed);
        };
        let StagedDatagramInner {
            scope,
            peer,
            endpoint,
            path_id,
            path_mtu,
            binding,
            remote_cid,
            mut tx,
            rx,
            hops,
            renewals,
            lease,
            session_permit,
        } = inner;

        let clock = Arc::clone(&scope.runtime.clock);

        if scope.sessions.is_closed() {
            scope
                .path_source
                .report_outcome(path_id, PathOutcome::Failed(CoreError::Closed));
            scope.metrics.record_setup_failure(
                Plane::Datagram,
                Role::Origin,
                CoreError::Closed.failure_class(),
            );
            let hop_ctrls = hops.into_iter().map(|(_, _, c)| c).collect();
            scope.runtime.spawner.spawn(Box::pin(abort_datagram_staged(
                binding,
                remote_cid,
                tx,
                hop_ctrls,
            )));
            return Err(CoreError::Closed);
        }

        let confirm_deadline = clock.now().saturating_add(SETUP_TIMEOUT);
        let send_res: Result<(), CoreError> = async {
            let confirm_pkt = build_e2e_packet(&mut tx, e2e_dg::DG_DATA, &[], remote_cid)?;
            with_deadline(&*clock, confirm_deadline, binding.send_wait(confirm_pkt)).await
        }
        .await;

        if let Err(err) = send_res {
            scope
                .path_source
                .report_outcome(path_id, PathOutcome::Failed(err.clone()));
            scope
                .metrics
                .record_setup_failure(Plane::Datagram, Role::Origin, err.failure_class());
            let hop_ctrls = hops.into_iter().map(|(_, _, c)| c).collect();
            scope.runtime.spawner.spawn(Box::pin(abort_datagram_staged(
                binding,
                remote_cid,
                tx,
                hop_ctrls,
            )));
            return Err(err);
        }

        let mtu = path_mtu.current_mtu();
        scope
            .metrics
            .record_setup_established(Plane::Datagram, Role::Origin);
        scope
            .path_source
            .report_outcome(path_id, PathOutcome::Established { mtu });

        let mtu_watch = binding.mtu_watch();
        Ok(spawn_datagram_session(DatagramSessionParams {
            scope,
            peer,
            binding,
            remote_cid,
            mtu_watch,
            tx,
            rx,
            lease,
            session_permit,
            role: DatagramSessionRole::Origin(OriginDatagramMeta {
                path_id,
                endpoint,
                hops,
                renewals,
                path_mtu,
            }),
        }))
    }
}

impl Drop for StagedDatagram {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            inner
                .scope
                .path_source
                .report_outcome(inner.path_id, PathOutcome::Closed);
            let hop_ctrls = inner.hops.into_iter().map(|(_, _, c)| c).collect();
            inner.scope.runtime.spawner.spawn(Box::pin(abort_datagram_staged(
                inner.binding,
                inner.remote_cid,
                inner.tx,
                hop_ctrls,
            )));
        }
    }
}

impl fmt::Debug for StagedDatagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StagedDatagram")
            .field("mtu", &self.mtu())
            .field("path_id", &self.path_id())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Shared Pre-Flight & Sequential Credential Acquisition (Spec §6.1 Steps 1–6)
// ---------------------------------------------------------------------------

async fn fetch_initial_credentials(
    scope: &ScopeCore,
    plane: Plane,
    destination: PublicKey,
    endpoint: &str,
    path: &ExplicitPath,
) -> Result<(Credential, Vec<Credential>), CoreError> {
    let clock = &*scope.runtime.clock;
    let timeout = scope.auth_limits.auth_timeout;

    // Destination credential first (Spec §6.1 Step 6).
    let dest_dl = clock.now().saturating_add(timeout);
    let dest_cred = match with_deadline(
        clock,
        dest_dl,
        scope.credentials.credential(CredentialRequest {
            verifier: destination,
            target: TargetRef::Endpoint {
                name: endpoint,
                plane,
            },
            destination,
            endpoint,
            path_id: path.id,
            is_refresh: false,
            prior: &[],
        }),
    )
    .await
    {
        Ok(c) if c.len() <= CREDENTIAL_MAX => c,
        Ok(_) => return Err(CoreError::credential(CoreError::InvalidParameter)),
        Err(e) => return Err(CoreError::credential(e)),
    };

    // Each intermediate hop sequentially (0..N).
    let mut hop_creds = Vec::with_capacity(path.hops.len());
    for hop in &path.hops {
        let dl = clock.now().saturating_add(timeout);
        let cred = match with_deadline(
            clock,
            dl,
            scope.credentials.credential(CredentialRequest {
                verifier: hop.peer,
                target: TargetRef::Transit {
                    name: &hop.target,
                    plane,
                },
                destination,
                endpoint,
                path_id: path.id,
                is_refresh: false,
                prior: &[],
            }),
        )
        .await
        {
            Ok(c) if c.len() <= CREDENTIAL_MAX => c,
            Ok(_) => return Err(CoreError::credential(CoreError::InvalidParameter)),
            Err(e) => return Err(CoreError::credential(e)),
        };
        hop_creds.push(cred);
    }

    Ok((dest_cred, hop_creds))
}

fn validate_path_names(endpoint: &str, path: &ExplicitPath) -> Result<(), CoreError> {
    ValidatedName::validate_str(endpoint)?;
    if path.hops.len() > MAX_HOPS {
        return Err(CoreError::InvalidParameter);
    }
    for hop in &path.hops {
        ValidatedName::validate_str(&hop.target)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Stream Originator Staging (Spec §6.1)
// ---------------------------------------------------------------------------

pub(crate) async fn stage_stream(
    scope: Arc<ScopeCore>,
    peer: PublicKey,
    endpoint: &str,
    explicit_path: Option<ExplicitPath>,
) -> Result<StagedStream, CoreError> {
    if scope.sessions.is_closed() {
        if let Some(ref path) = explicit_path {
            scope
                .path_source
                .report_outcome(path.id, PathOutcome::Failed(CoreError::Closed));
        }
        return Err(CoreError::Closed);
    }

    let path = match explicit_path {
        Some(p) => p,
        None => {
            scope
                .path_source
                .resolve_path(peer, endpoint, Plane::Stream)
                .await?
        }
    };

    let path_id = path.id;
    scope
        .metrics
        .record_setup_attempt(Plane::Stream, Role::Origin);

    let res = stage_stream_inner(Arc::clone(&scope), peer, endpoint, &path).await;
    if let Err(ref err) = res {
        scope
            .path_source
            .report_outcome(path_id, PathOutcome::Failed(err.clone()));
        scope
            .metrics
            .record_setup_failure(Plane::Stream, Role::Origin, err.failure_class());
    }
    res
}

async fn stage_stream_inner(
    scope: Arc<ScopeCore>,
    peer: PublicKey,
    endpoint: &str,
    path: &ExplicitPath,
) -> Result<StagedStream, CoreError> {
    validate_path_names(endpoint, path)?;
    if scope.registry.is_vetoed(peer) {
        return Err(CoreError::Revoked);
    }

    let epoch = scope.registry.epoch_for_endpoint(peer, None);
    let session_permit = scope.try_acquire_session(Plane::Stream, Role::Origin)?;
    let min_mtu = path.min_mtu.max(STREAM_MIN_MTU);

    let carrier = scope.registry.get_stream_carrier(&path.first_channel)?;
    let carrier_mtu = carrier.caps().mtu();
    if carrier_mtu < min_mtu {
        return Err(CoreError::MtuTooSmall(carrier_mtu));
    }

    let (dest_cred, hop_creds) =
        fetch_initial_credentials(&scope, Plane::Stream, peer, endpoint, path).await?;

    let clock = Arc::clone(&scope.runtime.clock);
    let deadline = clock.now().saturating_add(SETUP_TIMEOUT);
    let max_attempts = path.hops.len().saturating_add(2);
    let mut cookies: HashMap<usize, Zeroizing<[u8; COOKIE_LEN]>> = HashMap::new();

    type EstablishedStreamParts = (
        OriginEstablished,
        Box<dyn StreamRead>,
        Box<dyn StreamWrite>,
        MtuWatch,
    );
    let mut established_parts: Option<EstablishedStreamParts> = None;

    for _attempt in 0..max_attempts {
        if clock.now() >= deadline {
            return Err(CoreError::Timeout);
        }

        let stream =
            with_deadline(&*clock, deadline, carrier.dial_stream(&path.first_locator)).await?;
        let caps = stream.caps();
        let origin_local_mtu = caps.mtu();
        if origin_local_mtu < min_mtu {
            return Err(CoreError::MtuTooSmall(origin_local_mtu));
        }
        let mtu_watch = caps.mtu_watch();
        let (mut reader, mut writer) = stream.into_halves();

        let hop_inputs: Vec<HopFlightInput<'_>> = path
            .hops
            .iter()
            .zip(hop_creds.iter())
            .map(|(h, c)| HopFlightInput {
                peer: h.peer,
                target: &h.target,
                credential: c.as_bytes(),
            })
            .collect();

        let (origin_state, flight) = SetupFlightBuilder::build(&SetupFlightParams {
            local: &scope.keypair,
            plane: Plane::Stream,
            origin_local_mtu,
            min_mtu,
            upstream_cid: Cid::UNBOUND,
            destination: peer,
            endpoint,
            dest_credential: dest_cred.as_bytes(),
            hops: &hop_inputs,
            cookies: &cookies,
            wall_time_ms: scope.runtime.wall_time_ms(),
        })?;

        with_deadline(&*clock, deadline, write_frame(&mut *writer, &flight, &*clock)).await?;
        let reply = read_setup_reply(&mut *reader, &*clock, deadline).await?;

        match reply {
            StreamSetupReply::Err(frame) => {
                return Err(origin_state.open_setup_err(&frame)?);
            }
            StreamSetupReply::Cookie(frame) => {
                let (idx, cookie) = origin_state.unseal_setup_cookie(&frame)?;
                if cookies.insert(idx, cookie).is_some() {
                    return Err(CoreError::CookieRequired);
                }
                continue;
            }
            StreamSetupReply::Ok(wire) => {
                let est = origin_state.finish_setup_ok(&wire)?;
                established_parts = Some((est, reader, writer, mtu_watch));
                break;
            }
        }
    }

    let Some((est, reader, writer, mtu_watch)) = established_parts else {
        return Err(CoreError::CookieRequired);
    };

    let lease = LeaseHandle::from_ttl(peer, est.dest_ttl, MAX_WIRE_LEASE_TTL, Arc::clone(&clock))?;
    scope.registry.track_endpoint(&epoch, peer, None, &lease)?;

    let hop_ttls_and_creds: Vec<(core::time::Duration, Credential)> =
        est.hop_ttls.into_iter().zip(hop_creds).collect();
    let renewals = RenewalDriver::new(
        Plane::Stream,
        est.dest_ttl,
        dest_cred,
        hop_ttls_and_creds,
        clock.now(),
        &mut OsRng,
    );

    let hops: Vec<(PublicKey, String, ControlCipher)> = path
        .hops
        .iter()
        .zip(est.hop_keys)
        .map(|(h, hk)| (h.peer, h.target.clone(), hk.control_cipher(true)))
        .collect();
    let terminal_ctrl = est.terminal_hop_key.control_cipher(true);
    let tx_cipher = StreamCipher::new(est.session_keys.tx_key());
    let rx_cipher = StreamCipher::new(est.session_keys.rx_key());

    Ok(StagedStream {
        inner: Some(StagedStreamInner {
            scope,
            peer,
            endpoint: endpoint.to_owned(),
            path_id: path.id,
            path_mtu: est.path_mtu,
            floor: min_mtu,
            reader,
            writer,
            mtu_watch,
            tx_cipher,
            rx_cipher,
            hops,
            terminal_ctrl,
            renewals,
            lease,
            session_permit,
        }),
    })
}

// ---------------------------------------------------------------------------
// Datagram Originator Staging (Spec §6.1)
// ---------------------------------------------------------------------------

pub(crate) async fn stage_datagram(
    scope: Arc<ScopeCore>,
    ports: Arc<PortSlot>,
    peer: PublicKey,
    endpoint: &str,
    caller_min_mtu: u16,
    explicit_path: Option<ExplicitPath>,
) -> Result<StagedDatagram, CoreError> {
    if scope.sessions.is_closed() {
        if let Some(ref path) = explicit_path {
            scope
                .path_source
                .report_outcome(path.id, PathOutcome::Failed(CoreError::Closed));
        }
        return Err(CoreError::Closed);
    }

    let path = match explicit_path {
        Some(p) => p,
        None => {
            scope
                .path_source
                .resolve_path(peer, endpoint, Plane::Datagram)
                .await?
        }
    };

    let path_id = path.id;
    scope
        .metrics
        .record_setup_attempt(Plane::Datagram, Role::Origin);

    let res = stage_datagram_inner(
        Arc::clone(&scope),
        ports,
        peer,
        endpoint,
        caller_min_mtu,
        &path,
    )
    .await;
    if let Err(ref err) = res {
        scope
            .path_source
            .report_outcome(path_id, PathOutcome::Failed(err.clone()));
        scope
            .metrics
            .record_setup_failure(Plane::Datagram, Role::Origin, err.failure_class());
    }
    res
}

async fn stage_datagram_inner(
    scope: Arc<ScopeCore>,
    ports: Arc<PortSlot>,
    peer: PublicKey,
    endpoint: &str,
    caller_min_mtu: u16,
    path: &ExplicitPath,
) -> Result<StagedDatagram, CoreError> {
    validate_path_names(endpoint, path)?;
    if scope.registry.is_vetoed(peer) {
        return Err(CoreError::Revoked);
    }

    let epoch = scope.registry.epoch_for_endpoint(peer, None);
    let session_permit = scope.try_acquire_session(Plane::Datagram, Role::Origin)?;
    let min_mtu = path.min_mtu.max(caller_min_mtu).max(DATAGRAM_MIN_MTU);

    let carrier = scope.registry.get_datagram_carrier(&path.first_channel)?;
    let carrier_mtu = carrier.caps().mtu();
    if carrier_mtu < min_mtu {
        return Err(CoreError::MtuTooSmall(carrier_mtu));
    }

    let (dest_cred, hop_creds) =
        fetch_initial_credentials(&scope, Plane::Datagram, peer, endpoint, path).await?;

    let clock = Arc::clone(&scope.runtime.clock);
    let deadline = clock.now().saturating_add(SETUP_TIMEOUT);

    // Open first_channel link ONCE before the cookie-retry loop and reuse ONE Binding across retries (Spec §6.1).
    let link = with_deadline(&*clock, deadline, carrier.open_link(&path.first_locator)).await?;
    let registry = ports.current();
    let (port, _port_hold) = registry.attach_outbound(link)?;
    let binding = port.bind(Some(Arc::clone(&scope.metrics)))?;

    let max_attempts = path.hops.len().saturating_add(2);
    let mut cookies: HashMap<usize, Zeroizing<[u8; COOKIE_LEN]>> = HashMap::new();
    let mut established: Option<OriginEstablished> = None;

    for _attempt in 0..max_attempts {
        if clock.now() >= deadline {
            return Err(CoreError::Timeout);
        }

        let origin_local_mtu = binding.mtu();
        if origin_local_mtu < min_mtu {
            return Err(CoreError::MtuTooSmall(origin_local_mtu));
        }

        let hop_inputs: Vec<HopFlightInput<'_>> = path
            .hops
            .iter()
            .zip(hop_creds.iter())
            .map(|(h, c)| HopFlightInput {
                peer: h.peer,
                target: &h.target,
                credential: c.as_bytes(),
            })
            .collect();

        let (origin_state, flight) = SetupFlightBuilder::build(&SetupFlightParams {
            local: &scope.keypair,
            plane: Plane::Datagram,
            origin_local_mtu,
            min_mtu,
            upstream_cid: binding.cid(),
            destination: peer,
            endpoint,
            dest_credential: dest_cred.as_bytes(),
            hops: &hop_inputs,
            cookies: &cookies,
            wall_time_ms: scope.runtime.wall_time_ms(),
        })?;

        let mut state_slot = Some(origin_state);
        let mut replies = SetupReplies::send(&binding, &flight, &*clock)?;

        let retry_cookie = loop {
            let pkt = replies.next_reply(deadline).await?;
            let bytes = pkt.payload();
            let Some(&op) = bytes.first() else {
                continue;
            };
            match op {
                outer::SETUP_ERR => {
                    let Ok(frame) = SetupErrFrame::parse(bytes) else {
                        continue;
                    };
                    if frame.target_cid != binding.cid() {
                        continue;
                    }
                    if let Some(ref st) = state_slot {
                        if let Ok(err) = st.open_setup_err(&frame) {
                            return Err(err);
                        }
                    }
                    // Unauthentic/spoofed SETUP_ERR -> silently ignore (Spec §6.1 Step 7).
                }
                outer::SETUP_COOKIE => {
                    let Ok(frame) = SetupCookieFrame::parse(bytes) else {
                        continue;
                    };
                    if frame.target_cid != binding.cid() {
                        continue;
                    }
                    if let Some(ref st) = state_slot {
                        if let Ok((idx, cookie)) = st.unseal_setup_cookie(&frame) {
                            break Some((idx, cookie));
                        }
                    }
                    // Unauthentic/spoofed SETUP_COOKIE -> silently ignore!
                }
                outer::SETUP_OK => {
                    // Authentic SETUP_OK advances state or fails on TTL/MTU; spoofed returns Ok(None)!
                    if let Some(est) =
                        OriginSetupState::try_finish_datagram_ok(&mut state_slot, binding.cid(), bytes)?
                    {
                        established = Some(est);
                        break None;
                    }
                }
                _ => continue,
            }
        };

        if let Some((idx, cookie)) = retry_cookie {
            if cookies.insert(idx, cookie).is_some() {
                return Err(CoreError::CookieRequired);
            }
            continue;
        }
        break;
    }

    let Some(est) = established else {
        return Err(CoreError::CookieRequired);
    };

    let lease = LeaseHandle::from_ttl(peer, est.dest_ttl, MAX_WIRE_LEASE_TTL, Arc::clone(&clock))?;
    scope.registry.track_endpoint(&epoch, peer, None, &lease)?;

    let hop_ttls_and_creds: Vec<(core::time::Duration, Credential)> =
        est.hop_ttls.into_iter().zip(hop_creds).collect();
    let renewals = RenewalDriver::new(
        Plane::Datagram,
        est.dest_ttl,
        dest_cred,
        hop_ttls_and_creds,
        clock.now(),
        &mut OsRng,
    );

    let hops: Vec<(PublicKey, String, ControlCipher)> = path
        .hops
        .iter()
        .zip(est.hop_keys)
        .map(|(h, hk)| (h.peer, h.target.clone(), hk.control_cipher(true)))
        .collect();
    let tx = DatagramTx::new(est.session_keys.tx_key());
    let rx = DatagramRx::new(est.session_keys.rx_key());
    let path_mtu = OriginPathMtu::new(est.legs, min_mtu);

    Ok(StagedDatagram {
        inner: Some(StagedDatagramInner {
            scope,
            peer,
            endpoint: endpoint.to_owned(),
            path_id: path.id,
            path_mtu,
            binding,
            remote_cid: est.responder_cid,
            tx,
            rx,
            hops,
            renewals,
            lease,
            session_permit,
        }),
    })
}
