use crate::datagram_session::ConfluenceDatagramSession;
use crate::error::{CoreError, Result};
use crate::scope::{PublishedDatagramEndpoint, PublishedStreamEndpoint, TrustScope};
use crate::seams::access::{AccessRequest, Action, Decision, Grant};
use crate::seams::channel::{
    BoxedAsyncStream, DatagramChannel, DatagramForwardChannel, StreamChannel, StreamForwardChannel,
};
use crate::seams::edge::InboundStream;
use crate::seams::routing::{ExplicitPath, PathSource};
use crate::security::cookie::{
    seal_handshake_envelope, unseal_cookie_challenge, EnvelopeCheck, COOKIE_BYTES,
    HANDSHAKE_MAC_BYTES,
};
use crate::security::grant::GrantEnforcer;
use crate::security::noise::{
    InitiatorHandshake, VerifiedInitiation, DATAGRAM_WIRE_OVERHEAD_BYTES, DEFAULT_PROLOGUE,
};
use crate::stream_session::ConfluenceStream;
use crate::types::{
    ChannelAddr, ChannelId, CircuitId, EndpointName, HopLabel, PeerId, Plane, ScopeId, TargetTag,
};
use crate::wire::{
    append_stream_segment, pack_chain_segments, read_stream_reply, read_stream_segment,
    write_stream_reply, DgramCtrlPacket, E2eHandshakeReq, E2eHandshakeResp, StreamSegmentMode,
    StreamSetupReply,
};
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::{oneshot, Semaphore};

/// Minimum MTU required on a Datagram Plane carrier.
pub const MIN_DATAGRAM_MTU: usize = 512;

enum PendingDgramOutcome {
    Accept { responder_label: u32, msg2: Vec<u8> },
    Challenge { target_tag: TargetTag, challenge: Vec<u8> },
    Reject { target_tag: TargetTag, reason: String },
}

/// A self-contained Confluence Node instance.
///
/// Multiple independent `Node` instances can coexist in user space without shared state,
/// host-wide privileges, or merged Trust Scopes (Cleanroom Invariant #9).
pub struct Node {
    path_source: Arc<dyn PathSource>,
    scopes_by_id: DashMap<ScopeId, Arc<TrustScope>>,
    scopes_by_tag: DashMap<TargetTag, Arc<TrustScope>>,
    dgram_carriers: DashMap<ChannelId, Arc<dyn DatagramChannel>>,
    stream_carriers: DashMap<ChannelId, Arc<dyn StreamChannel>>,
    dgram_fwd_channels: DashMap<TargetTag, Arc<dyn DatagramForwardChannel>>,
    stream_fwd_channels: DashMap<TargetTag, Arc<dyn StreamForwardChannel>>,
    dgram_sessions: Arc<DashMap<u32, Arc<ConfluenceDatagramSession>>>,
    pending_dgram_setups: DashMap<CircuitId, oneshot::Sender<PendingDgramOutcome>>,
    pending_ctrl_reqs: DashMap<u64, oneshot::Sender<Vec<u8>>>,
    next_label: AtomicU32,
    next_ctrl_req_id: AtomicU64,
    preauth_sem: Arc<Semaphore>,
    setup_timeout: Duration,
}

impl Node {
    pub fn new(path_source: Arc<dyn PathSource>) -> Arc<Self> {
        Self::with_setup_timeout(path_source, Duration::from_secs(5))
    }

    pub fn with_setup_timeout(
        path_source: Arc<dyn PathSource>,
        setup_timeout: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            path_source,
            scopes_by_id: DashMap::new(),
            scopes_by_tag: DashMap::new(),
            dgram_carriers: DashMap::new(),
            stream_carriers: DashMap::new(),
            dgram_fwd_channels: DashMap::new(),
            stream_fwd_channels: DashMap::new(),
            dgram_sessions: Arc::new(DashMap::new()),
            pending_dgram_setups: DashMap::new(),
            pending_ctrl_reqs: DashMap::new(),
            next_label: AtomicU32::new(1),
            next_ctrl_req_id: AtomicU64::new(1),
            preauth_sem: Arc::new(Semaphore::new(256)),
            setup_timeout,
        })
    }

    /// Mounts an isolated `TrustScope` onto this `Node`.
    pub fn add_scope(&self, scope: Arc<TrustScope>) -> Result<()> {
        let tag = scope.target_tag();
        if self.scopes_by_id.contains_key(scope.id()) || self.scopes_by_tag.contains_key(&tag) {
            return Err(CoreError::InvalidInput(format!(
                "scope '{}' or target_tag {tag} already mounted",
                scope.id()
            )));
        }
        self.scopes_by_id
            .insert(scope.id().clone(), Arc::clone(&scope));
        self.scopes_by_tag.insert(tag, scope);
        Ok(())
    }

    pub fn scope(&self, id: &ScopeId) -> Result<Arc<TrustScope>> {
        self.scopes_by_id
            .get(id)
            .map(|r| Arc::clone(r.value()))
            .ok_or_else(|| CoreError::ScopeNotFound(id.to_string()))
    }

    /// Publishes a Stream endpoint in `scope` (Seam 4 Inbound).
    pub fn publish_stream_endpoint(
        &self,
        scope: &ScopeId,
        endpoint: EndpointName,
    ) -> Result<PublishedStreamEndpoint> {
        self.scope(scope)?.publish_stream_endpoint(endpoint)
    }

    /// Publishes a Datagram endpoint in `scope` (Seam 4 Inbound).
    pub fn publish_datagram_endpoint(
        &self,
        scope: &ScopeId,
        endpoint: EndpointName,
    ) -> Result<PublishedDatagramEndpoint> {
        self.scope(scope)?.publish_datagram_endpoint(endpoint)
    }

    /// Attaches a Datagram Plane transport carrier and starts its packet demultiplexer loop.
    pub fn attach_datagram_channel(self: &Arc<Self>, carrier: Arc<dyn DatagramChannel>) -> Result<()> {
        let caps = carrier.caps();
        if caps.plane != Plane::Datagram {
            return Err(CoreError::PlaneMismatch {
                expected: Plane::Datagram,
                actual: caps.plane,
            });
        }
        let mtu = caps.max_payload_bytes.ok_or_else(|| {
            CoreError::CapabilityMismatch(
                "DatagramChannel must declare max_payload_bytes MTU".into(),
            )
        })?;
        if mtu < MIN_DATAGRAM_MTU {
            return Err(CoreError::CapabilityMismatch(format!(
                "DatagramChannel MTU {mtu} below minimum {MIN_DATAGRAM_MTU}"
            )));
        }
        if self.dgram_carriers.contains_key(carrier.id()) {
            return Ok(());
        }
        let cid = carrier.id().clone();
        self.dgram_carriers.insert(cid.clone(), Arc::clone(&carrier));

        let node = Arc::clone(self);
        tokio::spawn(async move {
            let mut buf = vec![0u8; mtu.max(65536)];
            loop {
                match carrier.recv_from(&mut buf).await {
                    Ok((n, src_addr)) => {
                        if n < 4 {
                            continue;
                        }
                        let pkt = buf[..n].to_vec();
                        node.dispatch_inbound_datagram(&carrier, src_addr, pkt).await;
                    }
                    Err(e) => {
                        // Carrier failed or closed -> tear down all datagram sessions bound to it honestly!
                        let reason = format!("carrier '{cid}' failed: {e}");
                        let affected: Vec<Arc<ConfluenceDatagramSession>> = node
                            .dgram_sessions
                            .iter()
                            .filter(|entry| entry.value().carrier_id() == &cid)
                            .map(|entry| Arc::clone(entry.value()))
                            .collect();
                        for sess in affected {
                            sess.terminate_locally(reason.clone());
                        }
                        break;
                    }
                }
            }
        });
        Ok(())
    }

    /// Attaches a Stream Plane transport carrier and starts its inbound stream accept loop.
    pub fn attach_stream_channel(self: &Arc<Self>, carrier: Arc<dyn StreamChannel>) -> Result<()> {
        let caps = carrier.caps();
        if caps.plane != Plane::Stream {
            return Err(CoreError::PlaneMismatch {
                expected: Plane::Stream,
                actual: caps.plane,
            });
        }
        if self.stream_carriers.contains_key(carrier.id()) {
            return Ok(());
        }
        self.stream_carriers
            .insert(carrier.id().clone(), Arc::clone(&carrier));

        let node = Arc::clone(self);
        tokio::spawn(async move {
            while let Ok((stream, src_addr)) = carrier.accept().await {
                let Ok(permit) = Arc::clone(&node.preauth_sem).try_acquire_owned() else {
                    // Pre-auth overload protection: drop excess unauthenticated inbound connections immediately.
                    continue;
                };
                let n_clone = Arc::clone(&node);
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = tokio::time::timeout(
                        n_clone.setup_timeout,
                        n_clone.handle_inbound_stream(stream, src_addr),
                    )
                    .await;
                });
            }
        });
        Ok(())
    }

    /// Mounts a composable forwardable Datagram channel plugin by its `TargetTag`.
    pub fn mount_datagram_forward_channel(
        self: &Arc<Self>,
        fwd: Arc<dyn DatagramForwardChannel>,
    ) -> Result<()> {
        let caps = fwd.caps();
        if caps.plane != Plane::Datagram {
            return Err(CoreError::PlaneMismatch {
                expected: Plane::Datagram,
                actual: caps.plane,
            });
        }
        if let Some(carrier) = fwd.underlying_carrier() {
            self.attach_datagram_channel(carrier)?;
        }
        self.dgram_fwd_channels.insert(fwd.target_tag(), fwd);
        Ok(())
    }

    /// Mounts a composable forwardable Stream channel plugin by its `TargetTag`.
    pub fn mount_stream_forward_channel(
        &self,
        fwd: Arc<dyn StreamForwardChannel>,
    ) -> Result<()> {
        let caps = fwd.caps();
        if caps.plane != Plane::Stream {
            return Err(CoreError::PlaneMismatch {
                expected: Plane::Stream,
                actual: caps.plane,
            });
        }
        self.stream_fwd_channels.insert(fwd.target_tag(), fwd);
        Ok(())
    }

    /// Sends an opaque control request to a remote `DatagramForwardChannel` (e.g., for passive relay registration)
    /// and awaits its `ChannelControlResp`.
    pub async fn send_datagram_channel_control(
        &self,
        carrier_id: &ChannelId,
        dest_addr: &ChannelAddr,
        target_tag: TargetTag,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let carrier = self.validate_datagram_carrier(carrier_id)?;
        let req_id = self.next_ctrl_req_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending_ctrl_reqs.insert(req_id, tx);

        let pkt = DgramCtrlPacket::ChannelControl {
            req_id,
            target_tag,
            payload,
        }
        .encode()?;

        if let Err(e) = carrier.send_to(dest_addr, &pkt).await {
            self.pending_ctrl_reqs.remove(&req_id);
            return Err(e);
        }

        tokio::time::timeout(self.setup_timeout, rx)
            .await
            .map_err(|_| {
                self.pending_ctrl_reqs.remove(&req_id);
                CoreError::Timeout
            })?
            .map_err(|_| CoreError::Closed("control request cancelled".into()))
    }

    /// Opens an end-to-end authenticated Stream to `endpoint` on `target_peer` within `scope` (Seam 4 Outbound).
    pub async fn open_stream(
        self: &Arc<Self>,
        scope_id: &ScopeId,
        target_peer: PeerId,
        endpoint: EndpointName,
    ) -> Result<ConfluenceStream> {
        let scope = self.scope(scope_id)?;
        let path = self
            .path_source
            .resolve(scope_id, &target_peer, Plane::Stream)
            .await?;
        self.validate_explicit_path(&path, Plane::Stream, &target_peer)?;

        let carrier = self.validate_stream_carrier(&path.entry_channel)?;
        let mut cookies: HashMap<TargetTag, [u8; COOKIE_BYTES]> = HashMap::new();

        for attempt in 0..2 {
            let mut raw_stream = carrier.open(&path.entry_addr).await?;

            // Build single-pass pipelined setup burst `[Seg_1 | ... | Seg_k | FinalE2e]`.
            let mut sent_mac1s: HashMap<TargetTag, ([u8; HANDSHAKE_MAC_BYTES], PeerId)> =
                HashMap::new();
            let mut burst = Vec::new();

            for hop in &path.hops {
                let hop_req = crate::wire::HopHandshakeReq {
                    timestamp: scope.next_timestamp(),
                    plane: Plane::Stream,
                    next_addr: hop.next_addr.clone(),
                    credential: hop.credential.clone(),
                }
                .encode();
                let (_, hop_msg1) = InitiatorHandshake::initiate(
                    scope.keypair(),
                    hop.channel_pubkey,
                    DEFAULT_PROLOGUE,
                    &hop_req,
                )?;
                let (env, mac1) = seal_handshake_envelope(
                    &hop.channel_pubkey,
                    &hop_msg1,
                    cookies.get(&hop.target_tag),
                )?;
                sent_mac1s.insert(hop.target_tag, (mac1, hop.channel_pubkey));
                append_stream_segment(
                    &mut burst,
                    StreamSegmentMode::ForwardHop,
                    hop.target_tag,
                    &env,
                )?;
            }

            let e2e_req = E2eHandshakeReq {
                timestamp: scope.next_timestamp(),
                plane: Plane::Stream,
                endpoint: endpoint.clone(),
                credential: path.target_credential.clone(),
            }
            .encode();
            let (e2e_init, e2e_msg1) = InitiatorHandshake::initiate(
                scope.keypair(),
                path.target_pubkey,
                DEFAULT_PROLOGUE,
                &e2e_req,
            )?;
            let (final_env, final_mac1) = seal_handshake_envelope(
                &path.target_pubkey,
                &e2e_msg1,
                cookies.get(&path.target_scope_tag),
            )?;
            sent_mac1s.insert(path.target_scope_tag, (final_mac1, path.target_pubkey));
            append_stream_segment(
                &mut burst,
                StreamSegmentMode::FinalE2e,
                path.target_scope_tag,
                &final_env,
            )?;

            raw_stream.write_all(&burst).await?;
            raw_stream.flush().await?;

            let reply = tokio::time::timeout(self.setup_timeout, read_stream_reply(&mut raw_stream))
                .await
                .map_err(|_| CoreError::Timeout)??;

            match reply {
                StreamSetupReply::Accept { target_tag, msg2 } => {
                    if target_tag != path.target_scope_tag {
                        return Err(CoreError::AuthFailed);
                    }
                    let (keys, resp_pt) = e2e_init.finalize(&msg2)?;
                    let resp = E2eHandshakeResp::decode(&resp_pt)?;
                    let grant = Grant::with_ttl(Duration::from_millis(resp.granted_ttl_millis));
                    let enforcer = GrantEnforcer::new(grant);
                    enforcer.spawn_revocation_watcher(
                        scope.access().revocations(),
                        scope.id().clone(),
                        target_peer,
                        Some(endpoint.clone()),
                    );
                    return Ok(ConfluenceStream::spawn_new(
                        raw_stream,
                        keys,
                        target_peer,
                        scope.id().clone(),
                        endpoint,
                        enforcer,
                        None,
                        None,
                        None,
                    ));
                }
                StreamSetupReply::Challenge {
                    target_tag,
                    challenge,
                } if attempt == 0 => {
                    let (sent_mac1, responder_pk) = sent_mac1s
                        .get(&target_tag)
                        .ok_or(CoreError::AuthFailed)?;
                    let cookie = unseal_cookie_challenge(responder_pk, sent_mac1, &challenge)?;
                    cookies.insert(target_tag, cookie);
                    continue;
                }
                StreamSetupReply::Challenge { target_tag, .. } => {
                    return Err(CoreError::PathSetupFailed(format!(
                        "repeated cookie challenge from {target_tag}"
                    )));
                }
                StreamSetupReply::Reject { target_tag, reason } => {
                    return Err(CoreError::AccessDenied(format!(
                        "target {target_tag} rejected setup: {reason}"
                    )));
                }
            }
        }

        Err(CoreError::PathSetupFailed("stream setup exhausted".into()))
    }

    /// Opens an end-to-end authenticated Datagram session to `endpoint` on `target_peer` within `scope` (Seam 4 Outbound).
    pub async fn open_datagram(
        self: &Arc<Self>,
        scope_id: &ScopeId,
        target_peer: PeerId,
        endpoint: EndpointName,
    ) -> Result<Arc<ConfluenceDatagramSession>> {
        let scope = self.scope(scope_id)?;
        let path = self
            .path_source
            .resolve(scope_id, &target_peer, Plane::Datagram)
            .await?;
        self.validate_explicit_path(&path, Plane::Datagram, &target_peer)?;

        let carrier = self.validate_datagram_carrier(&path.entry_channel)?;
        let mtu = carrier.caps().max_payload_bytes.unwrap_or(1200);
        let mut cookies: HashMap<TargetTag, [u8; COOKIE_BYTES]> = HashMap::new();

        for attempt in 0..2 {
            let circuit_id = CircuitId::random();
            let in_label = self.alloc_label();
            let mut sent_mac1s: HashMap<TargetTag, ([u8; HANDSHAKE_MAC_BYTES], PeerId)> =
                HashMap::new();
            let mut segments: Vec<(TargetTag, Vec<u8>)> = Vec::with_capacity(path.hops.len() + 1);

            for hop in &path.hops {
                let hop_req = crate::wire::HopHandshakeReq {
                    timestamp: scope.next_timestamp(),
                    plane: Plane::Datagram,
                    next_addr: hop.next_addr.clone(),
                    credential: hop.credential.clone(),
                }
                .encode();
                let (_, hop_msg1) = InitiatorHandshake::initiate(
                    scope.keypair(),
                    hop.channel_pubkey,
                    DEFAULT_PROLOGUE,
                    &hop_req,
                )?;
                let (env, mac1) = seal_handshake_envelope(
                    &hop.channel_pubkey,
                    &hop_msg1,
                    cookies.get(&hop.target_tag),
                )?;
                sent_mac1s.insert(hop.target_tag, (mac1, hop.channel_pubkey));
                segments.push((hop.target_tag, env));
            }

            let e2e_req = E2eHandshakeReq {
                timestamp: scope.next_timestamp(),
                plane: Plane::Datagram,
                endpoint: endpoint.clone(),
                credential: path.target_credential.clone(),
            }
            .encode();
            let (e2e_init, e2e_msg1) = InitiatorHandshake::initiate(
                scope.keypair(),
                path.target_pubkey,
                DEFAULT_PROLOGUE,
                &e2e_req,
            )?;
            let (final_env, final_mac1) = seal_handshake_envelope(
                &path.target_pubkey,
                &e2e_msg1,
                cookies.get(&path.target_scope_tag),
            )?;
            sent_mac1s.insert(path.target_scope_tag, (final_mac1, path.target_pubkey));
            segments.push((path.target_scope_tag, final_env));

            let (first_tag, first_seg) = segments.remove(0);
            let remaining_tail = pack_chain_segments(&segments)?;

            let setup_pkt = DgramCtrlPacket::ChainSetup {
                circuit_id,
                sender_return_label: in_label,
                target_tag: first_tag,
                seg_payload: first_seg,
                remaining_tail,
            }
            .encode()?;

            if setup_pkt.len() > mtu {
                return Err(CoreError::CapabilityMismatch(format!(
                    "ChainSetup packet ({} bytes) exceeds entry carrier MTU ({mtu} bytes)",
                    setup_pkt.len()
                )));
            }

            let (tx, rx) = oneshot::channel();
            self.pending_dgram_setups.insert(circuit_id, tx);

            if let Err(e) = carrier.send_to(&path.entry_addr, &setup_pkt).await {
                self.pending_dgram_setups.remove(&circuit_id);
                return Err(e);
            }

            let outcome = tokio::time::timeout(self.setup_timeout, rx)
                .await
                .map_err(|_| {
                    self.pending_dgram_setups.remove(&circuit_id);
                    CoreError::Timeout
                })?
                .map_err(|_| CoreError::Closed("datagram setup cancelled".into()))?;

            match outcome {
                PendingDgramOutcome::Accept {
                    responder_label,
                    msg2,
                } => {
                    let (keys, resp_pt) = e2e_init.finalize(&msg2)?;
                    let resp = E2eHandshakeResp::decode(&resp_pt)?;
                    let grant = Grant::with_ttl(Duration::from_millis(resp.granted_ttl_millis));
                    let enforcer = GrantEnforcer::new(grant);
                    enforcer.spawn_revocation_watcher(
                        scope.access().revocations(),
                        scope.id().clone(),
                        target_peer,
                        Some(endpoint.clone()),
                    );
                    let session = ConfluenceDatagramSession::new(
                        in_label,
                        responder_label,
                        keys,
                        target_peer,
                        scope.id().clone(),
                        endpoint,
                        enforcer,
                        Arc::clone(&carrier),
                        path.entry_addr.clone(),
                        None,
                        None,
                        Arc::clone(&self.dgram_sessions),
                    );
                    self.dgram_sessions.insert(in_label, Arc::clone(&session));
                    return Ok(session);
                }
                PendingDgramOutcome::Challenge {
                    target_tag,
                    challenge,
                } if attempt == 0 => {
                    let (sent_mac1, responder_pk) = sent_mac1s
                        .get(&target_tag)
                        .ok_or(CoreError::AuthFailed)?;
                    let cookie = unseal_cookie_challenge(responder_pk, sent_mac1, &challenge)?;
                    cookies.insert(target_tag, cookie);
                    continue;
                }
                PendingDgramOutcome::Challenge { target_tag, .. } => {
                    return Err(CoreError::PathSetupFailed(format!(
                        "repeated cookie challenge from {target_tag}"
                    )));
                }
                PendingDgramOutcome::Reject { target_tag, reason } => {
                    return Err(CoreError::AccessDenied(format!(
                        "target {target_tag} rejected setup: {reason}"
                    )));
                }
            }
        }

        Err(CoreError::PathSetupFailed("datagram setup exhausted".into()))
    }

    fn alloc_label(&self) -> u32 {
        loop {
            let l = self.next_label.fetch_add(1, Ordering::Relaxed);
            if l != 0 && !self.dgram_sessions.contains_key(&l) {
                return l;
            }
        }
    }

    fn validate_explicit_path(
        &self,
        path: &ExplicitPath,
        required_plane: Plane,
        expected_target: &PeerId,
    ) -> Result<()> {
        if path.plane != required_plane {
            return Err(CoreError::PlaneMismatch {
                expected: required_plane,
                actual: path.plane,
            });
        }
        if &path.target_pubkey != expected_target {
            return Err(CoreError::InvalidInput(
                "ExplicitPath target_pubkey does not match requested PeerId".into(),
            ));
        }
        if path.target_scope_tag != path.target_pubkey.target_tag() {
            return Err(CoreError::InvalidInput(
                "ExplicitPath target_scope_tag does not match target_pubkey".into(),
            ));
        }
        Ok(())
    }

    fn validate_datagram_carrier(&self, id: &ChannelId) -> Result<Arc<dyn DatagramChannel>> {
        let Some(carrier) = self.dgram_carriers.get(id).map(|r| Arc::clone(r.value())) else {
            if self.stream_carriers.contains_key(id) {
                return Err(CoreError::PlaneMismatch {
                    expected: Plane::Datagram,
                    actual: Plane::Stream,
                });
            }
            return Err(CoreError::ChannelNotFound(id.to_string()));
        };
        if !carrier.health().is_usable() {
            return Err(CoreError::ChannelUnhealthy(format!(
                "datagram carrier '{id}' is closed"
            )));
        }
        Ok(carrier)
    }

    fn validate_stream_carrier(&self, id: &ChannelId) -> Result<Arc<dyn StreamChannel>> {
        let Some(carrier) = self.stream_carriers.get(id).map(|r| Arc::clone(r.value())) else {
            if self.dgram_carriers.contains_key(id) {
                return Err(CoreError::PlaneMismatch {
                    expected: Plane::Stream,
                    actual: Plane::Datagram,
                });
            }
            return Err(CoreError::ChannelNotFound(id.to_string()));
        };
        if !carrier.health().is_usable() {
            return Err(CoreError::ChannelUnhealthy(format!(
                "stream carrier '{id}' is closed"
            )));
        }
        Ok(carrier)
    }

    async fn dispatch_inbound_datagram(
        self: &Arc<Self>,
        carrier: &Arc<dyn DatagramChannel>,
        src_addr: ChannelAddr,
        pkt: Vec<u8>,
    ) {
        let label = HopLabel::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
        if !label.is_control() {
            if let Some(sess) = self.dgram_sessions.get(&label.0).map(|r| Arc::clone(r.value())) {
                sess.handle_inbound_packet(&pkt[4..]).await;
            }
            return;
        }

        // Control packet (`HopLabel(0)`) — parse silently dropping malformed pre-auth packets.
        let Ok(ctrl) = DgramCtrlPacket::decode(&pkt) else {
            return;
        };

        match ctrl {
            DgramCtrlPacket::ChainSetup {
                circuit_id,
                sender_return_label,
                target_tag,
                seg_payload,
                remaining_tail,
            } => {
                if remaining_tail.is_empty() {
                    self.handle_final_datagram_setup(
                        carrier,
                        &src_addr,
                        circuit_id,
                        sender_return_label,
                        target_tag,
                        &seg_payload,
                    )
                    .await;
                }
                // Non-empty `remaining_tail` is handled by the Multi-Hop Path Engine (Phase 3a).
            }
            DgramCtrlPacket::ChainSetupResp {
                circuit_id,
                responder_label,
                msg2,
            } => {
                if let Some((_, waiter)) = self.pending_dgram_setups.remove(&circuit_id) {
                    let _ = waiter.send(PendingDgramOutcome::Accept {
                        responder_label,
                        msg2,
                    });
                }
            }
            DgramCtrlPacket::ChainSetupChallenge {
                circuit_id,
                target_tag,
                challenge,
            } => {
                if let Some((_, waiter)) = self.pending_dgram_setups.remove(&circuit_id) {
                    let _ = waiter.send(PendingDgramOutcome::Challenge {
                        target_tag,
                        challenge,
                    });
                }
            }
            DgramCtrlPacket::ChainSetupReject {
                circuit_id,
                target_tag,
                reason,
            } => {
                if let Some((_, waiter)) = self.pending_dgram_setups.remove(&circuit_id) {
                    let _ = waiter.send(PendingDgramOutcome::Reject { target_tag, reason });
                }
            }
            DgramCtrlPacket::ChannelControl {
                req_id,
                target_tag,
                payload,
            } => {
                if let Some(fwd) = self
                    .dgram_fwd_channels
                    .get(&target_tag)
                    .map(|r| Arc::clone(r.value()))
                {
                    if let Ok(Some(resp_payload)) =
                        fwd.handle_control(Arc::clone(carrier), &src_addr, &payload).await
                    {
                        if let Ok(raw) = (DgramCtrlPacket::ChannelControlResp {
                            req_id,
                            target_tag,
                            payload: resp_payload,
                        })
                        .encode()
                        {
                            let _ = carrier.send_to(&src_addr, &raw).await;
                        }
                    }
                }
            }
            DgramCtrlPacket::ChannelControlResp {
                req_id, payload, ..
            } => {
                if let Some((_, waiter)) = self.pending_ctrl_reqs.remove(&req_id) {
                    let _ = waiter.send(payload);
                }
            }
            DgramCtrlPacket::CircuitRenew { .. } | DgramCtrlPacket::CircuitRenewResp { .. } => {}
        }
    }

    async fn handle_final_datagram_setup(
        self: &Arc<Self>,
        carrier: &Arc<dyn DatagramChannel>,
        src_addr: &ChannelAddr,
        circuit_id: CircuitId,
        sender_return_label: u32,
        target_tag: TargetTag,
        envelope: &[u8],
    ) {
        let Some(scope) = self
            .scopes_by_tag
            .get(&target_tag)
            .map(|r| Arc::clone(r.value()))
        else {
            // Unrecognized target_tag -> silent pre-auth drop!
            return;
        };

        // 1. Pre-DH MAC1 + stateless MAC2 flood cookie check!
        let inner_msg1 = match scope
            .cookie_protector()
            .verify_envelope(src_addr.as_bytes(), envelope)
        {
            EnvelopeCheck::Verified(inner) => inner,
            EnvelopeCheck::Challenge(challenge) => {
                if let Ok(raw) = (DgramCtrlPacket::ChainSetupChallenge {
                    circuit_id,
                    target_tag,
                    challenge,
                })
                .encode()
                {
                    let _ = carrier.send_to(src_addr, &raw).await;
                }
                return;
            }
            EnvelopeCheck::Drop => return,
        };

        // 2. Cryptographic `Noise_IK` initiator verification.
        let Ok(verified) =
            VerifiedInitiation::read_msg1(scope.keypair(), DEFAULT_PROLOGUE, inner_msg1)
        else {
            return;
        };
        let remote_peer = verified.initiator_peer();

        // 3. Decode inner E2E request & check TAI64N replay window BEFORE calling AccessControl!
        let Ok(req) = E2eHandshakeReq::decode(verified.payload()) else {
            return;
        };
        if req.plane != Plane::Datagram {
            return;
        }
        if scope
            .replay_window()
            .check_and_record(&remote_peer, req.timestamp)
            .is_err()
        {
            return;
        }

        // 4. Verify endpoint is explicitly published in this isolated TrustScope.
        let Some((ep_tx, unpublish_rx)) = scope
            .endpoints()
            .datagram_endpoints
            .get(&req.endpoint)
            .map(|e| (e.tx.clone(), e.unpublish_rx.clone()))
        else {
            if let Ok(raw) = (DgramCtrlPacket::ChainSetupReject {
                circuit_id,
                target_tag,
                reason: format!("endpoint '{}' not published", req.endpoint),
            })
            .encode()
            {
                let _ = carrier.send_to(src_addr, &raw).await;
            }
            return;
        };

        // 5. Evaluate AccessControl on control event (fail-closed on error).
        let ac_req = AccessRequest {
            scope: scope.id().clone(),
            peer: remote_peer,
            credential: req.credential,
            action: Action::OpenEndpoint {
                endpoint: req.endpoint.clone(),
                plane: Plane::Datagram,
            },
        };
        let grant = match scope.access().evaluate(ac_req).await {
            Ok(Decision::Allow(g)) => g,
            Ok(Decision::Deny { reason }) => {
                if let Ok(raw) = (DgramCtrlPacket::ChainSetupReject {
                    circuit_id,
                    target_tag,
                    reason,
                })
                .encode()
                {
                    let _ = carrier.send_to(src_addr, &raw).await;
                }
                return;
            }
            Err(e) => {
                if let Ok(raw) = (DgramCtrlPacket::ChainSetupReject {
                    circuit_id,
                    target_tag,
                    reason: e.to_string(),
                })
                .encode()
                {
                    let _ = carrier.send_to(src_addr, &raw).await;
                }
                return;
            }
        };

        let ttl_millis = grant
            .expires_at
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(u64::MAX as u128) as u64;
        let resp_bytes = E2eHandshakeResp {
            granted_ttl_millis: ttl_millis,
        }
        .encode();
        let Ok((keys, msg2)) = verified.respond(&resp_bytes) else {
            return;
        };

        let in_label = self.alloc_label();
        let enforcer = GrantEnforcer::new(grant);
        enforcer.spawn_revocation_watcher(
            scope.access().revocations(),
            scope.id().clone(),
            remote_peer,
            Some(req.endpoint.clone()),
        );

        let session = ConfluenceDatagramSession::new(
            in_label,
            sender_return_label,
            keys,
            remote_peer,
            scope.id().clone(),
            req.endpoint,
            enforcer,
            Arc::clone(carrier),
            src_addr.clone(),
            Some(Arc::clone(scope.access())),
            Some(unpublish_rx),
            Arc::clone(&self.dgram_sessions),
        );
        self.dgram_sessions.insert(in_label, Arc::clone(&session));

        // Deliver authenticated session to published endpoint and send ChainSetupResp!
        if ep_tx.send(Arc::clone(&session)).await.is_err() {
            session.terminate_locally("endpoint listener dropped".into());
            return;
        }
        if let Ok(raw) = (DgramCtrlPacket::ChainSetupResp {
            circuit_id,
            responder_label: in_label,
            msg2,
        })
        .encode()
        {
            let _ = carrier.send_to(src_addr, &raw).await;
        }
        let _ = DATAGRAM_WIRE_OVERHEAD_BYTES;
    }

    async fn handle_inbound_stream(
        self: &Arc<Self>,
        mut stream: BoxedAsyncStream,
        src_addr: ChannelAddr,
    ) -> Result<()> {
        let (mode, target_tag, envelope) = read_stream_segment(&mut stream).await?;
        match mode {
            StreamSegmentMode::FinalE2e => {
                self.handle_final_stream_setup(stream, &src_addr, target_tag, &envelope)
                    .await
            }
            StreamSegmentMode::ChannelControl => {
                if let Some(fwd) = self
                    .stream_fwd_channels
                    .get(&target_tag)
                    .map(|r| Arc::clone(r.value()))
                {
                    fwd.handle_control_stream(stream, &src_addr, &envelope).await
                } else {
                    Ok(())
                }
            }
            StreamSegmentMode::ForwardHop => {
                // Handled by Multi-Hop Path Engine in Phase 3a.
                let _ = write_stream_reply(
                    &mut stream,
                    &StreamSetupReply::Reject {
                        target_tag,
                        reason: "forward channel not mounted".into(),
                    },
                )
                .await;
                Ok(())
            }
        }
    }

    async fn handle_final_stream_setup(
        self: &Arc<Self>,
        mut stream: BoxedAsyncStream,
        src_addr: &ChannelAddr,
        target_tag: TargetTag,
        envelope: &[u8],
    ) -> Result<()> {
        let Some(scope) = self
            .scopes_by_tag
            .get(&target_tag)
            .map(|r| Arc::clone(r.value()))
        else {
            // Silent pre-auth drop!
            return Ok(());
        };

        let inner_msg1 = match scope
            .cookie_protector()
            .verify_envelope(src_addr.as_bytes(), envelope)
        {
            EnvelopeCheck::Verified(inner) => inner,
            EnvelopeCheck::Challenge(challenge) => {
                let _ = write_stream_reply(
                    &mut stream,
                    &StreamSetupReply::Challenge {
                        target_tag,
                        challenge,
                    },
                )
                .await;
                return Ok(());
            }
            EnvelopeCheck::Drop => return Ok(()),
        };

        let Ok(verified) =
            VerifiedInitiation::read_msg1(scope.keypair(), DEFAULT_PROLOGUE, inner_msg1)
        else {
            return Ok(());
        };
        let remote_peer = verified.initiator_peer();

        let Ok(req) = E2eHandshakeReq::decode(verified.payload()) else {
            return Ok(());
        };
        if req.plane != Plane::Stream {
            return Ok(());
        }
        if scope
            .replay_window()
            .check_and_record(&remote_peer, req.timestamp)
            .is_err()
        {
            return Ok(());
        }

        let Some((ep_tx, unpublish_rx)) = scope
            .endpoints()
            .stream_endpoints
            .get(&req.endpoint)
            .map(|e| (e.tx.clone(), e.unpublish_rx.clone()))
        else {
            let _ = write_stream_reply(
                &mut stream,
                &StreamSetupReply::Reject {
                    target_tag,
                    reason: format!("endpoint '{}' not published", req.endpoint),
                },
            )
            .await;
            return Ok(());
        };

        let ac_req = AccessRequest {
            scope: scope.id().clone(),
            peer: remote_peer,
            credential: req.credential,
            action: Action::OpenEndpoint {
                endpoint: req.endpoint.clone(),
                plane: Plane::Stream,
            },
        };
        let grant = match scope.access().evaluate(ac_req).await {
            Ok(Decision::Allow(g)) => g,
            Ok(Decision::Deny { reason }) => {
                let _ = write_stream_reply(
                    &mut stream,
                    &StreamSetupReply::Reject { target_tag, reason },
                )
                .await;
                return Ok(());
            }
            Err(e) => {
                let _ = write_stream_reply(
                    &mut stream,
                    &StreamSetupReply::Reject {
                        target_tag,
                        reason: e.to_string(),
                    },
                )
                .await;
                return Ok(());
            }
        };

        let enforcer = GrantEnforcer::new(grant);
        let Ok(permit) = enforcer.try_acquire_stream() else {
            let _ = write_stream_reply(
                &mut stream,
                &StreamSetupReply::Reject {
                    target_tag,
                    reason: "concurrent stream limit exceeded".into(),
                },
            )
            .await;
            return Ok(());
        };
        enforcer.spawn_revocation_watcher(
            scope.access().revocations(),
            scope.id().clone(),
            remote_peer,
            Some(req.endpoint.clone()),
        );

        let ttl_millis = grant
            .expires_at
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(u64::MAX as u128) as u64;
        let resp_bytes = E2eHandshakeResp {
            granted_ttl_millis: ttl_millis,
        }
        .encode();
        let (keys, msg2) = verified.respond(&resp_bytes)?;

        write_stream_reply(
            &mut stream,
            &StreamSetupReply::Accept { target_tag, msg2 },
        )
        .await?;

        let conf_stream = ConfluenceStream::spawn_new(
            stream,
            keys,
            remote_peer,
            scope.id().clone(),
            req.endpoint.clone(),
            enforcer,
            Some(permit),
            Some(Arc::clone(scope.access())),
            Some(unpublish_rx),
        );

        let _ = ep_tx
            .send(InboundStream {
                remote_peer,
                scope: scope.id().clone(),
                endpoint: req.endpoint,
                stream: conf_stream,
            })
            .await;
        Ok(())
    }
}
