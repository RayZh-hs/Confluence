use crate::datagram_session::ConfluenceDatagramSession;
use crate::error::{CoreError, Result};
use crate::scope::{PublishedDatagramEndpoint, PublishedStreamEndpoint, TrustScope};
use crate::seams::access::{AccessRequest, Action, Decision, Grant};
use crate::seams::channel::{
    BoxedAsyncStream, BoxedDatagramForwardHandle, DatagramChannel, DatagramForwardChannel,
    SetupOutcome, StreamChannel, StreamForwardChannel,
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
    append_stream_segment, pack_chain_segments, pop_chain_segment, read_stream_reply,
    read_stream_segment, write_stream_reply, DgramCtrlPacket, E2eHandshakeReq, E2eHandshakeResp,
    StreamSegmentMode, StreamSetupReply,
};
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};

/// Minimum MTU required on a Datagram Plane carrier.
pub const MIN_DATAGRAM_MTU: usize = 512;

enum PendingDgramOutcome {
    Accept { responder_label: u32, msg2: Vec<u8> },
    Challenge { target_tag: TargetTag, challenge: Vec<u8> },
    Reject { target_tag: TargetTag, reason: String },
}

#[derive(Clone)]
enum SwitchTarget {
    /// Upstream -> Downstream: transmit via the channel plugin's Grant-enforced handle.
    ForwardHandle(BoxedDatagramForwardHandle),
    /// Downstream -> Upstream: account against the circuit's Grant and transmit back upstream.
    ReturnLink {
        carrier: Arc<dyn DatagramChannel>,
        addr: ChannelAddr,
        handle: BoxedDatagramForwardHandle,
    },
}

#[derive(Clone)]
struct LabelSwitchEntry {
    out_label: u32,
    pair_label: u32,
    target: SwitchTarget,
}

struct PendingHopCircuit {
    up_label: u32,
    down_label: u32,
    upstream_carrier: Arc<dyn DatagramChannel>,
    upstream_addr: ChannelAddr,
    upstream_return_label: u32,
    target_tag: TargetTag,
    handle: BoxedDatagramForwardHandle,
}

struct InstalledHopCircuit {
    upstream_carrier: Arc<dyn DatagramChannel>,
    upstream_addr: ChannelAddr,
    target_tag: TargetTag,
    handle: BoxedDatagramForwardHandle,
}

/// A self-contained Confluence Node instance.
///
/// Implements the Two-Plane E2E Engine and the Blind Single-Pass Multi-Hop Path Engine:
/// - Zero application protocol parsing (Cleanroom Invariant #1).
/// - Strict Datagram vs. Stream plane separation (Cleanroom Invariant #2).
/// - Relay-agnostic, hop-ACL-agnostic, hop-crypto-agnostic Path Engine (Cleanroom Invariants #3, #5, #6).
pub struct Node {
    path_source: Arc<dyn PathSource>,
    scopes_by_id: DashMap<ScopeId, Arc<TrustScope>>,
    scopes_by_tag: DashMap<TargetTag, Arc<TrustScope>>,
    dgram_carriers: DashMap<ChannelId, Arc<dyn DatagramChannel>>,
    stream_carriers: DashMap<ChannelId, Arc<dyn StreamChannel>>,
    dgram_fwd_channels: DashMap<TargetTag, Arc<dyn DatagramForwardChannel>>,
    stream_fwd_channels: DashMap<TargetTag, Arc<dyn StreamForwardChannel>>,
    dgram_sessions: Arc<DashMap<u32, Arc<ConfluenceDatagramSession>>>,
    dgram_label_switches: Arc<DashMap<u32, LabelSwitchEntry>>,
    pending_hop_circuits: Arc<DashMap<CircuitId, PendingHopCircuit>>,
    installed_hop_circuits: Arc<DashMap<CircuitId, InstalledHopCircuit>>,
    pending_dgram_setups: DashMap<CircuitId, oneshot::Sender<PendingDgramOutcome>>,
    pending_ctrl_reqs: DashMap<u64, oneshot::Sender<Vec<u8>>>,
    pending_circuit_renews: DashMap<(CircuitId, TargetTag), oneshot::Sender<Vec<u8>>>,
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
            dgram_label_switches: Arc::new(DashMap::new()),
            pending_hop_circuits: Arc::new(DashMap::new()),
            installed_hop_circuits: Arc::new(DashMap::new()),
            pending_dgram_setups: DashMap::new(),
            pending_ctrl_reqs: DashMap::new(),
            pending_circuit_renews: DashMap::new(),
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
    pub fn attach_datagram_channel(
        self: &Arc<Self>,
        carrier: Arc<dyn DatagramChannel>,
    ) -> Result<()> {
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
        self.dgram_carriers
            .insert(cid.clone(), Arc::clone(&carrier));

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
                        node.dispatch_inbound_datagram(&carrier, src_addr, pkt)
                            .await;
                    }
                    Err(e) => {
                        // Carrier failed or closed -> tear down bound E2E sessions & hop circuits honestly!
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

                        let dead_labels: Vec<(u32, u32)> = node
                            .dgram_label_switches
                            .iter()
                            .filter_map(|entry| match &entry.value().target {
                                SwitchTarget::ReturnLink { carrier: c, .. } if c.id() == &cid => {
                                    Some((*entry.key(), entry.value().pair_label))
                                }
                                _ => None,
                            })
                            .collect();
                        for (l1, l2) in dead_labels {
                            node.dgram_label_switches.remove(&l1);
                            node.dgram_label_switches.remove(&l2);
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
                    continue;
                };
                let n_clone = Arc::clone(&node);
                tokio::spawn(async move {
                    let _ = n_clone
                        .handle_inbound_stream(stream, src_addr, permit)
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
    pub fn mount_stream_forward_channel(&self, fwd: Arc<dyn StreamForwardChannel>) -> Result<()> {
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

    /// Number of currently installed flat datagram label-switch entries on this Node.
    pub fn active_label_switch_count(&self) -> usize {
        self.dgram_label_switches.len()
    }

    /// Sends an opaque control request to a remote `DatagramForwardChannel` and awaits `ChannelControlResp`.
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

    /// Renews a hop channel's `DatagramForwardHandle` along an active datagram circuit.
    pub async fn send_circuit_renew(
        &self,
        carrier_id: &ChannelId,
        entry_addr: &ChannelAddr,
        circuit_id: CircuitId,
        target_tag: TargetTag,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let carrier = self.validate_datagram_carrier(carrier_id)?;
        let key = (circuit_id, target_tag);
        let (tx, rx) = oneshot::channel();
        self.pending_circuit_renews.insert(key, tx);

        let pkt = DgramCtrlPacket::CircuitRenew {
            circuit_id,
            target_tag,
            payload,
        }
        .encode()?;

        if let Err(e) = carrier.send_to(entry_addr, &pkt).await {
            self.pending_circuit_renews.remove(&key);
            return Err(e);
        }

        tokio::time::timeout(self.setup_timeout, rx)
            .await
            .map_err(|_| {
                self.pending_circuit_renews.remove(&key);
                CoreError::Timeout
            })?
            .map_err(|_| CoreError::Closed("circuit renew cancelled".into()))
    }

    /// Opens an end-to-end authenticated Stream to `endpoint` on `target_peer` within `scope` (Seam 4 Outbound).
    ///
    /// Executes **single-pass 1-RTT pipelined chain setup**: all intermediate hop segments plus
    /// the final E2E segment are sent in one burst (`0` per-hop round-trips, `1` RTT total).
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

        for attempt in 0..=path.hops.len() + 1 {
            let mut raw_stream = carrier.open(&path.entry_addr).await?;

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
                } if attempt <= path.hops.len() && !cookies.contains_key(&target_tag) => {
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
    ///
    /// Executes **single-pass 1-RTT pipelined chain setup** and installs flat 4-byte `HopLabel`
    /// switches on intermediate hops (**29 bytes** constant data-plane overhead regardless of hop count).
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

        for attempt in 0..=path.hops.len() + 1 {
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
                } if attempt <= path.hops.len() && !cookies.contains_key(&target_tag) => {
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
            if l != 0
                && !self.dgram_sessions.contains_key(&l)
                && !self.dgram_label_switches.contains_key(&l)
            {
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
        for hop in &path.hops {
            if hop.target_tag != hop.channel_pubkey.target_tag() {
                return Err(CoreError::InvalidInput(
                    "PathHop target_tag does not match channel_pubkey".into(),
                ));
            }
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
        mut pkt: Vec<u8>,
    ) {
        let label = HopLabel::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
        if !label.is_control() {
            // 1. Check local E2E datagram sessions.
            if let Some(sess) = self.dgram_sessions.get(&label.0).map(|r| Arc::clone(r.value())) {
                sess.handle_inbound_packet(&pkt[4..]).await;
                return;
            }

            // 2. Blind Flat Label Switching fast path: overwrite 4-byte HopLabel in place!
            let Some(entry) = self
                .dgram_label_switches
                .get(&label.0)
                .map(|r| r.value().clone())
            else {
                return;
            };
            pkt[..4].copy_from_slice(&entry.out_label.to_be_bytes());
            match entry.target {
                SwitchTarget::ForwardHandle(handle) => {
                    if let Err(e) = handle.send(&pkt).await {
                        if matches!(
                            e,
                            CoreError::GrantRevoked
                                | CoreError::GrantExpired
                                | CoreError::Closed(_)
                                | CoreError::ChannelUnhealthy(_)
                        ) {
                            self.dgram_label_switches.remove(&label.0);
                            self.dgram_label_switches.remove(&entry.pair_label);
                        }
                    }
                }
                SwitchTarget::ReturnLink {
                    carrier: ret_carrier,
                    addr: ret_addr,
                    handle,
                } => {
                    match handle.check_and_record_reverse(pkt.len()) {
                        Ok(()) => {
                            if let Err(e) = ret_carrier.send_to(&ret_addr, &pkt).await {
                                if matches!(e, CoreError::Closed(_) | CoreError::ChannelUnhealthy(_))
                                {
                                    self.dgram_label_switches.remove(&label.0);
                                    self.dgram_label_switches.remove(&entry.pair_label);
                                }
                            }
                        }
                        Err(
                            CoreError::GrantRevoked
                            | CoreError::GrantExpired
                            | CoreError::Closed(_),
                        ) => {
                            self.dgram_label_switches.remove(&label.0);
                            self.dgram_label_switches.remove(&entry.pair_label);
                        }
                        Err(_) => {}
                    }
                }
            }
            return;
        }

        // Control packet (`HopLabel(0)`) — drop malformed packets silently.
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
                } else {
                    self.handle_hop_datagram_setup(
                        carrier,
                        &src_addr,
                        circuit_id,
                        sender_return_label,
                        target_tag,
                        &seg_payload,
                        &remaining_tail,
                    )
                    .await;
                }
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
                } else if let Some((_, hop)) = self.pending_hop_circuits.remove(&circuit_id) {
                    self.install_hop_datagram_circuit(circuit_id, hop, responder_label, msg2)
                        .await;
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
                } else if let Some((_, hop)) = self.pending_hop_circuits.remove(&circuit_id) {
                    if let Ok(raw) = (DgramCtrlPacket::ChainSetupChallenge {
                        circuit_id,
                        target_tag,
                        challenge,
                    })
                    .encode()
                    {
                        let _ = hop.upstream_carrier.send_to(&hop.upstream_addr, &raw).await;
                    }
                }
            }
            DgramCtrlPacket::ChainSetupReject {
                circuit_id,
                target_tag,
                reason,
            } => {
                if let Some((_, waiter)) = self.pending_dgram_setups.remove(&circuit_id) {
                    let _ = waiter.send(PendingDgramOutcome::Reject { target_tag, reason });
                } else if let Some((_, hop)) = self.pending_hop_circuits.remove(&circuit_id) {
                    if let Ok(raw) = (DgramCtrlPacket::ChainSetupReject {
                        circuit_id,
                        target_tag,
                        reason,
                    })
                    .encode()
                    {
                        let _ = hop.upstream_carrier.send_to(&hop.upstream_addr, &raw).await;
                    }
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
                        fwd.handle_control(Arc::clone(carrier), &src_addr, &payload)
                            .await
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
            DgramCtrlPacket::CircuitRenew {
                circuit_id,
                target_tag,
                payload,
            } => {
                let hop_entry = self.installed_hop_circuits.get(&circuit_id).map(|e| {
                    (
                        e.target_tag,
                        Arc::clone(&e.handle),
                    )
                });
                if let Some((local_tag, handle)) = hop_entry {
                    if local_tag == target_tag {
                        if let Ok(resp_payload) = handle.renew(&payload).await {
                            if let Ok(raw) = (DgramCtrlPacket::CircuitRenewResp {
                                circuit_id,
                                target_tag,
                                payload: resp_payload,
                            })
                            .encode()
                            {
                                let _ = carrier.send_to(&src_addr, &raw).await;
                            }
                        }
                    } else if let Ok(raw) = (DgramCtrlPacket::CircuitRenew {
                        circuit_id,
                        target_tag,
                        payload,
                    })
                    .encode()
                    {
                        // Forward CircuitRenew transparently toward downstream hop!
                        let _ = handle.send(&raw).await;
                    }
                }
            }
            DgramCtrlPacket::CircuitRenewResp {
                circuit_id,
                target_tag,
                payload,
            } => {
                if let Some((_, waiter)) =
                    self.pending_circuit_renews.remove(&(circuit_id, target_tag))
                {
                    let _ = waiter.send(payload);
                } else if let Some(hop) = self.installed_hop_circuits.get(&circuit_id) {
                    let up_carrier = Arc::clone(&hop.upstream_carrier);
                    let up_addr = hop.upstream_addr.clone();
                    drop(hop);
                    if let Ok(raw) = (DgramCtrlPacket::CircuitRenewResp {
                        circuit_id,
                        target_tag,
                        payload,
                    })
                    .encode()
                    {
                        let _ = up_carrier.send_to(&up_addr, &raw).await;
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_hop_datagram_setup(
        self: &Arc<Self>,
        in_carrier: &Arc<dyn DatagramChannel>,
        src_addr: &ChannelAddr,
        circuit_id: CircuitId,
        sender_return_label: u32,
        target_tag: TargetTag,
        seg_payload: &[u8],
        remaining_tail: &[u8],
    ) {
        // Blind dispatch to mounted DatagramForwardChannel matching `target_tag`!
        let Some(fwd_chan) = self
            .dgram_fwd_channels
            .get(&target_tag)
            .map(|r| Arc::clone(r.value()))
        else {
            return;
        };

        let Ok((next_tag, next_seg, next_tail)) = pop_chain_segment(remaining_tail) else {
            return;
        };

        // Bound concurrent pending circuits against pre-auth state exhaustion.
        if self.pending_hop_circuits.len() >= 1024 {
            return;
        }

        match fwd_chan.handle_setup(src_addr, seg_payload).await {
            Ok(SetupOutcome::Accept { handle, .. }) => {
                let up_label = self.alloc_label();
                let down_label = self.alloc_label();

                let fwd_pkt = match (DgramCtrlPacket::ChainSetup {
                    circuit_id,
                    sender_return_label: down_label,
                    target_tag: next_tag,
                    seg_payload: next_seg,
                    remaining_tail: next_tail,
                })
                .encode()
                {
                    Ok(p) => p,
                    Err(_) => return,
                };

                self.pending_hop_circuits.insert(
                    circuit_id,
                    PendingHopCircuit {
                        up_label,
                        down_label,
                        upstream_carrier: Arc::clone(in_carrier),
                        upstream_addr: src_addr.clone(),
                        upstream_return_label: sender_return_label,
                        target_tag,
                        handle: Arc::clone(&handle),
                    },
                );

                // Automatic pending circuit expiry if downstream never responds within setup_timeout.
                let pending_map = Arc::clone(&self.pending_hop_circuits);
                let ttl = self.setup_timeout;
                tokio::spawn(async move {
                    tokio::time::sleep(ttl).await;
                    pending_map.remove(&circuit_id);
                });

                if let Err(e) = handle.send(&fwd_pkt).await {
                    self.pending_hop_circuits.remove(&circuit_id);
                    if let Ok(raw) = (DgramCtrlPacket::ChainSetupReject {
                        circuit_id,
                        target_tag,
                        reason: e.to_string(),
                    })
                    .encode()
                    {
                        let _ = in_carrier.send_to(src_addr, &raw).await;
                    }
                }
            }
            Ok(SetupOutcome::Challenge(challenge)) => {
                if let Ok(raw) = (DgramCtrlPacket::ChainSetupChallenge {
                    circuit_id,
                    target_tag,
                    challenge,
                })
                .encode()
                {
                    let _ = in_carrier.send_to(src_addr, &raw).await;
                }
            }
            Ok(SetupOutcome::Reject(reason)) => {
                if let Ok(raw) = (DgramCtrlPacket::ChainSetupReject {
                    circuit_id,
                    target_tag,
                    reason,
                })
                .encode()
                {
                    let _ = in_carrier.send_to(src_addr, &raw).await;
                }
            }
            Err(e) => {
                if let Ok(raw) = (DgramCtrlPacket::ChainSetupReject {
                    circuit_id,
                    target_tag,
                    reason: e.to_string(),
                })
                .encode()
                {
                    let _ = in_carrier.send_to(src_addr, &raw).await;
                }
            }
        }
    }

    async fn install_hop_datagram_circuit(
        &self,
        circuit_id: CircuitId,
        hop: PendingHopCircuit,
        downstream_label: u32,
        msg2: Vec<u8>,
    ) {
        self.dgram_label_switches.insert(
            hop.up_label,
            LabelSwitchEntry {
                out_label: downstream_label,
                pair_label: hop.down_label,
                target: SwitchTarget::ForwardHandle(Arc::clone(&hop.handle)),
            },
        );
        self.dgram_label_switches.insert(
            hop.down_label,
            LabelSwitchEntry {
                out_label: hop.upstream_return_label,
                pair_label: hop.up_label,
                target: SwitchTarget::ReturnLink {
                    carrier: Arc::clone(&hop.upstream_carrier),
                    addr: hop.upstream_addr.clone(),
                    handle: Arc::clone(&hop.handle),
                },
            },
        );
        self.installed_hop_circuits.insert(
            circuit_id,
            InstalledHopCircuit {
                upstream_carrier: Arc::clone(&hop.upstream_carrier),
                upstream_addr: hop.upstream_addr.clone(),
                target_tag: hop.target_tag,
                handle: Arc::clone(&hop.handle),
            },
        );

        // Immediate revocation teardown: purge both label switches as soon as handle closes!
        let mut closed_rx = hop.handle.closed();
        let switches = Arc::clone(&self.dgram_label_switches);
        let circuits = Arc::clone(&self.installed_hop_circuits);
        let up_l = hop.up_label;
        let down_l = hop.down_label;
        tokio::spawn(async move {
            let _ = closed_rx.wait_for(|&c| c).await;
            switches.remove(&up_l);
            switches.remove(&down_l);
            circuits.remove(&circuit_id);
        });

        if let Ok(raw) = (DgramCtrlPacket::ChainSetupResp {
            circuit_id,
            responder_label: hop.up_label,
            msg2,
        })
        .encode()
        {
            let _ = hop.upstream_carrier.send_to(&hop.upstream_addr, &raw).await;
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
            return;
        };

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

        let Ok(verified) =
            VerifiedInitiation::read_msg1(scope.keypair(), DEFAULT_PROLOGUE, inner_msg1)
        else {
            return;
        };
        let remote_peer = verified.initiator_peer();

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
        preauth_permit: OwnedSemaphorePermit,
    ) -> Result<()> {
        let (mode, target_tag, envelope) = tokio::time::timeout(
            self.setup_timeout,
            read_stream_segment(&mut stream),
        )
        .await
        .map_err(|_| CoreError::Timeout)??;

        match mode {
            StreamSegmentMode::FinalE2e => {
                let res = tokio::time::timeout(
                    self.setup_timeout,
                    self.handle_final_stream_setup(stream, &src_addr, target_tag, &envelope),
                )
                .await
                .map_err(|_| CoreError::Timeout)?;
                drop(preauth_permit);
                res
            }
            StreamSegmentMode::ChannelControl => {
                drop(preauth_permit);
                if let Some(fwd) = self
                    .stream_fwd_channels
                    .get(&target_tag)
                    .map(|r| Arc::clone(r.value()))
                {
                    fwd.handle_control_stream(stream, &src_addr, &envelope)
                        .await
                } else {
                    Ok(())
                }
            }
            StreamSegmentMode::ForwardHop => {
                // Blind Single-Pass Stream Splice: dispatch opaque hop segment to target channel plugin!
                let Some(fwd) = self
                    .stream_fwd_channels
                    .get(&target_tag)
                    .map(|r| Arc::clone(r.value()))
                else {
                    return Ok(());
                };

                let setup_res = tokio::time::timeout(
                    self.setup_timeout,
                    fwd.handle_setup(&src_addr, &envelope),
                )
                .await
                .map_err(|_| CoreError::Timeout)?;

                drop(preauth_permit);

                match setup_res {
                    Ok(SetupOutcome::Accept {
                        handle: mut downstream,
                        ..
                    }) => {
                        // Immediately splice remaining pipelined setup segments & subsequent E2E
                        // AEAD frames bidirectionally with zero per-hop round-trip!
                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut downstream).await;
                        Ok(())
                    }
                    Ok(SetupOutcome::Challenge(challenge)) => {
                        let _ = write_stream_reply(
                            &mut stream,
                            &StreamSetupReply::Challenge {
                                target_tag,
                                challenge,
                            },
                        )
                        .await;
                        Ok(())
                    }
                    Ok(SetupOutcome::Reject(reason)) => {
                        let _ = write_stream_reply(
                            &mut stream,
                            &StreamSetupReply::Reject { target_tag, reason },
                        )
                        .await;
                        Ok(())
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
                        Ok(())
                    }
                }
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
