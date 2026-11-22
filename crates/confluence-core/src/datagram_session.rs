use crate::error::{CoreError, Result};
use crate::seams::access::{AccessControl, AccessRequest, Action, Decision, Grant};
use crate::seams::channel::DatagramChannel;
use crate::seams::edge::DatagramSession;
use crate::security::grant::GrantEnforcer;
use crate::security::noise::{DatagramSessionCipher, TransportKeys, DATAGRAM_WIRE_OVERHEAD_BYTES};
use crate::types::{
    ChannelAddr, ChannelId, CircuitId, EndpointName, OpaqueCredential, PeerId, Plane, ScopeId,
};
use crate::wire::{DataMsgType, InBandRenewReqPayload, InBandRenewRespPayload};
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, watch};

/// End-to-end authenticated Datagram Plane session (`1 Noise_IK session per (A, B, scope, endpoint)`).
///
/// Steady-state packets carry a flat 4-byte `HopLabel` + 8-byte nonce + AEAD(1B type || payload) + 16B tag
/// (**29 bytes** constant overhead regardless of hop count, zero extra endpoint header bytes).
pub struct ConfluenceDatagramSession {
    circuit_id: CircuitId,
    in_label: u32,
    out_label: u32,
    remote_peer: PeerId,
    scope: ScopeId,
    endpoint: EndpointName,
    cipher: DatagramSessionCipher,
    enforcer: Arc<GrantEnforcer>,
    carrier: Arc<dyn DatagramChannel>,
    next_hop_addr: ChannelAddr,
    max_app_payload: usize,
    inbound_tx: mpsc::Sender<Bytes>,
    inbound_rx: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    responder_access: Option<Arc<dyn AccessControl>>,
    pending_renews: DashMap<u64, oneshot::Sender<Result<Duration>>>,
    next_req_id: AtomicU64,
    closed_flag: AtomicBool,
    closed_tx: watch::Sender<Option<String>>,
    closed_rx: watch::Receiver<Option<String>>,
    cleanup_table: Arc<DashMap<u32, Arc<ConfluenceDatagramSession>>>,
}

impl ConfluenceDatagramSession {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        circuit_id: CircuitId,
        in_label: u32,
        out_label: u32,
        keys: TransportKeys,
        remote_peer: PeerId,
        scope: ScopeId,
        endpoint: EndpointName,
        enforcer: Arc<GrantEnforcer>,
        carrier: Arc<dyn DatagramChannel>,
        next_hop_addr: ChannelAddr,
        responder_access: Option<Arc<dyn AccessControl>>,
        unpublish_rx: Option<watch::Receiver<bool>>,
        cleanup_table: Arc<DashMap<u32, Arc<ConfluenceDatagramSession>>>,
    ) -> Arc<Self> {
        let mtu = carrier.caps().max_payload_bytes.unwrap_or(1200);
        let max_app_payload = mtu.saturating_sub(DATAGRAM_WIRE_OVERHEAD_BYTES);
        let (inbound_tx, inbound_rx) = mpsc::channel(512);
        let (closed_tx, closed_rx) = watch::channel(None);

        let session = Arc::new(Self {
            circuit_id,
            in_label,
            out_label,
            remote_peer,
            scope,
            endpoint,
            cipher: DatagramSessionCipher::new(keys),
            enforcer: Arc::clone(&enforcer),
            carrier,
            next_hop_addr,
            max_app_payload,
            inbound_tx,
            inbound_rx: tokio::sync::Mutex::new(inbound_rx),
            responder_access,
            pending_renews: DashMap::new(),
            next_req_id: AtomicU64::new(1),
            closed_flag: AtomicBool::new(false),
            closed_tx,
            closed_rx,
            cleanup_table,
        });

        // Immediately tear down session when Grant is revoked or endpoint is unpublished.
        let weak_rev = Arc::downgrade(&session);
        let mut enf_watch = enforcer.closed_watch();
        tokio::spawn(async move {
            if enf_watch.wait_for(|&c| c).await.is_ok() {
                if let Some(s) = weak_rev.upgrade() {
                    s.terminate_locally("grant revoked".into());
                }
            }
        });

        if let Some(mut up_rx) = unpublish_rx {
            let weak_up = Arc::downgrade(&session);
            tokio::spawn(async move {
                if up_rx.wait_for(|&u| u).await.is_ok() {
                    if let Some(s) = weak_up.upgrade() {
                        s.enforcer.revoke();
                        s.terminate_locally("endpoint unpublished".into());
                    }
                }
            });
        }

        session
    }

    pub fn circuit_id(&self) -> CircuitId {
        self.circuit_id
    }

    pub fn in_label(&self) -> u32 {
        self.in_label
    }

    pub fn max_payload_bytes(&self) -> usize {
        self.max_app_payload
    }

    pub(crate) fn carrier_id(&self) -> &ChannelId {
        self.carrier.id()
    }

    pub(crate) fn next_hop_addr(&self) -> &ChannelAddr {
        &self.next_hop_addr
    }

    pub(crate) fn terminate_locally(&self, reason: String) {
        if !self.closed_flag.swap(true, Ordering::AcqRel) {
            self.cleanup_table.remove(&self.in_label);
            let _ = self.closed_tx.send(Some(reason));
            self.pending_renews.clear();
        }
    }

    /// Processes an inbound wire datagram (`packet_after_label` starts right after the 4B `HopLabel`).
    pub(crate) async fn handle_inbound_packet(self: &Arc<Self>, packet_after_label: &[u8]) {
        if self.closed_flag.load(Ordering::Acquire) {
            return;
        }
        // Verify AEAD & sliding replay window first (pre-enforcement authenticity!).
        let Ok((msg_ty_raw, pt)) = self.cipher.open_packet(packet_after_label) else {
            return;
        };
        let Ok(msg_ty) = DataMsgType::from_u8(msg_ty_raw) else {
            return;
        };

        match msg_ty {
            DataMsgType::Data => {
                if self
                    .enforcer
                    .check_and_record_datagram(DATAGRAM_WIRE_OVERHEAD_BYTES + pt.len())
                    .is_err()
                {
                    if self.enforcer.is_revoked() {
                        self.terminate_locally("grant revoked".into());
                    }
                    return;
                }
                let _ = self.inbound_tx.try_send(Bytes::from(pt));
            }
            DataMsgType::InBandRenewReq => {
                let Ok(req) = InBandRenewReqPayload::decode(&pt) else {
                    return;
                };
                let resp = if let Some(ref ac) = self.responder_access {
                    let ac_req = AccessRequest {
                        scope: self.scope.clone(),
                        peer: self.remote_peer,
                        credential: req.credential,
                        action: Action::RenewGrant {
                            target_action: Box::new(Action::OpenEndpoint {
                                endpoint: self.endpoint.clone(),
                                plane: Plane::Datagram,
                            }),
                        },
                    };
                    match ac.evaluate(ac_req).await {
                        Ok(Decision::Allow(new_grant)) => {
                            let ttl_millis = new_grant
                                .expires_at
                                .saturating_duration_since(Instant::now())
                                .as_millis()
                                .min(u64::MAX as u128)
                                as u64;
                            self.enforcer.update_grant(new_grant);
                            InBandRenewRespPayload::Accepted {
                                req_id: req.req_id,
                                ttl_millis,
                            }
                        }
                        Ok(Decision::Deny { reason }) => InBandRenewRespPayload::Denied {
                            req_id: req.req_id,
                            reason,
                        },
                        Err(e) => InBandRenewRespPayload::Denied {
                            req_id: req.req_id,
                            reason: e.to_string(),
                        },
                    }
                } else {
                    InBandRenewRespPayload::Denied {
                        req_id: req.req_id,
                        reason: "renewal not supported on initiator".into(),
                    }
                };
                if let Ok(pkt) = self.cipher.seal_packet(
                    self.out_label,
                    DataMsgType::InBandRenewResp as u8,
                    &resp.encode(),
                ) {
                    let _ = self.carrier.send_to(&self.next_hop_addr, &pkt).await;
                }
            }
            DataMsgType::InBandRenewResp => {
                if let Ok(resp) = InBandRenewRespPayload::decode(&pt) {
                    match resp {
                        InBandRenewRespPayload::Accepted { req_id, ttl_millis } => {
                            if let Some((_, waiter)) = self.pending_renews.remove(&req_id) {
                                let _ = waiter.send(Ok(Duration::from_millis(ttl_millis)));
                            }
                        }
                        InBandRenewRespPayload::Denied { req_id, reason } => {
                            if let Some((_, waiter)) = self.pending_renews.remove(&req_id) {
                                let _ = waiter.send(Err(CoreError::AccessDenied(reason)));
                            }
                        }
                    }
                }
            }
            DataMsgType::Close => {
                self.terminate_locally("closed by remote peer".into());
            }
        }
    }
}

impl std::fmt::Debug for ConfluenceDatagramSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfluenceDatagramSession")
            .field("in_label", &self.in_label)
            .field("out_label", &self.out_label)
            .field("remote_peer", &self.remote_peer)
            .field("scope", &self.scope)
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl DatagramSession for ConfluenceDatagramSession {
    fn remote_peer(&self) -> PeerId {
        self.remote_peer
    }

    fn scope(&self) -> &ScopeId {
        &self.scope
    }

    fn endpoint(&self) -> &EndpointName {
        &self.endpoint
    }

    async fn send(&self, payload: &[u8]) -> Result<()> {
        if let Some(ref reason) = *self.closed_rx.borrow() {
            if self.enforcer.is_revoked() {
                return Err(CoreError::GrantRevoked);
            }
            return Err(CoreError::Closed(reason.clone()));
        }
        if payload.len() > self.max_app_payload {
            return Err(CoreError::CapabilityMismatch(format!(
                "datagram payload {} exceeds max session payload {}",
                payload.len(),
                self.max_app_payload
            )));
        }
        self.enforcer
            .check_and_record_datagram(DATAGRAM_WIRE_OVERHEAD_BYTES + payload.len())?;

        let pkt = self
            .cipher
            .seal_packet(self.out_label, DataMsgType::Data as u8, payload)?;
        if let Err(e) = self.carrier.send_to(&self.next_hop_addr, &pkt).await {
            if matches!(e, CoreError::ChannelUnhealthy(_) | CoreError::Closed(_)) {
                self.terminate_locally(e.to_string());
            }
            return Err(e);
        }
        Ok(())
    }

    async fn recv(&self) -> Result<Bytes> {
        if self.enforcer.is_revoked() {
            return Err(CoreError::GrantRevoked);
        }
        self.enforcer.check_liveness(Instant::now())?;
        if let Some(ref reason) = *self.closed_rx.borrow() {
            return Err(CoreError::Closed(reason.clone()));
        }

        let mut closed_rx = self.closed_rx.clone();
        let mut guard = self.inbound_rx.lock().await;
        tokio::select! {
            _ = closed_rx.changed() => {
                if self.enforcer.is_revoked() {
                    return Err(CoreError::GrantRevoked);
                }
                let reason = closed_rx.borrow().clone().unwrap_or_else(|| "session closed".into());
                Err(CoreError::Closed(reason))
            }
            msg = guard.recv() => {
                let bytes = msg.ok_or_else(|| CoreError::Closed("session closed".into()))?;
                self.enforcer.check_liveness(Instant::now())?;
                Ok(bytes)
            }
        }
    }

    async fn renew(&self, credential: Option<OpaqueCredential>) -> Result<()> {
        if self.closed_flag.load(Ordering::Acquire) {
            return Err(CoreError::Closed("session closed".into()));
        }
        let req_id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending_renews.insert(req_id, tx);

        let payload = InBandRenewReqPayload { req_id, credential }.encode();
        let pkt =
            self.cipher
                .seal_packet(self.out_label, DataMsgType::InBandRenewReq as u8, &payload)?;
        if let Err(e) = self.carrier.send_to(&self.next_hop_addr, &pkt).await {
            self.pending_renews.remove(&req_id);
            return Err(e);
        }

        let ttl = tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .map_err(|_| {
                self.pending_renews.remove(&req_id);
                CoreError::Timeout
            })?
            .map_err(|_| CoreError::Closed("session closed during renewal".into()))??;

        self.enforcer.update_grant(Grant::with_ttl(ttl));
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        if let Ok(pkt) = self
            .cipher
            .seal_packet(self.out_label, DataMsgType::Close as u8, b"")
        {
            let _ = self.carrier.send_to(&self.next_hop_addr, &pkt).await;
        }
        self.terminate_locally("closed locally".into());
        Ok(())
    }
}
