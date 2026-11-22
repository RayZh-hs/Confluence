use async_trait::async_trait;
use confluence_core::seams::access::{AccessControl, AccessRequest, Action, Decision};
use confluence_core::seams::channel::{
    BoxedDatagramForwardHandle, ChannelCaps, DatagramChannel, DatagramForwardChannel,
    DatagramForwardHandle, SetupOutcome,
};
use confluence_core::security::cookie::{seal_handshake_envelope, CookieProtector, EnvelopeCheck};
use confluence_core::security::grant::GrantEnforcer;
use confluence_core::security::noise::{InitiatorHandshake, VerifiedInitiation, DEFAULT_PROLOGUE};
use confluence_core::security::replay::{Tai64nGenerator, Tai64nReplayWindow};
use confluence_core::wire::{E2eHandshakeResp, HopHandshakeReq};
use confluence_core::{
    ChannelAddr, ChannelId, CoreError, Node, OpaqueCredential, PeerId, Plane, Result, ScopeId,
    StaticKeypair, TargetTag,
};
use dashmap::DashMap;
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

struct DatagramSlot {
    ingress: Arc<dyn DatagramChannel>,
    peer_addr: RwLock<ChannelAddr>,
    enforcer: Arc<GrantEnforcer>,
}

/// Passive Relay channel plugin on the Datagram Plane (mounted on Relay Node `R`).
///
/// - Zero outbound dialing: never sends to arbitrary network addresses; `next_addr` in setup
///   must be the hex `PeerId` of a peer holding an active, authenticated inbound slot.
/// - Works uniformly for 1-hop `A -> R <- B` and multi-hop `A -> H1 -> R <- B` with direct `A <-> R` auth.
pub struct RelayDatagramChannel {
    scope: ScopeId,
    keypair: StaticKeypair,
    mtu: usize,
    access: Arc<dyn AccessControl>,
    cookie_protector: Arc<CookieProtector>,
    replay_window: Arc<Tai64nReplayWindow>,
    slots: Arc<DashMap<PeerId, Arc<DatagramSlot>>>,
}

impl RelayDatagramChannel {
    pub fn new(
        scope: ScopeId,
        keypair: StaticKeypair,
        mtu: usize,
        access: Arc<dyn AccessControl>,
    ) -> Arc<Self> {
        let peer_id = keypair.peer_id();
        Arc::new(Self {
            scope,
            keypair,
            mtu,
            access,
            cookie_protector: Arc::new(CookieProtector::new(peer_id, Duration::from_secs(120))),
            replay_window: Arc::new(Tai64nReplayWindow::default()),
            slots: Arc::new(DashMap::new()),
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.keypair.peer_id()
    }

    pub fn cookie_protector(&self) -> &CookieProtector {
        &self.cookie_protector
    }

    pub fn active_slot_count(&self) -> usize {
        self.slots.len()
    }
}

struct RelayDatagramHandle {
    slot: Arc<DatagramSlot>,
    target_slot_peer: PeerId,
    originator_peer: PeerId,
    scope: ScopeId,
    keypair: StaticKeypair,
    cookie_protector: Arc<CookieProtector>,
    replay_window: Arc<Tai64nReplayWindow>,
    access: Arc<dyn AccessControl>,
    connect_enforcer: Arc<GrantEnforcer>,
    merged_closed_rx: watch::Receiver<bool>,
}

impl RelayDatagramHandle {
    #[allow(clippy::too_many_arguments)]
    fn new(
        slot: Arc<DatagramSlot>,
        target_slot_peer: PeerId,
        originator_peer: PeerId,
        scope: ScopeId,
        keypair: StaticKeypair,
        cookie_protector: Arc<CookieProtector>,
        replay_window: Arc<Tai64nReplayWindow>,
        access: Arc<dyn AccessControl>,
        connect_enforcer: Arc<GrantEnforcer>,
    ) -> Arc<Self> {
        let (tx, rx) = watch::channel(false);
        let mut c_rx = connect_enforcer.closed_watch();
        let mut s_rx = slot.enforcer.closed_watch();
        tokio::spawn(async move {
            tokio::select! {
                _ = c_rx.wait_for(|&c| c) => { let _ = tx.send(true); }
                _ = s_rx.wait_for(|&c| c) => { let _ = tx.send(true); }
            }
        });
        Arc::new(Self {
            slot,
            target_slot_peer,
            originator_peer,
            scope,
            keypair,
            cookie_protector,
            replay_window,
            access,
            connect_enforcer,
            merged_closed_rx: rx,
        })
    }
}

#[async_trait]
impl DatagramForwardHandle for RelayDatagramHandle {
    async fn send(&self, packet: &[u8]) -> Result<()> {
        self.connect_enforcer
            .check_and_record_datagram(packet.len())?;
        self.slot.enforcer.check_and_record_datagram(packet.len())?;
        let dst = self.slot.peer_addr.read().clone();
        self.slot.ingress.send_to(&dst, packet).await
    }

    fn check_and_record_reverse(&self, byte_len: usize) -> Result<()> {
        self.connect_enforcer.check_and_record_datagram(byte_len)?;
        self.slot.enforcer.check_and_record_datagram(byte_len)
    }

    async fn renew(&self, renew_payload: &[u8]) -> Result<Vec<u8>> {
        let inner_msg1 = self
            .cookie_protector
            .verify_mac1_only(renew_payload)
            .ok_or(CoreError::AuthFailed)?;
        let verified = VerifiedInitiation::read_msg1(&self.keypair, DEFAULT_PROLOGUE, inner_msg1)?;
        if verified.initiator_peer() != self.originator_peer {
            return Err(CoreError::AuthFailed);
        }
        let req = HopHandshakeReq::decode(verified.payload())?;
        self.replay_window
            .check_and_record(&self.originator_peer, req.timestamp)?;

        let ac_req = AccessRequest {
            scope: self.scope.clone(),
            peer: self.originator_peer,
            credential: req.credential,
            action: Action::RenewGrant {
                target_action: Box::new(Action::ChannelCustom {
                    kind: "relay_connect".into(),
                    target: self.target_slot_peer.to_string(),
                    plane: Plane::Datagram,
                }),
            },
        };
        match self.access.evaluate(ac_req).await? {
            Decision::Allow(new_grant) => {
                let ttl_millis = new_grant
                    .expires_at
                    .saturating_duration_since(Instant::now())
                    .as_millis()
                    .min(u64::MAX as u128) as u64;
                self.connect_enforcer.update_grant(new_grant);
                let resp = E2eHandshakeResp {
                    granted_ttl_millis: ttl_millis,
                }
                .encode();
                let (_keys, msg2) = verified.respond(&resp)?;
                Ok(msg2)
            }
            Decision::Deny { reason } => Err(CoreError::AccessDenied(reason)),
        }
    }

    fn closed(&self) -> watch::Receiver<bool> {
        self.merged_closed_rx.clone()
    }
}

#[async_trait]
impl DatagramForwardChannel for RelayDatagramChannel {
    fn target_tag(&self) -> TargetTag {
        self.keypair.target_tag()
    }

    fn caps(&self) -> ChannelCaps {
        ChannelCaps {
            plane: Plane::Datagram,
            reliable_underlay: false,
            ordered_underlay: false,
            max_payload_bytes: Some(self.mtu),
        }
    }

    async fn handle_control(
        &self,
        ingress: Arc<dyn DatagramChannel>,
        source_addr: &ChannelAddr,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let inner_msg1 = match self
            .cookie_protector
            .verify_envelope(source_addr.as_bytes(), payload)
        {
            EnvelopeCheck::Verified(b) => b,
            _ => return Ok(None),
        };
        let Ok(verified) =
            VerifiedInitiation::read_msg1(&self.keypair, DEFAULT_PROLOGUE, inner_msg1)
        else {
            return Ok(None);
        };
        let registrant = verified.initiator_peer();
        let Ok(req) = HopHandshakeReq::decode(verified.payload()) else {
            return Ok(None);
        };
        if req.plane != Plane::Datagram
            || self
                .replay_window
                .check_and_record(&registrant, req.timestamp)
                .is_err()
        {
            return Ok(None);
        }

        let ac_req = AccessRequest {
            scope: self.scope.clone(),
            peer: registrant,
            credential: req.credential,
            action: Action::ChannelCustom {
                kind: "relay_register".into(),
                target: registrant.to_string(),
                plane: Plane::Datagram,
            },
        };
        let grant = match self.access.evaluate(ac_req).await {
            Ok(Decision::Allow(g)) => g,
            _ => return Ok(None),
        };

        let ttl_millis = grant
            .expires_at
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(u64::MAX as u128) as u64;

        if let Some(existing) = self.slots.get(&registrant) {
            *existing.peer_addr.write() = source_addr.clone();
            existing.enforcer.update_grant(grant);
        } else {
            let enforcer = GrantEnforcer::new(grant);
            enforcer.spawn_revocation_watcher(
                self.access.revocations(),
                self.scope.clone(),
                registrant,
                None,
            );
            let slot = Arc::new(DatagramSlot {
                ingress,
                peer_addr: RwLock::new(source_addr.clone()),
                enforcer: Arc::clone(&enforcer),
            });
            self.slots.insert(registrant, slot);

            let slots_map = Arc::clone(&self.slots);
            let mut closed_rx = enforcer.closed_watch();
            tokio::spawn(async move {
                let _ = closed_rx.wait_for(|&c| c).await;
                slots_map.remove(&registrant);
            });
        }

        let resp = E2eHandshakeResp {
            granted_ttl_millis: ttl_millis,
        }
        .encode();
        let (_keys, msg2) = verified.respond(&resp)?;
        Ok(Some(msg2))
    }

    async fn handle_setup(
        &self,
        source_addr: &ChannelAddr,
        setup_payload: &[u8],
    ) -> Result<SetupOutcome<BoxedDatagramForwardHandle>> {
        let inner_msg1 = match self
            .cookie_protector
            .verify_envelope(source_addr.as_bytes(), setup_payload)
        {
            EnvelopeCheck::Verified(b) => b,
            EnvelopeCheck::Challenge(ch) => return Ok(SetupOutcome::Challenge(ch)),
            EnvelopeCheck::Drop => return Ok(SetupOutcome::Reject("invalid envelope".into())),
        };

        let verified =
            match VerifiedInitiation::read_msg1(&self.keypair, DEFAULT_PROLOGUE, inner_msg1) {
                Ok(v) => v,
                Err(_) => return Ok(SetupOutcome::Reject("relay authentication failed".into())),
            };
        let originator_peer = verified.initiator_peer();

        let req = match HopHandshakeReq::decode(verified.payload()) {
            Ok(r) if r.plane == Plane::Datagram => r,
            _ => return Ok(SetupOutcome::Reject("invalid relay setup request".into())),
        };

        if self
            .replay_window
            .check_and_record(&originator_peer, req.timestamp)
            .is_err()
        {
            return Ok(SetupOutcome::Reject("relay timestamp replay".into()));
        }

        // `next_addr` MUST be a registered PeerId slot — never an outbound IP:port!
        let Ok(target_slot_peer) = req.next_addr.as_str().parse::<PeerId>() else {
            return Ok(SetupOutcome::Reject(
                "passive relay target must be a registered PeerId slot".into(),
            ));
        };

        let ac_req = AccessRequest {
            scope: self.scope.clone(),
            peer: originator_peer,
            credential: req.credential,
            action: Action::ChannelCustom {
                kind: "relay_connect".into(),
                target: target_slot_peer.to_string(),
                plane: Plane::Datagram,
            },
        };
        let connect_grant = match self.access.evaluate(ac_req).await {
            Ok(Decision::Allow(g)) => g,
            Ok(Decision::Deny { reason }) => return Ok(SetupOutcome::Reject(reason)),
            Err(e) => return Ok(SetupOutcome::Reject(e.to_string())),
        };

        let Some(slot) = self
            .slots
            .get(&target_slot_peer)
            .map(|r| Arc::clone(r.value()))
        else {
            return Ok(SetupOutcome::Reject(format!(
                "peer {target_slot_peer} has no active passive relay slot"
            )));
        };
        if slot.enforcer.check_liveness(Instant::now()).is_err() {
            self.slots.remove(&target_slot_peer);
            return Ok(SetupOutcome::Reject(
                "target peer relay slot expired".into(),
            ));
        }

        let connect_enforcer = GrantEnforcer::new(connect_grant);
        connect_enforcer.spawn_revocation_watcher(
            self.access.revocations(),
            self.scope.clone(),
            originator_peer,
            None,
        );

        let handle: BoxedDatagramForwardHandle = RelayDatagramHandle::new(
            slot,
            target_slot_peer,
            originator_peer,
            self.scope.clone(),
            self.keypair.clone(),
            Arc::clone(&self.cookie_protector),
            Arc::clone(&self.replay_window),
            Arc::clone(&self.access),
            connect_enforcer,
        );
        Ok(SetupOutcome::Accept {
            handle,
            reply_hint: None,
        })
    }
}

/// Client helper used by destination Node `B` to register and refresh its passive Datagram slot on Relay `R`.
pub struct RelayDatagramClient {
    ts_gen: Tai64nGenerator,
}

impl Default for RelayDatagramClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayDatagramClient {
    pub fn new() -> Self {
        Self {
            ts_gen: Tai64nGenerator::new(),
        }
    }

    /// Performs an authenticated inbound passive slot registration from `node` (`B`) to `relay_addr` (`R`).
    pub async fn register_once(
        &self,
        node: &Arc<Node>,
        local_keypair: &StaticKeypair,
        carrier_id: &ChannelId,
        relay_addr: &ChannelAddr,
        relay_pubkey: PeerId,
        credential: Option<OpaqueCredential>,
    ) -> Result<Duration> {
        let req = HopHandshakeReq {
            timestamp: self.ts_gen.next(),
            plane: Plane::Datagram,
            next_addr: ChannelAddr::new("register")?,
            credential,
        }
        .encode();

        let (init, msg1) =
            InitiatorHandshake::initiate(local_keypair, relay_pubkey, DEFAULT_PROLOGUE, &req)?;
        let (env, _mac1) = seal_handshake_envelope(&relay_pubkey, &msg1, None)?;

        let resp_msg2 = node
            .send_datagram_channel_control(carrier_id, relay_addr, relay_pubkey.target_tag(), env)
            .await?;

        let (_keys, resp_pt) = init
            .finalize(&resp_msg2)
            .map_err(|_| CoreError::AccessDenied("relay slot registration rejected".into()))?;
        let resp = E2eHandshakeResp::decode(&resp_pt)?;
        Ok(Duration::from_millis(resp.granted_ttl_millis))
    }

    /// Spawns a background keepalive task refreshing `B`'s passive datagram slot at `interval`.
    pub fn spawn_keepalive(
        node: Arc<Node>,
        local_keypair: StaticKeypair,
        carrier_id: ChannelId,
        relay_addr: ChannelAddr,
        relay_pubkey: PeerId,
        credential: Option<OpaqueCredential>,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let client = Self::new();
        tokio::spawn(async move {
            loop {
                let _ = client
                    .register_once(
                        &node,
                        &local_keypair,
                        &carrier_id,
                        &relay_addr,
                        relay_pubkey,
                        credential.clone(),
                    )
                    .await;
                tokio::time::sleep(interval).await;
            }
        })
    }
}
