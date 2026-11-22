use async_trait::async_trait;
use confluence_core::seams::access::{AccessControl, AccessRequest, Action, Decision};
use confluence_core::seams::channel::{
    BoxedAsyncStream, ChannelCaps, ChannelHealth, SetupOutcome, StreamChannel, StreamForwardChannel,
};
use confluence_core::security::cookie::{seal_handshake_envelope, CookieProtector, EnvelopeCheck};
use confluence_core::security::grant::{GrantEnforcedStream, GrantEnforcer};
use confluence_core::security::noise::{InitiatorHandshake, VerifiedInitiation, DEFAULT_PROLOGUE};
use confluence_core::security::replay::{Tai64nGenerator, Tai64nReplayWindow};
use confluence_core::wire::{
    append_stream_segment, read_stream_reply, write_stream_reply, E2eHandshakeResp,
    HopHandshakeReq, StreamSegmentMode, StreamSetupReply,
};
use confluence_core::{
    ChannelAddr, ChannelId, CoreError, OpaqueCredential, PeerId, Plane, Result, ScopeId,
    StaticKeypair, TargetTag,
};
use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};

const RELAY_WAKE_BYTE: u8 = 0xA5;
const MAX_PARKED_STREAMS_PER_PEER: usize = 32;

struct StreamSlot {
    enforcer: Arc<GrantEnforcer>,
    parked: Mutex<VecDeque<BoxedAsyncStream>>,
}

/// Passive Relay channel plugin on the Stream Plane (mounted on Relay Node `R`).
///
/// Structurally holds **zero** `StreamChannel` reference — making outbound dialing from `R`
/// impossible at compile time! `B` parks pre-opened inbound streams via `ChannelControl`,
/// and `handle_setup` pops an already-established stream from `B`'s passive slot.
pub struct RelayStreamChannel {
    scope: ScopeId,
    keypair: StaticKeypair,
    access: Arc<dyn AccessControl>,
    cookie_protector: CookieProtector,
    replay_window: Tai64nReplayWindow,
    slots: Arc<DashMap<PeerId, Arc<StreamSlot>>>,
}

impl RelayStreamChannel {
    pub fn new(
        scope: ScopeId,
        keypair: StaticKeypair,
        access: Arc<dyn AccessControl>,
    ) -> Arc<Self> {
        let peer_id = keypair.peer_id();
        Arc::new(Self {
            scope,
            keypair,
            access,
            cookie_protector: CookieProtector::new(peer_id, Duration::from_secs(120)),
            replay_window: Tai64nReplayWindow::default(),
            slots: Arc::new(DashMap::new()),
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.keypair.peer_id()
    }

    pub fn cookie_protector(&self) -> &CookieProtector {
        &self.cookie_protector
    }

    pub fn parked_stream_count(&self, peer: &PeerId) -> usize {
        self.slots
            .get(peer)
            .map(|s| s.parked.lock().len())
            .unwrap_or(0)
    }
}

#[async_trait]
impl StreamForwardChannel for RelayStreamChannel {
    fn target_tag(&self) -> TargetTag {
        self.keypair.target_tag()
    }

    fn caps(&self) -> ChannelCaps {
        ChannelCaps {
            plane: Plane::Stream,
            reliable_underlay: true,
            ordered_underlay: true,
            max_payload_bytes: None,
        }
    }

    async fn handle_control_stream(
        &self,
        mut stream: BoxedAsyncStream,
        source_addr: &ChannelAddr,
        payload: &[u8],
    ) -> Result<()> {
        let target_tag = self.keypair.target_tag();
        let inner_msg1 = match self
            .cookie_protector
            .verify_envelope(source_addr.as_bytes(), payload)
        {
            EnvelopeCheck::Verified(b) => b,
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
            VerifiedInitiation::read_msg1(&self.keypair, DEFAULT_PROLOGUE, inner_msg1)
        else {
            return Ok(());
        };
        let registrant = verified.initiator_peer();
        let Ok(req) = HopHandshakeReq::decode(verified.payload()) else {
            return Ok(());
        };
        if req.plane != Plane::Stream
            || self
                .replay_window
                .check_and_record(&registrant, req.timestamp)
                .is_err()
        {
            return Ok(());
        }

        let ac_req = AccessRequest {
            scope: self.scope.clone(),
            peer: registrant,
            credential: req.credential,
            action: Action::ChannelCustom {
                kind: "relay_register".into(),
                target: registrant.to_string(),
                plane: Plane::Stream,
            },
        };
        let grant = match self.access.evaluate(ac_req).await {
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

        let ttl_millis = grant
            .expires_at
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(u64::MAX as u128) as u64;
        let resp = E2eHandshakeResp {
            granted_ttl_millis: ttl_millis,
        }
        .encode();
        let (_keys, msg2) = verified.respond(&resp)?;

        write_stream_reply(&mut stream, &StreamSetupReply::Accept { target_tag, msg2 }).await?;

        let slot = if let Some(existing) = self.slots.get(&registrant) {
            existing.enforcer.update_grant(grant);
            Arc::clone(existing.value())
        } else {
            let enforcer = GrantEnforcer::new(grant);
            enforcer.spawn_revocation_watcher(
                self.access.revocations(),
                self.scope.clone(),
                registrant,
                None,
            );
            let new_slot = Arc::new(StreamSlot {
                enforcer: Arc::clone(&enforcer),
                parked: Mutex::new(VecDeque::new()),
            });
            self.slots.insert(registrant, Arc::clone(&new_slot));

            let slots_map = Arc::clone(&self.slots);
            let mut closed_rx = enforcer.closed_watch();
            tokio::spawn(async move {
                let _ = closed_rx.wait_for(|&c| c).await;
                slots_map.remove(&registrant);
            });
            new_slot
        };

        let mut q = slot.parked.lock();
        if q.len() >= MAX_PARKED_STREAMS_PER_PEER {
            q.pop_front();
        }
        q.push_back(stream);
        Ok(())
    }

    async fn handle_setup(
        &self,
        source_addr: &ChannelAddr,
        setup_payload: &[u8],
    ) -> Result<SetupOutcome<BoxedAsyncStream>> {
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
            Ok(r) if r.plane == Plane::Stream => r,
            _ => return Ok(SetupOutcome::Reject("invalid relay stream setup".into())),
        };

        if self
            .replay_window
            .check_and_record(&originator_peer, req.timestamp)
            .is_err()
        {
            return Ok(SetupOutcome::Reject("relay timestamp replay".into()));
        }

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
                plane: Plane::Stream,
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
                "peer {target_slot_peer} has no registered passive stream slot"
            )));
        };
        if slot.enforcer.check_liveness(Instant::now()).is_err() {
            self.slots.remove(&target_slot_peer);
            return Ok(SetupOutcome::Reject(
                "target peer relay slot expired".into(),
            ));
        }

        let connect_enforcer = GrantEnforcer::new(connect_grant);
        let connect_permit = match connect_enforcer.try_acquire_stream() {
            Ok(p) => p,
            Err(e) => return Ok(SetupOutcome::Reject(e.to_string())),
        };
        let slot_permit = match slot.enforcer.try_acquire_stream() {
            Ok(p) => p,
            Err(e) => return Ok(SetupOutcome::Reject(e.to_string())),
        };
        connect_enforcer.spawn_revocation_watcher(
            self.access.revocations(),
            self.scope.clone(),
            originator_peer,
            None,
        );

        // Pop a healthy pre-opened stream parked by B and wake B with RELAY_WAKE_BYTE!
        loop {
            let candidate = slot.parked.lock().pop_front();
            let Some(mut parked_stream) = candidate else {
                return Ok(SetupOutcome::Reject(format!(
                    "peer {target_slot_peer} has no available parked stream"
                )));
            };
            if parked_stream.write_all(&[RELAY_WAKE_BYTE]).await.is_ok()
                && parked_stream.flush().await.is_ok()
            {
                // Enforce BOTH B's slot Grant and A's connect Grant on the spliced stream!
                let slot_guarded = GrantEnforcedStream::new(
                    parked_stream,
                    Arc::clone(&slot.enforcer),
                    Some(slot_permit),
                );
                let both_guarded: BoxedAsyncStream = Box::pin(GrantEnforcedStream::new(
                    slot_guarded,
                    connect_enforcer,
                    Some(connect_permit),
                ));
                return Ok(SetupOutcome::Accept {
                    handle: both_guarded,
                    reply_hint: None,
                });
            }
        }
    }
}

/// Composable `StreamChannel` mounted on destination Node `B` that maintains a pool of
/// outbound-dialed passive rendezvous streams to Relay `R` (`B -> R`, so `R` never dials `B`!).
///
/// Whenever `R` wakes one parked stream for an incoming connection, `RelayIngressStreamChannel`
/// yields that stream via `accept()` directly into `B`'s `Node` and immediately opens a fresh
/// replacement idle stream to `R`.
pub struct RelayIngressStreamChannel {
    id: ChannelId,
    relay_addr: ChannelAddr,
    activated_rx: tokio::sync::Mutex<mpsc::Receiver<(BoxedAsyncStream, ChannelAddr)>>,
    closed: AtomicBool,
    stop_tx: watch::Sender<bool>,
}

impl RelayIngressStreamChannel {
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_pool<S: StreamChannel>(
        id: ChannelId,
        underlay: Arc<S>,
        local_keypair: StaticKeypair,
        relay_addr: ChannelAddr,
        relay_pubkey: PeerId,
        credential: Option<OpaqueCredential>,
        pool_size: usize,
    ) -> Result<Arc<Self>> {
        let pool_size = pool_size.max(1);
        let (activated_tx, activated_rx) = mpsc::channel(128);
        let (stop_tx, stop_rx) = watch::channel(false);
        let ts_gen = Arc::new(Tai64nGenerator::new());

        // Park initial pool synchronously so `B`'s passive presence is immediately ready when returned!
        for _ in 0..pool_size {
            let parked = park_one_stream(
                &underlay,
                &local_keypair,
                &relay_addr,
                relay_pubkey,
                credential.clone(),
                &ts_gen,
            )
            .await?;

            spawn_parked_watcher(
                parked,
                Arc::clone(&underlay),
                local_keypair.clone(),
                relay_addr.clone(),
                relay_pubkey,
                credential.clone(),
                Arc::clone(&ts_gen),
                activated_tx.clone(),
                stop_rx.clone(),
            );
        }

        Ok(Arc::new(Self {
            id,
            relay_addr,
            activated_rx: tokio::sync::Mutex::new(activated_rx),
            closed: AtomicBool::new(false),
            stop_tx,
        }))
    }
}

async fn park_one_stream<S: StreamChannel>(
    underlay: &Arc<S>,
    local_keypair: &StaticKeypair,
    relay_addr: &ChannelAddr,
    relay_pubkey: PeerId,
    credential: Option<OpaqueCredential>,
    ts_gen: &Tai64nGenerator,
) -> Result<BoxedAsyncStream> {
    let mut stream = underlay.open(relay_addr).await?;
    let req = HopHandshakeReq {
        timestamp: ts_gen.next(),
        plane: Plane::Stream,
        next_addr: ChannelAddr::new("register")?,
        credential,
    }
    .encode();
    let (init, msg1) =
        InitiatorHandshake::initiate(local_keypair, relay_pubkey, DEFAULT_PROLOGUE, &req)?;
    let (env, _) = seal_handshake_envelope(&relay_pubkey, &msg1, None)?;

    let mut seg = Vec::new();
    append_stream_segment(
        &mut seg,
        StreamSegmentMode::ChannelControl,
        relay_pubkey.target_tag(),
        &env,
    )?;
    stream.write_all(&seg).await?;
    stream.flush().await?;

    match read_stream_reply(&mut stream).await? {
        StreamSetupReply::Accept { msg2, .. } => {
            let _ = init.finalize(&msg2)?;
            Ok(stream)
        }
        StreamSetupReply::Reject { reason, .. } => Err(CoreError::AccessDenied(reason)),
        StreamSetupReply::Challenge { .. } => Err(CoreError::PathSetupFailed(
            "relay stream park challenged".into(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_parked_watcher<S: StreamChannel>(
    mut stream: BoxedAsyncStream,
    underlay: Arc<S>,
    local_keypair: StaticKeypair,
    relay_addr: ChannelAddr,
    relay_pubkey: PeerId,
    credential: Option<OpaqueCredential>,
    ts_gen: Arc<Tai64nGenerator>,
    activated_tx: mpsc::Sender<(BoxedAsyncStream, ChannelAddr)>,
    mut stop_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        if *stop_rx.borrow() {
            return;
        }
        let mut wake = [0u8; 1];
        tokio::select! {
            _ = stop_rx.changed() => {}
            res = stream.read_exact(&mut wake) => {
                if res.is_ok() && wake[0] == RELAY_WAKE_BYTE {
                    // Replenish passive pool in the background immediately!
                    let u2 = Arc::clone(&underlay);
                    let kp2 = local_keypair.clone();
                    let ra2 = relay_addr.clone();
                    let cred2 = credential.clone();
                    let tg2 = Arc::clone(&ts_gen);
                    let tx2 = activated_tx.clone();
                    let srx2 = stop_rx.clone();
                    tokio::spawn(async move {
                        if !*srx2.borrow() {
                            if let Ok(next_parked) = park_one_stream(&u2, &kp2, &ra2, relay_pubkey, cred2.clone(), &tg2).await {
                                spawn_parked_watcher(next_parked, u2, kp2, ra2, relay_pubkey, cred2, tg2, tx2, srx2);
                            }
                        }
                    });
                    let _ = activated_tx.send((stream, relay_addr)).await;
                }
            }
        }
    });
}

#[async_trait]
impl StreamChannel for RelayIngressStreamChannel {
    fn id(&self) -> &ChannelId {
        &self.id
    }

    fn caps(&self) -> ChannelCaps {
        ChannelCaps {
            plane: Plane::Stream,
            reliable_underlay: true,
            ordered_underlay: true,
            max_payload_bytes: None,
        }
    }

    async fn open(&self, _addr: &ChannelAddr) -> Result<BoxedAsyncStream> {
        Err(CoreError::CapabilityMismatch(format!(
            "RelayIngressStreamChannel '{}' is passive-inbound only (use regular carrier for outbound)",
            self.relay_addr
        )))
    }

    async fn accept(&self) -> Result<(BoxedAsyncStream, ChannelAddr)> {
        let mut guard = self.activated_rx.lock().await;
        guard
            .recv()
            .await
            .ok_or_else(|| CoreError::Closed("relay ingress pool closed".into()))
    }

    fn health(&self) -> ChannelHealth {
        if self.closed.load(Ordering::Acquire) {
            ChannelHealth::Closed("closed".into())
        } else {
            ChannelHealth::Healthy
        }
    }

    async fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::Release);
        let _ = self.stop_tx.send(true);
        Ok(())
    }
}
