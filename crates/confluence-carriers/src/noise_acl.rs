use async_trait::async_trait;
use confluence_core::seams::access::{AccessControl, AccessRequest, Action, Decision};
use confluence_core::seams::channel::{
    BoxedAsyncStream, BoxedDatagramForwardHandle, ChannelCaps, DatagramChannel,
    DatagramForwardChannel, DatagramForwardHandle, SetupOutcome, StreamChannel,
    StreamForwardChannel,
};
use confluence_core::security::cookie::{CookieProtector, EnvelopeCheck};
use confluence_core::security::grant::{GrantEnforcedStream, GrantEnforcer};
use confluence_core::security::noise::{VerifiedInitiation, DEFAULT_PROLOGUE};
use confluence_core::security::replay::Tai64nReplayWindow;
use confluence_core::wire::{E2eHandshakeResp, HopHandshakeReq};
use confluence_core::{
    ChannelAddr, ChannelId, CoreError, PeerId, Plane, Result, ScopeId, StaticKeypair, TargetTag,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// Composable vertical Datagram channel middleware wrapping any [`DatagramChannel`] carrier
/// with direct `channel <-> originator` `Noise_IK` authentication, TAI64N 0-RTT replay protection,
/// stateless MAC2 flood cookies, `AccessControl` policy verification, and `GrantEnforcer` limits.
pub struct NoiseAclDatagramChannel<D: DatagramChannel> {
    inner: Arc<D>,
    scope: ScopeId,
    keypair: StaticKeypair,
    access: Arc<dyn AccessControl>,
    cookie_protector: Arc<CookieProtector>,
    replay_window: Arc<Tai64nReplayWindow>,
}

impl<D: DatagramChannel> NoiseAclDatagramChannel<D> {
    pub fn new(
        inner: Arc<D>,
        scope: ScopeId,
        keypair: StaticKeypair,
        access: Arc<dyn AccessControl>,
    ) -> Arc<Self> {
        let peer_id = keypair.peer_id();
        Arc::new(Self {
            inner,
            scope,
            keypair,
            access,
            cookie_protector: Arc::new(CookieProtector::new(peer_id, Duration::from_secs(120))),
            replay_window: Arc::new(Tai64nReplayWindow::default()),
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.keypair.peer_id()
    }

    pub fn cookie_protector(&self) -> &CookieProtector {
        &self.cookie_protector
    }
}

struct NoiseAclDatagramHandle<D: DatagramChannel> {
    inner: Arc<D>,
    channel_id: ChannelId,
    target_addr: ChannelAddr,
    originator_peer: PeerId,
    scope: ScopeId,
    keypair: StaticKeypair,
    cookie_protector: Arc<CookieProtector>,
    replay_window: Arc<Tai64nReplayWindow>,
    access: Arc<dyn AccessControl>,
    enforcer: Arc<GrantEnforcer>,
}

#[async_trait]
impl<D: DatagramChannel> DatagramForwardHandle for NoiseAclDatagramHandle<D> {
    async fn send(&self, packet: &[u8]) -> Result<()> {
        self.enforcer.check_and_record_datagram(packet.len())?;
        self.inner.send_to(&self.target_addr, packet).await
    }

    fn check_and_record_reverse(&self, byte_len: usize) -> Result<()> {
        self.enforcer.check_and_record_datagram(byte_len)
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
                target_action: Box::new(Action::ChannelForward {
                    channel: self.channel_id.clone(),
                    target: self.target_addr.clone(),
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
                self.enforcer.update_grant(new_grant);
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
        self.enforcer.closed_watch()
    }
}

#[async_trait]
impl<D: DatagramChannel> DatagramForwardChannel for NoiseAclDatagramChannel<D> {
    fn target_tag(&self) -> TargetTag {
        self.keypair.target_tag()
    }

    fn caps(&self) -> ChannelCaps {
        self.inner.caps()
    }

    fn underlying_carrier(&self) -> Option<Arc<dyn DatagramChannel>> {
        let carrier: Arc<dyn DatagramChannel> = self.inner.clone();
        Some(carrier)
    }

    async fn handle_setup(
        &self,
        source_addr: &ChannelAddr,
        setup_payload: &[u8],
    ) -> Result<SetupOutcome<BoxedDatagramForwardHandle>> {
        if !self.inner.health().is_usable() {
            return Ok(SetupOutcome::Reject("egress carrier closed".into()));
        }

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
                Err(_) => return Ok(SetupOutcome::Reject("hop authentication failed".into())),
            };
        let originator_peer = verified.initiator_peer();

        let req = match HopHandshakeReq::decode(verified.payload()) {
            Ok(r) if r.plane == Plane::Datagram => r,
            _ => return Ok(SetupOutcome::Reject("malformed hop setup payload".into())),
        };

        if self
            .replay_window
            .check_and_record(&originator_peer, req.timestamp)
            .is_err()
        {
            return Ok(SetupOutcome::Reject("hop timestamp replay".into()));
        }

        let ac_req = AccessRequest {
            scope: self.scope.clone(),
            peer: originator_peer,
            credential: req.credential,
            action: Action::ChannelForward {
                channel: self.inner.id().clone(),
                target: req.next_addr.clone(),
                plane: Plane::Datagram,
            },
        };

        let grant = match self.access.evaluate(ac_req).await {
            Ok(Decision::Allow(g)) => g,
            Ok(Decision::Deny { reason }) => return Ok(SetupOutcome::Reject(reason)),
            Err(e) => return Ok(SetupOutcome::Reject(e.to_string())),
        };

        let enforcer = GrantEnforcer::new(grant);
        enforcer.spawn_revocation_watcher(
            self.access.revocations(),
            self.scope.clone(),
            originator_peer,
            None,
        );

        let handle: BoxedDatagramForwardHandle = Arc::new(NoiseAclDatagramHandle {
            inner: Arc::clone(&self.inner),
            channel_id: self.inner.id().clone(),
            target_addr: req.next_addr,
            originator_peer,
            scope: self.scope.clone(),
            keypair: self.keypair.clone(),
            cookie_protector: Arc::clone(&self.cookie_protector),
            replay_window: Arc::clone(&self.replay_window),
            access: Arc::clone(&self.access),
            enforcer,
        });

        Ok(SetupOutcome::Accept {
            handle,
            reply_hint: None,
        })
    }
}

/// Composable vertical Stream channel middleware wrapping any [`StreamChannel`] carrier
/// with direct `channel <-> originator` `Noise_IK` authentication, TAI64N 0-RTT replay protection,
/// stateless MAC2 flood cookies, `AccessControl` policy verification, and `GrantEnforcedStream`.
pub struct NoiseAclStreamChannel<S: StreamChannel> {
    inner: Arc<S>,
    scope: ScopeId,
    keypair: StaticKeypair,
    access: Arc<dyn AccessControl>,
    cookie_protector: CookieProtector,
    replay_window: Tai64nReplayWindow,
}

impl<S: StreamChannel> NoiseAclStreamChannel<S> {
    pub fn new(
        inner: Arc<S>,
        scope: ScopeId,
        keypair: StaticKeypair,
        access: Arc<dyn AccessControl>,
    ) -> Arc<Self> {
        let peer_id = keypair.peer_id();
        Arc::new(Self {
            inner,
            scope,
            keypair,
            access,
            cookie_protector: CookieProtector::new(peer_id, Duration::from_secs(120)),
            replay_window: Tai64nReplayWindow::default(),
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.keypair.peer_id()
    }

    pub fn cookie_protector(&self) -> &CookieProtector {
        &self.cookie_protector
    }
}

#[async_trait]
impl<S: StreamChannel> StreamForwardChannel for NoiseAclStreamChannel<S> {
    fn target_tag(&self) -> TargetTag {
        self.keypair.target_tag()
    }

    fn caps(&self) -> ChannelCaps {
        self.inner.caps()
    }

    async fn handle_setup(
        &self,
        source_addr: &ChannelAddr,
        setup_payload: &[u8],
    ) -> Result<SetupOutcome<BoxedAsyncStream>> {
        if !self.inner.health().is_usable() {
            return Ok(SetupOutcome::Reject("egress stream carrier closed".into()));
        }

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
                Err(_) => return Ok(SetupOutcome::Reject("hop authentication failed".into())),
            };
        let originator_peer = verified.initiator_peer();

        let req = match HopHandshakeReq::decode(verified.payload()) {
            Ok(r) if r.plane == Plane::Stream => r,
            _ => return Ok(SetupOutcome::Reject("malformed hop setup payload".into())),
        };

        if self
            .replay_window
            .check_and_record(&originator_peer, req.timestamp)
            .is_err()
        {
            return Ok(SetupOutcome::Reject("hop timestamp replay".into()));
        }

        let ac_req = AccessRequest {
            scope: self.scope.clone(),
            peer: originator_peer,
            credential: req.credential,
            action: Action::ChannelForward {
                channel: self.inner.id().clone(),
                target: req.next_addr.clone(),
                plane: Plane::Stream,
            },
        };

        let grant = match self.access.evaluate(ac_req).await {
            Ok(Decision::Allow(g)) => g,
            Ok(Decision::Deny { reason }) => return Ok(SetupOutcome::Reject(reason)),
            Err(e) => return Ok(SetupOutcome::Reject(e.to_string())),
        };

        let enforcer = GrantEnforcer::new(grant);
        let permit = match enforcer.try_acquire_stream() {
            Ok(p) => p,
            Err(e) => return Ok(SetupOutcome::Reject(e.to_string())),
        };
        enforcer.spawn_revocation_watcher(
            self.access.revocations(),
            self.scope.clone(),
            originator_peer,
            None,
        );

        let out_stream = match self.inner.open(&req.next_addr).await {
            Ok(s) => s,
            Err(e) => return Ok(SetupOutcome::Reject(format!("egress dial failed: {e}"))),
        };

        let guarded: BoxedAsyncStream =
            Box::pin(GrantEnforcedStream::new(out_stream, enforcer, Some(permit)));

        Ok(SetupOutcome::Accept {
            handle: guarded,
            reply_hint: None,
        })
    }
}
