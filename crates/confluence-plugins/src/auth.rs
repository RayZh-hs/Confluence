use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use confluence_core::{
    ActionRef, AsyncStream, BoxFut, ChannelCaps, ChannelErr, CoreErr, DatagramChannel,
    DatagramLink, HopAdmission, HopAuthCtx, HopReject, Plane, PolicyGate, ScopeInstance,
    ScopeKeypair, StreamChannel,
    crypto::{
        noise_ik::{Responder, parse_hop},
        replay::SetupReplay,
    },
    grant::GrantEnforcer,
};

/// Adds originator authentication and policy to any existing same-plane carrier.
pub struct AuthAclWrapper<T> {
    channel: T,
    tag: u64,
    identity: Arc<ScopeKeypair>,
    replay: SetupReplay,
    gate: Arc<PolicyGate>,
}
impl<T> AuthAclWrapper<T> {
    pub fn new(scope: &ScopeInstance, tag: u64, channel: T) -> Self {
        Self {
            channel,
            tag,
            identity: scope.identity(),
            gate: scope.policy(),
            replay: SetupReplay::default(),
        }
    }
    async fn admit(
        &self,
        segment: &[u8],
        aad: &[u8; 32],
        plane: Plane,
    ) -> Result<(HopAuthCtx, Vec<u8>), HopReject> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let opened = Responder::accept(&self.identity, &self.replay, segment, aad, now)
            .map_err(|_| HopReject::Silent)?;
        let hop_key = opened.hop_key();
        let reject = |error| HopReject::Authenticated(hop_key.clone(), error);
        let (credential, locator) = parse_hop(&opened.plaintext).map_err(reject)?;
        let peer = opened.peer;
        let pending = self.gate.pending(peer).map_err(reject)?;
        let epoch = self.gate.epoch_for(peer, None);
        let grant = self
            .gate
            .verify(
                &peer,
                ActionRef::HopForward {
                    chan_tag: self.tag,
                    plane,
                },
                credential,
            )
            .await
            .map_err(reject)?;
        let grant = Arc::new(GrantEnforcer::new(grant).map_err(reject)?);
        self.gate.track(epoch, peer, None, &grant).map_err(reject)?;
        Ok((
            HopAuthCtx {
                peer,
                hop_key,
                grant,
                gate: self.gate.clone(),
                channel: self.tag,
                plane,
                pending: Some(pending),
            },
            locator.to_vec(),
        ))
    }
}
impl<T: StreamChannel> StreamChannel for AuthAclWrapper<T> {
    fn precheck_hop(&self, segment: &[u8]) -> bool {
        self.identity.verify_mac1(segment)
    }
    fn caps(&self) -> ChannelCaps {
        self.channel.caps()
    }
    fn dial_stream<'a>(
        &'a self,
        locator: &'a [u8],
    ) -> BoxFut<'a, Result<Box<dyn AsyncStream>, ChannelErr>> {
        self.channel.dial_stream(locator)
    }
    fn accept_hop_stream<'a>(
        &'a self,
        segment: &'a [u8],
        aad: &'a [u8; 32],
        min_mtu: u16,
    ) -> BoxFut<'a, HopAdmission<Box<dyn AsyncStream>>> {
        Box::pin(async move {
            let (ctx, locator) = self.admit(segment, aad, Plane::Stream).await?;
            let reject = |error| HopReject::Authenticated(ctx.hop_key.clone(), error);
            let limit = self.channel.caps().mtu();
            if limit < min_mtu {
                return Err(reject(CoreErr::MtuTooSmall(limit)));
            }
            let stream = self.channel.dial_stream(&locator).await.map_err(reject)?;
            ctx.grant.remaining().map_err(reject)?;
            Ok((stream, ctx))
        })
    }
}
impl<T: DatagramChannel> DatagramChannel for AuthAclWrapper<T> {
    fn precheck_hop(&self, segment: &[u8]) -> bool {
        self.identity.verify_mac1(segment)
    }
    fn caps(&self) -> ChannelCaps {
        self.channel.caps()
    }
    fn open_link<'a>(
        &'a self,
        locator: &'a [u8],
    ) -> BoxFut<'a, Result<Arc<dyn DatagramLink>, ChannelErr>> {
        self.channel.open_link(locator)
    }
    fn accept_hop_datagram<'a>(
        &'a self,
        segment: &'a [u8],
        aad: &'a [u8; 32],
        min_mtu: u16,
    ) -> BoxFut<'a, HopAdmission<Arc<dyn DatagramLink>>> {
        Box::pin(async move {
            let (ctx, locator) = self.admit(segment, aad, Plane::Datagram).await?;
            let reject = |error| HopReject::Authenticated(ctx.hop_key.clone(), error);
            let limit = self.channel.caps().mtu();
            if limit < min_mtu {
                return Err(reject(CoreErr::MtuTooSmall(limit)));
            }
            let link = self.channel.open_link(&locator).await.map_err(reject)?;
            ctx.grant.remaining().map_err(reject)?;
            Ok((link, ctx))
        })
    }
}
