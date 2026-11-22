use crate::{
    BoxFut, CoreErr, PacketBuf, Plane, PublicKey,
    crypto::noise_ik::HopKey,
    grant::GrantEnforcer,
    seams::{ActionRef, PendingSetup, PolicyGate},
};
use std::sync::Arc;
use tokio::sync::watch;

pub type ChannelErr = CoreErr;

#[derive(Clone, Debug)]
pub struct ChannelCaps {
    pub effective_mtu: u16,
    pub reliable_underlay: bool,
    pub mtu_watch: watch::Receiver<u16>,
}
impl ChannelCaps {
    pub fn fixed(effective_mtu: u16, reliable_underlay: bool) -> Self {
        Self {
            effective_mtu,
            reliable_underlay,
            mtu_watch: watch::channel(effective_mtu).1,
        }
    }
    pub fn mtu(&self) -> u16 {
        *self.mtu_watch.borrow()
    }
}

pub trait StreamRead: Send + 'static {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFut<'a, Result<usize, ChannelErr>>;
}
pub trait StreamWrite: Send + 'static {
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> BoxFut<'a, Result<(), ChannelErr>>;
    fn shutdown(&mut self) -> BoxFut<'_, Result<(), ChannelErr>>;
}
pub trait AsyncStream: Send + 'static {
    fn caps(&self) -> ChannelCaps;
    fn split(self: Box<Self>) -> (Box<dyn StreamRead>, Box<dyn StreamWrite>);
}
pub trait DatagramLink: Send + Sync + 'static {
    fn caps(&self) -> ChannelCaps;
    fn send(&self, packet: PacketBuf) -> BoxFut<'_, Result<(), ChannelErr>>;
    fn recv(&self) -> BoxFut<'_, Result<PacketBuf, ChannelErr>>;
}
pub struct HopAuthCtx {
    pub peer: PublicKey,
    pub hop_key: HopKey,
    pub grant: Arc<GrantEnforcer>,
    pub gate: Arc<PolicyGate>,
    pub channel: u64,
    pub plane: Plane,
    pub pending: Option<PendingSetup>,
}
impl HopAuthCtx {
    pub fn renewal(&self, credential: Vec<u8>) -> BoxFut<'static, Result<[u8; 16], CoreErr>> {
        let (peer, channel, plane) = (self.peer, self.channel, self.plane);
        let (gate, enforcer) = (self.gate.clone(), self.grant.clone());
        Box::pin(async move {
            let grant = gate
                .verify(
                    &peer,
                    ActionRef::HopForward {
                        chan_tag: channel,
                        plane,
                    },
                    &credential,
                )
                .await?;
            enforcer.renew(grant)?;
            Ok(grant.to_wire())
        })
    }
}

pub enum HopReject {
    Silent,
    Authenticated(HopKey, CoreErr),
}

pub type HopAdmission<T> = Result<(T, HopAuthCtx), HopReject>;

pub trait StreamChannel: Send + Sync + 'static {
    /// Optional stack-only check before the setup tail is read into memory.
    fn precheck_hop(&self, _segment: &[u8]) -> bool {
        true
    }
    fn caps(&self) -> ChannelCaps;
    fn dial_stream<'a>(
        &'a self,
        locator: &'a [u8],
    ) -> BoxFut<'a, Result<Box<dyn AsyncStream>, ChannelErr>>;
    fn accept_hop_stream<'a>(
        &'a self,
        _hop_seg: &'a [u8],
        _tail_aad: &'a [u8; 32],
        _min_mtu: u16,
    ) -> BoxFut<'a, HopAdmission<Box<dyn AsyncStream>>> {
        Box::pin(async { Err(HopReject::Silent) })
    }
}
pub trait DatagramChannel: Send + Sync + 'static {
    /// Optional stack-only check before a worker or circuit is allocated.
    fn precheck_hop(&self, _segment: &[u8]) -> bool {
        true
    }
    fn caps(&self) -> ChannelCaps;
    fn open_link<'a>(
        &'a self,
        locator: &'a [u8],
    ) -> BoxFut<'a, Result<Arc<dyn DatagramLink>, ChannelErr>>;
    fn accept_hop_datagram<'a>(
        &'a self,
        _hop_seg: &'a [u8],
        _tail_aad: &'a [u8; 32],
        _min_mtu: u16,
    ) -> BoxFut<'a, HopAdmission<Arc<dyn DatagramLink>>> {
        Box::pin(async { Err(HopReject::Silent) })
    }
}

// The boxed futures in these public traits already make them dyn-safe.
pub use DatagramChannel as DynDatagramChannel;
pub use StreamChannel as DynStreamChannel;

pub async fn read_exact(reader: &mut dyn StreamRead, mut into: &mut [u8]) -> Result<(), CoreErr> {
    while !into.is_empty() {
        let amount = reader.read(into).await?;
        if amount == 0 {
            return Err(CoreErr::UnexpectedEof);
        }
        if amount > into.len() {
            return Err(CoreErr::Malformed);
        }
        into = &mut into[amount..];
    }
    Ok(())
}
