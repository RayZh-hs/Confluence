#![forbid(unsafe_code)]

use confluence_core::{
    AsyncStream, BoxFut, ChannelCaps, CoreErr, DATAGRAM_MTU, DatagramChannel, DatagramLink,
    PacketBuf, StreamChannel,
};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, Weak},
};

const MAX_PRESENCES: usize = 4096;
const MAX_IDLE_STREAMS: usize = 32;

type Streams = HashMap<Vec<u8>, VecDeque<Box<dyn AsyncStream>>>;
type Datagrams = HashMap<Vec<u8>, Arc<PresenceLink>>;

/// A passive carrier that only selects already-connected presence links.
/// Wrap it with a forward-admission plugin to register it as a transit channel.
#[derive(Clone)]
pub struct PassiveRelay {
    streams: Arc<Mutex<Streams>>,
    datagrams: Arc<Mutex<Datagrams>>,
    datagram_mtu: u16,
    stream_mtu: u16,
}
pub struct DatagramPresence {
    id: Vec<u8>,
    links: Weak<Mutex<Datagrams>>,
    _registered: tokio::sync::watch::Sender<()>,
}
impl Drop for DatagramPresence {
    fn drop(&mut self) {
        if let Some(links) = self.links.upgrade() {
            links.lock().unwrap().remove(&self.id);
        }
    }
}
impl PassiveRelay {
    pub fn new(stream_mtu: u16, datagram_mtu: u16) -> Result<Self, CoreErr> {
        if datagram_mtu < DATAGRAM_MTU {
            return Err(CoreErr::MtuTooSmall(datagram_mtu));
        }
        Ok(Self {
            streams: Default::default(),
            datagrams: Default::default(),
            datagram_mtu,
            stream_mtu,
        })
    }
    /// Registers one pre-established stream, consumed by one circuit.
    pub fn register_stream(&self, id: &[u8], stream: Box<dyn AsyncStream>) -> Result<(), CoreErr> {
        validate(id)?;
        let mut streams = self.streams.lock().unwrap();
        if streams.len() >= MAX_PRESENCES && !streams.contains_key(id) {
            return Err(CoreErr::Busy);
        }
        let queue = streams.entry(id.into()).or_default();
        if queue.len() >= MAX_IDLE_STREAMS {
            return Err(CoreErr::Busy);
        }
        queue.push_back(stream);
        Ok(())
    }
    pub fn remove_stream_presence(&self, id: &[u8]) {
        self.streams.lock().unwrap().remove(id);
    }
    pub fn register_datagram(
        &self,
        id: &[u8],
        link: Arc<dyn DatagramLink>,
    ) -> Result<DatagramPresence, CoreErr> {
        validate(id)?;
        let mut datagrams = self.datagrams.lock().unwrap();
        if datagrams.contains_key(id) {
            return Err(CoreErr::AlreadyPublished);
        }
        if datagrams.len() >= MAX_PRESENCES {
            return Err(CoreErr::Busy);
        }
        let (registration, released) = tokio::sync::watch::channel(());
        datagrams.insert(id.into(), Arc::new(PresenceLink { link, released }));
        Ok(DatagramPresence {
            id: id.into(),
            links: Arc::downgrade(&self.datagrams),
            _registered: registration,
        })
    }
}
fn validate(id: &[u8]) -> Result<(), CoreErr> {
    if id.is_empty() || id.len() > 255 {
        Err(CoreErr::Malformed)
    } else {
        Ok(())
    }
}
impl StreamChannel for PassiveRelay {
    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(self.stream_mtu, true)
    }
    fn dial_stream<'a>(
        &'a self,
        locator: &'a [u8],
    ) -> BoxFut<'a, Result<Box<dyn AsyncStream>, CoreErr>> {
        Box::pin(async move {
            let mut streams = self.streams.lock().unwrap();
            let queue = streams.get_mut(locator).ok_or(CoreErr::TargetUnreachable)?;
            let stream = queue.pop_front().ok_or(CoreErr::TargetUnreachable)?;
            if queue.is_empty() {
                streams.remove(locator);
            }
            Ok(stream)
        })
    }
}
impl DatagramChannel for PassiveRelay {
    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(self.datagram_mtu, false)
    }
    fn open_link<'a>(
        &'a self,
        locator: &'a [u8],
    ) -> BoxFut<'a, Result<Arc<dyn DatagramLink>, CoreErr>> {
        Box::pin(async move {
            self.datagrams
                .lock()
                .unwrap()
                .get(locator)
                .cloned()
                .map(|link| link as Arc<dyn DatagramLink>)
                .ok_or(CoreErr::TargetUnreachable)
        })
    }
}

struct PresenceLink {
    link: Arc<dyn DatagramLink>,
    released: tokio::sync::watch::Receiver<()>,
}
impl DatagramLink for PresenceLink {
    fn caps(&self) -> ChannelCaps {
        self.link.caps()
    }
    fn send(&self, packet: PacketBuf) -> BoxFut<'_, Result<(), CoreErr>> {
        Box::pin(async move {
            let mut released = self.released.clone();
            tokio::select! {
                biased;
                _ = released.changed() => Err(CoreErr::Closed),
                result = self.link.send(packet) => result,
            }
        })
    }
    fn recv(&self) -> BoxFut<'_, Result<PacketBuf, CoreErr>> {
        Box::pin(async move {
            let mut released = self.released.clone();
            tokio::select! {
                biased;
                _ = released.changed() => Err(CoreErr::Closed),
                result = self.link.recv() => result,
            }
        })
    }
}
