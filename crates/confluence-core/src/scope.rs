use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::{Semaphore, broadcast, watch};

use crate::{
    AsyncStream, CoreErr, DATAGRAM_MTU, DatagramChannel, DatagramEndpointHandler, DatagramLink,
    E2eDatagram, E2eStream, PathOutcome, PathSource, Plane, PolicyGate, PublicKey, Revocation,
    ScopeId, ScopeKeypair, StreamChannel, StreamEndpointHandler, TaskSpawner,
    crypto::replay::SetupReplay,
    path::{dg_switch::DatagramPort, dialer, inbound},
};

#[derive(Clone)]
pub struct ScopeInstance(pub(crate) Arc<Scope>);
pub(crate) struct Scope {
    pub id: ScopeId,
    pub identity: Arc<ScopeKeypair>,
    pub replay: SetupReplay,
    pub policy: Arc<PolicyGate>,
    pub source: Arc<dyn PathSource>,
    pub tasks: Arc<dyn TaskSpawner>,
    pub pending: Arc<Semaphore>,
    pub sessions: Arc<Semaphore>,
    pub endpoints: Mutex<HashMap<String, Arc<Published>>>,
    pub stream_channels: Mutex<HashMap<u64, Arc<dyn StreamChannel>>>,
    pub datagram_channels: Mutex<HashMap<u64, Arc<dyn DatagramChannel>>>,
    pub datagram_ports: Mutex<HashMap<usize, Weak<DatagramPort>>>,
    pub wake_on_drop: watch::Sender<()>,
    pub port_count: Arc<AtomicUsize>,
}

pub(crate) enum Published {
    Stream(Arc<dyn StreamEndpointHandler>),
    Datagram(u16, Arc<dyn DatagramEndpointHandler>),
}
impl Published {
    pub fn plane(&self) -> Plane {
        match self {
            Self::Stream(_) => Plane::Stream,
            Self::Datagram(..) => Plane::Datagram,
        }
    }
    pub fn min_mtu(&self) -> u16 {
        match self {
            Self::Stream(_) => 0,
            Self::Datagram(mtu, _) => *mtu,
        }
    }
}
pub struct PublishGuard {
    scope: Weak<Scope>,
    name: String,
}
impl Drop for PublishGuard {
    fn drop(&mut self) {
        if let Some(scope) = self.scope.upgrade() {
            let mut endpoints = scope.endpoints.lock().unwrap();
            endpoints.remove(&self.name);
            scope.policy.revoke_endpoint(&self.name);
        }
    }
}

/// Keeps a datagram ingress dispatcher active for a carrier link.
pub struct DatagramIngress {
    port: Arc<DatagramPort>,
}
impl DatagramIngress {
    pub async fn closed(&self) -> CoreErr {
        self.port.closed().await
    }
    /// True once at least one setup on this link has passed cryptographic and policy admission.
    pub fn is_admitted(&self) -> bool {
        self.port.is_admitted()
    }
    /// True if an unauthenticated link's initial setup attempt failed admission.
    pub fn is_rejected(&self) -> bool {
        self.port.is_rejected()
    }
}

impl ScopeInstance {
    pub fn new(
        id: ScopeId,
        identity: ScopeKeypair,
        acl: Arc<dyn crate::AccessControl>,
        source: Arc<dyn PathSource>,
        tasks: Arc<dyn TaskSpawner>,
    ) -> Self {
        let scope = Arc::new(Scope {
            id,
            identity: Arc::new(identity),
            replay: SetupReplay::default(),
            policy: Arc::new(PolicyGate::new(id, acl)),
            source,
            tasks,
            pending: Arc::new(Semaphore::new(256)),
            sessions: Arc::new(Semaphore::new(4096)),
            endpoints: Default::default(),
            stream_channels: Default::default(),
            datagram_channels: Default::default(),
            datagram_ports: Default::default(),
            wake_on_drop: watch::channel(()).0,
            port_count: Default::default(),
        });
        if let Some(mut events) = scope.policy.revocations() {
            let weak = Arc::downgrade(&scope);
            let mut dropped = scope.wake_on_drop.subscribe();
            scope.tasks.spawn(Box::pin(async move {
                while let crate::Either::Left(event) =
                    crate::race(events.recv(), dropped.changed()).await
                {
                    let Some(scope) = weak.upgrade() else { break };
                    match event {
                        Ok(Revocation::Peer(peer)) => scope.policy.revoke_peer_sessions(peer),
                        Ok(Revocation::Endpoint(ep)) => scope.policy.revoke_endpoint(&ep),
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            // A lost event means the scope can no longer assume its
                            // current authorization snapshot is valid.
                            scope.policy.invalidate();
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }));
        }
        Self(scope)
    }
    pub fn id(&self) -> ScopeId {
        self.0.id
    }
    pub fn public_key(&self) -> PublicKey {
        self.0.identity.public_key()
    }
    pub fn identity(&self) -> Arc<ScopeKeypair> {
        self.0.identity.clone()
    }
    pub fn policy(&self) -> Arc<PolicyGate> {
        self.0.policy.clone()
    }
    pub fn revoke_peer(&self, peer: &PublicKey) {
        self.0.policy.revoke_peer(*peer);
    }

    pub fn register_stream_channel(
        &self,
        tag: u64,
        channel: Arc<dyn StreamChannel>,
    ) -> Result<(), CoreErr> {
        insert(&self.0.stream_channels, tag, channel)
    }
    pub fn register_datagram_channel(
        &self,
        tag: u64,
        channel: Arc<dyn DatagramChannel>,
    ) -> Result<(), CoreErr> {
        insert(&self.0.datagram_channels, tag, channel)
    }
    pub fn publish_stream(
        &self,
        name: &str,
        handler: Arc<dyn StreamEndpointHandler>,
    ) -> Result<PublishGuard, CoreErr> {
        self.publish(name, Published::Stream(handler))
    }
    pub fn publish_datagram(
        &self,
        name: &str,
        min_mtu: u16,
        handler: Arc<dyn DatagramEndpointHandler>,
    ) -> Result<PublishGuard, CoreErr> {
        if min_mtu < DATAGRAM_MTU {
            return Err(CoreErr::MtuTooSmall(min_mtu));
        }
        self.publish(name, Published::Datagram(min_mtu, handler))
    }
    fn publish(&self, name: &str, published: Published) -> Result<PublishGuard, CoreErr> {
        if name.is_empty() || name.len() > 255 {
            return Err(CoreErr::Malformed);
        }
        insert(&self.0.endpoints, name.to_owned(), Arc::new(published))?;
        Ok(PublishGuard {
            scope: Arc::downgrade(&self.0),
            name: name.into(),
        })
    }

    /// Attach an explicitly accepted carrier stream to this trust scope.
    pub fn accept_stream(&self, stream: Box<dyn AsyncStream>) -> Result<(), CoreErr> {
        let permit = self
            .0
            .pending
            .clone()
            .try_acquire_owned()
            .map_err(|_| CoreErr::Busy)?;
        let scope = self.0.clone();
        self.0.tasks.spawn(Box::pin(async move {
            let _ = inbound::stream(scope, stream, permit).await;
        }));
        Ok(())
    }
    /// Public front-door filter for carriers sharing a socket across peers.
    pub fn precheck_datagram_setup(&self, wire: &[u8]) -> bool {
        self.0.precheck_datagram_setup(wire)
    }
    pub fn attach_datagram(&self, link: Arc<dyn DatagramLink>) -> Result<DatagramIngress, CoreErr> {
        let port = DatagramPort::attach(&self.0, link)?;
        Ok(DatagramIngress { port })
    }
    pub async fn dial_stream(
        &self,
        peer: PublicKey,
        ep: &str,
        cred: &[u8],
    ) -> Result<E2eStream, CoreErr> {
        let path = self
            .0
            .source
            .resolve_path(self.0.id, &peer, ep, Plane::Stream)
            .await?;
        let result = dialer::stream(&self.0, &path, peer, ep, cred).await;
        if let Err(error) = &result {
            self.0
                .source
                .report_outcome(path.id, PathOutcome::Failed(error.clone()));
        }
        result
    }
    pub async fn dial_datagram(
        &self,
        peer: PublicKey,
        ep: &str,
        min_mtu: u16,
        cred: &[u8],
    ) -> Result<E2eDatagram, CoreErr> {
        let path = self
            .0
            .source
            .resolve_path(self.0.id, &peer, ep, Plane::Datagram)
            .await?;
        let result = dialer::datagram(&self.0, &path, peer, ep, min_mtu, cred).await;
        if let Err(error) = &result {
            self.0
                .source
                .report_outcome(path.id, PathOutcome::Failed(error.clone()));
        }
        result
    }
}

impl Scope {
    pub fn precheck_datagram_setup(&self, wire: &[u8]) -> bool {
        use crate::wire::setup::{ForwardHeader, Segment};
        let Ok(hdr) = ForwardHeader::parse(wire) else {
            return false;
        };
        if hdr.upstream == crate::cid::Cid::UNBOUND {
            return false;
        }
        let Ok(segment) = Segment::parse(&wire[8..]) else {
            return false;
        };
        if segment.plane != Plane::Datagram {
            return false;
        }
        match segment.channel {
            Some(tag) => self
                .datagram_channel(tag)
                .is_ok_and(|channel| channel.precheck_hop(segment.encrypted)),
            None => self.identity.verify_mac1(segment.encrypted),
        }
    }
    pub(crate) fn precheck_stream_segment(&self, channel: Option<u64>, segment: &[u8]) -> bool {
        match channel {
            Some(tag) => self
                .stream_channel(tag)
                .is_ok_and(|channel| channel.precheck_hop(segment)),
            None => self.identity.verify_mac1(segment),
        }
    }
    pub fn stream_channel(&self, tag: u64) -> Result<Arc<dyn StreamChannel>, CoreErr> {
        self.stream_channels
            .lock()
            .unwrap()
            .get(&tag)
            .cloned()
            .ok_or(CoreErr::Unpublished)
    }
    pub fn datagram_channel(&self, tag: u64) -> Result<Arc<dyn DatagramChannel>, CoreErr> {
        self.datagram_channels
            .lock()
            .unwrap()
            .get(&tag)
            .cloned()
            .ok_or(CoreErr::Unpublished)
    }
    pub fn session(&self) -> Result<tokio::sync::OwnedSemaphorePermit, CoreErr> {
        self.sessions
            .clone()
            .try_acquire_owned()
            .map_err(|_| CoreErr::Busy)
    }
    pub fn reserve_port(&self) -> Result<(), CoreErr> {
        self.port_count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < 4096).then_some(n + 1)
            })
            .map(|_| ())
            .map_err(|_| CoreErr::Busy)
    }
}

fn insert<K: std::hash::Hash + Eq, V>(
    table: &Mutex<HashMap<K, V>>,
    key: K,
    value: V,
) -> Result<(), CoreErr> {
    use std::collections::hash_map::Entry;
    match table.lock().unwrap().entry(key) {
        Entry::Vacant(entry) => {
            entry.insert(value);
            Ok(())
        }
        Entry::Occupied(_) => Err(CoreErr::AlreadyPublished),
    }
}
