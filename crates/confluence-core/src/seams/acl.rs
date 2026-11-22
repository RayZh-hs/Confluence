use crate::{
    BoxFut, CoreErr, Plane, PublicKey,
    grant::{GrantEnforcer, GrantSpec, RevocationIndex, RevocationKey},
};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{Semaphore, broadcast};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct ScopeId(pub u64);

#[derive(Clone, Copy, Debug)]
pub enum ActionRef<'a> {
    EndpointOpen { ep: &'a str, plane: Plane },
    HopForward { chan_tag: u64, plane: Plane },
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("policy denied")]
pub struct PolicyDenied;

#[derive(Clone, Debug)]
pub enum Revocation {
    Peer(PublicKey),
    Endpoint(String),
}

pub trait AccessControl: Send + Sync + 'static {
    fn verify<'a>(
        &'a self,
        scope: ScopeId,
        peer: &'a PublicKey,
        action: ActionRef<'a>,
        credential: &'a [u8],
    ) -> BoxFut<'a, Result<GrantSpec, PolicyDenied>>;
    fn revocations(&self, _scope: ScopeId) -> Option<broadcast::Receiver<Revocation>> {
        None
    }
}

const PER_PEER_PENDING: usize = 8;
const POLICY_CONCURRENCY: usize = 32;
const POLICY_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyEpoch {
    global: u64,
    peer: u64,
    endpoint: u64,
}

#[derive(Default)]
struct HostState {
    vetoed: HashSet<PublicKey>,
    pending: HashMap<PublicKey, usize>,
    global_epoch: u64,
    peer_epochs: HashMap<PublicKey, u64>,
    endpoint_epochs: HashMap<String, u64>,
}

pub struct PolicyGate {
    scope: ScopeId,
    acl: Arc<dyn AccessControl>,
    permits: Semaphore,
    host: Arc<Mutex<HostState>>,
    index: RevocationIndex,
}

pub struct PendingSetup {
    host: Arc<Mutex<HostState>>,
    peer: PublicKey,
}
impl Drop for PendingSetup {
    fn drop(&mut self) {
        let mut host = self.host.lock().unwrap();
        if let Some(count) = host.pending.get_mut(&self.peer) {
            *count -= 1;
            if *count == 0 {
                host.pending.remove(&self.peer);
            }
        }
    }
}

impl PolicyGate {
    pub fn new(scope: ScopeId, acl: Arc<dyn AccessControl>) -> Self {
        Self {
            scope,
            acl,
            permits: Semaphore::new(POLICY_CONCURRENCY),
            host: Default::default(),
            index: Default::default(),
        }
    }
    pub fn revocations(&self) -> Option<broadcast::Receiver<Revocation>> {
        self.acl.revocations(self.scope)
    }
    pub fn pending(&self, peer: PublicKey) -> Result<PendingSetup, CoreErr> {
        let mut host = self.host.lock().unwrap();
        if host.vetoed.contains(&peer) {
            return Err(CoreErr::Revoked);
        }
        let count = host.pending.entry(peer).or_default();
        if *count == PER_PEER_PENDING {
            return Err(CoreErr::Busy);
        }
        *count += 1;
        Ok(PendingSetup {
            host: self.host.clone(),
            peer,
        })
    }
    pub async fn verify(
        &self,
        peer: &PublicKey,
        action: ActionRef<'_>,
        credential: &[u8],
    ) -> Result<GrantSpec, CoreErr> {
        {
            if self.host.lock().unwrap().vetoed.contains(peer) {
                return Err(CoreErr::Revoked);
            }
        }
        let deadline = tokio::time::Instant::now() + POLICY_TIMEOUT;
        let grant = tokio::time::timeout_at(deadline, async {
            let _permit = self.permits.acquire().await.map_err(|_| CoreErr::Denied)?;
            self.acl
                .verify(self.scope, peer, action, credential)
                .await
                .map_err(|_| CoreErr::Denied)
        })
        .await
        .map_err(|_| CoreErr::Timeout)??;
        if tokio::time::Instant::now() >= deadline {
            return Err(CoreErr::Timeout);
        }
        if self.host.lock().unwrap().vetoed.contains(peer) {
            return Err(CoreErr::Revoked);
        }
        grant.validate()
    }
    pub fn is_vetoed(&self, peer: &PublicKey) -> bool {
        self.host.lock().unwrap().vetoed.contains(peer)
    }
    pub fn epoch_for(&self, peer: PublicKey, endpoint: Option<&str>) -> PolicyEpoch {
        let host = self.host.lock().unwrap();
        PolicyEpoch {
            global: host.global_epoch,
            peer: host.peer_epochs.get(&peer).copied().unwrap_or(0),
            endpoint: endpoint
                .and_then(|name| host.endpoint_epochs.get(name).copied())
                .unwrap_or(0),
        }
    }
    pub fn track(
        &self,
        epoch: PolicyEpoch,
        peer: PublicKey,
        endpoint: Option<&str>,
        grant: &Arc<GrantEnforcer>,
    ) -> Result<(), CoreErr> {
        let host = self.host.lock().unwrap();
        if host.global_epoch != epoch.global
            || host.vetoed.contains(&peer)
            || host.peer_epochs.get(&peer).copied().unwrap_or(0) != epoch.peer
            || endpoint.is_some_and(|name| {
                host.endpoint_epochs.get(name).copied().unwrap_or(0) != epoch.endpoint
            })
        {
            return Err(CoreErr::Revoked);
        }
        self.index
            .track(RevocationKey::Peer(self.scope, peer), grant);
        if let Some(endpoint) = endpoint {
            self.index
                .track(RevocationKey::Endpoint(self.scope, endpoint.into()), grant);
        }
        Ok(())
    }
    pub fn revoke_peer(&self, peer: PublicKey) {
        let mut host = self.host.lock().unwrap();
        host.vetoed.insert(peer);
        let entry = host.peer_epochs.entry(peer).or_default();
        *entry = entry.wrapping_add(1);
        self.index
            .revoke(&RevocationKey::Peer(self.scope, peer), CoreErr::Revoked);
    }
    pub(crate) fn revoke_peer_sessions(&self, peer: PublicKey) {
        let mut host = self.host.lock().unwrap();
        let entry = host.peer_epochs.entry(peer).or_default();
        *entry = entry.wrapping_add(1);
        self.index
            .revoke(&RevocationKey::Peer(self.scope, peer), CoreErr::Revoked);
    }
    pub fn revoke_endpoint(&self, endpoint: &str) {
        let mut host = self.host.lock().unwrap();
        let entry = host.endpoint_epochs.entry(endpoint.to_owned()).or_default();
        *entry = entry.wrapping_add(1);
        self.index.revoke(
            &RevocationKey::Endpoint(self.scope, endpoint.into()),
            CoreErr::Unpublished,
        );
    }
}

impl PolicyGate {
    pub(crate) fn invalidate(&self) {
        let mut host = self.host.lock().unwrap();
        host.global_epoch = host.global_epoch.wrapping_add(1);
        self.index.invalidate();
    }
}
