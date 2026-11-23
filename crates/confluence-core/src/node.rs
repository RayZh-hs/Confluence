//! Thin multi-scope [`Node`] container allowing multiple isolated [`ScopeInstance`]s to share
//! a single TCP/UDP listener with $O(1)$ [`ScopeKid`] demultiplexing for both endpoints and
//! transit hops while preserving per-link `SlabTable` circuit isolation.

use parking_lot::Mutex;
use std::{
    collections::HashMap,
    sync::{Arc, Weak},
};
use tokio::sync::Semaphore;

use crate::{
    AsyncStream, CoreErr, DatagramIngress, DatagramListener, IntoDynDatagramLink, LinkId,
    PublicKey, ScopeInstance, ScopeKid, StreamListener, TaskSpawner,
    path::{
        dg_switch::{DatagramPort, datagram_setup},
        inbound,
    },
    scope::Scope,
};

/// Multi-scope runtime container demultiplexing shared Stream and Datagram listeners onto
/// isolated [`ScopeInstance`]s in $O(1)$ by opaque [`ScopeKid`].
#[derive(Clone)]
pub struct Node(pub(crate) Arc<NodeInner>);

/// Non-owning weak handle to a [`Node`] to avoid `Arc` reference cycles.
#[derive(Clone)]
pub struct WeakNode(Weak<NodeInner>);

impl WeakNode {
    /// Attempts to upgrade to a live [`Node`], returning `None` if dropped.
    pub fn upgrade(&self) -> Option<Node> {
        self.0.upgrade().map(Node)
    }
}

pub(crate) struct NodeInner {
    pub tasks: Arc<dyn TaskSpawner>,
    pub pending: Arc<Semaphore>,
    scopes_by_pk: Mutex<HashMap<PublicKey, ScopeInstance>>,
    scopes_by_kid: Mutex<HashMap<ScopeKid, ScopeInstance>>,
    pub datagram_ports: Mutex<HashMap<LinkId, Weak<DatagramPort>>>,
    pub max_datagram_ports: usize,
}

impl Node {
    /// Creates an empty multi-scope [`Node`] driven by `tasks` using default resource limits.
    pub fn new(tasks: Arc<dyn TaskSpawner>) -> Self {
        Self::new_with_limits(tasks, 512, 4096)
    }

    /// Creates an empty multi-scope [`Node`] with explicit pending-setup and datagram-port limits.
    pub fn new_with_limits(
        tasks: Arc<dyn TaskSpawner>,
        max_pending: usize,
        max_datagram_ports: usize,
    ) -> Self {
        Self(Arc::new(NodeInner {
            tasks,
            pending: Arc::new(Semaphore::new(max_pending.max(1))),
            scopes_by_pk: Default::default(),
            scopes_by_kid: Default::default(),
            datagram_ports: Default::default(),
            max_datagram_ports: max_datagram_ports.max(1),
        }))
    }

    /// Creates a non-owning [`WeakNode`] handle to break `Arc` reference cycles.
    pub fn downgrade(&self) -> WeakNode {
        WeakNode(Arc::downgrade(&self.0))
    }

    /// Mounts an isolated [`ScopeInstance`] on this node. Fails if its public key or [`ScopeKid`]
    /// collides with an already-mounted scope.
    pub fn add_scope(&self, scope: ScopeInstance) -> Result<(), CoreErr> {
        let pk = scope.public_key();
        let kid = scope.kid();
        let mut by_pk = self.0.scopes_by_pk.lock();
        let mut by_kid = self.0.scopes_by_kid.lock();
        if by_pk.contains_key(&pk) || by_kid.contains_key(&kid) {
            return Err(CoreErr::AlreadyPublished);
        }
        let mut membership = scope.0.node.lock();
        if membership.as_ref().and_then(Weak::upgrade).is_some() {
            return Err(CoreErr::AlreadyPublished);
        }
        DatagramPort::mount_scope(&self.0, &scope.0)?;
        by_pk.insert(pk, scope.clone());
        by_kid.insert(kid, scope.clone());
        *membership = Some(Arc::downgrade(&self.0));
        Ok(())
    }

    /// Unmounts the scope identified by `pubkey`, returning it if present.
    pub fn remove_scope(&self, pubkey: &PublicKey) -> Option<ScopeInstance> {
        let mut by_pk = self.0.scopes_by_pk.lock();
        let removed = by_pk.remove(pubkey)?;
        self.0.scopes_by_kid.lock().remove(&removed.kid());
        {
            let mut membership = removed.0.node.lock();
            DatagramPort::unmount_scope(&removed.0);
            *membership = None;
        }
        Some(removed)
    }

    /// Looks up a mounted scope by its static [`PublicKey`].
    pub fn scope(&self, pubkey: &PublicKey) -> Option<ScopeInstance> {
        self.0.scopes_by_pk.lock().get(pubkey).cloned()
    }

    /// Returns snapshots of all currently mounted scopes.
    pub fn scopes(&self) -> Vec<ScopeInstance> {
        self.0.scopes_by_pk.lock().values().cloned().collect()
    }

    /// Stack-only $O(1)$ precheck across all mounted scopes for shared UDP listeners.
    pub fn precheck_datagram_setup(&self, wire: &[u8]) -> bool {
        self.0.resolve_datagram_scope(wire).is_some()
    }

    /// Accepts an inbound stream on a shared listener and demultiplexes it to the matching scope.
    pub fn accept_stream<S: AsyncStream>(&self, stream: S) -> Result<(), CoreErr> {
        let permit = self
            .0
            .pending
            .clone()
            .try_acquire_owned()
            .map_err(|_| CoreErr::Busy)?;
        let node = self.0.clone();
        let stream = stream.into_dyn_stream();
        self.0.tasks.spawn(Box::pin(async move {
            let _ = inbound::stream_from_node(node, stream, permit).await;
        }));
        Ok(())
    }

    /// Attaches a per-peer [`crate::DatagramLink`] to this node's multi-scope ingress dispatcher.
    /// Per-link `SlabTable` isolation is preserved even when multiple scopes share the link.
    pub fn attach_datagram<L: IntoDynDatagramLink>(
        &self,
        link: L,
    ) -> Result<DatagramIngress, CoreErr> {
        let port = DatagramPort::attach_node(&self.0, link.into_dyn_link())?;
        Ok(DatagramIngress { port })
    }

    /// Continuously accepts streams from `listener` and demultiplexes them across mounted scopes.
    pub async fn serve_stream_listener<L: StreamListener>(
        &self,
        listener: &L,
    ) -> Result<(), CoreErr> {
        loop {
            let stream = listener.accept().await?;
            let _ = self.accept_stream(stream);
        }
    }

    /// Continuously accepts datagram links from `listener` and attaches them to this node.
    pub async fn serve_datagram_listener<L: DatagramListener>(
        &self,
        listener: &L,
    ) -> Result<(), CoreErr> {
        loop {
            let link = listener.accept_link().await?;
            if let Ok(ingress) = self.attach_datagram(link) {
                self.0.tasks.spawn(Box::pin(async move {
                    ingress.closed().await;
                }));
            }
        }
    }
}

impl NodeInner {
    pub(crate) fn scope_by_kid(&self, kid: ScopeKid) -> Option<Arc<Scope>> {
        self.scopes_by_kid
            .lock()
            .get(&kid)
            .map(|scope| scope.0.clone())
    }

    /// $O(1)$ scope lookup by `ScopeKid` + stack-only `mac1` check (identical for hops & endpoints).
    pub(crate) fn resolve_stream_scope(
        &self,
        segment: &[u8],
        has_mac2: bool,
    ) -> Option<Arc<Scope>> {
        if segment.len() < 8 {
            return None;
        }
        let kid = ScopeKid(segment[..8].try_into().ok()?);
        let scope = self.scopes_by_kid.lock().get(&kid)?.0.clone();
        scope
            .identity
            .verify_mac1_with_flag(segment, has_mac2)
            .then_some(scope)
    }

    /// $O(1)$ scope lookup by `ScopeKid` + stack-only `mac1` check for inbound datagram setups.
    pub(crate) fn resolve_datagram_scope(&self, wire: &[u8]) -> Option<Arc<Scope>> {
        let (kid, segment) = datagram_setup(wire)?;
        let scope = self.scope_by_kid(kid)?;
        scope
            .identity
            .verify_mac1_with_flag(segment.encrypted, segment.has_mac2)
            .then_some(scope)
    }
}
