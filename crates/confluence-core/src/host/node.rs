//! Multi-scope container (`Node`, `WeakNode`, `NodeBuilder`, `NodeLimits`, Spec §8.2).
//!
//! Demultiplexes shared Stream and Datagram listeners across isolated Trust Scopes in $O(1)$
//! by `ScopeKid`, enforces shared `Clock` identity, deduplicates concurrent `DatagramLink`
//! attachments into one `DatagramPort`/`SlabTable`, and atomically adopts/unmounts live ports.

use core::fmt;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, RwLock, Weak};

use crate::constants::{DEFAULT_MAX_DATAGRAM_PORTS, DEFAULT_NODE_MAX_PENDING};
use crate::engine::context::{NodePendingGate, ScopeCore, ScopeResolver};
use crate::engine::datagram::inbound::InboundDatagramDispatcher;
use crate::engine::datagram::port::{PortMetricOwner, PortRegistry};
use crate::engine::stream::spawn_inbound_stream;
use crate::error::CoreError;
use crate::host::scope::ScopeInstance;
use crate::protocol::setup::precheck_datagram_setup_frame;
use crate::runtime::Runtime;
use crate::seam::channel::{
    BoxedStream, DatagramIngress, DatagramLink, DatagramListener, IntoStreamHalves, StreamListener,
};
use crate::stats::{NodeMetrics, NodeStats};
use crate::types::ScopeKid;

/// Clamped admission and datagram port capacity limits for a multi-scope [`Node`] (Spec §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeLimits {
    /// Maximum concurrent node-level pending inbound setups (default `512`, min `1`).
    pub max_pending: usize,
    /// Maximum deduplicated `DatagramPort` links hosted by the node (default `4096`, min `1`).
    pub max_datagram_ports: usize,
}

impl Default for NodeLimits {
    fn default() -> Self {
        Self {
            max_pending: DEFAULT_NODE_MAX_PENDING,
            max_datagram_ports: DEFAULT_MAX_DATAGRAM_PORTS,
        }
    }
}

impl NodeLimits {
    /// Returns a copy of these limits clamped to normative minimum bounds (`>= 1`).
    #[must_use]
    pub fn clamped(self) -> Self {
        Self {
            max_pending: self.max_pending.max(1),
            max_datagram_ports: self.max_datagram_ports.max(1),
        }
    }
}

/// Builder configuring a multi-scope [`Node`].
pub struct NodeBuilder {
    runtime: Runtime,
    limits: NodeLimits,
}

impl NodeBuilder {
    /// Creates a new `NodeBuilder` with default [`NodeLimits`].
    #[must_use]
    pub fn new(runtime: Runtime) -> Self {
        Self {
            runtime,
            limits: NodeLimits::default(),
        }
    }

    /// Configures node capacity limits (clamped to `>= 1`).
    #[must_use]
    pub const fn with_limits(mut self, limits: NodeLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Builds the multi-scope [`Node`].
    #[must_use]
    pub fn build(self) -> Arc<Node> {
        let limits = self.limits.clamped();
        let metrics = Arc::new(NodeMetrics::new());
        let pending = NodePendingGate::new(limits.max_pending, Arc::clone(&metrics));
        let scope_cores = Arc::new(RwLock::new(HashMap::<ScopeKid, Arc<ScopeCore>>::new()));
        let resolver = Arc::new(NodeScopeResolver {
            scopes: Arc::clone(&scope_cores),
            metrics: Arc::clone(&metrics),
        });
        let ports = PortRegistry::new(
            limits.max_datagram_ports,
            PortMetricOwner::Node(Arc::clone(&metrics)),
            Arc::clone(&self.runtime.clock),
            Arc::clone(&self.runtime.spawner),
            Arc::clone(&resolver) as Arc<dyn ScopeResolver>,
            InboundDatagramDispatcher::new(),
            Some(Arc::clone(&pending)),
        );

        Arc::new(Node {
            runtime: self.runtime,
            limits,
            metrics,
            pending,
            membership: Mutex::new(HashMap::new()),
            scope_cores,
            resolver,
            ports,
        })
    }
}

impl fmt::Debug for NodeBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeBuilder")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

struct NodeScopeResolver {
    scopes: Arc<RwLock<HashMap<ScopeKid, Arc<ScopeCore>>>>,
    metrics: Arc<NodeMetrics>,
}

impl ScopeResolver for NodeScopeResolver {
    fn resolve(&self, kid: ScopeKid) -> Option<Arc<ScopeCore>> {
        self.scopes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&kid)
            .cloned()
    }

    fn record_unknown_scope(&self) {
        self.metrics
            .unknown_scope_drops_total
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_mac1_drop(&self, matched_scope: Option<&ScopeCore>) {
        self.metrics
            .mac1_drops_total
            .fetch_add(1, Ordering::Relaxed);
        if let Some(sc) = matched_scope {
            sc.metrics.mac1_drops_total.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Multi-scope runtime container mounting isolated [`ScopeInstance`]s behind shared listeners.
pub struct Node {
    runtime: Runtime,
    limits: NodeLimits,
    metrics: Arc<NodeMetrics>,
    pending: Arc<NodePendingGate>,
    /// Lock Level 1: serializes scope mounting/unmounting and port adoption.
    membership: Mutex<HashMap<ScopeKid, Arc<ScopeInstance>>>,
    scope_cores: Arc<RwLock<HashMap<ScopeKid, Arc<ScopeCore>>>>,
    resolver: Arc<NodeScopeResolver>,
    ports: Arc<PortRegistry>,
}

/// Weak non-owning handle to a [`Node`] preventing `Arc` reference cycles.
#[derive(Clone)]
pub struct WeakNode {
    inner: Weak<Node>,
}

impl WeakNode {
    /// Upgrades to a strong `Arc<Node>` if the node is still alive.
    #[must_use]
    pub fn upgrade(&self) -> Option<Arc<Node>> {
        self.inner.upgrade()
    }
}

impl fmt::Debug for WeakNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WeakNode")
            .field("alive", &(self.inner.strong_count() > 0))
            .finish()
    }
}

impl Node {
    /// Returns a [`NodeBuilder`] initialized with default [`NodeLimits`].
    #[must_use]
    pub fn builder(runtime: Runtime) -> NodeBuilder {
        NodeBuilder::new(runtime)
    }

    /// Creates a non-owning [`WeakNode`] handle to avoid `Arc` reference cycles.
    #[must_use]
    pub fn downgrade(self: &Arc<Self>) -> WeakNode {
        WeakNode {
            inner: Arc::downgrade(self),
        }
    }

    /// Returns the effective clamped [`NodeLimits`].
    #[must_use]
    pub const fn limits(&self) -> NodeLimits {
        self.limits
    }

    /// Mounts `scope` onto this `Node` (Spec §8.2 Rules 1, 2, 4).
    ///
    /// - Enforces exact `Arc::ptr_eq` shared [`crate::runtime::Clock`] identity (`InvalidParameter`).
    /// - Rejects duplicate `PublicKey`, duplicate `ScopeKid`, or already-mounted scopes (`AlreadyPublished`).
    /// - Atomically validates capacity (`Busy`) and non-conflicting `LinkId`s (`AlreadyPublished`)
    ///   before adopting any live standalone `DatagramPort`s (`node_wide = false`).
    pub fn add_scope(&self, scope: Arc<ScopeInstance>) -> Result<(), CoreError> {
        if !Arc::ptr_eq(&self.runtime.clock, &scope.core.runtime.clock) {
            return Err(CoreError::InvalidParameter);
        }

        // Lock Level 1: membership.
        let mut mounted = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if scope.core.mounted.load(Ordering::Acquire) {
            return Err(CoreError::AlreadyPublished);
        }

        let kid = scope.scope_kid();
        let pk = scope.public_key();
        if mounted.contains_key(&kid) || mounted.values().any(|s| s.public_key() == pk) {
            return Err(CoreError::AlreadyPublished);
        }

        // Lock Level 2: atomically adopt any live standalone datagram ports into the Node registry.
        self.ports.adopt_from(scope.ports.standalone())?;

        // Commit membership atomically.
        scope.ports.switch_to(Arc::clone(&self.ports));
        scope.core.mounted.store(true, Ordering::Release);
        {
            let mut cores = self
                .scope_cores
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cores.insert(kid, Arc::clone(&scope.core));
        }
        mounted.insert(kid, scope);
        self.metrics.mounted_scopes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Unmounts the scope identified by `kid`, removing it from node demultiplexing and from all
    /// explicit scope lists on attached `DatagramPort`s (Spec §8.2 Rule 4).
    pub fn remove_scope(&self, kid: ScopeKid) -> Option<Arc<ScopeInstance>> {
        let mut mounted = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let scope = mounted.remove(&kid)?;
        {
            let mut cores = self
                .scope_cores
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cores.remove(&kid);
        }
        self.metrics.mounted_scopes.fetch_sub(1, Ordering::Relaxed);
        self.ports.detach_scope(kid);
        scope.ports.restore_standalone();
        scope.core.mounted.store(false, Ordering::Release);
        Some(scope)
    }

    /// Admits one inbound pure byte stream, demultiplexing in $O(1)$ by `ScopeKid`.
    pub fn accept_stream<S: IntoStreamHalves>(&self, stream: S) -> Result<(), CoreError> {
        let node_permit = self.pending.try_acquire()?;
        spawn_inbound_stream(
            Arc::clone(&self.resolver) as Arc<dyn ScopeResolver>,
            Arc::clone(&self.runtime.clock),
            Arc::clone(&self.runtime.spawner),
            BoxedStream::from_stream(stream),
            None,
            Some(node_permit),
        );
        Ok(())
    }

    /// Attaches an inbound [`DatagramLink`] node-wide (`node_wide = true`), deduplicating
    /// concurrent attachments of the same [`crate::LinkId`] into one `DatagramPort`/`SlabTable`.
    pub fn attach_datagram<L: DatagramLink>(&self, link: L) -> Result<DatagramIngress, CoreError> {
        if self.pending.is_closed() {
            return Err(CoreError::Closed);
        }
        self.ports.attach_inbound(Arc::new(link), None, true)
    }

    /// Runs a shared inbound Stream listener loop, ignoring per-connection admission errors and
    /// terminating only when `listener.accept()` fails (Spec §8.2 Rule 5).
    pub async fn serve_stream_listener<L: StreamListener>(&self, listener: L) -> CoreError {
        loop {
            match listener.accept().await {
                Ok(stream) => {
                    let _ = self.accept_stream(stream);
                }
                Err(err) => return err,
            }
        }
    }

    /// Runs a shared inbound Datagram listener loop, ignoring per-link admission errors and
    /// terminating only when `listener.accept_link()` fails (Spec §8.2 Rule 5).
    pub async fn serve_datagram_listener<L: DatagramListener>(&self, listener: L) -> CoreError {
        loop {
            match listener.accept_link().await {
                Ok(link) => {
                    let _ = self.attach_datagram(link);
                }
                Err(err) => return err,
            }
        }
    }

    /// Zero-allocation stack-only front-door precheck across all mounted scopes (Spec §8.2 Rule 3).
    ///
    /// Accepts both `SETUP_FWD` (`0x11`) and fragment 0 of `SETUP_FRAG` (`0x15`). Returns `false`
    /// once the node or matching scope closes admission.
    #[must_use]
    pub fn precheck_datagram_setup(&self, wire: &[u8]) -> bool {
        if self.pending.is_closed() {
            return false;
        }
        precheck_datagram_setup_frame(wire, |kid, seg, has_mac2| {
            let Some(scope) = self.resolver.resolve(kid) else {
                return false;
            };
            !scope.pending.is_closed() && scope.cookies.verify_mac1_only(seg, has_mac2)
        })
    }

    /// Closes the shared node ingress gate so `accept_stream` and `attach_datagram` fail with `Closed`.
    pub fn close_admission(&self) {
        self.pending.close();
    }

    /// Captures a lock-free atomic telemetry snapshot for this node.
    #[must_use]
    pub fn stats(&self) -> NodeStats {
        self.metrics.snapshot()
    }
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("limits", &self.limits)
            .field("mounted_scopes", &self.metrics.mounted_scopes.load(Ordering::Relaxed))
            .finish()
    }
}
