//! Isolated per-scope runtime (`ScopeInstance`) managing one unlinkable X25519 identity,
//! outbound carriers, published Endpoints, published named Transits, `AuthGate`, flood cookies,
//! and ingress attachment.

use parking_lot::Mutex;
use std::{
    collections::HashMap,
    sync::{
        Arc, Weak,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::{Semaphore, broadcast, watch};

use crate::{
    AsyncStream, AuthGate, AuthLimits, Authorizer, CoreErr, CredentialProvider, DATAGRAM_MTU,
    DatagramChannel, DatagramEndpointHandler, DatagramListener, DatagramTransitHandler,
    DenyAllAuthorizer, DynDatagramChannel, DynDatagramEndpointHandler, DynDatagramTransitHandler,
    DynStreamChannel, DynStreamEndpointHandler, DynStreamTransitHandler, E2eDatagram, E2eStream,
    EmptyCredentials, IntoDynDatagramLink, LinkId, NoRoutes, PathOutcome, PathSource, Plane,
    PublicKey, Revocation, ScopeKeypair, ScopeKid, StagedDatagram, StagedStream, StaticTransit,
    StreamChannel, StreamEndpointHandler, StreamListener, StreamTransitHandler, TaskSpawner,
    crypto::{
        cookie::{CookieProtector, DEFAULT_ROTATION_INTERVAL},
        replay::SetupReplay,
    },
    path::{dg_switch::DatagramPort, dialer, inbound},
    wire::setup,
};

/// Configurable resource limits for a [`ScopeInstance`] (with safe fail-closed defaults).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopeLimits {
    /// Auth-gate timeout, concurrency, per-peer pending cap, and lease TTL ceiling.
    pub auth: AuthLimits,
    /// Maximum concurrent unconfirmed inbound setups across this scope (`default: 256`).
    pub max_pending: usize,
    /// Maximum concurrent active sessions/circuits across this scope (`default: 4096`).
    pub max_sessions: usize,
    /// Maximum simultaneously attached per-peer `DatagramPort` dispatchers (`default: 4096`).
    pub max_datagram_ports: usize,
}

impl Default for ScopeLimits {
    fn default() -> Self {
        Self {
            auth: AuthLimits::default(),
            max_pending: 256,
            max_sessions: 4096,
            max_datagram_ports: 4096,
        }
    }
}

impl ScopeLimits {
    /// Clamps every limit into its safe operational envelope.
    pub fn clamped(self) -> Self {
        Self {
            auth: self.auth.clamped(),
            max_pending: self.max_pending.max(1),
            max_sessions: self.max_sessions.max(1),
            max_datagram_ports: self.max_datagram_ports.max(1),
        }
    }
}

/// Ergonomic builder for an isolated [`ScopeInstance`] with fail-closed defaults:
/// - [`DenyAllAuthorizer`] (denies all inbound requests until an authorizer is attached)
/// - [`NoRoutes`] (no outbound routes until a [`PathSource`] is attached)
/// - [`EmptyCredentials`] (public-key-only until a [`CredentialProvider`] is attached)
pub struct ScopeBuilder {
    identity: ScopeKeypair,
    tasks: Arc<dyn TaskSpawner>,
    authorizer: Arc<dyn Authorizer>,
    routes: Arc<dyn PathSource>,
    credentials: Arc<dyn CredentialProvider>,
    limits: ScopeLimits,
    under_load: bool,
}

impl ScopeBuilder {
    /// Attaches the verifier-side [`Authorizer`] evaluating inbound endpoints and transits.
    pub fn authorizer(mut self, authorizer: Arc<dyn Authorizer>) -> Self {
        self.authorizer = authorizer;
        self
    }

    /// Attaches the originator-side [`PathSource`] supplying explicit single-path routes.
    pub fn routes(mut self, routes: Arc<dyn PathSource>) -> Self {
        self.routes = routes;
        self
    }

    /// Attaches the originator-side [`CredentialProvider`] supplying and refreshing credentials.
    pub fn credentials(mut self, credentials: Arc<dyn CredentialProvider>) -> Self {
        self.credentials = credentials;
        self
    }

    /// Overrides the scope's clamped resource and auth limits.
    pub fn limits(mut self, limits: ScopeLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Enables or disables stateless rotating `MAC2` flood-cookie challenges at startup.
    pub fn under_load(mut self, under_load: bool) -> Self {
        self.under_load = under_load;
        self
    }

    /// Builds the isolated [`ScopeInstance`].
    pub fn build(self) -> ScopeInstance {
        let inst = ScopeInstance::new_with_limits(
            self.identity,
            self.authorizer,
            self.routes,
            self.credentials,
            self.tasks,
            self.limits,
        );
        inst.set_under_load(self.under_load);
        inst
    }
}

/// Handle to an isolated Trust Scope instance.
///
/// Each `ScopeInstance` owns one independent X25519 identity keypair so observers and
/// intermediaries cannot correlate its presence across unrelated Trust Scopes. Multiple
/// `ScopeInstance`s can share a single TCP/UDP listener by mounting them on a [`crate::Node`].
#[derive(Clone)]
pub struct ScopeInstance(pub(crate) Arc<Scope>);

/// Non-owning weak handle to a [`ScopeInstance`] to break `Arc` reference cycles.
#[derive(Clone)]
pub struct WeakScope(Weak<Scope>);

impl WeakScope {
    /// Attempts to upgrade to a live [`ScopeInstance`], returning `None` if dropped.
    pub fn upgrade(&self) -> Option<ScopeInstance> {
        self.0.upgrade().map(ScopeInstance)
    }
}

pub(crate) struct Scope {
    pub identity: Arc<ScopeKeypair>,
    pub cookies: CookieProtector,
    pub replay: SetupReplay,
    pub auth: Arc<AuthGate>,
    pub source: Arc<dyn PathSource>,
    pub credentials: Arc<dyn CredentialProvider>,
    pub tasks: Arc<dyn TaskSpawner>,
    pub pending: Arc<Semaphore>,
    pub sessions: Arc<Semaphore>,
    pub endpoints: Mutex<HashMap<String, Arc<PublishedEndpoint>>>,
    pub stream_carriers: Mutex<HashMap<String, Arc<dyn DynStreamChannel>>>,
    pub datagram_carriers: Mutex<HashMap<String, Arc<dyn DynDatagramChannel>>>,
    pub stream_transits: Mutex<HashMap<String, Arc<dyn DynStreamTransitHandler>>>,
    pub datagram_transits: Mutex<HashMap<String, Arc<dyn DynDatagramTransitHandler>>>,
    pub stream_transit_prefixes: Mutex<HashMap<String, Arc<dyn DynStreamTransitHandler>>>,
    pub datagram_transit_prefixes: Mutex<HashMap<String, Arc<dyn DynDatagramTransitHandler>>>,
    pub datagram_ports: Mutex<HashMap<LinkId, Weak<DatagramPort>>>,
    pub node: Mutex<Option<Weak<crate::node::NodeInner>>>,
    pub wake_on_drop: watch::Sender<()>,
    pub port_count: Arc<AtomicUsize>,
    pub max_datagram_ports: usize,
}

pub(crate) enum PublishedEndpoint {
    Stream(Arc<dyn DynStreamEndpointHandler>),
    Datagram(u16, Arc<dyn DynDatagramEndpointHandler>),
}

impl PublishedEndpoint {
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

enum PublishKind {
    Endpoint(String),
    StreamTransit(String),
    DatagramTransit(String),
    StreamTransitPrefix(String),
    DatagramTransitPrefix(String),
}

/// RAII publication handle. Dropping it immediately unpublishes the endpoint or named transit
/// and revokes all active sessions/circuits bound to it.
pub struct PublishGuard {
    scope: Weak<Scope>,
    kind: PublishKind,
}

impl Drop for PublishGuard {
    fn drop(&mut self) {
        let Some(scope) = self.scope.upgrade() else {
            return;
        };
        match &self.kind {
            PublishKind::Endpoint(name) => {
                scope.endpoints.lock().remove(name);
                scope.auth.revoke_endpoint(name);
            }
            PublishKind::StreamTransit(name) => {
                scope.stream_transits.lock().remove(name);
                scope
                    .auth
                    .revoke_transit_plane(Plane::Stream, name, CoreErr::Unpublished);
            }
            PublishKind::DatagramTransit(name) => {
                scope.datagram_transits.lock().remove(name);
                scope
                    .auth
                    .revoke_transit_plane(Plane::Datagram, name, CoreErr::Unpublished);
            }
            PublishKind::StreamTransitPrefix(prefix) => {
                scope.stream_transit_prefixes.lock().remove(prefix);
                scope
                    .auth
                    .revoke_transit_plane(Plane::Stream, prefix, CoreErr::Unpublished);
            }
            PublishKind::DatagramTransitPrefix(prefix) => {
                scope.datagram_transit_prefixes.lock().remove(prefix);
                scope
                    .auth
                    .revoke_transit_plane(Plane::Datagram, prefix, CoreErr::Unpublished);
            }
        }
    }
}

/// Keeps a datagram ingress dispatcher active for a carrier link.
pub struct DatagramIngress {
    pub(crate) port: Arc<DatagramPort>,
}

impl DatagramIngress {
    /// Resolves with the terminal link error when the underlying [`crate::DatagramLink`] closes.
    pub async fn closed(&self) -> CoreErr {
        self.port.closed().await
    }

    /// True once at least one setup on this link has passed admission.
    pub fn is_admitted(&self) -> bool {
        self.port.is_admitted()
    }

    /// True if an unauthenticated link's initial setup attempt failed admission.
    pub fn is_rejected(&self) -> bool {
        self.port.is_rejected()
    }
}

impl ScopeInstance {
    /// Starts building an isolated [`ScopeInstance`] with fail-closed defaults.
    pub fn builder(identity: ScopeKeypair, tasks: Arc<dyn TaskSpawner>) -> ScopeBuilder {
        ScopeBuilder {
            identity,
            tasks,
            authorizer: Arc::new(DenyAllAuthorizer),
            routes: Arc::new(NoRoutes),
            credentials: Arc::new(EmptyCredentials),
            limits: ScopeLimits::default(),
            under_load: false,
        }
    }

    /// Creates an isolated Trust Scope bound to `identity`, `authorizer`, `source`, `credentials`,
    /// and `tasks` using default [`ScopeLimits`].
    pub fn new(
        identity: ScopeKeypair,
        authorizer: Arc<dyn Authorizer>,
        source: Arc<dyn PathSource>,
        credentials: Arc<dyn CredentialProvider>,
        tasks: Arc<dyn TaskSpawner>,
    ) -> Self {
        Self::new_with_limits(
            identity,
            authorizer,
            source,
            credentials,
            tasks,
            ScopeLimits::default(),
        )
    }

    /// Creates an isolated Trust Scope with explicit clamped [`ScopeLimits`].
    pub fn new_with_limits(
        identity: ScopeKeypair,
        authorizer: Arc<dyn Authorizer>,
        source: Arc<dyn PathSource>,
        credentials: Arc<dyn CredentialProvider>,
        tasks: Arc<dyn TaskSpawner>,
        limits: ScopeLimits,
    ) -> Self {
        let limits = limits.clamped();
        let cookies = CookieProtector::new(identity.public_key(), DEFAULT_ROTATION_INTERVAL);
        let scope = Arc::new(Scope {
            identity: Arc::new(identity),
            cookies,
            replay: SetupReplay::default(),
            auth: Arc::new(AuthGate::with_limits(authorizer, limits.auth)),
            source,
            credentials,
            tasks,
            pending: Arc::new(Semaphore::new(limits.max_pending)),
            sessions: Arc::new(Semaphore::new(limits.max_sessions)),
            endpoints: Default::default(),
            stream_carriers: Default::default(),
            datagram_carriers: Default::default(),
            stream_transits: Default::default(),
            datagram_transits: Default::default(),
            stream_transit_prefixes: Default::default(),
            datagram_transit_prefixes: Default::default(),
            datagram_ports: Default::default(),
            node: Default::default(),
            wake_on_drop: watch::channel(()).0,
            port_count: Default::default(),
            max_datagram_ports: limits.max_datagram_ports,
        });
        for mut events in scope.auth.revocation_streams() {
            let weak = Arc::downgrade(&scope);
            let mut dropped = scope.wake_on_drop.subscribe();
            scope.tasks.spawn(Box::pin(async move {
                loop {
                    tokio::select! {
                        _ = dropped.changed() => break,
                        event = events.recv() => {
                            let Some(scope) = weak.upgrade() else { break };
                            match event {
                                Ok(Revocation::Peer(peer)) => scope.auth.revoke_peer_sessions(peer),
                                Ok(Revocation::Endpoint(ep)) => scope.auth.revoke_endpoint(&ep),
                                Ok(Revocation::Transit(name)) => {
                                    scope.auth.revoke_transit(&name, CoreErr::Revoked);
                                }
                                Ok(Revocation::All) => scope.auth.invalidate(),
                                Err(broadcast::error::RecvError::Lagged(_)) => {
                                    scope.auth.invalidate();
                                }
                                Err(broadcast::error::RecvError::Closed) => break,
                            }
                        }
                    }
                }
            }));
        }
        Self(scope)
    }

    /// Creates a non-owning [`WeakScope`] handle to break `Arc` reference cycles.
    pub fn downgrade(&self) -> WeakScope {
        WeakScope(Arc::downgrade(&self.0))
    }

    /// Returns this scope's X25519 static public key.
    pub fn public_key(&self) -> PublicKey {
        self.0.identity.public_key()
    }

    /// Returns this scope's unlinkable 8-byte [`ScopeKid`].
    pub fn kid(&self) -> ScopeKid {
        self.0.identity.kid()
    }

    /// Returns a shared handle to this scope's identity keypair.
    pub fn identity(&self) -> Arc<ScopeKeypair> {
        self.0.identity.clone()
    }

    /// Returns a shared handle to this scope's [`AuthGate`].
    pub fn auth_gate(&self) -> Arc<AuthGate> {
        self.0.auth.clone()
    }

    /// Enables or disables stateless rotating `MAC2` flood-cookie challenges on this scope
    /// (protects both published endpoints and published named transits).
    pub fn set_under_load(&self, under_load: bool) {
        self.0.cookies.set_under_load(under_load);
    }

    /// Returns `true` if `MAC2` flood-cookie challenges are currently enabled on this scope.
    pub fn is_under_load(&self) -> bool {
        self.0.cookies.is_under_load()
    }

    /// Applies a local hard veto on `peer`, immediately tearing down all active sessions/circuits.
    pub fn revoke_peer(&self, peer: &PublicKey) {
        self.0.auth.revoke_peer(*peer);
    }

    /// Lifts a previous local hard veto on `peer`, allowing future sessions to be re-admitted.
    pub fn unrevoke_peer(&self, peer: &PublicKey) {
        self.0.auth.unrevoke_peer(*peer);
    }

    /// Immediately tears down all active transit circuits admitted through `name` across both planes.
    pub fn revoke_transit(&self, name: &str) {
        self.0.auth.revoke_transit(name, CoreErr::Revoked);
    }

    /// Registers a local outbound Stream carrier used only as a first-hop when this scope dials out.
    /// Never exposes this node for inbound forwarding (default-deny forwarding).
    pub fn register_stream_carrier<C: StreamChannel>(
        &self,
        name: &str,
        carrier: Arc<C>,
    ) -> Result<(), CoreErr> {
        validate_name(name)?;
        let erased: Arc<dyn DynStreamChannel> = carrier;
        insert(&self.0.stream_carriers, name.to_owned(), erased)
    }

    /// Registers a local outbound Datagram carrier used only as a first-hop when this scope dials out.
    /// Never exposes this node for inbound forwarding (default-deny forwarding).
    pub fn register_datagram_carrier<C: DatagramChannel>(
        &self,
        name: &str,
        carrier: Arc<C>,
    ) -> Result<(), CoreErr> {
        validate_name(name)?;
        let erased: Arc<dyn DynDatagramChannel> = carrier;
        insert(&self.0.datagram_carriers, name.to_owned(), erased)
    }

    /// Publishes an explicit Stream endpoint inside this Trust Scope.
    pub fn publish_stream<H: StreamEndpointHandler>(
        &self,
        name: &str,
        handler: Arc<H>,
    ) -> Result<PublishGuard, CoreErr> {
        let erased: Arc<dyn DynStreamEndpointHandler> = handler;
        self.publish_endpoint(name, PublishedEndpoint::Stream(erased))
    }

    /// Publishes an explicit Datagram endpoint inside this Trust Scope with minimum floor `min_mtu`.
    pub fn publish_datagram<H: DatagramEndpointHandler>(
        &self,
        name: &str,
        min_mtu: u16,
        handler: Arc<H>,
    ) -> Result<PublishGuard, CoreErr> {
        if min_mtu < DATAGRAM_MTU {
            return Err(CoreErr::MtuTooSmall(min_mtu));
        }
        let erased: Arc<dyn DynDatagramEndpointHandler> = handler;
        self.publish_endpoint(name, PublishedEndpoint::Datagram(min_mtu, erased))
    }

    fn publish_endpoint(
        &self,
        name: &str,
        published: PublishedEndpoint,
    ) -> Result<PublishGuard, CoreErr> {
        validate_name(name)?;
        insert(&self.0.endpoints, name.to_owned(), Arc::new(published))?;
        Ok(PublishGuard {
            scope: Arc::downgrade(&self.0),
            kind: PublishKind::Endpoint(name.into()),
        })
    }

    /// Publishes a named Stream forwarding transit (e.g., `"to-prod"`).
    /// Inbound hops authenticate directly against this scope's keypair and [`Authorizer`].
    pub fn publish_stream_transit<H: StreamTransitHandler>(
        &self,
        name: &str,
        handler: Arc<H>,
    ) -> Result<PublishGuard, CoreErr> {
        validate_name(name)?;
        let erased: Arc<dyn DynStreamTransitHandler> = handler;
        insert(&self.0.stream_transits, name.to_owned(), erased)?;
        Ok(PublishGuard {
            scope: Arc::downgrade(&self.0),
            kind: PublishKind::StreamTransit(name.into()),
        })
    }

    /// Publishes a named Datagram forwarding transit (e.g., `"to-prod"`).
    pub fn publish_datagram_transit<H: DatagramTransitHandler>(
        &self,
        name: &str,
        handler: Arc<H>,
    ) -> Result<PublishGuard, CoreErr> {
        validate_name(name)?;
        let erased: Arc<dyn DynDatagramTransitHandler> = handler;
        insert(&self.0.datagram_transits, name.to_owned(), erased)?;
        Ok(PublishGuard {
            scope: Arc::downgrade(&self.0),
            kind: PublishKind::DatagramTransit(name.into()),
        })
    }

    /// Convenience helper publishing a fixed-destination Stream transit route hiding `channel`
    /// and `locator` behind logical name `name`.
    pub fn publish_stream_route<C: StreamChannel>(
        &self,
        name: &str,
        channel: C,
        locator: impl Into<Vec<u8>>,
    ) -> Result<PublishGuard, CoreErr> {
        self.publish_stream_transit(name, Arc::new(StaticTransit::new(channel, locator)))
    }

    /// Convenience helper publishing a fixed-destination Datagram transit route hiding `channel`
    /// and `locator` behind logical name `name`.
    pub fn publish_datagram_route<C: DatagramChannel>(
        &self,
        name: &str,
        channel: C,
        locator: impl Into<Vec<u8>>,
    ) -> Result<PublishGuard, CoreErr> {
        self.publish_datagram_transit(name, Arc::new(StaticTransit::new(channel, locator)))
    }

    /// Publishes a prefix-matched Stream transit handler (e.g., `"relay/"` matching `"relay/bob"`).
    /// The handler receives the suffix after `prefix`, while [`Authorizer`] evaluates the full name.
    pub fn publish_stream_transit_prefix<H: StreamTransitHandler>(
        &self,
        prefix: &str,
        handler: Arc<H>,
    ) -> Result<PublishGuard, CoreErr> {
        validate_name(prefix)?;
        let erased: Arc<dyn DynStreamTransitHandler> = handler;
        insert(&self.0.stream_transit_prefixes, prefix.to_owned(), erased)?;
        Ok(PublishGuard {
            scope: Arc::downgrade(&self.0),
            kind: PublishKind::StreamTransitPrefix(prefix.into()),
        })
    }

    /// Publishes a prefix-matched Datagram transit handler (e.g., `"relay/"` matching `"relay/bob"`).
    pub fn publish_datagram_transit_prefix<H: DatagramTransitHandler>(
        &self,
        prefix: &str,
        handler: Arc<H>,
    ) -> Result<PublishGuard, CoreErr> {
        validate_name(prefix)?;
        let erased: Arc<dyn DynDatagramTransitHandler> = handler;
        insert(&self.0.datagram_transit_prefixes, prefix.to_owned(), erased)?;
        Ok(PublishGuard {
            scope: Arc::downgrade(&self.0),
            kind: PublishKind::DatagramTransitPrefix(prefix.into()),
        })
    }

    /// Attaches an explicitly accepted carrier stream to this Trust Scope.
    pub fn accept_stream<S: AsyncStream>(&self, stream: S) -> Result<(), CoreErr> {
        let permit = self
            .0
            .pending
            .clone()
            .try_acquire_owned()
            .map_err(|_| CoreErr::Busy)?;
        let scope = self.0.clone();
        let stream = stream.into_dyn_stream();
        self.0.tasks.spawn(Box::pin(async move {
            let _ = inbound::stream(scope, stream, permit).await;
        }));
        Ok(())
    }

    /// Continuously accepts streams from any [`StreamListener`] and feeds them into this scope.
    pub async fn serve_stream_listener<L: StreamListener>(
        &self,
        listener: &L,
    ) -> Result<(), CoreErr> {
        loop {
            let stream = listener.accept().await?;
            let _ = self.accept_stream(stream);
        }
    }

    /// Continuously accepts datagram links from any [`DatagramListener`] and attaches them.
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

    /// Public stack-only front-door filter for carriers sharing a socket across peers.
    pub fn precheck_datagram_setup(&self, wire: &[u8]) -> bool {
        self.0.precheck_datagram_setup(wire)
    }

    /// Attaches a per-peer [`crate::DatagramLink`] to this scope's ingress dispatcher.
    pub fn attach_datagram<L: IntoDynDatagramLink>(
        &self,
        link: L,
    ) -> Result<DatagramIngress, CoreErr> {
        let port = DatagramPort::attach_scope(&self.0, link.into_dyn_link())?;
        Ok(DatagramIngress { port })
    }

    /// Completes the 1-RTT Stream handshake without transmitting the confirmation record yet,
    /// allowing out-of-core path racers to compare candidates before invoking `B`'s handler.
    pub async fn dial_stream_staged(
        &self,
        peer: PublicKey,
        ep: &str,
    ) -> Result<StagedStream, CoreErr> {
        let path = self.0.source.resolve_path(&peer, ep, Plane::Stream).await?;
        let result = dialer::stream_staged(&self.0, &path, peer, ep).await;
        if let Err(error) = &result {
            self.0
                .source
                .report_outcome(path.id, PathOutcome::Failed(error.clone()));
        }
        result
    }

    /// Dials an end-to-end authenticated Stream to `ep` on `peer` over the single explicit path
    /// resolved by [`PathSource`], fetching credentials automatically via [`CredentialProvider`].
    pub async fn dial_stream(&self, peer: PublicKey, ep: &str) -> Result<E2eStream, CoreErr> {
        let staged = self.dial_stream_staged(peer, ep).await?;
        let path_id = staged.path_id();
        let result = staged.confirm().await;
        if let Err(error) = &result {
            self.0
                .source
                .report_outcome(path_id, PathOutcome::Failed(error.clone()));
        }
        result
    }

    /// Completes the 1-RTT Datagram handshake without transmitting the confirmation frame yet,
    /// allowing out-of-core path racers to compare candidates with zero destination side effects.
    pub async fn dial_datagram_staged(
        &self,
        peer: PublicKey,
        ep: &str,
        min_mtu: u16,
    ) -> Result<StagedDatagram, CoreErr> {
        let path = self
            .0
            .source
            .resolve_path(&peer, ep, Plane::Datagram)
            .await?;
        let result = dialer::datagram_staged(&self.0, &path, peer, ep, min_mtu).await;
        if let Err(error) = &result {
            self.0
                .source
                .report_outcome(path.id, PathOutcome::Failed(error.clone()));
        }
        result
    }

    /// Dials an end-to-end authenticated Datagram session to `ep` on `peer` with floor `min_mtu`,
    /// fetching credentials automatically via [`CredentialProvider`].
    pub async fn dial_datagram(
        &self,
        peer: PublicKey,
        ep: &str,
        min_mtu: u16,
    ) -> Result<E2eDatagram, CoreErr> {
        let staged = self.dial_datagram_staged(peer, ep, min_mtu).await?;
        let path_id = staged.path_id();
        let result = staged.confirm().await;
        if let Err(error) = &result {
            self.0
                .source
                .report_outcome(path_id, PathOutcome::Failed(error.clone()));
        }
        result
    }
}

pub(crate) struct ResolvedTransit<H> {
    pub handler: H,
    pub subtarget: String,
    pub prefix: Option<String>,
}

impl Scope {
    pub fn precheck_datagram_setup(&self, wire: &[u8]) -> bool {
        let Ok(hdr) = setup::ForwardHeader::parse(wire) else {
            return false;
        };
        if hdr.upstream == crate::cid::Cid::UNBOUND {
            return false;
        }
        let Ok(segment) = setup::Segment::parse(&wire[8..]) else {
            return false;
        };
        if segment.plane != Plane::Datagram {
            return false;
        }
        self.identity
            .verify_mac1_with_flag(segment.encrypted, segment.has_mac2)
    }

    pub(crate) fn precheck_stream_segment(&self, segment: &[u8], has_mac2: bool) -> bool {
        self.identity.verify_mac1_with_flag(segment, has_mac2)
    }

    pub fn stream_carrier(&self, name: &str) -> Result<Arc<dyn DynStreamChannel>, CoreErr> {
        self.stream_carriers
            .lock()
            .get(name)
            .cloned()
            .ok_or(CoreErr::Unpublished)
    }

    pub fn datagram_carrier(&self, name: &str) -> Result<Arc<dyn DynDatagramChannel>, CoreErr> {
        self.datagram_carriers
            .lock()
            .get(name)
            .cloned()
            .ok_or(CoreErr::Unpublished)
    }

    pub(crate) fn resolve_stream_transit(
        &self,
        target: &str,
    ) -> Result<ResolvedTransit<Arc<dyn DynStreamTransitHandler>>, CoreErr> {
        if let Some(resolved) =
            resolve_in_tables(&self.stream_transits, &self.stream_transit_prefixes, target)
        {
            return Ok(resolved);
        }
        if has_in_tables(
            &self.datagram_transits,
            &self.datagram_transit_prefixes,
            target,
        ) {
            return Err(CoreErr::WrongPlane);
        }
        Err(CoreErr::Unpublished)
    }

    pub(crate) fn resolve_datagram_transit(
        &self,
        target: &str,
    ) -> Result<ResolvedTransit<Arc<dyn DynDatagramTransitHandler>>, CoreErr> {
        if let Some(resolved) = resolve_in_tables(
            &self.datagram_transits,
            &self.datagram_transit_prefixes,
            target,
        ) {
            return Ok(resolved);
        }
        if has_in_tables(&self.stream_transits, &self.stream_transit_prefixes, target) {
            return Err(CoreErr::WrongPlane);
        }
        Err(CoreErr::Unpublished)
    }

    pub(crate) fn is_stream_transit_published(
        &self,
        target: &str,
        prefix: Option<&str>,
        expected: &Arc<dyn DynStreamTransitHandler>,
    ) -> bool {
        match prefix {
            Some(p) => self
                .stream_transit_prefixes
                .lock()
                .get(p)
                .is_some_and(|h| Arc::ptr_eq(h, expected)),
            None => self
                .stream_transits
                .lock()
                .get(target)
                .is_some_and(|h| Arc::ptr_eq(h, expected)),
        }
    }

    pub(crate) fn is_datagram_transit_published(
        &self,
        target: &str,
        prefix: Option<&str>,
        expected: &Arc<dyn DynDatagramTransitHandler>,
    ) -> bool {
        match prefix {
            Some(p) => self
                .datagram_transit_prefixes
                .lock()
                .get(p)
                .is_some_and(|h| Arc::ptr_eq(h, expected)),
            None => self
                .datagram_transits
                .lock()
                .get(target)
                .is_some_and(|h| Arc::ptr_eq(h, expected)),
        }
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
                (n < self.max_datagram_ports).then_some(n + 1)
            })
            .map(|_| ())
            .map_err(|_| CoreErr::Busy)
    }

    pub(crate) fn remember_datagram_port(&self, port: &Arc<DatagramPort>) {
        let id = port.link.link_id();
        let mut ports = self.datagram_ports.lock();
        if ports.len() >= 256 {
            ports.retain(|_, existing| existing.strong_count() != 0);
        }
        ports.entry(id).or_insert_with(|| Arc::downgrade(port));
    }
}

fn validate_name(name: &str) -> Result<(), CoreErr> {
    if name.is_empty() || name.len() > 255 {
        Err(CoreErr::Malformed)
    } else {
        Ok(())
    }
}

fn resolve_in_tables<H: Clone>(
    exact: &Mutex<HashMap<String, H>>,
    prefixes: &Mutex<HashMap<String, H>>,
    target: &str,
) -> Option<ResolvedTransit<H>> {
    if let Some(handler) = exact.lock().get(target).cloned() {
        return Some(ResolvedTransit {
            handler,
            subtarget: target.to_owned(),
            prefix: None,
        });
    }
    let prefixes = prefixes.lock();
    prefixes
        .iter()
        .filter(|(p, _)| target.starts_with(p.as_str()) && target.len() > p.len())
        .max_by_key(|(p, _)| p.len())
        .map(|(p, h)| ResolvedTransit {
            handler: h.clone(),
            subtarget: target[p.len()..].to_owned(),
            prefix: Some(p.clone()),
        })
}

fn has_in_tables<H>(
    exact: &Mutex<HashMap<String, H>>,
    prefixes: &Mutex<HashMap<String, H>>,
    target: &str,
) -> bool {
    exact.lock().contains_key(target)
        || prefixes
            .lock()
            .keys()
            .any(|p| target.starts_with(p.as_str()) && target.len() > p.len())
}

fn insert<K: std::hash::Hash + Eq, V>(
    table: &Mutex<HashMap<K, V>>,
    key: K,
    value: V,
) -> Result<(), CoreErr> {
    use std::collections::hash_map::Entry;
    match table.lock().entry(key) {
        Entry::Vacant(entry) => {
            entry.insert(value);
            Ok(())
        }
        Entry::Occupied(_) => Err(CoreErr::AlreadyPublished),
    }
}
