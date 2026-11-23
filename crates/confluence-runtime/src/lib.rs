//! Compose and run Confluence nodes from ordinary Rust applications.

#![forbid(unsafe_code)]

mod running;

pub use running::{BoundForward, RunningNode};

use confluence_core::{
    Authorizer, CoreErr, CredentialProvider, DATAGRAM_MTU, DatagramChannel,
    DatagramEndpointHandler, DatagramTransitHandler, ExplicitPath, PathSource, Plane, PublicKey,
    PublishGuard, ScopeInstance, ScopeKeypair, ScopeKid, ScopeLimits, StreamChannel,
    StreamEndpointHandler, StreamTransitHandler,
};
use confluence_edge::Destination;
use confluence_net::{TcpCarrier, UdpCarrier};
use confluence_relay::RelayRegistrationVerifier;
use std::{collections::HashSet, io, net::SocketAddr, sync::Arc, time::Duration};
use zeroize::Zeroizing;

/// Failure to prepare, start, or serve a node.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("{0}")]
    Invalid(String),
    #[error("{operation}: {source}")]
    Core {
        operation: String,
        #[source]
        source: CoreErr,
    },
    #[error("{operation}: {source}")]
    Io {
        operation: String,
        #[source]
        source: io::Error,
    },
    #[error("{0} stopped unexpectedly")]
    ServiceExited(String),
    #[error("node service task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
}

impl RuntimeError {
    fn core(operation: impl Into<String>, source: CoreErr) -> Self {
        Self::Core {
            operation: operation.into(),
            source,
        }
    }

    fn io(operation: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            operation: operation.into(),
            source,
        }
    }
}

/// Local deployment wiring. Constructing and preparing a plan does not start network I/O.
#[derive(Default)]
pub struct NodePlan {
    scopes: Vec<ScopePlan>,
    tcp: Vec<(SocketAddr, TcpCarrier)>,
    udp: Vec<(SocketAddr, UdpCarrier)>,
}

impl NodePlan {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a named trust scope. Names are local to the deployment.
    pub fn scope(
        &mut self,
        name: impl Into<String>,
        identity: ScopeKeypair,
    ) -> Result<&mut ScopePlan, RuntimeError> {
        let name = name.into();
        check_name("scope", &name)?;
        if self.scopes.iter().any(|scope| scope.name == name) {
            return Err(RuntimeError::Invalid(format!("duplicate scope {name:?}")));
        }
        self.scopes.push(ScopePlan::new(name, identity));
        Ok(self.scopes.last_mut().expect("just added a scope"))
    }

    /// Listens for stream ingress on behalf of all scopes.
    pub fn listen_tcp(&mut self, addr: SocketAddr) -> &mut Self {
        self.listen_tcp_with(addr, TcpCarrier::default())
    }

    pub fn listen_tcp_with(&mut self, addr: SocketAddr, carrier: TcpCarrier) -> &mut Self {
        self.tcp.push((addr, carrier));
        self
    }

    /// Listens for datagram ingress on behalf of all scopes.
    pub fn listen_udp(&mut self, addr: SocketAddr, carrier: UdpCarrier) -> &mut Self {
        self.udp.push((addr, carrier));
        self
    }

    /// Validates the scopes and the static routes and forwards declared in this plan.
    pub fn prepare(self) -> Result<PreparedNode, RuntimeError> {
        if self.scopes.is_empty() {
            return Err(RuntimeError::Invalid(
                "a node needs at least one scope".into(),
            ));
        }
        let mut identities = HashSet::<ScopeKid>::new();
        for scope in &self.scopes {
            if !identities.insert(scope.identity.kid()) {
                return Err(RuntimeError::Invalid(format!(
                    "scope {:?} reuses a trust scope identity or KID",
                    scope.name
                )));
            }
            scope.validate()?;
        }
        Ok(PreparedNode(self))
    }
}

/// A validated plan ready to bind sockets and start serving.
pub struct PreparedNode(NodePlan);

type Install =
    Box<dyn FnOnce(&ScopeInstance, &mut Vec<PublishGuard>) -> Result<(), CoreErr> + Send>;

/// Wiring within one trust scope. Authorization, routing, and credentials use the Core seams.
pub struct ScopePlan {
    name: String,
    identity: ScopeKeypair,
    authorizer: Option<Arc<dyn Authorizer>>,
    path_source: Option<Arc<dyn PathSource>>,
    credentials: Option<Arc<dyn CredentialProvider>>,
    under_load: bool,
    limits: ScopeLimits,
    carriers: HashSet<(Plane, String)>,
    endpoints: HashSet<String>,
    transits: HashSet<(Plane, String)>,
    install: Vec<(String, Install)>,
    routes: Vec<(Destination, Plane, ExplicitPath)>,
    forwards: Vec<Forward>,
    relay: Option<Relay>,
    registrations: Vec<Registration>,
    #[cfg(unix)]
    admin: Option<std::path::PathBuf>,
}

impl ScopePlan {
    fn new(name: String, identity: ScopeKeypair) -> Self {
        Self {
            name,
            identity,
            authorizer: None,
            path_source: None,
            credentials: None,
            under_load: false,
            limits: ScopeLimits::default(),
            carriers: HashSet::new(),
            endpoints: HashSet::new(),
            transits: HashSet::new(),
            install: Vec::new(),
            routes: Vec::new(),
            forwards: Vec::new(),
            relay: None,
            registrations: Vec::new(),
            #[cfg(unix)]
            admin: None,
        }
    }

    pub fn authorizer(&mut self, authorizer: Arc<dyn Authorizer>) -> &mut Self {
        self.authorizer = Some(authorizer);
        self
    }

    /// Uses a caller-owned path source, including dynamic routes.
    pub fn path_source(&mut self, source: Arc<dyn PathSource>) -> &mut Self {
        self.path_source = Some(source);
        self
    }

    pub fn credentials(&mut self, provider: Arc<dyn CredentialProvider>) -> &mut Self {
        self.credentials = Some(provider);
        self
    }

    pub fn under_load(&mut self, enabled: bool) -> &mut Self {
        self.under_load = enabled;
        self
    }

    pub fn limits(&mut self, limits: ScopeLimits) -> &mut Self {
        self.limits = limits;
        self
    }

    pub fn stream_carrier<C: StreamChannel>(
        &mut self,
        name: &str,
        carrier: Arc<C>,
    ) -> Result<&mut Self, RuntimeError> {
        self.add_carrier(Plane::Stream, name, move |scope, name| {
            scope.register_stream_carrier(name, carrier)
        })
    }

    pub fn datagram_carrier<C: DatagramChannel>(
        &mut self,
        name: &str,
        carrier: Arc<C>,
    ) -> Result<&mut Self, RuntimeError> {
        self.add_carrier(Plane::Datagram, name, move |scope, name| {
            scope.register_datagram_carrier(name, carrier)
        })
    }

    fn add_carrier(
        &mut self,
        plane: Plane,
        name: &str,
        install: impl FnOnce(&ScopeInstance, &str) -> Result<(), CoreErr> + Send + 'static,
    ) -> Result<&mut Self, RuntimeError> {
        check_name("carrier", name)?;
        if !self.carriers.insert((plane, name.into())) {
            return Err(RuntimeError::Invalid(format!(
                "duplicate {plane} carrier {name:?}"
            )));
        }
        let name = name.to_owned();
        self.install.push((
            format!("register {plane} carrier {name:?}"),
            Box::new(move |scope, _| install(scope, &name)),
        ));
        Ok(self)
    }

    pub fn publish_stream<H: StreamEndpointHandler>(
        &mut self,
        name: &str,
        handler: Arc<H>,
    ) -> Result<&mut Self, RuntimeError> {
        self.add_endpoint(name, move |scope, name| scope.publish_stream(name, handler))
    }

    pub fn publish_datagram<H: DatagramEndpointHandler>(
        &mut self,
        name: &str,
        min_mtu: u16,
        handler: Arc<H>,
    ) -> Result<&mut Self, RuntimeError> {
        check_datagram_mtu(min_mtu)?;
        self.add_endpoint(name, move |scope, name| {
            scope.publish_datagram(name, min_mtu, handler)
        })
    }

    fn add_endpoint(
        &mut self,
        name: &str,
        publish: impl FnOnce(&ScopeInstance, &str) -> Result<PublishGuard, CoreErr> + Send + 'static,
    ) -> Result<&mut Self, RuntimeError> {
        check_name("endpoint", name)?;
        if !self.endpoints.insert(name.into()) {
            return Err(RuntimeError::Invalid(format!(
                "duplicate endpoint {name:?}"
            )));
        }
        self.add_publication(format!("publish endpoint {name:?}"), name, publish);
        Ok(self)
    }

    pub fn publish_stream_transit<H: StreamTransitHandler>(
        &mut self,
        name: &str,
        handler: Arc<H>,
    ) -> Result<&mut Self, RuntimeError> {
        self.add_transit(Plane::Stream, name, move |scope, name| {
            scope.publish_stream_transit(name, handler)
        })
    }

    pub fn publish_datagram_transit<H: DatagramTransitHandler>(
        &mut self,
        name: &str,
        handler: Arc<H>,
    ) -> Result<&mut Self, RuntimeError> {
        self.add_transit(Plane::Datagram, name, move |scope, name| {
            scope.publish_datagram_transit(name, handler)
        })
    }

    fn add_transit(
        &mut self,
        plane: Plane,
        name: &str,
        publish: impl FnOnce(&ScopeInstance, &str) -> Result<PublishGuard, CoreErr> + Send + 'static,
    ) -> Result<&mut Self, RuntimeError> {
        check_name("transit", name)?;
        if !self.transits.insert((plane, name.into())) {
            return Err(RuntimeError::Invalid(format!(
                "duplicate {plane} transit {name:?}"
            )));
        }
        self.add_publication(format!("publish {plane} transit {name:?}"), name, publish);
        Ok(self)
    }

    fn add_publication(
        &mut self,
        operation: String,
        name: &str,
        publish: impl FnOnce(&ScopeInstance, &str) -> Result<PublishGuard, CoreErr> + Send + 'static,
    ) {
        let name = name.to_owned();
        self.install.push((
            operation,
            Box::new(move |scope, guards| {
                guards.push(publish(scope, &name)?);
                Ok(())
            }),
        ));
    }

    /// Declares a static path. Set a custom path source for routing managed outside the plan.
    pub fn route(
        &mut self,
        destination: Destination,
        plane: Plane,
        path: ExplicitPath,
    ) -> &mut Self {
        self.routes.push((destination, plane, path));
        self
    }

    pub fn forward_tcp(&mut self, addr: SocketAddr, destination: Destination) -> &mut Self {
        self.forwards.push(Forward {
            addr,
            destination,
            kind: ForwardKind::Tcp,
        });
        self
    }

    /// Forwards local datagrams. A zero MTU uses the Core datagram floor.
    pub fn forward_udp(
        &mut self,
        addr: SocketAddr,
        destination: Destination,
        min_mtu: u16,
    ) -> &mut Self {
        self.forwards.push(Forward {
            addr,
            destination,
            kind: ForwardKind::Udp(min_mtu),
        });
        self
    }

    /// Publishes a passive relay prefix on both planes and shares the node's ingress ports.
    pub fn publish_relay(
        &mut self,
        prefix: &str,
        verifier: Arc<dyn RelayRegistrationVerifier>,
        stream_mtu: u16,
        datagram_mtu: u16,
    ) -> Result<&mut Self, RuntimeError> {
        check_name("relay prefix", prefix)?;
        check_datagram_mtu(datagram_mtu)?;
        if let Some(relay) = &self.relay {
            return Err(RuntimeError::Invalid(format!(
                "relay prefixes {:?} and {prefix:?} in scope {:?} share a registration key",
                relay.prefix, self.name,
            )));
        }
        self.relay = Some(Relay {
            prefix: prefix.into(),
            verifier,
            stream_mtu,
            datagram_mtu,
        });
        Ok(self)
    }

    /// Parks and replenishes TCP presence streams at a passive relay.
    pub fn register_relay_tcp(
        &mut self,
        addr: SocketAddr,
        presence: RelayPresence,
        pool_size: usize,
    ) -> &mut Self {
        self.registrations.push(Registration {
            addr,
            presence,
            kind: RegistrationKind::Tcp(pool_size),
        });
        self
    }

    /// Establishes a UDP presence at a passive relay and refreshes it while the node runs.
    pub fn register_relay_udp(
        &mut self,
        addr: SocketAddr,
        presence: RelayPresence,
        carrier: UdpCarrier,
        keepalive: Duration,
    ) -> &mut Self {
        self.registrations.push(Registration {
            addr,
            presence,
            kind: RegistrationKind::Udp { carrier, keepalive },
        });
        self
    }

    /// Enables the owner-only Unix administration socket for this scope.
    #[cfg(unix)]
    pub fn admin_socket(&mut self, path: impl Into<std::path::PathBuf>) -> &mut Self {
        self.admin = Some(path.into());
        self
    }

    fn validate(&self) -> Result<(), RuntimeError> {
        if self.path_source.is_some() && !self.routes.is_empty() {
            return Err(RuntimeError::Invalid(format!(
                "scope {:?} declares static routes and a custom path source",
                self.name
            )));
        }
        let mut routes = HashSet::new();
        for (destination, plane, path) in &self.routes {
            check_name("route endpoint", &destination.endpoint)?;
            if !self
                .carriers
                .contains(&(*plane, path.first_channel.clone()))
            {
                return Err(RuntimeError::Invalid(format!(
                    "scope {:?} route {} uses unknown {plane} carrier {:?}",
                    self.name, path.id, path.first_channel
                )));
            }
            if path.hops.len() > u8::MAX as usize {
                return Err(RuntimeError::Invalid(format!(
                    "route {} exceeds 255 hops",
                    path.id
                )));
            }
            for hop in &path.hops {
                check_name("hop target", &hop.target)?;
            }
            if !routes.insert((destination.peer, destination.endpoint.as_str(), *plane)) {
                return Err(RuntimeError::Invalid(format!(
                    "scope {:?} has multiple {plane} routes to {} / {:?}",
                    self.name, destination.peer, destination.endpoint
                )));
            }
        }
        for forward in &self.forwards {
            check_name("forward endpoint", &forward.destination.endpoint)?;
            if let ForwardKind::Udp(min_mtu) = forward.kind
                && min_mtu != 0
            {
                check_datagram_mtu(min_mtu)?;
            }
            let plane = forward.kind.plane();
            let dst = &forward.destination;
            if self.path_source.is_none()
                && !routes.contains(&(dst.peer, dst.endpoint.as_str(), plane))
            {
                return Err(RuntimeError::Invalid(format!(
                    "scope {:?} has no {plane} route for forward to {} / {:?}",
                    self.name, dst.peer, dst.endpoint
                )));
            }
        }
        for reg in &self.registrations {
            check_name("relay presence", &reg.presence.name)?;
            if let RegistrationKind::Udp { keepalive, .. } = &reg.kind
                && keepalive.is_zero()
            {
                return Err(RuntimeError::Invalid(
                    "relay keepalive must be positive".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Identity, slot name, and credential for registering at a passive relay.
#[derive(Clone)]
pub struct RelayPresence {
    relay: PublicKey,
    name: String,
    credential: Zeroizing<Vec<u8>>,
}

impl RelayPresence {
    pub fn new(relay: PublicKey, name: impl Into<String>, credential: Vec<u8>) -> Self {
        Self {
            relay,
            name: name.into(),
            credential: Zeroizing::new(credential),
        }
    }
}

struct Relay {
    prefix: String,
    verifier: Arc<dyn RelayRegistrationVerifier>,
    stream_mtu: u16,
    datagram_mtu: u16,
}

struct Registration {
    addr: SocketAddr,
    presence: RelayPresence,
    kind: RegistrationKind,
}

enum RegistrationKind {
    Tcp(usize),
    Udp {
        carrier: UdpCarrier,
        keepalive: Duration,
    },
}

struct Forward {
    addr: SocketAddr,
    destination: Destination,
    kind: ForwardKind,
}

#[derive(Clone, Copy)]
enum ForwardKind {
    Tcp,
    Udp(u16),
}

impl ForwardKind {
    fn plane(self) -> Plane {
        match self {
            Self::Tcp => Plane::Stream,
            Self::Udp(_) => Plane::Datagram,
        }
    }
}

fn check_name(kind: &str, name: &str) -> Result<(), RuntimeError> {
    if name.is_empty() || name.len() > u8::MAX as usize {
        return Err(RuntimeError::Invalid(format!(
            "{kind} name must be 1 to 255 bytes"
        )));
    }
    Ok(())
}

fn check_datagram_mtu(mtu: u16) -> Result<(), RuntimeError> {
    if mtu < DATAGRAM_MTU {
        return Err(RuntimeError::core(
            "datagram MTU",
            CoreErr::MtuTooSmall(mtu),
        ));
    }
    Ok(())
}
