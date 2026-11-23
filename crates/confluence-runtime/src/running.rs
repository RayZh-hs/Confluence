use crate::{
    ForwardKind, NodePlan, PreparedNode, Registration, RegistrationKind, RuntimeError, ScopePlan,
};
use confluence_core::{BoxFut, CoreErr, Node, Plane, PublishGuard, ScopeInstance, TaskSpawner};
use confluence_edge::{Destination, serve_local_tcp, serve_local_udp};
use confluence_net::{TcpCarrier, serve_tcp_node};
use confluence_plugins::StaticPathSource;
use confluence_relay::{PassiveStreamPool, RelayClientDatagramLink, RelayMux, RelayService};
use parking_lot::Mutex;
use std::{collections::HashMap, future::Future, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, UdpSocket},
    task::JoinSet,
};

type Service = BoxFut<'static, RuntimeError>;

/// Actual bound address of a local forwarder, including the OS-assigned port.
#[derive(Debug, Clone)]
pub struct BoundForward {
    pub scope: String,
    pub plane: Plane,
    pub destination: Destination,
    pub addr: SocketAddr,
}

impl PreparedNode {
    /// Starts serving. If startup fails, cancels and joins the managed services.
    pub async fn start(self) -> Result<RunningNode, RuntimeError> {
        let workers = Arc::new(NodeWorkers::new());
        let mut running = RunningNode {
            node: Node::new(workers.clone()),
            workers,
            scopes: HashMap::new(),
            tcp_listener_addrs: Vec::new(),
            udp_listener_addrs: Vec::new(),
            forwards: Vec::new(),
            publications: Vec::new(),
            pools: Vec::new(),
            services: JoinSet::new(),
        };
        if let Err(error) = running.initialize(self.0).await {
            running.shutdown().await;
            return Err(error);
        }
        Ok(running)
    }
}

/// Owns listeners, forwarders, relay registrations, and publications for a node.
pub struct RunningNode {
    node: Node,
    workers: Arc<NodeWorkers>,
    scopes: HashMap<String, ScopeInstance>,
    tcp_listener_addrs: Vec<SocketAddr>,
    udp_listener_addrs: Vec<SocketAddr>,
    forwards: Vec<BoundForward>,
    publications: Vec<PublishGuard>,
    pools: Vec<Arc<PassiveStreamPool>>,
    services: JoinSet<RuntimeError>,
}

impl RunningNode {
    pub fn node(&self) -> &Node {
        &self.node
    }

    pub fn scope(&self, name: &str) -> Option<&ScopeInstance> {
        self.scopes.get(name)
    }

    pub fn tcp_listener_addrs(&self) -> &[SocketAddr] {
        &self.tcp_listener_addrs
    }

    pub fn udp_listener_addrs(&self) -> &[SocketAddr] {
        &self.udp_listener_addrs
    }

    pub fn forwards(&self) -> &[BoundForward] {
        &self.forwards
    }

    /// Serves until the caller's shutdown signal fires or a managed service stops.
    pub async fn run_until(
        mut self,
        shutdown: impl Future<Output = std::io::Result<()>>,
    ) -> Result<(), RuntimeError> {
        let result = tokio::select! {
            signal = shutdown => signal.map_err(|error| RuntimeError::io("shutdown signal", error)),
            service = self.services.join_next(), if !self.services.is_empty() => {
                Err(service.expect("a service was running").unwrap_or_else(RuntimeError::from))
            }
        };
        self.shutdown().await;
        result
    }

    /// Stops accepting traffic and waits for the node's managed tasks to finish cancellation.
    pub async fn shutdown(mut self) {
        self.stop_services();
        let workers = self.workers.take();
        self.services.shutdown().await;
        if let Some(mut workers) = workers {
            workers.shutdown().await;
        }
        for pool in &self.pools {
            pool.shutdown().await;
        }
    }

    async fn initialize(&mut self, plan: NodePlan) -> Result<(), RuntimeError> {
        let mut local_services = Vec::new();
        let mut ingress_services = Vec::new();
        let mut relays = Vec::new();
        let mut registrations = Vec::new();

        for plan in plan.scopes {
            let ScopePlan {
                name,
                identity,
                authorizer,
                path_source,
                credentials,
                limits,
                under_load,
                routes,
                install,
                forwards,
                relay,
                registrations: scope_registrations,
                #[cfg(unix)]
                admin,
                ..
            } = plan;
            let mut builder = ScopeInstance::builder(identity, self.workers.clone())
                .limits(limits)
                .under_load(under_load);
            if let Some(authorizer) = authorizer {
                builder = builder.authorizer(authorizer);
            }
            if let Some(credentials) = credentials {
                builder = builder.credentials(credentials);
            }
            if let Some(source) = path_source {
                builder = builder.routes(source);
            } else if !routes.is_empty() {
                let source = StaticPathSource::default();
                for (dst, plane, path) in routes {
                    source.set(dst.peer, dst.endpoint, plane, path);
                }
                builder = builder.routes(Arc::new(source));
            }
            let scope = builder.build();
            self.node
                .add_scope(scope.clone())
                .map_err(|error| RuntimeError::core(format!("add scope {name:?}"), error))?;
            for (operation, install) in install {
                install(&scope, &mut self.publications).map_err(|error| {
                    RuntimeError::core(format!("scope {name:?}: {operation}"), error)
                })?;
            }
            if let Some(relay) = relay {
                let publish = || -> Result<_, CoreErr> {
                    let service = RelayService::new(
                        &scope,
                        &relay.prefix,
                        relay.verifier,
                        relay.stream_mtu,
                        relay.datagram_mtu,
                    )?;
                    let handler = Arc::new(service.clone());
                    self.publications
                        .push(scope.publish_stream_transit_prefix(&relay.prefix, handler.clone())?);
                    self.publications
                        .push(scope.publish_datagram_transit_prefix(&relay.prefix, handler)?);
                    Ok(service)
                };
                relays.push(publish().map_err(|error| {
                    RuntimeError::core(format!("publish relay in scope {name:?}"), error)
                })?);
            }

            for forward in forwards {
                let destination = forward.destination;
                let addr = forward.addr;
                let operation = format!(
                    "{} forward in scope {name:?} on {addr}",
                    forward.kind.plane()
                );
                let (addr, service) = match forward.kind {
                    ForwardKind::Tcp => {
                        let listener = TcpListener::bind(addr).await.map_err(|error| {
                            RuntimeError::io(format!("bind {operation}"), error)
                        })?;
                        let addr = listener
                            .local_addr()
                            .map_err(|error| RuntimeError::io(&operation, error))?;
                        let service = core_service(
                            operation,
                            serve_local_tcp(listener, scope.clone(), destination.clone()),
                        );
                        (addr, service)
                    }
                    ForwardKind::Udp(min_mtu) => {
                        let socket = UdpSocket::bind(addr).await.map_err(|error| {
                            RuntimeError::io(format!("bind {operation}"), error)
                        })?;
                        let addr = socket
                            .local_addr()
                            .map_err(|error| RuntimeError::io(&operation, error))?;
                        let service = core_service(
                            operation,
                            serve_local_udp(socket, scope.clone(), destination.clone(), min_mtu),
                        );
                        (addr, service)
                    }
                };
                local_services.push(service);
                self.forwards.push(BoundForward {
                    scope: name.clone(),
                    plane: forward.kind.plane(),
                    destination,
                    addr,
                });
            }
            #[cfg(unix)]
            if let Some(path) = admin {
                use confluence_edge::admin::AdminSocket;

                let operation = format!("admin socket {}", path.display());
                let socket = AdminSocket::bind(&path)
                    .map_err(|error| RuntimeError::io(format!("bind {operation}"), error))?;
                let scope = scope.clone();
                local_services.push(Box::pin(async move {
                    match socket.serve(scope).await {
                        Ok(()) => RuntimeError::ServiceExited(operation),
                        Err(error) => RuntimeError::io(operation, error),
                    }
                }));
            }
            for registration in scope_registrations {
                registrations.push((scope.clone(), registration));
            }
            self.scopes.insert(name, scope);
        }

        let mux = RelayMux::try_new(relays)
            .map_err(|error| RuntimeError::core("configure relay ingress", error))?;
        for (addr, carrier) in plan.tcp {
            let operation = format!("TCP ingress on {addr}");
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|error| RuntimeError::io(format!("bind {operation}"), error))?;
            self.tcp_listener_addrs.push(
                listener
                    .local_addr()
                    .map_err(|error| RuntimeError::io(&operation, error))?,
            );
            let node = self.node.clone();
            let mux = mux.clone();
            ingress_services.push(core_service(operation, async move {
                if mux.is_empty() {
                    serve_tcp_node(listener, node, carrier).await
                } else {
                    mux.serve_tcp_node(listener, node, carrier).await
                }
            }));
        }
        for (addr, carrier) in plan.udp {
            let operation = format!("UDP ingress on {addr}");
            let ingress = carrier
                .bind(addr)
                .map_err(|error| RuntimeError::core(format!("bind {operation}"), error))?;
            self.udp_listener_addrs.push(
                ingress
                    .local_addr()
                    .map_err(|error| RuntimeError::core(&operation, error))?,
            );
            let node = self.node.clone();
            let mux = mux.clone();
            ingress_services.push(core_service(operation, async move {
                if mux.is_empty() {
                    ingress.serve_node(node).await
                } else {
                    mux.serve_udp_node(ingress, node).await
                }
            }));
        }
        // Ingress can host the relay used by a local scope. Local forwarders only
        // begin serving after every startup registration has succeeded.
        for service in ingress_services {
            self.services.spawn(service);
        }
        for (scope, registration) in registrations {
            self.register_presence(scope, registration).await?;
        }
        for service in local_services {
            self.services.spawn(service);
        }
        Ok(())
    }

    async fn register_presence(
        &mut self,
        scope: ScopeInstance,
        registration: Registration,
    ) -> Result<(), RuntimeError> {
        let Registration {
            addr,
            presence,
            kind,
        } = registration;
        let operation = format!("relay presence {:?} at {addr}", presence.name);
        match kind {
            RegistrationKind::Tcp(pool_size) => {
                let pool = PassiveStreamPool::start(
                    Arc::new(TcpCarrier::default()),
                    scope.identity(),
                    addr.to_string().into_bytes(),
                    presence.relay,
                    presence.name,
                    presence.credential.to_vec(),
                    pool_size,
                )
                .await
                .map_err(|error| RuntimeError::core(&operation, error))?;
                self.pools.push(pool.clone());
                self.services.spawn(core_service(operation, async move {
                    scope.serve_stream_listener(&*pool).await
                }));
            }
            RegistrationKind::Udp { carrier, keepalive } => {
                let bind = if addr.is_ipv4() {
                    SocketAddr::from(([0; 4], 0))
                } else {
                    SocketAddr::from(([0; 8], 0))
                };
                let raw = carrier
                    .connect_from(bind, addr)
                    .await
                    .map_err(|error| RuntimeError::core(&operation, error))?;
                let link = RelayClientDatagramLink::new(raw);
                let identity = scope.identity();
                let lease = link
                    .register_presence(
                        &identity,
                        presence.relay,
                        &presence.name,
                        &presence.credential,
                    )
                    .await
                    .map_err(|error| RuntimeError::core(&operation, error))?;
                let ingress = scope
                    .attach_datagram(link.clone())
                    .map_err(|error| RuntimeError::core(&operation, error))?;

                self.services.spawn(core_service(operation, async move {
                    let mut delay = keepalive.min(lease.ttl / 2).max(Duration::from_millis(1));
                    loop {
                        tokio::select! {
                            error = ingress.closed() => return Err(error),
                            _ = tokio::time::sleep(delay) => {
                                delay = match link.register_presence(
                                    &identity, presence.relay, &presence.name, &presence.credential,
                                ).await {
                                    Ok(lease) => keepalive.min(lease.ttl / 2),
                                    Err(_) => keepalive.min(Duration::from_secs(1)),
                                }.max(Duration::from_millis(1));
                            }
                        }
                    }
                }));
            }
        }
        Ok(())
    }

    fn stop_services(&mut self) {
        self.services.abort_all();
        for pool in &self.pools {
            pool.close();
        }
        self.publications.clear();
    }
}

impl Drop for RunningNode {
    fn drop(&mut self) {
        self.stop_services();
        drop(self.workers.take());
    }
}

fn core_service(
    operation: String,
    serve: impl Future<Output = Result<(), CoreErr>> + Send + 'static,
) -> Service {
    Box::pin(async move {
        match serve.await {
            Ok(()) => RuntimeError::ServiceExited(operation),
            Err(error) => RuntimeError::core(operation, error),
        }
    })
}

struct NodeWorkers(Mutex<Option<JoinSet<()>>>);

impl NodeWorkers {
    fn new() -> Self {
        Self(Mutex::new(Some(JoinSet::new())))
    }

    fn take(&self) -> Option<JoinSet<()>> {
        self.0.lock().take()
    }
}

impl TaskSpawner for NodeWorkers {
    fn spawn(&self, task: BoxFut<'static, ()>) {
        if let Some(workers) = self.0.lock().as_mut() {
            while workers.try_join_next().is_some() {}
            workers.spawn(task);
        }
    }
}
