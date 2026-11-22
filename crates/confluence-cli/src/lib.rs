//! Declarative TOML configuration schema, pre-bind validation, and node bootstrapper for `confluence-cli`.

#![forbid(unsafe_code)]

use confluence_core::{
    CoreErr, DATAGRAM_MTU, ExplicitPath, HopSpec, Node, Plane, PublicKey, PublishGuard,
    ScopeInstance, ScopeKeypair, StaticTransit,
};
use confluence_edge::{Destination, TcpTarget, UdpTarget, serve_local_tcp, serve_local_udp};
use confluence_net::{TcpCarrier, UdpCarrier, serve_tcp_node};
use confluence_plugins::{
    CredentialRuleConfig, PolicyConfig, RuleTargetKind, StaticCredentials, StaticPathSource,
    StaticPolicy, TokioSpawner,
};
use confluence_relay::{
    PassiveStreamPool, RegistrationRule, RelayClientDatagramLink, RelayMux, RelayService,
    StaticRegistrationRules,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
};

fn default_udp_mtu() -> u16 {
    1400
}

fn default_stream_mtu() -> u16 {
    16384
}

fn default_min_dg_mtu() -> u16 {
    DATAGRAM_MTU
}

fn default_keepalive_secs() -> u64 {
    30
}

fn default_pool_size() -> usize {
    4
}

fn default_reg_ttl_secs() -> u64 {
    120
}

fn default_any_action() -> RuleTargetKind {
    RuleTargetKind::Any
}

/// Isolated Trust Scope configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeConfig {
    /// Human-readable local scope name (used to wire config sections together; never sent on wire).
    pub name: String,
    /// 64-character lowercase hex X25519 secret key.
    pub secret_key: String,
    /// Enables WireGuard-style stateless rotating `MAC2` flood cookies on this scope
    /// (protects both published endpoints and published named transits).
    #[serde(default)]
    pub under_load: bool,
}

/// Originator-side credential entry loaded into a scope's [`StaticCredentials`] provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfig {
    pub scope: String,
    /// Optional verifier public key (`None` matches any verifier).
    pub verifier: Option<PublicKey>,
    /// Target kind (`"endpoint"`, `"transit"`, or `"any"`).
    #[serde(default = "default_any_action")]
    pub action: RuleTargetKind,
    /// Optional plane restriction (`"stream"` or `"datagram"`).
    pub plane: Option<Plane>,
    /// Optional target name pattern (`"*"` or `"prefix*"`).
    pub target: Option<String>,
    /// Opaque UTF-8 credential presented to the verifier.
    pub credential: String,
}

/// Shared UDP listener bound on this node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpListenerConfig {
    pub bind_addr: SocketAddr,
    #[serde(default = "default_udp_mtu")]
    pub mtu: u16,
}

/// Shared TCP listener bound on this node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpListenerConfig {
    pub listen_addr: SocketAddr,
    #[serde(default = "default_stream_mtu")]
    pub chunk_limit: u16,
}

/// Outbound first-hop native carrier mounted on a scope (never enables inbound forwarding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundCarrierConfig {
    pub scope: String,
    pub name: String,
    pub plane: Plane,
    #[serde(default = "default_udp_mtu")]
    pub mtu: u16,
}

/// Published named forwarding transit hiding a fixed downstream address behind a logical name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitConfig {
    pub scope: String,
    pub name: String,
    pub plane: Plane,
    pub target_addr: SocketAddr,
    #[serde(default = "default_udp_mtu")]
    pub mtu: u16,
}

/// Declarative rule authorizing NATed peers to register presence on a [`RelayTransitConfig`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayRegistrationRuleConfig {
    /// Allowed registering peer hex public keys, or `"*"` for any peer.
    pub peers: Vec<String>,
    /// Optional presence name pattern (`"*"` or `"prefix*"`).
    pub presence: Option<String>,
    /// Optional plane restriction (`"stream"` or `"datagram"`).
    pub plane: Option<Plane>,
    /// Optional required UTF-8 registration credential.
    pub required_credential: Option<String>,
    /// Registration lease TTL in seconds.
    #[serde(default = "default_reg_ttl_secs")]
    pub ttl_secs: u64,
}

/// Out-of-core zero-dialing single-port Passive Relay transit prefix mounted on a scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayTransitConfig {
    pub scope: String,
    /// Published transit prefix (e.g., `"relay/"` so callers target `"relay/bob"`).
    pub prefix: String,
    #[serde(default = "default_stream_mtu")]
    pub stream_mtu: u16,
    #[serde(default = "default_udp_mtu")]
    pub datagram_mtu: u16,
    /// Out-of-core registration rules controlling which NATed peers may register presence slots.
    #[serde(default)]
    pub registration_rules: Vec<RelayRegistrationRuleConfig>,
}

/// NAT-side passive presence registration to a remote [`RelayService`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayRegistrationConfig {
    pub scope: String,
    pub plane: Plane,
    pub relay_addr: SocketAddr,
    pub relay_pubkey: PublicKey,
    pub presence_id: String,
    pub credential: Option<String>,
    #[serde(default = "default_udp_mtu")]
    pub mtu: u16,
    #[serde(default = "default_keepalive_secs")]
    pub keepalive_secs: u64,
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
}

/// One named intermediate hop inside a declarative route entry (zero credentials, zero raw IPs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteHopConfig {
    pub peer: PublicKey,
    pub target: String,
}

/// Declarative explicit path entry loaded into [`StaticPathSource`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    pub id: u64,
    pub scope: String,
    pub target_pubkey: PublicKey,
    pub endpoint: String,
    pub plane: Plane,
    pub first_channel: String,
    pub first_locator: String,
    #[serde(default)]
    pub min_mtu: u16,
    #[serde(default)]
    pub hops: Vec<RouteHopConfig>,
}

/// Published local service exposed inside a Trust Scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishEdgeConfig {
    pub scope: String,
    pub endpoint: String,
    pub plane: Plane,
    pub local_target: SocketAddr,
    #[serde(default = "default_min_dg_mtu")]
    pub min_mtu: u16,
}

/// Local port forwarder dialing a remote published endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindEdgeConfig {
    pub scope: String,
    pub target_pubkey: PublicKey,
    pub endpoint: String,
    pub plane: Plane,
    pub listen_addr: SocketAddr,
    #[serde(default = "default_min_dg_mtu")]
    pub min_mtu: u16,
}

/// Optional explicit local-only `0600` Unix administration socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSocketConfig {
    pub scope: String,
    pub path: PathBuf,
}

/// Complete declarative configuration for a Confluence node instance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeConfig {
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub scopes: Vec<ScopeConfig>,
    #[serde(default)]
    pub credentials: Vec<CredentialConfig>,
    #[serde(default)]
    pub udp_listeners: Vec<UdpListenerConfig>,
    #[serde(default)]
    pub tcp_listeners: Vec<TcpListenerConfig>,
    #[serde(default)]
    pub outbound_carriers: Vec<OutboundCarrierConfig>,
    #[serde(default)]
    pub transits: Vec<TransitConfig>,
    #[serde(default)]
    pub relay_transits: Vec<RelayTransitConfig>,
    #[serde(default)]
    pub relay_registrations: Vec<RelayRegistrationConfig>,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    #[serde(default)]
    pub publish_endpoints: Vec<PublishEdgeConfig>,
    #[serde(default)]
    pub bind_endpoints: Vec<BindEdgeConfig>,
    pub admin_socket: Option<AdminSocketConfig>,
}

impl NodeConfig {
    /// Parses and validates a [`NodeConfig`] from TOML text.
    pub fn from_toml_str(toml_str: &str) -> Result<Self, String> {
        let cfg: Self = toml::from_str(toml_str).map_err(|e| format!("invalid TOML: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validates all keys, scope names, carriers, transits, MTUs, and cross-references before binding sockets.
    pub fn validate(&self) -> Result<(), String> {
        if self.scopes.is_empty() {
            return Err("configuration must define at least one [[scopes]] entry".into());
        }
        let mut scope_names: HashSet<&str> = HashSet::new();
        let mut scope_kids = HashSet::new();
        for sc in &self.scopes {
            if sc.name.is_empty() {
                return Err("scope name must not be empty".into());
            }
            if !scope_names.insert(sc.name.as_str()) {
                return Err(format!("duplicate scope name '{}'", sc.name));
            }
            let kp = ScopeKeypair::from_secret_hex(&sc.secret_key)
                .map_err(|_| format!("invalid secret_key hex in scope '{}'", sc.name))?;
            if !scope_kids.insert(kp.kid()) {
                return Err(format!("duplicate keypair/kid in scope '{}'", sc.name));
            }
        }

        for cred in &self.credentials {
            if !scope_names.contains(cred.scope.as_str()) {
                return Err(format!(
                    "credential references unknown scope '{}'",
                    cred.scope
                ));
            }
        }

        for u in &self.udp_listeners {
            if u.mtu < DATAGRAM_MTU {
                return Err(format!(
                    "udp_listener {} mtu {} below minimum {DATAGRAM_MTU}",
                    u.bind_addr, u.mtu
                ));
            }
        }

        let mut carriers: HashSet<(&str, Plane, &str)> = HashSet::new();
        for c in &self.outbound_carriers {
            if !scope_names.contains(c.scope.as_str()) {
                return Err(format!(
                    "outbound_carrier '{}' references unknown scope '{}'",
                    c.name, c.scope
                ));
            }
            if c.name.is_empty() || c.name.len() > 255 {
                return Err(format!("outbound_carrier '{}' has invalid name", c.name));
            }
            if c.plane == Plane::Datagram && c.mtu < DATAGRAM_MTU {
                return Err(format!(
                    "outbound datagram carrier '{}' mtu {} < {DATAGRAM_MTU}",
                    c.name, c.mtu
                ));
            }
            if !carriers.insert((c.scope.as_str(), c.plane, c.name.as_str())) {
                return Err(format!(
                    "duplicate {} outbound_carrier '{}' in scope '{}'",
                    c.plane, c.name, c.scope
                ));
            }
        }

        let mut transits: HashSet<(&str, Plane, &str)> = HashSet::new();
        for t in &self.transits {
            if !scope_names.contains(t.scope.as_str()) {
                return Err(format!(
                    "transit '{}' references unknown scope '{}'",
                    t.name, t.scope
                ));
            }
            if t.name.is_empty() || t.name.len() > 255 {
                return Err(format!("transit '{}' has invalid name", t.name));
            }
            if t.plane == Plane::Datagram && t.mtu < DATAGRAM_MTU {
                return Err(format!(
                    "datagram transit '{}' mtu {} < {DATAGRAM_MTU}",
                    t.name, t.mtu
                ));
            }
            if !transits.insert((t.scope.as_str(), t.plane, t.name.as_str())) {
                return Err(format!(
                    "duplicate {} transit '{}' in scope '{}'",
                    t.plane, t.name, t.scope
                ));
            }
        }

        let mut relay_prefixes: HashSet<(&str, &str)> = HashSet::new();
        for r in &self.relay_transits {
            if !scope_names.contains(r.scope.as_str()) {
                return Err(format!(
                    "relay_transit '{}' references unknown scope '{}'",
                    r.prefix, r.scope
                ));
            }
            if r.prefix.is_empty() || r.prefix.len() > 255 {
                return Err(format!("relay_transit '{}' has invalid prefix", r.prefix));
            }
            if r.datagram_mtu < DATAGRAM_MTU {
                return Err(format!(
                    "relay_transit '{}' datagram_mtu {} < {DATAGRAM_MTU}",
                    r.prefix, r.datagram_mtu
                ));
            }
            if !relay_prefixes.insert((r.scope.as_str(), r.prefix.as_str())) {
                return Err(format!(
                    "duplicate relay_transit prefix '{}' in scope '{}'",
                    r.prefix, r.scope
                ));
            }
        }

        for reg in &self.relay_registrations {
            if !scope_names.contains(reg.scope.as_str()) {
                return Err(format!(
                    "relay_registration references unknown scope '{}'",
                    reg.scope
                ));
            }
            if reg.presence_id.is_empty() || reg.presence_id.len() > 255 {
                return Err("relay_registration presence_id must be 1..=255 bytes".into());
            }
            if reg.plane == Plane::Datagram && reg.mtu < DATAGRAM_MTU {
                return Err(format!(
                    "relay_registration datagram mtu {} < {DATAGRAM_MTU}",
                    reg.mtu
                ));
            }
        }

        for route in &self.routes {
            if !scope_names.contains(route.scope.as_str()) {
                return Err(format!(
                    "route {} references unknown scope '{}'",
                    route.id, route.scope
                ));
            }
            if !carriers.contains(&(
                route.scope.as_str(),
                route.plane,
                route.first_channel.as_str(),
            )) {
                return Err(format!(
                    "route {} references unregistered {} outbound_carrier '{}' in scope '{}'",
                    route.id, route.plane, route.first_channel, route.scope
                ));
            }
            if route.endpoint.is_empty() || route.endpoint.len() > 255 {
                return Err(format!("route {} has invalid endpoint name", route.id));
            }
            for hop in &route.hops {
                if hop.target.is_empty() || hop.target.len() > 255 {
                    return Err(format!(
                        "route {} contains hop with invalid target name",
                        route.id
                    ));
                }
            }
        }

        let mut published_names: HashSet<(&str, &str)> = HashSet::new();
        for p in &self.publish_endpoints {
            if !scope_names.contains(p.scope.as_str()) {
                return Err(format!(
                    "publish_endpoint '{}' references unknown scope '{}'",
                    p.endpoint, p.scope
                ));
            }
            if p.endpoint.is_empty() || p.endpoint.len() > 255 {
                return Err(format!(
                    "publish_endpoint '{}' has invalid name length",
                    p.endpoint
                ));
            }
            if !published_names.insert((p.scope.as_str(), p.endpoint.as_str())) {
                return Err(format!(
                    "duplicate publish_endpoint '{}' in scope '{}' (endpoint names must be unique across planes)",
                    p.endpoint, p.scope
                ));
            }
            if p.plane == Plane::Datagram && p.min_mtu < DATAGRAM_MTU {
                return Err(format!(
                    "publish_endpoint '{}' datagram min_mtu {} < {DATAGRAM_MTU}",
                    p.endpoint, p.min_mtu
                ));
            }
        }

        for b in &self.bind_endpoints {
            if !scope_names.contains(b.scope.as_str()) {
                return Err(format!(
                    "bind_endpoint '{}' references unknown scope '{}'",
                    b.endpoint, b.scope
                ));
            }
        }
        if let Some(admin) = &self.admin_socket
            && !scope_names.contains(admin.scope.as_str())
        {
            return Err(format!(
                "admin_socket references unknown scope '{}'",
                admin.scope
            ));
        }
        Ok(())
    }
}

/// Live running Confluence node started from a [`NodeConfig`].
pub struct RunningNode {
    pub node: Node,
    pub scopes: HashMap<String, ScopeInstance>,
    pub tcp_listener_addrs: Vec<SocketAddr>,
    pub udp_listener_addrs: Vec<SocketAddr>,
    pub bound_tcp_addrs: HashMap<String, SocketAddr>,
    pub bound_udp_addrs: HashMap<String, SocketAddr>,
    _publish_guards: Vec<PublishGuard>,
    _stream_pools: Vec<Arc<PassiveStreamPool>>,
    tasks: Vec<JoinHandle<()>>,
}

impl RunningNode {
    /// Validates and starts all scopes, listeners, carriers, transits, relays, routes, and edge forwarders.
    pub async fn start(cfg: NodeConfig) -> Result<Self, String> {
        cfg.validate()?;

        let spawner = Arc::new(TokioSpawner);
        let node = Node::new(spawner.clone());
        let mut scopes = HashMap::new();
        let mut route_tables = HashMap::new();

        for sc in &cfg.scopes {
            let kp = ScopeKeypair::from_secret_hex(&sc.secret_key).map_err(|e| e.to_string())?;
            let policy = Arc::new(StaticPolicy::for_scope(cfg.policy.clone(), &sc.name));
            let routes = Arc::new(StaticPathSource::default());
            let cred_cfgs: Vec<CredentialRuleConfig> = cfg
                .credentials
                .iter()
                .filter(|c| c.scope == sc.name)
                .map(|c| CredentialRuleConfig {
                    verifier: c.verifier,
                    action: c.action,
                    plane: c.plane,
                    target: c.target.clone(),
                    credential: c.credential.clone(),
                })
                .collect();
            let creds = Arc::new(StaticCredentials::from_configs(&cred_cfgs));

            let inst = ScopeInstance::builder(kp, spawner.clone())
                .authorizer(policy)
                .routes(routes.clone())
                .credentials(creds)
                .under_load(sc.under_load)
                .build();
            node.add_scope(inst.clone()).map_err(|e| e.to_string())?;
            scopes.insert(sc.name.clone(), inst);
            route_tables.insert(sc.name.clone(), routes);
        }

        // Register outbound first-hop carriers (never enables inbound forwarding).
        for c in &cfg.outbound_carriers {
            let scope = scopes.get(&c.scope).ok_or("missing scope")?;
            match c.plane {
                Plane::Stream => {
                    scope
                        .register_stream_carrier(&c.name, Arc::new(TcpCarrier::default()))
                        .map_err(|e| e.to_string())?;
                }
                Plane::Datagram => {
                    let carrier = Arc::new(UdpCarrier::new(c.mtu).map_err(|e| e.to_string())?);
                    scope
                        .register_datagram_carrier(&c.name, carrier)
                        .map_err(|e| e.to_string())?;
                }
            }
        }

        let mut publish_guards = Vec::new();

        // Publish fixed named transits (QoS is enforced directly via StaticPolicy's Lease gates/guards).
        for t in &cfg.transits {
            let scope = scopes.get(&t.scope).ok_or("missing scope")?;
            let locator = t.target_addr.to_string().into_bytes();
            let guard = match t.plane {
                Plane::Stream => scope
                    .publish_stream_transit(
                        &t.name,
                        Arc::new(StaticTransit::new(TcpCarrier::default(), locator)),
                    )
                    .map_err(|e| e.to_string())?,
                Plane::Datagram => {
                    let udp = UdpCarrier::new(t.mtu).map_err(|e| e.to_string())?;
                    scope
                        .publish_datagram_transit(
                            &t.name,
                            Arc::new(StaticTransit::new(udp, locator)),
                        )
                        .map_err(|e| e.to_string())?
                }
            };
            publish_guards.push(guard);
        }

        // Publish out-of-core zero-dialing single-port passive relay transits.
        let mut relay_services = Vec::new();
        for r in &cfg.relay_transits {
            let scope = scopes.get(&r.scope).ok_or("missing scope")?;
            let rules = r
                .registration_rules
                .iter()
                .map(|rule| RegistrationRule {
                    peers: rule.peers.clone(),
                    presence: rule.presence.clone(),
                    plane: rule.plane,
                    required_credential: rule.required_credential.clone(),
                    ttl: Duration::from_secs(rule.ttl_secs.max(1)),
                })
                .collect();
            let verifier = Arc::new(StaticRegistrationRules::new(rules));
            let relay = RelayService::new(scope, &r.prefix, verifier, r.stream_mtu, r.datagram_mtu)
                .map_err(|e| e.to_string())?;
            publish_guards.push(
                scope
                    .publish_stream_transit_prefix(&r.prefix, Arc::new(relay.clone()))
                    .map_err(|e| e.to_string())?,
            );
            publish_guards.push(
                scope
                    .publish_datagram_transit_prefix(&r.prefix, Arc::new(relay.clone()))
                    .map_err(|e| e.to_string())?,
            );
            relay_services.push(relay);
        }
        let relay_mux = RelayMux::new(relay_services);

        // Load explicit routes per scope.
        for route in &cfg.routes {
            let routes = route_tables.get(&route.scope).ok_or("missing scope")?;
            routes.set(
                route.target_pubkey,
                route.endpoint.clone(),
                route.plane,
                ExplicitPath {
                    id: route.id,
                    first_channel: route.first_channel.clone(),
                    first_locator: route.first_locator.as_bytes().to_vec(),
                    min_mtu: route.min_mtu,
                    hops: route
                        .hops
                        .iter()
                        .map(|h| HopSpec {
                            peer: h.peer,
                            target: h.target.clone(),
                        })
                        .collect(),
                },
            );
        }

        let mut tasks = Vec::new();
        let mut tcp_listener_addrs = Vec::new();
        let mut udp_listener_addrs = Vec::new();

        for l in &cfg.tcp_listeners {
            let listener = TcpListener::bind(l.listen_addr)
                .await
                .map_err(|e| format!("bind TCP {}: {e}", l.listen_addr))?;
            let local = listener.local_addr().map_err(|e| e.to_string())?;
            tcp_listener_addrs.push(local);
            let node_c = node.clone();
            let carrier = TcpCarrier::with_chunk_limit(l.chunk_limit);
            if relay_mux.is_empty() {
                tasks.push(tokio::spawn(async move {
                    let _ = serve_tcp_node(listener, node_c, carrier).await;
                }));
            } else {
                let mux = relay_mux.clone();
                tasks.push(tokio::spawn(async move {
                    let _ = mux.serve_tcp_node(listener, node_c, carrier).await;
                }));
            }
        }

        for l in &cfg.udp_listeners {
            let carrier = UdpCarrier::new(l.mtu).map_err(|e| e.to_string())?;
            let ingress = carrier.bind(l.bind_addr).map_err(|e| e.to_string())?;
            let local = ingress.local_addr().map_err(|e| e.to_string())?;
            udp_listener_addrs.push(local);
            let node_c = node.clone();
            if relay_mux.is_empty() {
                tasks.push(tokio::spawn(async move {
                    let _ = ingress.serve_node(node_c).await;
                }));
            } else {
                let mux = relay_mux.clone();
                tasks.push(tokio::spawn(async move {
                    let _ = mux.serve_udp_node(ingress, node_c).await;
                }));
            }
        }

        // Publish local target endpoints (QoS is enforced automatically via StaticPolicy's Lease)
        // BEFORE registering passive presence so incoming circuits immediately find them.
        for p in &cfg.publish_endpoints {
            let scope = scopes.get(&p.scope).ok_or("missing scope")?;
            let guard = match p.plane {
                Plane::Stream => scope
                    .publish_stream(&p.endpoint, Arc::new(TcpTarget(p.local_target)))
                    .map_err(|e| e.to_string())?,
                Plane::Datagram => scope
                    .publish_datagram(&p.endpoint, p.min_mtu, Arc::new(UdpTarget(p.local_target)))
                    .map_err(|e| e.to_string())?,
            };
            publish_guards.push(guard);
        }

        // Perform NAT-side passive relay registrations.
        let mut stream_pools = Vec::new();
        for reg in &cfg.relay_registrations {
            let scope = scopes.get(&reg.scope).ok_or("missing scope")?.clone();
            let cred = reg
                .credential
                .as_deref()
                .map(|s| s.as_bytes().to_vec())
                .unwrap_or_default();
            match reg.plane {
                Plane::Datagram => {
                    let udp = UdpCarrier::new(reg.mtu).map_err(|e| e.to_string())?;
                    let local_bind = if reg.relay_addr.is_ipv4() {
                        SocketAddr::from(([0; 4], 0))
                    } else {
                        SocketAddr::from(([0; 8], 0))
                    };
                    let raw_link = udp
                        .connect_from(local_bind, reg.relay_addr)
                        .await
                        .map_err(|e| format!("connect relay UDP {}: {e}", reg.relay_addr))?;
                    let client_link = RelayClientDatagramLink::new(raw_link);
                    let _lease = client_link
                        .register_presence(
                            &scope.identity(),
                            reg.relay_pubkey,
                            &reg.presence_id,
                            &cred,
                        )
                        .await
                        .map_err(|e| format!("register datagram presence: {e}"))?;
                    let ingress = scope
                        .attach_datagram(client_link.clone())
                        .map_err(|e| e.to_string())?;
                    let keepalive = Duration::from_secs(reg.keepalive_secs.max(5));
                    let relay_pk = reg.relay_pubkey;
                    let presence_id = reg.presence_id.clone();
                    tasks.push(tokio::spawn(async move {
                        let mut tick = tokio::time::interval(keepalive);
                        tick.tick().await;
                        loop {
                            tokio::select! {
                                _ = ingress.closed() => break,
                                _ = tick.tick() => {
                                    let _ = client_link
                                        .register_presence(
                                            &scope.identity(),
                                            relay_pk,
                                            &presence_id,
                                            &cred,
                                        )
                                        .await;
                                }
                            }
                        }
                    }));
                }
                Plane::Stream => {
                    let pool = PassiveStreamPool::start(
                        Arc::new(TcpCarrier::default()),
                        scope.identity(),
                        reg.relay_addr.to_string().into_bytes(),
                        reg.relay_pubkey,
                        reg.presence_id.clone(),
                        cred,
                        reg.pool_size,
                    )
                    .await
                    .map_err(|e| format!("start passive stream pool: {e}"))?;
                    let pool_c = pool.clone();
                    tasks.push(tokio::spawn(async move {
                        let _ = scope.serve_stream_listener(&*pool_c).await;
                    }));
                    stream_pools.push(pool);
                }
            }
        }

        // Bind local outbound edge port forwarders.
        let mut bound_tcp_addrs = HashMap::new();
        let mut bound_udp_addrs = HashMap::new();
        for b in &cfg.bind_endpoints {
            let scope = scopes.get(&b.scope).ok_or("missing scope")?.clone();
            let dst = Destination {
                peer: b.target_pubkey,
                endpoint: b.endpoint.clone(),
            };
            match b.plane {
                Plane::Stream => {
                    let listener = TcpListener::bind(b.listen_addr)
                        .await
                        .map_err(|e| format!("bind edge TCP {}: {e}", b.listen_addr))?;
                    let local = listener.local_addr().map_err(|e| e.to_string())?;
                    bound_tcp_addrs.insert(b.endpoint.clone(), local);
                    tasks.push(tokio::spawn(async move {
                        let _ = serve_local_tcp(listener, scope, dst).await;
                    }));
                }
                Plane::Datagram => {
                    let sock = UdpSocket::bind(b.listen_addr)
                        .await
                        .map_err(|e| format!("bind edge UDP {}: {e}", b.listen_addr))?;
                    let local = sock.local_addr().map_err(|e| e.to_string())?;
                    bound_udp_addrs.insert(b.endpoint.clone(), local);
                    let min_mtu = b.min_mtu;
                    tasks.push(tokio::spawn(async move {
                        let _ = serve_local_udp(sock, scope, dst, min_mtu).await;
                    }));
                }
            }
        }

        #[cfg(unix)]
        if let Some(admin_cfg) = &cfg.admin_socket {
            let scope = scopes.get(&admin_cfg.scope).ok_or("missing scope")?.clone();
            let admin = confluence_edge::admin::AdminSocket::bind(&admin_cfg.path)
                .map_err(|e| format!("bind admin socket {:?}: {e}", admin_cfg.path))?;
            tasks.push(tokio::spawn(async move {
                let _ = admin.serve(scope).await;
            }));
        }

        Ok(Self {
            node,
            scopes,
            tcp_listener_addrs,
            udp_listener_addrs,
            bound_tcp_addrs,
            bound_udp_addrs,
            _publish_guards: publish_guards,
            _stream_pools: stream_pools,
            tasks,
        })
    }

    /// Stops all spawned listeners, relays, and forwarders cleanly.
    pub fn shutdown(self) {
        for pool in &self._stream_pools {
            pool.close();
        }
        for handle in self.tasks {
            handle.abort();
        }
    }
}

/// Generates a fresh X25519 keypair and returns `(secret_hex, public_hex, kid_hex)`.
pub fn generate_keypair_hex() -> (String, String, String) {
    let kp = ScopeKeypair::generate();
    (
        kp.secret_hex(),
        kp.public_key().to_string(),
        kp.kid().to_string(),
    )
}

/// Parses a hex [`PublicKey`] helper export for tests.
pub fn parse_public_key(hex: &str) -> Result<PublicKey, CoreErr> {
    hex.parse()
}
