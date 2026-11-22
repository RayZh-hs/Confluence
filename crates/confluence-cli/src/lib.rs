#![forbid(unsafe_code)]
//! Declarative TOML configuration schema and node bootstrapper for `confluence-cli`.

use confluence_carriers::{
    NoiseAclDatagramChannel, NoiseAclStreamChannel, TcpStreamChannel, UdpDatagramChannel,
};
use confluence_core::seams::channel::{DatagramChannel, StreamChannel};
use confluence_core::{
    ChannelAddr, ChannelId, CoreError, EndpointName, Node, OpaqueCredential, PeerId, Plane, Result,
    ScopeId, StaticKeypair, TrustScope,
};
use confluence_edge::{
    TcpInboundForwarder, TcpOutboundForwarder, UdpInboundForwarder, UdpOutboundForwarder,
};
use confluence_policy::{PolicyConfig, StaticPolicy};
use confluence_relay::{
    RelayDatagramChannel, RelayDatagramClient, RelayIngressStreamChannel, RelayStreamChannel,
};
use confluence_routing::{RouteEntryConfig, RoutingConfig, StaticRouter};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeConfig {
    pub id: String,
    pub secret_key: String,
    #[serde(default)]
    pub under_load: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpCarrierConfig {
    pub id: String,
    pub bind_addr: SocketAddr,
    #[serde(default = "default_udp_mtu")]
    pub mtu: usize,
}

fn default_udp_mtu() -> usize {
    1400
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpCarrierConfig {
    pub id: String,
    /// If `Some`, binds an inbound + outbound TCP listener; if `None`, outbound-only.
    pub listen_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclForwardConfig {
    pub plane: Plane,
    pub carrier_id: String,
    pub scope: String,
    pub secret_key: String,
    #[serde(default)]
    pub under_load: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayChannelConfig {
    pub plane: Plane,
    pub scope: String,
    pub secret_key: String,
    #[serde(default = "default_udp_mtu")]
    pub mtu: usize,
    #[serde(default)]
    pub under_load: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayRegistrationConfig {
    pub plane: Plane,
    pub scope: String,
    pub carrier_id: String,
    /// Local channel ID for the virtual inbound stream pool when `plane == "stream"`.
    pub ingress_id: Option<String>,
    pub relay_addr: String,
    pub relay_pubkey: PeerId,
    pub credential: Option<String>,
    #[serde(default = "default_keepalive_secs")]
    pub keepalive_secs: u64,
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
}

fn default_keepalive_secs() -> u64 {
    30
}

fn default_pool_size() -> usize {
    4
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishEdgeConfig {
    pub scope: String,
    pub endpoint: String,
    pub plane: Plane,
    pub local_target: SocketAddr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindEdgeConfig {
    pub scope: String,
    pub target_pubkey: PeerId,
    pub endpoint: String,
    pub plane: Plane,
    pub listen_addr: SocketAddr,
}

/// Complete declarative configuration for a Confluence Node instance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeConfig {
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub scopes: Vec<ScopeConfig>,
    #[serde(default)]
    pub udp_carriers: Vec<UdpCarrierConfig>,
    #[serde(default)]
    pub tcp_carriers: Vec<TcpCarrierConfig>,
    #[serde(default)]
    pub acl_forward_channels: Vec<AclForwardConfig>,
    #[serde(default)]
    pub relay_channels: Vec<RelayChannelConfig>,
    #[serde(default)]
    pub relay_registrations: Vec<RelayRegistrationConfig>,
    #[serde(default)]
    pub routes: Vec<RouteEntryConfig>,
    #[serde(default)]
    pub publish_endpoints: Vec<PublishEdgeConfig>,
    #[serde(default)]
    pub bind_endpoints: Vec<BindEdgeConfig>,
}

impl NodeConfig {
    pub fn from_toml_str(toml_str: &str) -> Result<Self> {
        let cfg: Self = toml::from_str(toml_str)
            .map_err(|e| CoreError::InvalidInput(format!("invalid node TOML: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validates static keys, identifiers, carrier references, and explicit routes before binding sockets.
    pub fn validate(&self) -> Result<()> {
        let mut scope_ids = std::collections::HashSet::new();
        for sc in &self.scopes {
            let sid = ScopeId::new(&sc.id)?;
            if !scope_ids.insert(sid) {
                return Err(CoreError::InvalidInput(format!(
                    "duplicate scope id '{}'",
                    sc.id
                )));
            }
            let _ = StaticKeypair::from_secret_hex(&sc.secret_key)?;
        }

        let mut udp_ids = std::collections::HashSet::new();
        for u in &self.udp_carriers {
            let cid = ChannelId::new(&u.id)?;
            if !udp_ids.insert(cid) {
                return Err(CoreError::InvalidInput(format!(
                    "duplicate udp_carrier id '{}'",
                    u.id
                )));
            }
        }

        let mut tcp_ids = std::collections::HashSet::new();
        for t in &self.tcp_carriers {
            let cid = ChannelId::new(&t.id)?;
            if !tcp_ids.insert(cid) {
                return Err(CoreError::InvalidInput(format!(
                    "duplicate tcp_carrier id '{}'",
                    t.id
                )));
            }
        }

        for fwd in &self.acl_forward_channels {
            let _ = ScopeId::new(&fwd.scope)?;
            let _ = StaticKeypair::from_secret_hex(&fwd.secret_key)?;
            let cid = ChannelId::new(&fwd.carrier_id)?;
            match fwd.plane {
                Plane::Datagram if !udp_ids.contains(&cid) => {
                    return Err(CoreError::ChannelNotFound(format!(
                        "acl_forward_channels references unknown udp_carrier '{}'",
                        fwd.carrier_id
                    )));
                }
                Plane::Stream if !tcp_ids.contains(&cid) => {
                    return Err(CoreError::ChannelNotFound(format!(
                        "acl_forward_channels references unknown tcp_carrier '{}'",
                        fwd.carrier_id
                    )));
                }
                _ => {}
            }
        }

        for r in &self.relay_channels {
            let _ = ScopeId::new(&r.scope)?;
            let _ = StaticKeypair::from_secret_hex(&r.secret_key)?;
        }

        for reg in &self.relay_registrations {
            let sid = ScopeId::new(&reg.scope)?;
            if !scope_ids.contains(&sid) {
                return Err(CoreError::ScopeNotFound(reg.scope.clone()));
            }
            let _ = ChannelAddr::new(&reg.relay_addr)?;
            if let Some(ref c) = reg.credential {
                let _ = OpaqueCredential::from_utf8(c)?;
            }
        }

        let _ = StaticRouter::from_config(&RoutingConfig {
            routes: self.routes.clone(),
        })?;

        for pub_ep in &self.publish_endpoints {
            let sid = ScopeId::new(&pub_ep.scope)?;
            if !scope_ids.contains(&sid) {
                return Err(CoreError::ScopeNotFound(pub_ep.scope.clone()));
            }
            let _ = EndpointName::new(&pub_ep.endpoint)?;
        }

        for bind_ep in &self.bind_endpoints {
            let sid = ScopeId::new(&bind_ep.scope)?;
            if !scope_ids.contains(&sid) {
                return Err(CoreError::ScopeNotFound(bind_ep.scope.clone()));
            }
            let _ = EndpointName::new(&bind_ep.endpoint)?;
        }

        Ok(())
    }
}

/// Live handle to a booted Confluence Node and its attached carriers, relays, and edge adapters.
pub struct RunningNode {
    node: Arc<Node>,
    policy: Arc<StaticPolicy>,
    router: Arc<StaticRouter>,
    udp_addrs: HashMap<String, SocketAddr>,
    tcp_addrs: HashMap<String, SocketAddr>,
    bound_tcp_edges: HashMap<(String, String), SocketAddr>,
    bound_udp_edges: HashMap<(String, String), SocketAddr>,
    udp_carriers: Vec<Arc<UdpDatagramChannel>>,
    tcp_carriers: Vec<Arc<TcpStreamChannel>>,
    relay_ingress: Vec<Arc<RelayIngressStreamChannel>>,
    tcp_in_edges: Vec<TcpInboundForwarder>,
    tcp_out_edges: Vec<TcpOutboundForwarder>,
    udp_in_edges: Vec<UdpInboundForwarder>,
    udp_out_edges: Vec<UdpOutboundForwarder>,
    bg_tasks: Vec<JoinHandle<()>>,
}

impl RunningNode {
    /// Boots a complete Confluence Node from a validated [`NodeConfig`].
    pub async fn start(cfg: NodeConfig) -> Result<Self> {
        cfg.validate()?;

        let policy = StaticPolicy::new(cfg.policy.clone());
        let router = StaticRouter::from_config(&RoutingConfig {
            routes: cfg.routes.clone(),
        })?;
        let node = Node::new(Arc::clone(&router) as Arc<_>);

        let mut scope_keys: HashMap<String, StaticKeypair> = HashMap::new();
        for sc in &cfg.scopes {
            let kp = StaticKeypair::from_secret_hex(&sc.secret_key)?;
            scope_keys.insert(sc.id.clone(), kp.clone());
            let scope = TrustScope::new(ScopeId::new(&sc.id)?, kp, Arc::clone(&policy) as Arc<_>);
            scope.cookie_protector().set_under_load(sc.under_load);
            node.add_scope(scope)?;
        }

        let mut udp_map: HashMap<String, Arc<UdpDatagramChannel>> = HashMap::new();
        let mut udp_addrs = HashMap::new();
        let mut udp_carriers = Vec::new();
        for u in &cfg.udp_carriers {
            let ch = UdpDatagramChannel::bind(ChannelId::new(&u.id)?, u.bind_addr, u.mtu).await?;
            udp_addrs.insert(u.id.clone(), ch.local_addr());
            node.attach_datagram_channel(Arc::clone(&ch) as Arc<_>)?;
            udp_map.insert(u.id.clone(), Arc::clone(&ch));
            udp_carriers.push(ch);
        }

        let mut tcp_map: HashMap<String, Arc<TcpStreamChannel>> = HashMap::new();
        let mut tcp_addrs = HashMap::new();
        let mut tcp_carriers = Vec::new();
        for t in &cfg.tcp_carriers {
            let ch = match t.listen_addr {
                Some(addr) => TcpStreamChannel::bind(ChannelId::new(&t.id)?, addr).await?,
                None => TcpStreamChannel::outbound_only(ChannelId::new(&t.id)?),
            };
            if let Some(la) = ch.local_addr() {
                tcp_addrs.insert(t.id.clone(), la);
            }
            node.attach_stream_channel(Arc::clone(&ch) as Arc<_>)?;
            tcp_map.insert(t.id.clone(), Arc::clone(&ch));
            tcp_carriers.push(ch);
        }

        for fwd in &cfg.acl_forward_channels {
            let kp = StaticKeypair::from_secret_hex(&fwd.secret_key)?;
            let scope = ScopeId::new(&fwd.scope)?;
            match fwd.plane {
                Plane::Datagram => {
                    let carrier = udp_map.get(&fwd.carrier_id).ok_or_else(|| {
                        CoreError::ChannelNotFound(fwd.carrier_id.clone())
                    })?;
                    let wrapped = NoiseAclDatagramChannel::new(
                        Arc::clone(carrier),
                        scope,
                        kp,
                        Arc::clone(&policy) as Arc<_>,
                    );
                    wrapped.cookie_protector().set_under_load(fwd.under_load);
                    node.mount_datagram_forward_channel(wrapped)?;
                }
                Plane::Stream => {
                    let carrier = tcp_map.get(&fwd.carrier_id).ok_or_else(|| {
                        CoreError::ChannelNotFound(fwd.carrier_id.clone())
                    })?;
                    let wrapped = NoiseAclStreamChannel::new(
                        Arc::clone(carrier),
                        scope,
                        kp,
                        Arc::clone(&policy) as Arc<_>,
                    );
                    wrapped.cookie_protector().set_under_load(fwd.under_load);
                    node.mount_stream_forward_channel(wrapped)?;
                }
            }
        }

        for rel in &cfg.relay_channels {
            let kp = StaticKeypair::from_secret_hex(&rel.secret_key)?;
            let scope = ScopeId::new(&rel.scope)?;
            match rel.plane {
                Plane::Datagram => {
                    let ch = RelayDatagramChannel::new(
                        scope,
                        kp,
                        rel.mtu,
                        Arc::clone(&policy) as Arc<_>,
                    );
                    ch.cookie_protector().set_under_load(rel.under_load);
                    node.mount_datagram_forward_channel(ch)?;
                }
                Plane::Stream => {
                    let ch = RelayStreamChannel::new(scope, kp, Arc::clone(&policy) as Arc<_>);
                    ch.cookie_protector().set_under_load(rel.under_load);
                    node.mount_stream_forward_channel(ch)?;
                }
            }
        }

        let mut bg_tasks = Vec::new();
        let mut relay_ingress = Vec::new();
        for reg in &cfg.relay_registrations {
            let kp = scope_keys
                .get(&reg.scope)
                .ok_or_else(|| CoreError::ScopeNotFound(reg.scope.clone()))?
                .clone();
            let cred = match reg.credential {
                Some(ref s) => Some(OpaqueCredential::from_utf8(s)?),
                None => None,
            };
            let relay_addr = ChannelAddr::new(&reg.relay_addr)?;
            match reg.plane {
                Plane::Datagram => {
                    let cid = ChannelId::new(&reg.carrier_id)?;
                    // Initial synchronous registration followed by periodic keepalive!
                    RelayDatagramClient::new()
                        .register_once(
                            &node,
                            &kp,
                            &cid,
                            &relay_addr,
                            reg.relay_pubkey,
                            cred.clone(),
                        )
                        .await?;
                    let handle = RelayDatagramClient::spawn_keepalive(
                        Arc::clone(&node),
                        kp,
                        cid,
                        relay_addr,
                        reg.relay_pubkey,
                        cred,
                        Duration::from_secs(reg.keepalive_secs.max(1)),
                    );
                    bg_tasks.push(handle);
                }
                Plane::Stream => {
                    let underlay = tcp_map.get(&reg.carrier_id).ok_or_else(|| {
                        CoreError::ChannelNotFound(reg.carrier_id.clone())
                    })?;
                    let ingress_id = ChannelId::new(
                        reg.ingress_id
                            .clone()
                            .unwrap_or_else(|| format!("relay_in_{}", reg.scope)),
                    )?;
                    let pool = RelayIngressStreamChannel::connect_pool(
                        ingress_id,
                        Arc::clone(underlay),
                        kp,
                        relay_addr,
                        reg.relay_pubkey,
                        cred,
                        reg.pool_size,
                    )
                    .await?;
                    node.attach_stream_channel(Arc::clone(&pool) as Arc<_>)?;
                    relay_ingress.push(pool);
                }
            }
        }

        let mut tcp_in_edges = Vec::new();
        let mut udp_in_edges = Vec::new();
        for pub_ep in &cfg.publish_endpoints {
            let scope = ScopeId::new(&pub_ep.scope)?;
            let ep = EndpointName::new(&pub_ep.endpoint)?;
            match pub_ep.plane {
                Plane::Stream => {
                    tcp_in_edges.push(TcpInboundForwarder::start(
                        &node,
                        &scope,
                        ep,
                        pub_ep.local_target,
                    )?);
                }
                Plane::Datagram => {
                    udp_in_edges.push(UdpInboundForwarder::start(
                        &node,
                        &scope,
                        ep,
                        pub_ep.local_target,
                    )?);
                }
            }
        }

        let mut tcp_out_edges = Vec::new();
        let mut udp_out_edges = Vec::new();
        let mut bound_tcp_edges = HashMap::new();
        let mut bound_udp_edges = HashMap::new();
        for bind_ep in &cfg.bind_endpoints {
            let scope = ScopeId::new(&bind_ep.scope)?;
            let ep = EndpointName::new(&bind_ep.endpoint)?;
            match bind_ep.plane {
                Plane::Stream => {
                    let fwd = TcpOutboundForwarder::bind(
                        bind_ep.listen_addr,
                        Arc::clone(&node),
                        scope,
                        bind_ep.target_pubkey,
                        ep,
                    )
                    .await?;
                    bound_tcp_edges.insert(
                        (bind_ep.scope.clone(), bind_ep.endpoint.clone()),
                        fwd.local_addr(),
                    );
                    tcp_out_edges.push(fwd);
                }
                Plane::Datagram => {
                    let fwd = UdpOutboundForwarder::bind(
                        bind_ep.listen_addr,
                        Arc::clone(&node),
                        scope,
                        bind_ep.target_pubkey,
                        ep,
                    )
                    .await?;
                    bound_udp_edges.insert(
                        (bind_ep.scope.clone(), bind_ep.endpoint.clone()),
                        fwd.local_addr(),
                    );
                    udp_out_edges.push(fwd);
                }
            }
        }

        Ok(Self {
            node,
            policy,
            router,
            udp_addrs,
            tcp_addrs,
            bound_tcp_edges,
            bound_udp_edges,
            udp_carriers,
            tcp_carriers,
            relay_ingress,
            tcp_in_edges,
            tcp_out_edges,
            udp_in_edges,
            udp_out_edges,
            bg_tasks,
        })
    }

    pub fn node(&self) -> &Arc<Node> {
        &self.node
    }

    pub fn policy(&self) -> &Arc<StaticPolicy> {
        &self.policy
    }

    pub fn router(&self) -> &Arc<StaticRouter> {
        &self.router
    }

    pub fn udp_carrier_addr(&self, id: &str) -> Option<SocketAddr> {
        self.udp_addrs.get(id).copied()
    }

    pub fn tcp_carrier_addr(&self, id: &str) -> Option<SocketAddr> {
        self.tcp_addrs.get(id).copied()
    }

    pub fn bound_tcp_edge_addr(&self, scope: &str, endpoint: &str) -> Option<SocketAddr> {
        self.bound_tcp_edges
            .get(&(scope.to_string(), endpoint.to_string()))
            .copied()
    }

    pub fn bound_udp_edge_addr(&self, scope: &str, endpoint: &str) -> Option<SocketAddr> {
        self.bound_udp_edges
            .get(&(scope.to_string(), endpoint.to_string()))
            .copied()
    }

    /// Cleanly tears down all edge adapters, relay keepalives, and transport carriers.
    pub async fn shutdown(self) {
        for h in self.bg_tasks {
            h.abort();
        }
        for e in self.tcp_out_edges {
            e.stop();
        }
        for e in self.udp_out_edges {
            e.stop();
        }
        for e in self.tcp_in_edges {
            e.stop();
        }
        for e in self.udp_in_edges {
            e.stop();
        }
        for r in self.relay_ingress {
            let _ = r.close().await;
        }
        for c in self.udp_carriers {
            let _ = c.close().await;
        }
        for c in self.tcp_carriers {
            let _ = c.close().await;
        }
    }
}
