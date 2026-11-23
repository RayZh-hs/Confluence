//! Shared input handling for the runnable deployments.

#![forbid(unsafe_code)]

pub mod direct;
pub mod relayed;

use confluence_core::{DATAGRAM_MTU, ExplicitPath, HopSpec, Plane, PublicKey, ScopeKeypair};
use confluence_edge::Destination;
use confluence_plugins::{PolicyConfig, PolicyRuleConfig, QosLimits, RuleTargetKind, StaticPolicy};
use confluence_runtime::NodePlan;
use std::{env, error::Error, fs, net::SocketAddr, sync::Arc};
use zeroize::Zeroizing;

pub const MTU: u16 = 1400;
pub const TCP_ENDPOINT: &str = "demo-tcp";
pub const UDP_ENDPOINT: &str = "demo-udp";

pub type ExampleResult<T = ()> = Result<T, Box<dyn Error>>;

#[derive(Clone, Copy)]
pub struct Ports {
    pub tcp: SocketAddr,
    pub udp: SocketAddr,
}

pub fn ports(tcp_var: &str, udp_var: &str, defaults: (u16, u16)) -> ExampleResult<Ports> {
    fn address(var: &str, default: u16) -> ExampleResult<SocketAddr> {
        match env::var(var) {
            Ok(value) => value
                .parse()
                .map_err(|_| format!("{var} must be a socket address").into()),
            Err(env::VarError::NotPresent) => Ok(SocketAddr::from(([127, 0, 0, 1], default))),
            Err(error) => Err(error.into()),
        }
    }
    Ok(Ports {
        tcp: address(tcp_var, defaults.0)?,
        udp: address(udp_var, defaults.1)?,
    })
}

pub fn identity() -> ExampleResult<ScopeKeypair> {
    ScopeKeypair::from_secret_hex(&secret("IDENTITY_FILE")?).map_err(Into::into)
}

pub fn peer(var: &str) -> ExampleResult<PublicKey> {
    env::var(var)
        .map_err(|_| format!("set {var} to the peer's public key"))?
        .parse()
        .map_err(|_| format!("{var} must be a hex public key").into())
}

pub fn secret(var: &str) -> ExampleResult<Zeroizing<String>> {
    let path = env::var_os(var).ok_or_else(|| format!("set {var} to a file path"))?;
    let mut text =
        Zeroizing::new(fs::read_to_string(&path).map_err(|error| format!("read {var}: {error}"))?);
    let length = text.trim_end_matches(['\r', '\n']).len();
    text.truncate(length);
    if text.is_empty() {
        return Err(format!("{var} refers to an empty file").into());
    }
    Ok(text)
}

pub async fn run(app: NodePlan) -> ExampleResult {
    let mut args = env::args_os().skip(1);
    let check_only = match args.next() {
        None => false,
        Some(arg) if arg == "--check" && args.next().is_none() => true,
        _ => return Err("expected no arguments or --check".into()),
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();

    let prepared = app.prepare()?;
    if check_only {
        println!("Wiring validated");
        return Ok(());
    }
    let running = prepared.start().await?;
    for addr in running.tcp_listener_addrs() {
        println!("TCP ingress at {addr}");
    }
    for addr in running.udp_listener_addrs() {
        println!("UDP ingress at {addr}");
    }
    for forward in running.forwards() {
        println!(
            "{} forward for {} at {}",
            forward.plane, forward.destination.endpoint, forward.addr
        );
    }
    println!("Node started");
    running.run_until(tokio::signal::ctrl_c()).await?;
    Ok(())
}

fn demo_policy(rules: Vec<PolicyRuleConfig>) -> Arc<StaticPolicy> {
    Arc::new(StaticPolicy::new(PolicyConfig {
        rules,
        ..PolicyConfig::default()
    }))
}

fn allow(
    peer: PublicKey,
    action: RuleTargetKind,
    plane: Option<Plane>,
    target: &str,
    token: &str,
    qos: QosLimits,
) -> PolicyRuleConfig {
    PolicyRuleConfig {
        scope: None,
        peers: vec![peer.to_string()],
        action,
        plane,
        target: Some(target.into()),
        required_credential: Some(token.into()),
        ttl_secs: None,
        max_bytes_per_sec: Some(qos.max_bytes_per_sec),
        max_datagrams_per_sec: Some(qos.max_datagrams_per_sec),
        max_concurrent_streams: Some(qos.max_concurrent_streams),
    }
}

fn destination(peer: PublicKey, endpoint: &str) -> Destination {
    Destination {
        peer,
        endpoint: endpoint.into(),
    }
}

fn path(plane: Plane, first_hop: SocketAddr, hops: Vec<HopSpec>) -> ExplicitPath {
    let (id, channel, min_mtu) = match plane {
        Plane::Stream => (1, "tcp", 0),
        Plane::Datagram => (2, "udp", DATAGRAM_MTU),
    };
    ExplicitPath {
        id,
        first_channel: channel.into(),
        first_locator: first_hop.to_string().into_bytes(),
        min_mtu,
        hops,
    }
}
