//! Direct topology, with a shared service definition for Bob.

use crate::{
    ExampleResult, MTU, Ports, TCP_ENDPOINT, UDP_ENDPOINT, allow, demo_policy, destination, path,
};
use confluence_core::{DATAGRAM_MTU, HopSpec, Plane, PublicKey, ScopeKeypair};
use confluence_edge::{TcpTarget, UdpTarget};
use confluence_net::{TcpCarrier, UdpCarrier};
use confluence_plugins::{QosLimits, RuleTargetKind, StaticCredentials, StaticPolicy};
use confluence_runtime::{NodePlan, ScopePlan};
use std::sync::Arc;

/// Bob accepts Alice's calls and publishes two local services on shared ingress.
pub fn bob(
    identity: ScopeKeypair,
    alice: PublicKey,
    token: &str,
    backend: Ports,
    ingress: Ports,
) -> ExampleResult<NodePlan> {
    let mut app = NodePlan::new();
    app.scope("app", identity)?
        .authorizer(endpoint_policy(alice, token))
        .publish_stream(TCP_ENDPOINT, Arc::new(TcpTarget(backend.tcp)))?
        .publish_datagram(UDP_ENDPOINT, DATAGRAM_MTU, Arc::new(UdpTarget(backend.udp)))?;
    app.listen_tcp(ingress.tcp)
        .listen_udp(ingress.udp, UdpCarrier::new(MTU)?);
    Ok(app)
}

/// Alice forwards two local ports over explicitly declared direct paths to Bob.
pub fn alice(
    identity: ScopeKeypair,
    bob: PublicKey,
    token: &str,
    ingress: Ports,
    local: Ports,
) -> ExampleResult<NodePlan> {
    let mut app = NodePlan::new();
    let credentials = endpoint_credentials(bob, token);
    let scope = app.scope("app", identity)?.credentials(credentials);
    forward(scope, bob, ingress, local, Vec::new())?;
    Ok(app)
}

pub(crate) fn endpoint_policy(alice: PublicKey, token: &str) -> Arc<StaticPolicy> {
    demo_policy(vec![
        allow(
            alice,
            RuleTargetKind::Endpoint,
            Some(Plane::Stream),
            TCP_ENDPOINT,
            token,
            QosLimits {
                max_concurrent_streams: 32,
                ..QosLimits::default()
            },
        ),
        allow(
            alice,
            RuleTargetKind::Endpoint,
            Some(Plane::Datagram),
            UDP_ENDPOINT,
            token,
            QosLimits::default(),
        ),
    ])
}

pub(crate) fn endpoint_credentials(bob: PublicKey, token: &str) -> Arc<StaticCredentials> {
    let credentials = Arc::new(StaticCredentials::default());
    credentials.set_endpoint(bob, TCP_ENDPOINT, token.as_bytes());
    credentials.set_endpoint(bob, UDP_ENDPOINT, token.as_bytes());
    credentials
}

pub(crate) fn forward(
    scope: &mut ScopePlan,
    bob: PublicKey,
    first_hop: Ports,
    local: Ports,
    hops: Vec<HopSpec>,
) -> ExampleResult {
    let tcp = destination(bob, TCP_ENDPOINT);
    let udp = destination(bob, UDP_ENDPOINT);
    scope
        .stream_carrier("tcp", Arc::new(TcpCarrier::default()))?
        .datagram_carrier("udp", Arc::new(UdpCarrier::new(MTU)?))?
        .route(
            tcp.clone(),
            Plane::Stream,
            path(Plane::Stream, first_hop.tcp, hops.clone()),
        )
        .route(
            udp.clone(),
            Plane::Datagram,
            path(Plane::Datagram, first_hop.udp, hops),
        )
        .forward_tcp(local.tcp, tcp)
        .forward_udp(local.udp, udp, DATAGRAM_MTU);
    Ok(())
}
