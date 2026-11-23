//! Passive relay with an optional named transit in front of it.

use crate::{ExampleResult, MTU, Ports, TCP_ENDPOINT, UDP_ENDPOINT, allow, demo_policy, direct};
use confluence_core::{
    DATAGRAM_MTU, HopSpec, Plane, PublicKey, STREAM_CHUNK, ScopeKeypair, StaticTransit,
};
use confluence_edge::{TcpTarget, UdpTarget};
use confluence_net::{TcpCarrier, UdpCarrier};
use confluence_plugins::{QosLimits, RuleTargetKind};
use confluence_relay::{RegistrationRule, StaticRegistrationRules};
use confluence_runtime::{NodePlan, RelayPresence};
use std::{sync::Arc, time::Duration};

const PRESENCE: &str = "bob-presence";
const RELAY_PREFIX: &str = "relay/";
const RELAY_TARGET: &str = "relay/bob-presence";
const HOP_TARGET: &str = "to-relay";

pub struct TransitPeer<'a> {
    pub peer: PublicKey,
    pub token: &'a str,
}

/// Relay accepts Bob's registration and lets Alice request the named transit.
pub fn relay(
    identity: ScopeKeypair,
    alice: PublicKey,
    bob: PublicKey,
    transit_token: &str,
    registration_token: &str,
    ingress: Ports,
) -> ExampleResult<NodePlan> {
    let policy = demo_policy(vec![allow(
        alice,
        RuleTargetKind::Transit,
        None,
        RELAY_TARGET,
        transit_token,
        QosLimits::default(),
    )]);
    let registration = StaticRegistrationRules::new(vec![RegistrationRule {
        peers: vec![bob.to_string()],
        presence: Some(PRESENCE.into()),
        plane: None,
        required_credential: Some(registration_token.into()),
        ttl: Duration::from_secs(300),
    }]);
    let mut app = NodePlan::new();
    app.scope("relay", identity)?
        .authorizer(policy)
        .publish_relay(
            RELAY_PREFIX,
            Arc::new(registration),
            STREAM_CHUNK as u16,
            MTU,
        )?;
    app.listen_tcp(ingress.tcp)
        .listen_udp(ingress.udp, UdpCarrier::new(MTU)?);
    Ok(app)
}

/// Bob publishes local services and reaches the relay by registering outbound presence.
pub fn bob(
    identity: ScopeKeypair,
    alice: PublicKey,
    endpoint_token: &str,
    backend: Ports,
    relay: PublicKey,
    relay_ingress: Ports,
    registration_token: &str,
) -> ExampleResult<NodePlan> {
    let mut app = NodePlan::new();
    let presence = RelayPresence::new(relay, PRESENCE, registration_token.as_bytes().to_vec());
    app.scope("app", identity)?
        .under_load(true)
        .authorizer(direct::endpoint_policy(alice, endpoint_token))
        .publish_stream(TCP_ENDPOINT, Arc::new(TcpTarget(backend.tcp)))?
        .publish_datagram(UDP_ENDPOINT, DATAGRAM_MTU, Arc::new(UdpTarget(backend.udp)))?
        .register_relay_tcp(relay_ingress.tcp, presence.clone(), 4)
        .register_relay_udp(
            relay_ingress.udp,
            presence,
            UdpCarrier::new(MTU)?,
            Duration::from_secs(30),
        );
    Ok(app)
}

/// Optional first hop. It publishes a fixed relay destination and applies transit QoS.
pub fn hop(
    identity: ScopeKeypair,
    alice: PublicKey,
    token: &str,
    ingress: Ports,
    relay: Ports,
) -> ExampleResult<NodePlan> {
    let bandwidth = 50 * 1024 * 1024;
    let policy = demo_policy(vec![
        allow(
            alice,
            RuleTargetKind::Transit,
            Some(Plane::Stream),
            HOP_TARGET,
            token,
            QosLimits {
                max_bytes_per_sec: bandwidth,
                ..QosLimits::default()
            },
        ),
        allow(
            alice,
            RuleTargetKind::Transit,
            Some(Plane::Datagram),
            HOP_TARGET,
            token,
            QosLimits {
                max_bytes_per_sec: bandwidth,
                max_datagrams_per_sec: 5000,
                ..QosLimits::default()
            },
        ),
    ]);
    let mut app = NodePlan::new();
    app.scope("transit", identity)?
        .under_load(true)
        .authorizer(policy)
        .publish_stream_transit(
            HOP_TARGET,
            Arc::new(StaticTransit::new(
                TcpCarrier::default(),
                relay.tcp.to_string().into_bytes(),
            )),
        )?
        .publish_datagram_transit(
            HOP_TARGET,
            Arc::new(StaticTransit::new(
                UdpCarrier::new(MTU)?,
                relay.udp.to_string().into_bytes(),
            )),
        )?;
    app.listen_tcp(ingress.tcp)
        .listen_udp(ingress.udp, UdpCarrier::new(MTU)?);
    Ok(app)
}

/// Alice goes through the relay, optionally with a named transit as the first hop.
pub fn alice(
    identity: ScopeKeypair,
    bob: PublicKey,
    endpoint_token: &str,
    relay: TransitPeer<'_>,
    first_hop: Ports,
    local: Ports,
    hop: Option<TransitPeer<'_>>,
) -> ExampleResult<NodePlan> {
    let mut app = NodePlan::new();
    let credentials = direct::endpoint_credentials(bob, endpoint_token);
    credentials.set_transit(relay.peer, RELAY_TARGET, relay.token.as_bytes());

    let mut hops = Vec::new();
    if let Some(hop) = hop {
        credentials.set_transit(hop.peer, HOP_TARGET, hop.token.as_bytes());
        hops.push(HopSpec::new(hop.peer, HOP_TARGET));
    }
    hops.push(HopSpec::new(relay.peer, RELAY_TARGET));

    let scope = app.scope("app", identity)?.credentials(credentials);
    direct::forward(scope, bob, first_hop, local, hops)?;
    Ok(app)
}
