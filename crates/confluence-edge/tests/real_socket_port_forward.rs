use confluence_carriers::{
    NoiseAclDatagramChannel, NoiseAclStreamChannel, TcpStreamChannel, UdpDatagramChannel,
};
use confluence_core::seams::routing::{ExplicitPath, PathHop};
use confluence_core::{
    ChannelAddr, ChannelId, EndpointName, Node, Plane, ScopeId, StaticKeypair, TrustScope,
};
use confluence_edge::{
    TcpInboundForwarder, TcpOutboundForwarder, UdpInboundForwarder, UdpOutboundForwarder,
};
use confluence_policy::{PolicyConfig, StaticPolicy};
use confluence_relay::{
    RelayDatagramChannel, RelayDatagramClient, RelayIngressStreamChannel, RelayStreamChannel,
};
use confluence_routing::StaticRouter;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// Real localhost TCP + UDP end-to-end port-forward verification across a composed
/// `Alice -> Hop1 (NoiseAclChannel) -> Relay R (Passive Relay) <- Bob` topology!
#[tokio::test]
async fn real_loopback_tcp_and_udp_port_forward_across_multihop_passive_relay() {
    let loopback: SocketAddr = "127.0.0.1:0".parse().unwrap();

    // 1. Spin up real local backend TCP echo server and UDP echo server on Bob's host.
    let backend_tcp = TcpListener::bind(loopback).await.unwrap();
    let backend_tcp_addr = backend_tcp.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = backend_tcp.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let mut reply = b"tcp-echo:".to_vec();
                    reply.extend_from_slice(&buf[..n]);
                    if s.write_all(&reply).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let backend_udp = UdpSocket::bind(loopback).await.unwrap();
    let backend_udp_addr = backend_udp.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, client)) = backend_udp.recv_from(&mut buf).await {
            let mut reply = b"udp-echo:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            let _ = backend_udp.send_to(&reply, client).await;
        }
    });

    let allow_policy = StaticPolicy::new(PolicyConfig {
        default_allow: true,
        default_ttl_secs: 120,
        rules: vec![],
    });

    let scope_e2e = ScopeId::new("real-net").unwrap();
    let scope_h1 = ScopeId::new("h1-egress").unwrap();
    let scope_relay = ScopeId::new("relay-hub").unwrap();

    let alice_kp = StaticKeypair::generate();
    let bob_kp = StaticKeypair::generate();
    let h1_udp_kp = StaticKeypair::generate();
    let h1_tcp_kp = StaticKeypair::generate();
    let r_udp_kp = StaticKeypair::generate();
    let r_tcp_kp = StaticKeypair::generate();

    // 2. Start Relay Node `R` on real localhost UDP + TCP sockets.
    let r_node = Node::new(StaticRouter::new());
    let r_udp = UdpDatagramChannel::bind(ChannelId::new("udp0").unwrap(), loopback, 1400)
        .await
        .unwrap();
    let r_udp_addr = r_udp.local_addr();
    let r_tcp = TcpStreamChannel::bind(ChannelId::new("tcp0").unwrap(), loopback)
        .await
        .unwrap();
    let r_tcp_addr = r_tcp.local_addr().unwrap();
    r_node.attach_datagram_channel(r_udp).unwrap();
    r_node.attach_stream_channel(r_tcp).unwrap();
    r_node
        .mount_datagram_forward_channel(RelayDatagramChannel::new(
            scope_relay.clone(),
            r_udp_kp.clone(),
            1400,
            allow_policy.clone(),
        ))
        .unwrap();
    r_node
        .mount_stream_forward_channel(RelayStreamChannel::new(
            scope_relay,
            r_tcp_kp.clone(),
            allow_policy.clone(),
        ))
        .unwrap();

    // 3. Start Hop 1 Node `H1` on real localhost UDP + TCP sockets.
    let h1_node = Node::new(StaticRouter::new());
    let h1_udp = UdpDatagramChannel::bind(ChannelId::new("udp0").unwrap(), loopback, 1400)
        .await
        .unwrap();
    let h1_udp_addr = h1_udp.local_addr();
    let h1_tcp = TcpStreamChannel::bind(ChannelId::new("tcp0").unwrap(), loopback)
        .await
        .unwrap();
    let h1_tcp_addr = h1_tcp.local_addr().unwrap();
    h1_node.attach_datagram_channel(h1_udp.clone()).unwrap();
    h1_node.attach_stream_channel(h1_tcp.clone()).unwrap();
    h1_node
        .mount_datagram_forward_channel(NoiseAclDatagramChannel::new(
            h1_udp,
            scope_h1.clone(),
            h1_udp_kp.clone(),
            allow_policy.clone(),
        ))
        .unwrap();
    h1_node
        .mount_stream_forward_channel(NoiseAclStreamChannel::new(
            h1_tcp,
            scope_h1,
            h1_tcp_kp.clone(),
            allow_policy.clone(),
        ))
        .unwrap();

    // 4. Start Bob Node `B` (outbound-only behind NAT, registering passive slots on `R`) + Inbound Edge Forwarders!
    let b_node = Node::new(StaticRouter::new());
    b_node
        .add_scope(TrustScope::new(
            scope_e2e.clone(),
            bob_kp.clone(),
            allow_policy.clone(),
        ))
        .unwrap();
    let b_udp = UdpDatagramChannel::bind(ChannelId::new("udp_nat").unwrap(), loopback, 1400)
        .await
        .unwrap();
    b_node.attach_datagram_channel(b_udp).unwrap();

    RelayDatagramClient::new()
        .register_once(
            &b_node,
            &bob_kp,
            &ChannelId::new("udp_nat").unwrap(),
            &ChannelAddr::new(r_udp_addr.to_string()).unwrap(),
            r_udp_kp.peer_id(),
            None,
        )
        .await
        .unwrap();

    let b_tcp_out = TcpStreamChannel::outbound_only(ChannelId::new("tcp_nat").unwrap());
    let b_relay_in = RelayIngressStreamChannel::connect_pool(
        ChannelId::new("relay_in").unwrap(),
        b_tcp_out,
        bob_kp.clone(),
        ChannelAddr::new(r_tcp_addr.to_string()).unwrap(),
        r_tcp_kp.peer_id(),
        None,
        4,
    )
    .await
    .unwrap();
    b_node.attach_stream_channel(b_relay_in).unwrap();

    let ep_name = EndpointName::new("echo-svc").unwrap();
    let _b_tcp_edge =
        TcpInboundForwarder::start(&b_node, &scope_e2e, ep_name.clone(), backend_tcp_addr).unwrap();
    let _b_udp_edge =
        UdpInboundForwarder::start(&b_node, &scope_e2e, ep_name.clone(), backend_udp_addr).unwrap();

    // 5. Start Alice Node `A` with explicit routes `A -> H1 -> R <- B` + Outbound Edge Forwarders!
    let a_router = StaticRouter::new();
    let bob_slot = ChannelAddr::new(bob_kp.peer_id().to_string()).unwrap();
    a_router.upsert_route(
        scope_e2e.clone(),
        ExplicitPath {
            plane: Plane::Stream,
            entry_channel: ChannelId::new("tcp0").unwrap(),
            entry_addr: ChannelAddr::new(h1_tcp_addr.to_string()).unwrap(),
            hops: vec![
                PathHop {
                    target_tag: h1_tcp_kp.target_tag(),
                    channel_pubkey: h1_tcp_kp.peer_id(),
                    next_addr: ChannelAddr::new(r_tcp_addr.to_string()).unwrap(),
                    credential: None,
                },
                PathHop {
                    target_tag: r_tcp_kp.target_tag(),
                    channel_pubkey: r_tcp_kp.peer_id(),
                    next_addr: bob_slot.clone(),
                    credential: None,
                },
            ],
            target_scope_tag: bob_kp.target_tag(),
            target_pubkey: bob_kp.peer_id(),
            target_credential: None,
        },
    );
    a_router.upsert_route(
        scope_e2e.clone(),
        ExplicitPath {
            plane: Plane::Datagram,
            entry_channel: ChannelId::new("udp0").unwrap(),
            entry_addr: ChannelAddr::new(h1_udp_addr.to_string()).unwrap(),
            hops: vec![
                PathHop {
                    target_tag: h1_udp_kp.target_tag(),
                    channel_pubkey: h1_udp_kp.peer_id(),
                    next_addr: ChannelAddr::new(r_udp_addr.to_string()).unwrap(),
                    credential: None,
                },
                PathHop {
                    target_tag: r_udp_kp.target_tag(),
                    channel_pubkey: r_udp_kp.peer_id(),
                    next_addr: bob_slot,
                    credential: None,
                },
            ],
            target_scope_tag: bob_kp.target_tag(),
            target_pubkey: bob_kp.peer_id(),
            target_credential: None,
        },
    );

    let a_node = Node::new(a_router);
    a_node
        .add_scope(TrustScope::new(scope_e2e.clone(), alice_kp, allow_policy))
        .unwrap();
    a_node
        .attach_datagram_channel(
            UdpDatagramChannel::bind(ChannelId::new("udp0").unwrap(), loopback, 1400)
                .await
                .unwrap(),
        )
        .unwrap();
    a_node
        .attach_stream_channel(TcpStreamChannel::outbound_only(
            ChannelId::new("tcp0").unwrap(),
        ))
        .unwrap();

    let a_tcp_bind = TcpOutboundForwarder::bind(
        loopback,
        a_node.clone(),
        scope_e2e.clone(),
        bob_kp.peer_id(),
        ep_name.clone(),
    )
    .await
    .unwrap();
    let a_udp_bind = UdpOutboundForwarder::bind(
        loopback,
        a_node,
        scope_e2e,
        bob_kp.peer_id(),
        ep_name,
    )
    .await
    .unwrap();

    // 6. Connect an ordinary local TCP application client to Alice's local TCP port!
    let mut app_tcp = TcpStream::connect(a_tcp_bind.local_addr()).await.unwrap();
    app_tcp.write_all(b"real-socket-hello").await.unwrap();
    let mut tcp_resp = [0u8; 64];
    let tn = app_tcp.read(&mut tcp_resp).await.unwrap();
    assert_eq!(&tcp_resp[..tn], b"tcp-echo:real-socket-hello");

    // 7. Send ordinary local UDP application datagrams to Alice's local UDP port!
    let app_udp = UdpSocket::bind(loopback).await.unwrap();
    app_udp
        .send_to(b"real-udp-ping", a_udp_bind.local_addr())
        .await
        .unwrap();
    let mut udp_resp = [0u8; 64];
    let (un, _) = app_udp.recv_from(&mut udp_resp).await.unwrap();
    assert_eq!(&udp_resp[..un], b"udp-echo:real-udp-ping");
}
