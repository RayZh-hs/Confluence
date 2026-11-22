use confluence_cli::{NodeConfig, RunningNode};
use confluence_core::StaticKeypair;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

async fn spawn_echo_backends() -> (SocketAddr, SocketAddr) {
    let loopback: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let tcp_listener = TcpListener::bind(loopback).await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = tcp_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let udp_sock = UdpSocket::bind(loopback).await.unwrap();
    let udp_addr = udp_sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, src)) = udp_sock.recv_from(&mut buf).await {
            let _ = udp_sock.send_to(&buf[..n], src).await;
        }
    });

    (tcp_addr, udp_addr)
}

#[tokio::test]
async fn declarative_toml_cli_runs_direct_passive_relay_and_multihop_e2e() {
    let (backend_tcp, backend_udp) = spawn_echo_backends().await;

    let alice_kp = StaticKeypair::from_secret_bytes([0x11; 32]);
    let bob_kp = StaticKeypair::from_secret_bytes([0x22; 32]);
    let relay_udp_kp = StaticKeypair::from_secret_bytes([0x33; 32]);
    let relay_tcp_kp = StaticKeypair::from_secret_bytes([0x44; 32]);
    let hop1_udp_kp = StaticKeypair::from_secret_bytes([0x55; 32]);
    let hop1_tcp_kp = StaticKeypair::from_secret_bytes([0x66; 32]);

    let a_sec = hex::encode(alice_kp.secret_bytes());
    let b_sec = hex::encode(bob_kp.secret_bytes());
    let r_u_sec = hex::encode(relay_udp_kp.secret_bytes());
    let r_t_sec = hex::encode(relay_tcp_kp.secret_bytes());
    let h1_u_sec = hex::encode(hop1_udp_kp.secret_bytes());
    let h1_t_sec = hex::encode(hop1_tcp_kp.secret_bytes());

    // --- 1. Boot Relay Node `R` from TOML ---
    let relay_toml = format!(
        r#"
        [policy]
        default_allow = false
        default_ttl_secs = 120

        [[policy.rules]]
        scope = "relay-scope"
        peers = ["{bob_id}"]
        action = "channel_custom"
        target = "relay_register"

        [[policy.rules]]
        scope = "relay-scope"
        peers = ["{alice_id}"]
        action = "channel_custom"
        target = "relay_connect"
        required_credential = "relay-pass"

        [[udp_carriers]]
        id = "udp0"
        bind_addr = "127.0.0.1:0"

        [[tcp_carriers]]
        id = "tcp0"
        listen_addr = "127.0.0.1:0"

        [[relay_channels]]
        plane = "datagram"
        scope = "relay-scope"
        secret_key = "{r_u_sec}"

        [[relay_channels]]
        plane = "stream"
        scope = "relay-scope"
        secret_key = "{r_t_sec}"
        "#,
        bob_id = bob_kp.peer_id(),
        alice_id = alice_kp.peer_id(),
    );
    let relay_node = RunningNode::start(NodeConfig::from_toml_str(&relay_toml).unwrap())
        .await
        .unwrap();
    let r_udp_addr = relay_node.udp_carrier_addr("udp0").unwrap();
    let r_tcp_addr = relay_node.tcp_carrier_addr("tcp0").unwrap();

    // --- 2. Boot Hop1 Node `H1` from TOML ---
    let hop1_toml = format!(
        r#"
        [policy]
        default_allow = false
        default_ttl_secs = 120

        [[policy.rules]]
        scope = "hop1-scope"
        peers = ["{alice_id}"]
        action = "channel_forward"
        required_credential = "hop1-pass"

        [[udp_carriers]]
        id = "udp0"
        bind_addr = "127.0.0.1:0"

        [[tcp_carriers]]
        id = "tcp0"
        listen_addr = "127.0.0.1:0"

        [[acl_forward_channels]]
        plane = "datagram"
        carrier_id = "udp0"
        scope = "hop1-scope"
        secret_key = "{h1_u_sec}"

        [[acl_forward_channels]]
        plane = "stream"
        carrier_id = "tcp0"
        scope = "hop1-scope"
        secret_key = "{h1_t_sec}"
        "#,
        alice_id = alice_kp.peer_id(),
    );
    let hop1_node = RunningNode::start(NodeConfig::from_toml_str(&hop1_toml).unwrap())
        .await
        .unwrap();
    let h1_udp_addr = hop1_node.udp_carrier_addr("udp0").unwrap();
    let h1_tcp_addr = hop1_node.tcp_carrier_addr("tcp0").unwrap();

    // --- 3. Boot Destination Node `B` from TOML (supports BOTH Direct listener AND Passive Relay presence!) ---
    let bob_toml = format!(
        r#"
        [policy]
        default_allow = false
        default_ttl_secs = 120

        [[policy.rules]]
        scope = "demo-group"
        peers = ["{alice_id}"]
        action = "open_endpoint"
        required_credential = "bob-e2e-pass"

        [[scopes]]
        id = "demo-group"
        secret_key = "{b_sec}"

        [[udp_carriers]]
        id = "udp0"
        bind_addr = "127.0.0.1:0"

        [[tcp_carriers]]
        id = "tcp0"
        listen_addr = "127.0.0.1:0"

        [[relay_registrations]]
        plane = "datagram"
        scope = "demo-group"
        carrier_id = "udp0"
        relay_addr = "{r_udp_addr}"
        relay_pubkey = "{r_u_pk}"

        [[relay_registrations]]
        plane = "stream"
        scope = "demo-group"
        carrier_id = "tcp0"
        ingress_id = "relay_in"
        relay_addr = "{r_tcp_addr}"
        relay_pubkey = "{r_t_pk}"
        pool_size = 4

        [[publish_endpoints]]
        scope = "demo-group"
        endpoint = "app"
        plane = "stream"
        local_target = "{backend_tcp}"

        [[publish_endpoints]]
        scope = "demo-group"
        endpoint = "app"
        plane = "datagram"
        local_target = "{backend_udp}"
        "#,
        alice_id = alice_kp.peer_id(),
        r_u_pk = relay_udp_kp.peer_id(),
        r_t_pk = relay_tcp_kp.peer_id(),
    );
    let bob_node = RunningNode::start(NodeConfig::from_toml_str(&bob_toml).unwrap())
        .await
        .unwrap();
    let b_direct_udp = bob_node.udp_carrier_addr("udp0").unwrap();
    let b_direct_tcp = bob_node.tcp_carrier_addr("tcp0").unwrap();

    // --- 4A. Verify DIRECT Alice TOML (`A -> B`) ---
    let alice_direct_toml = format!(
        r#"
        [policy]
        default_allow = true

        [[scopes]]
        id = "demo-group"
        secret_key = "{a_sec}"

        [[udp_carriers]]
        id = "udp0"
        bind_addr = "127.0.0.1:0"

        [[tcp_carriers]]
        id = "tcp0"

        [[routes]]
        scope = "demo-group"
        target_pubkey = "{b_pk}"
        plane = "stream"
        entry_channel = "tcp0"
        entry_addr = "{b_direct_tcp}"
        target_credential = "bob-e2e-pass"

        [[routes]]
        scope = "demo-group"
        target_pubkey = "{b_pk}"
        plane = "datagram"
        entry_channel = "udp0"
        entry_addr = "{b_direct_udp}"
        target_credential = "bob-e2e-pass"

        [[bind_endpoints]]
        scope = "demo-group"
        target_pubkey = "{b_pk}"
        endpoint = "app"
        plane = "stream"
        listen_addr = "127.0.0.1:0"

        [[bind_endpoints]]
        scope = "demo-group"
        target_pubkey = "{b_pk}"
        endpoint = "app"
        plane = "datagram"
        listen_addr = "127.0.0.1:0"
        "#,
        b_pk = bob_kp.peer_id(),
    );
    let a_direct = RunningNode::start(NodeConfig::from_toml_str(&alice_direct_toml).unwrap())
        .await
        .unwrap();
    assert_tcp_udp_roundtrip(
        a_direct.bound_tcp_edge_addr("demo-group", "app").unwrap(),
        a_direct.bound_udp_edge_addr("demo-group", "app").unwrap(),
        b"direct-toml-msg",
    )
    .await;
    a_direct.shutdown().await;

    // --- 4B. Verify PASSIVE RELAY Alice TOML (`A -> R <- B`) ---
    let alice_relay_toml = format!(
        r#"
        [policy]
        default_allow = true

        [[scopes]]
        id = "demo-group"
        secret_key = "{a_sec}"

        [[udp_carriers]]
        id = "udp0"
        bind_addr = "127.0.0.1:0"

        [[tcp_carriers]]
        id = "tcp0"

        [[routes]]
        scope = "demo-group"
        target_pubkey = "{b_pk}"
        plane = "stream"
        entry_channel = "tcp0"
        entry_addr = "{r_tcp_addr}"
        target_credential = "bob-e2e-pass"

        [[routes.hops]]
        channel_pubkey = "{r_t_pk}"
        next_addr = "{b_pk}"
        credential = "relay-pass"

        [[routes]]
        scope = "demo-group"
        target_pubkey = "{b_pk}"
        plane = "datagram"
        entry_channel = "udp0"
        entry_addr = "{r_udp_addr}"
        target_credential = "bob-e2e-pass"

        [[routes.hops]]
        channel_pubkey = "{r_u_pk}"
        next_addr = "{b_pk}"
        credential = "relay-pass"

        [[bind_endpoints]]
        scope = "demo-group"
        target_pubkey = "{b_pk}"
        endpoint = "app"
        plane = "stream"
        listen_addr = "127.0.0.1:0"

        [[bind_endpoints]]
        scope = "demo-group"
        target_pubkey = "{b_pk}"
        endpoint = "app"
        plane = "datagram"
        listen_addr = "127.0.0.1:0"
        "#,
        b_pk = bob_kp.peer_id(),
        r_t_pk = relay_tcp_kp.peer_id(),
        r_u_pk = relay_udp_kp.peer_id(),
    );
    let a_relay = RunningNode::start(NodeConfig::from_toml_str(&alice_relay_toml).unwrap())
        .await
        .unwrap();
    assert_tcp_udp_roundtrip(
        a_relay.bound_tcp_edge_addr("demo-group", "app").unwrap(),
        a_relay.bound_udp_edge_addr("demo-group", "app").unwrap(),
        b"passive-relay-toml-msg",
    )
    .await;
    a_relay.shutdown().await;

    // --- 4C. Verify MULTI-HOP + PASSIVE RELAY Alice TOML (`A -> H1 -> R <- B`) ---
    let alice_mhop_toml = format!(
        r#"
        [policy]
        default_allow = true

        [[scopes]]
        id = "demo-group"
        secret_key = "{a_sec}"

        [[udp_carriers]]
        id = "udp0"
        bind_addr = "127.0.0.1:0"

        [[tcp_carriers]]
        id = "tcp0"

        [[routes]]
        scope = "demo-group"
        target_pubkey = "{b_pk}"
        plane = "stream"
        entry_channel = "tcp0"
        entry_addr = "{h1_tcp_addr}"
        target_credential = "bob-e2e-pass"

        [[routes.hops]]
        channel_pubkey = "{h1_t_pk}"
        next_addr = "{r_tcp_addr}"
        credential = "hop1-pass"

        [[routes.hops]]
        channel_pubkey = "{r_t_pk}"
        next_addr = "{b_pk}"
        credential = "relay-pass"

        [[routes]]
        scope = "demo-group"
        target_pubkey = "{b_pk}"
        plane = "datagram"
        entry_channel = "udp0"
        entry_addr = "{h1_udp_addr}"
        target_credential = "bob-e2e-pass"

        [[routes.hops]]
        channel_pubkey = "{h1_u_pk}"
        next_addr = "{r_udp_addr}"
        credential = "hop1-pass"

        [[routes.hops]]
        channel_pubkey = "{r_u_pk}"
        next_addr = "{b_pk}"
        credential = "relay-pass"

        [[bind_endpoints]]
        scope = "demo-group"
        target_pubkey = "{b_pk}"
        endpoint = "app"
        plane = "stream"
        listen_addr = "127.0.0.1:0"

        [[bind_endpoints]]
        scope = "demo-group"
        target_pubkey = "{b_pk}"
        endpoint = "app"
        plane = "datagram"
        listen_addr = "127.0.0.1:0"
        "#,
        b_pk = bob_kp.peer_id(),
        h1_t_pk = hop1_tcp_kp.peer_id(),
        h1_u_pk = hop1_udp_kp.peer_id(),
        r_t_pk = relay_tcp_kp.peer_id(),
        r_u_pk = relay_udp_kp.peer_id(),
    );
    let a_mhop = RunningNode::start(NodeConfig::from_toml_str(&alice_mhop_toml).unwrap())
        .await
        .unwrap();
    assert_tcp_udp_roundtrip(
        a_mhop.bound_tcp_edge_addr("demo-group", "app").unwrap(),
        a_mhop.bound_udp_edge_addr("demo-group", "app").unwrap(),
        b"multihop-relay-toml-msg",
    )
    .await;

    a_mhop.shutdown().await;
    bob_node.shutdown().await;
    hop1_node.shutdown().await;
    relay_node.shutdown().await;
}

async fn assert_tcp_udp_roundtrip(tcp_addr: SocketAddr, udp_addr: SocketAddr, msg: &[u8]) {
    let mut tcp = TcpStream::connect(tcp_addr).await.unwrap();
    tcp.write_all(msg).await.unwrap();
    let mut rbuf = vec![0u8; msg.len()];
    tcp.read_exact(&mut rbuf).await.unwrap();
    assert_eq!(rbuf, msg);

    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.send_to(msg, udp_addr).await.unwrap();
    let mut ubuf = [0u8; 256];
    let (n, _) = udp.recv_from(&mut ubuf).await.unwrap();
    assert_eq!(&ubuf[..n], msg);
}

#[test]
fn all_repository_example_toml_configs_validate_cleanly() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    let examples_dir = workspace_root.join("examples");

    let expected_files = [
        "direct/bob.toml",
        "direct/alice.toml",
        "passive-relay/relay.toml",
        "passive-relay/bob.toml",
        "passive-relay/alice.toml",
        "multihop-relay/hop1.toml",
        "multihop-relay/relay.toml",
        "multihop-relay/bob.toml",
        "multihop-relay/alice.toml",
    ];

    for rel in expected_files {
        let full = examples_dir.join(rel);
        let raw = std::fs::read_to_string(&full)
            .unwrap_or_else(|e| panic!("failed to read example {}: {e}", full.display()));
        NodeConfig::from_toml_str(&raw)
            .unwrap_or_else(|e| panic!("example {} failed validation: {e}", full.display()));
    }
}
