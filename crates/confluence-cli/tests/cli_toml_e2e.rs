#![cfg(target_os = "linux")]

use confluence_cli::{NodeConfig, RunningNode, generate_keypair_hex};
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(5);

async fn spawn_echo_backends() -> (SocketAddr, SocketAddr, Vec<tokio::task::JoinHandle<()>>) {
    let tcp_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();
    let t_tcp = tokio::spawn(async move {
        while let Ok((stream, _)) = tcp_listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = stream.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });

    let udp_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let udp_addr = udp_sock.local_addr().unwrap();
    let t_udp = tokio::spawn(async move {
        let mut buf = vec![0u8; 65_507];
        while let Ok((n, src)) = udp_sock.recv_from(&mut buf).await {
            if udp_sock.send_to(&buf[..n], src).await.is_err() {
                break;
            }
        }
    });

    (tcp_addr, udp_addr, vec![t_tcp, t_udp])
}

async fn assert_tcp_udp_roundtrip(tcp_addr: SocketAddr, udp_addr: SocketAddr, payload: &[u8]) {
    let mut tcp = timeout(WAIT, TcpStream::connect(tcp_addr))
        .await
        .unwrap()
        .unwrap();
    tcp.write_all(payload).await.unwrap();
    tcp.shutdown().await.unwrap();
    let mut tcp_reply = Vec::new();
    timeout(WAIT, tcp.read_to_end(&mut tcp_reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tcp_reply, payload);

    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    udp.connect(udp_addr).await.unwrap();
    udp.send(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len() + 32];
    let n = timeout(WAIT, udp.recv(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..n], payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn declarative_toml_cli_runs_direct_and_multihop_passive_relay_e2e() {
    let (tcp_echo, udp_echo, backends) = spawn_echo_backends().await;
    let (a_sec, a_pub, _) = generate_keypair_hex();
    let (h1_sec, h1_pub, _) = generate_keypair_hex();
    let (r_sec, r_pub, _) = generate_keypair_hex();
    let (b_sec, b_pub, _) = generate_keypair_hex();

    // --- 1. Start Passive Relay R (single TCP + single UDP port, zero outbound dialing) ---
    let relay_toml = format!(
        r#"
        [policy]
        default_allow = false
        default_ttl_secs = 120

        [[policy.rules]]
        scope = "default"
        peers = ["{a_pub}"]
        action = "transit"
        target = "relay/bob-nat"
        required_credential = "relay-tok"

        [[scopes]]
        name = "default"
        secret_key = "{r_sec}"

        [[tcp_listeners]]
        listen_addr = "127.0.0.1:0"

        [[udp_listeners]]
        bind_addr = "127.0.0.1:0"
        mtu = 1400

        [[relay_transits]]
        scope = "default"
        prefix = "relay/"
        stream_mtu = 16384
        datagram_mtu = 1400

        [[relay_transits.registration_rules]]
        peers = ["{b_pub}"]
        presence = "bob-nat"
        required_credential = "reg-tok"
        ttl_secs = 120
        "#
    );
    let relay_node = RunningNode::start(NodeConfig::from_toml_str(&relay_toml).unwrap())
        .await
        .unwrap();
    let r_tcp = relay_node.tcp_listener_addrs[0];
    let r_udp = relay_node.udp_listener_addrs[0];

    // --- 2. Start Transit Hop H1 (named transit "to-relay" hiding R's address + MAC2 cookies) ---
    let h1_toml = format!(
        r#"
        [policy]
        default_allow = false
        default_ttl_secs = 120

        [[policy.rules]]
        scope = "default"
        peers = ["{a_pub}"]
        action = "transit"
        target = "to-relay"
        required_credential = "hop1-tok"

        [[scopes]]
        name = "default"
        secret_key = "{h1_sec}"
        under_load = true

        [[tcp_listeners]]
        listen_addr = "127.0.0.1:0"

        [[udp_listeners]]
        bind_addr = "127.0.0.1:0"
        mtu = 1400

        [[transits]]
        scope = "default"
        name = "to-relay"
        plane = "stream"
        target_addr = "{r_tcp}"

        [[transits]]
        scope = "default"
        name = "to-relay"
        plane = "datagram"
        target_addr = "{r_udp}"
        mtu = 1400
        "#
    );
    let h1_node = RunningNode::start(NodeConfig::from_toml_str(&h1_toml).unwrap())
        .await
        .unwrap();
    let h1_tcp = h1_node.tcp_listener_addrs[0];
    let h1_udp = h1_node.udp_listener_addrs[0];

    // --- 3. Start Bob (serves BOTH direct listeners AND NATed passive registration to R!) ---
    let bob_toml = format!(
        r#"
        [policy]
        default_allow = false
        default_ttl_secs = 120

        [[policy.rules]]
        scope = "default"
        peers = ["{a_pub}"]
        action = "endpoint"
        plane = "stream"
        target = "demo-tcp"
        required_credential = "bob-tok"

        [[policy.rules]]
        scope = "default"
        peers = ["{a_pub}"]
        action = "endpoint"
        plane = "datagram"
        target = "demo-udp"
        required_credential = "bob-tok"

        [[scopes]]
        name = "default"
        secret_key = "{b_sec}"
        under_load = true

        [[tcp_listeners]]
        listen_addr = "127.0.0.1:0"

        [[udp_listeners]]
        bind_addr = "127.0.0.1:0"
        mtu = 1400

        [[relay_registrations]]
        scope = "default"
        plane = "stream"
        relay_addr = "{r_tcp}"
        relay_pubkey = "{r_pub}"
        presence_id = "bob-nat"
        credential = "reg-tok"
        pool_size = 2

        [[relay_registrations]]
        scope = "default"
        plane = "datagram"
        relay_addr = "{r_udp}"
        relay_pubkey = "{r_pub}"
        presence_id = "bob-nat"
        credential = "reg-tok"
        mtu = 1400

        [[publish_endpoints]]
        scope = "default"
        endpoint = "demo-tcp"
        plane = "stream"
        local_target = "{tcp_echo}"

        [[publish_endpoints]]
        scope = "default"
        endpoint = "demo-udp"
        plane = "datagram"
        local_target = "{udp_echo}"
        min_mtu = 1232
        "#
    );
    let bob_node = RunningNode::start(NodeConfig::from_toml_str(&bob_toml).unwrap())
        .await
        .unwrap();
    let b_tcp = bob_node.tcp_listener_addrs[0];
    let b_udp = bob_node.udp_listener_addrs[0];

    // --- 4A. Alice Direct (A -> B) ---
    let alice_direct_toml = format!(
        r#"
        [[scopes]]
        name = "default"
        secret_key = "{a_sec}"

        [[credentials]]
        scope = "default"
        verifier = "{b_pub}"
        action = "endpoint"
        credential = "bob-tok"

        [[outbound_carriers]]
        scope = "default"
        name = "tcp"
        plane = "stream"

        [[outbound_carriers]]
        scope = "default"
        name = "udp"
        plane = "datagram"
        mtu = 1400

        [[routes]]
        id = 1
        scope = "default"
        target_pubkey = "{b_pub}"
        endpoint = "demo-tcp"
        plane = "stream"
        first_channel = "tcp"
        first_locator = "{b_tcp}"

        [[routes]]
        id = 2
        scope = "default"
        target_pubkey = "{b_pub}"
        endpoint = "demo-udp"
        plane = "datagram"
        first_channel = "udp"
        first_locator = "{b_udp}"
        min_mtu = 1232

        [[bind_endpoints]]
        scope = "default"
        target_pubkey = "{b_pub}"
        endpoint = "demo-tcp"
        plane = "stream"
        listen_addr = "127.0.0.1:0"

        [[bind_endpoints]]
        scope = "default"
        target_pubkey = "{b_pub}"
        endpoint = "demo-udp"
        plane = "datagram"
        listen_addr = "127.0.0.1:0"
        min_mtu = 1232
        "#
    );
    let alice_direct = RunningNode::start(NodeConfig::from_toml_str(&alice_direct_toml).unwrap())
        .await
        .unwrap();
    assert_tcp_udp_roundtrip(
        alice_direct.bound_tcp_addrs["demo-tcp"],
        alice_direct.bound_udp_addrs["demo-udp"],
        b"hello-direct-cli",
    )
    .await;
    alice_direct.shutdown();

    // --- 4B. Alice Multi-Hop + Passive Relay (A -> H1 -> R <- B) ---
    let alice_chain_toml = format!(
        r#"
        [[scopes]]
        name = "default"
        secret_key = "{a_sec}"

        [[credentials]]
        scope = "default"
        verifier = "{h1_pub}"
        action = "transit"
        target = "to-relay"
        credential = "hop1-tok"

        [[credentials]]
        scope = "default"
        verifier = "{r_pub}"
        action = "transit"
        target = "relay/bob-nat"
        credential = "relay-tok"

        [[credentials]]
        scope = "default"
        verifier = "{b_pub}"
        action = "endpoint"
        credential = "bob-tok"

        [[outbound_carriers]]
        scope = "default"
        name = "tcp"
        plane = "stream"

        [[outbound_carriers]]
        scope = "default"
        name = "udp"
        plane = "datagram"
        mtu = 1400

        [[routes]]
        id = 10
        scope = "default"
        target_pubkey = "{b_pub}"
        endpoint = "demo-tcp"
        plane = "stream"
        first_channel = "tcp"
        first_locator = "{h1_tcp}"

        [[routes.hops]]
        peer = "{h1_pub}"
        target = "to-relay"

        [[routes.hops]]
        peer = "{r_pub}"
        target = "relay/bob-nat"

        [[routes]]
        id = 11
        scope = "default"
        target_pubkey = "{b_pub}"
        endpoint = "demo-udp"
        plane = "datagram"
        first_channel = "udp"
        first_locator = "{h1_udp}"
        min_mtu = 1232

        [[routes.hops]]
        peer = "{h1_pub}"
        target = "to-relay"

        [[routes.hops]]
        peer = "{r_pub}"
        target = "relay/bob-nat"

        [[bind_endpoints]]
        scope = "default"
        target_pubkey = "{b_pub}"
        endpoint = "demo-tcp"
        plane = "stream"
        listen_addr = "127.0.0.1:0"

        [[bind_endpoints]]
        scope = "default"
        target_pubkey = "{b_pub}"
        endpoint = "demo-udp"
        plane = "datagram"
        listen_addr = "127.0.0.1:0"
        min_mtu = 1232
        "#
    );
    let alice_chain = RunningNode::start(NodeConfig::from_toml_str(&alice_chain_toml).unwrap())
        .await
        .unwrap();
    assert_tcp_udp_roundtrip(
        alice_chain.bound_tcp_addrs["demo-tcp"],
        alice_chain.bound_udp_addrs["demo-udp"],
        b"hello-multihop-passive-relay-cli",
    )
    .await;

    alice_chain.shutdown();
    bob_node.shutdown();
    h1_node.shutdown();
    relay_node.shutdown();
    for b in backends {
        b.abort();
    }
}

#[test]
fn all_repository_example_toml_configs_validate_cleanly() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let examples_dir = manifest_dir.join("../../examples");
    let expected = [
        "direct/alice.toml",
        "direct/bob.toml",
        "passive-relay/alice.toml",
        "passive-relay/relay.toml",
        "passive-relay/bob.toml",
        "multihop-relay/alice.toml",
        "multihop-relay/hop1.toml",
        "multihop-relay/relay.toml",
        "multihop-relay/bob.toml",
    ];
    for rel in expected {
        let path = examples_dir.join(rel);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        NodeConfig::from_toml_str(&text)
            .unwrap_or_else(|e| panic!("invalid example {}: {e}", path.display()));
    }
}
