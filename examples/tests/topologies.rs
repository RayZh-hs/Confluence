#![cfg(target_os = "linux")]

use confluence_core::ScopeKeypair;
use confluence_examples::{
    Ports, direct,
    relayed::{self, TransitPeer},
};
use confluence_runtime::{NodePlan, RunningNode};
use std::{
    net::{Ipv4Addr, SocketAddr},
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

fn ephemeral() -> Ports {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    Ports {
        tcp: addr,
        udp: addr,
    }
}

fn ingress(node: &RunningNode) -> Ports {
    Ports {
        tcp: node.tcp_listener_addrs()[0],
        udp: node.udp_listener_addrs()[0],
    }
}

async fn start(plan: NodePlan) -> RunningNode {
    timeout(WAIT, plan.prepare().unwrap().start())
        .await
        .unwrap()
        .unwrap()
}

async fn check_forward(node: RunningNode, payload: &[u8]) {
    let [tcp, udp] = node.forwards() else {
        panic!("expected a TCP and UDP forward")
    };
    assert_tcp_udp_roundtrip(tcp.addr, udp.addr, payload).await;
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_passive_relay_and_multihop_forward_both_planes() {
    let (tcp, udp, backends) = spawn_echo_backends().await;
    let backend = Ports { tcp, udp };
    let alice = ScopeKeypair::generate();
    let bob = ScopeKeypair::generate();
    let relay = ScopeKeypair::generate();
    let hop = ScopeKeypair::generate();
    let alice_key = alice.public_key();
    let bob_key = bob.public_key();
    let relay_key = relay.public_key();
    let hop_key = hop.public_key();
    let endpoint_token = "end-to-end";
    let registration_token = "register-bob";
    let relay_token = "transit-relay";
    let hop_token = "transit-hop";

    let direct_bob = start(
        direct::bob(
            ScopeKeypair::from_bytes(bob.secret_bytes()),
            alice_key,
            endpoint_token,
            backend,
            ephemeral(),
        )
        .unwrap(),
    )
    .await;
    let direct_alice = start(
        direct::alice(
            ScopeKeypair::from_bytes(alice.secret_bytes()),
            bob_key,
            endpoint_token,
            ingress(&direct_bob),
            ephemeral(),
        )
        .unwrap(),
    )
    .await;
    check_forward(direct_alice, b"direct").await;
    direct_bob.shutdown().await;

    let relay = start(
        relayed::relay(
            relay,
            alice_key,
            bob_key,
            relay_token,
            registration_token,
            ephemeral(),
        )
        .unwrap(),
    )
    .await;
    let relay_ingress = ingress(&relay);
    let bob = start(
        relayed::bob(
            bob,
            alice_key,
            endpoint_token,
            backend,
            relay_key,
            relay_ingress,
            registration_token,
        )
        .unwrap(),
    )
    .await;
    let relay_alice = start(
        relayed::alice(
            ScopeKeypair::from_bytes(alice.secret_bytes()),
            bob_key,
            endpoint_token,
            TransitPeer {
                peer: relay_key,
                token: relay_token,
            },
            relay_ingress,
            ephemeral(),
            None,
        )
        .unwrap(),
    )
    .await;
    check_forward(relay_alice, b"passive relay").await;

    let hop =
        start(relayed::hop(hop, alice_key, hop_token, ephemeral(), relay_ingress).unwrap()).await;
    let multihop_alice = start(
        relayed::alice(
            alice,
            bob_key,
            endpoint_token,
            TransitPeer {
                peer: relay_key,
                token: relay_token,
            },
            ingress(&hop),
            ephemeral(),
            Some(TransitPeer {
                peer: hop_key,
                token: hop_token,
            }),
        )
        .unwrap(),
    )
    .await;
    check_forward(multihop_alice, b"multihop").await;

    bob.shutdown().await;
    hop.shutdown().await;
    relay.shutdown().await;
    for backend in backends {
        backend.abort();
    }
}
