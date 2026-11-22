//! Comprehensive evaluation suite exercising out-of-core Confluence plugins
//! across channels, ACLs, cross-plane adapters, UDP P2P, and application archetypes.

use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use confluence_core::{
    Authorizer, CoreErr, CredentialProvider, CredentialRequest, DATAGRAM_MTU, DatagramChannel,
    DatagramLink, ExplicitPath, HopSpec, IntersectAuthorizer, Lease, PacketBuf, PathOutcome, Plane,
    ScopeInstance, ScopeKeypair,
};
use confluence_edge::{Destination, TcpTarget, UdpTarget, serve_local_tcp, serve_local_udp};
use confluence_ext::{
    acl::{FnCredentials, GroupAcl, GroupIssuer, GroupRule, LocalHostPolicy, caps},
    cross_plane::{
        SodMux, StreamOverDatagramChannel, StripedConfig, StripedTcpDatagramChannel,
        serve_striped_tcp_datagram,
    },
    encrypted::{
        DG_LINK_OVERHEAD, EncryptedDatagramChannel, EncryptedDatagramLink, EncryptedLocator,
        EncryptedStream, EncryptedStreamChannel, EncryptedUdpNode, MuxPassiveStreamRelay,
        encode_slot_hex, serve_encrypted_tcp,
    },
    tailscale_mesh::{
        KvClient, KvService, MESH_ENDPOINT, PathCandidate, SmartPathSource, VirtualL3Node,
    },
    udp_p2p::{BlindRendezvous, HostUdpTransport, NatKind, PeerMetadata, SimNat, UdpP2pNode},
};
use confluence_net::{TcpCarrier, TcpIo, serve_tcp};
use confluence_plugins::{
    MemDatagramChannel, MemStreamChannel, StaticAuthorizer, StaticCredentials, StaticPathSource,
    TokioSpawner, mem_datagram_pair,
};
use confluence_relay::PassiveRelay;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{sleep, timeout},
};

const WAIT: Duration = Duration::from_secs(5);

fn local() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn spawn_scope(
    auth: Arc<dyn Authorizer>,
    routes: Arc<dyn confluence_core::PathSource>,
) -> ScopeInstance {
    ScopeInstance::builder(ScopeKeypair::generate(), Arc::new(TokioSpawner))
        .authorizer(auth)
        .routes(routes)
        .build()
}

fn spawn_scope_with_creds(
    kp: ScopeKeypair,
    auth: Arc<dyn Authorizer>,
    routes: Arc<dyn confluence_core::PathSource>,
    creds: Arc<dyn CredentialProvider>,
) -> ScopeInstance {
    ScopeInstance::builder(kp, Arc::new(TokioSpawner))
        .authorizer(auth)
        .routes(routes)
        .credentials(creds)
        .build()
}

fn start_tcp_echo_multi(listener: TcpListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = stream.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    })
}

fn start_udp_echo(socket: UdpSocket) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65507];
        while let Ok((n, src)) = socket.recv_from(&mut buf).await {
            if socket.send_to(&buf[..n], src).await.is_err() {
                break;
            }
        }
    })
}

// ===========================================================================
// TEST 1: Group Semantic ACL, Short-Lived Tokens, Live Renewal, CRL,
//         IntersectAuthorizer Host Veto, and Named Transit SSRF Prevention
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_group_acl_capabilities_renewal_crl_and_host_veto_intersection() {
    let group_secret = [0x5Au8; 32];
    let issuer = Arc::new(GroupIssuer::new(777, group_secret));

    let group_acl = Arc::new(GroupAcl::new(
        777,
        group_secret,
        GroupRule {
            required_caps: 0,
            allowed_endpoints: None,
            allowed_transits: None,
            max_ttl: Duration::from_secs(10),
        },
    ));

    // Destination B enforces Core's IntersectAuthorizer(LocalHostPolicy, GroupAcl):
    // LocalHostPolicy only exposes "minecraft", vetoing "admin-db" even if the
    // Group issuer minted a wildcard member token!
    let local_policy = Arc::new(LocalHostPolicy::default());
    local_policy.allow_endpoint("minecraft");
    local_policy.set_max_ttl(Duration::from_millis(850));
    let b_auth = Arc::new(IntersectAuthorizer::new(local_policy, group_acl.clone()));

    let a_routes = Arc::new(SmartPathSource::default());
    let empty_routes = Arc::new(StaticPathSource::default());

    let alice_kp = ScopeKeypair::generate();
    let alice_pk = alice_kp.public_key();
    let alice_token = Arc::new(RwLock::new(Vec::<u8>::new()));
    let refresh_count = Arc::new(AtomicUsize::new(0));
    let auto_refresh = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let tok_slot = alice_token.clone();
    let issuer_r = issuer.clone();
    let count_r = refresh_count.clone();
    let auto_r = auto_refresh.clone();
    let alice_creds = Arc::new(FnCredentials(move |req: CredentialRequest<'_>| {
        if req.is_refresh && auto_r.load(Ordering::Acquire) {
            if req.target.is_endpoint() {
                count_r.fetch_add(1, Ordering::Relaxed);
                let (_, fresh) = issuer_r.issue(
                    alice_pk,
                    caps::MEMBER,
                    Some("minecraft"),
                    Duration::from_secs(5),
                    0,
                );
                return Ok(fresh);
            }
            let (_, fresh) =
                issuer_r.issue(alice_pk, caps::MEMBER, None, Duration::from_secs(5), 0);
            return Ok(fresh);
        }
        Ok(tok_slot.read().unwrap().clone())
    }));

    let charlie_kp = ScopeKeypair::generate();
    let charlie_creds = Arc::new(StaticCredentials::default());

    // Hop enforces named transit allowlist: only "allowed-bob" is published & authorized!
    let hop_local = Arc::new(LocalHostPolicy::default());
    hop_local.allow_transit("allowed-bob");
    let hop_auth = Arc::new(IntersectAuthorizer::new(hop_local, group_acl.clone()));

    let alice = spawn_scope_with_creds(alice_kp, group_acl.clone(), a_routes.clone(), alice_creds);
    let bob = spawn_scope(b_auth, empty_routes.clone());
    let charlie = spawn_scope_with_creds(
        charlie_kp,
        group_acl.clone(),
        a_routes.clone(),
        charlie_creds.clone(),
    );
    let hop = spawn_scope(hop_auth, empty_routes);

    // Wire in-memory stream fabric: A/C -> B directly, and A -> Hop -> B
    let mem_direct = MemStreamChannel::new(4096, 4096);
    let _l_direct = tokio::spawn(mem_direct.listen(b"bob").unwrap().serve_stream(bob.clone()));
    alice
        .register_stream_carrier("direct", Arc::new(mem_direct.clone()))
        .unwrap();
    charlie
        .register_stream_carrier("direct", Arc::new(mem_direct))
        .unwrap();

    let mem_to_hop = MemStreamChannel::new(4096, 4096);
    let mem_hop_out = MemStreamChannel::new(4096, 4096);
    let _l_hop = tokio::spawn(mem_to_hop.listen(b"hop").unwrap().serve_stream(hop.clone()));
    let _l_b2 = tokio::spawn(
        mem_hop_out
            .listen(b"allowed-bob")
            .unwrap()
            .serve_stream(bob.clone()),
    );
    alice
        .register_stream_carrier("to-hop", Arc::new(mem_to_hop))
        .unwrap();
    // Named transit replaces ScopedTransitWrapper completely!
    let _g_hop = hop
        .publish_stream_route("allowed-bob", mem_hop_out, b"allowed-bob")
        .unwrap();

    let kv = KvService::new();
    let _p1 = bob.publish_stream("minecraft", kv.clone()).unwrap();
    let _p2 = bob.publish_stream("admin-db", kv).unwrap();

    for ep in ["minecraft", "admin-db"] {
        a_routes.set_candidates(
            bob.public_key(),
            ep,
            Plane::Stream,
            vec![PathCandidate {
                label: "direct".into(),
                path: ExplicitPath {
                    id: 0,
                    first_channel: "direct".into(),
                    first_locator: b"bob".to_vec(),
                    min_mtu: 64,
                    hops: vec![],
                },
            }],
        );
    }

    // 1. Guest token scoped ONLY to "minecraft": succeeds on "minecraft", denied on "admin-db"
    let (guest_serial, guest_tok) = issuer.issue(
        alice.public_key(),
        caps::GUEST_ENDPOINT_ONLY,
        Some("minecraft"),
        Duration::from_secs(5),
        0,
    );
    *alice_token.write().unwrap() = guest_tok.clone();
    let client = KvClient::connect(&alice, bob.public_key(), "minecraft")
        .await
        .unwrap();
    client.put("world", b"seed-42").await.unwrap();
    assert_eq!(
        client.get("world").await.unwrap().as_deref(),
        Some(b"seed-42".as_slice())
    );
    assert_eq!(
        alice.dial_stream(bob.public_key(), "admin-db").await.err(),
        Some(CoreErr::Denied)
    );

    // 2. Stolen token check: Charlie presenting Alice's token MUST be denied
    charlie_creds.set_default(guest_tok.clone());
    assert_eq!(
        charlie
            .dial_stream(bob.public_key(), "minecraft")
            .await
            .err(),
        Some(CoreErr::Denied)
    );

    // 3. Host Sovereignty: even with ADMIN wildcard token, LocalHostPolicy vetoes "admin-db"
    let (_s, admin_tok) = issuer.issue(
        alice.public_key(),
        caps::MEMBER | caps::ADMIN,
        None,
        Duration::from_secs(5),
        0,
    );
    *alice_token.write().unwrap() = admin_tok;
    assert_eq!(
        alice.dial_stream(bob.public_key(), "admin-db").await.err(),
        Some(CoreErr::Denied)
    );

    // 4. Serial CRL revocation: immediately tears down Alice's active guest circuit
    *alice_token.write().unwrap() = guest_tok;
    group_acl.revoke_tokens_below(alice.public_key(), guest_serial + 1);
    let revoked_err = timeout(Duration::from_millis(500), client.get("world"))
        .await
        .unwrap();
    assert!(revoked_err.is_err());
    assert_eq!(
        alice.dial_stream(bob.public_key(), "minecraft").await.err(),
        Some(CoreErr::Denied)
    );

    // 5. Live in-band renewal with short-lived rotating tokens (TTL capped at 850ms!)
    auto_refresh.store(true, Ordering::Release);
    let (_, initial_tok) = issuer.issue(
        alice.public_key(),
        caps::MEMBER,
        Some("minecraft"),
        Duration::from_secs(5),
        0,
    );
    *alice_token.write().unwrap() = initial_tok;
    let long_client = KvClient::connect(&alice, bob.public_key(), "minecraft")
        .await
        .unwrap();
    for i in 0..10u8 {
        long_client.put("tick", &[i]).await.unwrap();
        assert_eq!(
            long_client.get("tick").await.unwrap().as_deref(),
            Some(&[i][..])
        );
        sleep(Duration::from_millis(200)).await;
    }
    assert!(
        refresh_count.load(Ordering::Relaxed) >= 2,
        "expected >= 2 in-band token renewals, got {}",
        refresh_count.load(Ordering::Relaxed)
    );

    // 6. Member kick + unkick
    group_acl.kick_member(alice.public_key());
    assert!(
        timeout(Duration::from_millis(500), long_client.get("tick"))
            .await
            .unwrap()
            .is_err()
    );
    group_acl.unkick_member(alice.public_key());
    let (_, post_unkick) = issuer.issue(
        alice.public_key(),
        caps::MEMBER,
        None,
        Duration::from_secs(5),
        0,
    );
    *alice_token.write().unwrap() = post_unkick;
    let ok_again = KvClient::connect(&alice, bob.public_key(), "minecraft")
        .await
        .unwrap();
    assert_eq!(
        ok_again.get("world").await.unwrap().as_deref(),
        Some(b"seed-42".as_slice())
    );

    // 7. Named transit SSRF prevention: unpublished target "169.254.169.254:80" is rejected!
    a_routes.set_candidates(
        bob.public_key(),
        "minecraft",
        Plane::Stream,
        vec![PathCandidate {
            label: "ssrf-attempt".into(),
            path: ExplicitPath {
                id: 0,
                first_channel: "to-hop".into(),
                first_locator: b"hop".to_vec(),
                min_mtu: 64,
                hops: vec![HopSpec {
                    peer: hop.public_key(),
                    target: "169.254.169.254:80".into(),
                }],
            },
        }],
    );
    assert!(matches!(
        alice.dial_stream(bob.public_key(), "minecraft").await,
        Err(CoreErr::HopRejected { index: 0, reason })
            if *reason == CoreErr::Denied || *reason == CoreErr::Unpublished
    ));

    // Allowed named transit "allowed-bob" succeeds!
    a_routes.clear_failures();
    a_routes.set_candidates(
        bob.public_key(),
        "minecraft",
        Plane::Stream,
        vec![PathCandidate {
            label: "allowed-hop".into(),
            path: ExplicitPath {
                id: 0,
                first_channel: "to-hop".into(),
                first_locator: b"hop".to_vec(),
                min_mtu: 64,
                hops: vec![HopSpec {
                    peer: hop.public_key(),
                    target: "allowed-bob".into(),
                }],
            },
        }],
    );
    let via_hop = KvClient::connect(&alice, bob.public_key(), "minecraft")
        .await
        .unwrap();
    assert_eq!(
        via_hop.get("world").await.unwrap().as_deref(),
        Some(b"seed-42".as_slice())
    );

    // 8. Dissolve entire group -> O(1) Revocation::All sweeps all live sessions!
    group_acl.revoke_entire_group();
    assert!(
        timeout(Duration::from_millis(500), via_hop.get("world"))
            .await
            .unwrap()
            .is_err()
    );
}

// ===========================================================================
// TEST 2: Encrypted TCP Relay + Multiplexed Encrypted Passive TCP Relay (FRP)
//         + Private Local Vertical Stacks + Multi-App Reuse
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_encrypted_tcp_relay_and_muxed_passive_tcp_frp_app() {
    let auth = Arc::new(StaticAuthorizer::default());
    let routes = Arc::new(StaticPathSource::default());

    let a = spawn_scope(auth.clone(), routes.clone());
    let h1 = spawn_scope(auth.clone(), routes.clone());
    let relay = spawn_scope(auth.clone(), routes.clone());
    let b = spawn_scope(auth.clone(), routes.clone());
    auth.allow(a.public_key(), Lease::new(Duration::from_secs(30)));

    // Topology: A --(plain TcpCarrier)--> H1 --(EncryptedStreamChannel<TcpCarrier>)--> R <--(ONE Encrypted TCP Mux Presence)-- B
    a.register_stream_carrier("tcp", Arc::new(TcpCarrier::default()))
        .unwrap();

    let h1_listener = TcpListener::bind(local()).await.unwrap();
    let h1_addr = h1_listener.local_addr().unwrap();
    let t_h1 = tokio::spawn(serve_tcp(h1_listener, h1.clone(), TcpCarrier::default()));

    let h1_link_key = Arc::new(ScopeKeypair::generate());
    let r_link_key = Arc::new(ScopeKeypair::generate());
    let enc_tcp_h1 = EncryptedStreamChannel::new(h1_link_key, TcpCarrier::default());

    let r_listener = TcpListener::bind(local()).await.unwrap();
    let r_addr = r_listener.local_addr().unwrap();
    let t_r = tokio::spawn(serve_encrypted_tcp(
        r_listener,
        relay.clone(),
        r_link_key.clone(),
    ));

    // H1 hides its private EncryptedStreamChannel & R's link pubkey behind named transit "to-relay"!
    let _g_h1 = h1
        .publish_stream_route(
            "to-relay",
            enc_tcp_h1,
            EncryptedLocator::encode(r_link_key.public_key(), r_addr.to_string().as_bytes()),
        )
        .unwrap();

    // R <-> B uses MuxPassiveStreamRelay published directly under prefix "mux/"!
    let mux_relay = MuxPassiveStreamRelay::new(16384);
    let _g_r = relay
        .publish_stream_transit_prefix("mux/", Arc::new(mux_relay.clone()))
        .unwrap();

    // B (behind NAT) dials R's presence port ONCE over Encrypted TCP
    let presence_listener = TcpListener::bind(local()).await.unwrap();
    let presence_addr = presence_listener.local_addr().unwrap();
    let b_link_key = Arc::new(ScopeKeypair::generate());
    let r_pres_key = Arc::new(ScopeKeypair::generate());
    let r_pres_pub = r_pres_key.public_key();
    let mux_for_accept = mux_relay.clone();
    let (reg_tx, reg_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (sock, _) = presence_listener.accept().await.unwrap();
        let io = Box::new(TcpIo::new(sock, 16384).unwrap());
        let replay = confluence_core::crypto::replay::SetupReplay::default();
        let enc = EncryptedStream::handshake_server(io, &r_pres_key, &replay)
            .await
            .unwrap();
        let guard = mux_for_accept
            .register_presence(b"b-nat-presence", Box::new(enc))
            .unwrap();
        let _ = reg_tx.send(guard);
    });

    let b_tcp = TcpStream::connect(presence_addr).await.unwrap();
    let b_enc = EncryptedStream::handshake_client(
        Box::new(TcpIo::new(b_tcp, 16384).unwrap()),
        &b_link_key,
        r_pres_pub,
    )
    .await
    .unwrap();
    let _presence_guard = reg_rx.await.unwrap();
    let t_b_pres = tokio::spawn(MuxPassiveStreamRelay::serve_destination_presence(
        Box::new(b_enc),
        b.clone(),
    ));

    let target_tcp = TcpListener::bind(local()).await.unwrap();
    let target_addr = target_tcp.local_addr().unwrap();
    let t_echo = start_tcp_echo_multi(target_tcp);
    let _p_tcp = b
        .publish_stream("web-app", Arc::new(TcpTarget(target_addr)))
        .unwrap();
    let _p_kv = b.publish_stream("kv-rpc", KvService::new()).unwrap();

    for ep in ["web-app", "kv-rpc"] {
        routes.set(
            b.public_key(),
            ep,
            Plane::Stream,
            ExplicitPath {
                id: 50,
                first_channel: "tcp".into(),
                first_locator: h1_addr.to_string().into_bytes(),
                min_mtu: 64,
                hops: vec![
                    HopSpec {
                        peer: h1.public_key(),
                        target: "to-relay".into(),
                    },
                    HopSpec {
                        peer: relay.public_key(),
                        target: "mux/b-nat-presence".into(),
                    },
                ],
            },
        );
    }

    let edge_listener = TcpListener::bind(local()).await.unwrap();
    let edge_addr = edge_listener.local_addr().unwrap();
    let t_edge = tokio::spawn(serve_local_tcp(
        edge_listener,
        a.clone(),
        Destination {
            peer: b.public_key(),
            endpoint: "web-app".into(),
        },
    ));

    let tcp_tasks: Vec<_> = (0..3u8)
        .map(|i| {
            tokio::spawn(async move {
                let mut client = TcpStream::connect(edge_addr).await.unwrap();
                let payload = vec![0x30 + i; 4096];
                client.write_all(&payload).await.unwrap();
                client.shutdown().await.unwrap();
                let mut reply = Vec::new();
                client.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, payload);
            })
        })
        .collect();

    let kv = KvClient::connect(&a, b.public_key(), "kv-rpc")
        .await
        .unwrap();
    kv.put("mode", b"frp-muxed-enc-tcp").await.unwrap();
    assert_eq!(
        kv.get("mode").await.unwrap().as_deref(),
        Some(b"frp-muxed-enc-tcp".as_slice())
    );

    for handle in tcp_tasks {
        timeout(WAIT, handle).await.unwrap().unwrap();
    }

    t_edge.abort();
    t_b_pres.abort();
    t_r.abort();
    t_h1.abort();
    t_echo.abort();
}

// ===========================================================================
// TEST 3: Encrypted UDP Wrapper (MTU Propagation) + Home UDP Relay
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_encrypted_udp_wrapper_and_home_udp_relay() {
    let (raw_a, raw_b) = mem_datagram_pair(1500, 32);
    let k_a = ScopeKeypair::generate();
    let k_b = ScopeKeypair::generate();
    let replay = confluence_core::crypto::replay::SetupReplay::default();
    let (enc_a, (enc_b, peer)) = tokio::try_join!(
        EncryptedDatagramLink::connect(raw_a.clone(), &k_a, k_b.public_key()),
        EncryptedDatagramLink::accept(raw_b.clone(), &k_b, &replay),
    )
    .unwrap();
    assert_eq!(peer, k_a.public_key());
    assert_eq!(enc_a.caps().mtu(), 1500 - DG_LINK_OVERHEAD);
    let mut watch_a = enc_a.caps().mtu_watch;
    raw_a.set_mtu(1360);
    timeout(WAIT, watch_a.changed()).await.unwrap().unwrap();
    assert_eq!(watch_a.mtu(), 1360 - DG_LINK_OVERHEAD);
    drop((enc_a, enc_b));

    let mem = MemDatagramChannel::new(1400);
    let enc_chan = EncryptedDatagramChannel::new(Arc::new(ScopeKeypair::generate()), mem).unwrap();
    assert_eq!(enc_chan.caps().mtu(), 1400 - DG_LINK_OVERHEAD);

    let auth = Arc::new(StaticAuthorizer::default());
    let routes = Arc::new(StaticPathSource::default());

    let a = spawn_scope(auth.clone(), routes.clone());
    let r = spawn_scope(auth.clone(), routes.clone());
    let b = spawn_scope(auth.clone(), routes.clone());
    auth.allow(a.public_key(), Lease::new(Duration::from_secs(30)));

    let a_udp = EncryptedUdpNode::bind(local(), Arc::new(ScopeKeypair::generate()), 1400)
        .await
        .unwrap();
    let r_udp = EncryptedUdpNode::bind(local(), Arc::new(ScopeKeypair::generate()), 1400)
        .await
        .unwrap();
    let b_udp = EncryptedUdpNode::bind(local(), Arc::new(ScopeKeypair::generate()), 1400)
        .await
        .unwrap();

    // Relay R mounts PassiveRelay directly under prefix "home/" (zero outbound dialing!)
    let passive = PassiveRelay::new(16384, 1400).unwrap();
    let _g_r = r
        .publish_datagram_transit_prefix("home/", Arc::new(passive.clone()))
        .unwrap();
    let b_link_pub = b_udp.public_key();
    r_udp.enable_home_relay(
        passive,
        Arc::new(move |peer_key, cred| *peer_key == b_link_pub && cred == b"slot-secret"),
    );

    let t_a = a_udp.spawn_loop(Some(a.clone()));
    let t_r = r_udp.spawn_loop(Some(r.clone()));
    let t_b = b_udp.spawn_loop(None);

    let b_to_r = b_udp
        .connect_peer(r_udp.public_key(), r_udp.local_addr().unwrap())
        .await
        .unwrap();
    let slot_token = b_to_r
        .register_home_relay_slot(b"slot-secret")
        .await
        .unwrap();
    let _b_ingress = b.attach_datagram(b_to_r).unwrap();

    let target_udp = UdpSocket::bind(local()).await.unwrap();
    let target_addr = target_udp.local_addr().unwrap();
    let t_echo = start_udp_echo(target_udp);
    let _pub_b = b
        .publish_datagram("game-udp", DATAGRAM_MTU, Arc::new(UdpTarget(target_addr)))
        .unwrap();

    a.register_datagram_carrier("enc-udp", Arc::new(a_udp))
        .unwrap();
    routes.set(
        b.public_key(),
        "game-udp",
        Plane::Datagram,
        ExplicitPath {
            id: 300,
            first_channel: "enc-udp".into(),
            first_locator: EncryptedUdpNode::locator(
                r_udp.public_key(),
                r_udp.local_addr().unwrap(),
            ),
            min_mtu: DATAGRAM_MTU,
            hops: vec![HopSpec {
                peer: r.public_key(),
                target: format!("home/{}", encode_slot_hex(&slot_token)),
            }],
        },
    );

    let edge_udp = UdpSocket::bind(local()).await.unwrap();
    let edge_addr = edge_udp.local_addr().unwrap();
    let t_edge = tokio::spawn(serve_local_udp(
        edge_udp,
        a.clone(),
        Destination {
            peer: b.public_key(),
            endpoint: "game-udp".into(),
        },
        DATAGRAM_MTU,
    ));

    let c1 = UdpSocket::bind(local()).await.unwrap();
    let c2 = UdpSocket::bind(local()).await.unwrap();
    c1.connect(edge_addr).await.unwrap();
    c2.connect(edge_addr).await.unwrap();
    c1.send(b"player-1-tick").await.unwrap();
    c2.send(b"player-2-tick").await.unwrap();

    let mut buf = [0u8; 64];
    let n1 = timeout(WAIT, c1.recv(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..n1], b"player-1-tick");
    let n2 = timeout(WAIT, c2.recv(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..n2], b"player-2-tick");

    t_edge.abort();
    t_echo.abort();
    t_a.abort();
    t_r.abort();
    t_b.abort();
}

// ===========================================================================
// TEST 4: UDP P2P: Blind Rendezvous + SealedEnvelope + Real Cone-NAT
//         Simultaneous Hole-Punching + Bidirectional Reuse + Roaming!
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_udp_p2p_blind_rendezvous_hole_punch_bidirectional_and_roaming() {
    let topic_id = 4040u64;
    let discovery_key = blake3::derive_key("eval-group-discovery", b"shared-friends-secret");

    let meta = PeerMetadata {
        lan_addrs: vec![SocketAddr::from((Ipv4Addr::new(192, 168, 1, 5), 5555))],
        home_relay: None,
        timestamp_ms: 123456,
    };
    let sample_pk = ScopeKeypair::generate().public_key();
    let sealed = meta.seal(&discovery_key, topic_id, sample_pk).unwrap();
    assert_eq!(
        PeerMetadata::open(&discovery_key, topic_id, sample_pk, &sealed).unwrap(),
        meta
    );
    assert!(PeerMetadata::open(&[0xFF; 32], topic_id, sample_pk, &sealed).is_err());
    assert!(PeerMetadata::open(&discovery_key, topic_id + 1, sample_pk, &sealed).is_err());

    let rv = BlindRendezvous::start(ScopeKeypair::generate())
        .await
        .unwrap();
    let nat_a = SimNat::start(NatKind::AddressPortRestrictedCone)
        .await
        .unwrap();
    let nat_b = SimNat::start(NatKind::AddressPortRestrictedCone)
        .await
        .unwrap();

    let auth = Arc::new(StaticAuthorizer::default());
    let routes_a = Arc::new(StaticPathSource::default());
    let routes_b = Arc::new(StaticPathSource::default());
    let alice = spawn_scope(auth.clone(), routes_a.clone());
    let bob = spawn_scope(auth.clone(), routes_b.clone());
    auth.allow(alice.public_key(), Lease::new(Duration::from_secs(30)));
    auth.allow(bob.public_key(), Lease::new(Duration::from_secs(30)));

    let p2p_a = UdpP2pNode::new(
        HostUdpTransport::behind_nat(&nat_a).await.unwrap(),
        alice.identity(),
        topic_id,
        discovery_key,
        1280,
    )
    .unwrap();
    let p2p_b = UdpP2pNode::new(
        HostUdpTransport::behind_nat(&nat_b).await.unwrap(),
        bob.identity(),
        topic_id,
        discovery_key,
        1280,
    )
    .unwrap();

    let t_a = p2p_a.spawn_loop(alice.clone());
    let t_b = p2p_b.spawn_loop(bob.clone());

    p2p_a
        .register_with_rendezvous(rv.addr(), rv.public_key(), &meta)
        .await
        .unwrap();
    p2p_b
        .register_with_rendezvous(rv.addr(), rv.public_key(), &meta)
        .await
        .unwrap();

    alice
        .register_datagram_carrier("p2p", Arc::new(p2p_a))
        .unwrap();
    bob.register_datagram_carrier("p2p", Arc::new(p2p_b))
        .unwrap();

    let echo_b = UdpSocket::bind(local()).await.unwrap();
    let echo_b_addr = echo_b.local_addr().unwrap();
    let t_eb = start_udp_echo(echo_b);
    let _pb = bob
        .publish_datagram("ping", DATAGRAM_MTU, Arc::new(UdpTarget(echo_b_addr)))
        .unwrap();

    let echo_a = UdpSocket::bind(local()).await.unwrap();
    let echo_a_addr = echo_a.local_addr().unwrap();
    let t_ea = start_udp_echo(echo_a);
    let _pa = alice
        .publish_datagram("pong", DATAGRAM_MTU, Arc::new(UdpTarget(echo_a_addr)))
        .unwrap();

    routes_a.set(
        bob.public_key(),
        "ping",
        Plane::Datagram,
        ExplicitPath {
            id: 401,
            first_channel: "p2p".into(),
            first_locator: bob.public_key().0.to_vec(),
            min_mtu: DATAGRAM_MTU,
            hops: vec![],
        },
    );
    routes_b.set(
        alice.public_key(),
        "pong",
        Plane::Datagram,
        ExplicitPath {
            id: 402,
            first_channel: "p2p".into(),
            first_locator: alice.public_key().0.to_vec(),
            min_mtu: DATAGRAM_MTU,
            hops: vec![],
        },
    );

    let a_to_b = timeout(
        WAIT,
        alice.dial_datagram(bob.public_key(), "ping", DATAGRAM_MTU),
    )
    .await
    .unwrap()
    .unwrap();
    a_to_b
        .send(PacketBuf::from_slice(b"direct-p2p-across-two-nats"))
        .unwrap();
    let reply = timeout(WAIT, a_to_b.recv()).await.unwrap().unwrap();
    assert_eq!(reply.as_slice(), b"direct-p2p-across-two-nats");

    let b_to_a = timeout(
        WAIT,
        bob.dial_datagram(alice.public_key(), "pong", DATAGRAM_MTU),
    )
    .await
    .unwrap()
    .unwrap();
    b_to_a
        .send(PacketBuf::from_slice(b"reverse-same-pinhole"))
        .unwrap();
    let rev = timeout(WAIT, b_to_a.recv()).await.unwrap().unwrap();
    assert_eq!(rev.as_slice(), b"reverse-same-pinhole");

    let routes_c = Arc::new(StaticPathSource::default());
    let charlie_pub = spawn_scope(auth, routes_c);
    let p2p_c = UdpP2pNode::new(
        HostUdpTransport::direct(local()).await.unwrap(),
        charlie_pub.identity(),
        topic_id,
        discovery_key,
        1280,
    )
    .unwrap();
    let t_c = p2p_c.spawn_loop(charlie_pub.clone());
    p2p_c
        .register_with_rendezvous(rv.addr(), rv.public_key(), &meta)
        .await
        .unwrap();
    let echo_c = UdpSocket::bind(local()).await.unwrap();
    let echo_c_addr = echo_c.local_addr().unwrap();
    let t_ec = start_udp_echo(echo_c);
    let _pc = charlie_pub
        .publish_datagram("roam", DATAGRAM_MTU, Arc::new(UdpTarget(echo_c_addr)))
        .unwrap();
    routes_a.set(
        charlie_pub.public_key(),
        "roam",
        Plane::Datagram,
        ExplicitPath {
            id: 403,
            first_channel: "p2p".into(),
            first_locator: charlie_pub.public_key().0.to_vec(),
            min_mtu: DATAGRAM_MTU,
            hops: vec![],
        },
    );
    let a_to_c = timeout(
        WAIT,
        alice.dial_datagram(charlie_pub.public_key(), "roam", DATAGRAM_MTU),
    )
    .await
    .unwrap()
    .unwrap();
    a_to_c
        .send(PacketBuf::from_slice(b"before-rebind"))
        .unwrap();
    assert_eq!(
        timeout(WAIT, a_to_c.recv())
            .await
            .unwrap()
            .unwrap()
            .as_slice(),
        b"before-rebind"
    );

    let old_wan = nat_a.wan_addr();
    let new_wan = nat_a.rebind_wan_port().await.unwrap();
    assert_ne!(old_wan, new_wan);

    a_to_c
        .send(PacketBuf::from_slice(b"survived-nat-rebind"))
        .unwrap();
    let roamed = timeout(WAIT, a_to_c.recv()).await.unwrap().unwrap();
    assert_eq!(roamed.as_slice(), b"survived-nat-rebind");

    t_a.abort();
    t_b.abort();
    t_c.abort();
    t_ea.abort();
    t_eb.abort();
    t_ec.abort();
}

// ===========================================================================
// TEST 5: Symmetric Cross-Plane Adapters (Striped-TCP Datagram + StreamOverDatagram)
//         AND Heterogeneous 3-Hop Chain (StripedTCP -> EncUDP -> PassiveRelay)
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cross_plane_adapters_and_heterogeneous_three_hop_chain() {
    let auth = Arc::new(StaticAuthorizer::default());
    let routes = Arc::new(StaticPathSource::default());

    let a = spawn_scope(auth.clone(), routes.clone());
    let h1 = spawn_scope(auth.clone(), routes.clone());
    let h2 = spawn_scope(auth.clone(), routes.clone());
    let b = spawn_scope(auth.clone(), routes.clone());
    auth.allow(a.public_key(), Lease::new(Duration::from_secs(30)));

    let h1_striped_key = Arc::new(ScopeKeypair::generate());
    let h1_tcp = TcpListener::bind(local()).await.unwrap();
    let h1_tcp_addr = h1_tcp.local_addr().unwrap();
    let t_h1_in = tokio::spawn(serve_striped_tcp_datagram(
        h1_tcp,
        h1.clone(),
        h1_striped_key.clone(),
        StripedConfig::default(),
    ));

    let a_striped = StripedTcpDatagramChannel::new(
        Arc::new(ScopeKeypair::generate()),
        StripedConfig::default(),
    );
    a.register_datagram_carrier("striped", Arc::new(a_striped))
        .unwrap();

    // Leg 2: H1 -> H2 via EncryptedUdpNode behind named transit "to-h2"
    let h1_udp = EncryptedUdpNode::bind(local(), Arc::new(ScopeKeypair::generate()), 1400)
        .await
        .unwrap();
    let h2_udp = EncryptedUdpNode::bind(local(), Arc::new(ScopeKeypair::generate()), 1400)
        .await
        .unwrap();
    let t_h1_u = h1_udp.spawn_loop(None);
    let t_h2_u = h2_udp.spawn_loop(Some(h2.clone()));
    let _g_h1 = h1
        .publish_datagram_route(
            "to-h2",
            h1_udp,
            EncryptedUdpNode::locator(h2_udp.public_key(), h2_udp.local_addr().unwrap()),
        )
        .unwrap();

    // Leg 3: H2 -> B via PassiveRelay under named transit "b-slot"
    let passive = PassiveRelay::new(16384, 1400).unwrap();
    let _g_h2 = h2
        .publish_datagram_transit("b-slot", Arc::new(passive.clone()))
        .unwrap();
    let (h2_link, b_link) = mem_datagram_pair(1400, 64);
    let _pres = passive.register_datagram(b"b-slot", h2_link).unwrap();
    let _b_ing = b.attach_datagram(b_link).unwrap();

    let udp_echo = UdpSocket::bind(local()).await.unwrap();
    let udp_echo_addr = udp_echo.local_addr().unwrap();
    let t_echo = start_udp_echo(udp_echo);
    let _pub_dg = b
        .publish_datagram("het-dg", DATAGRAM_MTU, Arc::new(UdpTarget(udp_echo_addr)))
        .unwrap();

    routes.set(
        b.public_key(),
        "het-dg",
        Plane::Datagram,
        ExplicitPath {
            id: 500,
            first_channel: "striped".into(),
            first_locator: EncryptedLocator::encode(
                h1_striped_key.public_key(),
                h1_tcp_addr.to_string().as_bytes(),
            ),
            min_mtu: DATAGRAM_MTU,
            hops: vec![
                HopSpec {
                    peer: h1.public_key(),
                    target: "to-h2".into(),
                },
                HopSpec {
                    peer: h2.public_key(),
                    target: "b-slot".into(),
                },
            ],
        },
    );

    let dg = timeout(
        WAIT,
        a.dial_datagram(b.public_key(), "het-dg", DATAGRAM_MTU),
    )
    .await
    .unwrap()
    .unwrap();
    for i in 0..16u8 {
        let msg = vec![i; 600];
        dg.send_wait(PacketBuf::from_slice(&msg)).await.unwrap();
        let got = timeout(WAIT, dg.recv()).await.unwrap().unwrap();
        assert_eq!(got.as_slice(), &msg);
    }

    // Reverse Cross-Plane (StreamOverDatagramChannel)
    let dg_mem = MemDatagramChannel::new(1400);
    let dg_listener = dg_mem.listen(b"sod-b").unwrap();
    let b_for_sod = b.clone();
    let t_sod = tokio::spawn(async move {
        let mut muxes = Vec::new();
        while let Some(link) = dg_listener.accept().await {
            muxes.push(SodMux::start(link, Some(b_for_sod.clone())));
        }
    });

    let sod_channel = StreamOverDatagramChannel::new(dg_mem).unwrap();
    a.register_stream_carrier("sod", Arc::new(sod_channel))
        .unwrap();

    let tcp_echo = TcpListener::bind(local()).await.unwrap();
    let tcp_echo_addr = tcp_echo.local_addr().unwrap();
    let t_tcp_echo = start_tcp_echo_multi(tcp_echo);
    let _pub_st = b
        .publish_stream("sod-tcp", Arc::new(TcpTarget(tcp_echo_addr)))
        .unwrap();

    routes.set(
        b.public_key(),
        "sod-tcp",
        Plane::Stream,
        ExplicitPath {
            id: 501,
            first_channel: "sod".into(),
            first_locator: b"sod-b".to_vec(),
            min_mtu: 64,
            hops: vec![],
        },
    );

    let st = timeout(WAIT, a.dial_stream(b.public_key(), "sod-tcp"))
        .await
        .unwrap()
        .unwrap();
    let bulk: Vec<u8> = (0..65536).map(|i| (i % 251) as u8).collect();
    let st_w = st.clone();
    let bulk_c = bulk.clone();
    let writer = tokio::spawn(async move {
        st_w.write_all(&bulk_c).await.unwrap();
        st_w.shutdown().await.unwrap();
    });
    let mut received = Vec::with_capacity(bulk.len());
    let mut chunk = [0u8; 4096];
    loop {
        let n = timeout(WAIT, st.read(&mut chunk)).await.unwrap().unwrap();
        if n == 0 {
            break;
        }
        received.extend_from_slice(&chunk[..n]);
    }
    writer.await.unwrap();
    assert_eq!(received, bulk);

    t_h1_in.abort();
    t_h1_u.abort();
    t_h2_u.abort();
    t_echo.abort();
    t_sod.abort();
    t_tcp_echo.abort();
}

// ===========================================================================
// TEST 6: Tailscale Replacement Vision:
//         Multi-Scope Isolation + Virtual L3 Mesh (with L3 Fragmentation) +
//         Full Failover Matrix (Direct UDP P2P -> Home UDP Relay -> Striped-TCP)
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_tailscale_replacement_mesh_failover_fragmentation_and_multi_scope_isolation() {
    let friends_secret = [0x11u8; 32];
    let corp_secret = [0x22u8; 32];
    let friends_disc = blake3::derive_key("friends-disc", &friends_secret);

    let friends_issuer = GroupIssuer::new(100, friends_secret);
    let corp_issuer = GroupIssuer::new(200, corp_secret);

    let friends_acl = Arc::new(GroupAcl::new(100, friends_secret, GroupRule::default()));
    let corp_acl = Arc::new(GroupAcl::new(200, corp_secret, GroupRule::default()));

    let rv = BlindRendezvous::start(ScopeKeypair::generate())
        .await
        .unwrap();
    let relay_scope = spawn_scope(friends_acl.clone(), Arc::new(StaticPathSource::default()));
    let relay_udp = EncryptedUdpNode::bind(local(), Arc::new(ScopeKeypair::generate()), 1400)
        .await
        .unwrap();
    let passive_udp = PassiveRelay::new(16384, 1400).unwrap();
    let _g_relay = relay_scope
        .publish_datagram_transit_prefix("home/", Arc::new(passive_udp.clone()))
        .unwrap();
    relay_udp.enable_home_relay(passive_udp, Arc::new(|_, cred| cred == b"friends-home"));
    let t_relay = relay_udp.spawn_loop(Some(relay_scope.clone()));

    let alice_friends_kp = ScopeKeypair::generate();
    let (_, tok_alice_friends) = friends_issuer.issue(
        alice_friends_kp.public_key(),
        caps::MEMBER,
        None,
        Duration::from_secs(60),
        0,
    );
    let alice_creds = Arc::new(StaticCredentials::default());
    alice_creds.set_default(tok_alice_friends);

    let alice_friends_routes = Arc::new(SmartPathSource::default());
    let alice_friends = spawn_scope_with_creds(
        alice_friends_kp,
        friends_acl.clone(),
        alice_friends_routes.clone(),
        alice_creds,
    );
    let alice_corp = spawn_scope(corp_acl.clone(), Arc::new(StaticPathSource::default()));

    assert_ne!(alice_friends.public_key(), alice_corp.public_key());
    assert_ne!(alice_friends.kid(), alice_corp.kid());

    let bob = spawn_scope(friends_acl.clone(), Arc::new(SmartPathSource::default()));
    let charlie = spawn_scope(friends_acl.clone(), Arc::new(SmartPathSource::default()));
    let eve = spawn_scope(friends_acl.clone(), Arc::new(SmartPathSource::default()));

    let nat_alice = SimNat::start(NatKind::AddressPortRestrictedCone)
        .await
        .unwrap();
    let nat_bob = SimNat::start(NatKind::AddressPortRestrictedCone)
        .await
        .unwrap();
    let nat_charlie = SimNat::start(NatKind::Symmetric).await.unwrap();
    let nat_eve = SimNat::start(NatKind::UdpBlocked).await.unwrap();

    let p2p_alice = UdpP2pNode::new(
        HostUdpTransport::behind_nat(&nat_alice).await.unwrap(),
        alice_friends.identity(),
        100,
        friends_disc,
        1280,
    )
    .unwrap()
    .with_punch_timeout(Duration::from_millis(300));
    let p2p_bob = UdpP2pNode::new(
        HostUdpTransport::behind_nat(&nat_bob).await.unwrap(),
        bob.identity(),
        100,
        friends_disc,
        1280,
    )
    .unwrap();
    let p2p_charlie = UdpP2pNode::new(
        HostUdpTransport::behind_nat(&nat_charlie).await.unwrap(),
        charlie.identity(),
        100,
        friends_disc,
        1280,
    )
    .unwrap();
    let p2p_eve = UdpP2pNode::new(
        HostUdpTransport::behind_nat(&nat_eve).await.unwrap(),
        eve.identity(),
        100,
        friends_disc,
        1280,
    )
    .unwrap();

    let t_pa = p2p_alice.spawn_loop(alice_friends.clone());
    let t_pb = p2p_bob.spawn_loop(bob.clone());
    let t_pc = p2p_charlie.spawn_loop(charlie.clone());
    let t_pe = p2p_eve.spawn_loop(eve.clone());

    let charlie_udp = EncryptedUdpNode::bind(local(), Arc::new(ScopeKeypair::generate()), 1400)
        .await
        .unwrap();
    let t_cu = charlie_udp.spawn_loop(None);
    let charlie_relay_link = charlie_udp
        .connect_peer(relay_udp.public_key(), relay_udp.local_addr().unwrap())
        .await
        .unwrap();
    let charlie_slot = charlie_relay_link
        .register_home_relay_slot(b"friends-home")
        .await
        .unwrap();
    let _c_ing = charlie.attach_datagram(charlie_relay_link).unwrap();

    let empty_meta = PeerMetadata {
        lan_addrs: vec![],
        home_relay: None,
        timestamp_ms: 1,
    };
    let charlie_meta = PeerMetadata {
        lan_addrs: vec![],
        home_relay: Some((
            relay_udp.local_addr().unwrap(),
            relay_udp.public_key(),
            charlie_slot,
        )),
        timestamp_ms: 1,
    };
    p2p_alice
        .register_with_rendezvous(rv.addr(), rv.public_key(), &empty_meta)
        .await
        .unwrap();
    p2p_bob
        .register_with_rendezvous(rv.addr(), rv.public_key(), &empty_meta)
        .await
        .unwrap();
    p2p_charlie
        .register_with_rendezvous(rv.addr(), rv.public_key(), &charlie_meta)
        .await
        .unwrap();

    let eve_striped_key = Arc::new(ScopeKeypair::generate());
    let eve_tcp = TcpListener::bind(local()).await.unwrap();
    let eve_tcp_addr = eve_tcp.local_addr().unwrap();
    let t_eve_striped = tokio::spawn(serve_striped_tcp_datagram(
        eve_tcp,
        eve.clone(),
        eve_striped_key.clone(),
        StripedConfig::default(),
    ));

    let alice_enc_udp = EncryptedUdpNode::bind(local(), Arc::new(ScopeKeypair::generate()), 1400)
        .await
        .unwrap();
    let t_au = alice_enc_udp.spawn_loop(None);
    let alice_striped = StripedTcpDatagramChannel::new(
        Arc::new(ScopeKeypair::generate()),
        StripedConfig::default(),
    );
    alice_friends
        .register_datagram_carrier("p2p", Arc::new(p2p_alice.clone()))
        .unwrap();
    alice_friends
        .register_datagram_carrier("enc-udp", Arc::new(alice_enc_udp))
        .unwrap();
    alice_friends
        .register_datagram_carrier("striped", Arc::new(alice_striped))
        .unwrap();

    alice_friends_routes.enable_p2p_relay_fallback(
        p2p_alice,
        "enc-udp",
        "home/",
        relay_scope.public_key(),
    );

    alice_friends_routes.set_candidates(
        bob.public_key(),
        MESH_ENDPOINT,
        Plane::Datagram,
        vec![PathCandidate {
            label: "udp-p2p".into(),
            path: ExplicitPath {
                id: 0,
                first_channel: "p2p".into(),
                first_locator: bob.public_key().0.to_vec(),
                min_mtu: DATAGRAM_MTU,
                hops: vec![],
            },
        }],
    );

    alice_friends_routes.set_candidates(
        charlie.public_key(),
        MESH_ENDPOINT,
        Plane::Datagram,
        vec![PathCandidate {
            label: "udp-p2p".into(),
            path: ExplicitPath {
                id: 0,
                first_channel: "p2p".into(),
                first_locator: charlie.public_key().0.to_vec(),
                min_mtu: DATAGRAM_MTU,
                hops: vec![],
            },
        }],
    );

    alice_friends_routes.set_candidates(
        eve.public_key(),
        MESH_ENDPOINT,
        Plane::Datagram,
        vec![
            PathCandidate {
                label: "udp-p2p".into(),
                path: ExplicitPath {
                    id: 0,
                    first_channel: "p2p".into(),
                    first_locator: eve.public_key().0.to_vec(),
                    min_mtu: DATAGRAM_MTU,
                    hops: vec![],
                },
            },
            PathCandidate {
                label: "striped-tcp".into(),
                path: ExplicitPath {
                    id: 0,
                    first_channel: "striped".into(),
                    first_locator: EncryptedLocator::encode(
                        eve_striped_key.public_key(),
                        eve_tcp_addr.to_string().as_bytes(),
                    ),
                    min_mtu: DATAGRAM_MTU,
                    hops: vec![],
                },
            },
        ],
    );

    let mesh_alice =
        VirtualL3Node::attach(alice_friends.clone(), Ipv4Addr::new(100, 64, 1, 1)).unwrap();
    let mesh_bob = VirtualL3Node::attach(bob.clone(), Ipv4Addr::new(100, 64, 1, 2)).unwrap();
    let mesh_charlie =
        VirtualL3Node::attach(charlie.clone(), Ipv4Addr::new(100, 64, 1, 3)).unwrap();
    let mesh_eve = VirtualL3Node::attach(eve.clone(), Ipv4Addr::new(100, 64, 1, 4)).unwrap();

    mesh_alice.add_peer(
        "bob.friends",
        Ipv4Addr::new(100, 64, 1, 2),
        bob.public_key(),
    );
    mesh_alice.add_peer(
        "charlie.friends",
        Ipv4Addr::new(100, 64, 1, 3),
        charlie.public_key(),
    );
    mesh_alice.add_peer(
        "eve.friends",
        Ipv4Addr::new(100, 64, 1, 4),
        eve.public_key(),
    );

    // CASE 1: Cone NAT <-> Cone NAT -> Direct UDP P2P + L3 Fragmentation of 2400B IP packet!
    let large_ip_payload: Vec<u8> = (0..2400).map(|i| (i % 251) as u8).collect();
    timeout(
        WAIT,
        mesh_alice.send_to_name("bob.friends", &large_ip_payload),
    )
    .await
    .unwrap()
    .unwrap();
    let pkt_bob = timeout(WAIT, mesh_bob.recv_ip()).await.unwrap().unwrap();
    assert_eq!(pkt_bob.src, Ipv4Addr::new(100, 64, 1, 1));
    assert_eq!(pkt_bob.dst, Ipv4Addr::new(100, 64, 1, 2));
    assert_eq!(pkt_bob.payload, large_ip_payload);

    // CASE 2: Cone NAT <-> Symmetric NAT -> P2P fails -> Auto-fallback to Encrypted Home UDP Relay!
    timeout(
        WAIT,
        mesh_alice.send_to_name("charlie.friends", b"sym-nat-via-home-relay"),
    )
    .await
    .unwrap()
    .unwrap();
    let pkt_charlie = timeout(WAIT, mesh_charlie.recv_ip())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pkt_charlie.payload, b"sym-nat-via-home-relay");

    // CASE 3: UDP Blocked -> P2P fails -> Auto-fallback to Striped Encrypted-TCP Datagram!
    timeout(
        WAIT,
        mesh_alice.send_to_name("eve.friends", b"udp-blocked-via-striped-tcp"),
    )
    .await
    .unwrap()
    .unwrap();
    let pkt_eve = timeout(WAIT, mesh_eve.recv_ip()).await.unwrap().unwrap();
    assert_eq!(pkt_eve.payload, b"udp-blocked-via-striped-tcp");

    let outcomes = alice_friends_routes.recorded_outcomes();
    let established_labels: HashSet<&str> = outcomes
        .iter()
        .filter_map(|(_, label, out)| {
            matches!(out, PathOutcome::Established { .. }).then_some(label.as_str())
        })
        .collect();
    assert!(
        established_labels.contains("udp-p2p"),
        "outcomes: {outcomes:?}"
    );
    assert!(
        established_labels.contains("home-udp-relay"),
        "outcomes: {outcomes:?}"
    );
    assert!(
        established_labels.contains("striped-tcp"),
        "outcomes: {outcomes:?}"
    );

    // CASE 4: Multi-Scope Isolation check
    let corp_mem = MemStreamChannel::new(4096, 4096);
    let _l_corp = tokio::spawn(
        corp_mem
            .listen(b"alice-corp")
            .unwrap()
            .serve_stream(alice_corp.clone()),
    );
    let _pub_corp = alice_corp
        .publish_stream("corp-db", KvService::new())
        .unwrap();

    let corp_routes_dave = Arc::new(StaticPathSource::default());
    let dave_kp = ScopeKeypair::generate();
    let (_, tok_dave) = corp_issuer.issue(
        dave_kp.public_key(),
        caps::MEMBER,
        None,
        Duration::from_secs(30),
        0,
    );
    let dave_creds = Arc::new(StaticCredentials::default());
    dave_creds.set_default(tok_dave);
    let dave = spawn_scope_with_creds(dave_kp, corp_acl, corp_routes_dave.clone(), dave_creds);
    dave.register_stream_carrier("mem", Arc::new(corp_mem.clone()))
        .unwrap();
    corp_routes_dave.set(
        alice_corp.public_key(),
        "corp-db",
        Plane::Stream,
        ExplicitPath {
            id: 900,
            first_channel: "mem".into(),
            first_locator: b"alice-corp".to_vec(),
            min_mtu: 64,
            hops: vec![],
        },
    );
    let kv_dave = KvClient::connect(&dave, alice_corp.public_key(), "corp-db")
        .await
        .unwrap();
    kv_dave.put("secret", b"q4-roadmap").await.unwrap();
    assert_eq!(
        kv_dave.get("secret").await.unwrap().as_deref(),
        Some(b"q4-roadmap".as_slice())
    );

    let bob_rogue_routes = Arc::new(StaticPathSource::default());
    let bob_friends_kp = ScopeKeypair::generate();
    let (_, tok_bob_friends) = friends_issuer.issue(
        bob_friends_kp.public_key(),
        caps::MEMBER,
        None,
        Duration::from_secs(30),
        0,
    );
    let bob_friends_creds = Arc::new(StaticCredentials::default());
    bob_friends_creds.set_default(tok_bob_friends);
    let bob_in_friends = spawn_scope_with_creds(
        bob_friends_kp,
        friends_acl,
        bob_rogue_routes.clone(),
        bob_friends_creds,
    );
    bob_in_friends
        .register_stream_carrier("mem", Arc::new(corp_mem))
        .unwrap();
    bob_rogue_routes.set(
        alice_corp.public_key(),
        "corp-db",
        Plane::Stream,
        ExplicitPath {
            id: 901,
            first_channel: "mem".into(),
            first_locator: b"alice-corp".to_vec(),
            min_mtu: 64,
            hops: vec![],
        },
    );
    assert_eq!(
        bob_in_friends
            .dial_stream(alice_corp.public_key(), "corp-db")
            .await
            .err(),
        Some(CoreErr::Denied)
    );

    t_relay.abort();
    t_pa.abort();
    t_pb.abort();
    t_pc.abort();
    t_pe.abort();
    t_cu.abort();
    t_au.abort();
    t_eve_striped.abort();
}

// ===========================================================================
// TEST 7: Compile-Time Static Vertical Stacks & Zero-Copy In-Place
//         Outer Datagram Sealing + MtuWatch Overhead/Cap Composition
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_compile_time_vertical_stacks_and_zero_copy_encrypted_datagram_link() {
    use confluence_core::{
        AsyncStream, DatagramLinkExt, MtuWatch, StaticTransit, StreamChannel, StreamListener,
        StreamReadExt, StreamTransitHandler, StreamWriteExt,
    };
    use confluence_ext::{cross_plane::SodStream, encrypted::EncryptedStreamListener};
    use confluence_net::TcpListenerSource;
    use confluence_plugins::MemDatagramLink;

    fn assert_stream_type<C: StreamChannel<Stream = S>, S: AsyncStream>(_: &C) {}
    fn assert_transit_stream_type<T: StreamTransitHandler<Stream = S>, S: AsyncStream>(_: &T) {}
    fn assert_listener_type<L: StreamListener<Stream = S>, S: AsyncStream>(_: &L) {}
    fn assert_dg_type<C: DatagramChannel<Link = L>, L>(_: &C) {}

    let enc_tcp_stack = StaticTransit::new(
        EncryptedStreamChannel::new(Arc::new(ScopeKeypair::generate()), TcpCarrier::default()),
        b"dest".to_vec(),
    );
    assert_transit_stream_type::<_, EncryptedStream<TcpIo>>(&enc_tcp_stack);

    let enc_dg_stack = EncryptedDatagramChannel::new(
        Arc::new(ScopeKeypair::generate()),
        MemDatagramChannel::new(1400),
    )
    .unwrap();
    assert_dg_type::<_, Arc<EncryptedDatagramLink<Arc<MemDatagramLink>>>>(&enc_dg_stack);

    let sod_enc_dg_stack = StreamOverDatagramChannel::new(
        EncryptedDatagramChannel::new(
            Arc::new(ScopeKeypair::generate()),
            MemDatagramChannel::new(1400),
        )
        .unwrap(),
    )
    .unwrap();
    assert_stream_type::<_, SodStream<Arc<EncryptedDatagramLink<Arc<MemDatagramLink>>>>>(
        &sod_enc_dg_stack,
    );

    let listener = TcpListener::bind(local()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let srv_key = Arc::new(ScopeKeypair::generate());
    let cli_key = Arc::new(ScopeKeypair::generate());
    let enc_listener = EncryptedStreamListener::start(
        TcpListenerSource::new(listener, TcpCarrier::default()),
        srv_key.clone(),
    );
    assert_listener_type::<_, EncryptedStream<TcpIo>>(&enc_listener);

    let enc_client = EncryptedStreamChannel::new(cli_key, TcpCarrier::default());
    let loc = EncryptedLocator::encode(srv_key.public_key(), addr.to_string().as_bytes());
    let (cli_stream, srv_stream) =
        tokio::try_join!(enc_client.dial_stream(&loc), enc_listener.accept()).unwrap();
    let (mut cli_r, mut cli_w) = cli_stream.split();
    let (mut srv_r, mut srv_w) = srv_stream.split();

    cli_w.write_all(b"static-poll-encrypted-tcp").await.unwrap();
    cli_w.shutdown().await.unwrap();
    let mut got = Vec::new();
    let mut chunk = [0u8; 64];
    loop {
        let n = srv_r.read(&mut chunk).await.unwrap();
        if n == 0 {
            break;
        }
        got.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(got, b"static-poll-encrypted-tcp");
    srv_w.write_all(b"ack-static").await.unwrap();
    srv_w.shutdown().await.unwrap();
    let mut ack = [0u8; 32];
    let n = cli_r.read(&mut ack).await.unwrap();
    assert_eq!(&ack[..n], b"ack-static");
    assert_eq!(cli_r.read(&mut ack).await.unwrap(), 0);

    let (raw_a, raw_b) = mem_datagram_pair(1500, 16);
    let k_a = ScopeKeypair::generate();
    let k_b = ScopeKeypair::generate();
    let replay = confluence_core::crypto::replay::SetupReplay::default();
    let (enc_a, (enc_b, _)) = tokio::try_join!(
        EncryptedDatagramLink::connect(raw_a.clone(), &k_a, k_b.public_key()),
        EncryptedDatagramLink::accept(raw_b.clone(), &k_b, &replay),
    )
    .unwrap();
    let pkt = PacketBuf::from_slice(b"in-place-sealed-datagram");
    let orig_ptr = pkt.as_slice().as_ptr();
    enc_a.send(pkt).await.unwrap();
    let received = enc_b.recv().await.unwrap();
    assert_eq!(received.as_slice(), b"in-place-sealed-datagram");
    assert_eq!(received.as_slice().as_ptr(), orig_ptr);

    let (tx, rx) = tokio::sync::watch::channel(1500u16);
    let mut w = MtuWatch::new(rx).with_cap(1400).with_overhead(30);
    assert_eq!(w.mtu(), 1370);
    tx.send_replace(1380);
    timeout(WAIT, w.changed()).await.unwrap().unwrap();
    assert_eq!(w.mtu(), 1350);
}
