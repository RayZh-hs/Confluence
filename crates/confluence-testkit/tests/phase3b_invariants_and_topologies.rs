use confluence_carriers::{NoiseAclDatagramChannel, NoiseAclStreamChannel};
use confluence_core::seams::access::{Action, Decision, RevocationEvent};
use confluence_core::seams::edge::DatagramSession;
use confluence_core::seams::routing::{ExplicitPath, PathHop};
use confluence_core::security::noise::DATAGRAM_WIRE_OVERHEAD_BYTES;
use confluence_core::{
    ChannelAddr, ChannelId, CoreError, EndpointName, Node, OpaqueCredential, Plane, ScopeId,
    StaticKeypair, TrustScope,
};
use confluence_relay::{
    RelayDatagramChannel, RelayDatagramClient, RelayIngressStreamChannel, RelayStreamChannel,
};
use confluence_testkit::{AuditAccessControl, MemDatagramHub, MemStreamHub, StaticMapPathSource};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Verifies single-pass 1-RTT Multi-Hop (`A -> H1 -> H2 -> B`) across `NoiseAclChannel` hops
/// on both Datagram and Stream planes:
/// - `H1` and `H2` authenticate `A` directly (`channel <-> A`), never transitive hop identities!
/// - `H1` never sees `H2`'s credential, `B`'s credential, `B`'s endpoint name, or E2E plaintext!
/// - `H2` never sees `H1`'s credential, `B`'s credential, `B`'s endpoint name, or E2E plaintext!
/// - Datagram Plane overhead stays flat at 29 bytes across all 3 links!
#[tokio::test]
async fn multihop_three_link_blind_intermediaries_and_no_transitive_trust() {
    let dgram_hub = MemDatagramHub::new(1400);
    let stream_hub = MemStreamHub::new();

    let scope_e2e = ScopeId::new("e2e-research").unwrap();
    let scope_h1 = ScopeId::new("h1-transit").unwrap();
    let scope_h2 = ScopeId::new("h2-transit").unwrap();

    let alice_kp = StaticKeypair::generate();
    let bob_kp = StaticKeypair::generate();

    let h1_dgram_kp = StaticKeypair::generate();
    let h1_stream_kp = StaticKeypair::generate();
    let h2_dgram_kp = StaticKeypair::generate();
    let h2_stream_kp = StaticKeypair::generate();

    let cred_h1 = b"SECRET_CRED_FOR_H1_ONLY";
    let cred_h2 = b"SECRET_CRED_FOR_H2_ONLY";
    let cred_bob = b"SECRET_CRED_FOR_BOB_E2E_ONLY";
    let secret_ep_str = "SUPER_SECRET_ENDPOINT_NAME";
    let secret_stream_msg = b"TOP_SECRET_STREAM_PAYLOAD_BYTES";
    let secret_dgram_msg = b"TOP_SECRET_DGRAM_PAYLOAD_BYTES";

    // Hop 1 policy: MUST verify Alice's PeerId directly + H1's credential!
    let h1_policy = AuditAccessControl::deny_by_default(Duration::from_secs(60));
    let expected_alice = alice_kp.peer_id();
    h1_policy.add_rule(move |req| {
        if req.peer == expected_alice
            && req.credential.as_ref().map(|c| c.as_bytes()) == Some(cred_h1.as_slice())
            && matches!(req.action, Action::ChannelForward { .. })
        {
            Some(Decision::Allow(confluence_core::seams::access::Grant::with_ttl(
                Duration::from_secs(60),
            )))
        } else {
            None
        }
    });

    // Hop 2 policy: MUST verify Alice's PeerId directly (NOT H1!) + H2's credential!
    let h2_policy = AuditAccessControl::deny_by_default(Duration::from_secs(60));
    h2_policy.add_rule(move |req| {
        if req.peer == expected_alice
            && req.credential.as_ref().map(|c| c.as_bytes()) == Some(cred_h2.as_slice())
            && matches!(req.action, Action::ChannelForward { .. })
        {
            Some(Decision::Allow(confluence_core::seams::access::Grant::with_ttl(
                Duration::from_secs(60),
            )))
        } else {
            None
        }
    });

    // Bob E2E policy: MUST verify Alice's PeerId + Bob's E2E credential!
    let bob_policy = AuditAccessControl::deny_by_default(Duration::from_secs(60));
    bob_policy.add_rule(move |req| {
        if req.peer == expected_alice
            && req.credential.as_ref().map(|c| c.as_bytes()) == Some(cred_bob.as_slice())
            && matches!(req.action, Action::OpenEndpoint { .. })
        {
            Some(Decision::Allow(confluence_core::seams::access::Grant::with_ttl(
                Duration::from_secs(60),
            )))
        } else {
            None
        }
    });

    // Set up H1
    let h1_node = Node::new(StaticMapPathSource::new());
    let h1_udp = dgram_hub.bind("udp0", "h1:1000");
    let h1_tcp = stream_hub.bind("tcp0", "h1:2000");
    h1_node.attach_datagram_channel(h1_udp.clone()).unwrap();
    h1_node.attach_stream_channel(h1_tcp.clone()).unwrap();
    h1_node
        .mount_datagram_forward_channel(NoiseAclDatagramChannel::new(
            h1_udp,
            scope_h1.clone(),
            h1_dgram_kp.clone(),
            h1_policy.clone(),
        ))
        .unwrap();
    h1_node
        .mount_stream_forward_channel(NoiseAclStreamChannel::new(
            h1_tcp,
            scope_h1,
            h1_stream_kp.clone(),
            h1_policy.clone(),
        ))
        .unwrap();

    // Set up H2
    let h2_node = Node::new(StaticMapPathSource::new());
    let h2_udp = dgram_hub.bind("udp0", "h2:1000");
    let h2_tcp = stream_hub.bind("tcp0", "h2:2000");
    h2_node.attach_datagram_channel(h2_udp.clone()).unwrap();
    h2_node.attach_stream_channel(h2_tcp.clone()).unwrap();
    h2_node
        .mount_datagram_forward_channel(NoiseAclDatagramChannel::new(
            h2_udp,
            scope_h2.clone(),
            h2_dgram_kp.clone(),
            h2_policy.clone(),
        ))
        .unwrap();
    h2_node
        .mount_stream_forward_channel(NoiseAclStreamChannel::new(
            h2_tcp,
            scope_h2,
            h2_stream_kp.clone(),
            h2_policy.clone(),
        ))
        .unwrap();

    // Set up Bob
    let bob_node = Node::new(StaticMapPathSource::new());
    bob_node
        .add_scope(TrustScope::new(
            scope_e2e.clone(),
            bob_kp.clone(),
            bob_policy.clone(),
        ))
        .unwrap();
    bob_node
        .attach_datagram_channel(dgram_hub.bind("udp0", "bob:1000"))
        .unwrap();
    bob_node
        .attach_stream_channel(stream_hub.bind("tcp0", "bob:2000"))
        .unwrap();

    let ep = EndpointName::new(secret_ep_str).unwrap();
    let mut b_dgram_ep = bob_node
        .publish_datagram_endpoint(&scope_e2e, ep.clone())
        .unwrap();
    let mut b_stream_ep = bob_node
        .publish_stream_endpoint(&scope_e2e, ep.clone())
        .unwrap();

    // Set up Alice with explicit 2-hop chain `A -> H1 -> H2 -> B`
    let routes = StaticMapPathSource::new();
    routes.insert(
        scope_e2e.clone(),
        bob_kp.peer_id(),
        ExplicitPath {
            plane: Plane::Datagram,
            entry_channel: ChannelId::new("udp0").unwrap(),
            entry_addr: ChannelAddr::new("h1:1000").unwrap(),
            hops: vec![
                PathHop {
                    target_tag: h1_dgram_kp.target_tag(),
                    channel_pubkey: h1_dgram_kp.peer_id(),
                    next_addr: ChannelAddr::new("h2:1000").unwrap(),
                    credential: Some(OpaqueCredential::new(cred_h1.to_vec()).unwrap()),
                },
                PathHop {
                    target_tag: h2_dgram_kp.target_tag(),
                    channel_pubkey: h2_dgram_kp.peer_id(),
                    next_addr: ChannelAddr::new("bob:1000").unwrap(),
                    credential: Some(OpaqueCredential::new(cred_h2.to_vec()).unwrap()),
                },
            ],
            target_scope_tag: bob_kp.target_tag(),
            target_pubkey: bob_kp.peer_id(),
            target_credential: Some(OpaqueCredential::new(cred_bob.to_vec()).unwrap()),
        },
    );
    routes.insert(
        scope_e2e.clone(),
        bob_kp.peer_id(),
        ExplicitPath {
            plane: Plane::Stream,
            entry_channel: ChannelId::new("tcp0").unwrap(),
            entry_addr: ChannelAddr::new("h1:2000").unwrap(),
            hops: vec![
                PathHop {
                    target_tag: h1_stream_kp.target_tag(),
                    channel_pubkey: h1_stream_kp.peer_id(),
                    next_addr: ChannelAddr::new("h2:2000").unwrap(),
                    credential: Some(OpaqueCredential::new(cred_h1.to_vec()).unwrap()),
                },
                PathHop {
                    target_tag: h2_stream_kp.target_tag(),
                    channel_pubkey: h2_stream_kp.peer_id(),
                    next_addr: ChannelAddr::new("bob:2000").unwrap(),
                    credential: Some(OpaqueCredential::new(cred_h2.to_vec()).unwrap()),
                },
            ],
            target_scope_tag: bob_kp.target_tag(),
            target_pubkey: bob_kp.peer_id(),
            target_credential: Some(OpaqueCredential::new(cred_bob.to_vec()).unwrap()),
        },
    );

    let alice_node = Node::new(routes);
    alice_node
        .add_scope(TrustScope::new(
            scope_e2e.clone(),
            alice_kp.clone(),
            AuditAccessControl::allow_all(Duration::from_secs(60)),
        ))
        .unwrap();
    alice_node
        .attach_datagram_channel(dgram_hub.bind("udp0", "alice:1000"))
        .unwrap();
    alice_node
        .attach_stream_channel(stream_hub.bind("tcp0", "alice:2000"))
        .unwrap();

    // 1. Execute Datagram `A -> H1 -> H2 -> B`
    let a_dgram = alice_node
        .open_datagram(&scope_e2e, bob_kp.peer_id(), ep.clone())
        .await
        .unwrap();
    let b_dgram = b_dgram_ep.accept().await.unwrap();

    let idx_ah1 = dgram_hub.captured_packets("alice:1000", "h1:1000").len();
    let idx_h1h2 = dgram_hub.captured_packets("h1:1000", "h2:1000").len();
    let idx_h2b = dgram_hub.captured_packets("h2:1000", "bob:1000").len();

    a_dgram.send(secret_dgram_msg).await.unwrap();
    assert_eq!(&b_dgram.recv().await.unwrap()[..], secret_dgram_msg);

    // Assert constant 29-byte overhead across ALL 3 hops (no growing nested crypto overhead!)
    let p1 = &dgram_hub.captured_packets("alice:1000", "h1:1000")[idx_ah1];
    let p2 = &dgram_hub.captured_packets("h1:1000", "h2:1000")[idx_h1h2];
    let p3 = &dgram_hub.captured_packets("h2:1000", "bob:1000")[idx_h2b];
    let expected_len = DATAGRAM_WIRE_OVERHEAD_BYTES + secret_dgram_msg.len();
    assert_eq!(p1.len(), expected_len);
    assert_eq!(p2.len(), expected_len);
    assert_eq!(p3.len(), expected_len);
    assert_eq!(&p1[4..], &p2[4..]);
    assert_eq!(&p2[4..], &p3[4..]);

    // 2. Execute Stream `A -> H1 -> H2 -> B`
    let mut a_stream = alice_node
        .open_stream(&scope_e2e, bob_kp.peer_id(), ep)
        .await
        .unwrap();
    let mut b_stream = b_stream_ep.accept().await.unwrap();

    a_stream.write_all(secret_stream_msg).await.unwrap();
    let mut rbuf = vec![0u8; secret_stream_msg.len()];
    b_stream.stream.read_exact(&mut rbuf).await.unwrap();
    assert_eq!(rbuf, secret_stream_msg);

    // 3. Assert NO credential leakage, NO endpoint name leakage, and NO plaintext leakage on ANY wire!
    for (_src, _dst, pkt) in dgram_hub.all_captured_packets() {
        assert!(!pkt.windows(cred_h1.len()).any(|w| w == cred_h1));
        assert!(!pkt.windows(cred_h2.len()).any(|w| w == cred_h2));
        assert!(!pkt.windows(cred_bob.len()).any(|w| w == cred_bob));
        assert!(!pkt
            .windows(secret_ep_str.len())
            .any(|w| w == secret_ep_str.as_bytes()));
        assert!(!pkt
            .windows(secret_dgram_msg.len())
            .any(|w| w == secret_dgram_msg));
    }
    for (src, dst) in [
        ("alice:2000", "h1:2000"),
        ("h1:2000", "h2:2000"),
        ("h2:2000", "bob:2000"),
    ] {
        let raw = stream_hub.captured_bytes(src, dst);
        assert!(!raw.windows(cred_h1.len()).any(|w| w == cred_h1));
        assert!(!raw.windows(cred_h2.len()).any(|w| w == cred_h2));
        assert!(!raw.windows(cred_bob.len()).any(|w| w == cred_bob));
        assert!(!raw
            .windows(secret_ep_str.len())
            .any(|w| w == secret_ep_str.as_bytes()));
        assert!(!raw
            .windows(secret_stream_msg.len())
            .any(|w| w == secret_stream_msg));
    }

    // 4. Assert H1 ONLY saw cred_h1 in policy, H2 ONLY saw cred_h2, Bob ONLY saw cred_bob!
    for r in h1_policy.requests() {
        assert_eq!(r.peer, alice_kp.peer_id());
        assert_eq!(r.credential.unwrap().as_bytes(), cred_h1);
    }
    for r in h2_policy.requests() {
        assert_eq!(r.peer, alice_kp.peer_id());
        assert_eq!(r.credential.unwrap().as_bytes(), cred_h2);
    }
    for r in bob_policy.requests() {
        assert_eq!(r.peer, alice_kp.peer_id());
        assert_eq!(r.credential.unwrap().as_bytes(), cred_bob);
    }
}

/// Verifies BOTH:
/// 1) 1-hop Passive Relay (`A -> R <- B`) on both planes
/// 2) Composed Multi-Hop + Passive Relay (`A -> H1 -> R <- B`) on a **single shared listener** on `R`
/// 3) Zero outbound dialing on `R` (`r_tcp.outbound_dial_count() == 0`, and `B` is unreachable from `R` if `R` tried to dial `B`!)
/// 4) Mid-session hop revocation & link-cut teardown!
#[tokio::test]
async fn passive_relay_direct_and_composed_multihop_zero_dial_and_revocation() {
    let dgram_hub = MemDatagramHub::new(1400);
    let stream_hub = MemStreamHub::new();

    let scope_e2e = ScopeId::new("game-group").unwrap();
    let scope_h1 = ScopeId::new("h1-acl").unwrap();
    let scope_relay = ScopeId::new("public-relay").unwrap();

    let alice_1hop_kp = StaticKeypair::generate();
    let alice_2hop_kp = StaticKeypair::generate();
    let bob_kp = StaticKeypair::generate();
    let h1_dgram_kp = StaticKeypair::generate();
    let h1_stream_kp = StaticKeypair::generate();
    let relay_dgram_kp = StaticKeypair::generate();
    let relay_stream_kp = StaticKeypair::generate();

    // Relay Node `R` bound on ONE shared UDP port ("relay:5000") and ONE shared TCP port ("relay:6000").
    let relay_policy = AuditAccessControl::allow_all(Duration::from_secs(60));
    let relay_node = Node::new(StaticMapPathSource::new());
    let r_udp = dgram_hub.bind("udp_shared", "relay:5000");
    let r_tcp = stream_hub.bind("tcp_shared", "relay:6000");
    relay_node.attach_datagram_channel(r_udp.clone()).unwrap();
    relay_node.attach_stream_channel(r_tcp.clone()).unwrap();

    let relay_dgram_plugin = RelayDatagramChannel::new(
        scope_relay.clone(),
        relay_dgram_kp.clone(),
        1400,
        relay_policy.clone(),
    );
    let relay_stream_plugin =
        RelayStreamChannel::new(scope_relay.clone(), relay_stream_kp.clone(), relay_policy.clone());
    relay_node
        .mount_datagram_forward_channel(relay_dgram_plugin.clone())
        .unwrap();
    relay_node
        .mount_stream_forward_channel(relay_stream_plugin.clone())
        .unwrap();

    // Hop 1 Node `H1`
    let h1_policy = AuditAccessControl::allow_all(Duration::from_secs(60));
    let h1_node = Node::new(StaticMapPathSource::new());
    let h1_udp = dgram_hub.bind("udp0", "h1:1000");
    let h1_tcp = stream_hub.bind("tcp0", "h1:2000");
    h1_node.attach_datagram_channel(h1_udp.clone()).unwrap();
    h1_node.attach_stream_channel(h1_tcp.clone()).unwrap();
    h1_node
        .mount_datagram_forward_channel(NoiseAclDatagramChannel::new(
            h1_udp,
            scope_h1.clone(),
            h1_dgram_kp.clone(),
            h1_policy.clone(),
        ))
        .unwrap();
    h1_node
        .mount_stream_forward_channel(NoiseAclStreamChannel::new(
            h1_tcp,
            scope_h1.clone(),
            h1_stream_kp.clone(),
            h1_policy.clone(),
        ))
        .unwrap();

    // Destination Node `B` behind firewall (notice B does NOT attach `b_tcp` as a public listener on Core —
    // B ONLY dials outbound to `R:6000` via `RelayIngressStreamChannel`!).
    let bob_node = Node::new(StaticMapPathSource::new());
    bob_node
        .add_scope(TrustScope::new(
            scope_e2e.clone(),
            bob_kp.clone(),
            AuditAccessControl::allow_all(Duration::from_secs(60)),
        ))
        .unwrap();
    let b_udp = dgram_hub.bind("udp_nat", "bob-nat:49152");
    let b_tcp_underlay = stream_hub.bind("tcp_nat", "bob-nat:49153");
    bob_node.attach_datagram_channel(b_udp).unwrap();

    // Register B's passive Datagram slot on R:5000!
    let dgram_reg = RelayDatagramClient::new();
    dgram_reg
        .register_once(
            &bob_node,
            &bob_kp,
            &ChannelId::new("udp_nat").unwrap(),
            &ChannelAddr::new("relay:5000").unwrap(),
            relay_dgram_kp.peer_id(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(relay_dgram_plugin.active_slot_count(), 1);

    // Register B's passive Stream pool (4 idle streams) on R:6000!
    let b_relay_ingress = RelayIngressStreamChannel::connect_pool(
        ChannelId::new("relay_in").unwrap(),
        b_tcp_underlay,
        bob_kp.clone(),
        ChannelAddr::new("relay:6000").unwrap(),
        relay_stream_kp.peer_id(),
        None,
        4,
    )
    .await
    .unwrap();
    bob_node.attach_stream_channel(b_relay_ingress).unwrap();
    assert_eq!(relay_stream_plugin.parked_stream_count(&bob_kp.peer_id()), 4);

    let ep = EndpointName::new("terraria").unwrap();
    let mut b_dgram_ep = bob_node
        .publish_datagram_endpoint(&scope_e2e, ep.clone())
        .unwrap();
    let mut b_stream_ep = bob_node
        .publish_stream_endpoint(&scope_e2e, ep.clone())
        .unwrap();

    let bob_slot_addr = ChannelAddr::new(bob_kp.peer_id().to_string()).unwrap();

    // --- PART A: 1-Hop Passive Relay (`A1 -> R <- B`) on BOTH planes ---
    let routes_1hop = StaticMapPathSource::new();
    routes_1hop.insert(
        scope_e2e.clone(),
        bob_kp.peer_id(),
        ExplicitPath {
            plane: Plane::Datagram,
            entry_channel: ChannelId::new("udp0").unwrap(),
            entry_addr: ChannelAddr::new("relay:5000").unwrap(),
            hops: vec![PathHop {
                target_tag: relay_dgram_kp.target_tag(),
                channel_pubkey: relay_dgram_kp.peer_id(),
                next_addr: bob_slot_addr.clone(),
                credential: None,
            }],
            target_scope_tag: bob_kp.target_tag(),
            target_pubkey: bob_kp.peer_id(),
            target_credential: None,
        },
    );
    routes_1hop.insert(
        scope_e2e.clone(),
        bob_kp.peer_id(),
        ExplicitPath {
            plane: Plane::Stream,
            entry_channel: ChannelId::new("tcp0").unwrap(),
            entry_addr: ChannelAddr::new("relay:6000").unwrap(),
            hops: vec![PathHop {
                target_tag: relay_stream_kp.target_tag(),
                channel_pubkey: relay_stream_kp.peer_id(),
                next_addr: bob_slot_addr.clone(),
                credential: None,
            }],
            target_scope_tag: bob_kp.target_tag(),
            target_pubkey: bob_kp.peer_id(),
            target_credential: None,
        },
    );

    let a1_node = Node::new(routes_1hop);
    a1_node
        .add_scope(TrustScope::new(
            scope_e2e.clone(),
            alice_1hop_kp.clone(),
            AuditAccessControl::allow_all(Duration::from_secs(60)),
        ))
        .unwrap();
    a1_node
        .attach_datagram_channel(dgram_hub.bind("udp0", "a1:1000"))
        .unwrap();
    a1_node
        .attach_stream_channel(stream_hub.bind("tcp0", "a1:2000"))
        .unwrap();

    let a1_dgram = a1_node
        .open_datagram(&scope_e2e, bob_kp.peer_id(), ep.clone())
        .await
        .unwrap();
    let b_dgram_1 = b_dgram_ep.accept().await.unwrap();
    a1_dgram.send(b"1hop-relay-dgram").await.unwrap();
    assert_eq!(&b_dgram_1.recv().await.unwrap()[..], b"1hop-relay-dgram");

    let mut a1_stream = a1_node
        .open_stream(&scope_e2e, bob_kp.peer_id(), ep.clone())
        .await
        .unwrap();
    let mut b_stream_1 = b_stream_ep.accept().await.unwrap();
    a1_stream.write_all(b"1hop-relay-stream").await.unwrap();
    let mut buf = [0u8; 32];
    let n = b_stream_1.stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"1hop-relay-stream");

    // --- PART B: Composed Multi-Hop + Passive Relay (`A2 -> H1 -> R <- B`) on shared R listener! ---
    let routes_2hop = StaticMapPathSource::new();
    routes_2hop.insert(
        scope_e2e.clone(),
        bob_kp.peer_id(),
        ExplicitPath {
            plane: Plane::Datagram,
            entry_channel: ChannelId::new("udp0").unwrap(),
            entry_addr: ChannelAddr::new("h1:1000").unwrap(),
            hops: vec![
                PathHop {
                    target_tag: h1_dgram_kp.target_tag(),
                    channel_pubkey: h1_dgram_kp.peer_id(),
                    next_addr: ChannelAddr::new("relay:5000").unwrap(),
                    credential: None,
                },
                PathHop {
                    target_tag: relay_dgram_kp.target_tag(),
                    channel_pubkey: relay_dgram_kp.peer_id(),
                    next_addr: bob_slot_addr.clone(),
                    credential: None,
                },
            ],
            target_scope_tag: bob_kp.target_tag(),
            target_pubkey: bob_kp.peer_id(),
            target_credential: None,
        },
    );
    routes_2hop.insert(
        scope_e2e.clone(),
        bob_kp.peer_id(),
        ExplicitPath {
            plane: Plane::Stream,
            entry_channel: ChannelId::new("tcp0").unwrap(),
            entry_addr: ChannelAddr::new("h1:2000").unwrap(),
            hops: vec![
                PathHop {
                    target_tag: h1_stream_kp.target_tag(),
                    channel_pubkey: h1_stream_kp.peer_id(),
                    next_addr: ChannelAddr::new("relay:6000").unwrap(),
                    credential: None,
                },
                PathHop {
                    target_tag: relay_stream_kp.target_tag(),
                    channel_pubkey: relay_stream_kp.peer_id(),
                    next_addr: bob_slot_addr,
                    credential: None,
                },
            ],
            target_scope_tag: bob_kp.target_tag(),
            target_pubkey: bob_kp.peer_id(),
            target_credential: None,
        },
    );

    let a2_node = Node::new(routes_2hop);
    a2_node
        .add_scope(TrustScope::new(
            scope_e2e.clone(),
            alice_2hop_kp.clone(),
            AuditAccessControl::allow_all(Duration::from_secs(60)),
        ))
        .unwrap();
    a2_node
        .attach_datagram_channel(dgram_hub.bind("udp0", "a2:1000"))
        .unwrap();
    a2_node
        .attach_stream_channel(stream_hub.bind("tcp0", "a2:2000"))
        .unwrap();

    let a2_dgram = a2_node
        .open_datagram(&scope_e2e, bob_kp.peer_id(), ep.clone())
        .await
        .unwrap();
    let b_dgram_2 = b_dgram_ep.accept().await.unwrap();
    a2_dgram.send(b"composed-h1-relay-dgram").await.unwrap();
    assert_eq!(
        &b_dgram_2.recv().await.unwrap()[..],
        b"composed-h1-relay-dgram"
    );
    b_dgram_2.send(b"composed-reverse-dgram").await.unwrap();
    assert_eq!(
        &a2_dgram.recv().await.unwrap()[..],
        b"composed-reverse-dgram"
    );

    let mut a2_stream = a2_node
        .open_stream(&scope_e2e, bob_kp.peer_id(), ep)
        .await
        .unwrap();
    let mut b_stream_2 = b_stream_ep.accept().await.unwrap();
    assert_eq!(b_stream_2.remote_peer, alice_2hop_kp.peer_id());
    a2_stream.write_all(b"composed-h1-relay-stream").await.unwrap();
    let n2 = b_stream_2.stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n2], b"composed-h1-relay-stream");

    // --- INVARIANT #5 PROOF: Relay Node R performed ZERO outbound dials! ---
    assert_eq!(r_tcp.outbound_dial_count(), 0);

    // --- INVARIANT #6 PROOF: Relay R verified `alice_2hop_kp` directly (NOT H1!) ---
    assert!(relay_policy.requests().iter().any(|req| {
        req.peer == alice_2hop_kp.peer_id()
            && matches!(&req.action, Action::ChannelCustom { kind, .. } if kind == "relay_connect")
    }));

    // --- Mid-Session Revocation at Intermediate Hop H1 immediately tears down active stream & circuit! ---
    h1_policy.trigger_revocation(RevocationEvent {
        scope: Some(scope_h1),
        peer: Some(alice_2hop_kp.peer_id()),
        endpoint: None,
    });

    // Active stream across A2 -> H1 -> R <- B severs immediately (honest ConnectionReset at B!)
    let stream_dead = tokio::time::timeout(Duration::from_secs(1), b_stream_2.stream.read(&mut buf))
        .await
        .expect("mid-chain hop revocation must sever stream immediately")
        .unwrap_err();
    assert_eq!(stream_dead.kind(), std::io::ErrorKind::ConnectionReset);

    // Active datagram label switches on H1 are purged immediately!
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(h1_node.active_label_switch_count(), 0);

    // --- Mid-Session Link Cut on `a1 <-> relay` severs A1's active stream honestly! ---
    stream_hub.set_symmetric_link_down("a1:2000", "relay:6000", true);
    let link_cut_err = tokio::time::timeout(Duration::from_secs(1), b_stream_1.stream.read(&mut buf))
        .await
        .expect("link cut on relay leg must propagate to B")
        .unwrap_err();
    assert_eq!(link_cut_err.kind(), std::io::ErrorKind::ConnectionReset);
    let _ = CoreError::AuthFailed;
}
