use confluence_core::seams::access::{Decision, Grant, RevocationEvent};
use confluence_core::seams::channel::DatagramChannel;
use confluence_core::seams::edge::DatagramSession;
use confluence_core::seams::routing::ExplicitPath;
use confluence_core::security::noise::DATAGRAM_WIRE_OVERHEAD_BYTES;
use confluence_core::{
    ChannelAddr, ChannelId, CoreError, EndpointName, Node, OpaqueCredential, Plane, ScopeId,
    StaticKeypair, TrustScope,
};
use confluence_testkit::{AuditAccessControl, MemDatagramHub, MemStreamHub, StaticMapPathSource};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn direct_two_plane_roundtrip_cookie_flood_and_control_only_acl() {
    let dgram_hub = MemDatagramHub::new(1400);
    let stream_hub = MemStreamHub::new();

    let scope_id = ScopeId::new("friends-gaming").unwrap();
    let alice_kp = StaticKeypair::generate();
    let bob_kp = StaticKeypair::generate();

    let alice_policy = AuditAccessControl::allow_all(Duration::from_secs(60));
    let bob_policy = AuditAccessControl::allow_all(Duration::from_secs(60));

    let alice_routes = StaticMapPathSource::new();
    alice_routes.insert(
        scope_id.clone(),
        bob_kp.peer_id(),
        ExplicitPath {
            plane: Plane::Stream,
            entry_channel: ChannelId::new("tcp0").unwrap(),
            entry_addr: ChannelAddr::new("bob:2000").unwrap(),
            hops: vec![],
            target_scope_tag: bob_kp.target_tag(),
            target_pubkey: bob_kp.peer_id(),
            target_credential: Some(OpaqueCredential::from_utf8("cred-ok").unwrap()),
        },
    );
    alice_routes.insert(
        scope_id.clone(),
        bob_kp.peer_id(),
        ExplicitPath {
            plane: Plane::Datagram,
            entry_channel: ChannelId::new("udp0").unwrap(),
            entry_addr: ChannelAddr::new("bob:1000").unwrap(),
            hops: vec![],
            target_scope_tag: bob_kp.target_tag(),
            target_pubkey: bob_kp.peer_id(),
            target_credential: Some(OpaqueCredential::from_utf8("cred-ok").unwrap()),
        },
    );

    let alice_node = Node::new(alice_routes);
    alice_node
        .add_scope(TrustScope::new(
            scope_id.clone(),
            alice_kp.clone(),
            alice_policy,
        ))
        .unwrap();
    let a_udp = dgram_hub.bind("udp0", "alice:1000");
    let a_tcp = stream_hub.bind("tcp0", "alice:2000");
    alice_node.attach_datagram_channel(a_udp.clone()).unwrap();
    alice_node.attach_stream_channel(a_tcp).unwrap();

    let bob_node = Node::new(StaticMapPathSource::new());
    let bob_scope = TrustScope::new(scope_id.clone(), bob_kp.clone(), bob_policy.clone());
    // Enable flood cookie mode on Bob to verify transparent stateless MAC2 challenge-response!
    bob_scope.cookie_protector().set_under_load(true);
    bob_node.add_scope(bob_scope).unwrap();
    let b_udp = dgram_hub.bind("udp0", "bob:1000");
    let b_tcp = stream_hub.bind("tcp0", "bob:2000");
    bob_node.attach_datagram_channel(b_udp).unwrap();
    bob_node.attach_stream_channel(b_tcp).unwrap();

    // 1. Pre-auth resilience: inject garbage UDP packets to Bob -> silently dropped, 0 ACL calls!
    a_udp
        .send_to(
            &ChannelAddr::new("bob:1000").unwrap(),
            &[0, 0, 0, 0, 0x10, 1, 2, 3],
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(bob_policy.evaluation_count(), 0);

    // 2. Publish Stream and Datagram endpoints on Bob.
    let ep_name = EndpointName::new("minecraft").unwrap();
    let mut stream_ep = bob_node
        .publish_stream_endpoint(&scope_id, ep_name.clone())
        .unwrap();
    let mut dgram_ep = bob_node
        .publish_datagram_endpoint(&scope_id, ep_name.clone())
        .unwrap();

    // 3. Stream Plane: multi-chunk 64 KiB roundtrip under flood cookie challenge.
    let accept_task = tokio::spawn(async move {
        let mut inbound = stream_ep.accept().await.unwrap();
        let mut payload = vec![0u8; 64 * 1024];
        inbound.stream.read_exact(&mut payload).await.unwrap();
        inbound
            .stream
            .write_all(b"stream-ack-from-bob")
            .await
            .unwrap();
        inbound.stream.close().await.unwrap();
        (inbound.remote_peer, payload)
    });

    let mut client_stream = alice_node
        .open_stream(&scope_id, bob_kp.peer_id(), ep_name.clone())
        .await
        .unwrap();
    assert_eq!(client_stream.remote_peer(), bob_kp.peer_id());

    let big_data: Vec<u8> = (0..(64 * 1024)).map(|i| (i % 251) as u8).collect();
    client_stream.write_all(&big_data).await.unwrap();
    let mut ack = Vec::new();
    client_stream.read_to_end(&mut ack).await.unwrap();
    assert_eq!(ack, b"stream-ack-from-bob");

    let (verified_peer, received_big) = accept_task.await.unwrap();
    assert_eq!(verified_peer, alice_kp.peer_id());
    assert_eq!(received_big, big_data);

    // AccessControl ran ONCE for the entire 64KiB stream (never per packet/chunk!).
    assert_eq!(bob_policy.evaluation_count(), 1);

    // 4. Datagram Plane: discrete messages with reorder + constant 29B overhead!
    let dgram_accept = tokio::spawn(async move {
        let sess = dgram_ep.accept().await.unwrap();
        let m1 = sess.recv().await.unwrap();
        let m2 = sess.recv().await.unwrap();
        sess.send(b"dgram-pong").await.unwrap();
        (sess.remote_peer(), m1, m2, dgram_ep)
    });

    let a_dgram = alice_node
        .open_datagram(&scope_id, bob_kp.peer_id(), ep_name)
        .await
        .unwrap();

    let pkts_before_data = dgram_hub.captured_packets("alice:1000", "bob:1000").len();
    dgram_hub.set_reorder_adjacent("alice:1000", "bob:1000", true);
    a_dgram.send(b"pkt-one").await.unwrap();
    a_dgram.send(b"pkt-two").await.unwrap();
    dgram_hub.set_reorder_adjacent("alice:1000", "bob:1000", false);

    let pong = a_dgram.recv().await.unwrap();
    assert_eq!(&pong[..], b"dgram-pong");

    let (dgram_peer, m1, m2, _keep_ep) = dgram_accept.await.unwrap();
    assert_eq!(dgram_peer, alice_kp.peer_id());
    assert_eq!(&m1[..], b"pkt-two");
    assert_eq!(&m2[..], b"pkt-one");

    // Verify exact 29-byte wire overhead on data datagrams and zero plaintext on wire!
    let all_pkts = dgram_hub.captured_packets("alice:1000", "bob:1000");
    let data_pkt = &all_pkts[pkts_before_data];
    assert_eq!(
        data_pkt.len(),
        DATAGRAM_WIRE_OVERHEAD_BYTES + b"pkt-one".len()
    );
    assert!(!data_pkt.windows(7).any(|w| w == b"pkt-one"));

    // Only 2 total AccessControl evaluations (1 for stream open, 1 for datagram open)!
    assert_eq!(bob_policy.evaluation_count(), 2);
}

#[tokio::test]
async fn strict_plane_separation_and_scope_isolation() {
    let dgram_hub = MemDatagramHub::new(1400);
    let stream_hub = MemStreamHub::new();

    let scope_alpha = ScopeId::new("alpha").unwrap();
    let scope_beta = ScopeId::new("beta").unwrap();

    let alice_alpha = StaticKeypair::generate();
    let bob_alpha = StaticKeypair::generate();
    let bob_beta = StaticKeypair::generate();

    let routes = StaticMapPathSource::new();
    // Misconfigure Stream route to point at Datagram carrier `udp0` -> must fail explicitly!
    routes.insert(
        scope_alpha.clone(),
        bob_alpha.peer_id(),
        ExplicitPath {
            plane: Plane::Stream,
            entry_channel: ChannelId::new("udp0").unwrap(),
            entry_addr: ChannelAddr::new("bob:1000").unwrap(),
            hops: vec![],
            target_scope_tag: bob_alpha.target_tag(),
            target_pubkey: bob_alpha.peer_id(),
            target_credential: None,
        },
    );
    routes.insert(
        scope_alpha.clone(),
        bob_alpha.peer_id(),
        ExplicitPath {
            plane: Plane::Datagram,
            entry_channel: ChannelId::new("udp0").unwrap(),
            entry_addr: ChannelAddr::new("bob:1000").unwrap(),
            hops: vec![],
            target_scope_tag: bob_alpha.target_tag(),
            target_pubkey: bob_alpha.peer_id(),
            target_credential: None,
        },
    );

    let alice_node = Node::new(routes);
    alice_node
        .add_scope(TrustScope::new(
            scope_alpha.clone(),
            alice_alpha,
            AuditAccessControl::allow_all(Duration::from_secs(60)),
        ))
        .unwrap();
    alice_node
        .attach_datagram_channel(dgram_hub.bind("udp0", "alice:1000"))
        .unwrap();
    alice_node
        .attach_stream_channel(stream_hub.bind("tcp0", "alice:2000"))
        .unwrap();

    let bob_node = Node::new(StaticMapPathSource::new());
    bob_node
        .add_scope(TrustScope::new(
            scope_alpha.clone(),
            bob_alpha.clone(),
            AuditAccessControl::allow_all(Duration::from_secs(60)),
        ))
        .unwrap();
    bob_node
        .add_scope(TrustScope::new(
            scope_beta.clone(),
            bob_beta,
            AuditAccessControl::allow_all(Duration::from_secs(60)),
        ))
        .unwrap();
    bob_node
        .attach_datagram_channel(dgram_hub.bind("udp0", "bob:1000"))
        .unwrap();

    let secret_ep = EndpointName::new("internal-db").unwrap();
    let _beta_ep = bob_node
        .publish_datagram_endpoint(&scope_beta, secret_ep.clone())
        .unwrap();

    let mismatch_err = alice_node
        .open_stream(&scope_alpha, bob_alpha.peer_id(), secret_ep.clone())
        .await
        .expect_err("cross-plane route must be rejected");
    assert!(matches!(mismatch_err, CoreError::PlaneMismatch { .. }));

    let iso_err = alice_node
        .open_datagram(&scope_alpha, bob_alpha.peer_id(), secret_ep)
        .await
        .expect_err("unpublished endpoint in alpha must be rejected");
    assert!(matches!(iso_err, CoreError::AccessDenied(_)));
}

#[tokio::test]
async fn in_band_renewal_and_immediate_teardown_on_revocation_unpublish_and_link_drop() {
    let dgram_hub = MemDatagramHub::new(1400);
    let stream_hub = MemStreamHub::new();

    let scope_id = ScopeId::new("collab").unwrap();
    let alice_kp = StaticKeypair::generate();
    let bob_kp = StaticKeypair::generate();

    let bob_policy = AuditAccessControl::allow_all(Duration::from_millis(150));
    bob_policy.add_rule(|req| {
        if matches!(
            req.action,
            confluence_core::seams::access::Action::RenewGrant { .. }
        ) {
            Some(Decision::Allow(Grant::with_ttl(Duration::from_secs(10))))
        } else {
            None
        }
    });

    let routes = StaticMapPathSource::new();
    routes.insert(
        scope_id.clone(),
        bob_kp.peer_id(),
        ExplicitPath {
            plane: Plane::Stream,
            entry_channel: ChannelId::new("tcp0").unwrap(),
            entry_addr: ChannelAddr::new("bob:2000").unwrap(),
            hops: vec![],
            target_scope_tag: bob_kp.target_tag(),
            target_pubkey: bob_kp.peer_id(),
            target_credential: None,
        },
    );
    routes.insert(
        scope_id.clone(),
        bob_kp.peer_id(),
        ExplicitPath {
            plane: Plane::Datagram,
            entry_channel: ChannelId::new("udp0").unwrap(),
            entry_addr: ChannelAddr::new("bob:1000").unwrap(),
            hops: vec![],
            target_scope_tag: bob_kp.target_tag(),
            target_pubkey: bob_kp.peer_id(),
            target_credential: None,
        },
    );

    let alice_node = Node::new(routes);
    alice_node
        .add_scope(TrustScope::new(
            scope_id.clone(),
            alice_kp.clone(),
            AuditAccessControl::allow_all(Duration::from_secs(60)),
        ))
        .unwrap();
    let a_udp = dgram_hub.bind("udp0", "alice:1000");
    alice_node.attach_datagram_channel(a_udp.clone()).unwrap();
    alice_node
        .attach_stream_channel(stream_hub.bind("tcp0", "alice:2000"))
        .unwrap();

    let bob_node = Node::new(StaticMapPathSource::new());
    bob_node
        .add_scope(TrustScope::new(
            scope_id.clone(),
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

    let ep_stream = EndpointName::new("ssh-dev").unwrap();
    let ep_dgram = EndpointName::new("telemetry").unwrap();
    let mut b_stream_ep = bob_node
        .publish_stream_endpoint(&scope_id, ep_stream.clone())
        .unwrap();
    let mut b_dgram_ep = bob_node
        .publish_datagram_endpoint(&scope_id, ep_dgram.clone())
        .unwrap();

    let mut a_stream = alice_node
        .open_stream(&scope_id, bob_kp.peer_id(), ep_stream.clone())
        .await
        .unwrap();
    let mut b_inbound = b_stream_ep.accept().await.unwrap();

    a_stream
        .renew(Some(OpaqueCredential::from_utf8("fresh-token").unwrap()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    a_stream.write_all(b"still-alive").await.unwrap();
    let mut buf = [0u8; 32];
    let n = b_inbound.stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"still-alive");

    bob_policy.trigger_revocation(RevocationEvent {
        scope: Some(scope_id.clone()),
        peer: Some(alice_kp.peer_id()),
        endpoint: Some(ep_stream),
    });
    let rev_err = tokio::time::timeout(Duration::from_secs(1), b_inbound.stream.read(&mut buf))
        .await
        .expect("revoked stream must wake immediately")
        .unwrap_err();
    assert_eq!(rev_err.kind(), std::io::ErrorKind::PermissionDenied);

    let a_sess = alice_node
        .open_datagram(&scope_id, bob_kp.peer_id(), ep_dgram)
        .await
        .unwrap();
    let b_sess = b_dgram_ep.accept().await.unwrap();
    a_sess.renew(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    a_sess.send(b"post-renew").await.unwrap();
    assert_eq!(&b_sess.recv().await.unwrap()[..], b"post-renew");

    b_dgram_ep.unpublish();
    let unpub_err = tokio::time::timeout(Duration::from_secs(1), b_sess.recv())
        .await
        .expect("unpublished session must wake immediately")
        .unwrap_err();
    assert!(matches!(
        unpub_err,
        CoreError::GrantRevoked | CoreError::Closed(_)
    ));

    a_udp.fail_channel("NIC unplugged");
    let link_err = tokio::time::timeout(Duration::from_secs(1), a_sess.recv())
        .await
        .expect("carrier failure must surface promptly")
        .unwrap_err();
    assert!(matches!(link_err, CoreError::Closed(_)));
}
