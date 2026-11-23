//! Integration tests verifying Confluence Core's modular architecture:
//! - Rotating `MAC2` flood cookies across direct and multi-hop named transits on both planes
//! - Multi-scope `Node` single-listener demultiplexing
//! - `IntersectAuthorizer` host sovereignty + named-transit SSRF prevention + Lease-level
//!   out-of-core QoS concurrency cap (zero handler wrapping) + reversible `unrevoke_peer`
//! - Out-of-core single-port `RelayService` (zero outbound dials, blind wire-tap, control-only ACL)
//! - `E2eStreamIo` (`tokio::io::AsyncRead + AsyncWrite`) + testkit fault injection

use std::{sync::Arc, time::Duration};

use confluence_core::{
    AsyncStream, AuthDenied, Authorizer, CoreErr, DATAGRAM_MTU, DatagramChannel,
    DatagramEndpointHandler, DatagramLinkExt, ExplicitPath, HopSpec, IntersectAuthorizer, Lease,
    Node, PacketBuf, Plane, ScopeInstance, ScopeKeypair, SessionAuth, StreamEndpointHandler,
    StreamReadExt, StreamWriteExt, TargetRef,
};
use confluence_edge::E2eStreamIo;
use confluence_plugins::{
    MemDatagramLink, MemStream, PolicyConfig, PolicyRuleConfig, RuleTargetKind, StaticAuthorizer,
    StaticCredentials, StaticPathSource, StaticPolicy, TokioSpawner, mem_datagram_pair,
    mem_stream_pair,
};
use confluence_relay::{
    FnRegistrationVerifier, PassiveStreamPool, RegistrationLease, RelayService,
    register_datagram_presence,
};
use confluence_testkit::{AuditAuthorizer, MemDatagramHub, MemStreamHub};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::{sleep, timeout},
};

const WAIT: Duration = Duration::from_secs(5);
const CARRIER: &str = "hub";

struct EchoStream;
impl StreamEndpointHandler for EchoStream {
    type Stream = MemStream;

    async fn open(&self, _auth: SessionAuth) -> Result<MemStream, CoreErr> {
        let (server, app) = mem_stream_pair(16384, 8192);
        tokio::spawn(async move {
            let (mut rx, mut tx) = app.split();
            let mut data = [0; 4096];
            while let Ok(n) = rx.read(&mut data).await {
                if n == 0 {
                    let _ = tx.shutdown().await;
                    break;
                }
                if tx.write_all(&data[..n]).await.is_err() {
                    break;
                }
            }
        });
        Ok(server)
    }
}

struct EchoDatagram;
impl DatagramEndpointHandler for EchoDatagram {
    type Link = Arc<MemDatagramLink>;

    async fn open(&self, _auth: SessionAuth) -> Result<Arc<MemDatagramLink>, CoreErr> {
        let (server, app) = mem_datagram_pair(u16::MAX, 64);
        tokio::spawn(async move {
            while let Ok(pkt) = app.recv().await {
                if app.send(pkt).await.is_err() {
                    break;
                }
            }
        });
        Ok(server)
    }
}

fn make_scope(auth: Arc<dyn Authorizer>, routes: Arc<StaticPathSource>) -> ScopeInstance {
    ScopeInstance::builder(ScopeKeypair::generate(), Arc::new(TokioSpawner))
        .authorizer(auth)
        .routes(routes)
        .build()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mac2_flood_cookies_across_direct_and_multihop_both_planes() {
    let auth = AuditAuthorizer::allow_all(Duration::from_secs(30));
    let routes = Arc::new(StaticPathSource::default());
    let creds = Arc::new(StaticCredentials::default());

    let a = ScopeInstance::builder(ScopeKeypair::generate(), Arc::new(TokioSpawner))
        .authorizer(auth.clone())
        .routes(routes.clone())
        .credentials(creds.clone())
        .build();
    let h1 = make_scope(auth.clone(), routes.clone());
    let b = make_scope(auth, routes.clone());

    creds.set_transit(h1.public_key(), "to-b", b"hop-ok".to_vec());
    creds.set_endpoint(b.public_key(), "echo", b"dest-ok".to_vec());
    creds.set_endpoint(b.public_key(), "echo-dg", b"dest-ok".to_vec());

    // Enable WireGuard-style MAC2 flood cookies on BOTH intermediate hop and destination!
    h1.set_under_load(true);
    b.set_under_load(true);
    assert!(h1.is_under_load());
    assert!(b.is_under_load());

    let st_hub = MemStreamHub::new(4096, 8192);
    let dg_hub = MemDatagramHub::new(1500);

    let a_st = st_hub.bind(b"a");
    let h1_st = st_hub.bind(b"h1");
    let b_st = st_hub.bind(b"b");

    let a_dg = dg_hub.bind(b"a");
    let h1_dg = dg_hub.bind(b"h1");
    let b_dg = dg_hub.bind(b"b");

    a.register_stream_carrier(CARRIER, a_st).unwrap();
    a.register_datagram_carrier(CARRIER, a_dg).unwrap();
    let _g1 = h1
        .publish_stream_route("to-b", h1_st.clone(), b"b")
        .unwrap();
    let _g2 = h1
        .publish_datagram_route("to-b", h1_dg.clone(), b"b")
        .unwrap();

    let h1_c = h1.clone();
    let b_c = b.clone();
    let t1 = tokio::spawn(async move {
        let _ = h1_c.serve_stream_listener(&*h1_st).await;
    });
    let t2 = tokio::spawn(async move {
        let _ = b_c.serve_stream_listener(&*b_st).await;
    });
    let h1_c2 = h1.clone();
    let b_c2 = b.clone();
    let t3 = tokio::spawn(async move {
        let _ = h1_c2.serve_datagram_listener(&*h1_dg).await;
    });
    let t4 = tokio::spawn(async move {
        let _ = b_c2.serve_datagram_listener(&*b_dg).await;
    });

    let _ps = b.publish_stream("echo", Arc::new(EchoStream)).unwrap();
    let _pd = b
        .publish_datagram("echo-dg", DATAGRAM_MTU, Arc::new(EchoDatagram))
        .unwrap();

    let hops = vec![HopSpec {
        peer: h1.public_key(),
        target: "to-b".into(),
    }];
    routes.set(
        b.public_key(),
        "echo",
        Plane::Stream,
        ExplicitPath {
            id: 1,
            first_channel: CARRIER.into(),
            first_locator: b"h1".to_vec(),
            min_mtu: 64,
            hops: hops.clone(),
        },
    );
    routes.set(
        b.public_key(),
        "echo-dg",
        Plane::Datagram,
        ExplicitPath {
            id: 2,
            first_channel: CARRIER.into(),
            first_locator: b"h1".to_vec(),
            min_mtu: DATAGRAM_MTU,
            hops,
        },
    );

    // Stream setup transparently resolves cookie challenges from H1 AND B.
    let stream = timeout(WAIT, a.dial_stream(b.public_key(), "echo"))
        .await
        .unwrap()
        .unwrap();
    stream.write_all(b"cookie-protected-stream").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut buf = [0u8; 64];
    let n = timeout(WAIT, stream.read(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"cookie-protected-stream");

    // Datagram setup also resolves cookie challenges from H1 AND B.
    let dg = timeout(
        WAIT,
        a.dial_datagram(b.public_key(), "echo-dg", DATAGRAM_MTU),
    )
    .await
    .unwrap()
    .unwrap();
    dg.send(PacketBuf::from_slice(b"cookie-protected-dg"))
        .unwrap();
    let reply = timeout(WAIT, dg.recv()).await.unwrap().unwrap();
    assert_eq!(reply.as_slice(), b"cookie-protected-dg");

    for t in [t1, t2, t3, t4] {
        t.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_scope_node_demuxes_single_listener_on_both_planes() {
    let auth = AuditAuthorizer::allow_all(Duration::from_secs(30));
    let routes_s1 = Arc::new(StaticPathSource::default());
    let routes_s2 = Arc::new(StaticPathSource::default());

    let alice_s1 = make_scope(auth.clone(), routes_s1.clone());
    let alice_s2 = make_scope(auth.clone(), routes_s2.clone());
    let bob_s1 = make_scope(auth.clone(), routes_s1.clone());
    let bob_s2 = make_scope(auth, routes_s2.clone());

    // Mount BOTH isolated Trust Scopes on a SINGLE Node sharing ONE listener per plane!
    let bob_node = Node::new(Arc::new(TokioSpawner));
    bob_node.add_scope(bob_s1.clone()).unwrap();
    bob_node.add_scope(bob_s2.clone()).unwrap();
    assert_eq!(
        bob_node.add_scope(bob_s1.clone()),
        Err(CoreErr::AlreadyPublished)
    );

    let st_hub = MemStreamHub::new(4096, 8192);
    let dg_hub = MemDatagramHub::new(1500);
    let a_st = st_hub.bind(b"alice");
    let b_st = st_hub.bind(b"bob-shared");
    let a_dg = dg_hub.bind(b"alice");
    let b_dg = dg_hub.bind(b"bob-shared");

    alice_s1
        .register_stream_carrier(CARRIER, a_st.clone())
        .unwrap();
    alice_s2.register_stream_carrier(CARRIER, a_st).unwrap();
    alice_s1
        .register_datagram_carrier(CARRIER, a_dg.clone())
        .unwrap();
    alice_s2.register_datagram_carrier(CARRIER, a_dg).unwrap();

    let bn1 = bob_node.clone();
    let bn2 = bob_node.clone();
    let t1 = tokio::spawn(async move {
        let _ = bn1.serve_stream_listener(&*b_st).await;
    });
    let t2 = tokio::spawn(async move {
        let _ = bn2.serve_datagram_listener(&*b_dg).await;
    });

    let _p1 = bob_s1
        .publish_stream("only-s1", Arc::new(EchoStream))
        .unwrap();
    let _p2 = bob_s2
        .publish_datagram("only-s2", DATAGRAM_MTU, Arc::new(EchoDatagram))
        .unwrap();

    routes_s1.set(
        bob_s1.public_key(),
        "only-s1",
        Plane::Stream,
        ExplicitPath {
            id: 11,
            first_channel: CARRIER.into(),
            first_locator: b"bob-shared".to_vec(),
            min_mtu: 64,
            hops: vec![],
        },
    );
    routes_s2.set(
        bob_s2.public_key(),
        "only-s2",
        Plane::Datagram,
        ExplicitPath {
            id: 22,
            first_channel: CARRIER.into(),
            first_locator: b"bob-shared".to_vec(),
            min_mtu: DATAGRAM_MTU,
            hops: vec![],
        },
    );
    // Cross-scope attempt: try reaching s1's endpoint via s2's key!
    routes_s2.set(
        bob_s2.public_key(),
        "only-s1",
        Plane::Stream,
        ExplicitPath {
            id: 23,
            first_channel: CARRIER.into(),
            first_locator: b"bob-shared".to_vec(),
            min_mtu: 64,
            hops: vec![],
        },
    );

    let st = timeout(WAIT, alice_s1.dial_stream(bob_s1.public_key(), "only-s1"))
        .await
        .unwrap()
        .unwrap();
    st.write_all(b"scope-1-stream").await.unwrap();
    st.shutdown().await.unwrap();
    let mut buf = [0u8; 32];
    let n = timeout(WAIT, st.read(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"scope-1-stream");

    let dg = timeout(
        WAIT,
        alice_s2.dial_datagram(bob_s2.public_key(), "only-s2", DATAGRAM_MTU),
    )
    .await
    .unwrap()
    .unwrap();
    dg.send(PacketBuf::from_slice(b"scope-2-dgram")).unwrap();
    assert_eq!(
        timeout(WAIT, dg.recv()).await.unwrap().unwrap().as_slice(),
        b"scope-2-dgram"
    );

    assert_eq!(
        alice_s2
            .dial_stream(bob_s2.public_key(), "only-s1")
            .await
            .err(),
        Some(CoreErr::Unpublished)
    );

    t1.abort();
    t2.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn intersect_authorizer_named_transit_ssrf_out_of_core_qos_and_unrevoke() {
    let routes = Arc::new(StaticPathSource::default());

    // Local policy allows only endpoint "allowed" with out-of-core QosLimits (max 2 concurrent
    // streams) and named transit "good-bob"; external policy allows everything with longer TTL.
    let local = Arc::new(StaticPolicy::new(PolicyConfig {
        default_allow: false,
        default_ttl_secs: 60,
        rules: vec![
            PolicyRuleConfig {
                scope: None,
                peers: vec!["*".into()],
                action: RuleTargetKind::Endpoint,
                plane: Some(Plane::Stream),
                target: Some("allowed".into()),
                required_credential: None,
                ttl_secs: Some(30),
                max_bytes_per_sec: None,
                max_datagrams_per_sec: None,
                max_concurrent_streams: Some(2),
            },
            PolicyRuleConfig {
                scope: None,
                peers: vec!["*".into()],
                action: RuleTargetKind::Transit,
                plane: Some(Plane::Stream),
                target: Some("good-bob".into()),
                required_credential: None,
                ttl_secs: Some(30),
                max_bytes_per_sec: None,
                max_datagrams_per_sec: None,
                max_concurrent_streams: None,
            },
        ],
    }));
    let external = AuditAuthorizer::allow_all(Duration::from_secs(120));
    let combined = Arc::new(IntersectAuthorizer::new(local, external));

    let a = make_scope(combined.clone(), routes.clone());
    let h = make_scope(combined.clone(), routes.clone());
    let b = make_scope(combined, routes.clone());

    let hub = MemStreamHub::new(4096, 8192);
    let a_ch = hub.bind(b"a");
    let h_ch = hub.bind(b"h");
    let b_ch = hub.bind(b"good-bob");

    a.register_stream_carrier(CARRIER, a_ch).unwrap();
    // Named transit hides downstream locator: H only publishes "good-bob", never raw IP dialing!
    let _h_transit = h
        .publish_stream_route("good-bob", h_ch.clone(), b"good-bob")
        .unwrap();

    let h_c = h.clone();
    let b_c = b.clone();
    let t1 = tokio::spawn(async move {
        let _ = h_c.serve_stream_listener(&*h_ch).await;
    });
    let t2 = tokio::spawn(async move {
        let _ = b_c.serve_stream_listener(&*b_ch).await;
    });

    // Zero handler wrapping needed: StaticPolicy enforces max_concurrent_streams directly via Lease!
    let _p1 = b.publish_stream("allowed", Arc::new(EchoStream)).unwrap();
    let _p2 = b.publish_stream("vetoed", Arc::new(EchoStream)).unwrap();

    // 1. SSRF prevention by construction: arbitrary target "169.254.169.254:80" is neither
    //    authorized nor published on H.
    routes.set(
        b.public_key(),
        "allowed",
        Plane::Stream,
        ExplicitPath {
            id: 1,
            first_channel: CARRIER.into(),
            first_locator: b"h".to_vec(),
            min_mtu: 64,
            hops: vec![HopSpec {
                peer: h.public_key(),
                target: "169.254.169.254:80".into(),
            }],
        },
    );
    assert!(matches!(
        a.dial_stream(b.public_key(), "allowed").await,
        Err(CoreErr::HopRejected { index: 0, reason })
            if *reason == CoreErr::Denied || *reason == CoreErr::Unpublished
    ));

    // 2. Named transit "good-bob" succeeds; local host veto still blocks "vetoed" endpoint.
    let good_path = ExplicitPath {
        id: 2,
        first_channel: CARRIER.into(),
        first_locator: b"h".to_vec(),
        min_mtu: 64,
        hops: vec![HopSpec {
            peer: h.public_key(),
            target: "good-bob".into(),
        }],
    };
    routes.set(b.public_key(), "allowed", Plane::Stream, good_path.clone());
    routes.set(b.public_key(), "vetoed", Plane::Stream, good_path);

    assert_eq!(
        a.dial_stream(b.public_key(), "vetoed").await.err(),
        Some(CoreErr::Denied)
    );

    // 3. Out-of-core max_concurrent_streams = 2 enforced automatically via StaticPolicy's Lease guard!
    let s1 = a.dial_stream(b.public_key(), "allowed").await.unwrap();
    let s2 = a.dial_stream(b.public_key(), "allowed").await.unwrap();
    assert_eq!(
        a.dial_stream(b.public_key(), "allowed").await.err(),
        Some(CoreErr::Busy)
    );
    drop(s1);
    sleep(Duration::from_millis(60)).await;
    let s3 = timeout(WAIT, a.dial_stream(b.public_key(), "allowed"))
        .await
        .unwrap()
        .unwrap();

    // 4. Local revoke_peer + reversible unrevoke_peer!
    b.revoke_peer(&a.public_key());
    let mut buf = [0u8; 8];
    assert!(timeout(WAIT, s2.read(&mut buf)).await.unwrap().is_err());
    assert!(timeout(WAIT, s3.read(&mut buf)).await.unwrap().is_err());
    assert_eq!(
        a.dial_stream(b.public_key(), "allowed").await.err(),
        Some(CoreErr::Revoked)
    );
    drop((s2, s3));

    b.unrevoke_peer(&a.public_key());
    let s4 = timeout(WAIT, a.dial_stream(b.public_key(), "allowed"))
        .await
        .unwrap()
        .unwrap();
    s4.write_all(b"re-admitted").await.unwrap();
    s4.shutdown().await.unwrap();
    let mut out = [0u8; 16];
    let n = timeout(WAIT, s4.read(&mut out)).await.unwrap().unwrap();
    assert_eq!(&out[..n], b"re-admitted");

    t1.abort();
    t2.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_port_out_of_core_passive_relay_zero_dial_blind_wire_tap_and_control_only_acl() {
    let routes = Arc::new(StaticPathSource::default());
    let a_creds = Arc::new(StaticCredentials::default());

    let b_auth = AuditAuthorizer::allow_all(Duration::from_secs(30));
    let h1_auth = AuditAuthorizer::allow_all(Duration::from_secs(30));
    let r_auth = AuditAuthorizer::deny_by_default();

    let a = ScopeInstance::builder(ScopeKeypair::generate(), Arc::new(TokioSpawner))
        .authorizer(Arc::new(StaticAuthorizer::default()))
        .routes(routes.clone())
        .credentials(a_creds.clone())
        .build();
    let h1 = make_scope(h1_auth.clone(), routes.clone());
    let r = make_scope(r_auth.clone(), routes.clone());
    let b = make_scope(b_auth.clone(), routes.clone());

    let a_pk = a.public_key();
    let b_pk = b.public_key();

    // Relay R's Core Authorizer authorizes Alice's named transit "relay/bob-slot".
    r_auth.add_rule(move |req| match req.target {
        TargetRef::Transit {
            name: "relay/bob-slot",
            ..
        } if req.peer == a_pk && req.credential == b"relay-tok" => {
            Some(Ok(Lease::new(Duration::from_secs(30))))
        }
        _ => Some(Err(AuthDenied::Denied)),
    });

    // Out-of-core registration verifier independently authorizes Bob's NAT presence registration.
    let reg_verifier = Arc::new(FnRegistrationVerifier(
        move |req: confluence_relay::RelayRegistrationRequest<'_>| {
            if req.peer == b_pk && req.presence_id == "bob-slot" && req.credential == b"reg-secret"
            {
                Ok(RegistrationLease::new(Duration::from_secs(30)))
            } else {
                Err(CoreErr::Denied)
            }
        },
    ));

    // Originator A configures credentials cleanly on CredentialProvider (zero creds in routes/dials!).
    a_creds.set_transit(h1.public_key(), "to-relay", b"h1-only-cred".to_vec());
    a_creds.set_transit(r.public_key(), "relay/bob-slot", b"relay-tok".to_vec());
    a_creds.set_endpoint(
        b.public_key(),
        "super-secret-svc",
        b"bob-only-cred".to_vec(),
    );
    a_creds.set_endpoint(b.public_key(), "super-secret-dg", b"bob-only-cred".to_vec());

    let st_hub = MemStreamHub::new(4096, 8192);
    let dg_hub = MemDatagramHub::new(1500);

    let a_st = st_hub.bind(b"a");
    let h1_st = st_hub.bind(b"h1");
    let r_st = st_hub.bind(b"r");
    let b_st_nat = st_hub.bind(b"b-nat");

    let a_dg = dg_hub.bind(b"a");
    let h1_dg = dg_hub.bind(b"h1");
    let r_dg = dg_hub.bind(b"r");
    let b_dg_nat = dg_hub.bind(b"b-nat");

    a.register_stream_carrier(CARRIER, a_st).unwrap();
    a.register_datagram_carrier(CARRIER, a_dg).unwrap();
    let _h1_st_guard = h1
        .publish_stream_route("to-relay", h1_st.clone(), b"r")
        .unwrap();
    let _h1_dg_guard = h1
        .publish_datagram_route("to-relay", h1_dg.clone(), b"r")
        .unwrap();

    // Relay R mounts out-of-core RelayService under prefix "relay/" on its SINGLE shared
    // stream & datagram listeners (zero extra ports, zero Core passive-relay coupling!).
    let relay_svc = RelayService::new(&r, "relay/", reg_verifier, 4096, 1500).unwrap();
    let _r_st_guard = r
        .publish_stream_transit_prefix("relay/", Arc::new(relay_svc.clone()))
        .unwrap();
    let _r_dg_guard = r
        .publish_datagram_transit_prefix("relay/", Arc::new(relay_svc.clone()))
        .unwrap();

    let h1_c = h1.clone();
    let r_c = r.clone();
    let r_st_mux = relay_svc.wrap_stream_listener(r_st.clone());
    let r_dg_mux = relay_svc.wrap_datagram_listener(r_dg.clone());
    let t1 = tokio::spawn(async move {
        let _ = h1_c.serve_stream_listener(&*h1_st).await;
    });
    let t2 = tokio::spawn(async move {
        let _ = r_c.serve_stream_listener(&r_st_mux).await;
    });
    let h1_c2 = h1.clone();
    let r_c2 = r.clone();
    let t3 = tokio::spawn(async move {
        let _ = h1_c2.serve_datagram_listener(&*h1_dg).await;
    });
    let t4 = tokio::spawn(async move {
        let _ = r_c2.serve_datagram_listener(&r_dg_mux).await;
    });

    // NATed B registers passive presence over R's SINGLE port on BOTH planes (zero inbound ports on B!).
    let b_dg_link = b_dg_nat.open_link(b"r").await.unwrap();
    let reg_lease = register_datagram_presence(
        &b.identity(),
        &b_dg_link,
        r.public_key(),
        "bob-slot",
        b"reg-secret",
    )
    .await
    .unwrap();
    assert_eq!(reg_lease.ttl, Duration::from_secs(30));
    let _b_dg_in = b.attach_datagram(b_dg_link).unwrap();

    let stream_pool = PassiveStreamPool::start(
        b_st_nat,
        b.identity(),
        b"r".to_vec(),
        r.public_key(),
        "bob-slot",
        b"reg-secret".to_vec(),
        2,
    )
    .await
    .unwrap();
    let b_c = b.clone();
    let pool_c = stream_pool.clone();
    let t5 = tokio::spawn(async move {
        let _ = b_c.serve_stream_listener(&*pool_c).await;
    });

    let _ps = b
        .publish_stream("super-secret-svc", Arc::new(EchoStream))
        .unwrap();
    let _pd = b
        .publish_datagram("super-secret-dg", DATAGRAM_MTU, Arc::new(EchoDatagram))
        .unwrap();

    let hops = vec![
        HopSpec {
            peer: h1.public_key(),
            target: "to-relay".into(),
        },
        HopSpec {
            peer: r.public_key(),
            target: "relay/bob-slot".into(),
        },
    ];
    routes.set(
        b.public_key(),
        "super-secret-svc",
        Plane::Stream,
        ExplicitPath {
            id: 100,
            first_channel: CARRIER.into(),
            first_locator: b"h1".to_vec(),
            min_mtu: 64,
            hops: hops.clone(),
        },
    );
    routes.set(
        b.public_key(),
        "super-secret-dg",
        Plane::Datagram,
        ExplicitPath {
            id: 101,
            first_channel: CARRIER.into(),
            first_locator: b"h1".to_vec(),
            min_mtu: DATAGRAM_MTU,
            hops,
        },
    );

    // Run 3 sequential streams through pool_size=2 (proving auto-replenishment!).
    for idx in 0..3u8 {
        let st = timeout(WAIT, a.dial_stream(b.public_key(), "super-secret-svc"))
            .await
            .unwrap()
            .unwrap();
        let msg = format!("TOP_SECRET_STREAM_PAYLOAD_{idx}");
        st.write_all(msg.as_bytes()).await.unwrap();
        st.shutdown().await.unwrap();
        let mut out = vec![0u8; 64];
        let n = timeout(WAIT, st.read(&mut out)).await.unwrap().unwrap();
        assert_eq!(&out[..n], msg.as_bytes());
        sleep(Duration::from_millis(20)).await;
    }

    // Run 30 datagrams and verify Authorizer is NEVER called per data packet!
    let dg = timeout(
        WAIT,
        a.dial_datagram(b.public_key(), "super-secret-dg", DATAGRAM_MTU),
    )
    .await
    .unwrap()
    .unwrap();
    sleep(Duration::from_millis(50)).await;
    let b_evals_before = b_auth.evaluation_count();
    let h1_evals_before = h1_auth.evaluation_count();
    let r_evals_before = r_auth.evaluation_count();

    for i in 0..30u8 {
        let msg = format!("TOP_SECRET_DGRAM_PAYLOAD_{i}");
        dg.send(PacketBuf::from_slice(msg.as_bytes())).unwrap();
        let reply = timeout(WAIT, dg.recv()).await.unwrap().unwrap();
        assert_eq!(reply.as_slice(), msg.as_bytes());
    }
    assert_eq!(b_auth.evaluation_count(), b_evals_before);
    assert_eq!(h1_auth.evaluation_count(), h1_evals_before);
    assert_eq!(r_auth.evaluation_count(), r_evals_before);

    // Proof 1: Relay R made ZERO outbound dials on BOTH planes!
    assert_eq!(r_st.outbound_dial_count(), 0);
    assert_eq!(r_dg.outbound_open_count(), 0);

    // Proof 2: Blind intermediaries — zero plaintext, endpoint name, or E2E cred anywhere on wire!
    let needles: &[&[u8]] = &[
        b"TOP_SECRET_STREAM_PAYLOAD",
        b"TOP_SECRET_DGRAM_PAYLOAD",
        b"super-secret-svc",
        b"super-secret-dg",
        b"bob-only-cred",
        b"relay-tok",
    ];
    for (_, _, raw) in st_hub.all_captured_bytes() {
        for needle in needles {
            assert!(
                !raw.windows(needle.len()).any(|w| w == *needle),
                "leaked {:?} on stream wire",
                std::str::from_utf8(needle)
            );
        }
    }
    for (_, _, raw) in dg_hub.all_captured_packets() {
        for needle in needles {
            assert!(
                !raw.windows(needle.len()).any(|w| w == *needle),
                "leaked {:?} on datagram wire",
                std::str::from_utf8(needle)
            );
        }
    }

    stream_pool.close();
    for t in [t1, t2, t3, t4, t5] {
        t.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_stream_io_adapter_and_testkit_fault_injection() {
    let auth = AuditAuthorizer::allow_all(Duration::from_secs(30));
    let routes = Arc::new(StaticPathSource::default());

    let a = make_scope(auth.clone(), routes.clone());
    let b = make_scope(auth, routes.clone());

    let st_hub = MemStreamHub::new(4096, 8192);
    let dg_hub = MemDatagramHub::new(1500);

    let a_st = st_hub.bind(b"a");
    let b_st = st_hub.bind(b"b");
    let a_dg = dg_hub.bind(b"a");
    let b_dg = dg_hub.bind(b"b");

    a.register_stream_carrier(CARRIER, a_st).unwrap();
    a.register_datagram_carrier(CARRIER, a_dg).unwrap();
    let b_c1 = b.clone();
    let b_c2 = b.clone();
    let t1 = tokio::spawn(async move {
        let _ = b_c1.serve_stream_listener(&*b_st).await;
    });
    let t2 = tokio::spawn(async move {
        let _ = b_c2.serve_datagram_listener(&*b_dg).await;
    });

    let _ps = b.publish_stream("io", Arc::new(EchoStream)).unwrap();
    let _pd = b
        .publish_datagram("dg", DATAGRAM_MTU, Arc::new(EchoDatagram))
        .unwrap();

    routes.set(
        b.public_key(),
        "io",
        Plane::Stream,
        ExplicitPath {
            id: 1,
            first_channel: CARRIER.into(),
            first_locator: b"b".to_vec(),
            min_mtu: 64,
            hops: vec![],
        },
    );
    routes.set(
        b.public_key(),
        "dg",
        Plane::Datagram,
        ExplicitPath {
            id: 2,
            first_channel: CARRIER.into(),
            first_locator: b"b".to_vec(),
            min_mtu: DATAGRAM_MTU,
            hops: vec![],
        },
    );

    // 1. E2eStreamIo clean AsyncRead/AsyncWrite roundtrip & authenticated EOF.
    let raw = a.dial_stream(b.public_key(), "io").await.unwrap();
    let mut io = E2eStreamIo::new(raw);
    io.write_all(b"via-tokio-async-io").await.unwrap();
    io.shutdown().await.unwrap();
    let mut reply = Vec::new();
    timeout(WAIT, io.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, b"via-tokio-async-io");

    // 2. E2eStreamIo surfaces UnexpectedEof when carrier link is abruptly cut!
    let raw2 = a.dial_stream(b.public_key(), "io").await.unwrap();
    let mut io2 = E2eStreamIo::new(raw2);
    st_hub.cut_active_links(b"a", b"b");
    let mut buf = [0u8; 16];
    let err = timeout(WAIT, io2.read(&mut buf))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);

    // 3. MemDatagramHub deterministic adjacent-packet reordering!
    let dg = a
        .dial_datagram(b.public_key(), "dg", DATAGRAM_MTU)
        .await
        .unwrap();
    sleep(Duration::from_millis(50)).await;
    dg_hub.set_reorder_adjacent(b"a", b"b", true);
    dg.send(PacketBuf::from_slice(b"pkt-1")).unwrap();
    dg.send(PacketBuf::from_slice(b"pkt-2")).unwrap();
    let r1 = timeout(WAIT, dg.recv()).await.unwrap().unwrap();
    let r2 = timeout(WAIT, dg.recv()).await.unwrap().unwrap();
    assert_eq!(r1.as_slice(), b"pkt-2");
    assert_eq!(r2.as_slice(), b"pkt-1");

    t1.abort();
    t2.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mounted_scopes_share_an_outbound_datagram_link_after_adoption() {
    let routes = Arc::new(StaticPathSource::default());
    let auth = AuditAuthorizer::allow_all(Duration::from_secs(30));
    let first = make_scope(auth.clone(), routes.clone());
    let second = make_scope(auth.clone(), routes.clone());
    let remote = make_scope(auth, routes.clone());
    let node = Node::new(Arc::new(TokioSpawner));

    let hub = MemDatagramHub::new(1500);
    let local_carrier = hub.bind(b"local");
    let remote_carrier = hub.bind(b"remote");
    first
        .register_datagram_carrier(CARRIER, local_carrier.clone())
        .unwrap();
    second
        .register_datagram_carrier(CARRIER, local_carrier)
        .unwrap();
    let _publication = remote
        .publish_datagram("echo", DATAGRAM_MTU, Arc::new(EchoDatagram))
        .unwrap();
    routes.set(
        remote.public_key(),
        "echo",
        Plane::Datagram,
        ExplicitPath {
            id: 1,
            first_channel: CARRIER.into(),
            first_locator: b"remote".to_vec(),
            min_mtu: DATAGRAM_MTU,
            hops: Vec::new(),
        },
    );
    let remote_scope = remote.clone();
    let _server =
        tokio::spawn(async move { remote_scope.serve_datagram_listener(&*remote_carrier).await });

    let first_flow = first
        .dial_datagram(remote.public_key(), "echo", DATAGRAM_MTU)
        .await
        .unwrap();
    node.add_scope(first.clone()).unwrap();
    node.add_scope(second.clone()).unwrap();
    let second_flow = second
        .dial_datagram(remote.public_key(), "echo", DATAGRAM_MTU)
        .await
        .unwrap();
    for (flow, bytes) in [
        (&first_flow, b"first".as_slice()),
        (&second_flow, b"second".as_slice()),
    ] {
        flow.send(PacketBuf::from_slice(bytes)).unwrap();
        assert_eq!(
            timeout(WAIT, flow.recv())
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            bytes
        );
    }
}

#[tokio::test]
async fn mounted_scope_attachment_only_accepts_its_scope() {
    let routes = Arc::new(StaticPathSource::default());
    let auth = AuditAuthorizer::allow_all(Duration::from_secs(30));
    let origin = make_scope(auth.clone(), routes.clone());
    let allowed = make_scope(auth.clone(), routes.clone());
    let sibling = make_scope(auth, routes.clone());
    let node = Node::new(Arc::new(TokioSpawner));
    node.add_scope(allowed.clone()).unwrap();
    node.add_scope(sibling.clone()).unwrap();

    let hub = MemDatagramHub::new(1500);
    let origin_carrier = hub.bind(b"origin");
    let destination_carrier = hub.bind(b"destination");
    let _link = origin_carrier.open_link(b"destination").await.unwrap();
    let inbound = confluence_core::DatagramListener::accept_link(&*destination_carrier)
        .await
        .unwrap();
    let _ingress = allowed.attach_datagram(inbound.clone()).unwrap();
    origin
        .register_datagram_carrier(CARRIER, origin_carrier)
        .unwrap();

    let mut publications = Vec::new();
    for (id, scope) in [(1, &allowed), (2, &sibling)] {
        publications.push(
            scope
                .publish_datagram("echo", DATAGRAM_MTU, Arc::new(EchoDatagram))
                .unwrap(),
        );
        routes.set(
            scope.public_key(),
            "echo",
            Plane::Datagram,
            ExplicitPath {
                id,
                first_channel: CARRIER.into(),
                first_locator: b"destination".to_vec(),
                min_mtu: DATAGRAM_MTU,
                hops: Vec::new(),
            },
        );
    }

    let allowed_flow = origin
        .dial_datagram(allowed.public_key(), "echo", DATAGRAM_MTU)
        .await
        .unwrap();
    assert!(
        timeout(
            Duration::from_millis(150),
            origin.dial_datagram(sibling.public_key(), "echo", DATAGRAM_MTU)
        )
        .await
        .is_err()
    );

    let _node_ingress = node.attach_datagram(inbound).unwrap();
    let sibling_flow = origin
        .dial_datagram(sibling.public_key(), "echo", DATAGRAM_MTU)
        .await
        .unwrap();
    for flow in [&allowed_flow, &sibling_flow] {
        flow.send(PacketBuf::from_slice(b"echo")).unwrap();
        assert_eq!(
            timeout(WAIT, flow.recv())
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            b"echo"
        );
    }
}

#[tokio::test]
async fn stream_io_shutdown_then_drop_forwards_buffered_data_and_fin() {
    struct CaptureStream(tokio::sync::mpsc::UnboundedSender<MemStream>);
    impl StreamEndpointHandler for CaptureStream {
        type Stream = MemStream;

        async fn open(&self, _auth: SessionAuth) -> Result<MemStream, CoreErr> {
            let (server, app) = mem_stream_pair(4096, 8192);
            self.0.send(app).map_err(|_| CoreErr::Closed)?;
            Ok(server)
        }
    }

    let routes = Arc::new(StaticPathSource::default());
    let auth = AuditAuthorizer::allow_all(Duration::from_secs(30));
    let origin = make_scope(auth.clone(), routes.clone());
    let remote = make_scope(auth, routes.clone());
    let hub = MemStreamHub::new(4096, 8192);
    let listener = hub.bind(b"remote");
    origin
        .register_stream_carrier(CARRIER, hub.bind(b"origin"))
        .unwrap();
    routes.set(
        remote.public_key(),
        "sink",
        Plane::Stream,
        ExplicitPath {
            id: 1,
            first_channel: CARRIER.into(),
            first_locator: b"remote".to_vec(),
            min_mtu: 64,
            hops: Vec::new(),
        },
    );
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    let _publication = remote
        .publish_stream("sink", Arc::new(CaptureStream(send)))
        .unwrap();
    let remote_scope = remote.clone();
    let _server = tokio::spawn(async move { remote_scope.serve_stream_listener(&*listener).await });

    let stream = origin
        .dial_stream(remote.public_key(), "sink")
        .await
        .unwrap();
    let (mut backend, _writer) = timeout(WAIT, receive.recv())
        .await
        .unwrap()
        .unwrap()
        .split();
    let mut io = E2eStreamIo::new(stream);
    io.write_all(b"flush").await.unwrap();
    io.flush().await.unwrap();
    let mut buf = [0; 5];
    timeout(WAIT, backend.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"flush");

    io.write_all(b"final").await.unwrap();
    io.shutdown().await.unwrap();
    drop(io);
    timeout(WAIT, backend.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"final");
    assert_eq!(
        timeout(WAIT, backend.read(&mut buf))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn passive_stream_pool_rotates_idle_connections_and_retries_refill() {
    let routes = Arc::new(StaticPathSource::default());
    let auth = AuditAuthorizer::allow_all(Duration::from_secs(30));
    let relay = make_scope(auth.clone(), routes.clone());
    let registrant = make_scope(auth, routes);
    let ttl = Duration::from_millis(500);
    let registrations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counts = registrations.clone();
    let verifier = Arc::new(FnRegistrationVerifier(
        move |_: confluence_relay::RelayRegistrationRequest<'_>| {
            counts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(RegistrationLease::new(ttl))
        },
    ));
    let service = RelayService::new(&relay, "relay/", verifier, 4096, 1500).unwrap();
    let hub = MemStreamHub::new(4096, 8192);
    let client = hub.bind(b"client");
    let listener = service.wrap_stream_listener(hub.bind(b"relay"));
    let _server = tokio::spawn(async move { relay.serve_stream_listener(&listener).await });
    let pool = PassiveStreamPool::start(
        client,
        registrant.identity(),
        b"relay".to_vec(),
        service.public_key(),
        "peer",
        vec![],
        1,
    )
    .await
    .unwrap();

    let dial_relay = || {
        confluence_core::StreamTransitHandler::open(
            &service,
            "peer",
            SessionAuth::new(registrant.public_key()),
        )
    };

    // The first lease expires while the pool is idle.
    sleep(ttl + Duration::from_millis(50)).await;
    let stream = timeout(WAIT, dial_relay()).await.unwrap().unwrap();
    let active = timeout(WAIT, confluence_core::StreamListener::accept(&*pool))
        .await
        .unwrap()
        .unwrap();
    drop((stream, active));

    // Cut the parked connection and make the first refill attempts fail.
    hub.set_link_down(b"client", b"relay", true);
    hub.cut_active_links(b"client", b"relay");
    let before = registrations.load(std::sync::atomic::Ordering::Relaxed);
    sleep(Duration::from_millis(125)).await;
    hub.set_link_down(b"client", b"relay", false);
    timeout(WAIT, async {
        while registrations.load(std::sync::atomic::Ordering::Relaxed) <= before
            || service.relay().parked_stream_count(b"peer") == 0
        {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let stream = timeout(WAIT, dial_relay()).await.unwrap().unwrap();
    let active = timeout(WAIT, confluence_core::StreamListener::accept(&*pool))
        .await
        .unwrap()
        .unwrap();
    drop((stream, active));
    pool.shutdown().await;
}
