use async_trait::async_trait;
use confluence_core::seams::access::{
    AccessControl, AccessRequest, Action, Decision, Grant, IntersectAccessControl, RevocationEvent,
};
use confluence_core::security::cookie::{
    seal_handshake_envelope, unseal_cookie_challenge, CookieProtector, EnvelopeCheck,
};
use confluence_core::security::grant::{GrantEnforcedStream, GrantEnforcer};
use confluence_core::security::noise::{
    split_stream_ciphers, DatagramSessionCipher, InitiatorHandshake, VerifiedInitiation,
    DATAGRAM_WIRE_OVERHEAD_BYTES, DEFAULT_PROLOGUE,
};
use confluence_core::security::replay::{
    ReplayWindow64, Tai64nGenerator, Tai64nReplayWindow, Tai64nTimestamp,
};
use confluence_core::{
    CoreError, EndpointName, OpaqueCredential, Plane, Result, ScopeId, StaticKeypair,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::sync::broadcast;

#[test]
fn noise_ik_mutual_auth_and_session_ciphers_roundtrip() {
    let alice = StaticKeypair::generate();
    let bob = StaticKeypair::generate();
    let eve = StaticKeypair::generate();

    let init_payload = b"hello-bob-endpoint";
    let (init_state, msg1) =
        InitiatorHandshake::initiate(&alice, bob.peer_id(), DEFAULT_PROLOGUE, init_payload)
            .expect("initiate should succeed");

    // Wrong static key (Eve) cannot read Alice's msg1.
    assert!(matches!(
        VerifiedInitiation::read_msg1(&eve, DEFAULT_PROLOGUE, &msg1),
        Err(CoreError::AuthFailed)
    ));

    // Tampered msg1 fails authentication.
    let mut tampered = msg1.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(matches!(
        VerifiedInitiation::read_msg1(&bob, DEFAULT_PROLOGUE, &tampered),
        Err(CoreError::AuthFailed)
    ));

    // Bob verifies Alice's static PeerId and payload.
    let verified = VerifiedInitiation::read_msg1(&bob, DEFAULT_PROLOGUE, &msg1)
        .expect("bob should verify alice");
    assert_eq!(verified.initiator_peer(), alice.peer_id());
    assert_eq!(verified.payload(), init_payload);

    let (bob_keys, msg2) = verified
        .respond(b"welcome-alice")
        .expect("bob should respond");
    let (alice_keys, resp_payload) = init_state.finalize(&msg2).expect("alice should finalize");
    assert_eq!(resp_payload, b"welcome-alice");
    assert_eq!(alice_keys.handshake_hash, bob_keys.handshake_hash);
    assert_eq!(alice_keys.tx_key, bob_keys.rx_key);
    assert_eq!(alice_keys.rx_key, bob_keys.tx_key);

    // Verify stream ciphers first using cloned/split keys, then datagram ciphers.
    let (mut a_write, mut a_read) = split_stream_ciphers(&alice_keys);
    let (mut b_write, mut b_read) = split_stream_ciphers(&bob_keys);

    let rec1 = a_write.seal_record(0x01, b"stream-chunk-1").unwrap();
    let len1 = u16::from_be_bytes([rec1[0], rec1[1]]) as usize;
    assert_eq!(len1 + 2, rec1.len());
    let (ty1, pt1) = b_read.open_record(&rec1[2..]).unwrap();
    assert_eq!(ty1, 0x01);
    assert_eq!(pt1, b"stream-chunk-1");

    let rec2 = b_write.seal_record(0x01, b"stream-reply-1").unwrap();
    let (ty2, pt2) = a_read.open_record(&rec2[2..]).unwrap();
    assert_eq!(ty2, 0x01);
    assert_eq!(pt2, b"stream-reply-1");

    // Verify constant 29-byte overhead & anti-replay on DatagramSessionCipher.
    let a_dgram = DatagramSessionCipher::new(alice_keys);
    let b_dgram = DatagramSessionCipher::new(bob_keys);

    let pkt0 = a_dgram.seal_packet(42, 0x01, b"ping-0").unwrap();
    assert_eq!(pkt0.len(), DATAGRAM_WIRE_OVERHEAD_BYTES + b"ping-0".len());
    assert_eq!(u32::from_be_bytes([pkt0[0], pkt0[1], pkt0[2], pkt0[3]]), 42);

    let pkt1 = a_dgram.seal_packet(42, 0x01, b"ping-1").unwrap();

    // Out-of-order delivery: pkt1 arrives before pkt0 -> both accepted!
    let (_, d1) = b_dgram.open_packet(&pkt1[4..]).unwrap();
    assert_eq!(d1, b"ping-1");
    let (_, d0) = b_dgram.open_packet(&pkt0[4..]).unwrap();
    assert_eq!(d0, b"ping-0");

    // Replay of pkt1 is rejected!
    assert!(matches!(
        b_dgram.open_packet(&pkt1[4..]),
        Err(CoreError::ReplayDetected)
    ));

    // Forged high-nonce packet must fail AuthFailed WITHOUT poisoning the replay window!
    let mut forged = pkt1.clone();
    forged[4..12].copy_from_slice(&999_999u64.to_be_bytes());
    assert!(matches!(
        b_dgram.open_packet(&forged[4..]),
        Err(CoreError::AuthFailed)
    ));
    let pkt2 = a_dgram.seal_packet(42, 0x01, b"ping-2").unwrap();
    let (_, d2) = b_dgram.open_packet(&pkt2[4..]).unwrap();
    assert_eq!(d2, b"ping-2");
}

#[test]
fn tai64n_replay_window_and_sliding_window64() {
    let gen = Tai64nGenerator::new();
    let t1 = gen.next();
    let t2 = gen.next();
    let t3 = gen.next();
    assert!(t1 < t2 && t2 < t3);

    let peer_a = StaticKeypair::generate().peer_id();
    let peer_b = StaticKeypair::generate().peer_id();
    let window = Tai64nReplayWindow::new(Duration::from_secs(60), 2, 4);

    let base_tai = 0x4000_0000_0000_1000u64;
    let ts_a1 = Tai64nTimestamp::from_parts(base_tai, 100);
    let ts_a2 = Tai64nTimestamp::from_parts(base_tai, 200);
    let ts_stale = Tai64nTimestamp::from_parts(base_tai - 120, 0);

    // Slight out-of-order (ts_a2 before ts_a1) succeeds for distinct timestamps.
    window.check_and_record_at(&peer_a, ts_a2, base_tai).unwrap();
    window.check_and_record_at(&peer_a, ts_a1, base_tai).unwrap();

    // Exact replay is rejected.
    assert!(matches!(
        window.check_and_record_at(&peer_a, ts_a2, base_tai),
        Err(CoreError::ReplayDetected)
    ));

    // Clock-skew outside +-60s is rejected.
    assert!(matches!(
        window.check_and_record_at(&peer_b, ts_stale, base_tai),
        Err(CoreError::ReplayDetected)
    ));

    // ReplayWindow64 boundary check (>64 jump evicts old sequence numbers).
    let mut rw = ReplayWindow64::new();
    assert!(rw.accept(0));
    assert!(!rw.accept(0));
    assert!(rw.accept(100));
    assert!(!rw.accept(36)); // 100 - 36 == 64 -> outside 64-bit window
    assert!(rw.accept(37));  // 100 - 37 == 63 -> inside window
    assert!(!rw.accept(37)); // duplicate rejected
}

#[test]
fn stateless_mac1_and_mac2_cookie_flood_challenge() {
    let responder = StaticKeypair::generate();
    let protector = CookieProtector::new(responder.peer_id(), Duration::from_secs(120));
    let source_addr = b"198.51.100.7:54321";
    let dummy_msg1 = vec![0xAB; 112];

    // 1. Corrupted / wrong-key MAC1 is silently dropped even when not under load.
    let wrong_key = StaticKeypair::generate();
    let (bad_env, _) = seal_handshake_envelope(&wrong_key.peer_id(), &dummy_msg1, None).unwrap();
    assert!(matches!(
        protector.verify_envelope(source_addr, &bad_env),
        EnvelopeCheck::Drop
    ));

    // 2. Valid MAC1 without cookie succeeds in 0-RTT when not under load.
    let (env_no_cookie, sent_mac1) =
        seal_handshake_envelope(&responder.peer_id(), &dummy_msg1, None).unwrap();
    match protector.verify_envelope(source_addr, &env_no_cookie) {
        EnvelopeCheck::Verified(inner) => assert_eq!(inner, dummy_msg1.as_slice()),
        _ => panic!("expected 0-RTT Verified when not under load"),
    }

    // 3. Under flood: missing MAC2 triggers stateless encrypted CookieChallenge (zero DH!).
    protector.set_under_load(true);
    let challenge = match protector.verify_envelope(source_addr, &env_no_cookie) {
        EnvelopeCheck::Challenge(ch) => ch,
        _ => panic!("expected Challenge when under load without cookie"),
    };

    // 4. Initiator unseals cookie (AAD-bound to sent_mac1) and retries cleanly.
    let cookie = unseal_cookie_challenge(&responder.peer_id(), &sent_mac1, &challenge)
        .expect("should unseal valid cookie challenge");
    let (env_with_cookie, _) =
        seal_handshake_envelope(&responder.peer_id(), &dummy_msg1, Some(&cookie)).unwrap();

    // Spoofed source address cannot reuse another address's cookie!
    assert!(matches!(
        protector.verify_envelope(b"203.0.113.9:9999", &env_with_cookie),
        EnvelopeCheck::Challenge(_)
    ));

    // Legitimate source address passes MAC2 verification!
    match protector.verify_envelope(source_addr, &env_with_cookie) {
        EnvelopeCheck::Verified(inner) => assert_eq!(inner, dummy_msg1.as_slice()),
        _ => panic!("expected Verified with valid MAC2 cookie"),
    }
}

struct MockPolicy {
    decision: Decision,
    fail: bool,
    delay: Duration,
    rev_tx: broadcast::Sender<RevocationEvent>,
}

impl MockPolicy {
    fn new(decision: Decision) -> (Arc<Self>, broadcast::Sender<RevocationEvent>) {
        let (tx, _) = broadcast::channel(16);
        (
            Arc::new(Self {
                decision,
                fail: false,
                delay: Duration::ZERO,
                rev_tx: tx.clone(),
            }),
            tx,
        )
    }
}

#[async_trait]
impl AccessControl for MockPolicy {
    async fn evaluate(&self, _req: AccessRequest) -> Result<Decision> {
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        if self.fail {
            return Err(CoreError::PolicyError("backend unavailable".into()));
        }
        Ok(self.decision.clone())
    }

    fn revocations(&self) -> broadcast::Receiver<RevocationEvent> {
        self.rev_tx.subscribe()
    }
}

#[tokio::test]
async fn local_policy_veto_intersection_and_fail_closed() {
    let scope = ScopeId::new("research-lab").unwrap();
    let peer = StaticKeypair::generate().peer_id();
    let endpoint = EndpointName::new("jupyter").unwrap();
    let cred = OpaqueCredential::from_utf8("opaque-bearer-xyz").unwrap();

    let req = AccessRequest {
        scope: scope.clone(),
        peer,
        credential: Some(cred),
        action: Action::OpenEndpoint {
            endpoint: endpoint.clone(),
            plane: Plane::Stream,
        },
    };

    // 1. Local Deny vetoes permissive External Allow (Host Sovereignty!).
    let (local_deny, _) = MockPolicy::new(Decision::Deny {
        reason: "blocked by local host owner".into(),
    });
    let (ext_allow, _) = MockPolicy::new(Decision::Allow(Grant::with_ttl(Duration::from_secs(300))));
    let composed_veto =
        IntersectAccessControl::new(local_deny, ext_allow.clone(), Duration::from_millis(200));
    assert!(matches!(
        composed_veto.evaluate(req.clone()).await.unwrap(),
        Decision::Deny { .. }
    ));

    // 2. Both Allow -> strict minimum intersection of expiry, rate bounds, and concurrency.
    let now = Instant::now();
    let g_local = Grant {
        expires_at: now + Duration::from_secs(60),
        max_bytes_per_sec: Some(100_000),
        max_datagrams_per_sec: None,
        max_concurrent_streams: Some(4),
    };
    let g_ext = Grant {
        expires_at: now + Duration::from_secs(300),
        max_bytes_per_sec: Some(500_000),
        max_datagrams_per_sec: Some(50),
        max_concurrent_streams: Some(2),
    };
    let (p_local, rev_local_tx) = MockPolicy::new(Decision::Allow(g_local));
    let (p_ext, _) = MockPolicy::new(Decision::Allow(g_ext));
    let composed_ok = IntersectAccessControl::new(p_local, p_ext, Duration::from_millis(200));

    let grant = match composed_ok.evaluate(req.clone()).await.unwrap() {
        Decision::Allow(g) => g,
        Decision::Deny { reason } => panic!("unexpected deny: {reason}"),
    };
    assert_eq!(grant.expires_at, g_local.expires_at);
    assert_eq!(grant.max_bytes_per_sec, Some(100_000));
    assert_eq!(grant.max_datagrams_per_sec, Some(50));
    assert_eq!(grant.max_concurrent_streams, Some(2));

    // 3. Revocation broadcast propagates through IntersectAccessControl into GrantEnforcer.
    let enforcer = GrantEnforcer::new(grant);
    enforcer.spawn_revocation_watcher(
        composed_ok.revocations(),
        scope.clone(),
        peer,
        Some(endpoint.clone()),
    );
    rev_local_tx
        .send(RevocationEvent {
            scope: Some(scope),
            peer: Some(peer),
            endpoint: Some(endpoint),
        })
        .unwrap();

    tokio::time::timeout(Duration::from_secs(1), async {
        let mut watch = enforcer.closed_watch();
        watch.wait_for(|&closed| closed).await.unwrap();
    })
    .await
    .expect("revocation must propagate promptly");
    assert!(matches!(
        enforcer.check_liveness(Instant::now()),
        Err(CoreError::GrantRevoked)
    ));

    // 4. Hung external policy fails closed on timeout.
    let (tx_dummy, _) = broadcast::channel(4);
    let hung_ext = Arc::new(MockPolicy {
        decision: Decision::Allow(Grant::with_ttl(Duration::from_secs(60))),
        fail: false,
        delay: Duration::from_secs(5),
        rev_tx: tx_dummy,
    });
    let (local_ok, _) = MockPolicy::new(Decision::Allow(Grant::with_ttl(Duration::from_secs(60))));
    let composed_timeout =
        IntersectAccessControl::new(local_ok, hung_ext, Duration::from_millis(30));
    assert!(matches!(
        composed_timeout.evaluate(req).await,
        Err(CoreError::PolicyError(_))
    ));
}

#[tokio::test]
async fn grant_enforcer_rate_concurrency_renewal_and_idle_stream_revocation() {
    let initial = Grant {
        expires_at: Instant::now() + Duration::from_millis(80),
        max_bytes_per_sec: Some(1_024),
        max_datagrams_per_sec: Some(2),
        max_concurrent_streams: Some(1),
    };
    let enforcer = GrantEnforcer::new(initial);

    // Datagram rate limit: 2 datagrams allowed in initial burst, 3rd rejected immediately.
    enforcer.check_and_record_datagram(100).unwrap();
    enforcer.check_and_record_datagram(100).unwrap();
    assert!(matches!(
        enforcer.check_and_record_datagram(100),
        Err(CoreError::RateLimitExceeded)
    ));

    // Concurrency limit: max 1 active stream permit; 2nd rejected until 1st drops.
    let p1 = enforcer.try_acquire_stream().unwrap();
    assert!(matches!(
        enforcer.try_acquire_stream(),
        Err(CoreError::ConcurrencyLimitExceeded)
    ));
    drop(p1);
    let p2 = enforcer.try_acquire_stream().unwrap();

    // Expiry check + atomic in-place renewal restores liveness!
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(matches!(
        enforcer.check_liveness(Instant::now()),
        Err(CoreError::GrantExpired)
    ));
    enforcer.update_grant(Grant {
        expires_at: Instant::now() + Duration::from_secs(10),
        max_bytes_per_sec: Some(65_536),
        max_datagrams_per_sec: Some(100),
        max_concurrent_streams: Some(2),
    });
    enforcer.check_liveness(Instant::now()).unwrap();

    // Idle GrantEnforcedStream wakes and terminates immediately when revoked!
    let (client_io, _server_io) = tokio::io::duplex(4096);
    let mut guarded = GrantEnforcedStream::new(client_io, Arc::clone(&enforcer), Some(p2));
    let enforcer_killer = Arc::clone(&enforcer);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(25)).await;
        enforcer_killer.revoke();
    });

    let mut buf = [0u8; 64];
    let read_res = tokio::time::timeout(Duration::from_secs(1), guarded.read(&mut buf))
        .await
        .expect("idle stream read must wake immediately on revoke");
    assert!(read_res.is_err());
    assert_eq!(read_res.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
}
