//! End-to-end deterministic Trust, Authorization, Revocation, Multi-Scope `Node`, and
//! pure outer-crate public API conformance suite (Spec §§7, 8, 10.4).
//!
//! Zero OS sockets, zero wall-clock sleeps, zero internal/private imports.

#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::task::{Context, Poll};
use core::time::Duration;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use confluence_core::auth::{
    AuthDenied, AuthRequest, Authorizer, DatagramAction, IntersectAuthorizer, Lease, Revocation,
    RevocationReceiver, RevocationSender, SessionAuth, StreamAction, TrafficGate,
    revocation_channel,
};
use confluence_core::channel::{
    BoxedStream, ChannelCaps, DatagramCarrier, DatagramLink, DatagramLinkExt, DatagramListener,
    IntoStreamHalves, StreamReadExt, StreamWriteExt,
};
use confluence_core::constants::DG_OVERHEAD;
use confluence_core::handler::{
    DatagramEndpointHandler, DatagramTransitHandler, StaticTransit, StreamEndpointHandler,
    StreamTransitHandler,
};
use confluence_core::path::{ExplicitPath, HopSpec};
use confluence_core::runtime::BoxFuture;
use confluence_core::testing::{
    MemoryDatagramLink, MemoryDatagramPair, MemoryStreamPair, TestRuntime, memory_stream_channel,
};
use confluence_core::{
    CoreError, LinkId, Node, NodeLimits, PacketBuf, PublicKey, ScopeInstance, ScopeKeypair,
};

// ---------------------------------------------------------------------------
// Shared Helpers
// ---------------------------------------------------------------------------

struct AllowAll(Duration);

impl Authorizer for AllowAll {
    fn authorize<'a>(&'a self, _req: AuthRequest<'a>) -> BoxFuture<'a, Result<Lease, AuthDenied>> {
        let ttl = self.0;
        Box::pin(async move { Ok(Lease::new(ttl)) })
    }
}

#[derive(Clone)]
struct SharedDgCarrier(Arc<MemoryDatagramLink>);

impl DatagramCarrier for SharedDgCarrier {
    type Link = Arc<MemoryDatagramLink>;

    fn caps(&self) -> ChannelCaps {
        self.0.caps()
    }

    async fn open_link(&self, _locator: &[u8]) -> Result<Self::Link, CoreError> {
        Ok(Arc::clone(&self.0))
    }
}

struct SingleDgListener(async_channel::Receiver<Arc<MemoryDatagramLink>>);

impl DatagramListener for SingleDgListener {
    type Link = Arc<MemoryDatagramLink>;

    async fn accept_link(&self) -> Result<Self::Link, CoreError> {
        self.0.recv().await.map_err(|_| CoreError::Closed)
    }
}

fn dg_pair_channel(
    mtu: u16,
) -> (
    SharedDgCarrier,
    SingleDgListener,
    Arc<MemoryDatagramLink>,
    Arc<MemoryDatagramLink>,
    confluence_core::testing::DatagramFaults,
    confluence_core::testing::DatagramFaults,
) {
    let pair = MemoryDatagramPair::with_source_tags(mtu, [0x33; 16], [0x44; 16]);
    let (tx, rx) = async_channel::bounded(1);
    let _ = tx.try_send(Arc::clone(&pair.b));
    (
        SharedDgCarrier(Arc::clone(&pair.a)),
        SingleDgListener(rx),
        pair.a,
        pair.b,
        pair.a_faults,
        pair.b_faults,
    )
}

struct StreamEcho {
    rt: TestRuntime,
}

impl StreamEndpointHandler for StreamEcho {
    fn open(&self, _auth: SessionAuth) -> BoxFuture<'_, Result<BoxedStream, CoreError>> {
        let spawner = Arc::clone(&self.rt.runtime.spawner);
        Box::pin(async move {
            let pair = MemoryStreamPair::pair(16_384);
            let (mut r, mut w) = pair.b.into_halves();
            spawner.spawn(Box::pin(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = r.read(&mut buf).await {
                    if n == 0 {
                        let _ = w.shutdown().await;
                        break;
                    }
                    if w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }));
            Ok(BoxedStream::from_stream(pair.a))
        })
    }
}

struct DatagramEcho {
    rt: TestRuntime,
}

impl DatagramEndpointHandler for DatagramEcho {
    fn open(&self, _auth: SessionAuth) -> BoxFuture<'_, Result<Arc<dyn DatagramLink>, CoreError>> {
        let spawner = Arc::clone(&self.rt.runtime.spawner);
        Box::pin(async move {
            let pair = MemoryDatagramPair::pair(65_535);
            let b = pair.b;
            spawner.spawn(Box::pin(async move {
                while let Ok(pkt) = b.recv().await {
                    if b.send(pkt).await.is_err() {
                        break;
                    }
                }
            }));
            Ok(pair.a as Arc<dyn DatagramLink>)
        })
    }
}

fn static_st_transit<C: confluence_core::channel::StreamCarrier>(
    c: C,
    loc: Vec<u8>,
) -> Arc<dyn StreamTransitHandler> {
    Arc::new(StaticTransit::new(Arc::new(c), loc))
}

fn static_dg_transit<C: DatagramCarrier>(
    c: C,
    loc: Vec<u8>,
) -> Arc<dyn DatagramTransitHandler> {
    Arc::new(StaticTransit::new(Arc::new(c), loc))
}

// ---------------------------------------------------------------------------
// 1. IntersectAuthorizer End-to-End: Local Veto First, TTL Intersection, TrafficGate
//    Strictly on DATA (Immune to Control), SessionGuard Preservation & Live AuthExtensions
// ---------------------------------------------------------------------------

#[test]
fn intersect_authorizer_end_to_end_veto_ttl_gate_guards_and_live_claims() {
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct RoleClaim(&'static str);
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ExtOnlyClaim(&'static str);

    struct DropTrack(Arc<AtomicUsize>);
    impl Drop for DropTrack {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// TrafficGate that drops Datagram DATA when `drop_dg` is set and delays Stream DATA by 50 ms.
    struct SelectiveGate {
        drop_dg: Arc<AtomicBool>,
        delay_stream: Arc<AtomicBool>,
    }
    impl TrafficGate for SelectiveGate {
        fn check_datagram(&self, _dir: confluence_core::Direction, _bytes: usize) -> DatagramAction {
            if self.drop_dg.load(Ordering::Acquire) {
                DatagramAction::Drop
            } else {
                DatagramAction::Allow
            }
        }
        fn charge_stream(&self, _dir: confluence_core::Direction, _bytes: usize) -> StreamAction {
            if self.delay_stream.load(Ordering::Acquire) {
                StreamAction::Delay(Duration::from_millis(50))
            } else {
                StreamAction::Allow
            }
        }
    }

    struct LocalAuth {
        deny: AtomicBool,
        guards_dropped: Arc<AtomicUsize>,
        drop_dg: Arc<AtomicBool>,
        delay_stream: Arc<AtomicBool>,
    }
    impl Authorizer for LocalAuth {
        fn authorize<'a>(&'a self, req: AuthRequest<'a>) -> BoxFuture<'a, Result<Lease, AuthDenied>> {
            if self.deny.load(Ordering::Acquire) {
                return Box::pin(async { Err(AuthDenied::Denied) });
            }
            let claim = if req.is_renewal {
                RoleClaim("local-renewed")
            } else {
                RoleClaim("local-initial")
            };
            let guard = DropTrack(Arc::clone(&self.guards_dropped));
            let gate = Arc::new(SelectiveGate {
                drop_dg: Arc::clone(&self.drop_dg),
                delay_stream: Arc::clone(&self.delay_stream),
            });
            Box::pin(async move {
                Ok(Lease::new(Duration::from_secs(10))
                    .with_gate(gate)
                    .with_guard(guard)
                    .with_context(claim))
            })
        }
    }

    struct ExternalAuth {
        calls: AtomicUsize,
        guards_dropped: Arc<AtomicUsize>,
    }
    impl Authorizer for ExternalAuth {
        fn authorize<'a>(&'a self, req: AuthRequest<'a>) -> BoxFuture<'a, Result<Lease, AuthDenied>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let ext_claim = if req.is_renewal {
                ExtOnlyClaim("ext-renewed")
            } else {
                ExtOnlyClaim("ext-initial")
            };
            let guard = DropTrack(Arc::clone(&self.guards_dropped));
            Box::pin(async move {
                Ok(Lease::new(Duration::from_secs(30))
                    .with_guard(guard)
                    // Colliding RoleClaim MUST yield to LocalAuth's precedence!
                    .with_context(RoleClaim("external-should-lose"))
                    .with_context(ext_claim))
            })
        }
    }

    let tr = TestRuntime::new();
    let local_drops = Arc::new(AtomicUsize::new(0));
    let ext_drops = Arc::new(AtomicUsize::new(0));
    let drop_dg = Arc::new(AtomicBool::new(false));
    let delay_stream = Arc::new(AtomicBool::new(false));

    let local = Arc::new(LocalAuth {
        deny: AtomicBool::new(true),
        guards_dropped: Arc::clone(&local_drops),
        drop_dg: Arc::clone(&drop_dg),
        delay_stream: Arc::clone(&delay_stream),
    });
    let external = Arc::new(ExternalAuth {
        calls: AtomicUsize::new(0),
        guards_dropped: Arc::clone(&ext_drops),
    });
    let intersected = Arc::new(IntersectAuthorizer::new(local.clone(), external.clone()));

    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(intersected)
        .build();

    let (dg_c, dg_l, _a, _b, _af, _bf) = dg_pair_channel(1_500);
    let (st_c, st_l, _) = memory_stream_channel(4_096);
    origin.register_datagram_carrier("dg", dg_c).unwrap();
    origin.register_stream_carrier("st", st_c).unwrap();

    // Endpoint observing initial AND live-updated SessionAuth claims across renewal!
    let observed_claims = Arc::new(Mutex::new(Vec::<(RoleClaim, ExtOnlyClaim)>::new()));
    struct ClaimObserverDg {
        rt: TestRuntime,
        observed: Arc<Mutex<Vec<(RoleClaim, ExtOnlyClaim)>>>,
    }
    impl DatagramEndpointHandler for ClaimObserverDg {
        fn open(&self, mut auth: SessionAuth) -> BoxFuture<'_, Result<Arc<dyn DatagramLink>, CoreError>> {
            let obs = Arc::clone(&self.observed);
            let spawner = Arc::clone(&self.rt.runtime.spawner);
            Box::pin(async move {
                let c1 = auth.context::<RoleClaim>().unwrap().as_ref().clone();
                let c2 = auth.context::<ExtOnlyClaim>().unwrap().as_ref().clone();
                obs.lock().unwrap().push((c1, c2));

                spawner.spawn(Box::pin(async move {
                    while auth.changed().await {
                        let r = auth.context::<RoleClaim>().unwrap().as_ref().clone();
                        let e = auth.context::<ExtOnlyClaim>().unwrap().as_ref().clone();
                        obs.lock().unwrap().push((r, e));
                    }
                }));

                let pair = MemoryDatagramPair::pair(65_535);
                let b = pair.b;
                spawner.spawn(Box::pin(async move {
                    while let Ok(pkt) = b.recv().await {
                        if b.send(pkt).await.is_err() {
                            break;
                        }
                    }
                }));
                Ok(pair.a as Arc<dyn DatagramLink>)
            })
        }
    }

    let _ep_dg = dest
        .publish_datagram_endpoint(
            "claims",
            1_200,
            Arc::new(ClaimObserverDg {
                rt: tr.clone(),
                observed: Arc::clone(&observed_claims),
            }),
        )
        .unwrap();
    let _ep_st = dest
        .publish_stream_endpoint("echo", Arc::new(StreamEcho { rt: tr.clone() }))
        .unwrap();

    let d1 = Arc::clone(&dest);
    tr.runtime.spawner.spawn(Box::pin(async move {
        let _ = d1.serve_datagram_listener(dg_l).await;
    }));
    let d2 = Arc::clone(&dest);
    tr.runtime.spawner.spawn(Box::pin(async move {
        let _ = d2.serve_stream_listener(st_l).await;
    }));
    tr.drive_until_idle();

    // 1. Local hard veto first: external MUST NOT be called!
    let veto_err = tr
        .spawner
        .try_block_on(origin.dial_datagram_via(
            dest.public_key(),
            "claims",
            1_200,
            ExplicitPath::direct(1, "dg", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(veto_err, CoreError::Denied);
    assert_eq!(external.calls.load(Ordering::SeqCst), 0);

    // 2. Allow both -> establish Datagram circuit!
    local.deny.store(false, Ordering::Release);
    let dg = tr
        .spawner
        .try_block_on(origin.dial_datagram_via(
            dest.public_key(),
            "claims",
            1_200,
            ExplicitPath::direct(2, "dg", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();
    assert_eq!(external.calls.load(Ordering::SeqCst), 1);
    assert_eq!(local_drops.load(Ordering::SeqCst), 0);
    assert_eq!(ext_drops.load(Ordering::SeqCst), 0);

    // Verify initial local-precedence claims!
    {
        let obs = observed_claims.lock().unwrap();
        assert_eq!(
            obs.as_slice(),
            &[(RoleClaim("local-initial"), ExtOnlyClaim("ext-initial"))]
        );
    }

    // 3. Turn ON Datagram TrafficGate::Drop -> DATA packets drop, yet control frames (DG_RENEW)
    //    bypass TrafficGate completely and renew the 10 s intersected lease!
    drop_dg.store(true, Ordering::Release);
    dg.send(PacketBuf::from_payload(b"dropped-by-gate")).unwrap();
    tr.drive_until_idle();
    assert_eq!(dest.stats().traffic_gate_drops_total, 1);

    // Advance 9.5 s (past 70–80% of intersected 10 s TTL, well before external's 30 s!).
    for _ in 0..95 {
        tr.advance_and_drive(Duration::from_millis(100));
    }
    assert!(
        dest.stats().auth_endpoint.renewed >= 1,
        "DG_RENEW control frames MUST bypass TrafficGate::Drop and renew at min(10s, 30s)!"
    );

    // SessionGuards from BOTH initial and renewed leases MUST still be alive!
    assert_eq!(local_drops.load(Ordering::SeqCst), 0);
    assert_eq!(ext_drops.load(Ordering::SeqCst), 0);

    // Live SessionAuth::changed() observed updated local-precedence claims!
    {
        let obs = observed_claims.lock().unwrap();
        assert!(obs.len() >= 2);
        assert_eq!(
            obs[1],
            (RoleClaim("local-renewed"), ExtOnlyClaim("ext-renewed"))
        );
    }

    // Turn off TrafficGate::Drop and prove session is still alive past original 10 s TTL!
    drop_dg.store(false, Ordering::Release);
    tr.advance_and_drive(Duration::from_secs(2));
    let echo_res = tr.spawner.try_block_on(async {
        dg.send(PacketBuf::from_payload(b"post-renew"))?;
        let r = dg.recv().await?;
        assert_eq!(r.payload(), b"post-renew");
        Ok::<(), CoreError>(())
    });
    assert_eq!(echo_res, Some(Ok(())));

    // Dropping the session releases ALL accumulated SessionGuards (initial + renewed)!
    drop(dg);
    tr.drive_until_idle();
    assert!(local_drops.load(Ordering::SeqCst) >= 2);
    assert!(ext_drops.load(Ordering::SeqCst) >= 2);

    // 4. Stream TrafficGate::Delay paces ST_DATA cleanly while allowing renewal!
    delay_stream.store(true, Ordering::Release);
    let mut st = tr
        .spawner
        .try_block_on(origin.dial_stream_via(
            dest.public_key(),
            "echo",
            ExplicitPath::direct(3, "st", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();
    let res = tr.spawner.try_block_on(st.write_all(b"paced"));
    assert_eq!(res, Some(Ok(())));
    // Data is delayed by 50 ms on ingress, then echoed and delayed by 50 ms on egress:
    // advance two 60 ms steps so ingress fires first and schedules egress cleanly!
    tr.advance_and_drive(Duration::from_millis(60));
    tr.advance_and_drive(Duration::from_millis(60));
    let mut out = [0u8; 5];
    assert_eq!(tr.spawner.try_block_on(st.read_exact(&mut out)), Some(Ok(())));
    assert_eq!(&out, b"paced");
}

// ---------------------------------------------------------------------------
// 2. TOCTOU Revocation Epochs, PublishGuard Drop, Scoped TransitRevoker Isolation,
//    Authorizer Revocation::Peer vs Host revoke_peer/unrevoke_peer, Revocation::Endpoint
// ---------------------------------------------------------------------------

#[test]
fn toctou_revocation_epochs_publish_guard_transit_revoker_and_peer_revocation_semantics() {
    /// Authorizer that can pause on a manual gate to deterministically trigger TOCTOU races,
    /// AND emits live revocations over a `RevocationSender`.
    struct ControllableAuth {
        pause: AtomicBool,
        gate_tx: Mutex<Option<async_channel::Sender<()>>>,
        gate_rx: Mutex<Option<async_channel::Receiver<()>>>,
        entered: AtomicUsize,
        rev_tx: RevocationSender,
    }

    impl ControllableAuth {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                pause: AtomicBool::new(false),
                gate_tx: Mutex::new(None),
                gate_rx: Mutex::new(None),
                entered: AtomicUsize::new(0),
                rev_tx: revocation_channel(64).0,
            })
        }

        fn arm_pause(&self) {
            let (tx, rx) = async_channel::bounded(1);
            *self.gate_tx.lock().unwrap() = Some(tx);
            *self.gate_rx.lock().unwrap() = Some(rx);
            self.pause.store(true, Ordering::Release);
        }

        fn release_pause(&self) {
            self.pause.store(false, Ordering::Release);
            if let Some(tx) = self.gate_tx.lock().unwrap().take() {
                let _ = tx.try_send(());
            }
        }
    }

    impl Authorizer for ControllableAuth {
        fn authorize<'a>(&'a self, _req: AuthRequest<'a>) -> BoxFuture<'a, Result<Lease, AuthDenied>> {
            self.entered.fetch_add(1, Ordering::SeqCst);
            let rx = if self.pause.load(Ordering::Acquire) {
                self.gate_rx.lock().unwrap().take()
            } else {
                None
            };
            Box::pin(async move {
                if let Some(rx) = rx {
                    let _ = rx.recv().await;
                }
                Ok(Lease::new(Duration::from_secs(60)))
            })
        }

        fn revocation_streams(&self) -> Vec<RevocationReceiver> {
            vec![self.rev_tx.subscribe()]
        }
    }

    let tr = TestRuntime::new();
    let dest_auth = ControllableAuth::new();
    let hop_auth = ControllableAuth::new();

    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let hop0 = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(hop_auth.clone())
        .build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(dest_auth.clone())
        .build();

    let (st_a_b, st_l_b, _) = memory_stream_channel(4_096);
    let (st_a_h0, st_l_h0, _) = memory_stream_channel(4_096);
    let (st_h0_b, st_l_b_hop, _) = memory_stream_channel(4_096);
    let (dg_a_h0, dg_l_h0, _, _, _, _) = dg_pair_channel(1_500);
    let (dg_h0_b, dg_l_b_hop, _, _, _, _) = dg_pair_channel(1_500);

    origin.register_stream_carrier("st_b", st_a_b).unwrap();
    origin.register_stream_carrier("st_h0", st_a_h0).unwrap();
    origin.register_datagram_carrier("dg_h0", dg_a_h0).unwrap();

    let ep_st_guard = dest
        .publish_stream_endpoint("ep", Arc::new(StreamEcho { rt: tr.clone() }))
        .unwrap();
    let _ep_dg_guard = dest
        .publish_datagram_endpoint("ep_dg", 1_200, Arc::new(DatagramEcho { rt: tr.clone() }))
        .unwrap();

    // Overlapping transits on hop0: Stream prefix "net/", Datagram prefix "net/", and Stream exact "net/exact"!
    let tr_st_prefix = hop0
        .publish_stream_transit_prefix("net/", static_st_transit(st_h0_b.clone(), b"b".to_vec()))
        .unwrap();
    let _tr_dg_prefix = hop0
        .publish_datagram_transit_prefix("net/", static_dg_transit(dg_h0_b.clone(), b"b".to_vec()))
        .unwrap();
    let _tr_st_exact = hop0
        .publish_stream_transit("net/exact", static_st_transit(st_h0_b.clone(), b"b".to_vec()))
        .unwrap();

    let d1 = Arc::clone(&dest);
    tr.runtime.spawner.spawn(Box::pin(async move {
        let _ = d1.serve_stream_listener(st_l_b).await;
    }));
    let d2 = Arc::clone(&dest);
    tr.runtime.spawner.spawn(Box::pin(async move {
        let _ = d2.serve_stream_listener(st_l_b_hop).await;
    }));
    let d3 = Arc::clone(&dest);
    tr.runtime.spawner.spawn(Box::pin(async move {
        let _ = d3.serve_datagram_listener(dg_l_b_hop).await;
    }));
    let h1 = Arc::clone(&hop0);
    tr.runtime.spawner.spawn(Box::pin(async move {
        let _ = h1.serve_stream_listener(st_l_h0).await;
    }));
    let h2 = Arc::clone(&hop0);
    tr.runtime.spawner.spawn(Box::pin(async move {
        let _ = h2.serve_datagram_listener(dg_l_h0).await;
    }));
    tr.drive_until_idle();

    // 1. TOCTOU revocation race: pause dest's Authorizer, emit Revocation::Peer while suspended,
    //    release Authorizer -> MUST fail with Revoked (not admit racing setup)!
    dest_auth.arm_pause();
    let (res_tx, res_rx) = async_channel::bounded(1);
    let o_c = Arc::clone(&origin);
    let dest_pk = dest.public_key();
    tr.runtime.spawner.spawn(Box::pin(async move {
        let r = o_c
            .dial_stream_via(dest_pk, "ep", ExplicitPath::direct(1, "st_b", b"b".to_vec()))
            .await;
        let _ = res_tx.send(r).await;
    }));
    tr.drive_until_idle();
    assert_eq!(dest_auth.entered.load(Ordering::SeqCst), 1);

    // Emit Authorizer Revocation::Peer(origin.public_key()) while authorize() is suspended!
    dest_auth.rev_tx.send(Revocation::Peer(origin.public_key()));
    tr.drive_until_idle();
    dest_auth.release_pause();
    tr.drive_until_idle();

    let toctou_err = res_rx.try_recv().unwrap().unwrap_err();
    assert_eq!(toctou_err, CoreError::Revoked);

    // 2. Authorizer Revocation::Peer MUST NOT permanently veto origin (subsequent dial SUCCEEDS!).
    let mut st = tr
        .spawner
        .try_block_on(origin.dial_stream_via(
            dest_pk,
            "ep",
            ExplicitPath::direct(2, "st_b", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();

    // Live Authorizer Revocation::Peer revokes the active session with Revoked, STILL without vetoing!
    dest_auth.rev_tx.send(Revocation::Peer(origin.public_key()));
    tr.drive_until_idle();
    let mut buf = [0u8; 8];
    assert_eq!(
        tr.spawner.try_block_on(st.read(&mut buf)),
        Some(Err(CoreError::Revoked))
    );
    assert!(dest.stats().revocations_peer_total >= 2);

    // Next dial STILL succeeds (no permanent local veto from Authorizer::Revocation::Peer)!
    let mut st2 = tr
        .spawner
        .try_block_on(origin.dial_stream_via(
            dest_pk,
            "ep",
            ExplicitPath::direct(3, "st_b", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();

    // 3. Host `ScopeInstance::revoke_peer` revokes active session AND permanently vetoes until `unrevoke_peer`!
    dest.revoke_peer(origin.public_key());
    tr.drive_until_idle();
    assert_eq!(
        tr.spawner.try_block_on(st2.read(&mut buf)),
        Some(Err(CoreError::Revoked))
    );
    let entered_before = dest_auth.entered.load(Ordering::SeqCst);
    let vetoed = tr
        .spawner
        .try_block_on(origin.dial_stream_via(
            dest_pk,
            "ep",
            ExplicitPath::direct(4, "st_b", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(vetoed, CoreError::Revoked);
    assert_eq!(
        dest_auth.entered.load(Ordering::SeqCst),
        entered_before,
        "local veto MUST block before invoking Authorizer"
    );

    // Unrevoke restores access immediately!
    dest.unrevoke_peer(origin.public_key());
    let mut st3 = tr
        .spawner
        .try_block_on(origin.dial_stream_via(
            dest_pk,
            "ep",
            ExplicitPath::direct(5, "st_b", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();

    // 4. Authorizer `Revocation::Endpoint` revokes with `Unpublished`!
    dest_auth.rev_tx.send(Revocation::Endpoint("ep".into()));
    tr.drive_until_idle();
    assert_eq!(
        tr.spawner.try_block_on(st3.read(&mut buf)),
        Some(Err(CoreError::Unpublished))
    );
    assert!(dest.stats().revocations_endpoint_total >= 1);

    // 5. Scoped `TransitRevoker` isolation across Plane + PublicationId + subtarget!
    let mut p_st_sub_a = ExplicitPath::direct(10, "st_h0", b"h0".to_vec());
    p_st_sub_a.hops = vec![HopSpec {
        peer: hop0.public_key(),
        target: "net/a".into(),
    }];
    let mut p_st_sub_b = ExplicitPath::direct(11, "st_h0", b"h0".to_vec());
    p_st_sub_b.hops = vec![HopSpec {
        peer: hop0.public_key(),
        target: "net/b".into(),
    }];
    let mut p_st_exact = ExplicitPath::direct(12, "st_h0", b"h0".to_vec());
    p_st_exact.hops = vec![HopSpec {
        peer: hop0.public_key(),
        target: "net/exact".into(),
    }];
    let mut p_dg_sub_a = ExplicitPath::direct(13, "dg_h0", b"h0".to_vec());
    p_dg_sub_a.hops = vec![HopSpec {
        peer: hop0.public_key(),
        target: "net/a".into(),
    }];

    let mut s_a = tr
        .spawner
        .try_block_on(origin.dial_stream_via(dest_pk, "ep", p_st_sub_a))
        .unwrap()
        .unwrap();
    let mut s_b = tr
        .spawner
        .try_block_on(origin.dial_stream_via(dest_pk, "ep", p_st_sub_b))
        .unwrap()
        .unwrap();
    let mut s_exact = tr
        .spawner
        .try_block_on(origin.dial_stream_via(dest_pk, "ep", p_st_exact))
        .unwrap()
        .unwrap();
    let d_a = tr
        .spawner
        .try_block_on(origin.dial_datagram_via(dest_pk, "ep_dg", 1_200, p_dg_sub_a))
        .unwrap()
        .unwrap();

    // Revoke ONLY subtarget "a" on Stream prefix publication `tr_st_prefix`:
    let revoker = tr_st_prefix.revoker().unwrap();
    revoker.revoke_target("a").unwrap();
    tr.drive_until_idle();

    // `s_a` MUST terminate with HopRejected(0, Revoked)!
    assert_eq!(
        tr.spawner.try_block_on(s_a.read(&mut buf)),
        Some(Err(CoreError::hop_rejected(0, CoreError::Revoked)))
    );

    // `s_b`, `s_exact`, and Datagram `d_a` MUST ALL remain completely alive!
    let survive = tr.spawner.try_block_on(async {
        s_b.write_all(b"sb").await?;
        let mut o = [0u8; 2];
        s_b.read_exact(&mut o).await?;
        assert_eq!(&o, b"sb");

        s_exact.write_all(b"ex").await?;
        s_exact.read_exact(&mut o).await?;
        assert_eq!(&o, b"ex");

        d_a.send(PacketBuf::from_payload(b"dg-a"))?;
        assert_eq!(d_a.recv().await?.payload(), b"dg-a");
        Ok::<(), CoreError>(())
    });
    assert_eq!(survive, Some(Ok(())));

    // 6. Dropping `PublishGuard` (`ep_st_guard`) terminates active endpoint sessions with `Unpublished`!
    drop(ep_st_guard);
    tr.drive_until_idle();
    assert_eq!(
        tr.spawner.try_block_on(s_b.read(&mut buf)),
        Some(Err(CoreError::Unpublished))
    );
    assert_eq!(
        tr.spawner.try_block_on(s_exact.read(&mut buf)),
        Some(Err(CoreError::Unpublished))
    );
}

// ---------------------------------------------------------------------------
// 3. Revocation Broadcast Lag Fail-Closed Invalidates All Active Leases
// ---------------------------------------------------------------------------

#[test]
fn revocation_broadcast_lag_fail_closed_invalidates_all_active_leases() {
    struct LagAuth {
        rev_tx: RevocationSender,
    }
    impl Authorizer for LagAuth {
        fn authorize<'a>(&'a self, _req: AuthRequest<'a>) -> BoxFuture<'a, Result<Lease, AuthDenied>> {
            Box::pin(async { Ok(Lease::new(Duration::from_secs(60))) })
        }
        fn revocation_streams(&self) -> Vec<RevocationReceiver> {
            vec![self.rev_tx.subscribe()]
        }
    }

    let tr = TestRuntime::new();
    let (rev_tx, _rx) = revocation_channel(8); // small capacity = 8 to force deterministic lag!
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(LagAuth {
            rev_tx: rev_tx.clone(),
        }))
        .build();

    let (st_c, st_l, _) = memory_stream_channel(4_096);
    let (dg_c, dg_l, _, _, _, _) = dg_pair_channel(1_500);
    origin.register_stream_carrier("st", st_c).unwrap();
    origin.register_datagram_carrier("dg", dg_c).unwrap();

    let _g1 = dest
        .publish_stream_endpoint("st", Arc::new(StreamEcho { rt: tr.clone() }))
        .unwrap();
    let _g2 = dest
        .publish_datagram_endpoint("dg", 1_200, Arc::new(DatagramEcho { rt: tr.clone() }))
        .unwrap();

    let d1 = Arc::clone(&dest);
    tr.runtime.spawner.spawn(Box::pin(async move {
        let _ = d1.serve_stream_listener(st_l).await;
    }));
    let d2 = Arc::clone(&dest);
    tr.runtime.spawner.spawn(Box::pin(async move {
        let _ = d2.serve_datagram_listener(dg_l).await;
    }));
    tr.drive_until_idle();

    let mut st = tr
        .spawner
        .try_block_on(origin.dial_stream_via(
            dest.public_key(),
            "st",
            ExplicitPath::direct(1, "st", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();
    let dg = tr
        .spawner
        .try_block_on(origin.dial_datagram_via(
            dest.public_key(),
            "dg",
            1_200,
            ExplicitPath::direct(2, "dg", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();

    // Overflow broadcast buffer (capacity 8) with 25 revocations for an unrelated peer BEFORE driving!
    let unrelated = PublicKey::from_bytes([0xEE; 32]);
    for _ in 0..25 {
        rev_tx.send(Revocation::Peer(unrelated));
    }
    tr.drive_until_idle();

    // Fail-closed: BOTH active sessions invalidated with Revoked + lag metric incremented!
    let mut buf = [0u8; 8];
    assert_eq!(
        tr.spawner.try_block_on(st.read(&mut buf)),
        Some(Err(CoreError::Revoked))
    );
    assert_eq!(
        tr.spawner.try_block_on(dg.recv()),
        Some(Err(CoreError::Revoked))
    );
    assert!(dest.stats().revocation_lag_invalidations_total >= 1);
}

// ---------------------------------------------------------------------------
// 4. Multi-Scope Node: Clock Check, O(1) ScopeKid Demux, Link Deduplication,
//    Atomic Port Adoption & Rollback, Unmount, and close_admission
// ---------------------------------------------------------------------------

#[test]
fn node_multiscope_clock_check_o1_demux_datagram_dedup_port_adoption_and_unmount() {
    let tr = TestRuntime::new();
    let other_tr = TestRuntime::new();

    let kp_a = ScopeKeypair::generate();
    let kp_a_dup = ScopeKeypair::from_secret_hex(kp_a.to_secret_hex().as_str()).unwrap();
    let scope_a = ScopeInstance::builder(kp_a, tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();
    let scope_a_dup = ScopeInstance::builder(kp_a_dup, tr.runtime.clone()).build();
    let scope_b = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();
    let scope_bad_clock = ScopeInstance::builder(ScopeKeypair::generate(), other_tr.runtime.clone())
        .build();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();

    let node = Node::builder(tr.runtime.clone())
        .with_limits(NodeLimits {
            max_pending: 32,
            max_datagram_ports: 2,
        })
        .build();

    // 1. Mismatched Clock rejected with InvalidParameter!
    assert_eq!(
        node.add_scope(scope_bad_clock).unwrap_err(),
        CoreError::InvalidParameter
    );

    // 2. Mount scope_a & scope_b; reject duplicate PK or already-mounted scope with AlreadyPublished!
    node.add_scope(Arc::clone(&scope_a)).unwrap();
    assert_eq!(
        node.add_scope(Arc::clone(&scope_a)).unwrap_err(),
        CoreError::AlreadyPublished
    );
    assert_eq!(
        node.add_scope(scope_a_dup).unwrap_err(),
        CoreError::AlreadyPublished
    );
    node.add_scope(Arc::clone(&scope_b)).unwrap();
    assert_eq!(node.stats().mounted_scopes, 2);

    // 3. O(1) ScopeKid demux over shared Stream listener AND deduplicated shared DatagramLink!
    let (st_c, st_l, _) = memory_stream_channel(4_096);
    let (dg_c, _dg_l, _dg_a, dg_b, _, _) = dg_pair_channel(1_500);
    origin.register_stream_carrier("st", st_c).unwrap();
    origin.register_datagram_carrier("dg", dg_c).unwrap();

    let _ga_st = scope_a
        .publish_stream_endpoint("echo", Arc::new(StreamEcho { rt: tr.clone() }))
        .unwrap();
    let _gb_st = scope_b
        .publish_stream_endpoint("echo", Arc::new(StreamEcho { rt: tr.clone() }))
        .unwrap();
    let _ga_dg = scope_a
        .publish_datagram_endpoint("dg_echo", 1_200, Arc::new(DatagramEcho { rt: tr.clone() }))
        .unwrap();
    let _gb_dg = scope_b
        .publish_datagram_endpoint("dg_echo", 1_200, Arc::new(DatagramEcho { rt: tr.clone() }))
        .unwrap();

    let n_srv = Arc::clone(&node);
    tr.runtime.spawner.spawn(Box::pin(async move {
        let _ = n_srv.serve_stream_listener(st_l).await;
    }));
    // Attach the SAME `Arc<MemoryDatagramLink>` across BOTH mounted scopes + Node ->
    // deduplicated into ONE DatagramPort / SlabTable!
    let _ing1 = scope_a.attach_datagram(Arc::clone(&dg_b)).unwrap();
    let _ing2 = scope_b.attach_datagram(Arc::clone(&dg_b)).unwrap();
    let _ing3 = node.attach_datagram(Arc::clone(&dg_b)).unwrap();
    assert_eq!(node.stats().active_datagram_ports, 1);
    tr.drive_until_idle();

    let demux_ok = tr.spawner.try_block_on(async {
        // Stream to scope_a AND scope_b over ONE shared listener!
        let mut sa = origin
            .dial_stream_via(
                scope_a.public_key(),
                "echo",
                ExplicitPath::direct(1, "st", b"n".to_vec()),
            )
            .await?;
        let mut sb = origin
            .dial_stream_via(
                scope_b.public_key(),
                "echo",
                ExplicitPath::direct(2, "st", b"n".to_vec()),
            )
            .await?;
        sa.write_all(b"A").await?;
        sb.write_all(b"B").await?;
        let mut out = [0u8; 1];
        sa.read_exact(&mut out).await?;
        assert_eq!(&out, b"A");
        sb.read_exact(&mut out).await?;
        assert_eq!(&out, b"B");

        // Datagram to scope_a AND scope_b multiplexed over ONE deduplicated DatagramPort!
        let dga = origin
            .dial_datagram_via(
                scope_a.public_key(),
                "dg_echo",
                1_200,
                ExplicitPath::direct(3, "dg", b"n".to_vec()),
            )
            .await?;
        let dgb = origin
            .dial_datagram_via(
                scope_b.public_key(),
                "dg_echo",
                1_200,
                ExplicitPath::direct(4, "dg", b"n".to_vec()),
            )
            .await?;
        dga.send(PacketBuf::from_payload(b"dg-A"))?;
        dgb.send(PacketBuf::from_payload(b"dg-B"))?;
        assert_eq!(dga.recv().await?.payload(), b"dg-A");
        assert_eq!(dgb.recv().await?.payload(), b"dg-B");
        Ok::<(), CoreError>(())
    });
    assert_eq!(demux_ok, Some(Ok(())));
    assert_eq!(node.stats().active_datagram_ports, 1);

    // 4. Atomic live port adoption on `add_scope` + failure rollback (AlreadyPublished & Busy)!
    let scope_conflict = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();
    // Attach the SAME `dg_b` (same LinkId already owned by `node`) to standalone `scope_conflict`.
    let _c_ing = scope_conflict.attach_datagram(Arc::clone(&dg_b)).unwrap();
    assert_eq!(
        node.add_scope(Arc::clone(&scope_conflict)).unwrap_err(),
        CoreError::AlreadyPublished
    );
    assert_eq!(node.stats().mounted_scopes, 2);

    // Capacity rollback: node has max_datagram_ports = 2 (1 used, 1 free).
    // Attach 2 standalone ports to `scope_too_many` -> adoption MUST fail atomically with Busy!
    let scope_too_many = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let p_x1 = MemoryDatagramPair::pair(1_400);
    let p_x2 = MemoryDatagramPair::pair(1_400);
    let _ix1 = scope_too_many.attach_datagram(p_x1.b).unwrap();
    let _ix2 = scope_too_many.attach_datagram(p_x2.b).unwrap();
    assert_eq!(
        node.add_scope(Arc::clone(&scope_too_many)).unwrap_err(),
        CoreError::Busy
    );
    assert_eq!(node.stats().active_datagram_ports, 1);
    assert_eq!(scope_too_many.stats().active_datagram_ports, 2);

    // Successful adoption of 1 live standalone port into the 1 remaining node slot!
    let scope_c = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();
    let (dg_c_car, _dg_c_l, _dg_c_a, dg_c_b, _, _) = dg_pair_channel(1_500);
    origin.register_datagram_carrier("dg_c", dg_c_car).unwrap();
    let _gc_dg = scope_c
        .publish_datagram_endpoint("echo", 1_200, Arc::new(DatagramEcho { rt: tr.clone() }))
        .unwrap();
    let _ic = scope_c.attach_datagram(dg_c_b).unwrap();
    assert_eq!(scope_c.stats().active_datagram_ports, 1);

    node.add_scope(Arc::clone(&scope_c)).unwrap();
    assert_eq!(node.stats().mounted_scopes, 3);
    assert_eq!(node.stats().active_datagram_ports, 2);

    // Adopted port continues accepting setups for `scope_c`!
    let adopted_ok = tr.spawner.try_block_on(async {
        let dgc = origin
            .dial_datagram_via(
                scope_c.public_key(),
                "echo",
                1_200,
                ExplicitPath::direct(5, "dg_c", b"c".to_vec()),
            )
            .await?;
        dgc.send(PacketBuf::from_payload(b"adopted"))?;
        assert_eq!(dgc.recv().await?.payload(), b"adopted");
        Ok::<(), CoreError>(())
    });
    assert_eq!(adopted_ok, Some(Ok(())));

    // 5. `remove_scope` removes `scope_c` from node demux AND adopted ports!
    let removed = node.remove_scope(scope_c.scope_kid());
    assert!(removed.is_some());
    assert_eq!(node.stats().mounted_scopes, 2);

    // 6. `Node::close_admission()` rejects new Stream/Datagram attachments with `Closed`!
    node.close_admission();
    let p_closed_st = MemoryStreamPair::pair(4_096);
    assert_eq!(node.accept_stream(p_closed_st.b).unwrap_err(), CoreError::Closed);
    let p_closed_dg = MemoryDatagramPair::pair(1_400);
    assert_eq!(
        node.attach_datagram(p_closed_dg.b).unwrap_err(),
        CoreError::Closed
    );
}

// ---------------------------------------------------------------------------
// 5. Pure Outer-Crate Public API Integration Test: 12 B Framed DatagramCarrier Wrapper
//    (`with_overhead(12)` + `Arc<L>`), Custom Claims `Authorizer` + `IntersectAuthorizer` & `Node`
// ---------------------------------------------------------------------------

#[test]
fn outer_crate_pure_public_api_framed_carrier_custom_authorizer_and_multiscope_node() {
    const FRAME_HDR_LEN: usize = 12;
    const MAGIC: [u8; 12] = *b"OUTERFRAME12";

    /// Outer-crate vertical framing wrapper adding a 12-byte wire header and subtracting
    /// 12 bytes from live `ChannelCaps` / `MtuWatch` via `with_overhead(12)`!
    struct FramedDatagramLink<L: DatagramLink> {
        inner: L,
        id: LinkId,
    }

    impl<L: DatagramLink> DatagramLink for FramedDatagramLink<L> {
        fn caps(&self) -> ChannelCaps {
            self.inner.caps().with_overhead(FRAME_HDR_LEN as u16)
        }

        fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
            self.inner.poll_send_ready(cx)
        }

        fn try_send(&self, mut packet: PacketBuf) -> Result<(), CoreError> {
            packet.prepend_header(&MAGIC)?;
            self.inner.try_send(packet)
        }

        fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<PacketBuf, CoreError>> {
            match self.inner.poll_recv(cx) {
                Poll::Ready(Ok(mut pkt)) => {
                    if pkt.len() < FRAME_HDR_LEN || pkt.strip_header(FRAME_HDR_LEN)? != MAGIC {
                        return Poll::Ready(Err(CoreError::Malformed));
                    }
                    Poll::Ready(Ok(pkt))
                }
                other => other,
            }
        }

        fn source_tag(&self) -> [u8; 16] {
            self.inner.source_tag()
        }

        fn link_id(&self) -> LinkId {
            self.id
        }
    }

    struct FramedCarrier<L: DatagramLink>(Arc<FramedDatagramLink<L>>);
    impl<L: DatagramLink> DatagramCarrier for FramedCarrier<L> {
        type Link = Arc<FramedDatagramLink<L>>;
        fn caps(&self) -> ChannelCaps {
            self.0.caps()
        }
        async fn open_link(&self, _locator: &[u8]) -> Result<Self::Link, CoreError> {
            Ok(Arc::clone(&self.0))
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TenantId(&'static str);

    struct TenantAuth(&'static str);
    impl Authorizer for TenantAuth {
        fn authorize<'a>(&'a self, _req: AuthRequest<'a>) -> BoxFuture<'a, Result<Lease, AuthDenied>> {
            let tenant = TenantId(self.0);
            Box::pin(async move { Ok(Lease::new(Duration::from_secs(60)).with_context(tenant)) })
        }
    }

    let tr = TestRuntime::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(IntersectAuthorizer::new(
            Arc::new(TenantAuth("tenant-alpha")),
            Arc::new(AllowAll(Duration::from_secs(120))),
        )))
        .build();
    let node = Node::builder(tr.runtime.clone()).build();
    node.add_scope(Arc::clone(&dest)).unwrap();

    // Base link MTU = 1500 -> FramedDatagramLink effective MTU = 1488!
    let pair = MemoryDatagramPair::pair(1_500);
    let framed_a = Arc::new(FramedDatagramLink {
        inner: pair.a,
        id: LinkId::allocate(),
    });
    let framed_b = Arc::new(FramedDatagramLink {
        inner: pair.b,
        id: LinkId::allocate(),
    });

    origin
        .register_datagram_carrier("framed", FramedCarrier(framed_a))
        .unwrap();
    let _ing = node.attach_datagram(framed_b).unwrap();

    let seen_tenant = Arc::new(Mutex::new(None::<TenantId>));
    struct TenantEcho {
        rt: TestRuntime,
        seen: Arc<Mutex<Option<TenantId>>>,
    }
    impl DatagramEndpointHandler for TenantEcho {
        fn open(&self, auth: SessionAuth) -> BoxFuture<'_, Result<Arc<dyn DatagramLink>, CoreError>> {
            let t = auth.context::<TenantId>().map(|v| (*v).clone());
            *self.seen.lock().unwrap() = t;
            let spawner = Arc::clone(&self.rt.runtime.spawner);
            Box::pin(async move {
                let p = MemoryDatagramPair::pair(65_535);
                let b = p.b;
                spawner.spawn(Box::pin(async move {
                    while let Ok(pkt) = b.recv().await {
                        if b.send(pkt).await.is_err() {
                            break;
                        }
                    }
                }));
                Ok(p.a as Arc<dyn DatagramLink>)
            })
        }
    }

    let _ep = dest
        .publish_datagram_endpoint(
            "svc",
            1_200,
            Arc::new(TenantEcho {
                rt: tr.clone(),
                seen: Arc::clone(&seen_tenant),
            }),
        )
        .unwrap();
    tr.drive_until_idle();

    let dg = tr
        .spawner
        .try_block_on(origin.dial_datagram_via(
            dest.public_key(),
            "svc",
            1_200,
            ExplicitPath::direct(1, "framed", b"n".to_vec()),
        ))
        .unwrap()
        .unwrap();

    // Vertical 12 B framing overhead accurately reflected in negotiated MTU & max_payload!
    assert_eq!(dg.mtu(), 1_488);
    assert_eq!(dg.max_payload(), 1_488 - DG_OVERHEAD);
    assert_eq!(*seen_tenant.lock().unwrap(), Some(TenantId("tenant-alpha")));

    // Live underlay MTU drop (1500 -> 1400) propagates automatically through with_overhead(12) -> 1388!
    pair.a_faults.set_mtu(1_400);
    tr.drive_until_idle();
    assert_eq!(dg.mtu(), 1_388);
    assert_eq!(dg.max_payload(), 1_388 - DG_OVERHEAD);

    let ok = tr.spawner.try_block_on(async {
        dg.send(PacketBuf::from_payload(b"framed-outer-api"))?;
        let r = dg.recv().await?;
        assert_eq!(r.payload(), b"framed-outer-api");
        Ok::<(), CoreError>(())
    });
    assert_eq!(ok, Some(Ok(())));
}


// ---------------------------------------------------------------------------
// Regression Tests for Codex Round 1 (DG-02, DG-03, DG-04, DG-05, DG-06)
// ---------------------------------------------------------------------------

#[test]
fn regression_dg02_dg03_concurrent_node_mount_rollback_and_attach_race() {
    use std::sync::Barrier;
    use std::thread;

    // Part A (DG-02): Two Nodes concurrently calling `add_scope` on the SAME `ScopeInstance`
    // across OS threads MUST allow AT MOST ONE winner and reject the other with `AlreadyPublished`!
    for _ in 0..32 {
        let tr = TestRuntime::new();
        let scope = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
        let node1 = Node::builder(tr.runtime.clone()).build();
        let node2 = Node::builder(tr.runtime.clone()).build();
        let barrier = Arc::new(Barrier::new(2));

        let b1 = Arc::clone(&barrier);
        let n1 = Arc::clone(&node1);
        let s1 = Arc::clone(&scope);
        let t1 = thread::spawn(move || {
            b1.wait();
            n1.add_scope(s1)
        });

        let b2 = Arc::clone(&barrier);
        let n2 = Arc::clone(&node2);
        let s2 = Arc::clone(&scope);
        let t2 = thread::spawn(move || {
            b2.wait();
            n2.add_scope(s2)
        });

        let r1 = t1.join().unwrap();
        let r2 = t2.join().unwrap();
        match (r1, r2) {
            (Ok(()), Err(CoreError::AlreadyPublished)) => {
                assert_eq!(node1.stats().mounted_scopes, 1);
                assert_eq!(node2.stats().mounted_scopes, 0);
            }
            (Err(CoreError::AlreadyPublished), Ok(())) => {
                assert_eq!(node1.stats().mounted_scopes, 0);
                assert_eq!(node2.stats().mounted_scopes, 1);
            }
            other => panic!("DG-02: expected exactly one winner and one AlreadyPublished, got {:?}", other),
        }
    }

    // Part B (DG-02 rollback): Failed port adoption (`Busy`) MUST release the atomic Node claim
    // so the scope can immediately be mounted onto another Node!
    {
        let tr = TestRuntime::new();
        let node_full = Node::builder(tr.runtime.clone())
            .with_limits(NodeLimits {
                max_pending: 16,
                max_datagram_ports: 1,
            })
            .build();
        let node_ok = Node::builder(tr.runtime.clone()).build();

        let p_fill = MemoryDatagramPair::pair(1_400);
        let _i_fill = node_full.attach_datagram(p_fill.b).unwrap();

        let scope = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
        let p_s = MemoryDatagramPair::pair(1_400);
        let _i_s = scope.attach_datagram(p_s.b).unwrap();

        assert_eq!(
            node_full.add_scope(Arc::clone(&scope)).unwrap_err(),
            CoreError::Busy
        );
        // Claim was rolled back cleanly -> mounting on `node_ok` MUST succeed!
        node_ok.add_scope(Arc::clone(&scope)).unwrap();
        assert_eq!(node_ok.stats().mounted_scopes, 1);
        assert_eq!(node_ok.stats().active_datagram_ports, 1);
        assert_eq!(scope.stats().active_datagram_ports, 0);
    }

    // Part C (DG-03): Concurrent `scope.attach_datagram(link)` racing `node.add_scope(scope)`
    // and `node.remove_scope(kid)` MUST NEVER leave an orphan standalone port while mounted,
    // NEVER spawn duplicate pumps for the same LinkId, and NEVER reinsert an unmounted ScopeKid!
    for _ in 0..24 {
        let tr = TestRuntime::new();
        let scope = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
            .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
            .build();
        let node = Node::builder(tr.runtime.clone()).build();
        let pair = MemoryDatagramPair::pair(1_500);
        let link = Arc::clone(&pair.b);
        let barrier = Arc::new(Barrier::new(2));

        let b1 = Arc::clone(&barrier);
        let s1 = Arc::clone(&scope);
        let l1 = Arc::clone(&link);
        let t_attach = thread::spawn(move || {
            b1.wait();
            s1.attach_datagram(l1)
        });

        let b2 = Arc::clone(&barrier);
        let n2 = Arc::clone(&node);
        let s2 = Arc::clone(&scope);
        let t_mount = thread::spawn(move || {
            b2.wait();
            n2.add_scope(s2)
        });

        let attach_res = t_attach.join().unwrap();
        let mount_res = t_mount.join().unwrap();
        assert!(attach_res.is_ok());
        assert!(mount_res.is_ok());

        // Regardless of ordering, the scope is now mounted, so ALL ports MUST live in `node`
        // (ZERO orphan standalone ports!), and attaching the same link on `node` deduplicates to 1!
        assert_eq!(
            scope.stats().active_datagram_ports,
            0,
            "DG-03: attach_datagram racing add_scope MUST NOT leave orphan standalone port"
        );
        let _ing_node = node.attach_datagram(Arc::clone(&link)).unwrap();
        assert_eq!(node.stats().active_datagram_ports, 1);

        // Now race `scope.attach_datagram(link2)` against `node.remove_scope(scope.scope_kid())`!
        let pair2 = MemoryDatagramPair::pair(1_500);
        let link2 = Arc::clone(&pair2.b);
        let barrier2 = Arc::new(Barrier::new(2));

        let b3 = Arc::clone(&barrier2);
        let s3 = Arc::clone(&scope);
        let l3 = Arc::clone(&link2);
        let t_attach2 = thread::spawn(move || {
            b3.wait();
            s3.attach_datagram(l3)
        });

        let b4 = Arc::clone(&barrier2);
        let n4 = Arc::clone(&node);
        let kid = scope.scope_kid();
        let t_unmount = thread::spawn(move || {
            b4.wait();
            n4.remove_scope(kid)
        });

        let _ = t_attach2.join().unwrap().unwrap();
        assert!(t_unmount.join().unwrap().is_some());
        tr.drive_until_idle();

        // After unmount:
        // - If attach2 landed BEFORE unmount, detach_scope removed scope.kid and retired unowned link2!
        //   So node has ONLY `link` (node_wide = true, active_datagram_ports == 1) and scope has 0.
        // - If attach2 landed AFTER unmount, it landed cleanly in `scope`'s standalone registry!
        //   So node STILL has ONLY `link` (active_datagram_ports == 1) and scope has 1.
        // In NEITHER case can `node` ever retain `link2` or `scope.kid`!
        assert_eq!(
            node.stats().active_datagram_ports,
            1,
            "DG-03: attach_datagram racing remove_scope MUST NEVER strand unmounted scope link in Node"
        );
    }
}

#[test]
fn regression_dg04_dying_port_during_adoption_never_blocks_link_id() {
    let tr = TestRuntime::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let scope = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();
    let node = Node::builder(tr.runtime.clone())
        .with_limits(NodeLimits {
            max_pending: 16,
            max_datagram_ports: 1,
        })
        .build();

    let shared_id = LinkId::allocate();

    struct FixedIdLink {
        inner: Arc<MemoryDatagramLink>,
        id: LinkId,
    }
    impl DatagramLink for FixedIdLink {
        fn caps(&self) -> ChannelCaps {
            self.inner.caps()
        }
        fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
            self.inner.poll_send_ready(cx)
        }
        fn try_send(&self, packet: PacketBuf) -> Result<(), CoreError> {
            self.inner.try_send(packet)
        }
        fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<PacketBuf, CoreError>> {
            self.inner.poll_recv(cx)
        }
        fn source_tag(&self) -> [u8; 16] {
            self.inner.source_tag()
        }
        fn link_id(&self) -> LinkId {
            self.id
        }
    }

    // Attach link #1 with `shared_id` to standalone `scope`, fail its carrier pipe, then adopt into `node`!
    let dead_pair = MemoryDatagramPair::pair(1_500);
    let ing_dead = scope
        .attach_datagram(FixedIdLink {
            inner: Arc::clone(&dead_pair.b),
            id: shared_id,
        })
        .unwrap();
    tr.drive_until_idle();

    // Inject fatal failure BEFORE mounting (pump wakes and exits cleanly during/before adoption).
    dead_pair
        .a_faults
        .inject_fatal_error(CoreError::Carrier("dead link".into()));
    tr.drive_until_idle();
    assert_eq!(
        tr.spawner.try_block_on(ing_dead.closed()),
        Some(CoreError::Carrier("dead link".into()))
    );

    node.add_scope(Arc::clone(&scope)).unwrap();
    assert_eq!(node.stats().active_datagram_ports, 0);

    // Now attach a live link #2 with the EXACT SAME `shared_id` on `node` and verify traffic works!
    let live_pair = MemoryDatagramPair::pair(1_500);
    let _ep = scope
        .publish_datagram_endpoint("echo", 1_200, Arc::new(DatagramEcho { rt: tr.clone() }))
        .unwrap();
    origin
        .register_datagram_carrier("mem", SharedDgCarrier(Arc::clone(&live_pair.a)))
        .unwrap();
    let _ing_live = node
        .attach_datagram(FixedIdLink {
            inner: Arc::clone(&live_pair.b),
            id: shared_id,
        })
        .unwrap();
    assert_eq!(node.stats().active_datagram_ports, 1);
    tr.drive_until_idle();

    let dg = tr
        .spawner
        .try_block_on(origin.dial_datagram_via(
            scope.public_key(),
            "echo",
            1_200,
            ExplicitPath::direct(1, "mem", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();
    let ok = tr.spawner.try_block_on(async {
        dg.send(PacketBuf::from_payload(b"dg04-alive"))?;
        assert_eq!(dg.recv().await?.payload(), b"dg04-alive");
        Ok::<(), CoreError>(())
    });
    assert_eq!(ok, Some(Ok(())));

    // Part B: Race pump termination directly against `node.add_scope()` across OS threads so
    // `adopt_from` and `run_pump` teardown interleave under contention — `shared_id` MUST NEVER
    // be stranded in `node`!
    for _ in 0..24 {
        let tr_r = TestRuntime::new();
        let sc = ScopeInstance::builder(ScopeKeypair::generate(), tr_r.runtime.clone()).build();
        let nd = Node::builder(tr_r.runtime.clone())
            .with_limits(NodeLimits {
                max_pending: 8,
                max_datagram_ports: 1,
            })
            .build();
        let link_id = LinkId::allocate();
        let p_dead = MemoryDatagramPair::pair(1_500);
        let ing = sc
            .attach_datagram(FixedIdLink {
                inner: Arc::clone(&p_dead.b),
                id: link_id,
            })
            .unwrap();
        tr_r.drive_until_idle();
        p_dead
            .a_faults
            .inject_fatal_error(CoreError::Carrier("mid-adopt fail".into()));

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let b1 = Arc::clone(&barrier);
        let sp = Arc::clone(&tr_r.spawner);
        let t_pump = std::thread::spawn(move || {
            b1.wait();
            sp.drive_until_idle();
        });
        let b2 = Arc::clone(&barrier);
        let nd_c = Arc::clone(&nd);
        let sc_c = Arc::clone(&sc);
        let t_adopt = std::thread::spawn(move || {
            b2.wait();
            nd_c.add_scope(sc_c).unwrap();
        });
        t_pump.join().unwrap();
        t_adopt.join().unwrap();
        tr_r.drive_until_idle();

        assert_eq!(
            tr_r.spawner.try_block_on(ing.closed()),
            Some(CoreError::Carrier("mid-adopt fail".into()))
        );
        assert_eq!(
            nd.stats().active_datagram_ports,
            0,
            "DG-04: port dying mid-adoption MUST NOT leave stale entry or leak permit"
        );
        // Reattaching the exact same `LinkId` on the 1-port Node MUST succeed!
        let p_live = MemoryDatagramPair::pair(1_500);
        let _ing2 = nd
            .attach_datagram(FixedIdLink {
                inner: Arc::clone(&p_live.b),
                id: link_id,
            })
            .expect("DG-04: LinkId MUST NOT be permanently blocked after mid-adoption death");
        assert_eq!(nd.stats().active_datagram_ports, 1);
    }
}

#[test]
fn regression_dg05_drop_standalone_scope_and_node_stops_pumps_and_releases_scopes() {
    /// DatagramLink wrapper that stays pending in `poll_recv` forever and increments `drops`
    /// when dropped — proving the background inbound pump exited rather than leaking!
    struct DropCountingLink {
        id: LinkId,
        drops: Arc<AtomicUsize>,
    }
    impl Drop for DropCountingLink {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl DatagramLink for DropCountingLink {
        fn caps(&self) -> ChannelCaps {
            ChannelCaps::fixed(1_500, false)
        }
        fn poll_send_ready(&self, _cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
            Poll::Ready(Ok(()))
        }
        fn try_send(&self, _packet: PacketBuf) -> Result<(), CoreError> {
            Ok(())
        }
        fn poll_recv(&self, _cx: &mut Context<'_>) -> Poll<Result<PacketBuf, CoreError>> {
            Poll::Pending
        }
        fn link_id(&self) -> LinkId {
            self.id
        }
    }

    // Part A: Dropping final standalone `Arc<ScopeInstance>` stops its inbound pump cleanly!
    {
        let tr = TestRuntime::new();
        let link_drops = Arc::new(AtomicUsize::new(0));
        let scope = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
        let ingress = scope
            .attach_datagram(DropCountingLink {
                id: LinkId::allocate(),
                drops: Arc::clone(&link_drops),
            })
            .unwrap();
        tr.drive_until_idle();
        assert_eq!(link_drops.load(Ordering::SeqCst), 0);

        drop(scope);
        tr.drive_until_idle();
        assert_eq!(
            tr.spawner.try_block_on(ingress.closed()),
            Some(CoreError::Closed),
            "DG-05: dropping standalone ScopeInstance MUST close inbound ports"
        );
        assert_eq!(
            link_drops.load(Ordering::SeqCst),
            1,
            "DG-05: standalone inbound pump MUST exit and drop its DatagramLink"
        );
    }

    // Part B: Dropping `Node` stops all node-wide & adopted pumps AND restores retained scopes
    // to unmounted standalone state so they can mount onto a replacement `Node`!
    {
        let tr = TestRuntime::new();
        let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
        let scope = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
            .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
            .build();
        let _ep = scope
            .publish_datagram_endpoint("echo", 1_200, Arc::new(DatagramEcho { rt: tr.clone() }))
            .unwrap();

        let node1 = Node::builder(tr.runtime.clone()).build();
        let link_drops = Arc::new(AtomicUsize::new(0));

        // Attach one standalone link (adopted on add_scope) and one node-wide link!
        let ing_adopted = scope
            .attach_datagram(DropCountingLink {
                id: LinkId::allocate(),
                drops: Arc::clone(&link_drops),
            })
            .unwrap();
        node1.add_scope(Arc::clone(&scope)).unwrap();
        let ing_node_wide = node1
            .attach_datagram(DropCountingLink {
                id: LinkId::allocate(),
                drops: Arc::clone(&link_drops),
            })
            .unwrap();
        tr.drive_until_idle();
        assert_eq!(link_drops.load(Ordering::SeqCst), 0);

        // Drop `node1` while retaining `scope`!
        drop(node1);
        tr.drive_until_idle();

        assert_eq!(
            tr.spawner.try_block_on(ing_adopted.closed()),
            Some(CoreError::Closed)
        );
        assert_eq!(
            tr.spawner.try_block_on(ing_node_wide.closed()),
            Some(CoreError::Closed)
        );
        assert_eq!(
            link_drops.load(Ordering::SeqCst),
            2,
            "DG-05: dropping Node MUST stop ALL inbound pumps (adopted + node-wide)"
        );

        // Retained `scope` MUST now be cleanly unmounted and mountable on a replacement `Node2`!
        let node2 = Node::builder(tr.runtime.clone()).build();
        node2
            .add_scope(Arc::clone(&scope))
            .expect("DG-05: retained scope MUST join replacement Node after previous Node drops");
        assert_eq!(node2.stats().mounted_scopes, 1);

        let (dg_c, _dg_l, _a, dg_b, _, _) = dg_pair_channel(1_500);
        origin.register_datagram_carrier("dg", dg_c).unwrap();
        let _ing2 = node2.attach_datagram(dg_b).unwrap();
        tr.drive_until_idle();

        let dg = tr
            .spawner
            .try_block_on(origin.dial_datagram_via(
                scope.public_key(),
                "echo",
                1_200,
                ExplicitPath::direct(1, "dg", b"n2".to_vec()),
            ))
            .unwrap()
            .unwrap();
        let ok = tr.spawner.try_block_on(async {
            dg.send(PacketBuf::from_payload(b"dg05-node2"))?;
            assert_eq!(dg.recv().await?.payload(), b"dg05-node2");
            Ok::<(), CoreError>(())
        });
        assert_eq!(ok, Some(Ok(())));
    }
}

#[test]
fn regression_dg06_unmounting_last_attached_scope_frees_node_port_capacity() {
    let tr = TestRuntime::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let scope = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();
    let _ep = scope
        .publish_datagram_endpoint("echo", 1_200, Arc::new(DatagramEcho { rt: tr.clone() }))
        .unwrap();

    // Node with strict 1-port capacity!
    let node = Node::builder(tr.runtime.clone())
        .with_limits(NodeLimits {
            max_pending: 16,
            max_datagram_ports: 1,
        })
        .build();

    // Part A: Idle adopted port (even while caller retains `DatagramIngress` handle!) MUST retire
    // immediately on `remove_scope` and free the single port slot without returning `Busy`!
    let p1 = MemoryDatagramPair::pair(1_500);
    let ing1 = scope.attach_datagram(Arc::clone(&p1.b)).unwrap();
    node.add_scope(Arc::clone(&scope)).unwrap();
    assert_eq!(node.stats().active_datagram_ports, 1);

    let removed = node.remove_scope(scope.scope_kid());
    assert!(removed.is_some());
    assert_eq!(
        node.stats().active_datagram_ports,
        0,
        "DG-06: unmounting last attached scope MUST immediately retire unowned idle port"
    );

    // Even BEFORE driving executor (and while `ing1` is still alive), a new link MUST succeed!
    let p2 = MemoryDatagramPair::pair(1_500);
    let _ing2 = node
        .attach_datagram(Arc::clone(&p2.b))
        .expect("DG-06: 1-port Node MUST NOT return Busy after unmounting last attached scope");
    assert_eq!(node.stats().active_datagram_ports, 1);

    tr.drive_until_idle();
    assert_eq!(
        tr.spawner.try_block_on(ing1.closed()),
        Some(CoreError::Closed)
    );

    // Part B: Adopted port with an ACTIVE circuit stays alive through `remove_scope`, then retires
    // automatically once the last circuit drops, freeing capacity for a replacement link!
    drop(node);
    tr.drive_until_idle();

    let node_b = Node::builder(tr.runtime.clone())
        .with_limits(NodeLimits {
            max_pending: 16,
            max_datagram_ports: 1,
        })
        .build();
    let (dg_c, _l, _a, dg_b, _, _) = dg_pair_channel(1_500);
    origin.register_datagram_carrier("dg", dg_c).unwrap();
    let ing_active = scope.attach_datagram(dg_b).unwrap();
    node_b.add_scope(Arc::clone(&scope)).unwrap();
    tr.drive_until_idle();

    let dg = tr
        .spawner
        .try_block_on(origin.dial_datagram_via(
            scope.public_key(),
            "echo",
            1_200,
            ExplicitPath::direct(1, "dg", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();
    assert_eq!(node_b.stats().active_datagram_ports, 1);

    // Unmount while circuit is still active: port remains open for the active circuit!
    assert!(node_b.remove_scope(scope.scope_kid()).is_some());
    assert_eq!(node_b.stats().active_datagram_ports, 1);

    // Active circuit continues working cleanly until dropped, then port retires and frees capacity!
    let ok = tr.spawner.try_block_on(async {
        dg.send(PacketBuf::from_payload(b"dg06-in-flight"))?;
        assert_eq!(dg.recv().await?.payload(), b"dg06-in-flight");
        Ok::<(), CoreError>(())
    });
    assert_eq!(ok, Some(Ok(())));

    drop(dg);
    tr.drive_until_idle();
    assert_eq!(
        node_b.stats().active_datagram_ports,
        0,
        "DG-06: unowned port MUST retire once its last circuit releases"
    );
    assert_eq!(
        tr.spawner.try_block_on(ing_active.closed()),
        Some(CoreError::Closed)
    );

    let p3 = MemoryDatagramPair::pair(1_500);
    let _ing3 = node_b
        .attach_datagram(p3.b)
        .expect("DG-06: freed port slot MUST accept new link");
    assert_eq!(node_b.stats().active_datagram_ports, 1);
}

// ===========================================================================
// Codex Round 2 Regression Test (`R2-DG-02`)
// ===========================================================================

/// R2-DG-02: Unmounting a scope via `Node::remove_scope` (or dropping `Node`) while a live
/// `DatagramPort` for `LinkId` remains alive (due to `node_wide`, another mounted scope, or
/// an active circuit's `Binding`) MUST NEVER allow a second receive pump or second `SlabTable`
/// to be spawned for that `LinkId`. Once the live port retires, reattaching MUST succeed cleanly.
#[test]
fn regression_r2_dg02_unmount_prevents_duplicate_receive_pumps_for_same_link_id() {
    let tr = TestRuntime::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let scope_a = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();
    let scope_b = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();
    let _ea = scope_a
        .publish_datagram_endpoint("echo", 1_200, Arc::new(DatagramEcho { rt: tr.clone() }))
        .unwrap();
    let _eb = scope_b
        .publish_datagram_endpoint("echo", 1_200, Arc::new(DatagramEcho { rt: tr.clone() }))
        .unwrap();

    // Part A: Node-wide port kept alive across `remove_scope`!
    let (dg_c1, _l1, _a1, dg_b1, _, _) = dg_pair_channel(1_500);
    origin.register_datagram_carrier("dg1", dg_c1).unwrap();

    let node = Node::builder(tr.runtime.clone()).build();
    node.add_scope(Arc::clone(&scope_a)).unwrap();
    node.add_scope(Arc::clone(&scope_b)).unwrap();
    let _node_ing = node.attach_datagram(Arc::clone(&dg_b1)).unwrap();
    tr.drive_until_idle();

    // Unmount `scope_a` while `node` still owns `dg_b1` node-wide!
    assert!(node.remove_scope(scope_a.scope_kid()).is_some());

    // Immediately attempting to reattach the SAME `LinkId` on standalone `scope_a` MUST fail with
    // `CoreError::Busy` instead of spawning a competing second receive pump!
    assert_eq!(
        scope_a.attach_datagram(Arc::clone(&dg_b1)).err(),
        Some(CoreError::Busy),
        "R2-DG-02: removed scope MUST NOT spawn a second receive pump while Node still holds live LinkId"
    );
    assert_eq!(scope_a.stats().active_datagram_ports, 0);

    // Verify `node`'s single receive pump continues serving `scope_b` with zero stolen packets!
    let ok_b = tr.spawner.try_block_on(async {
        let dg = origin
            .dial_datagram_via(
                scope_b.public_key(),
                "echo",
                1_200,
                ExplicitPath::direct(201, "dg1", b"b".to_vec()),
            )
            .await?;
        for i in 0..8u8 {
            dg.send(PacketBuf::from_payload(&[0xB0 + i; 16]))?;
            assert_eq!(dg.recv().await?.payload(), &[0xB0 + i; 16]);
        }
        Ok::<(), CoreError>(())
    });
    assert_eq!(ok_b, Some(Ok(())));

    // Dropping `node` retires `dg_b1`; NOW standalone `scope_a` MUST reattach `dg_b1` cleanly!
    drop(node);
    tr.drive_until_idle();
    let _standalone_ing = scope_a
        .attach_datagram(Arc::clone(&dg_b1))
        .expect("R2-DG-02: reattach MUST succeed once prior Node port retires");
    assert_eq!(scope_a.stats().active_datagram_ports, 1);

    let ok_a = tr.spawner.try_block_on(async {
        let dg = origin
            .dial_datagram_via(
                scope_a.public_key(),
                "echo",
                1_200,
                ExplicitPath::direct(202, "dg1", b"b".to_vec()),
            )
            .await?;
        dg.send(PacketBuf::from_payload(b"post-retire-ok"))?;
        assert_eq!(dg.recv().await?.payload(), b"post-retire-ok");
        Ok::<(), CoreError>(())
    });
    assert_eq!(ok_a, Some(Ok(())));
    drop(scope_a);
    tr.drive_until_idle();

    // Part B: Adopted port kept alive strictly by an active circuit (`outbound_refs > 0`) across
    // BOTH `Node::remove_scope` AND `Node::drop`!
    let scope_c = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();
    let _ec = scope_c
        .publish_datagram_endpoint("echo", 1_200, Arc::new(DatagramEcho { rt: tr.clone() }))
        .unwrap();
    let (dg_c2, _l2, _a2, dg_b2, _, _) = dg_pair_channel(1_500);
    origin.register_datagram_carrier("dg2", dg_c2).unwrap();

    let node_b = Node::builder(tr.runtime.clone()).build();
    let _ic = scope_c.attach_datagram(Arc::clone(&dg_b2)).unwrap();
    node_b.add_scope(Arc::clone(&scope_c)).unwrap();
    tr.drive_until_idle();

    let active_dg = tr
        .spawner
        .try_block_on(origin.dial_datagram_via(
            scope_c.public_key(),
            "echo",
            1_200,
            ExplicitPath::direct(203, "dg2", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();
    tr.drive_until_idle();

    // Unmount `scope_c` while `active_dg` keeps the port alive on `node_b`!
    assert!(node_b.remove_scope(scope_c.scope_kid()).is_some());
    assert_eq!(
        scope_c.attach_datagram(Arc::clone(&dg_b2)).err(),
        Some(CoreError::Busy),
        "R2-DG-02: MUST reject reattach while active circuit keeps port alive in Node"
    );

    // Even after dropping `node_b` while `active_dg` is STILL live (`outbound_refs > 0`),
    // reattaching `dg_b2` MUST STILL be rejected until `active_dg` closes and the pump retires!
    drop(node_b);
    tr.drive_until_idle();
    assert_eq!(
        scope_c.attach_datagram(Arc::clone(&dg_b2)).err(),
        Some(CoreError::Busy),
        "R2-DG-02: MUST reject reattach after Node drop while active circuit still owns live port"
    );

    // Active circuit MUST continue delivering 10/10 packets with zero competing pump interference!
    let ok_active = tr.spawner.try_block_on(async {
        for i in 0..10u8 {
            active_dg.send(PacketBuf::from_payload(&[0xC0 + i; 24]))?;
            assert_eq!(active_dg.recv().await?.payload(), &[0xC0 + i; 24]);
        }
        Ok::<(), CoreError>(())
    });
    assert_eq!(ok_active, Some(Ok(())));

    // Close `active_dg` -> port retires cleanly -> reattach on standalone `scope_c` now SUCCEEDS!
    drop(active_dg);
    tr.drive_until_idle();
    let _reattached = scope_c
        .attach_datagram(Arc::clone(&dg_b2))
        .expect("R2-DG-02: reattach MUST succeed after last active circuit retires port");
    assert_eq!(scope_c.stats().active_datagram_ports, 1);
}
