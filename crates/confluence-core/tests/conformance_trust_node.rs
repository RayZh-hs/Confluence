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
