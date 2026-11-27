//! End-to-end deterministic Datagram Plane conformance suite (Spec §§10.2–10.4).
//!
//! Covers direct & multi-hop flows, spoofed `reverse_mtu`, `MessageTooLarge`, staged 1.0 RTT
//! confirm/drop-abort, steady-state suppression of reordered empty `seq == 0`, `DatagramIngress`
//! lifecycle with no auto-close on `Rejected`, oversized `SETUP_FRAG` fragmentation/retries/
//! mid-reassembly cookie re-challenge/duplicate frag 0 re-ACK/`precheck_datagram_setup`,
//! multi-hop `SETUP_COOKIE` + 3 s `hold_for_cookie_retry`, live `MtuWatch` propagation + 5 s
//! transit drain window, in-band renewal with verifier idempotency, control-plane filters, and
//! graceful `begin_shutdown()` / `is_drained()`.

#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::task::{Context, Poll};
use core::time::Duration;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use confluence_core::auth::{
    AuthDenied, AuthRequest, Authorizer, CredentialProvider, CredentialRequest, Lease, SessionAuth,
};
use confluence_core::channel::{
    BoxedStream, ChannelCaps, DatagramAdmission, DatagramCarrier, DatagramLink, DatagramLinkExt,
    DatagramListener,
};
use confluence_core::constants::{DATAGRAM_MIN_MTU, DG_OVERHEAD};
use confluence_core::handler::{
    DatagramEndpointHandler, DatagramTransitHandler, StaticTransit, StreamEndpointHandler,
    StreamTransitHandler,
};
use confluence_core::path::{ExplicitPath, HopSpec, PathOutcome, PathSource};
use confluence_core::runtime::BoxFuture;
use confluence_core::testing::{
    DatagramFaults, MemoryDatagramLink, MemoryDatagramPair, MemoryStreamPair, TestRuntime,
};
use confluence_core::{
    CoreError, Credential, LinkId, Node, PacketBuf, Plane, PublicKey, ScopeInstance, ScopeKeypair,
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

struct RecordingPathSource {
    outcomes: Mutex<Vec<(u64, PathOutcome)>>,
}

impl RecordingPathSource {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            outcomes: Mutex::new(Vec::new()),
        })
    }

    fn snapshot(&self) -> Vec<(u64, PathOutcome)> {
        self.outcomes.lock().unwrap().clone()
    }
}

impl PathSource for RecordingPathSource {
    fn resolve_path(
        &self,
        _peer: PublicKey,
        _endpoint: &str,
        _plane: Plane,
    ) -> BoxFuture<'_, Result<ExplicitPath, CoreError>> {
        Box::pin(async { Err(CoreError::NoPath) })
    }

    fn report_outcome(&self, path_id: u64, outcome: PathOutcome) {
        self.outcomes.lock().unwrap().push((path_id, outcome));
    }
}

/// Datagram echo endpoint that records every received datagram payload and echoes it back.
struct DatagramEchoEndpoint {
    rt: TestRuntime,
    opens: Arc<AtomicUsize>,
    seen_payloads: Arc<Mutex<Vec<Vec<u8>>>>,
}

type PayloadLog = Arc<Mutex<Vec<Vec<u8>>>>;

impl DatagramEchoEndpoint {
    fn new(rt: &TestRuntime) -> (Arc<Self>, Arc<AtomicUsize>, PayloadLog) {
        let opens = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(Mutex::new(Vec::new()));
        (
            Arc::new(Self {
                rt: rt.clone(),
                opens: Arc::clone(&opens),
                seen_payloads: Arc::clone(&seen),
            }),
            opens,
            seen,
        )
    }
}

impl DatagramEndpointHandler for DatagramEchoEndpoint {
    fn open(&self, _auth: SessionAuth) -> BoxFuture<'_, Result<Arc<dyn DatagramLink>, CoreError>> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        let seen = Arc::clone(&self.seen_payloads);
        let spawner = Arc::clone(&self.rt.runtime.spawner);
        Box::pin(async move {
            let pair = MemoryDatagramPair::pair(65_535);
            let b = pair.b;
            spawner.spawn(Box::pin(async move {
                while let Ok(pkt) = b.recv().await {
                    seen.lock().unwrap().push(pkt.payload().to_vec());
                    if b.send(pkt).await.is_err() {
                        break;
                    }
                }
            }));
            Ok(pair.a as Arc<dyn DatagramLink>)
        })
    }
}

/// Controllable shared-link Datagram channel returning the SAME persistent `Arc<MemoryDatagramLink>`
/// (so `LinkId` deduplication and `DatagramFaults` / live MTU / packet capture work deterministically!).
#[derive(Clone)]
struct SharedDatagramCarrier {
    link: Arc<MemoryDatagramLink>,
}

struct SingleDatagramListener {
    rx: async_channel::Receiver<Arc<MemoryDatagramLink>>,
}

struct SharedLinkBundle {
    carrier: SharedDatagramCarrier,
    listener: SingleDatagramListener,
    a_faults: DatagramFaults,
    b_faults: DatagramFaults,
    a_link: Arc<MemoryDatagramLink>,
    b_link: Arc<MemoryDatagramLink>,
}

fn shared_datagram_channel(mtu: u16) -> SharedLinkBundle {
    let pair = MemoryDatagramPair::with_source_tags(mtu, [0x77; 16], [0x88; 16]);
    let a_link = pair.a;
    let b_link = pair.b;
    let (tx, rx) = async_channel::bounded(1);
    let _ = tx.try_send(Arc::clone(&b_link));
    SharedLinkBundle {
        carrier: SharedDatagramCarrier {
            link: Arc::clone(&a_link),
        },
        listener: SingleDatagramListener { rx },
        a_faults: pair.a_faults,
        b_faults: pair.b_faults,
        a_link,
        b_link,
    }
}

impl DatagramCarrier for SharedDatagramCarrier {
    type Link = Arc<MemoryDatagramLink>;

    fn caps(&self) -> ChannelCaps {
        self.link.caps()
    }

    async fn open_link(&self, _locator: &[u8]) -> Result<Self::Link, CoreError> {
        Ok(Arc::clone(&self.link))
    }
}

impl DatagramListener for SingleDatagramListener {
    type Link = Arc<MemoryDatagramLink>;

    async fn accept_link(&self) -> Result<Self::Link, CoreError> {
        self.rx.recv().await.map_err(|_| CoreError::Closed)
    }
}

fn static_dg_transit<C: DatagramCarrier>(
    carrier: C,
    locator: Vec<u8>,
) -> Arc<dyn DatagramTransitHandler> {
    Arc::new(StaticTransit::new(Arc::new(carrier), locator))
}

fn spawn_scope_dg_listener<L: DatagramListener>(
    rt: &TestRuntime,
    scope: &Arc<ScopeInstance>,
    listener: L,
) {
    let s = Arc::clone(scope);
    rt.runtime.spawner.spawn(Box::pin(async move {
        let _ = s.serve_datagram_listener(listener).await;
    }));
}

fn run_with_clock<F: core::future::Future>(
    rt: &TestRuntime,
    fut: F,
    step: Duration,
    max_steps: usize,
) -> F::Output {
    let mut fut = core::pin::pin!(fut);
    let flag = Arc::new(AtomicBool::new(true));
    struct FlagWake(Arc<AtomicBool>);
    impl std::task::Wake for FlagWake {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::Release);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::Release);
        }
    }
    let waker = core::task::Waker::from(Arc::new(FlagWake(Arc::clone(&flag))));
    let mut cx = Context::from_waker(&waker);

    for _ in 0..=max_steps {
        loop {
            if flag.swap(false, Ordering::AcqRel) {
                if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                    rt.drive_until_idle();
                    return out;
                }
            }
            let polls = rt.drive_until_idle();
            if polls == 0 && !flag.load(Ordering::Acquire) {
                break;
            }
        }
        rt.clock.advance(step);
    }
    panic!("future did not complete within {} virtual clock steps", max_steps);
}

// ---------------------------------------------------------------------------
// 1. Direct & 2-Hop Flows, Spoofed reverse_mtu Ignored, and MessageTooLarge Without Closing
// ---------------------------------------------------------------------------

#[test]
fn datagram_direct_and_multihop_spoofed_reverse_mtu_and_message_too_large() {
    /// Wrapper link that spoofs cleartext `SETUP_OK.reverse_mtu` (bytes 2..4) to 60000 on recv.
    struct SpoofingLink {
        inner: Arc<MemoryDatagramLink>,
        id: LinkId,
    }
    impl DatagramLink for SpoofingLink {
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
            match self.inner.poll_recv(cx) {
                Poll::Ready(Ok(mut pkt)) => {
                    if pkt.len() >= 4 && pkt.payload()[0] == 0x12 {
                        pkt.payload_mut()[2..4].copy_from_slice(&60_000u16.to_be_bytes());
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

    struct SpoofingCarrier(Arc<SpoofingLink>);
    impl DatagramCarrier for SpoofingCarrier {
        type Link = Arc<SpoofingLink>;
        fn caps(&self) -> ChannelCaps {
            self.0.caps()
        }
        async fn open_link(&self, _locator: &[u8]) -> Result<Self::Link, CoreError> {
            Ok(Arc::clone(&self.0))
        }
    }

    let tr = TestRuntime::new();
    let outcomes = RecordingPathSource::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_path_source(outcomes.clone())
        .build();
    let hop0 = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();
    let hop1 = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();

    let direct = shared_datagram_channel(1_500);
    let a_h0 = shared_datagram_channel(2_000);
    let h0_h1 = shared_datagram_channel(1_400);
    let h1_b = shared_datagram_channel(1_600);

    let spoofing_link = Arc::new(SpoofingLink {
        inner: Arc::clone(&a_h0.a_link),
        id: LinkId::allocate(),
    });

    origin
        .register_datagram_carrier("direct", direct.carrier.clone())
        .unwrap();
    origin
        .register_datagram_carrier("spoof_h0", SpoofingCarrier(spoofing_link))
        .unwrap();
    let _t0 = hop0
        .publish_datagram_transit("to-h1", static_dg_transit(h0_h1.carrier.clone(), b"h1".to_vec()))
        .unwrap();
    let _t1 = hop1
        .publish_datagram_transit("to-b", static_dg_transit(h1_b.carrier.clone(), b"b".to_vec()))
        .unwrap();

    let (echo, _, _) = DatagramEchoEndpoint::new(&tr);
    let _ep = dest.publish_datagram_endpoint("echo", 1_200, echo).unwrap();

    spawn_scope_dg_listener(&tr, &dest, direct.listener);
    spawn_scope_dg_listener(&tr, &hop0, a_h0.listener);
    spawn_scope_dg_listener(&tr, &hop1, h0_h1.listener);
    spawn_scope_dg_listener(&tr, &dest, h1_b.listener);
    tr.drive_until_idle();

    let res = tr.spawner.try_block_on(async {
        // Direct A -> B with MessageTooLarge check (no wire TX, session stays open!).
        let dg = origin
            .dial_datagram_via(
                dest.public_key(),
                "echo",
                1_200,
                ExplicitPath::direct(1, "direct", b"b".to_vec()),
            )
            .await?;
        let max_p = dg.max_payload();
        assert_eq!(max_p, 1_500 - DG_OVERHEAD);

        direct.a_faults.set_capture(true);
        let oversized = vec![0xEE; max_p + 1];
        assert_eq!(
            dg.send(PacketBuf::from_payload(&oversized)),
            Err(CoreError::MessageTooLarge(max_p))
        );
        assert_eq!(
            dg.send_wait(PacketBuf::from_payload(&oversized)).await,
            Err(CoreError::MessageTooLarge(max_p))
        );
        // Zero packets transmitted on wire for oversized sends!
        assert!(direct.a_faults.drain_captured().is_empty());

        // Session is still healthy and echoes exact max_payload bytes!
        let max_valid = vec![0x5A; max_p];
        dg.send(PacketBuf::from_payload(&max_valid))?;
        let echoed = dg.recv().await?;
        assert_eq!(echoed.payload(), max_valid.as_slice());

        // 2-hop A -> H0 -> H1 -> B with spoofed cleartext reverse_mtu=60000 -> MUST derive 1400!
        let mut p2 = ExplicitPath::direct(2, "spoof_h0", b"h0".to_vec());
        p2.hops = vec![
            HopSpec {
                peer: hop0.public_key(),
                target: "to-h1".into(),
            },
            HopSpec {
                peer: hop1.public_key(),
                target: "to-b".into(),
            },
        ];
        let dg2 = origin
            .dial_datagram_via(dest.public_key(), "echo", 1_200, p2)
            .await?;
        assert_eq!(dg2.mtu(), 1_400);
        assert_eq!(dg2.max_payload(), 1_400 - DG_OVERHEAD);
        dg2.send(PacketBuf::from_payload(b"hello-2hop-dg"))?;
        let r2 = dg2.recv().await?;
        assert_eq!(r2.payload(), b"hello-2hop-dg");
        Ok::<(), CoreError>(())
    });
    assert_eq!(res, Some(Ok(())));
    assert!(
        outcomes
            .snapshot()
            .contains(&(2, PathOutcome::Established { mtu: 1_400 }))
    );
}

// ---------------------------------------------------------------------------
// 2. Staged 1.0 RTT Deferred Open, Drop-Abort & Steady-State Reordered seq == 0 Suppression
// ---------------------------------------------------------------------------

#[test]
fn datagram_staged_deferred_open_confirm_drop_abort_and_reordered_seq0_suppression() {
    let tr = TestRuntime::new();
    let outcomes = RecordingPathSource::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_path_source(outcomes.clone())
        .build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();

    let chan = shared_datagram_channel(1_500);
    origin
        .register_datagram_carrier("mem", chan.carrier.clone())
        .unwrap();
    let (echo, opens, seen_payloads) = DatagramEchoEndpoint::new(&tr);
    let _ep = dest.publish_datagram_endpoint("echo", 1_200, echo).unwrap();
    spawn_scope_dg_listener(&tr, &dest, chan.listener);
    tr.drive_until_idle();

    // Stage #1: 0 handler opens; drop-abort cleanly with PathOutcome::Closed.
    let res1 = tr.spawner.try_block_on(async {
        let staged = origin
            .dial_datagram_staged_via(
                dest.public_key(),
                "echo",
                1_200,
                ExplicitPath::direct(11, "mem", b"b".to_vec()),
            )
            .await?;
        assert_eq!(opens.load(Ordering::SeqCst), 0);
        drop(staged);
        Ok::<(), CoreError>(())
    });
    assert_eq!(res1, Some(Ok(())));
    tr.drive_until_idle();
    assert_eq!(opens.load(Ordering::SeqCst), 0);
    assert_eq!(dest.stats().pending_setups, 0);
    assert!(outcomes.snapshot().contains(&(11, PathOutcome::Closed)));

    // Stage #2: Reorder empty `seq == 0` confirmation BEHIND `seq == 1 ("first-real")`!
    // Destination confirms on `seq == 1`, delivers `"first-real"`, then receives delayed empty
    // `seq == 0` in steady state and MUST suppress it (never delivering `b""` to app!).
    let res2 = tr.spawner.try_block_on(async {
        let staged = origin
            .dial_datagram_staged_via(
                dest.public_key(),
                "echo",
                1_200,
                ExplicitPath::direct(12, "mem", b"b".to_vec()),
            )
            .await?;
        assert_eq!(opens.load(Ordering::SeqCst), 0);

        // Arm single-pair reorder so `seq == 0` (from confirm) is swapped behind `seq == 1`!
        chan.a_faults.reorder_next_pair();
        let dg = staged.confirm().await?;
        // Send seq == 1 immediately so the wire delivers [seq=1, seq=0]!
        dg.send(PacketBuf::from_payload(b"first-real"))?;

        let r1 = dg.recv().await?;
        assert_eq!(r1.payload(), b"first-real");

        // Send seq == 2 and verify it arrives cleanly with NO spurious empty datagram!
        dg.send(PacketBuf::from_payload(b"second-real"))?;
        let r2 = dg.recv().await?;
        assert_eq!(r2.payload(), b"second-real");
        Ok::<(), CoreError>(())
    });
    assert_eq!(res2, Some(Ok(())));
    tr.drive_until_idle();

    assert_eq!(opens.load(Ordering::SeqCst), 1);
    let app_seen = seen_payloads.lock().unwrap().clone();
    assert_eq!(
        app_seen,
        vec![b"first-real".to_vec(), b"second-real".to_vec()],
        "empty seq==0 confirm packet MUST be suppressed even when reordered into steady state"
    );
}

// ---------------------------------------------------------------------------
// 3. DatagramIngress Admission Lifecycle (Idle -> Pending -> Rejected -> Pending -> Admitted)
//    with NO Auto-Close / NO Idle Timeout on Rejected
// ---------------------------------------------------------------------------

#[test]
fn datagram_ingress_admission_lifecycle_and_no_auto_close_on_rejected() {
    let tr = TestRuntime::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();

    let chan = shared_datagram_channel(1_500);
    origin
        .register_datagram_carrier("mem", chan.carrier.clone())
        .unwrap();
    let (echo, _, _) = DatagramEchoEndpoint::new(&tr);
    let _ep = dest.publish_datagram_endpoint("good", 1_200, echo).unwrap();

    // Attach link explicitly to observe DatagramIngress state transitions directly!
    let ingress = dest.attach_datagram(Arc::clone(&chan.b_link)).unwrap();
    assert_eq!(ingress.admission(), DatagramAdmission::Idle);
    assert_eq!(tr.spawner.try_block_on(ingress.closed()), None);

    // Step 1: Dial unpublished endpoint -> admission transitions Idle -> Pending -> Rejected!
    let err = tr.spawner.try_block_on(origin.dial_datagram_via(
        dest.public_key(),
        "nope",
        1_200,
        ExplicitPath::direct(1, "mem", b"b".to_vec()),
    ));
    assert_eq!(err.unwrap().unwrap_err(), CoreError::Unpublished);
    assert_eq!(ingress.admission(), DatagramAdmission::Rejected);
    assert_eq!(tr.spawner.try_block_on(ingress.closed()), None);

    // Step 2: Advance VirtualClock by 120 seconds — MUST NOT auto-close or idle-timeout!
    tr.advance_and_drive(Duration::from_secs(120));
    assert_eq!(tr.spawner.try_block_on(ingress.closed()), None);
    assert_eq!(ingress.admission(), DatagramAdmission::Rejected);

    // Step 3: Dial valid published endpoint on the SAME link -> Rejected -> Pending -> Admitted!
    let dg = tr
        .spawner
        .try_block_on(origin.dial_datagram_via(
            dest.public_key(),
            "good",
            1_200,
            ExplicitPath::direct(2, "mem", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();
    assert_eq!(ingress.admission(), DatagramAdmission::Admitted);
    assert_eq!(tr.spawner.try_block_on(ingress.closed()), None);

    // Step 4: Sticky Admitted: a subsequent rejected dial on the same link stays Admitted!
    let err2 = tr.spawner.try_block_on(origin.dial_datagram_via(
        dest.public_key(),
        "still-nope",
        1_200,
        ExplicitPath::direct(3, "mem", b"b".to_vec()),
    ));
    assert_eq!(err2.unwrap().unwrap_err(), CoreError::Unpublished);
    assert_eq!(ingress.admission(), DatagramAdmission::Admitted);
    drop(dg);
}

// ---------------------------------------------------------------------------
// 4. Oversized SETUP_FRAG Fragmentation (2..=8), [150, 300, 600] ms Retries,
//    Mid-Reassembly under_load Cookie Re-Challenge, Duplicate Frag 0 Re-ACK & Precheck
// ---------------------------------------------------------------------------

#[test]
fn datagram_oversized_setup_fragmentation_retries_mid_reassembly_cookie_and_precheck() {
    /// Returns a max-size 128 B credential for every verifier so a 2-hop SETUP_FWD exceeds 1200 B!
    struct LargeCreds;
    impl CredentialProvider for LargeCreds {
        fn credential<'a>(
            &'a self,
            _req: CredentialRequest<'a>,
        ) -> BoxFuture<'a, Result<Credential, CoreError>> {
            Box::pin(async { Ok(Credential::from_slice(&[0xCC; 128]).unwrap()) })
        }
    }

    let tr = TestRuntime::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_credentials(Arc::new(LargeCreds))
        .build();
    let hop0 = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();
    let hop1 = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();

    // Use 4-hop chain (or 3 hops + 128 B creds each -> ~1350 B SETUP_FWD > 1200 B MTU -> 2 SETUP_FRAG packets!).
    let hop2 = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();

    let a_h0 = shared_datagram_channel(1_200);
    let h0_h1 = shared_datagram_channel(1_200);
    let h1_h2 = shared_datagram_channel(1_200);
    let h2_b = shared_datagram_channel(1_200);

    let hop0_t = "transit-target-hop-zero-long-name-padding-to-exceed-1200-bytes-aa";
    let hop1_t = "transit-target-hop-one-long-name-padding-to-exceed-1200-bytes-bbb";
    let hop2_t = "transit-target-hop-two-long-name-padding-to-exceed-1200-bytes-ccc";
    let ep_name = "endpoint-long-name-padding-to-guarantee-setup-fragmentation-ddd";

    origin
        .register_datagram_carrier("to_h0", a_h0.carrier.clone())
        .unwrap();
    let _t0 = hop0
        .publish_datagram_transit(hop0_t, static_dg_transit(h0_h1.carrier.clone(), b"1".to_vec()))
        .unwrap();
    let _t1 = hop1
        .publish_datagram_transit(hop1_t, static_dg_transit(h1_h2.carrier.clone(), b"2".to_vec()))
        .unwrap();
    let _t2 = hop2
        .publish_datagram_transit(hop2_t, static_dg_transit(h2_b.carrier.clone(), b"b".to_vec()))
        .unwrap();
    let (echo, _, _) = DatagramEchoEndpoint::new(&tr);
    let _ep = dest
        .publish_datagram_endpoint(ep_name, 1_152, echo)
        .unwrap();

    let node = Node::builder(tr.runtime.clone()).build();
    node.add_scope(Arc::clone(&hop0)).unwrap();

    let node_srv = Arc::clone(&node);
    tr.runtime.spawner.spawn(Box::pin(async move {
        let _ = node_srv.serve_datagram_listener(a_h0.listener).await;
    }));
    spawn_scope_dg_listener(&tr, &hop1, h0_h1.listener);
    spawn_scope_dg_listener(&tr, &hop2, h1_h2.listener);
    spawn_scope_dg_listener(&tr, &dest, h2_b.listener);
    tr.drive_until_idle();

    let mut path = ExplicitPath::direct(1, "to_h0", b"h0".to_vec());
    path.hops = vec![
        HopSpec {
            peer: hop0.public_key(),
            target: hop0_t.into(),
        },
        HopSpec {
            peer: hop1.public_key(),
            target: hop1_t.into(),
        },
        HopSpec {
            peer: hop2.public_key(),
            target: hop2_t.into(),
        },
    ];

    // Part A: Drop first 2 packets (the entire initial SETUP_FRAG burst!) -> Origin retransmits at
    // 150 ms, receives SETUP_FRAG_ACK strictly post-authenticate, and establishes cleanly!
    a_h0.a_faults.set_capture(true);
    a_h0.b_faults.set_capture(true);
    a_h0.a_faults.drop_next(2);

    let dg = run_with_clock(
        &tr,
        origin.dial_datagram_via(dest.public_key(), ep_name, 1_152, path.clone()),
        Duration::from_millis(50),
        40,
    )
    .unwrap();

    let sent_wire = a_h0.a_faults.drain_captured();
    let recv_wire = a_h0.b_faults.drain_captured();
    let frag_pkts: Vec<&PacketBuf> = sent_wire
        .iter()
        .filter(|p| !p.is_empty() && p.payload()[0] == 0x15)
        .collect();
    assert!(
        frag_pkts.len() >= 2,
        "expected oversized SETUP_FWD to fragment into >= 2 SETUP_FRAG packets, got {}",
        frag_pkts.len()
    );
    assert!(
        recv_wire
            .iter()
            .any(|p| !p.is_empty() && p.payload()[0] == 0x16),
        "expected SETUP_FRAG_ACK (0x16) from hop0"
    );

    // Test precheck_datagram_setup on BOTH ScopeInstance and Node using captured frag 0 & frag 1!
    let frag0 = frag_pkts
        .iter()
        .find(|p| p.payload().get(1) == Some(&0))
        .unwrap();
    let frag1 = frag_pkts
        .iter()
        .find(|p| p.payload().get(1) == Some(&1))
        .unwrap();
    assert!(hop0.precheck_datagram_setup(frag0.payload()));
    assert!(node.precheck_datagram_setup(frag0.payload()));
    assert!(!hop0.precheck_datagram_setup(frag1.payload()));
    // Tampering inside hop0's leading encrypted segment invalidates mac1 -> precheck returns false!
    let mut bad_frag0 = frag0.payload().to_vec();
    bad_frag0[48] ^= 0x01;
    assert!(!hop0.precheck_datagram_setup(&bad_frag0));
    assert!(!node.precheck_datagram_setup(&bad_frag0));

    // Part B: Duplicate frag 0 replay after completion MUST re-emit SETUP_FRAG_ACK without
    // re-running setup (`hop0.stats().datagram.transit.setup_attempts` MUST NOT increment!).
    let attempts_before = hop0.stats().datagram.transit.setup_attempts;
    let _ = a_h0.b_faults.drain_captured();
    a_h0.a_link.try_send((*frag0).clone()).unwrap();
    tr.drive_until_idle();
    let reack_wire = a_h0.b_faults.drain_captured();
    assert!(
        reack_wire
            .iter()
            .any(|p| !p.is_empty() && p.payload()[0] == 0x16),
        "duplicate frag 0 MUST re-emit SETUP_FRAG_ACK"
    );
    assert_eq!(hop0.stats().datagram.transit.setup_attempts, attempts_before);

    // Verify established fragmented circuit carries datagrams cleanly!
    let echo_ok = tr.spawner.try_block_on(async {
        dg.send(PacketBuf::from_payload(b"frag-circuit-ok"))?;
        let r = dg.recv().await?;
        assert_eq!(r.payload(), b"frag-circuit-ok");
        Ok::<(), CoreError>(())
    });
    assert_eq!(echo_ok, Some(Ok(())));
    drop(dg);
    tr.drive_until_idle();

    // Part C: Mid-reassembly `under_load` flip!
    // Intercept frag 0 manually: send frag 0 while `!under_load`, then flip `hop0.set_under_load(Some(true))`,
    // then send frag 1 -> hop0 re-evaluates load, emits SETUP_COOKIE (0x14), and MUST drop FragmentReceipt
    // WITHOUT sending SETUP_FRAG_ACK (0x16)!
    let a_h0_mid = shared_datagram_channel(1_200);
    // Attach directly to hop0 (node-mounted, so attach on node!).
    let _ing = node.attach_datagram(Arc::clone(&a_h0_mid.b_link)).unwrap();
    // Build a fresh fragmented burst by capturing from a throwaway dial against a closed/capturing channel.
    let cap_chan = shared_datagram_channel(1_200);
    cap_chan.a_faults.set_capture(true);
    origin
        .register_datagram_carrier("cap", cap_chan.carrier.clone())
        .unwrap();
    let mut cap_path = path.clone();
    cap_path.id = 99;
    cap_path.first_channel = "cap".into();
    // Start dial in background so it transmits frag 0 + frag 1 into cap_chan.
    let o_bg = Arc::clone(&origin);
    let dest_pk = dest.public_key();
    let ep_owned = ep_name.to_owned();
    tr.runtime.spawner.spawn(Box::pin(async move {
        let _ = o_bg
            .dial_datagram_via(dest_pk, &ep_owned, 1_152, cap_path)
            .await;
    }));
    tr.drive_until_idle();
    let captured_frags: Vec<PacketBuf> = cap_chan
        .a_faults
        .drain_captured()
        .into_iter()
        .filter(|p| !p.is_empty() && p.payload()[0] == 0x15)
        .collect();
    assert!(captured_frags.len() >= 2);
    let f0 = captured_frags[0].clone();
    let f_rest = captured_frags[1..].to_vec();

    a_h0_mid.b_faults.set_capture(true);
    // Deliver frag 0 while !under_load -> enters reassembler.
    assert!(!hop0.stats().under_load);
    a_h0_mid.a_link.try_send(f0).unwrap();
    tr.drive_until_idle();
    assert!(a_h0_mid.b_faults.drain_captured().is_empty());

    // Flip under_load ON mid-reassembly BEFORE delivering remaining fragments!
    hop0.set_under_load(Some(true));
    for f in f_rest {
        a_h0_mid.a_link.try_send(f).unwrap();
    }
    tr.drive_until_idle();

    let mid_replies = a_h0_mid.b_faults.drain_captured();
    assert!(
        mid_replies
            .iter()
            .any(|p| !p.is_empty() && p.payload()[0] == 0x14),
        "expected SETUP_COOKIE (0x14) after mid-reassembly under_load flip"
    );
    assert!(
        !mid_replies
            .iter()
            .any(|p| !p.is_empty() && p.payload()[0] == 0x16),
        "MUST NOT emit SETUP_FRAG_ACK (0x16) when mid-reassembly cookie challenge fires!"
    );

    // Part D: precheck_datagram_setup returns false once admission closes!
    hop0.begin_shutdown();
    assert!(!hop0.precheck_datagram_setup(frag0.payload()));
    assert!(!node.precheck_datagram_setup(frag0.payload()));
}

// ---------------------------------------------------------------------------
// 5. Multi-Hop SETUP_COOKIE, 3 s hold_for_cookie_retry & Duplicate Challenge CookieRequired
// ---------------------------------------------------------------------------

#[test]
fn datagram_multihop_cookie_retry_3s_port_hold_and_duplicate_challenge() {
    let tr = TestRuntime::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let hop0 = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();

    let a_h0 = shared_datagram_channel(1_500);
    let h0_b = shared_datagram_channel(1_500);
    origin
        .register_datagram_carrier("to_h0", a_h0.carrier.clone())
        .unwrap();
    let _t0 = hop0
        .publish_datagram_transit("to-b", static_dg_transit(h0_b.carrier.clone(), b"b".to_vec()))
        .unwrap();
    let (echo, _, _) = DatagramEchoEndpoint::new(&tr);
    let _ep = dest.publish_datagram_endpoint("echo", 1_200, echo).unwrap();

    spawn_scope_dg_listener(&tr, &hop0, a_h0.listener);
    spawn_scope_dg_listener(&tr, &dest, h0_b.listener);
    tr.drive_until_idle();

    // Force BOTH hop0 and dest under load!
    // When dest challenges hop0 with SETUP_COOKIE, hop0 retains its outbound DatagramPort to dest
    // for 3 s (`hold_for_cookie_retry`) preserving source_tag/port, and retries succeed cleanly!
    hop0.set_under_load(Some(true));
    dest.set_under_load(Some(true));

    let mut path = ExplicitPath::direct(1, "to_h0", b"h0".to_vec());
    path.hops = vec![HopSpec {
        peer: hop0.public_key(),
        target: "to-b".into(),
    }];

    let dg = tr
        .spawner
        .try_block_on(origin.dial_datagram_via(dest.public_key(), "echo", 1_200, path))
        .unwrap()
        .unwrap();
    assert_eq!(hop0.stats().mac2_challenges_total, 1);
    assert_eq!(dest.stats().mac2_challenges_total, 1);

    // Confirm data flows over the cookie-retried circuit!
    let ok = tr.spawner.try_block_on(async {
        dg.send(PacketBuf::from_payload(b"dg-cookie-ok"))?;
        let r = dg.recv().await?;
        assert_eq!(r.payload(), b"dg-cookie-ok");
        Ok::<(), CoreError>(())
    });
    assert_eq!(ok, Some(Ok(())));
    drop(dg);
    tr.drive_until_idle();

    // Verify 3 s `hold_for_cookie_retry` retains hop0's outbound DatagramPort until 3 s elapse!
    // At t = 0 (circuit dropped), hop0 still has 2 ports (inbound a_h0 + held outbound h0_b)!
    assert_eq!(hop0.stats().active_datagram_ports, 2);
    tr.advance_and_drive(Duration::from_millis(2_900));
    assert_eq!(hop0.stats().active_datagram_ports, 2);
    // At t = 3.0 s+, hold_for_cookie_retry expires and outbound-only port h0_b retires cleanly!
    tr.advance_and_drive(Duration::from_millis(200));
    assert_eq!(hop0.stats().active_datagram_ports, 1);

    // Verify duplicate challenge from same responder fails cleanly with CoreError::CookieRequired!
    // Simulate NAT rebinding on the server-side link (`source_tag()` increments per lookup) so
    // the second setup attempt receives a fresh challenge from the same hop -> CookieRequired!
    struct RebindingTagLink {
        inner: Arc<MemoryDatagramLink>,
        counter: AtomicUsize,
        id: LinkId,
    }
    impl DatagramLink for RebindingTagLink {
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
            let n = self.counter.fetch_add(1, Ordering::AcqRel) as u64;
            let mut tag = [0u8; 16];
            tag[..8].copy_from_slice(&n.to_be_bytes());
            tag
        }
        fn link_id(&self) -> LinkId {
            self.id
        }
    }
    let rebind = shared_datagram_channel(1_500);
    origin
        .register_datagram_carrier("rebind", rebind.carrier.clone())
        .unwrap();
    let _ing = dest
        .attach_datagram(RebindingTagLink {
            inner: Arc::clone(&rebind.b_link),
            counter: AtomicUsize::new(1),
            id: LinkId::allocate(),
        })
        .unwrap();
    tr.drive_until_idle();

    let dup_err = tr
        .spawner
        .try_block_on(origin.dial_datagram_via(
            dest.public_key(),
            "echo",
            1_200,
            ExplicitPath::direct(2, "rebind", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(dup_err, CoreError::CookieRequired);
}

// ---------------------------------------------------------------------------
// 6. Live MtuWatch Propagation (Origin/Transit/Dest), Stale Epoch Ignored & 5 s Transit Drain
// ---------------------------------------------------------------------------

#[test]
fn datagram_live_mtu_propagation_stale_epoch_and_5s_transit_drain_window() {
    let tr = TestRuntime::new();
    let outcomes = RecordingPathSource::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_path_source(outcomes.clone())
        .build();
    let hop0 = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();

    let a_h0 = shared_datagram_channel(1_500);
    let h0_b = shared_datagram_channel(1_500);

    origin
        .register_datagram_carrier("to_h0", a_h0.carrier.clone())
        .unwrap();
    let _t0 = hop0
        .publish_datagram_transit("to-b", static_dg_transit(h0_b.carrier.clone(), b"b".to_vec()))
        .unwrap();
    let (echo, _, _) = DatagramEchoEndpoint::new(&tr);
    let _ep = dest.publish_datagram_endpoint("echo", 1_200, echo).unwrap();

    spawn_scope_dg_listener(&tr, &hop0, a_h0.listener);
    spawn_scope_dg_listener(&tr, &dest, h0_b.listener);
    tr.drive_until_idle();

    let mut path = ExplicitPath::direct(77, "to_h0", b"h0".to_vec());
    path.hops = vec![HopSpec {
        peer: hop0.public_key(),
        target: "to-b".into(),
    }];

    let dg = tr
        .spawner
        .try_block_on(origin.dial_datagram_via(dest.public_key(), "echo", 1_200, path.clone()))
        .unwrap()
        .unwrap();
    assert_eq!(dg.mtu(), 1_500);
    assert_eq!(dg.max_payload(), 1_500 - DG_OVERHEAD);

    // 1. Origin local MtuWatch drops 1500 -> 1400.
    a_h0.a_faults.set_mtu(1_400);
    tr.drive_until_idle();
    assert_eq!(dg.mtu(), 1_400);
    assert_eq!(dg.max_payload(), 1_400 - DG_OVERHEAD);
    assert!(
        outcomes
            .snapshot()
            .contains(&(77, PathOutcome::MtuChanged { mtu: 1_400 }))
    );

    // 2. Transit H0->B MtuWatch drops 1500 -> 1300 -> DG_MTU -> Origin -> DG_MTU_ACK!
    a_h0.b_faults.set_capture(true);
    h0_b.a_faults.set_mtu(1_300);
    tr.drive_until_idle();
    assert_eq!(dg.mtu(), 1_300);
    assert_eq!(dg.max_payload(), 1_300 - DG_OVERHEAD);
    assert!(
        outcomes
            .snapshot()
            .contains(&(77, PathOutcome::MtuChanged { mtu: 1_300 }))
    );
    let captured_from_h0 = a_h0.b_faults.drain_captured();
    let old_dg_mtu = captured_from_h0
        .iter()
        .find(|p| !p.is_empty() && p.payload()[0] == 0x24)
        .cloned()
        .expect("expected DG_MTU (0x24) from transit");

    // 3. Destination B MtuWatch drops 1500 -> 1250 -> DG_MTU -> H0 -> Origin -> DG_MTU_ACK!
    h0_b.b_faults.set_mtu(1_250);
    tr.drive_until_idle();
    assert_eq!(dg.mtu(), 1_250);
    assert_eq!(dg.max_payload(), 1_250 - DG_OVERHEAD);
    assert!(
        outcomes
            .snapshot()
            .contains(&(77, PathOutcome::MtuChanged { mtu: 1_250 }))
    );

    // 4. Replaying stale DG_MTU (epoch 1, mtu=1300) is ignored — MTU stays 1250 and session works!
    a_h0.b_link.try_send(old_dg_mtu).unwrap();
    tr.drive_until_idle();
    assert_eq!(dg.mtu(), 1_250);
    let ok = tr.spawner.try_block_on(async {
        dg.send(PacketBuf::from_payload(b"after-stale-mtu"))?;
        let r = dg.recv().await?;
        assert_eq!(r.payload(), b"after-stale-mtu");
        Ok::<(), CoreError>(())
    });
    assert_eq!(ok, Some(Ok(())));

    // 5. Floor violation at Transit H0->B (1100 < 1200):
    // H0 reports DG_MTU(1100) upstream and enters 5 s drain window -> Origin receives 1100 < 1200,
    // sends authenticated e2e::DG_CLOSE(MtuTooSmall(1100)) through H0's drain window to B, and
    // BOTH Origin and Destination tear down cleanly!
    h0_b.a_faults.set_mtu(1_100);
    tr.drive_until_idle();

    let err = tr.spawner.try_block_on(dg.recv()).unwrap().unwrap_err();
    assert_eq!(err, CoreError::MtuTooSmall(1_100));
    assert_eq!(dest.stats().datagram.destination.active_sessions, 0);

    // Advance 5 s so H0's transit drain window completes cleanly!
    tr.advance_and_drive(Duration::from_secs(6));
    assert_eq!(hop0.stats().datagram.transit.active_sessions, 0);

    // 6. Verify silent-Origin transit floor drain timeout (5 s REPORT_TIMEOUT):
    h0_b.a_faults.set_mtu(1_500);
    h0_b.b_faults.set_mtu(1_500);
    a_h0.a_faults.set_mtu(1_500);
    let dg2 = tr
        .spawner
        .try_block_on(origin.dial_datagram_via(dest.public_key(), "echo", 1_200, path))
        .unwrap()
        .unwrap();
    assert_eq!(hop0.stats().datagram.transit.active_sessions, 1);

    // Drop ALL packets from H0 -> A so Origin never hears DG_MTU and never sends DG_CLOSE!
    a_h0.b_faults.drop_next(100);
    h0_b.a_faults.set_mtu(1_100);
    tr.drive_until_idle();
    // At t + 4 s, H0 is STILL inside the 5 s drain window!
    tr.advance_and_drive(Duration::from_secs(4));
    assert_eq!(hop0.stats().datagram.transit.active_sessions, 1);
    // At t + 5 s+, H0 exits the drain window cleanly!
    tr.advance_and_drive(Duration::from_secs(2));
    assert_eq!(hop0.stats().datagram.transit.active_sessions, 0);
    drop(dg2);
}

// ---------------------------------------------------------------------------
// 7. Multi-Hop In-Band Datagram Renewal: Verifier Idempotency, Retryable Creds, Denial & Expiry
// ---------------------------------------------------------------------------

#[test]
fn datagram_multihop_in_band_renewal_idempotency_retry_denial_and_expiry() {
    struct CountingDestAuth {
        ttl: Duration,
        renewal_calls: AtomicUsize,
        deny_renewals: AtomicBool,
        hang_renewals: AtomicBool,
    }
    impl Authorizer for CountingDestAuth {
        fn authorize<'a>(&'a self, req: AuthRequest<'a>) -> BoxFuture<'a, Result<Lease, AuthDenied>> {
            let ttl = self.ttl;
            let is_ren = req.is_renewal;
            if is_ren {
                self.renewal_calls.fetch_add(1, Ordering::SeqCst);
            }
            let deny = is_ren && self.deny_renewals.load(Ordering::Acquire);
            let hang = is_ren && self.hang_renewals.load(Ordering::Acquire);
            Box::pin(async move {
                if hang {
                    core::future::pending::<()>().await;
                }
                if deny {
                    Err(AuthDenied::Denied)
                } else {
                    Ok(Lease::new(ttl))
                }
            })
        }
    }

    struct FlakyHopCreds {
        hop_pk: PublicKey,
        failed_once: AtomicBool,
    }
    impl CredentialProvider for FlakyHopCreds {
        fn credential<'a>(
            &'a self,
            req: CredentialRequest<'a>,
        ) -> BoxFuture<'a, Result<Credential, CoreError>> {
            Box::pin(async move {
                if req.is_refresh
                    && req.verifier == self.hop_pk
                    && !self.failed_once.swap(true, Ordering::AcqRel)
                {
                    return Err(CoreError::TargetUnreachable);
                }
                Ok(Credential::from_slice(b"dg-tok").unwrap())
            })
        }
    }

    let tr = TestRuntime::new();
    let hop0_kp = ScopeKeypair::generate();
    let dest_auth = Arc::new(CountingDestAuth {
        ttl: Duration::from_secs(12),
        renewal_calls: AtomicUsize::new(0),
        deny_renewals: AtomicBool::new(false),
        hang_renewals: AtomicBool::new(false),
    });

    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_credentials(Arc::new(FlakyHopCreds {
            hop_pk: hop0_kp.public_key(),
            failed_once: AtomicBool::new(false),
        }))
        .build();
    let hop0 = ScopeInstance::builder(hop0_kp, tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(10))))
        .build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(dest_auth.clone())
        .build();

    let a_h0 = shared_datagram_channel(1_500);
    let h0_b = shared_datagram_channel(1_500);
    origin
        .register_datagram_carrier("to_h0", a_h0.carrier.clone())
        .unwrap();
    let _t0 = hop0
        .publish_datagram_transit("to-b", static_dg_transit(h0_b.carrier.clone(), b"b".to_vec()))
        .unwrap();
    let (echo, _, _) = DatagramEchoEndpoint::new(&tr);
    let _ep = dest.publish_datagram_endpoint("echo", 1_200, echo).unwrap();

    spawn_scope_dg_listener(&tr, &hop0, a_h0.listener);
    spawn_scope_dg_listener(&tr, &dest, h0_b.listener);
    tr.drive_until_idle();

    let mut path = ExplicitPath::direct(1, "to_h0", b"h0".to_vec());
    path.hops = vec![HopSpec {
        peer: hop0.public_key(),
        target: "to-b".into(),
    }];

    let dg = tr
        .spawner
        .try_block_on(origin.dial_datagram_via(dest.public_key(), "echo", 1_200, path.clone()))
        .unwrap()
        .unwrap();

    // Advance to t = 7 s (right before Endpoint's 70–80% renewal window [8.4s, 9.6s]), then
    // arm a single drop on B -> H0 so the FIRST `DG_RENEW_OK` is lost on the wire!
    for _ in 0..70 {
        tr.advance_and_drive(Duration::from_millis(100));
    }
    h0_b.b_faults.drop_next(1);

    // Advance until Endpoint completes its first renewal (now up to t = 11.5 s).
    let mut observed_retry = false;
    for _ in 0..45 {
        tr.advance_and_drive(Duration::from_millis(100));
        if origin.stats().auth_endpoint.renewed >= 1 {
            observed_retry = origin.stats().auth_endpoint.renewal_retries >= 1;
            break;
        }
    }
    assert_eq!(origin.stats().auth_endpoint.renewed, 1);
    assert!(observed_retry, "Origin MUST have retried DG_RENEW after dropped DG_RENEW_OK");
    // Verifier idempotency: Destination's Authorizer was invoked ONLY ONCE despite duplicate delivery!
    assert_eq!(
        dest_auth.renewal_calls.load(Ordering::SeqCst),
        1,
        "Duplicate renewal_id MUST reply idempotently without re-invoking Authorizer!"
    );

    // Advance to t = 20 s to verify continuous multi-hop renewal across both Hop0 and Dest!
    for _ in 0..90 {
        tr.advance_and_drive(Duration::from_millis(100));
    }
    assert!(hop0.stats().auth_transit.renewed >= 2);
    assert!(origin.stats().auth_transit.renewal_retries >= 1);

    let alive = tr.spawner.try_block_on(async {
        dg.send(PacketBuf::from_payload(b"renewed-20s"))?;
        let r = dg.recv().await?;
        assert_eq!(r.payload(), b"renewed-20s");
        Ok::<(), CoreError>(())
    });
    assert_eq!(alive, Some(Ok(())));

    // Non-retryable AuthDenied::Denied tears down with CoreError::Denied!
    dest_auth.deny_renewals.store(true, Ordering::Release);
    let denied_err = run_with_clock(&tr, dg.recv(), Duration::from_millis(100), 150).unwrap_err();
    assert_eq!(denied_err, CoreError::Denied);

    // Hanging renewal past TTL tears down with CoreError::Expired!
    dest_auth.deny_renewals.store(false, Ordering::Release);
    dest_auth.hang_renewals.store(true, Ordering::Release);
    let dg2 = tr
        .spawner
        .try_block_on(origin.dial_datagram_via(dest.public_key(), "echo", 1_200, path))
        .unwrap()
        .unwrap();
    let exp_err = run_with_clock(&tr, dg2.recv(), Duration::from_millis(100), 150).unwrap_err();
    assert_eq!(exp_err, CoreError::Expired);
}

// ---------------------------------------------------------------------------
// 8. Plane Isolation, Control Filters (0x23..=0x27) & Graceful begin_shutdown / is_drained
// ---------------------------------------------------------------------------

#[test]
fn datagram_plane_isolation_control_filters_and_begin_shutdown() {
    struct DummyStEp;
    impl StreamEndpointHandler for DummyStEp {
        fn open(&self, _auth: SessionAuth) -> BoxFuture<'_, Result<BoxedStream, CoreError>> {
            Box::pin(async { Ok(BoxedStream::from_stream(MemoryStreamPair::pair(4096).a)) })
        }
    }
    struct DummyStTransit;
    impl StreamTransitHandler for DummyStTransit {
        fn caps(&self) -> ChannelCaps {
            ChannelCaps::fixed(4096, true)
        }
        fn open(
            &self,
            _subtarget: &str,
            _auth: SessionAuth,
        ) -> BoxFuture<'_, Result<BoxedStream, CoreError>> {
            Box::pin(async { Ok(BoxedStream::from_stream(MemoryStreamPair::pair(4096).a)) })
        }
    }

    let tr = TestRuntime::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let hop0 = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();

    let a_b = shared_datagram_channel(1_500);
    let a_h0 = shared_datagram_channel(1_500);
    let unused = shared_datagram_channel(1_500);

    origin
        .register_datagram_carrier("to_b", a_b.carrier.clone())
        .unwrap();
    origin
        .register_datagram_carrier("to_h0", a_h0.carrier.clone())
        .unwrap();
    hop0.register_datagram_carrier("outbound-only", unused.carrier.clone())
        .unwrap();

    let _st_ep = dest
        .publish_stream_endpoint("stream-only", Arc::new(DummyStEp))
        .unwrap();
    let _st_tr = hop0
        .publish_stream_transit("stream-hop", Arc::new(DummyStTransit))
        .unwrap();
    let (echo, _, _) = DatagramEchoEndpoint::new(&tr);
    let _dg_ep = dest.publish_datagram_endpoint("echo", 1_200, echo).unwrap();

    // Reject publishing a Datagram endpoint with min_mtu < DATAGRAM_MIN_MTU (1152 -> MtuTooSmall).
    assert_eq!(
        dest.publish_datagram_endpoint(
            "too-small",
            DATAGRAM_MIN_MTU - 1,
            Arc::new(DatagramEchoEndpoint {
                rt: tr.clone(),
                opens: Arc::new(AtomicUsize::new(0)),
                seen_payloads: Arc::new(Mutex::new(Vec::new())),
            }),
        )
        .unwrap_err(),
        CoreError::MtuTooSmall(DATAGRAM_MIN_MTU - 1)
    );

    spawn_scope_dg_listener(&tr, &dest, a_b.listener);
    spawn_scope_dg_listener(&tr, &hop0, a_h0.listener);
    tr.drive_until_idle();

    let res = tr.spawner.try_block_on(async {
        // Cross-plane Datagram -> Stream endpoint -> WrongPlane.
        assert_eq!(
            origin
                .dial_datagram_via(
                    dest.public_key(),
                    "stream-only",
                    1_200,
                    ExplicitPath::direct(1, "to_b", b"b".to_vec()),
                )
                .await
                .unwrap_err(),
            CoreError::WrongPlane
        );

        // Unpublished endpoint -> Unpublished.
        assert_eq!(
            origin
                .dial_datagram_via(
                    dest.public_key(),
                    "missing",
                    1_200,
                    ExplicitPath::direct(2, "to_b", b"b".to_vec()),
                )
                .await
                .unwrap_err(),
            CoreError::Unpublished
        );

        // Cross-plane Datagram -> Stream transit -> HopRejected(0, WrongPlane).
        let mut p3 = ExplicitPath::direct(3, "to_h0", b"h0".to_vec());
        p3.hops = vec![HopSpec {
            peer: hop0.public_key(),
            target: "stream-hop".into(),
        }];
        assert_eq!(
            origin
                .dial_datagram_via(dest.public_key(), "echo", 1_200, p3)
                .await
                .unwrap_err(),
            CoreError::hop_rejected(0, CoreError::WrongPlane)
        );

        // Default-deny outbound carrier isolation -> HopRejected(0, Unpublished).
        let mut p4 = ExplicitPath::direct(4, "to_h0", b"h0".to_vec());
        p4.hops = vec![HopSpec {
            peer: hop0.public_key(),
            target: "outbound-only".into(),
        }];
        assert_eq!(
            origin
                .dial_datagram_via(dest.public_key(), "echo", 1_200, p4)
                .await
                .unwrap_err(),
            CoreError::hop_rejected(0, CoreError::Unpublished)
        );

        // Establish valid direct circuit and test forged 0x23..=0x27 control packets are ignored!
        a_b.a_faults.set_capture(true);
        a_b.b_faults.set_capture(true);
        let dg = origin
            .dial_datagram_via(
                dest.public_key(),
                "echo",
                1_200,
                ExplicitPath::direct(5, "to_b", b"b".to_vec()),
            )
            .await?;
        dg.send(PacketBuf::from_payload(b"cid-probe"))?;
        assert_eq!(dg.recv().await?.payload(), b"cid-probe");

        // Extract real CIDs from captured DG_DATA (0x20) frames.
        let a_sent = a_b.a_faults.drain_captured();
        let b_sent = a_b.b_faults.drain_captured();
        let dest_cid_bytes = a_sent
            .iter()
            .find(|p| p.len() >= 5 && p.payload()[0] == 0x20)
            .unwrap()
            .payload()[1..5]
            .to_vec();
        let orig_cid_bytes = b_sent
            .iter()
            .find(|p| p.len() >= 5 && p.payload()[0] == 0x20)
            .unwrap()
            .payload()[1..5]
            .to_vec();

        // Inject forged 0x23..=0x27 toward Destination AND toward Origin (distance >= N = 0 & bad AEAD).
        for op in 0x23u8..=0x27 {
            let mut to_dest = vec![op, 0u8];
            to_dest.extend_from_slice(&dest_cid_bytes);
            to_dest.extend_from_slice(&[0xAA; 32]);
            let _ = a_b.a_link.try_send(PacketBuf::from_payload(&to_dest));

            let mut to_orig = vec![op, 0u8]; // distance = 0 >= N (0) on direct path!
            to_orig.extend_from_slice(&orig_cid_bytes);
            to_orig.extend_from_slice(&[0xBB; 32]);
            let _ = a_b.b_link.try_send(PacketBuf::from_payload(&to_orig));
        }

        // Session MUST survive all forged control frames unscathed!
        dg.send(PacketBuf::from_payload(b"still-healthy"))?;
        assert_eq!(dg.recv().await?.payload(), b"still-healthy");

        // Graceful begin_shutdown() on Destination emits e2e::DG_CLOSE(Closed) and drains!
        assert!(!dest.is_drained());
        dest.begin_shutdown();
        assert_eq!(dg.recv().await.unwrap_err(), CoreError::Closed);
        Ok::<(), CoreError>(())
    });
    assert_eq!(res, Some(Ok(())));
    tr.drive_until_idle();
    assert!(dest.is_drained());
}
