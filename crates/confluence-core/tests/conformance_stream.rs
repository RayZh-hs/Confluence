//! End-to-end deterministic Stream Plane conformance suite (Spec §§10.2–10.4).
//!
//! Uses exclusively `VirtualClock`, `FixedWallClock`, `TestSpawner`, and controllable
//! in-memory channels — zero OS sockets and zero wall-clock sleeps.

#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use confluence_core::auth::{
    AuthDenied, AuthRequest, Authorizer, CredentialProvider, CredentialRequest, Lease, SessionAuth,
};
use confluence_core::channel::{
    BoxedStream, ChannelCaps, DatagramLink, IntoStreamHalves, StreamCarrier, StreamListener,
    StreamRead, StreamReadExt, StreamWriteExt,
};
use confluence_core::constants::STREAM_MIN_MTU;
use confluence_core::handler::{
    DatagramEndpointHandler, DatagramTransitHandler, StaticTransit, StreamEndpointHandler,
    StreamTransitHandler,
};
use confluence_core::path::{ExplicitPath, HopSpec, PathOutcome, PathSource};
use confluence_core::runtime::BoxFuture;
use confluence_core::testing::{
    MemoryDatagramPair, MemoryStream, MemoryStreamPair, StreamFaults, TestRuntime,
    memory_stream_channel,
};
use confluence_core::{
    CoreError, Credential, Plane, PublicKey, ScopeInstance, ScopeKeypair, ScopeLimits,
};

fn static_stream_transit<C: StreamCarrier>(
    carrier: C,
    locator: Vec<u8>,
) -> Arc<dyn StreamTransitHandler> {
    Arc::new(StaticTransit::new(Arc::new(carrier), locator))
}

// ---------------------------------------------------------------------------
// Shared Deterministic Helpers
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

/// Echo endpoint that echoes every received byte and shuts down its write half on EOF.
struct EchoEndpoint {
    rt: TestRuntime,
    opens: Arc<AtomicUsize>,
}

impl EchoEndpoint {
    fn new(rt: &TestRuntime) -> (Arc<Self>, Arc<AtomicUsize>) {
        let opens = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(Self {
                rt: rt.clone(),
                opens: Arc::clone(&opens),
            }),
            opens,
        )
    }
}

impl StreamEndpointHandler for EchoEndpoint {
    fn open(&self, _auth: SessionAuth) -> BoxFuture<'_, Result<BoxedStream, CoreError>> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            let pair = MemoryStreamPair::pair(16_384);
            let (mut r, mut w) = pair.b.into_halves();
            self.rt.runtime.spawner.spawn(Box::pin(async move {
                let mut buf = vec![0u8; 4096];
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

/// Controllable stream channel exposing each accepted pair's `a_faults` and `b_faults`.
#[derive(Clone)]
struct ControllableStreamCarrier {
    mtu: u16,
    caps: ChannelCaps,
    tx: async_channel::Sender<MemoryStream>,
    faults: Arc<Mutex<Vec<(StreamFaults, StreamFaults)>>>,
    varying_tag: Arc<AtomicBool>,
    tag_counter: Arc<AtomicUsize>,
}

struct ControllableStreamListener {
    rx: async_channel::Receiver<MemoryStream>,
}

type StreamFaultLog = Arc<Mutex<Vec<(StreamFaults, StreamFaults)>>>;

fn controllable_stream_channel(
    mtu: u16,
) -> (
    ControllableStreamCarrier,
    ControllableStreamListener,
    StreamFaultLog,
) {
    let (tx, rx) = async_channel::unbounded();
    let faults = Arc::new(Mutex::new(Vec::new()));
    let carrier = ControllableStreamCarrier {
        mtu,
        caps: ChannelCaps::fixed(mtu, true),
        tx,
        faults: Arc::clone(&faults),
        varying_tag: Arc::new(AtomicBool::new(false)),
        tag_counter: Arc::new(AtomicUsize::new(1)),
    };
    (carrier, ControllableStreamListener { rx }, faults)
}

impl StreamCarrier for ControllableStreamCarrier {
    type Stream = MemoryStream;

    fn caps(&self) -> ChannelCaps {
        self.caps.clone()
    }

    async fn dial_stream(&self, _locator: &[u8]) -> Result<Self::Stream, CoreError> {
        let tag = if self.varying_tag.load(Ordering::Acquire) {
            let id = self.tag_counter.fetch_add(1, Ordering::AcqRel);
            let mut t = [0u8; 16];
            t[..8].copy_from_slice(&(id as u64).to_be_bytes());
            t
        } else {
            [0x42; 16]
        };
        let pair = MemoryStreamPair::with_source_tags(self.mtu, tag, tag);
        self.faults.lock().unwrap().push((pair.a_faults, pair.b_faults));
        self.tx
            .send(pair.b)
            .await
            .map_err(|_| CoreError::TargetUnreachable)?;
        Ok(pair.a)
    }
}

impl StreamListener for ControllableStreamListener {
    type Stream = MemoryStream;

    async fn accept(&self) -> Result<Self::Stream, CoreError> {
        self.rx.recv().await.map_err(|_| CoreError::Closed)
    }
}

fn spawn_scope_stream_listener<L: StreamListener>(
    rt: &TestRuntime,
    scope: &Arc<ScopeInstance>,
    listener: L,
) {
    let s = Arc::clone(scope);
    rt.runtime.spawner.spawn(Box::pin(async move {
        let _ = s.serve_stream_listener(listener).await;
    }));
}

/// Polls a future on `TestRuntime`, stepping `VirtualClock` in `step` increments up to `max_steps`
/// whenever tasks go idle.
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
// 1. Direct & Multi-Hop (A -> H0 -> H1 -> B), split() Concurrent I/O, Clean ST_FIN Half-Close
// ---------------------------------------------------------------------------

#[test]
fn stream_direct_and_multihop_split_concurrent_io_and_clean_half_close() {
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

    // Wire direct A -> B (16384) and 2-hop A -> H0 (8192) -> H1 (4096) -> B (12000).
    let (c_direct, l_direct, _) = memory_stream_channel(16_384);
    let (c_a_h0, l_h0, _) = memory_stream_channel(8_192);
    let (c_h0_h1, l_h1, _) = memory_stream_channel(4_096);
    let (c_h1_b, l_b_hop, _) = memory_stream_channel(12_000);

    origin.register_stream_carrier("direct", c_direct).unwrap();
    origin.register_stream_carrier("to_h0", c_a_h0).unwrap();

    let _t0 = hop0
        .publish_stream_transit("next-h1", static_stream_transit(c_h0_h1, b"h1".to_vec()))
        .unwrap();
    let _t1 = hop1
        .publish_stream_transit("to-dest", static_stream_transit(c_h1_b, b"b".to_vec()))
        .unwrap();

    // Custom endpoint that waits for client EOF before replying with its own trailing payload
    // to prove independent half-close semantics!
    struct HalfCloseEcho {
        rt: TestRuntime,
    }
    impl StreamEndpointHandler for HalfCloseEcho {
        fn open(&self, _auth: SessionAuth) -> BoxFuture<'_, Result<BoxedStream, CoreError>> {
            Box::pin(async {
                let pair = MemoryStreamPair::pair(16_384);
                let (mut r, mut w) = pair.b.into_halves();
                self.rt.runtime.spawner.spawn(Box::pin(async move {
                    let mut received = Vec::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        match r.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => received.extend_from_slice(&buf[..n]),
                            Err(_) => return,
                        }
                    }
                    // Peer already sent ST_FIN; server STILL writes back all bytes + trailer!
                    let _ = w.write_all(&received).await;
                    let _ = w.write_all(b"::POST_FIN_OK").await;
                    let _ = w.shutdown().await;
                }));
                Ok(BoxedStream::from_stream(pair.a))
            })
        }
    }

    let (echo_ep, _) = EchoEndpoint::new(&tr);
    let _g1 = dest.publish_stream_endpoint("echo", echo_ep).unwrap();
    let _g2 = dest
        .publish_stream_endpoint("halfclose", Arc::new(HalfCloseEcho { rt: tr.clone() }))
        .unwrap();

    spawn_scope_stream_listener(&tr, &dest, l_direct);
    spawn_scope_stream_listener(&tr, &hop0, l_h0);
    spawn_scope_stream_listener(&tr, &hop1, l_h1);
    spawn_scope_stream_listener(&tr, &dest, l_b_hop);

    // Direct flow with concurrent split() bidirectional streaming (> 40 KiB).
    let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    let res = tr.spawner.try_block_on(async {
        let direct = ExplicitPath::direct(10, "direct", b"b".to_vec());
        let st = origin.dial_stream_via(dest.public_key(), "echo", direct).await?;
        assert_eq!(st.mtu(), 16_384);

        let (mut r, mut w) = st.split();
        let to_send = payload.clone();
        let (done_tx, done_rx) = async_channel::bounded::<Result<(), CoreError>>(1);
        tr.runtime.spawner.spawn(Box::pin(async move {
            let res = async {
                w.write_all(&to_send).await?;
                w.shutdown().await?;
                Ok(())
            }
            .await;
            let _ = done_tx.send(res).await;
        }));

        let mut echoed = Vec::new();
        let mut buf = [0u8; 2048];
        loop {
            let n = r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            echoed.extend_from_slice(&buf[..n]);
        }
        assert_eq!(done_rx.recv().await.unwrap(), Ok(()));
        assert_eq!(echoed, payload);

        // Multi-hop (A -> H0 -> H1 -> B) proving min-MTU = 4096 and clean half-close after ST_FIN.
        let mut hop_path = ExplicitPath::direct(20, "to_h0", b"h0".to_vec());
        hop_path.hops = vec![
            HopSpec {
                peer: hop0.public_key(),
                target: "next-h1".into(),
            },
            HopSpec {
                peer: hop1.public_key(),
                target: "to-dest".into(),
            },
        ];
        let mut st2 = origin
            .dial_stream_via(dest.public_key(), "halfclose", hop_path)
            .await?;
        assert_eq!(st2.mtu(), 4_096);
        st2.write_all(b"multihop-data").await?;
        st2.shutdown().await?;

        let mut reply = Vec::new();
        loop {
            let n = st2.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            reply.extend_from_slice(&buf[..n]);
        }
        assert_eq!(reply, b"multihop-data::POST_FIN_OK");
        Ok::<(), CoreError>(())
    });
    assert_eq!(res, Some(Ok(())));
    tr.drive_until_idle();

    let recorded = outcomes.snapshot();
    assert!(recorded.contains(&(10, PathOutcome::Established { mtu: 16_384 })));
    assert!(recorded.contains(&(10, PathOutcome::Closed)));
    assert!(recorded.contains(&(20, PathOutcome::Established { mtu: 4_096 })));
    assert!(recorded.contains(&(20, PathOutcome::Closed)));
}

// ---------------------------------------------------------------------------
// 2. Abrupt Carrier EOF -> UnexpectedEof & Transit Downstream EOF -> HopRejected(0, UnexpectedEof)
// ---------------------------------------------------------------------------

#[test]
fn stream_abrupt_eof_and_transit_downstream_eof_propagation() {
    let tr = TestRuntime::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let hop0 = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();

    let (c_direct, l_direct, f_direct) = controllable_stream_channel(4096);
    let (c_a_h0, l_h0, _f_a_h0) = controllable_stream_channel(4096);
    let (c_h0_b, l_b_hop, f_h0_b) = controllable_stream_channel(4096);

    origin.register_stream_carrier("direct", c_direct).unwrap();
    origin.register_stream_carrier("to_h0", c_a_h0).unwrap();
    let _t = hop0
        .publish_stream_transit("to-b", static_stream_transit(c_h0_b, b"b".to_vec()))
        .unwrap();
    let (echo, _) = EchoEndpoint::new(&tr);
    let _g = dest.publish_stream_endpoint("echo", echo).unwrap();

    spawn_scope_stream_listener(&tr, &dest, l_direct);
    spawn_scope_stream_listener(&tr, &hop0, l_h0);
    spawn_scope_stream_listener(&tr, &dest, l_b_hop);

    // Part A: Direct abrupt carrier EOF before ST_FIN -> UnexpectedEof.
    let res = tr.spawner.try_block_on(async {
        let path = ExplicitPath::direct(1, "direct", b"b".to_vec());
        let mut st = origin.dial_stream_via(dest.public_key(), "echo", path).await?;
        let (_a_f, b_f) = f_direct.lock().unwrap()[0].clone();
        b_f.inject_abrupt_eof();
        let mut buf = [0u8; 16];
        let err = st.read(&mut buf).await.unwrap_err();
        assert_eq!(err, CoreError::UnexpectedEof);
        Ok::<(), CoreError>(())
    });
    assert_eq!(res, Some(Ok(())));

    // Part B: Transit downstream abrupt EOF -> H0 emits hop::ST_CLOSE(UnexpectedEof) upstream.
    let res2 = tr.spawner.try_block_on(async {
        let mut path = ExplicitPath::direct(2, "to_h0", b"h0".to_vec());
        path.hops = vec![HopSpec {
            peer: hop0.public_key(),
            target: "to-b".into(),
        }];
        let mut st = origin.dial_stream_via(dest.public_key(), "echo", path).await?;
        let (_a_f, b_f) = f_h0_b.lock().unwrap()[0].clone();
        b_f.inject_abrupt_eof();
        let mut buf = [0u8; 16];
        let err = st.read(&mut buf).await.unwrap_err();
        assert_eq!(err, CoreError::hop_rejected(0, CoreError::UnexpectedEof));
        Ok::<(), CoreError>(())
    });
    assert_eq!(res2, Some(Ok(())));
}

// ---------------------------------------------------------------------------
// 3. Staged 1.0 RTT Deferred Open: Confirm vs Drop-Abort (Zero Handler Opens)
// ---------------------------------------------------------------------------

#[test]
fn stream_staged_deferred_open_confirm_and_drop_abort() {
    let tr = TestRuntime::new();
    let outcomes = RecordingPathSource::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_path_source(outcomes.clone())
        .build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();

    let (carrier, listener, _) = memory_stream_channel(8_192);
    origin.register_stream_carrier("mem", carrier).unwrap();
    let (echo, opens) = EchoEndpoint::new(&tr);
    let _g = dest.publish_stream_endpoint("echo", echo).unwrap();
    spawn_scope_stream_listener(&tr, &dest, listener);

    let res = tr.spawner.try_block_on(async {
        // Stage #1: verify 0 handler invocations, then drop-abort cleanly.
        let staged1 = origin
            .dial_stream_staged_via(
                dest.public_key(),
                "echo",
                ExplicitPath::direct(101, "mem", b"b".to_vec()),
            )
            .await?;
        assert_eq!(staged1.mtu(), 8_192);
        assert_eq!(opens.load(Ordering::SeqCst), 0);
        drop(staged1);
        Ok::<(), CoreError>(())
    });
    assert_eq!(res, Some(Ok(())));
    tr.drive_until_idle();
    assert_eq!(opens.load(Ordering::SeqCst), 0);
    assert_eq!(dest.stats().pending_setups, 0);
    assert!(outcomes.snapshot().contains(&(101, PathOutcome::Closed)));

    // Stage #2: confirm invokes handler exactly once and establishes stream.
    let res2 = tr.spawner.try_block_on(async {
        let staged2 = origin
            .dial_stream_staged_via(
                dest.public_key(),
                "echo",
                ExplicitPath::direct(102, "mem", b"b".to_vec()),
            )
            .await?;
        assert_eq!(opens.load(Ordering::SeqCst), 0);
        let mut st = staged2.confirm().await?;
        assert_eq!(opens.load(Ordering::SeqCst), 1);
        st.write_all(b"ok").await?;
        st.shutdown().await?;
        let mut out = [0u8; 2];
        st.read_exact(&mut out).await?;
        assert_eq!(&out, b"ok");
        assert_eq!(st.read(&mut out).await?, 0);
        Ok::<(), CoreError>(())
    });
    assert_eq!(res2, Some(Ok(())));
    assert!(
        outcomes
            .snapshot()
            .contains(&(102, PathOutcome::Established { mtu: 8_192 }))
    );
}

// ---------------------------------------------------------------------------
// 4. Stream Destination Handler Errors -> TARGET_REFUSED / BUSY / DENIED / UNREACHABLE
// ---------------------------------------------------------------------------

#[test]
fn stream_destination_open_status_error_mapping() {
    struct FailHandler(CoreError);
    impl StreamEndpointHandler for FailHandler {
        fn open(&self, _auth: SessionAuth) -> BoxFuture<'_, Result<BoxedStream, CoreError>> {
            let err = self.0.clone();
            Box::pin(async move { Err(err) })
        }
    }

    let tr = TestRuntime::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();

    let (carrier, listener, _) = memory_stream_channel(4_096);
    origin.register_stream_carrier("mem", carrier).unwrap();
    let _g1 = dest
        .publish_stream_endpoint("refused", Arc::new(FailHandler(CoreError::TargetRefused)))
        .unwrap();
    let _g2 = dest
        .publish_stream_endpoint("busy", Arc::new(FailHandler(CoreError::Busy)))
        .unwrap();
    let _g3 = dest
        .publish_stream_endpoint("denied", Arc::new(FailHandler(CoreError::Denied)))
        .unwrap();
    let _g4 = dest
        .publish_stream_endpoint("other", Arc::new(FailHandler(CoreError::Carrier("boom".into()))))
        .unwrap();
    spawn_scope_stream_listener(&tr, &dest, listener);

    let cases = [
        ("refused", CoreError::TargetRefused),
        ("busy", CoreError::Busy),
        ("denied", CoreError::Denied),
        ("other", CoreError::TargetUnreachable),
    ];

    for (idx, (ep, expected)) in cases.into_iter().enumerate() {
        let res = tr.spawner.try_block_on(async {
            origin
                .dial_stream_via(
                    dest.public_key(),
                    ep,
                    ExplicitPath::direct(idx as u64 + 1, "mem", b"b".to_vec()),
                )
                .await
        });
        assert_eq!(res.unwrap().unwrap_err(), expected, "endpoint {ep}");
    }
}

// ---------------------------------------------------------------------------
// 5. Spoofed Cleartext SETUP_OK.reverse_mtu Ignored in Favor of Authenticated Trailers
// ---------------------------------------------------------------------------

#[test]
fn stream_spoofed_cleartext_reverse_mtu_ignored() {
    struct SpoofingRead {
        inner: confluence_core::testing::MemoryStreamRead,
        spoofed: bool,
        buf: VecDeque<u8>,
    }

    impl StreamRead for SpoofingRead {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            dst: &mut [u8],
        ) -> Poll<Result<usize, CoreError>> {
            if !self.buf.is_empty() {
                let n = dst.len().min(self.buf.len());
                for slot in dst.iter_mut().take(n) {
                    *slot = self.buf.pop_front().unwrap();
                }
                return Poll::Ready(Ok(n));
            }
            let mut tmp = [0u8; 4096];
            match Pin::new(&mut self.inner).poll_read(cx, &mut tmp) {
                Poll::Ready(Ok(n)) if n > 0 => {
                    if !self.spoofed && n >= 4 && tmp[0] == 0x12 {
                        // Tamper cleartext reverse_mtu (bytes 2..4) to spoofed huge value 60000!
                        tmp[2..4].copy_from_slice(&60_000u16.to_be_bytes());
                        self.spoofed = true;
                    }
                    self.buf.extend(&tmp[..n]);
                    let take = dst.len().min(self.buf.len());
                    for slot in dst.iter_mut().take(take) {
                        *slot = self.buf.pop_front().unwrap();
                    }
                    Poll::Ready(Ok(take))
                }
                other => other,
            }
        }
    }

    struct SpoofedStream(MemoryStream);
    impl IntoStreamHalves for SpoofedStream {
        type Read = SpoofingRead;
        type Write = confluence_core::testing::MemoryStreamWrite;
        fn caps(&self) -> ChannelCaps {
            self.0.caps()
        }
        fn into_halves(self) -> (Self::Read, Self::Write) {
            let (r, w) = self.0.into_halves();
            (
                SpoofingRead {
                    inner: r,
                    spoofed: false,
                    buf: VecDeque::new(),
                },
                w,
            )
        }
    }

    struct SpoofingCarrier(confluence_core::testing::MemoryStreamCarrier);
    impl StreamCarrier for SpoofingCarrier {
        type Stream = SpoofedStream;
        fn caps(&self) -> ChannelCaps {
            self.0.caps()
        }
        async fn dial_stream(&self, locator: &[u8]) -> Result<Self::Stream, CoreError> {
            Ok(SpoofedStream(self.0.dial_stream(locator).await?))
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

    // A->H0 is 12000 (with MITM spoofing reverse_mtu=60000); H0->B is 3072.
    let (c_a_h0, l_h0, _) = memory_stream_channel(12_000);
    let (c_h0_b, l_b, _) = memory_stream_channel(3_072);

    origin
        .register_stream_carrier("spoof", SpoofingCarrier(c_a_h0))
        .unwrap();
    let _t = hop0
        .publish_stream_transit("to-b", static_stream_transit(c_h0_b, b"b".to_vec()))
        .unwrap();
    let (echo, _) = EchoEndpoint::new(&tr);
    let _g = dest.publish_stream_endpoint("echo", echo).unwrap();

    spawn_scope_stream_listener(&tr, &hop0, l_h0);
    spawn_scope_stream_listener(&tr, &dest, l_b);

    let res = tr.spawner.try_block_on(async {
        let mut path = ExplicitPath::direct(1, "spoof", b"h0".to_vec());
        path.hops = vec![HopSpec {
            peer: hop0.public_key(),
            target: "to-b".into(),
        }];
        let staged = origin
            .dial_stream_staged_via(dest.public_key(), "echo", path)
            .await?;
        // MUST use authenticated hop trailer + Noise reply MTU (3072), NOT spoofed 60000!
        assert_eq!(staged.mtu(), 3_072);
        Ok::<(), CoreError>(())
    });
    assert_eq!(res, Some(Ok(())));
}

// ---------------------------------------------------------------------------
// 6. Live MtuWatch Drop Shrinks Outgoing Chunks Without Changing max_write_size; Floor Terminates
// ---------------------------------------------------------------------------

#[test]
fn stream_live_mtu_drop_shrinks_chunks_and_floor_terminates() {
    let tr = TestRuntime::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();

    let (carrier, listener, faults) = controllable_stream_channel(8_192);
    origin.register_stream_carrier("mem", carrier).unwrap();
    let (echo, _) = EchoEndpoint::new(&tr);
    let _g = dest.publish_stream_endpoint("echo", echo).unwrap();
    spawn_scope_stream_listener(&tr, &dest, listener);

    let res = tr.spawner.try_block_on(async {
        let mut path = ExplicitPath::direct(1, "mem", b"b".to_vec());
        path.min_mtu = 1_024;
        let mut st = origin.dial_stream_via(dest.public_key(), "echo", path).await?;
        let orig_max_write = st.max_write_size();
        assert_eq!(orig_max_write, 8_192 - 19);

        let (a_f, _b_f) = faults.lock().unwrap()[0].clone();
        // Drop live MTU to 1500 (>= path.min_mtu 1024): max_write_size stays fixed, writes still work.
        a_f.set_mtu(1_500);
        assert_eq!(st.max_write_size(), orig_max_write);
        let msg = vec![0xAB; 5_000];
        st.write_all(&msg).await?;
        let mut out = vec![0u8; 5_000];
        st.read_exact(&mut out).await?;
        assert_eq!(out, msg);

        // Drop live MTU strictly below floor (1024) -> terminates with MtuTooSmall(900)!
        a_f.set_mtu(900);
        let mut buf = [0u8; 16];
        let err = st.read(&mut buf).await.unwrap_err();
        assert_eq!(err, CoreError::MtuTooSmall(900));

        // Also verify default STREAM_MIN_MTU (20) floor termination when path.min_mtu == 0.
        let mut st2 = origin
            .dial_stream_via(
                dest.public_key(),
                "echo",
                ExplicitPath::direct(2, "mem", b"b".to_vec()),
            )
            .await?;
        let (a_f2, _) = faults.lock().unwrap()[1].clone();
        a_f2.set_mtu(STREAM_MIN_MTU - 1);
        let err2 = st2.read(&mut buf).await.unwrap_err();
        assert_eq!(err2, CoreError::MtuTooSmall(STREAM_MIN_MTU - 1));
        Ok::<(), CoreError>(())
    });
    assert_eq!(res, Some(Ok(())));
}

// ---------------------------------------------------------------------------
// 7. Stream write_frame Retryable Partial-Write Backoff & 3 s Budget Timeout
// ---------------------------------------------------------------------------

#[test]
fn stream_write_frame_retryable_partial_write_backoff_and_3s_budget() {
    let tr = TestRuntime::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();

    let (carrier, listener, faults) = controllable_stream_channel(4_096);
    origin.register_stream_carrier("mem", carrier).unwrap();
    let (echo, _) = EchoEndpoint::new(&tr);
    let _g = dest.publish_stream_endpoint("echo", echo).unwrap();
    spawn_scope_stream_listener(&tr, &dest, listener);

    // Part A: Partial writes (7 B) + 6 consecutive retryable errors (510 ms < 3 s budget) succeed!
    let ok = run_with_clock(
        &tr,
        async {
            let mut st = origin
                .dial_stream_via(
                    dest.public_key(),
                    "echo",
                    ExplicitPath::direct(1, "mem", b"b".to_vec()),
                )
                .await?;
            let (a_f, _b_f) = faults.lock().unwrap()[0].clone();
            a_f.set_max_write_chunk(Some(7));
            a_f.inject_retryable_write_errors(6);

            let msg = b"partial-write-resumes-across-retryable-errors";
            st.write_all(msg).await?;
            st.shutdown().await?;
            let mut out = vec![0u8; msg.len()];
            st.read_exact(&mut out).await?;
            assert_eq!(out, msg);
            assert_eq!(st.read(&mut out).await?, 0);
            Ok::<(), CoreError>(())
        },
        Duration::from_millis(10),
        100,
    );
    assert_eq!(ok, Ok(()));

    // Part B: Retryable errors exceeding the 3 s budget fail cleanly with CoreError::Timeout!
    let err = run_with_clock(
        &tr,
        async {
            let mut st = origin
                .dial_stream_via(
                    dest.public_key(),
                    "echo",
                    ExplicitPath::direct(2, "mem", b"b".to_vec()),
                )
                .await?;
            let (a_f, _b_f) = faults.lock().unwrap()[1].clone();
            a_f.inject_retryable_write_errors(100);
            st.write_all(b"will-timeout").await?;
            st.flush().await
        },
        Duration::from_millis(50),
        100,
    );
    assert_eq!(err, Err(CoreError::Timeout));
}

// ---------------------------------------------------------------------------
// 8. Cross-Plane WrongPlane, Unpublished & Outbound Carrier Isolation (Default-Deny)
// ---------------------------------------------------------------------------

#[test]
fn stream_plane_isolation_unpublished_and_default_deny_outbound_carrier() {
    struct DummyDgEp;
    impl DatagramEndpointHandler for DummyDgEp {
        fn open(&self, _auth: SessionAuth) -> BoxFuture<'_, Result<Arc<dyn DatagramLink>, CoreError>> {
            Box::pin(async { Ok(Arc::new(MemoryDatagramPair::pair(1400).a) as Arc<dyn DatagramLink>) })
        }
    }
    struct DummyDgTransit;
    impl DatagramTransitHandler for DummyDgTransit {
        fn caps(&self) -> ChannelCaps {
            ChannelCaps::fixed(1400, false)
        }
        fn open(
            &self,
            _subtarget: &str,
            _auth: SessionAuth,
        ) -> BoxFuture<'_, Result<Arc<dyn DatagramLink>, CoreError>> {
            Box::pin(async { Ok(Arc::new(MemoryDatagramPair::pair(1400).a) as Arc<dyn DatagramLink>) })
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

    let (c_a_b, l_b, _) = memory_stream_channel(4096);
    let (c_a_h0, l_h0, _) = memory_stream_channel(4096);
    let (c_unused, _l_unused, _) = memory_stream_channel(4096);

    origin.register_stream_carrier("to_b", c_a_b).unwrap();
    origin.register_stream_carrier("to_h0", c_a_h0).unwrap();
    // Registering outbound carrier on hop0 MUST NOT publish inbound transit!
    hop0.register_stream_carrier("outbound-only", c_unused)
        .unwrap();

    let _dg_ep = dest
        .publish_datagram_endpoint("dg-only", 1200, Arc::new(DummyDgEp))
        .unwrap();
    let _dg_tr = hop0
        .publish_datagram_transit("dg-hop", Arc::new(DummyDgTransit))
        .unwrap();

    spawn_scope_stream_listener(&tr, &dest, l_b);
    spawn_scope_stream_listener(&tr, &hop0, l_h0);

    let res = tr.spawner.try_block_on(async {
        // Stream dial to Datagram endpoint -> WrongPlane.
        let e1 = origin
            .dial_stream_via(
                dest.public_key(),
                "dg-only",
                ExplicitPath::direct(1, "to_b", b"b".to_vec()),
            )
            .await
            .unwrap_err();
        assert_eq!(e1, CoreError::WrongPlane);

        // Stream dial to unpublished endpoint -> Unpublished.
        let e2 = origin
            .dial_stream_via(
                dest.public_key(),
                "missing",
                ExplicitPath::direct(2, "to_b", b"b".to_vec()),
            )
            .await
            .unwrap_err();
        assert_eq!(e2, CoreError::Unpublished);

        // Stream dial through Datagram-only transit -> HopRejected(0, WrongPlane).
        let mut p3 = ExplicitPath::direct(3, "to_h0", b"h0".to_vec());
        p3.hops = vec![HopSpec {
            peer: hop0.public_key(),
            target: "dg-hop".into(),
        }];
        let e3 = origin
            .dial_stream_via(dest.public_key(), "dg-only", p3)
            .await
            .unwrap_err();
        assert_eq!(e3, CoreError::hop_rejected(0, CoreError::WrongPlane));

        // Outbound carrier registered on hop0 is NOT an inbound transit -> HopRejected(0, Unpublished).
        let mut p4 = ExplicitPath::direct(4, "to_h0", b"h0".to_vec());
        p4.hops = vec![HopSpec {
            peer: hop0.public_key(),
            target: "outbound-only".into(),
        }];
        let e4 = origin
            .dial_stream_via(dest.public_key(), "missing", p4)
            .await
            .unwrap_err();
        assert_eq!(e4, CoreError::hop_rejected(0, CoreError::Unpublished));
        Ok::<(), CoreError>(())
    });
    assert_eq!(res, Some(Ok(())));
}

// ---------------------------------------------------------------------------
// 9. Multi-Hop SETUP_COOKIE, Duplicate Challenge -> CookieRequired, Auto Hysteresis (75/25/5s)
// ---------------------------------------------------------------------------

#[test]
fn stream_multihop_cookie_retry_duplicate_challenge_and_load_hysteresis() {
    let tr = TestRuntime::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let hop0 = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .with_limits(ScopeLimits {
            max_pending: 4,
            max_sessions: 32,
            max_datagram_ports: 16,
        })
        .build();

    let (c_a_h0, l_h0, _) = controllable_stream_channel(4096);
    let (c_h0_b, l_b, _) = controllable_stream_channel(4096);
    let (c_a_b, l_b_direct, _) = controllable_stream_channel(4096);

    origin.register_stream_carrier("to_h0", c_a_h0.clone()).unwrap();
    origin.register_stream_carrier("to_b", c_a_b.clone()).unwrap();
    let _t = hop0
        .publish_stream_transit("to-b", static_stream_transit(c_h0_b, b"b".to_vec()))
        .unwrap();
    let (echo, _) = EchoEndpoint::new(&tr);
    let _g = dest.publish_stream_endpoint("echo", echo).unwrap();

    spawn_scope_stream_listener(&tr, &hop0, l_h0);
    spawn_scope_stream_listener(&tr, &dest, l_b);
    spawn_scope_stream_listener(&tr, &dest, l_b_direct);

    // Force BOTH hop0 and dest under load -> multi-hop succeeds after 2 sequential cookie challenges.
    hop0.set_under_load(Some(true));
    dest.set_under_load(Some(true));

    let res = tr.spawner.try_block_on(async {
        let mut path = ExplicitPath::direct(1, "to_h0", b"h0".to_vec());
        path.hops = vec![HopSpec {
            peer: hop0.public_key(),
            target: "to-b".into(),
        }];
        let mut st = origin.dial_stream_via(dest.public_key(), "echo", path).await?;
        st.write_all(b"cookie-ok").await?;
        st.shutdown().await?;
        let mut out = [0u8; 9];
        st.read_exact(&mut out).await?;
        assert_eq!(&out, b"cookie-ok");
        assert_eq!(st.read(&mut out).await?, 0);
        Ok::<(), CoreError>(())
    });
    assert_eq!(res, Some(Ok(())));
    assert_eq!(hop0.stats().mac2_challenges_total, 1);
    assert_eq!(dest.stats().mac2_challenges_total, 1);

    // Varying source_tag per dial causes the same responder to challenge twice -> CookieRequired!
    c_a_b.varying_tag.store(true, Ordering::Release);
    let err = tr.spawner.try_block_on(async {
        origin
            .dial_stream_via(
                dest.public_key(),
                "echo",
                ExplicitPath::direct(2, "to_b", b"b".to_vec()),
            )
            .await
    });
    assert_eq!(err.unwrap().unwrap_err(), CoreError::CookieRequired);
    c_a_b.varying_tag.store(false, Ordering::Release);

    // Clear manual override & test automatic 75% / 25% / 5s hysteresis on dest (max_pending = 4).
    dest.set_under_load(None);
    assert!(!dest.stats().under_load);

    // Hold 4 staged (AwaitingConfirm) connections -> pending_setups = 4/4 (> 75%!) -> under_load ON!
    // Wait: on 4th setup (when 3 are already pending = 75%), let's hold 4 with max_pending = 4.
    // Note: while 3 are held (3/4 = 75%), when the 4th enters `update_load()`, `pending.in_use() == 4`
    // (100% > 75%) -> triggers under_load = true AND challenges the 4th!
    let staged_res = tr.spawner.try_block_on(async {
        let s1 = origin
            .dial_stream_staged_via(
                dest.public_key(),
                "echo",
                ExplicitPath::direct(10, "to_b", b"b".to_vec()),
            )
            .await?;
        let s2 = origin
            .dial_stream_staged_via(
                dest.public_key(),
                "echo",
                ExplicitPath::direct(11, "to_b", b"b".to_vec()),
            )
            .await?;
        let s3 = origin
            .dial_stream_staged_via(
                dest.public_key(),
                "echo",
                ExplicitPath::direct(12, "to_b", b"b".to_vec()),
            )
            .await?;
        // 3/4 = 75% is NOT strictly > 75%, so still false until the 4th arrives!
        assert!(!dest.stats().under_load);
        let s4 = origin
            .dial_stream_staged_via(
                dest.public_key(),
                "echo",
                ExplicitPath::direct(13, "to_b", b"b".to_vec()),
            )
            .await?;
        // 4th setup observed 4/4 (100% > 75%), flipped under_load ON, challenged, and succeeded on retry!
        assert!(dest.stats().under_load);
        drop((s1, s2, s3, s4));
        Ok::<(), CoreError>(())
    });
    assert_eq!(staged_res, Some(Ok(())));
    tr.drive_until_idle();
    assert_eq!(dest.stats().pending_setups, 0);

    // Probe at t + 0s (starts low-water timer at <= 25%) -> still under_load == true.
    let probe = |id: u64| {
        let r = tr.spawner.try_block_on(async {
            origin
                .dial_stream_staged_via(
                    dest.public_key(),
                    "echo",
                    ExplicitPath::direct(id, "to_b", b"b".to_vec()),
                )
                .await
        });
        drop(r);
        tr.drive_until_idle();
    };
    probe(20);
    assert!(dest.stats().under_load);

    // Advance 4.9 s -> STILL under_load == true!
    tr.advance_and_drive(Duration::from_millis(4_900));
    probe(21);
    assert!(dest.stats().under_load);

    // Advance remaining 100 ms (total 5.0 s at <= 25%) -> clears under_load == false!
    tr.advance_and_drive(Duration::from_millis(100));
    probe(22);
    assert!(!dest.stats().under_load);
}

// ---------------------------------------------------------------------------
// 10. Multi-Hop In-Band Stream Lease Renewal, Retryable Cred Failure, Denial & Expiry
// ---------------------------------------------------------------------------

#[test]
fn stream_multihop_in_band_renewal_retry_denial_and_expiry() {
    struct FlakyCreds {
        fail_first_refresh_for: PublicKey,
        failed_once: AtomicBool,
    }
    impl CredentialProvider for FlakyCreds {
        fn credential<'a>(
            &'a self,
            req: CredentialRequest<'a>,
        ) -> BoxFuture<'a, Result<Credential, CoreError>> {
            Box::pin(async move {
                if req.is_refresh
                    && req.verifier == self.fail_first_refresh_for
                    && !self.failed_once.swap(true, Ordering::AcqRel)
                {
                    return Err(CoreError::TargetUnreachable);
                }
                Ok(Credential::from_slice(b"tok").unwrap())
            })
        }
    }

    struct ToggleAuth {
        ttl: Duration,
        deny_renewals: AtomicBool,
        hang_renewals: AtomicBool,
    }
    impl Authorizer for ToggleAuth {
        fn authorize<'a>(&'a self, req: AuthRequest<'a>) -> BoxFuture<'a, Result<Lease, AuthDenied>> {
            let ttl = self.ttl;
            let deny = req.is_renewal && self.deny_renewals.load(Ordering::Acquire);
            let hang = req.is_renewal && self.hang_renewals.load(Ordering::Acquire);
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

    let tr = TestRuntime::new();
    let hop0_kp = ScopeKeypair::generate();
    let hop0_pk = hop0_kp.public_key();
    let creds = Arc::new(FlakyCreds {
        fail_first_refresh_for: hop0_pk,
        failed_once: AtomicBool::new(false),
    });
    let hop_auth = Arc::new(ToggleAuth {
        ttl: Duration::from_secs(10),
        deny_renewals: AtomicBool::new(false),
        hang_renewals: AtomicBool::new(false),
    });
    let dest_auth = Arc::new(ToggleAuth {
        ttl: Duration::from_secs(12),
        deny_renewals: AtomicBool::new(false),
        hang_renewals: AtomicBool::new(false),
    });

    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_credentials(creds)
        .build();
    let hop0 = ScopeInstance::builder(hop0_kp, tr.runtime.clone())
        .with_authorizer(hop_auth.clone())
        .build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(dest_auth.clone())
        .build();

    let (c_a_h0, l_h0, _) = memory_stream_channel(4096);
    let (c_h0_b, l_b, _) = memory_stream_channel(4096);
    origin.register_stream_carrier("to_h0", c_a_h0).unwrap();
    let _t = hop0
        .publish_stream_transit("to-b", static_stream_transit(c_h0_b, b"b".to_vec()))
        .unwrap();
    let (echo, _) = EchoEndpoint::new(&tr);
    let _g = dest.publish_stream_endpoint("echo", echo).unwrap();

    spawn_scope_stream_listener(&tr, &hop0, l_h0);
    spawn_scope_stream_listener(&tr, &dest, l_b);

    // Establish A -> H0 -> B and advance 20 s (well past both initial 10 s and 12 s TTLs!).
    let mut path = ExplicitPath::direct(1, "to_h0", b"h0".to_vec());
    path.hops = vec![HopSpec {
        peer: hop0.public_key(),
        target: "to-b".into(),
    }];

    let mut st = tr
        .spawner
        .try_block_on(origin.dial_stream_via(dest.public_key(), "echo", path.clone()))
        .unwrap()
        .unwrap();

    for _ in 0..200 {
        tr.advance_and_drive(Duration::from_millis(100));
    }

    // Both Hop0 (after 1 retryable credential error) and Dest renewed seamlessly!
    assert!(hop0.stats().auth_transit.renewed >= 2);
    assert!(dest.stats().auth_endpoint.renewed >= 1);
    assert!(origin.stats().auth_transit.renewal_retries >= 1);

    // Traffic still flows cleanly at t = 20 s!
    let echo_ok = tr.spawner.try_block_on(async {
        st.write_all(b"still-alive").await?;
        let mut buf = [0u8; 11];
        st.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"still-alive");
        Ok::<(), CoreError>(())
    });
    assert_eq!(echo_ok, Some(Ok(())));

    // Now flip Destination to reject renewals with Denied -> session terminates with Denied!
    dest_auth.deny_renewals.store(true, Ordering::Release);
    let err = run_with_clock(
        &tr,
        async {
            let mut buf = [0u8; 16];
            st.read(&mut buf).await
        },
        Duration::from_millis(100),
        150,
    )
    .unwrap_err();
    assert_eq!(err, CoreError::Denied);
    assert!(dest.stats().auth_endpoint.renewal_failures >= 1);

    // Now test Expiry teardown when Destination hangs renewals past TTL.
    dest_auth.deny_renewals.store(false, Ordering::Release);
    dest_auth.hang_renewals.store(true, Ordering::Release);
    let mut st2 = tr
        .spawner
        .try_block_on(origin.dial_stream_via(dest.public_key(), "echo", path))
        .unwrap()
        .unwrap();
    let exp_err = run_with_clock(
        &tr,
        async {
            let mut buf = [0u8; 16];
            st2.read(&mut buf).await
        },
        Duration::from_millis(100),
        150,
    )
    .unwrap_err();
    assert_eq!(exp_err, CoreError::Expired);
}

// ---------------------------------------------------------------------------
// 11. Graceful begin_shutdown(): ST_FIN with No Artificial Drain Timeout + is_drained()
// ---------------------------------------------------------------------------

#[test]
fn stream_graceful_begin_shutdown_no_drain_timeout_and_is_drained() {
    let tr = TestRuntime::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(120))))
        .build();

    let (carrier, listener, _) = memory_stream_channel(4_096);
    origin.register_stream_carrier("mem", carrier).unwrap();

    // Endpoint that reads until EOF (so it stays open until Origin sends ST_FIN).
    let received_by_dest = Arc::new(Mutex::new(Vec::<u8>::new()));
    struct SinkEp {
        rt: TestRuntime,
        sink: Arc<Mutex<Vec<u8>>>,
    }
    impl StreamEndpointHandler for SinkEp {
        fn open(&self, _auth: SessionAuth) -> BoxFuture<'_, Result<BoxedStream, CoreError>> {
            let sink = Arc::clone(&self.sink);
            Box::pin(async move {
                let pair = MemoryStreamPair::pair(4_096);
                let (mut r, mut w) = pair.b.into_halves();
                self.rt.runtime.spawner.spawn(Box::pin(async move {
                    let mut buf = [0u8; 128];
                    while let Ok(n) = r.read(&mut buf).await {
                        if n == 0 {
                            let _ = w.shutdown().await;
                            break;
                        }
                        sink.lock().unwrap().extend_from_slice(&buf[..n]);
                    }
                }));
                Ok(BoxedStream::from_stream(pair.a))
            })
        }
    }

    let _g = dest
        .publish_stream_endpoint(
            "sink",
            Arc::new(SinkEp {
                rt: tr.clone(),
                sink: Arc::clone(&received_by_dest),
            }),
        )
        .unwrap();
    spawn_scope_stream_listener(&tr, &dest, listener);

    let mut st = tr
        .spawner
        .try_block_on(origin.dial_stream_via(
            dest.public_key(),
            "sink",
            ExplicitPath::direct(1, "mem", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();

    assert!(!dest.is_drained());
    dest.begin_shutdown();
    assert!(!dest.stats().accepting);
    assert!(!dest.is_drained());

    // New admissions are rejected with Closed.
    let reject = tr.spawner.try_block_on(dest.dial_stream_via(
        origin.public_key(),
        "x",
        ExplicitPath::direct(2, "mem", b"a".to_vec()),
    ));
    assert_eq!(reject.unwrap().unwrap_err(), CoreError::Closed);

    // Destination initiated ST_FIN -> Origin sees Ok(0) immediately!
    let eof = tr.spawner.try_block_on(async {
        let mut buf = [0u8; 8];
        st.read(&mut buf).await
    });
    assert_eq!(eof, Some(Ok(0)));

    // Advance 30 s (no artificial drain timeout!): Destination STILL awaits Origin's ST_FIN!
    for _ in 0..30 {
        tr.advance_and_drive(Duration::from_secs(1));
    }
    assert!(!dest.is_drained());

    // Origin can still finish sending trailing bytes and then send ST_FIN.
    let finish = tr.spawner.try_block_on(async {
        st.write_all(b"graceful-tail").await?;
        st.shutdown().await?;
        Ok::<(), CoreError>(())
    });
    assert_eq!(finish, Some(Ok(())));
    tr.drive_until_idle();

    assert_eq!(*received_by_dest.lock().unwrap(), b"graceful-tail");
    assert!(dest.is_drained());
}
