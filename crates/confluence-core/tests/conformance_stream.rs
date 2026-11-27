//! End-to-end deterministic Stream Plane conformance suite (Spec §§10.2–10.4).
//!
//! Uses exclusively `VirtualClock`, `FixedWallClock`, `TestSpawner`, and controllable
//! in-memory channels — zero OS sockets and zero wall-clock sleeps.

#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use confluence_core::auth::{
    AuthDenied, AuthRequest, Authorizer, CredentialProvider, CredentialRequest, Lease, SessionAuth,
};
use confluence_core::channel::{
    BoxedStream, ChannelCaps, DatagramLink, IntoStreamHalves, StreamCarrier, StreamListener,
    StreamRead, StreamReadExt, StreamWrite, StreamWriteExt,
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

// ---------------------------------------------------------------------------
// Regression Tests for Codex Round 1 Stream Engine Fixes (ST-01 .. ST-09)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct PipeControlState {
    stall_writes: bool,
    retryable_then_stall: bool,
    retryable_fired: bool,
    partial_bytes_before_stall: Option<usize>,
    pause_reads: bool,
    hold_eof: bool,
    sink_writes_after_close: bool,
    write_waker: Option<Waker>,
    read_waker: Option<Waker>,
    read_dropped: bool,
    write_dropped: bool,
}

#[derive(Clone, Default)]
struct PipeControl(Arc<Mutex<PipeControlState>>);

impl PipeControl {
    fn set_stall_writes(&self, stall: bool) {
        let w = {
            let mut st = self.0.lock().unwrap();
            st.stall_writes = stall;
            if !stall {
                st.write_waker.take()
            } else {
                None
            }
        };
        if let Some(w) = w {
            w.wake();
        }
    }

    fn set_partial_then_stall(&self, bytes: usize) {
        let mut st = self.0.lock().unwrap();
        st.partial_bytes_before_stall = Some(bytes);
    }

    fn arm_retryable_then_stall(&self) {
        let mut st = self.0.lock().unwrap();
        st.retryable_then_stall = true;
        st.retryable_fired = false;
    }

    fn set_pause_reads(&self, pause: bool) {
        let w = {
            let mut st = self.0.lock().unwrap();
            st.pause_reads = pause;
            if !pause {
                st.read_waker.take()
            } else {
                None
            }
        };
        if let Some(w) = w {
            w.wake();
        }
    }

    fn set_hold_eof(&self, hold: bool) {
        let w = {
            let mut st = self.0.lock().unwrap();
            st.hold_eof = hold;
            if !hold {
                st.read_waker.take()
            } else {
                None
            }
        };
        if let Some(w) = w {
            w.wake();
        }
    }

    fn set_sink_writes_after_close(&self, sink: bool) {
        self.0.lock().unwrap().sink_writes_after_close = sink;
    }

    fn read_dropped(&self) -> bool {
        self.0.lock().unwrap().read_dropped
    }

    fn write_dropped(&self) -> bool {
        self.0.lock().unwrap().write_dropped
    }
}

struct ControlledRead {
    inner: confluence_core::testing::MemoryStreamRead,
    ctrl: PipeControl,
}

impl StreamRead for ControlledRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, CoreError>> {
        {
            let mut st = self.ctrl.0.lock().unwrap();
            if st.pause_reads {
                st.read_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
        }
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(0)) => {
                let mut st = self.ctrl.0.lock().unwrap();
                if st.hold_eof {
                    st.read_waker = Some(cx.waker().clone());
                    Poll::Pending
                } else {
                    Poll::Ready(Ok(0))
                }
            }
            other => other,
        }
    }
}

impl Drop for ControlledRead {
    fn drop(&mut self) {
        self.ctrl.0.lock().unwrap().read_dropped = true;
    }
}

struct ControlledWrite {
    inner: confluence_core::testing::MemoryStreamWrite,
    ctrl: PipeControl,
}

impl StreamWrite for ControlledWrite {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, CoreError>> {
        let (limit, sink_after_close) = {
            let mut st = self.ctrl.0.lock().unwrap();
            if st.retryable_then_stall {
                if !st.retryable_fired {
                    st.retryable_fired = true;
                    return Poll::Ready(Err(CoreError::CarrierFailure {
                        message: "injected transient before stall".into(),
                        transient: true,
                    }));
                }
                st.write_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            if st.stall_writes {
                st.write_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            if let Some(rem) = st.partial_bytes_before_stall {
                if rem == 0 {
                    st.write_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                let take = rem.min(buf.len());
                st.partial_bytes_before_stall = Some(rem - take);
                (Some(take), st.sink_writes_after_close)
            } else {
                (None, st.sink_writes_after_close)
            }
        };
        let slice = match limit {
            Some(n) => &buf[..n],
            None => buf,
        };
        match Pin::new(&mut self.inner).poll_write(cx, slice) {
            Poll::Ready(Err(CoreError::Closed)) if sink_after_close => {
                Poll::Ready(Ok(slice.len()))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), CoreError>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Drop for ControlledWrite {
    fn drop(&mut self) {
        self.ctrl.0.lock().unwrap().write_dropped = true;
    }
}

struct ControlledStream {
    caps: ChannelCaps,
    source_tag: [u8; 16],
    read: ControlledRead,
    write: ControlledWrite,
}

impl IntoStreamHalves for ControlledStream {
    type Read = ControlledRead;
    type Write = ControlledWrite;

    fn caps(&self) -> ChannelCaps {
        self.caps.clone()
    }

    fn source_tag(&self) -> [u8; 16] {
        self.source_tag
    }

    fn into_halves(self) -> (Self::Read, Self::Write) {
        (self.read, self.write)
    }
}

type ControlledLog = Arc<Mutex<Vec<(PipeControl, PipeControl, StreamFaults, StreamFaults)>>>;

#[derive(Clone)]
struct ControlledStreamCarrier {
    mtu: u16,
    caps: ChannelCaps,
    tx: async_channel::Sender<ControlledStream>,
    log: ControlledLog,
}

struct ControlledStreamListener {
    rx: async_channel::Receiver<ControlledStream>,
}

fn controlled_stream_channel(
    mtu: u16,
) -> (ControlledStreamCarrier, ControlledStreamListener, ControlledLog) {
    let (tx, rx) = async_channel::unbounded();
    let log = Arc::new(Mutex::new(Vec::new()));
    let carrier = ControlledStreamCarrier {
        mtu,
        caps: ChannelCaps::fixed(mtu, true),
        tx,
        log: Arc::clone(&log),
    };
    (carrier, ControlledStreamListener { rx }, log)
}

impl StreamCarrier for ControlledStreamCarrier {
    type Stream = ControlledStream;

    fn caps(&self) -> ChannelCaps {
        self.caps.clone()
    }

    async fn dial_stream(&self, _locator: &[u8]) -> Result<Self::Stream, CoreError> {
        let pair = MemoryStreamPair::pair(self.mtu);
        let a_ctrl = PipeControl::default();
        let b_ctrl = PipeControl::default();
        let a_caps = pair.a.caps();
        let a_tag = pair.a.source_tag();
        let b_caps = pair.b.caps();
        let b_tag = pair.b.source_tag();
        let (ar, aw) = pair.a.into_halves();
        let (br, bw) = pair.b.into_halves();
        self.log.lock().unwrap().push((
            a_ctrl.clone(),
            b_ctrl.clone(),
            pair.a_faults,
            pair.b_faults,
        ));
        let b_stream = ControlledStream {
            caps: b_caps,
            source_tag: b_tag,
            read: ControlledRead {
                inner: br,
                ctrl: b_ctrl.clone(),
            },
            write: ControlledWrite {
                inner: bw,
                ctrl: b_ctrl,
            },
        };
        self.tx
            .send(b_stream)
            .await
            .map_err(|_| CoreError::TargetUnreachable)?;
        Ok(ControlledStream {
            caps: a_caps,
            source_tag: a_tag,
            read: ControlledRead {
                inner: ar,
                ctrl: a_ctrl.clone(),
            },
            write: ControlledWrite {
                inner: aw,
                ctrl: a_ctrl,
            },
        })
    }
}

impl StreamListener for ControlledStreamListener {
    type Stream = ControlledStream;

    async fn accept(&self) -> Result<Self::Stream, CoreError> {
        self.rx.recv().await.map_err(|_| CoreError::Closed)
    }
}

/// Endpoint that keeps the local application stream completely idle (holds `pair.b` alive).
struct IdleAppEndpoint {
    held: Mutex<Vec<MemoryStream>>,
}

impl IdleAppEndpoint {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            held: Mutex::new(Vec::new()),
        })
    }
}

impl StreamEndpointHandler for IdleAppEndpoint {
    fn open(&self, _auth: SessionAuth) -> BoxFuture<'_, Result<BoxedStream, CoreError>> {
        Box::pin(async {
            let pair = MemoryStreamPair::pair(4_096);
            self.held.lock().unwrap().push(pair.b);
            Ok(BoxedStream::from_stream(pair.a))
        })
    }
}

/// ST-01: Stalled peer during `flush()` MUST NOT wedge lease cancellation, shutdown, or drain.
#[test]
fn regression_st01_stalled_peer_during_flush_revocation_and_shutdown_still_drains() {
    let tr = TestRuntime::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();

    let (carrier, listener, log) = controlled_stream_channel(4_096);
    origin.register_stream_carrier("mem", carrier).unwrap();
    let (echo, _) = EchoEndpoint::new(&tr);
    let _g = dest.publish_stream_endpoint("echo", echo).unwrap();
    spawn_scope_stream_listener(&tr, &dest, listener);

    // Part A: Stall outbound carrier mid-frame during `flush()`, then revoke peer!
    let mut st = tr
        .spawner
        .try_block_on(origin.dial_stream_via(
            dest.public_key(),
            "echo",
            ExplicitPath::direct(1, "mem", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();
    let a_ctrl = log.lock().unwrap()[0].0.clone();
    // Allow 2 bytes of the hop header to commit, then stall forever mid-frame!
    a_ctrl.set_partial_then_stall(2);

    let (flush_tx, flush_rx) = async_channel::bounded::<Result<(), CoreError>>(1);
    tr.runtime.spawner.spawn(Box::pin(async move {
        let _ = st.write_all(b"stalled-payload").await;
        let res = st.flush().await;
        let _ = flush_tx.send(res).await;
        drop(st);
    }));
    tr.drive_until_idle();
    // Flush must be blocked on the stalled peer right now.
    assert!(flush_rx.try_recv().is_err());

    // Revoking peer MUST wake the worker, interrupt the stalled carrier write, fail flush with
    // Revoked, drop carrier write half, and drain origin promptly!
    origin.revoke_peer(dest.public_key());
    let flush_res = run_with_clock(&tr, flush_rx.recv(), Duration::from_millis(10), 20).unwrap();
    assert_eq!(flush_res, Err(CoreError::Revoked));
    tr.drive_until_idle();
    assert!(a_ctrl.write_dropped());
    assert!(a_ctrl.read_dropped());
    assert!(origin.is_drained());

    // Part B: Stall outbound carrier at frame boundary during `flush()`, call `begin_shutdown()`,
    // verify `ScopeShutdown` is processed immediately (closing further writes) and dropping handle drains!
    origin.unrevoke_peer(dest.public_key());
    let mut st2 = tr
        .spawner
        .try_block_on(origin.dial_stream_via(
            dest.public_key(),
            "echo",
            ExplicitPath::direct(2, "mem", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();
    let a_ctrl2 = log.lock().unwrap()[1].0.clone();
    a_ctrl2.set_stall_writes(true);

    tr.spawner
        .try_block_on(st2.write_all(b"stalled-before-shutdown"))
        .unwrap()
        .unwrap();

    // Split so we can start a blocked `flush()` while still observing scope shutdown.
    let (r2, mut w2) = st2.split();
    let (f2_tx, f2_rx) = async_channel::bounded::<(Result<(), CoreError>, _)>(1);
    tr.runtime.spawner.spawn(Box::pin(async move {
        let res = w2.flush().await;
        let _ = f2_tx.send((res, w2)).await;
    }));
    tr.drive_until_idle();
    assert!(f2_rx.try_recv().is_err());

    // begin_shutdown() must NOT be blocked by the stalled flush; dropping `r2` + aborting flush
    // (dropping `w2` when we drop the task or revoking) must drain cleanly.
    origin.begin_shutdown();
    tr.drive_until_idle();
    // Revoke peer to terminate the stalled flush & session while peer never reads:
    origin.revoke_peer(dest.public_key());
    let (res2, w2_out) =
        run_with_clock(&tr, f2_rx.recv(), Duration::from_millis(10), 30).unwrap();
    assert_eq!(res2, Err(CoreError::Revoked));
    drop((r2, w2_out));
    tr.advance_and_drive(Duration::from_millis(100));
    assert!(a_ctrl2.write_dropped());
    assert!(origin.is_drained());
}

/// ST-02: Once a first retryable carrier error anchors the 3 s budget in `write_frame`, a
/// subsequent stalled carrier write MUST fail with `CoreError::Timeout` at 3 s.
#[test]
fn regression_st02_write_frame_anchored_3s_deadline_fires_when_carrier_stalls() {
    let tr = TestRuntime::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();

    let (carrier, listener, log) = controlled_stream_channel(4_096);
    origin.register_stream_carrier("mem", carrier).unwrap();
    let (echo, _) = EchoEndpoint::new(&tr);
    let _g = dest.publish_stream_endpoint("echo", echo).unwrap();
    spawn_scope_stream_listener(&tr, &dest, listener);

    let mut st = tr
        .spawner
        .try_block_on(origin.dial_stream_via(
            dest.public_key(),
            "echo",
            ExplicitPath::direct(1, "mem", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();

    let a_ctrl = log.lock().unwrap()[0].0.clone();
    // Next write returns 1 transient error (anchoring 3s budget), then stalls forever!
    a_ctrl.arm_retryable_then_stall();

    let (res_tx, res_rx) = async_channel::bounded::<Result<(), CoreError>>(1);
    tr.runtime.spawner.spawn(Box::pin(async move {
        let _ = st.write_all(b"anchored-budget").await;
        let res = st.flush().await;
        let _ = res_tx.send(res).await;
    }));

    tr.drive_until_idle();
    // Advance 2.95 s -> still within anchored 3 s budget.
    for _ in 0..59 {
        tr.advance_and_drive(Duration::from_millis(50));
    }
    assert!(res_rx.try_recv().is_err(), "must not expire before 3 s");

    // Advance past 3.00 s -> anchored deadline fires CoreError::Timeout!
    tr.advance_and_drive(Duration::from_millis(100));
    assert_eq!(res_rx.try_recv(), Ok(Err(CoreError::Timeout)));
}

/// ST-03: Cancelling a backpressured `poll_write` and issuing a new `poll_write` with a shorter,
/// different buffer delivers ONLY the new buffer without stale bytes or length corruption.
#[test]
fn regression_st03_cancel_backpressured_poll_write_delivers_new_shorter_buffer_cleanly() {
    let tr = TestRuntime::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();

    let collected = Arc::new(Mutex::new(Vec::<u8>::new()));
    struct CollectEp {
        rt: TestRuntime,
        out: Arc<Mutex<Vec<u8>>>,
    }
    impl StreamEndpointHandler for CollectEp {
        fn open(&self, _auth: SessionAuth) -> BoxFuture<'_, Result<BoxedStream, CoreError>> {
            let out = Arc::clone(&self.out);
            Box::pin(async move {
                let pair = MemoryStreamPair::pair(4_096);
                let (mut r, mut w) = pair.b.into_halves();
                self.rt.runtime.spawner.spawn(Box::pin(async move {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = r.read(&mut buf).await {
                        if n == 0 {
                            let _ = w.shutdown().await;
                            break;
                        }
                        out.lock().unwrap().extend_from_slice(&buf[..n]);
                    }
                }));
                Ok(BoxedStream::from_stream(pair.a))
            })
        }
    }

    let (carrier, listener, log) = controlled_stream_channel(4_096);
    origin.register_stream_carrier("mem", carrier).unwrap();
    let _g = dest
        .publish_stream_endpoint(
            "collect",
            Arc::new(CollectEp {
                rt: tr.clone(),
                out: Arc::clone(&collected),
            }),
        )
        .unwrap();
    spawn_scope_stream_listener(&tr, &dest, listener);

    let mut st = tr
        .spawner
        .try_block_on(origin.dial_stream_via(
            dest.public_key(),
            "collect",
            ExplicitPath::direct(1, "mem", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();
    let a_ctrl = log.lock().unwrap()[0].0.clone();
    a_ctrl.set_stall_writes(true);

    // Fill writer queue + app write permits until poll_write returns Poll::Pending!
    let noop_waker = core::task::Waker::noop();
    let mut cx = Context::from_waker(noop_waker);
    let mut expected = Vec::new();
    let mut hit_backpressure = false;
    for i in 0..64u8 {
        let marker = [b'A', i];
        match Pin::new(&mut st).poll_write(&mut cx, &marker) {
            Poll::Ready(Ok(n)) => {
                assert_eq!(n, 2);
                expected.extend_from_slice(&marker);
                tr.drive_until_idle();
            }
            Poll::Pending => {
                hit_backpressure = true;
                break;
            }
            Poll::Ready(other) => panic!("unexpected poll_write result: {other:?}"),
        }
    }
    assert!(hit_backpressure, "expected poll_write to hit backpressure");

    // Issue a long write while backpressured, observe Poll::Pending, then CANCEL it!
    let cancelled_buf = b"CANCELLED_STALE_PAYLOAD_THAT_MUST_NEVER_BE_TRANSMITTED";
    assert!(matches!(
        Pin::new(&mut st).poll_write(&mut cx, cancelled_buf),
        Poll::Pending
    ));

    // Unstall carrier and drive so capacity opens up!
    a_ctrl.set_stall_writes(false);
    tr.drive_until_idle();

    // Now issue a MUCH SHORTER, completely different buffer: MUST return len == 4 (NOT 54) and
    // transmit ONLY b"NEW!"!
    let new_buf = b"NEW!";
    let written = tr.spawner.try_block_on(st.write(new_buf)).unwrap().unwrap();
    assert_eq!(written, new_buf.len());
    expected.extend_from_slice(new_buf);

    tr.spawner
        .try_block_on(async {
            st.flush().await?;
            st.shutdown().await?;
            let mut tmp = [0u8; 8];
            assert_eq!(st.read(&mut tmp).await?, 0);
            Ok::<(), CoreError>(())
        })
        .unwrap()
        .unwrap();
    tr.drive_until_idle();

    let got = collected.lock().unwrap().clone();
    assert_eq!(got, expected);
    assert!(
        !got.windows(b"CANCELLED".len()).any(|w| w == b"CANCELLED"),
        "cancelled buffer leaked into stream"
    );
}

/// ST-04: Back-to-back `ST_FIN` + authenticated `hop::ST_CLOSE(UnexpectedEof)` MUST process
/// `ST_FIN` first, preserving `received_fin` (clean `Ok(0)`) and keeping the outbound half alive.
#[test]
fn regression_st04_back_to_back_st_fin_and_st_close_unexpected_eof_preserves_fin_and_outbound() {
    let tr = TestRuntime::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let hop0 = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();

    let (c_a_h0, l_h0, log_a_h0) = controlled_stream_channel(4_096);
    let (c_h0_b, l_b, log_h0_b) = controlled_stream_channel(4_096);
    origin.register_stream_carrier("to_h0", c_a_h0).unwrap();
    let _t = hop0
        .publish_stream_transit("to-b", static_stream_transit(c_h0_b, b"b".to_vec()))
        .unwrap();

    // Destination endpoint sends final response + EOF on command while keeping its read half open.
    let (trigger_tx, trigger_rx) = async_channel::bounded::<()>(1);
    struct ControlledReplyEp {
        rt: TestRuntime,
        trigger: async_channel::Receiver<()>,
    }
    impl StreamEndpointHandler for ControlledReplyEp {
        fn open(&self, _auth: SessionAuth) -> BoxFuture<'_, Result<BoxedStream, CoreError>> {
            let rx = self.trigger.clone();
            Box::pin(async move {
                let pair = MemoryStreamPair::pair(4_096);
                let (_r, mut w) = pair.b.into_halves();
                self.rt.runtime.spawner.spawn(Box::pin(async move {
                    let _ = rx.recv().await;
                    let _ = w.write_all(b"final-before-fin").await;
                    let _ = w.shutdown().await;
                }));
                Ok(BoxedStream::from_stream(pair.a))
            })
        }
    }

    let _g = dest
        .publish_stream_endpoint(
            "reply",
            Arc::new(ControlledReplyEp {
                rt: tr.clone(),
                trigger: trigger_rx,
            }),
        )
        .unwrap();
    spawn_scope_stream_listener(&tr, &hop0, l_h0);
    spawn_scope_stream_listener(&tr, &dest, l_b);

    let mut path = ExplicitPath::direct(1, "to_h0", b"h0".to_vec());
    path.hops = vec![HopSpec {
        peer: hop0.public_key(),
        target: "to-b".into(),
    }];
    let mut st = tr
        .spawner
        .try_block_on(origin.dial_stream_via(dest.public_key(), "reply", path))
        .unwrap()
        .unwrap();

    let b_to_h0_faults = log_h0_b.lock().unwrap()[0].3.clone();

    // Pause Origin's inbound carrier read so ST_DATA("final-before-fin"), ST_FIN, and
    // authenticated hop::ST_CLOSE(UnexpectedEof) all arrive together in one burst!
    // Also keep Origin's carrier write accepting bytes so we can verify Origin's outbound half
    // stayed alive after ST_FIN + ST_CLOSE(UnexpectedEof).
    let a_ctrl = log_a_h0.lock().unwrap()[0].0.clone();
    a_ctrl.set_pause_reads(true);
    a_ctrl.set_hold_eof(true);
    a_ctrl.set_sink_writes_after_close(true);

    // 1. Let Destination emit ST_DATA("final-before-fin") + ST_FIN through H0 into H0->A's buffer.
    let _ = trigger_tx.try_send(());
    tr.drive_until_idle();

    // 2. Now abruptly close B->H0 so H0 appends real authenticated hop::ST_CLOSE(UnexpectedEof)
    //    into H0->A's buffer immediately after ST_FIN (while Origin's read is still paused!).
    b_to_h0_faults.inject_abrupt_eof();
    tr.drive_until_idle();

    // 3. Release the entire back-to-back burst (ST_DATA + ST_FIN + hop::ST_CLOSE(UnexpectedEof))!
    a_ctrl.set_pause_reads(false);
    tr.drive_until_idle();

    let res = tr.spawner.try_block_on(async {
        let mut out = vec![0u8; 16];
        st.read_exact(&mut out).await?;
        assert_eq!(&out, b"final-before-fin");
        // Must see clean authenticated EOF Ok(0), NOT HopRejected(0, UnexpectedEof)!
        assert_eq!(st.read(&mut out).await?, 0);
        // Outbound half MUST remain alive after ST_FIN + ST_CLOSE(UnexpectedEof) until local ST_FIN!
        st.write_all(b"outbound-still-alive").await?;
        st.flush().await?;
        st.shutdown().await?;
        Ok::<(), CoreError>(())
    });
    assert_eq!(res, Some(Ok(())));
    a_ctrl.set_hold_eof(false);
    tr.drive_until_idle();
}

/// ST-05: In multi-hop `st_splice`, downstream sending final data + `ST_FIN` and immediately
/// closing MUST flush all accepted reverse bytes + `ST_FIN` to upstream before EOF teardown.
#[test]
fn regression_st05_transit_reverse_final_data_and_fin_survive_immediate_downstream_close() {
    let tr = TestRuntime::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let hop0 = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();
    let hop1 = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();

    let (c_a_h0, l_h0, log_a_h0) = controlled_stream_channel(4_096);
    let (c_h0_h1, l_h1, log_h0_h1) = controlled_stream_channel(4_096);
    let (c_h1_b, l_b, log_h1_b) = controlled_stream_channel(4_096);

    origin.register_stream_carrier("to_h0", c_a_h0).unwrap();
    let _t0 = hop0
        .publish_stream_transit("to-h1", static_stream_transit(c_h0_h1, b"h1".to_vec()))
        .unwrap();
    let _t1 = hop1
        .publish_stream_transit("to-b", static_stream_transit(c_h1_b, b"b".to_vec()))
        .unwrap();

    let payload: Vec<u8> = (0..20_000u32).map(|i| ((i * 31) % 251) as u8).collect();
    let (go_tx, go_rx) = async_channel::bounded::<()>(1);

    struct BurstCloseEp {
        rt: TestRuntime,
        payload: Vec<u8>,
        go: async_channel::Receiver<()>,
    }
    impl StreamEndpointHandler for BurstCloseEp {
        fn open(&self, _auth: SessionAuth) -> BoxFuture<'_, Result<BoxedStream, CoreError>> {
            let data = self.payload.clone();
            let go = self.go.clone();
            Box::pin(async move {
                let pair = MemoryStreamPair::pair(4_096);
                let (_r, mut w) = pair.b.into_halves();
                self.rt.runtime.spawner.spawn(Box::pin(async move {
                    let _ = go.recv().await;
                    let _ = w.write_all(&data).await;
                    let _ = w.shutdown().await;
                }));
                Ok(BoxedStream::from_stream(pair.a))
            })
        }
    }

    let _g = dest
        .publish_stream_endpoint(
            "burst",
            Arc::new(BurstCloseEp {
                rt: tr.clone(),
                payload: payload.clone(),
                go: go_rx,
            }),
        )
        .unwrap();

    spawn_scope_stream_listener(&tr, &hop0, l_h0);
    spawn_scope_stream_listener(&tr, &hop1, l_h1);
    spawn_scope_stream_listener(&tr, &dest, l_b);

    let mut path = ExplicitPath::direct(1, "to_h0", b"h0".to_vec());
    path.hops = vec![
        HopSpec {
            peer: hop0.public_key(),
            target: "to-h1".into(),
        },
        HopSpec {
            peer: hop1.public_key(),
            target: "to-b".into(),
        },
    ];
    let mut st = tr
        .spawner
        .try_block_on(origin.dial_stream_via(dest.public_key(), "burst", path))
        .unwrap()
        .unwrap();

    // Stall H1's upstream write (H1 -> H0) so H1's `left_writer` queues reverse ST_DATA + ST_FIN
    // while B finishes transmitting, THEN close B -> H1 immediately while chunks are STILL queued!
    let h0_to_a_ctrl = log_a_h0.lock().unwrap()[0].1.clone();
    let h1_to_h0_ctrl = log_h0_h1.lock().unwrap()[0].1.clone();
    let b_to_h1_faults = log_h1_b.lock().unwrap()[0].3.clone();
    h1_to_h0_ctrl.set_stall_writes(true);
    h0_to_a_ctrl.set_stall_writes(true);

    // 1. B writes 20 KiB + ST_FIN onto B -> H1; H1 reads and queues them on H1's `left_writer`.
    let _ = go_tx.try_send(());
    tr.drive_until_idle();

    // 2. Immediately close B -> H1 while ALL reverse chunks + ST_FIN are queued in H1's writer!
    b_to_h1_faults.inject_abrupt_eof();
    tr.drive_until_idle();

    // 3. Unstall H1 -> H0 so H1 flushes all queued chunks + ST_FIN + hop::ST_CLOSE into H0's writer,
    //    while H0 -> A is still stalled (testing 2-hop FIFO ordering of reverse ST_DATA before ST_CLOSE!).
    h1_to_h0_ctrl.set_stall_writes(false);
    tr.drive_until_idle();

    // 4. Unstall H0 -> A and verify Origin receives ALL 20 KiB intact + clean ST_FIN Ok(0)!
    h0_to_a_ctrl.set_stall_writes(false);
    let received = tr
        .spawner
        .try_block_on(async {
            let mut out = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = st.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
            Ok::<Vec<u8>, CoreError>(out)
        })
        .unwrap()
        .unwrap();
    assert_eq!(received, payload);
}

/// ST-06: Dropping handles after `shutdown()` stops origin session & renewals; `flush`/`shutdown`
/// after scope-initiated `ST_FIN` succeed while further `write` is rejected.
#[test]
fn regression_st06_drop_after_shutdown_stops_renewals_and_post_scope_fin_controls_ack() {
    let tr = TestRuntime::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(10))))
        .build();

    let (carrier, listener, _) = memory_stream_channel(4_096);
    origin.register_stream_carrier("mem", carrier).unwrap();
    let idle_ep = IdleAppEndpoint::new();
    let _g = dest.publish_stream_endpoint("idle", idle_ep).unwrap();
    spawn_scope_stream_listener(&tr, &dest, listener);

    // Part A: `shutdown()` followed by dropping split handles (`w` first, then `r`) MUST stop
    // the origin session immediately so ZERO renewals occur across 3x lease TTL!
    let st = tr
        .spawner
        .try_block_on(origin.dial_stream_via(
            dest.public_key(),
            "idle",
            ExplicitPath::direct(1, "mem", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();
    let (r, mut w) = st.split();
    tr.spawner.try_block_on(w.shutdown()).unwrap().unwrap();
    drop(w);
    tr.drive_until_idle();
    // Still alive while `r` is held.
    assert!(!origin.is_drained());
    drop(r);
    tr.drive_until_idle();
    assert!(origin.is_drained());
    assert_eq!(origin.stats().stream.origin.active_sessions, 0);

    // Advance 30 s (3x lease TTL) -> ZERO endpoint renewals!
    for _ in 0..30 {
        tr.advance_and_drive(Duration::from_secs(1));
    }
    assert_eq!(dest.stats().auth_endpoint.renewed, 0);

    // Part B: After scope `begin_shutdown()` initiates ST_FIN, `write()` MUST fail with Closed
    // while `flush()` and `shutdown()` MUST still be serviced and return Ok(())!
    let origin2 = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let (carrier2, listener2, _) = memory_stream_channel(4_096);
    origin2.register_stream_carrier("mem", carrier2).unwrap();
    spawn_scope_stream_listener(&tr, &dest, listener2);

    let mut st2 = tr
        .spawner
        .try_block_on(origin2.dial_stream_via(
            dest.public_key(),
            "idle",
            ExplicitPath::direct(2, "mem", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();

    origin2.begin_shutdown();
    tr.drive_until_idle();

    let post_fin = tr.spawner.try_block_on(async {
        assert_eq!(st2.write(b"nope").await, Err(CoreError::Closed));
        assert_eq!(st2.flush().await, Ok(()));
        assert_eq!(st2.shutdown().await, Ok(()));
    });
    assert_eq!(post_fin, Some(()));

    drop(st2);
    tr.drive_until_idle();
    assert!(origin2.is_drained());
}

/// ST-07: Mid-body stalled splice peer + revocation cleanly exits BOTH forwarding tasks and
/// releases `SessionGuard`s, `SessionPermit`, and carrier halves.
#[test]
fn regression_st07_mid_body_stalled_splice_revocation_exits_tasks_and_releases_guards() {
    struct DropGuard(Arc<AtomicBool>);
    impl Drop for DropGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    struct GuardingAuth {
        dropped: Arc<AtomicBool>,
    }
    impl Authorizer for GuardingAuth {
        fn authorize<'a>(&'a self, _req: AuthRequest<'a>) -> BoxFuture<'a, Result<Lease, AuthDenied>> {
            let flag = Arc::clone(&self.dropped);
            Box::pin(async move { Ok(Lease::new(Duration::from_secs(60)).with_guard(DropGuard(flag))) })
        }
    }

    let tr = TestRuntime::new();
    let guard_dropped = Arc::new(AtomicBool::new(false));
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let hop0 = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(GuardingAuth {
            dropped: Arc::clone(&guard_dropped),
        }))
        .build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();

    let (c_a_h0, l_h0, log_a_h0) = controlled_stream_channel(4_096);
    let (c_h0_b, l_b, log_h0_b) = controlled_stream_channel(4_096);
    origin.register_stream_carrier("to_h0", c_a_h0).unwrap();
    let _t = hop0
        .publish_stream_transit("to-b", static_stream_transit(c_h0_b, b"b".to_vec()))
        .unwrap();
    let (echo, _) = EchoEndpoint::new(&tr);
    let _g = dest.publish_stream_endpoint("echo", echo).unwrap();

    spawn_scope_stream_listener(&tr, &hop0, l_h0);
    spawn_scope_stream_listener(&tr, &dest, l_b);

    let mut path = ExplicitPath::direct(1, "to_h0", b"h0".to_vec());
    path.hops = vec![HopSpec {
        peer: hop0.public_key(),
        target: "to-b".into(),
    }];
    let mut st = tr
        .spawner
        .try_block_on(origin.dial_stream_via(dest.public_key(), "echo", path))
        .unwrap()
        .unwrap();

    let (a_ctrl, h0_left_ctrl, _, _) = log_a_h0.lock().unwrap()[0].clone();
    let (h0_right_ctrl, _, _, _) = log_h0_b.lock().unwrap()[0].clone();

    // Commit the 4-byte ST_DATA header + 6 body bytes of a 500-byte payload, then stall MID-BODY!
    a_ctrl.set_partial_then_stall(10);
    let payload = vec![0x5Au8; 500];
    tr.spawner
        .try_block_on(st.write_all(&payload))
        .unwrap()
        .unwrap();
    tr.drive_until_idle();

    // Hop0's left->right forwarding task is now parked inside `left_r.read_exact(...)` mid-body!
    assert!(!guard_dropped.load(Ordering::Acquire));
    assert!(!hop0.is_drained());

    // Revoke the transit circuit on hop0!
    hop0.revoke_peer(origin.public_key());
    tr.advance_and_drive(Duration::from_millis(100));

    assert!(
        guard_dropped.load(Ordering::Acquire),
        "transit SessionGuard leaked in mid-body stalled forwarding task"
    );
    assert!(hop0.is_drained(), "hop0 failed to drain after revocation");
    assert!(h0_left_ctrl.read_dropped());
    assert!(h0_left_ctrl.write_dropped());
    assert!(h0_right_ctrl.read_dropped());
    assert!(h0_right_ctrl.write_dropped());
}

/// ST-08: Revoking an idle stream session MUST cancel & await its carrier reader task so neither
/// the reader task nor the carrier read half leaks.
#[test]
fn regression_st08_revoking_idle_stream_session_terminates_reader_and_drains() {
    let tr = TestRuntime::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();

    let (carrier, listener, log) = controlled_stream_channel(4_096);
    origin.register_stream_carrier("mem", carrier).unwrap();
    let idle_ep = IdleAppEndpoint::new();
    let _g = dest.publish_stream_endpoint("idle", idle_ep).unwrap();
    spawn_scope_stream_listener(&tr, &dest, listener);

    let st = tr
        .spawner
        .try_block_on(origin.dial_stream_via(
            dest.public_key(),
            "idle",
            ExplicitPath::direct(1, "mem", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();

    let (a_ctrl, b_ctrl, _, _) = log.lock().unwrap()[0].clone();
    // Keep Destination's carrier write half open and silent (peer never sends anything and never closes).
    b_ctrl.set_stall_writes(true);
    tr.drive_until_idle();

    assert!(!a_ctrl.read_dropped());
    assert!(!origin.is_drained());

    // Revoke on Origin while peer's sending half stays open & silent!
    origin.revoke_peer(dest.public_key());
    tr.advance_and_drive(Duration::from_millis(100));

    assert!(
        a_ctrl.read_dropped(),
        "origin carrier reader task leaked on idle session revocation"
    );
    assert!(a_ctrl.write_dropped());
    assert!(origin.is_drained());
    drop(st);
}

/// ST-09: Revoking a Destination stream session whose local app stream is completely idle MUST
/// cancel the blocked app read/write, drop `BridgeGuard`, and make `dest.is_drained() == true`,
/// both from steady state AND after a clean peer `ST_FIN` half-close.
#[test]
fn regression_st09_revoking_destination_with_idle_app_stream_drops_bridge_guard_and_drains() {
    let tr = TestRuntime::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
        .build();

    let (carrier, listener, _) = memory_stream_channel(4_096);
    origin.register_stream_carrier("mem", carrier).unwrap();
    let idle_ep = IdleAppEndpoint::new();
    let _g = dest
        .publish_stream_endpoint("idle", Arc::clone(&idle_ep) as Arc<dyn StreamEndpointHandler>)
        .unwrap();
    spawn_scope_stream_listener(&tr, &dest, listener);

    // Part A: Both directions idle on Destination -> revoke peer -> BridgeGuard drops immediately!
    let _st1 = tr
        .spawner
        .try_block_on(origin.dial_stream_via(
            dest.public_key(),
            "idle",
            ExplicitPath::direct(1, "mem", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();
    tr.drive_until_idle();
    assert!(!dest.is_drained());

    dest.revoke_peer(origin.public_key());
    tr.drive_until_idle();
    assert!(
        dest.is_drained(),
        "dest BridgeGuard leaked while local app stream was idle"
    );

    // Part B: Clean peer ST_FIN finishes dir1 while dir2 stays blocked on idle app_r -> revoke!
    dest.unrevoke_peer(origin.public_key());
    let mut st2 = tr
        .spawner
        .try_block_on(origin.dial_stream_via(
            dest.public_key(),
            "idle",
            ExplicitPath::direct(2, "mem", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();
    tr.spawner.try_block_on(st2.shutdown()).unwrap().unwrap();
    tr.drive_until_idle();
    // Clean half-close MUST keep dir2 alive until app closes or session terminates!
    assert!(!dest.is_drained());

    // Now revoke peer -> blocked dir2 MUST cancel and BridgeGuard MUST drop!
    dest.revoke_peer(origin.public_key());
    tr.drive_until_idle();
    assert!(
        dest.is_drained(),
        "dest BridgeGuard leaked after clean half-close + revocation"
    );
    drop((_st1, st2, idle_ep));
}

// ===========================================================================
// Codex Round 2 Regression Tests (`R2-ST-01` .. `R2-ST-03`)
// ===========================================================================

/// R2-ST-01: Calling `begin_shutdown()` while successfully accepted writes remain in
/// `app_write_rx`, `pending_app_writes`, or `delayed_egress` MUST stop accepting NEW writes,
/// drain ALL already-accepted writes in exact FIFO order, and ONLY THEN enqueue `e2e::ST_FIN`
/// so accepted writes are never silently truncated into a clean EOF.
#[test]
fn regression_r2_st01_begin_shutdown_drains_accepted_writes_before_fin() {
    use confluence_core::Direction;
    use confluence_core::auth::{DatagramAction, StreamAction, TrafficGate};

    // Part A: Accepted writes sitting in `app_write_rx` / `pending_app_writes` behind a
    // backpressured carrier when `origin.begin_shutdown()` is called.
    {
        let tr = TestRuntime::new();
        let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
        let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
            .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
            .build();

        let (carrier, listener, log) = controlled_stream_channel(4_096);
        origin.register_stream_carrier("mem", carrier).unwrap();
        let (echo, _) = EchoEndpoint::new(&tr);
        let _g = dest.publish_stream_endpoint("echo", echo).unwrap();
        spawn_scope_stream_listener(&tr, &dest, listener);

        let mut st = tr
            .spawner
            .try_block_on(origin.dial_stream_via(
                dest.public_key(),
                "echo",
                ExplicitPath::direct(1, "mem", b"b".to_vec()),
            ))
            .unwrap()
            .unwrap();

        let (a_ctrl, _, _, _) = log.lock().unwrap()[0].clone();
        // Stall Origin's carrier writes so accepted app writes queue in `app_write_rx` /
        // `pending_app_writes` without flushing to the carrier yet.
        a_ctrl.set_stall_writes(true);

        // Enqueue 3 accepted writes without calling `flush()` or `shutdown()`.
        let accepted = tr.spawner.try_block_on(async {
            st.write_all(b"chunk-1-").await?;
            st.write_all(b"chunk-2-").await?;
            st.write_all(b"chunk-3!").await?;
            Ok::<(), CoreError>(())
        });
        assert_eq!(accepted, Some(Ok(())));

        // Trigger graceful shutdown BEFORE the carrier unblocks (and while chunks are queued!).
        origin.begin_shutdown();
        tr.drive_until_idle();

        // Any NEW write after `begin_shutdown()` MUST be rejected immediately with `Closed`.
        assert_eq!(
            tr.spawner.try_block_on(st.write(b"rejected")),
            Some(Err(CoreError::Closed))
        );

        // Now unblock the carrier: ALL 3 accepted chunks MUST be delivered in exact FIFO order
        // BEFORE `ST_FIN`, echoed back cleanly by Destination, followed by clean EOF `Ok(0)`!
        a_ctrl.set_stall_writes(false);
        tr.drive_until_idle();

        let mut received = Vec::new();
        let read_res = tr.spawner.try_block_on(async {
            let mut buf = [0u8; 64];
            loop {
                let n = st.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
            }
            Ok::<(), CoreError>(())
        });
        assert_eq!(read_res, Some(Ok(())));
        assert_eq!(
            received, b"chunk-1-chunk-2-chunk-3!",
            "R2-ST-01: accepted writes MUST NOT be truncated before ST_FIN on begin_shutdown()"
        );
        drop(st);
        tr.drive_until_idle();
        assert!(origin.is_drained());
        assert!(dest.is_drained());
    }

    // Part B: Multiple accepted Destination writes behind an egress `TrafficGate::Delay` when
    // `dest.begin_shutdown()` is called — ALL delayed + queued writes MUST drain in FIFO order
    // before Destination's `ST_FIN`!
    {
        struct EgressDelayGate;
        impl TrafficGate for EgressDelayGate {
            fn check_datagram(&self, _dir: Direction, _bytes: usize) -> DatagramAction {
                DatagramAction::Allow
            }
            fn charge_stream(&self, dir: Direction, _bytes: usize) -> StreamAction {
                if dir == Direction::Egress {
                    StreamAction::Delay(Duration::from_millis(100))
                } else {
                    StreamAction::Allow
                }
            }
        }

        struct DelayAuthorizer;
        impl Authorizer for DelayAuthorizer {
            fn authorize<'a>(&'a self, _req: AuthRequest<'a>) -> BoxFuture<'a, Result<Lease, AuthDenied>> {
                Box::pin(async {
                    Ok(Lease::new(Duration::from_secs(60))
                        .with_gate(Arc::new(EgressDelayGate)))
                })
            }
        }

        struct ManualDestEndpoint {
            app_write_tx: Mutex<Option<Box<dyn StreamWrite>>>,
        }
        impl StreamEndpointHandler for ManualDestEndpoint {
            fn open(&self, _auth: SessionAuth) -> BoxFuture<'_, Result<BoxedStream, CoreError>> {
                let pair = MemoryStreamPair::pair(4_096);
                let (_r, w) = pair.b.into_halves();
                *self.app_write_tx.lock().unwrap() = Some(Box::new(w));
                Box::pin(async move { Ok(BoxedStream::from_stream(pair.a)) })
            }
        }

        let tr = TestRuntime::new();
        let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
        let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
            .with_authorizer(Arc::new(DelayAuthorizer))
            .build();
        let (carrier, listener, _) = memory_stream_channel(4_096);
        origin.register_stream_carrier("mem", carrier).unwrap();
        let ep = Arc::new(ManualDestEndpoint {
            app_write_tx: Mutex::new(None),
        });
        let _g = dest
            .publish_stream_endpoint("delay", Arc::clone(&ep) as Arc<dyn StreamEndpointHandler>)
            .unwrap();
        spawn_scope_stream_listener(&tr, &dest, listener);

        let mut st = tr
            .spawner
            .try_block_on(origin.dial_stream_via(
                dest.public_key(),
                "delay",
                ExplicitPath::direct(2, "mem", b"b".to_vec()),
            ))
            .unwrap()
            .unwrap();
        tr.drive_until_idle();

        let mut dest_app_w = ep.app_write_tx.lock().unwrap().take().unwrap();
        // Write 3 separate chunks on Destination's app stream so chunk 1 enters `delayed_egress`
        // while chunks 2 & 3 queue in `pending_app_writes` / `app_write_rx`.
        tr.spawner
            .try_block_on(dest_app_w.write_all(b"partA|"))
            .unwrap()
            .unwrap();
        tr.drive_until_idle();
        tr.spawner
            .try_block_on(dest_app_w.write_all(b"partB|"))
            .unwrap()
            .unwrap();
        tr.spawner
            .try_block_on(dest_app_w.write_all(b"partC"))
            .unwrap()
            .unwrap();
        tr.drive_until_idle();

        // Call `dest.begin_shutdown()` while partA is delayed and partB+partC are queued!
        dest.begin_shutdown();
        // Step past each sequential 100 ms TrafficGate delay (`partA|`, `partB|`, `partC`, `ST_FIN`).
        for _ in 0..5 {
            tr.advance_and_drive(Duration::from_millis(120));
        }

        let mut got = Vec::new();
        let rd = tr.spawner.try_block_on(async {
            let mut buf = [0u8; 64];
            loop {
                let n = st.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            Ok::<(), CoreError>(())
        });
        assert_eq!(rd, Some(Ok(())));
        assert_eq!(
            got, b"partA|partB|partC",
            "R2-ST-01: delayed_egress + queued pending_app_writes MUST ALL drain before ST_FIN"
        );
        tr.spawner.try_block_on(st.shutdown()).unwrap().unwrap();
        drop(dest_app_w);
        tr.drive_until_idle();
        assert!(dest.is_drained());
    }
}

/// R2-ST-02: After one successful renewal, flooding freshly encrypted duplicate renewal IDs
/// while the return carrier is stalled in `Poll::Pending` MUST NOT grow an unbounded ACK queue
/// (duplicate ACKs coalesce before sealing), and cancellation/revocation MUST stay responsive
/// on BOTH Stream Destination (`session.rs`) and Stream Transit (`splice.rs`).
#[test]
fn regression_r2_st02_duplicate_renewal_flood_on_stalled_carrier_stays_bounded() {
    use std::collections::HashMap;

    use confluence_core::Cid;
    use confluence_core::__conformance::{
        HopFlightInput, SetupFlightBuilder, SetupFlightParams, StHopHeader, StreamCipher,
        decode_renew_ok_payload, e2e_st, encode_renew_payload, outer,
    };

    // Helper: write one `ST_DATA` hop chunk wrapping a sealed E2E record.
    fn frame_e2e_record(tx: &mut StreamCipher, opcode: u8, body: &[u8]) -> Vec<u8> {
        let mut e2e = Vec::new();
        tx.seal_into(opcode, body, &mut e2e).unwrap();
        let hdr = StHopHeader {
            kind: outer::ST_DATA,
            ttl_or_dist: 0,
            len: u16::try_from(e2e.len()).unwrap(),
        };
        let mut out = Vec::with_capacity(4 + e2e.len());
        out.extend_from_slice(&hdr.encode());
        out.extend_from_slice(&e2e);
        out
    }

    // Helper: read one `ST_DATA`-wrapped E2E record from a raw stream reader.
    async fn read_one_e2e(
        r: &mut dyn StreamRead,
        rx: &mut StreamCipher,
        buf: &mut Vec<u8>,
    ) -> Result<(u8, Vec<u8>), CoreError> {
        loop {
            if buf.len() >= 2 {
                let blen = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
                let rec_len = blen + 19;
                if buf.len() >= rec_len {
                    let mut rec: Vec<u8> = buf.drain(..rec_len).collect();
                    let opened = rx.open_record(&mut rec)?;
                    return Ok((opened.opcode(), opened.body().to_vec()));
                }
            }
            let mut h = [0u8; 4];
            r.read_exact(&mut h).await?;
            let hdr = StHopHeader::parse(&h)?;
            let mut chunk = vec![0u8; usize::from(hdr.len)];
            r.read_exact(&mut chunk).await?;
            if hdr.kind == outer::ST_DATA {
                buf.extend_from_slice(&chunk);
            }
        }
    }

    // Part A: Stream Destination (`session.rs`) duplicate `e2e::ST_RENEW` flood.
    {
        let tr = TestRuntime::new();
        let origin_kp = ScopeKeypair::generate();
        let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
            .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
            .build();

        let (carrier, listener, log) = controlled_stream_channel(4_096);
        let idle_ep = IdleAppEndpoint::new();
        let _g = dest.publish_stream_endpoint("idle", idle_ep).unwrap();
        spawn_scope_stream_listener(&tr, &dest, listener);

        let stream = tr
            .spawner
            .try_block_on(carrier.dial_stream(b"dest"))
            .unwrap()
            .unwrap();
        let (mut r, mut w) = stream.into_halves();

        let (origin_state, flight) = SetupFlightBuilder::build(&SetupFlightParams {
            local: &origin_kp,
            plane: Plane::Stream,
            origin_local_mtu: 4_096,
            min_mtu: STREAM_MIN_MTU,
            upstream_cid: Cid::UNBOUND,
            destination: dest.public_key(),
            endpoint: "idle",
            dest_credential: b"c0",
            hops: &[],
            cookies: &HashMap::new(),
            wall_time_ms: tr.runtime.wall_time_ms(),
        })
        .unwrap();

        tr.spawner.try_block_on(w.write_all(&flight)).unwrap().unwrap();
        tr.spawner.try_block_on(w.flush()).unwrap().unwrap();
        tr.drive_until_idle();

        // Read SETUP_OK (70 B for 0 hops) and establish raw E2E StreamCiphers.
        let mut ok_wire = [0u8; 70];
        tr.spawner
            .try_block_on(r.read_exact(&mut ok_wire))
            .unwrap()
            .unwrap();
        let est = origin_state.finish_setup_ok(&ok_wire).unwrap();
        let mut tx = StreamCipher::new(est.session_keys.tx_key());
        let mut rx = StreamCipher::new(est.session_keys.rx_key());
        let mut rx_buf = Vec::new();

        // Confirm 1.0 RTT + read OPEN_OK.
        let confirm = frame_e2e_record(&mut tx, e2e_st::ST_DATA, &[]);
        tr.spawner.try_block_on(w.write_all(&confirm)).unwrap().unwrap();
        tr.spawner.try_block_on(w.flush()).unwrap().unwrap();
        tr.drive_until_idle();
        let (op, _) = tr
            .spawner
            .try_block_on(read_one_e2e(&mut r, &mut rx, &mut rx_buf))
            .unwrap()
            .unwrap();
        assert_eq!(op, e2e_st::OPEN_OK);

        // Complete 1 real renewal (id = 1) so `dest_verifier.applied == 1`.
        let renew1 = encode_renew_payload(1, b"c1").unwrap();
        let renew1_frame = frame_e2e_record(&mut tx, e2e_st::ST_RENEW, &renew1);
        tr.spawner
            .try_block_on(w.write_all(&renew1_frame))
            .unwrap()
            .unwrap();
        tr.spawner.try_block_on(w.flush()).unwrap().unwrap();
        tr.drive_until_idle();
        let (ack_op, ack_body) = tr
            .spawner
            .try_block_on(read_one_e2e(&mut r, &mut rx, &mut rx_buf))
            .unwrap()
            .unwrap();
        assert_eq!(ack_op, e2e_st::ST_RENEW_OK);
        assert_eq!(decode_renew_ok_payload(&ack_body).unwrap().0, 1);

        // Now stall Destination's carrier write half in `Poll::Pending` (origin stops reading!)
        // and flood 1,000 freshly encrypted duplicate `e2e::ST_RENEW(id = 1)` records!
        let (_, dest_ctrl, _, _) = log.lock().unwrap()[0].clone();
        dest_ctrl.set_stall_writes(true);

        for _ in 0..1_000 {
            let dup = frame_e2e_record(&mut tx, e2e_st::ST_RENEW, &renew1);
            tr.spawner.try_block_on(w.write_all(&dup)).unwrap().unwrap();
        }
        tr.spawner.try_block_on(w.flush()).unwrap().unwrap();
        tr.drive_until_idle();

        // Unblock Destination's writer and count how many `ST_RENEW_OK` replies were actually
        // queued: bounded writer channel (16) + 1 in-flight + 1 coalesced <= 20 (NOT 1,000!).
        dest_ctrl.set_stall_writes(false);
        tr.drive_until_idle();

        let mut ack_count = 0usize;
        while let Some(Ok((op, body))) =
            tr.spawner.try_block_on(read_one_e2e(&mut r, &mut rx, &mut rx_buf))
        {
            assert_eq!(op, e2e_st::ST_RENEW_OK);
            assert_eq!(decode_renew_ok_payload(&body).unwrap().0, 1);
            ack_count += 1;
            tr.drive_until_idle();
        }
        assert!(
            (1..=24).contains(&ack_count),
            "R2-ST-02 (Destination): expected coalesced bounded ACKs in 1..=24, got {ack_count}"
        );

        // Re-stall, flood another 500 duplicates, and verify revocation STILL drains immediately!
        dest_ctrl.set_stall_writes(true);
        for _ in 0..500 {
            let dup = frame_e2e_record(&mut tx, e2e_st::ST_RENEW, &renew1);
            tr.spawner.try_block_on(w.write_all(&dup)).unwrap().unwrap();
        }
        tr.drive_until_idle();
        dest.revoke_peer(origin_kp.public_key());
        // Step past both 50 ms best-effort teardown deadlines (`ST_CLOSE` + `writer.shutdown()`).
        tr.advance_and_drive(Duration::from_millis(60));
        tr.advance_and_drive(Duration::from_millis(60));
        assert!(
            dest.is_drained(),
            "R2-ST-02 (Destination): session MUST stay responsive to revocation under duplicate flood"
        );
    }

    // Part B: Stream Transit (`splice.rs`) duplicate `hop::ST_RENEW` flood.
    {
        let tr = TestRuntime::new();
        let origin_kp = ScopeKeypair::generate();
        let hop0 = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
            .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
            .build();
        let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
            .with_authorizer(Arc::new(AllowAll(Duration::from_secs(60))))
            .build();

        let (c_a_h0, l_h0, log_a_h0) = controlled_stream_channel(4_096);
        let (c_h0_b, l_b, _) = memory_stream_channel(4_096);
        let _t0 = hop0
            .publish_stream_transit("to-b", static_stream_transit(c_h0_b, b"b".to_vec()))
            .unwrap();
        let idle_ep = IdleAppEndpoint::new();
        let _g = dest.publish_stream_endpoint("idle", idle_ep).unwrap();
        spawn_scope_stream_listener(&tr, &hop0, l_h0);
        spawn_scope_stream_listener(&tr, &dest, l_b);

        let stream = tr
            .spawner
            .try_block_on(c_a_h0.dial_stream(b"h0"))
            .unwrap()
            .unwrap();
        let (mut r, mut w) = stream.into_halves();

        let hop_inputs = [HopFlightInput {
            peer: hop0.public_key(),
            target: "to-b",
            credential: b"h0",
        }];
        let (origin_state, flight) = SetupFlightBuilder::build(&SetupFlightParams {
            local: &origin_kp,
            plane: Plane::Stream,
            origin_local_mtu: 4_096,
            min_mtu: STREAM_MIN_MTU,
            upstream_cid: Cid::UNBOUND,
            destination: dest.public_key(),
            endpoint: "idle",
            dest_credential: b"d0",
            hops: &hop_inputs,
            cookies: &HashMap::new(),
            wall_time_ms: tr.runtime.wall_time_ms(),
        })
        .unwrap();

        tr.spawner.try_block_on(w.write_all(&flight)).unwrap().unwrap();
        tr.spawner.try_block_on(w.flush()).unwrap().unwrap();
        tr.drive_until_idle();

        // Read SETUP_OK (70 + 26 = 96 B for 1 hop).
        let mut ok_wire = [0u8; 96];
        tr.spawner
            .try_block_on(r.read_exact(&mut ok_wire))
            .unwrap()
            .unwrap();
        let est = origin_state.finish_setup_ok(&ok_wire).unwrap();
        let mut hop_ctrl = est.hop_keys[0].control_cipher(true);

        let renew1 = encode_renew_payload(1, b"h1").unwrap();
        let make_hop_renew = |ctrl: &mut confluence_core::__conformance::ControlCipher| {
            let sealed = ctrl.seal(outer::ST_RENEW, &renew1).unwrap();
            let hdr = StHopHeader {
                kind: outer::ST_RENEW,
                ttl_or_dist: 0,
                len: u16::try_from(sealed.len()).unwrap(),
            };
            let mut frame = Vec::with_capacity(4 + sealed.len());
            frame.extend_from_slice(&hdr.encode());
            frame.extend_from_slice(&sealed);
            frame
        };

        // Complete 1 real hop renewal (id = 1).
        let f1 = make_hop_renew(&mut hop_ctrl);
        tr.spawner.try_block_on(w.write_all(&f1)).unwrap().unwrap();
        tr.spawner.try_block_on(w.flush()).unwrap().unwrap();
        tr.drive_until_idle();

        let mut h_raw = [0u8; 4];
        tr.spawner
            .try_block_on(r.read_exact(&mut h_raw))
            .unwrap()
            .unwrap();
        let hdr = StHopHeader::parse(&h_raw).unwrap();
        assert_eq!(hdr.kind, outer::ST_RENEW_OK);
        let mut body = vec![0u8; usize::from(hdr.len)];
        tr.spawner
            .try_block_on(r.read_exact(&mut body))
            .unwrap()
            .unwrap();
        let pt = hop_ctrl.open(outer::ST_RENEW_OK, &body).unwrap();
        assert_eq!(decode_renew_ok_payload(&pt).unwrap().0, 1);

        // Stall hop0's reverse writer (`left_w`) in `Poll::Pending` and flood 1,000 duplicate
        // `hop::ST_RENEW(id = 1)` frames!
        let (_, h0_left_ctrl, _, _) = log_a_h0.lock().unwrap()[0].clone();
        h0_left_ctrl.set_stall_writes(true);

        for _ in 0..1_000 {
            let dup = make_hop_renew(&mut hop_ctrl);
            tr.spawner.try_block_on(w.write_all(&dup)).unwrap().unwrap();
        }
        tr.spawner.try_block_on(w.flush()).unwrap().unwrap();
        tr.drive_until_idle();

        // Unblock and verify ONLY bounded coalesced ACKs arrive (32-slot ctrl channel + 1 in-flight
        // + 1 coalesced <= 36, NOT 1,000!).
        h0_left_ctrl.set_stall_writes(false);
        tr.drive_until_idle();

        let mut hop_acks = 0usize;
        while let Some(Ok(())) = tr.spawner.try_block_on(r.read_exact(&mut h_raw)) {
            let h = StHopHeader::parse(&h_raw).unwrap();
            let mut b = vec![0u8; usize::from(h.len)];
            tr.spawner.try_block_on(r.read_exact(&mut b)).unwrap().unwrap();
            assert_eq!(h.kind, outer::ST_RENEW_OK);
            let p = hop_ctrl.open(outer::ST_RENEW_OK, &b).unwrap();
            assert_eq!(decode_renew_ok_payload(&p).unwrap().0, 1);
            hop_acks += 1;
            tr.drive_until_idle();
        }
        assert!(
            (1..=40).contains(&hop_acks),
            "R2-ST-02 (Transit): expected coalesced bounded ACKs in 1..=40, got {hop_acks}"
        );

        // Re-stall, flood more duplicates, and verify revocation STILL tears down splice cleanly!
        h0_left_ctrl.set_stall_writes(true);
        for _ in 0..500 {
            let dup = make_hop_renew(&mut hop_ctrl);
            tr.spawner.try_block_on(w.write_all(&dup)).unwrap().unwrap();
        }
        tr.drive_until_idle();
        hop0.revoke_peer(origin_kp.public_key());
        tr.advance_and_drive(Duration::from_millis(60));
        tr.advance_and_drive(Duration::from_millis(60));
        assert!(
            hop0.is_drained(),
            "R2-ST-02 (Transit): splice MUST stay responsive to revocation under duplicate flood"
        );
    }
}

/// R2-ST-03 (Stream): Revoking (or expiring) a staged Stream's destination peer locally BEFORE
/// calling `StagedStream::confirm()` while the carrier is immediately writable MUST fail BEFORE
/// transmitting confirmation, so Destination's `StreamEndpointHandler::open` is NEVER invoked.
#[test]
fn regression_r2_st03_revoked_staged_stream_confirm_never_triggers_destination() {
    let tr = TestRuntime::new();
    let outcomes = RecordingPathSource::new();
    let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_path_source(outcomes.clone())
        .build();
    let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
        .with_authorizer(Arc::new(AllowAll(Duration::from_secs(5))))
        .build();

    let (carrier, listener, _) = memory_stream_channel(4_096);
    origin.register_stream_carrier("mem", carrier).unwrap();
    let (echo, opens) = EchoEndpoint::new(&tr);
    let _g = dest.publish_stream_endpoint("echo", echo).unwrap();
    spawn_scope_stream_listener(&tr, &dest, listener);

    // Part A: Local peer revocation BEFORE `confirm()` while carrier is immediately writable!
    let staged = tr
        .spawner
        .try_block_on(origin.dial_stream_staged_via(
            dest.public_key(),
            "echo",
            ExplicitPath::direct(301, "mem", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();
    tr.drive_until_idle();
    assert_eq!(opens.load(Ordering::SeqCst), 0);

    origin.revoke_peer(dest.public_key());

    let err = tr
        .spawner
        .try_block_on(staged.confirm())
        .unwrap()
        .unwrap_err();
    assert_eq!(err, CoreError::Revoked);
    tr.advance_and_drive(Duration::from_millis(100));
    assert_eq!(
        opens.load(Ordering::SeqCst),
        0,
        "R2-ST-03: revoked StagedStream::confirm() MUST NOT transmit confirmation or open Destination"
    );
    assert!(outcomes
        .snapshot()
        .contains(&(301, PathOutcome::Failed(CoreError::Revoked))));
    assert!(origin.is_drained());
    assert!(dest.is_drained());

    // Part B: Lease expiry BEFORE `confirm()` while carrier is writable!
    origin.unrevoke_peer(dest.public_key());
    let staged2 = tr
        .spawner
        .try_block_on(origin.dial_stream_staged_via(
            dest.public_key(),
            "echo",
            ExplicitPath::direct(302, "mem", b"b".to_vec()),
        ))
        .unwrap()
        .unwrap();
    // Advance past 5 s dest TTL before confirming.
    tr.advance_and_drive(Duration::from_secs(6));
    let err2 = tr
        .spawner
        .try_block_on(staged2.confirm())
        .unwrap()
        .unwrap_err();
    assert_eq!(err2, CoreError::Expired);
    tr.advance_and_drive(Duration::from_millis(100));
    assert_eq!(
        opens.load(Ordering::SeqCst),
        0,
        "R2-ST-03: expired StagedStream::confirm() MUST NOT open Destination"
    );
    assert!(outcomes
        .snapshot()
        .contains(&(302, PathOutcome::Failed(CoreError::Expired))));
}
