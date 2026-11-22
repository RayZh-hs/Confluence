use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use confluence_core::wire::{hop, setup};
use confluence_core::*;
use confluence_plugins::{
    MemDatagramChannel, MemDatagramLink, MemRead, MemStream, MemStreamChannel, MemWrite,
    StaticAuthorizer, StaticCredentials, StaticPathSource, TokioSpawner, mem_datagram_pair,
    mem_stream_pair,
};
use tokio::{
    sync::watch,
    task::JoinHandle,
    time::{sleep, timeout},
};

const CARRIER: &str = "mem";
const ENDPOINT: &str = "echo";
const LONG_TTL: Duration = Duration::from_secs(15);

fn node(auth: Arc<dyn Authorizer>, routes: Arc<StaticPathSource>) -> ScopeInstance {
    ScopeInstance::builder(ScopeKeypair::generate(), Arc::new(TokioSpawner))
        .authorizer(auth)
        .routes(routes)
        .build()
}

fn node_with_creds(
    auth: Arc<dyn Authorizer>,
    routes: Arc<StaticPathSource>,
    creds: Arc<dyn CredentialProvider>,
) -> ScopeInstance {
    ScopeInstance::builder(ScopeKeypair::generate(), Arc::new(TokioSpawner))
        .authorizer(auth)
        .routes(routes)
        .credentials(creds)
        .build()
}

fn setup_route(
    routes: &StaticPathSource,
    dst: &ScopeInstance,
    plane: Plane,
    hops: Vec<HopSpec>,
    min_mtu: u16,
) {
    routes.set(
        dst.public_key(),
        ENDPOINT,
        plane,
        ExplicitPath {
            id: 19,
            first_channel: CARRIER.into(),
            first_locator: b"out".to_vec(),
            min_mtu,
            hops,
        },
    );
}

fn task(future: impl Future<Output = ()> + Send + 'static) -> JoinHandle<()> {
    tokio::spawn(future)
}

struct EchoStream;
impl StreamEndpointHandler for EchoStream {
    type Stream = MemStream;

    async fn open(&self, _auth: SessionAuth) -> Result<MemStream, CoreErr> {
        let (server, app) = mem_stream_pair(16384, 8192);
        task(async move {
            let (mut rx, mut tx) = app.split();
            let mut data = [0; 8192];
            while let Ok(size) = rx.read(&mut data).await {
                if size == 0 {
                    let _ = tx.shutdown().await;
                    break;
                }
                if tx.write_all(&data[..size]).await.is_err() {
                    break;
                }
            }
        });
        Ok(server)
    }
}

#[derive(Default)]
struct EchoDatagrams(AtomicUsize);
impl DatagramEndpointHandler for EchoDatagrams {
    type Link = Arc<MemDatagramLink>;

    async fn open(&self, _auth: SessionAuth) -> Result<Arc<MemDatagramLink>, CoreErr> {
        self.0.fetch_add(1, Ordering::Relaxed);
        let (server, app) = mem_datagram_pair(u16::MAX, 32);
        task(async move {
            while let Ok(packet) = app.recv().await {
                if app.send(packet).await.is_err() {
                    break;
                }
            }
        });
        Ok(server)
    }
}

struct Refused;
impl StreamEndpointHandler for Refused {
    type Stream = MemStream;

    async fn open(&self, _auth: SessionAuth) -> Result<MemStream, CoreErr> {
        Err(CoreErr::TargetRefused)
    }
}

struct FixedDatagram(Arc<MemDatagramLink>);
impl DatagramChannel for FixedDatagram {
    type Link = Arc<MemDatagramLink>;

    fn caps(&self) -> ChannelCaps {
        self.0.caps()
    }
    async fn open_link(&self, _: &[u8]) -> Result<Arc<MemDatagramLink>, CoreErr> {
        Ok(self.0.clone())
    }
}

struct CountPolicy {
    auth: StaticAuthorizer,
    checks: AtomicUsize,
}
impl CountPolicy {
    fn new() -> Self {
        Self {
            auth: StaticAuthorizer::default(),
            checks: AtomicUsize::new(0),
        }
    }
}
impl Authorizer for CountPolicy {
    fn authorize<'a>(&'a self, req: AuthRequest<'a>) -> BoxFut<'a, Result<Lease, AuthDenied>> {
        self.checks.fetch_add(1, Ordering::Relaxed);
        self.auth.authorize(req)
    }
}

#[tokio::test]
async fn datagrams_drop_corruption_keep_empty_messages_and_revoke_on_unpublish() {
    let routes = Arc::new(StaticPathSource::default());
    let auth = Arc::new(StaticAuthorizer::default());
    let a = node(auth.clone(), routes.clone());
    let b = node(auth.clone(), routes.clone());
    auth.allow(a.public_key(), Lease::new(LONG_TTL));
    let (out, inbound) = mem_datagram_pair(1232, 16);
    let _ingress = b.attach_datagram(inbound).unwrap();
    a.register_datagram_carrier(CARRIER, Arc::new(FixedDatagram(out.clone())))
        .unwrap();
    let handler = Arc::new(EchoDatagrams::default());
    let publish = b.publish_datagram(ENDPOINT, 1232, handler.clone()).unwrap();
    setup_route(&routes, &b, Plane::Datagram, vec![], 1232);

    let session = a
        .dial_datagram(b.public_key(), ENDPOINT, 1232)
        .await
        .unwrap();
    assert_eq!(session.max_payload(), 1202);
    assert_eq!(
        session.send(PacketBuf::from_slice(&[0; 1203])),
        Err(CoreErr::MessageTooLarge(1202))
    );
    out.corrupt_next_kind(hop::DG_DATA);
    session.send(PacketBuf::from_slice(b"discard")).unwrap();
    session.send(PacketBuf::from_slice(b"good")).unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), session.recv())
            .await
            .unwrap()
            .unwrap()
            .as_slice(),
        b"good"
    );
    session.send(PacketBuf::from_slice(b"")).unwrap();
    assert!(
        timeout(Duration::from_secs(1), session.recv())
            .await
            .unwrap()
            .unwrap()
            .is_empty()
    );
    assert_eq!(handler.0.load(Ordering::Relaxed), 1);
    drop(publish);
    assert!(matches!(
        timeout(Duration::from_millis(500), session.recv())
            .await
            .unwrap(),
        Err(CoreErr::Unpublished)
    ));
}

#[tokio::test]
async fn dropped_setup_ok_never_opens_the_destination() {
    let routes = Arc::new(StaticPathSource::default());
    let auth = Arc::new(StaticAuthorizer::default());
    let a = node(auth.clone(), routes.clone());
    let b = node(auth.clone(), routes.clone());
    auth.allow(a.public_key(), Lease::new(LONG_TTL));
    let (out, inbound) = mem_datagram_pair(1232, 16);
    inbound.drop_next_kind(setup::OK);
    let _ingress = b.attach_datagram(inbound).unwrap();
    a.register_datagram_carrier(CARRIER, Arc::new(FixedDatagram(out)))
        .unwrap();
    let handler = Arc::new(EchoDatagrams::default());
    let _published = b.publish_datagram(ENDPOINT, 1232, handler.clone()).unwrap();
    setup_route(&routes, &b, Plane::Datagram, vec![], 1232);
    assert!(matches!(
        a.dial_datagram(b.public_key(), ENDPOINT, 1232).await,
        Err(CoreErr::Timeout)
    ));
    assert_eq!(handler.0.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn stream_status_authenticated_fin_and_unexpected_eof_are_distinct() {
    let routes = Arc::new(StaticPathSource::default());
    let auth = Arc::new(StaticAuthorizer::default());
    let a = node(auth.clone(), routes.clone());
    let b = node(auth.clone(), routes.clone());
    auth.allow(a.public_key(), Lease::new(LONG_TTL));
    let base = MemStreamChannel::new(2048, 512);
    let listener = task(base.listen(b"out").unwrap().serve_stream(b.clone()));
    let (abort, stopped) = watch::channel(false);
    a.register_stream_carrier(CARRIER, Arc::new(FaultCarrier(base, stopped, None)))
        .unwrap();
    setup_route(&routes, &b, Plane::Stream, vec![], 20);
    let refused = b.publish_stream(ENDPOINT, Arc::new(Refused)).unwrap();
    assert!(matches!(
        a.dial_stream(b.public_key(), ENDPOINT).await,
        Err(CoreErr::TargetRefused)
    ));
    drop(refused);

    let _published = b.publish_stream(ENDPOINT, Arc::new(EchoStream)).unwrap();
    let stream = a.dial_stream(b.public_key(), ENDPOINT).await.unwrap();
    stream.write_all(b"bytes before FIN").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut buffer = [0; 256];
    let n = timeout(Duration::from_secs(1), stream.read(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..n], b"bytes before FIN");
    assert_eq!(stream.read(&mut buffer).await.unwrap(), 0);
    drop(stream);

    let abrupt = a.dial_stream(b.public_key(), ENDPOINT).await.unwrap();
    abort.send_replace(true);
    assert_eq!(
        timeout(Duration::from_secs(1), abrupt.read(&mut buffer))
            .await
            .unwrap(),
        Err(CoreErr::UnexpectedEof)
    );
    listener.abort();
}

struct FaultCarrier(
    MemStreamChannel,
    watch::Receiver<bool>,
    Option<watch::Receiver<u16>>,
);
impl StreamChannel for FaultCarrier {
    type Stream = FaultStream;

    fn caps(&self) -> ChannelCaps {
        self.0.caps()
    }
    async fn dial_stream(&self, locator: &[u8]) -> Result<FaultStream, CoreErr> {
        Ok(FaultStream(
            self.0.dial_stream(locator).await?,
            self.1.clone(),
            self.2.clone(),
        ))
    }
}
struct FaultStream(
    MemStream,
    watch::Receiver<bool>,
    Option<watch::Receiver<u16>>,
);
impl AsyncStream for FaultStream {
    type Read = FaultReader;
    type Write = MemWrite;

    fn caps(&self) -> ChannelCaps {
        match &self.2 {
            Some(mtu) => ChannelCaps::dynamic(mtu.clone(), true),
            None => self.0.caps(),
        }
    }
    fn split(self) -> (FaultReader, MemWrite) {
        let (reader, writer) = self.0.split();
        let mut abort_rx = self.1.clone();
        let abort_wait = Box::pin(async move {
            let _ = abort_rx.wait_for(|&stopped| stopped).await;
        });
        (FaultReader(reader, self.1, abort_wait), writer)
    }
}
struct FaultReader(MemRead, watch::Receiver<bool>, BoxFut<'static, ()>);
impl StreamRead for FaultReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, CoreErr>> {
        if *self.1.borrow() || self.2.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Ok(0));
        }
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn three_hops_clamp_both_planes_and_renew_every_lease_live() {
    let routes = Arc::new(StaticPathSource::default());
    let creds = Arc::new(StaticCredentials::default());
    creds.set_default(vec![9; 96]);
    let policies: Vec<_> = (0..5).map(|_| Arc::new(CountPolicy::new())).collect();
    let mut nodes = Vec::with_capacity(5);
    for (idx, auth) in policies.iter().enumerate() {
        if idx == 0 {
            nodes.push(node_with_creds(auth.clone(), routes.clone(), creds.clone()));
        } else {
            nodes.push(node(auth.clone(), routes.clone()));
        }
    }
    let (a, b) = (&nodes[0], &nodes[4]);
    for auth in &policies {
        auth.auth
            .allow(a.public_key(), Lease::new(Duration::from_millis(1300)));
    }
    let mut listeners = Vec::new();
    let mut transit_guards = Vec::new();
    for index in 0..4 {
        let mtu = if index == 2 { 1400 } else { 1500 };
        let (stream, datagram) = (
            MemStreamChannel::new(mtu, 256),
            MemDatagramChannel::new(mtu),
        );
        listeners.push(task(
            stream
                .listen(b"out")
                .unwrap()
                .serve_stream(nodes[index + 1].clone()),
        ));
        listeners.push(task(
            datagram
                .listen(b"out")
                .unwrap()
                .serve_datagram(nodes[index + 1].clone()),
        ));
        let scope = &nodes[index];
        if index == 0 {
            scope
                .register_stream_carrier(CARRIER, Arc::new(stream))
                .unwrap();
            scope
                .register_datagram_carrier(CARRIER, Arc::new(datagram))
                .unwrap();
        } else {
            transit_guards.push(scope.publish_stream_route("next", stream, b"out").unwrap());
            transit_guards.push(
                scope
                    .publish_datagram_route("next", datagram, b"out")
                    .unwrap(),
            );
        }
    }
    let hops: Vec<_> = nodes[1..4]
        .iter()
        .map(|scope| HopSpec {
            peer: scope.public_key(),
            target: "next".into(),
        })
        .collect();
    let _stream = b.publish_stream(ENDPOINT, Arc::new(EchoStream)).unwrap();
    let _datagram = b
        .publish_datagram("echo-dg", 1232, Arc::new(EchoDatagrams::default()))
        .unwrap();
    setup_route(&routes, b, Plane::Stream, hops.clone(), 1300);
    let explicit = |minimum| ExplicitPath {
        id: 33,
        first_channel: CARRIER.into(),
        first_locator: b"out".to_vec(),
        min_mtu: minimum,
        hops: hops.clone(),
    };
    routes.set(b.public_key(), "echo-dg", Plane::Datagram, explicit(1300));

    let stream = a.dial_stream(b.public_key(), ENDPOINT).await.unwrap();
    assert_eq!(stream.max_write_size(), 1381);
    let datagram = a
        .dial_datagram(b.public_key(), "echo-dg", 1300)
        .await
        .unwrap();
    assert_eq!(datagram.max_payload(), 1370);
    for index in 0..15 {
        let bytes = [index; 257];
        stream.write_all(&bytes).await.unwrap();
        let mut received = [0; 257];
        let mut offset = 0;
        while offset < received.len() {
            let n = timeout(Duration::from_secs(1), stream.read(&mut received[offset..]))
                .await
                .unwrap()
                .unwrap();
            assert_ne!(n, 0);
            offset += n;
        }
        assert_eq!(bytes, received);
        datagram.send(PacketBuf::from_slice(&bytes)).unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), datagram.recv())
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            &bytes
        );
        sleep(Duration::from_millis(100)).await;
    }
    for policy in &policies[1..] {
        assert!(policy.checks.load(Ordering::Relaxed) >= 4);
    }

    routes.set(b.public_key(), "echo-dg", Plane::Datagram, explicit(1450));
    let mut outcomes = routes.outcomes();
    let expected = CoreErr::HopRejected {
        index: 1,
        reason: Box::new(CoreErr::MtuTooSmall(1400)),
    };
    let rejected = timeout(
        Duration::from_secs(1),
        a.dial_datagram(b.public_key(), "echo-dg", 1450),
    )
    .await
    .unwrap();
    assert!(matches!(rejected, Err(ref error) if *error == expected));
    assert_eq!(
        outcomes.recv().await.unwrap(),
        (33, PathOutcome::Failed(expected))
    );

    nodes[2].revoke_peer(&a.public_key());
    let error = timeout(Duration::from_millis(500), datagram.recv())
        .await
        .unwrap();
    assert!(
        matches!(error, Err(CoreErr::HopRejected { index: 1, reason }) if *reason == CoreErr::Revoked)
    );
    drop(transit_guards);
    for listener in listeners {
        listener.abort();
    }
}

struct TimeoutPolicy;
impl Authorizer for TimeoutPolicy {
    fn authorize<'a>(&'a self, _: AuthRequest<'a>) -> BoxFut<'a, Result<Lease, AuthDenied>> {
        Box::pin(std::future::pending())
    }
}

#[tokio::test(start_paused = true)]
async fn policy_times_out_and_errors_fail_closed() {
    let peer = ScopeKeypair::generate().public_key();
    let req = AuthRequest {
        peer,
        target: TargetRef::Endpoint {
            name: ENDPOINT,
            plane: Plane::Stream,
        },
        credential: &[],
        is_renewal: false,
    };
    let blocked = AuthGate::new(Arc::new(TimeoutPolicy));
    let start = tokio::time::Instant::now();
    assert_eq!(blocked.authorize(req).await.err(), Some(CoreErr::Timeout));
    assert_eq!(start.elapsed(), Duration::from_millis(500));
    let empty = AuthGate::new(Arc::new(StaticAuthorizer::default()));
    assert_eq!(empty.authorize(req).await.err(), Some(CoreErr::Denied));
}

#[tokio::test]
async fn live_stream_caps_rechunk_data_and_cancel_below_the_floor() {
    let routes = Arc::new(StaticPathSource::default());
    let auth = Arc::new(StaticAuthorizer::default());
    let a = node(auth.clone(), routes.clone());
    let b = node(auth.clone(), routes.clone());
    auth.allow(a.public_key(), Lease::new(LONG_TTL));
    let memory = MemStreamChannel::new(2048, 512);
    let listener = task(memory.listen(b"out").unwrap().serve_stream(b.clone()));
    let (_keep_open, open) = watch::channel(false);
    let (mtu, watch) = watch::channel(2048);
    a.register_stream_carrier(CARRIER, Arc::new(FaultCarrier(memory, open, Some(watch))))
        .unwrap();
    let _published = b.publish_stream(ENDPOINT, Arc::new(EchoStream)).unwrap();
    setup_route(&routes, &b, Plane::Stream, vec![], 1000);
    let stream = a.dial_stream(b.public_key(), ENDPOINT).await.unwrap();

    mtu.send_replace(1200);
    let request = [7; 1900];
    stream.write_all(&request).await.unwrap();
    let mut reply = [0; 1900];
    let mut offset = 0;
    while offset < reply.len() {
        let count = timeout(Duration::from_secs(1), stream.read(&mut reply[offset..]))
            .await
            .unwrap()
            .unwrap();
        assert_ne!(count, 0);
        offset += count;
    }
    assert_eq!(request, reply);
    mtu.send_replace(999);
    assert_eq!(
        timeout(Duration::from_secs(1), stream.read(&mut reply))
            .await
            .unwrap(),
        Err(CoreErr::MtuTooSmall(999))
    );
    listener.abort();
}

#[tokio::test]
async fn per_target_epochs_isolate_revocations_and_allow_many_outbound_dials() {
    let routes = Arc::new(StaticPathSource::default());
    let auth = Arc::new(StaticAuthorizer::default());
    let a = node(auth.clone(), routes.clone());
    let b = node(auth.clone(), routes.clone());
    auth.allow(a.public_key(), Lease::new(LONG_TTL));

    // Unpublishing an unrelated endpoint or revoking another peer must not abort
    // an in-flight track for a different peer/endpoint.
    let gate = b.auth_gate();
    let other_peer = ScopeKeypair::generate().public_key();
    let epoch = gate.epoch_for_endpoint(a.public_key(), Some(ENDPOINT));
    gate.revoke_endpoint("unrelated");
    gate.revoke_peer(other_peer);
    let lease = Arc::new(LeaseHandle::new(LONG_TTL).unwrap());
    assert!(
        gate.track_endpoint(epoch, a.public_key(), Some(ENDPOINT), &lease)
            .is_ok()
    );

    // Saturating A's inbound per-peer pending quota for B must not block A's own
    // outbound dials to B, nor should unpublishing an unrelated endpoint on A.
    let _inbound_guards: Vec<_> = (0..8)
        .map(|_| a.auth_gate().pending(b.public_key()).unwrap())
        .collect();
    assert!(matches!(
        a.auth_gate().pending(b.public_key()),
        Err(CoreErr::Busy)
    ));
    let carrier = MemStreamChannel::new(4096, 1024);
    let listener = task(carrier.listen(b"out").unwrap().serve_stream(b.clone()));
    a.register_stream_carrier(CARRIER, Arc::new(carrier))
        .unwrap();
    let _published = b.publish_stream(ENDPOINT, Arc::new(EchoStream)).unwrap();
    setup_route(&routes, &b, Plane::Stream, vec![], 64);

    let stream = a.dial_stream(b.public_key(), ENDPOINT).await.unwrap();
    stream.write_all(b"ok").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut buf = [0u8; 8];
    let n = timeout(Duration::from_secs(1), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"ok");
    drop(stream);
    listener.abort();
}

#[tokio::test]
async fn queued_stream_bytes_survive_relay_eof_after_authenticated_fin() {
    let routes = Arc::new(StaticPathSource::default());
    let auth = Arc::new(StaticAuthorizer::default());
    let a = node(auth.clone(), routes.clone());
    let h = node(auth.clone(), routes.clone());
    let b = node(auth.clone(), routes.clone());
    auth.allow(a.public_key(), Lease::new(LONG_TTL));

    let leg1 = MemStreamChannel::new(4096, 1024);
    let leg2 = MemStreamChannel::new(4096, 1024);
    let l1 = task(leg1.listen(b"h").unwrap().serve_stream(h.clone()));
    let l2 = task(leg2.listen(b"b").unwrap().serve_stream(b.clone()));
    a.register_stream_carrier(CARRIER, Arc::new(leg1)).unwrap();
    let _h_transit = h.publish_stream_route("to-b", leg2, b"b").unwrap();
    let _pub = b.publish_stream(ENDPOINT, Arc::new(EchoStream)).unwrap();
    routes.set(
        b.public_key(),
        ENDPOINT,
        Plane::Stream,
        ExplicitPath {
            id: 77,
            first_channel: CARRIER.into(),
            first_locator: b"h".to_vec(),
            min_mtu: 64,
            hops: vec![HopSpec {
                peer: h.public_key(),
                target: "to-b".into(),
            }],
        },
    );

    // Repeat several times so B's close + relay ST_CLOSE(UnexpectedEof) races A's read.
    for round in 0..10u8 {
        let stream = a.dial_stream(b.public_key(), ENDPOINT).await.unwrap();
        let payload = [round; 64];
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();
        // Give B and H time to finish, send ST_FIN, close TCP, and emit relay ST_CLOSE.
        sleep(Duration::from_millis(20)).await;
        let mut received = Vec::new();
        let mut buf = [0u8; 32];
        loop {
            let n = timeout(Duration::from_secs(1), stream.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        assert_eq!(received, payload);
    }
    l1.abort();
    l2.abort();
}
