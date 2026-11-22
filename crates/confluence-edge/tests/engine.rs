use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use confluence_core::*;
use confluence_core::{
    grant::GrantSpec,
    wire::{hop, setup},
};
use confluence_plugins::{
    AuthAclWrapper, MemDatagramChannel, MemDatagramLink, MemStreamChannel, StaticAcl,
    StaticPathSource, TokioSpawner, mem_datagram_pair, mem_stream_pair,
};
use tokio::{
    sync::watch,
    task::JoinHandle,
    time::{sleep, timeout},
};

const TAG: u64 = 42;
const SCOPE: ScopeId = ScopeId(7);
const ENDPOINT: &str = "echo";
const LONG_TTL: Duration = Duration::from_secs(15);

fn node(acl: Arc<dyn AccessControl>, routes: Arc<StaticPathSource>) -> ScopeInstance {
    ScopeInstance::new(
        SCOPE,
        ScopeKeypair::generate(),
        acl,
        routes,
        Arc::new(TokioSpawner),
    )
}
fn setup_route(
    routes: &StaticPathSource,
    dst: &ScopeInstance,
    plane: Plane,
    hops: Vec<HopSpec>,
    min_mtu: u16,
) {
    routes.set(
        SCOPE,
        dst.public_key(),
        ENDPOINT,
        plane,
        ExplicitPath {
            id: 19,
            first_channel: TAG,
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
    fn open(&self, _peer: PublicKey) -> BoxFut<'_, Result<Box<dyn AsyncStream>, CoreErr>> {
        Box::pin(async {
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
        })
    }
}
#[derive(Default)]
struct EchoDatagrams(AtomicUsize);
impl DatagramEndpointHandler for EchoDatagrams {
    fn open(&self, _peer: PublicKey) -> BoxFut<'_, Result<Arc<dyn DatagramLink>, CoreErr>> {
        Box::pin(async {
            self.0.fetch_add(1, Ordering::Relaxed);
            let (server, app) = mem_datagram_pair(u16::MAX, 32);
            task(async move {
                while let Ok(packet) = app.recv().await {
                    if app.send(packet).await.is_err() {
                        break;
                    }
                }
            });
            Ok(server as Arc<dyn DatagramLink>)
        })
    }
}
struct Refused;
impl StreamEndpointHandler for Refused {
    fn open(&self, _peer: PublicKey) -> BoxFut<'_, Result<Box<dyn AsyncStream>, CoreErr>> {
        Box::pin(async { Err(CoreErr::TargetRefused) })
    }
}
struct FixedDatagram(Arc<MemDatagramLink>);
impl DatagramChannel for FixedDatagram {
    fn caps(&self) -> ChannelCaps {
        self.0.caps()
    }
    fn open_link<'a>(&'a self, _: &'a [u8]) -> BoxFut<'a, Result<Arc<dyn DatagramLink>, CoreErr>> {
        Box::pin(async { Ok(self.0.clone() as Arc<dyn DatagramLink>) })
    }
}
struct CountPolicy {
    acl: StaticAcl,
    checks: AtomicUsize,
}
impl CountPolicy {
    fn new() -> Self {
        Self {
            acl: StaticAcl::default(),
            checks: AtomicUsize::new(0),
        }
    }
}
impl AccessControl for CountPolicy {
    fn verify<'a>(
        &'a self,
        scope: ScopeId,
        peer: &'a PublicKey,
        action: ActionRef<'a>,
        cred: &'a [u8],
    ) -> BoxFut<'a, Result<GrantSpec, PolicyDenied>> {
        self.checks.fetch_add(1, Ordering::Relaxed);
        self.acl.verify(scope, peer, action, cred)
    }
}

#[tokio::test]
async fn datagrams_drop_corruption_keep_empty_messages_and_revoke_on_unpublish() {
    let routes = Arc::new(StaticPathSource::default());
    let acl = Arc::new(StaticAcl::default());
    let a = node(acl.clone(), routes.clone());
    let b = node(acl.clone(), routes.clone());
    acl.allow(SCOPE, a.public_key(), GrantSpec::new(LONG_TTL, 0));
    let (out, inbound) = mem_datagram_pair(1232, 16);
    let _ingress = b.attach_datagram(inbound).unwrap();
    a.register_datagram_channel(TAG, Arc::new(FixedDatagram(out.clone())))
        .unwrap();
    let handler = Arc::new(EchoDatagrams::default());
    let publish = b.publish_datagram(ENDPOINT, 1232, handler.clone()).unwrap();
    setup_route(&routes, &b, Plane::Datagram, vec![], 1232);

    let session = a
        .dial_datagram(b.public_key(), ENDPOINT, 1232, b"")
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
    let acl = Arc::new(StaticAcl::default());
    let a = node(acl.clone(), routes.clone());
    let b = node(acl.clone(), routes.clone());
    acl.allow(SCOPE, a.public_key(), GrantSpec::new(LONG_TTL, 0));
    let (out, inbound) = mem_datagram_pair(1232, 16);
    inbound.drop_next_kind(setup::OK);
    let _ingress = b.attach_datagram(inbound).unwrap();
    a.register_datagram_channel(TAG, Arc::new(FixedDatagram(out)))
        .unwrap();
    let handler = Arc::new(EchoDatagrams::default());
    let _published = b.publish_datagram(ENDPOINT, 1232, handler.clone()).unwrap();
    setup_route(&routes, &b, Plane::Datagram, vec![], 1232);
    assert!(matches!(
        a.dial_datagram(b.public_key(), ENDPOINT, 1232, &[]).await,
        Err(CoreErr::Timeout)
    ));
    assert_eq!(handler.0.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn stream_status_authenticated_fin_and_unexpected_eof_are_distinct() {
    let routes = Arc::new(StaticPathSource::default());
    let acl = Arc::new(StaticAcl::default());
    let a = node(acl.clone(), routes.clone());
    let b = node(acl.clone(), routes.clone());
    acl.allow(SCOPE, a.public_key(), GrantSpec::new(LONG_TTL, 0));
    let base = MemStreamChannel::new(2048, 512);
    let listener = task(base.listen(b"out").unwrap().serve_stream(b.clone()));
    let (abort, stopped) = watch::channel(false);
    a.register_stream_channel(TAG, Arc::new(FaultCarrier(base, stopped, None)))
        .unwrap();
    setup_route(&routes, &b, Plane::Stream, vec![], 20);
    let refused = b.publish_stream(ENDPOINT, Arc::new(Refused)).unwrap();
    assert!(matches!(
        a.dial_stream(b.public_key(), ENDPOINT, &[]).await,
        Err(CoreErr::TargetRefused)
    ));
    drop(refused);

    let _published = b.publish_stream(ENDPOINT, Arc::new(EchoStream)).unwrap();
    let stream = a.dial_stream(b.public_key(), ENDPOINT, &[]).await.unwrap();
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

    let abrupt = a.dial_stream(b.public_key(), ENDPOINT, &[]).await.unwrap();
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
    fn caps(&self) -> ChannelCaps {
        self.0.caps()
    }
    fn dial_stream<'a>(
        &'a self,
        locator: &'a [u8],
    ) -> BoxFut<'a, Result<Box<dyn AsyncStream>, CoreErr>> {
        Box::pin(async {
            Ok(Box::new(FaultStream(
                self.0.dial_stream(locator).await?,
                self.1.clone(),
                self.2.clone(),
            )) as Box<dyn AsyncStream>)
        })
    }
}
struct FaultStream(
    Box<dyn AsyncStream>,
    watch::Receiver<bool>,
    Option<watch::Receiver<u16>>,
);
impl AsyncStream for FaultStream {
    fn caps(&self) -> ChannelCaps {
        match &self.2 {
            Some(mtu) => ChannelCaps {
                effective_mtu: *mtu.borrow(),
                reliable_underlay: true,
                mtu_watch: mtu.clone(),
            },
            None => self.0.caps(),
        }
    }
    fn split(self: Box<Self>) -> (Box<dyn StreamRead>, Box<dyn StreamWrite>) {
        let (reader, writer) = self.0.split();
        (Box::new(FaultReader(reader, self.1)), writer)
    }
}
struct FaultReader(Box<dyn StreamRead>, watch::Receiver<bool>);
impl StreamRead for FaultReader {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFut<'a, Result<usize, CoreErr>> {
        Box::pin(async {
            if *self.1.borrow() {
                return Ok(0);
            }
            tokio::select! {
                biased;
                _ = self.1.changed() => Ok(0),
                result = self.0.read(buf) => result,
            }
        })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn three_hops_clamp_both_planes_and_renew_every_grant_live() {
    let routes = Arc::new(StaticPathSource::default());
    let policies: Vec<_> = (0..5).map(|_| Arc::new(CountPolicy::new())).collect();
    let nodes: Vec<_> = policies
        .iter()
        .map(|acl| node(acl.clone(), routes.clone()))
        .collect();
    let (a, b) = (&nodes[0], &nodes[4]);
    for acl in &policies {
        acl.acl.allow(
            SCOPE,
            a.public_key(),
            GrantSpec::new(Duration::from_millis(1300), 0),
        );
    }
    let mut listeners = Vec::new();
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
                .register_stream_channel(TAG, Arc::new(stream))
                .unwrap();
            scope
                .register_datagram_channel(TAG, Arc::new(datagram))
                .unwrap();
        } else {
            scope
                .register_stream_channel(TAG, Arc::new(AuthAclWrapper::new(scope, TAG, stream)))
                .unwrap();
            scope
                .register_datagram_channel(TAG, Arc::new(AuthAclWrapper::new(scope, TAG, datagram)))
                .unwrap();
        }
    }
    let hops: Vec<_> = nodes[1..4]
        .iter()
        .map(|scope| HopSpec {
            peer: scope.public_key(),
            channel: TAG,
            locator: b"out".to_vec(),
            credential: vec![9; 96],
        })
        .collect();
    let _stream = b.publish_stream(ENDPOINT, Arc::new(EchoStream)).unwrap();
    let _datagram = b
        .publish_datagram("echo-dg", 1232, Arc::new(EchoDatagrams::default()))
        .unwrap();
    setup_route(&routes, b, Plane::Stream, hops.clone(), 1300);
    let explicit = |minimum| ExplicitPath {
        id: 33,
        first_channel: TAG,
        first_locator: b"out".to_vec(),
        min_mtu: minimum,
        hops: hops.clone(),
    };
    routes.set(
        SCOPE,
        b.public_key(),
        "echo-dg",
        Plane::Datagram,
        explicit(1300),
    );

    let stream = a
        .dial_stream(b.public_key(), ENDPOINT, &[3; 96])
        .await
        .unwrap();
    assert_eq!(stream.max_write_size(), 1381);
    let datagram = a
        .dial_datagram(b.public_key(), "echo-dg", 1300, &[3; 96])
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

    routes.set(
        SCOPE,
        b.public_key(),
        "echo-dg",
        Plane::Datagram,
        explicit(1450),
    );
    let mut outcomes = routes.outcomes();
    let expected = CoreErr::HopRejected {
        index: 1,
        reason: Box::new(CoreErr::MtuTooSmall(1400)),
    };
    let rejected = timeout(
        Duration::from_secs(1),
        a.dial_datagram(b.public_key(), "echo-dg", 1450, &[]),
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
    for listener in listeners {
        listener.abort();
    }
}

struct TimeoutPolicy;
impl AccessControl for TimeoutPolicy {
    fn verify<'a>(
        &'a self,
        _: ScopeId,
        _: &'a PublicKey,
        _: ActionRef<'a>,
        _: &'a [u8],
    ) -> BoxFut<'a, Result<GrantSpec, PolicyDenied>> {
        Box::pin(std::future::pending())
    }
}
#[tokio::test(start_paused = true)]
async fn policy_times_out_and_errors_fail_closed() {
    let peer = ScopeKeypair::generate().public_key();
    let action = ActionRef::EndpointOpen {
        ep: ENDPOINT,
        plane: Plane::Stream,
    };
    let blocked = PolicyGate::new(SCOPE, Arc::new(TimeoutPolicy));
    let start = tokio::time::Instant::now();
    assert_eq!(
        blocked.verify(&peer, action, &[]).await,
        Err(CoreErr::Timeout)
    );
    assert_eq!(start.elapsed(), Duration::from_millis(500));
    let empty = PolicyGate::new(SCOPE, Arc::new(StaticAcl::default()));
    assert_eq!(empty.verify(&peer, action, &[]).await, Err(CoreErr::Denied));
}

#[tokio::test]
async fn live_stream_caps_rechunk_data_and_cancel_below_the_floor() {
    let routes = Arc::new(StaticPathSource::default());
    let acl = Arc::new(StaticAcl::default());
    let a = node(acl.clone(), routes.clone());
    let b = node(acl.clone(), routes.clone());
    acl.allow(SCOPE, a.public_key(), GrantSpec::new(LONG_TTL, 0));
    let memory = MemStreamChannel::new(2048, 512);
    let listener = task(memory.listen(b"out").unwrap().serve_stream(b.clone()));
    let (_keep_open, open) = watch::channel(false);
    let (mtu, watch) = watch::channel(2048);
    a.register_stream_channel(TAG, Arc::new(FaultCarrier(memory, open, Some(watch))))
        .unwrap();
    let _published = b.publish_stream(ENDPOINT, Arc::new(EchoStream)).unwrap();
    setup_route(&routes, &b, Plane::Stream, vec![], 1000);
    let stream = a.dial_stream(b.public_key(), ENDPOINT, &[]).await.unwrap();

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
    let acl = Arc::new(StaticAcl::default());
    let a = node(acl.clone(), routes.clone());
    let b = node(acl.clone(), routes.clone());
    acl.allow(SCOPE, a.public_key(), GrantSpec::new(LONG_TTL, 0));

    // Unpublishing an unrelated endpoint or revoking another peer must not abort
    // an in-flight track for a different peer/endpoint.
    let gate = b.policy();
    let other_peer = ScopeKeypair::generate().public_key();
    let epoch = gate.epoch_for(a.public_key(), Some(ENDPOINT));
    gate.revoke_endpoint("unrelated");
    gate.revoke_peer(other_peer);
    let grant = Arc::new(confluence_core::grant::GrantEnforcer::new(GrantSpec::new(LONG_TTL, 0)).unwrap());
    assert!(gate.track(epoch, a.public_key(), Some(ENDPOINT), &grant).is_ok());

    // Saturating A's inbound per-peer pending quota for B must not block A's own
    // outbound dials to B, nor should unpublishing an unrelated endpoint on A.
    let _inbound_guards: Vec<_> = (0..8)
        .map(|_| a.policy().pending(b.public_key()).unwrap())
        .collect();
    assert!(matches!(
        a.policy().pending(b.public_key()),
        Err(CoreErr::Busy)
    ));
    let carrier = MemStreamChannel::new(4096, 1024);
    let listener = task(carrier.listen(b"out").unwrap().serve_stream(b.clone()));
    a.register_stream_channel(TAG, Arc::new(carrier)).unwrap();
    let _published = b.publish_stream(ENDPOINT, Arc::new(EchoStream)).unwrap();
    setup_route(&routes, &b, Plane::Stream, vec![], 64);

    let stream = a.dial_stream(b.public_key(), ENDPOINT, &[]).await.unwrap();
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
    let acl = Arc::new(StaticAcl::default());
    let a = node(acl.clone(), routes.clone());
    let h = node(acl.clone(), routes.clone());
    let b = node(acl.clone(), routes.clone());
    acl.allow(SCOPE, a.public_key(), GrantSpec::new(LONG_TTL, 0));

    let leg1 = MemStreamChannel::new(4096, 1024);
    let leg2 = MemStreamChannel::new(4096, 1024);
    let l1 = task(leg1.listen(b"h").unwrap().serve_stream(h.clone()));
    let l2 = task(leg2.listen(b"b").unwrap().serve_stream(b.clone()));
    a.register_stream_channel(TAG, Arc::new(leg1)).unwrap();
    h.register_stream_channel(TAG, Arc::new(AuthAclWrapper::new(&h, TAG, leg2)))
        .unwrap();
    let _pub = b.publish_stream(ENDPOINT, Arc::new(EchoStream)).unwrap();
    routes.set(
        SCOPE,
        b.public_key(),
        ENDPOINT,
        Plane::Stream,
        ExplicitPath {
            id: 77,
            first_channel: TAG,
            first_locator: b"h".to_vec(),
            min_mtu: 64,
            hops: vec![HopSpec {
                peer: h.public_key(),
                channel: TAG,
                locator: b"b".to_vec(),
                credential: Vec::new(),
            }],
        },
    );

    // Repeat several times so B's close + relay ST_CLOSE(UnexpectedEof) races A's read.
    for round in 0..10u8 {
        let stream = a.dial_stream(b.public_key(), ENDPOINT, &[]).await.unwrap();
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
