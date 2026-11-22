#![cfg(target_os = "linux")]

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use confluence_core::grant::GrantSpec;
use confluence_core::*;
use confluence_edge::{
    Destination, TcpTarget, UdpTarget, admin::AdminSocket, serve_local_tcp, serve_local_udp,
};
use confluence_net::{TcpCarrier, TcpIo, UdpCarrier, serve_tcp};
use confluence_plugins::{
    AuthAclWrapper, MemDatagramChannel, MemStreamChannel, StaticAcl, StaticPathSource,
    TokioSpawner, mem_datagram_pair,
};
use confluence_relay::PassiveRelay;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket, UnixStream},
    sync::oneshot,
    time::{sleep, timeout},
};

const ID: ScopeId = ScopeId(21);
const TAG: u64 = 100;
const EP: &str = "echo";
const WAIT: Duration = Duration::from_secs(5);

fn local() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}
fn node(acl: &Arc<StaticAcl>, routes: &Arc<StaticPathSource>) -> ScopeInstance {
    ScopeInstance::new(
        ID,
        ScopeKeypair::generate(),
        acl.clone(),
        routes.clone(),
        Arc::new(TokioSpawner),
    )
}
fn setup() -> (
    Arc<StaticAcl>,
    Arc<StaticPathSource>,
    ScopeInstance,
    ScopeInstance,
) {
    let acl = Arc::new(StaticAcl::default());
    let routes = Arc::new(StaticPathSource::default());
    let a = node(&acl, &routes);
    let b = node(&acl, &routes);
    acl.allow(
        ID,
        a.public_key(),
        GrantSpec::new(Duration::from_secs(45), 0),
    );
    (acl, routes, a, b)
}
fn route(
    routes: &StaticPathSource,
    b: &ScopeInstance,
    plane: Plane,
    name: &str,
    first_locator: Vec<u8>,
    hops: Vec<HopSpec>,
) {
    routes.set(
        ID,
        b.public_key(),
        name,
        plane,
        ExplicitPath {
            id: 40,
            first_channel: TAG,
            first_locator,
            min_mtu: 0,
            hops,
        },
    );
}
fn hop(at: &ScopeInstance, locator: impl Into<Vec<u8>>) -> HopSpec {
    HopSpec {
        peer: at.public_key(),
        channel: TAG,
        locator: locator.into(),
        credential: Vec::new(),
    }
}
fn destination(node: &ScopeInstance, endpoint: &str) -> Destination {
    Destination {
        peer: node.public_key(),
        endpoint: endpoint.into(),
        credential: Vec::new(),
    }
}
fn start_udp_echo(socket: UdpSocket) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut bytes = vec![0; 65_507];
        while let Ok((n, peer)) = socket.recv_from(&mut bytes).await {
            if socket.send_to(&bytes[..n], peer).await.is_err() {
                break;
            }
        }
    })
}
fn start_tcp_echo(listener: TcpListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (mut read, mut write) = stream.into_split();
        tokio::io::copy(&mut read, &mut write).await.unwrap();
        write.shutdown().await.unwrap();
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_port_forward_backpressures_a_stalled_reader_across_three_native_hops() {
    let (acl, routes, a, b) = setup();
    let h1 = node(&acl, &routes);
    let h2 = node(&acl, &routes);
    let h3 = node(&acl, &routes);
    let carrier = TcpCarrier::default();
    a.register_stream_channel(TAG, Arc::new(carrier)).unwrap();
    for node in [&h1, &h2, &h3] {
        node.register_stream_channel(TAG, Arc::new(AuthAclWrapper::new(node, TAG, carrier)))
            .unwrap();
    }
    let mut ingress = Vec::new();
    let mut locators = Vec::new();
    for node in [&h1, &h2, &h3, &b] {
        let listener = TcpListener::bind(local()).await.unwrap();
        locators.push(listener.local_addr().unwrap().to_string().into_bytes());
        ingress.push(tokio::spawn(serve_tcp(listener, node.clone(), carrier)));
    }
    route(
        &routes,
        &b,
        Plane::Stream,
        EP,
        locators[0].clone(),
        vec![
            hop(&h1, locators[1].clone()),
            hop(&h2, locators[2].clone()),
            hop(&h3, locators[3].clone()),
        ],
    );
    let target = TcpListener::bind(local()).await.unwrap();
    let _published = b
        .publish_stream(EP, Arc::new(TcpTarget(target.local_addr().unwrap())))
        .unwrap();
    let local_edge = TcpListener::bind(local()).await.unwrap();
    let client_addr = local_edge.local_addr().unwrap();
    let forwarding = tokio::spawn(serve_local_tcp(local_edge, a, destination(&b, EP)));

    let (drain, resume) = oneshot::channel();
    let (accepted, ready) = oneshot::channel();
    let sink = tokio::spawn(async move {
        let (mut socket, _) = target.accept().await.unwrap();
        accepted.send(()).unwrap();
        resume.await.unwrap();
        let transferred = tokio::io::copy(&mut socket, &mut tokio::io::sink())
            .await
            .unwrap();
        socket.write_all(&transferred.to_be_bytes()).await.unwrap();
        socket.shutdown().await.unwrap();
        transferred
    });

    let mut client = TcpStream::connect(client_addr).await.unwrap();
    timeout(WAIT, ready).await.unwrap().unwrap();
    let baseline = rss_kib();
    const TOTAL: usize = 32 * 1024 * 1024;
    let sent = Arc::new(AtomicUsize::new(0));
    let writer_count = sent.clone();
    let writer = tokio::spawn(async move {
        let block = [0x42; 32 * 1024];
        for _ in 0..TOTAL / block.len() {
            client.write_all(&block).await.unwrap();
            writer_count.fetch_add(block.len(), Ordering::Relaxed);
        }
        client.shutdown().await.unwrap();
        let count = client.read_u64().await.unwrap();
        let mut eof = [0];
        assert_eq!(client.read(&mut eof).await.unwrap(), 0);
        count
    });

    sleep(Duration::from_millis(350)).await;
    assert!(
        sent.load(Ordering::Relaxed) < TOTAL,
        "the stalled target did not apply backpressure"
    );
    let growth = rss_kib().saturating_sub(baseline);
    assert!(growth < 24 * 1024, "stalled path grew by {growth} KiB");
    drain.send(()).unwrap();
    let (written, read) = timeout(Duration::from_secs(20), async {
        tokio::join!(writer, sink)
    })
    .await
    .unwrap();
    assert_eq!(written.unwrap(), TOTAL as u64);
    assert_eq!(read.unwrap(), TOTAL as u64);
    forwarding.abort();
    for listener in ingress {
        listener.abort();
    }
}
fn rss_kib() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_udp_emsgsize_at_a_relay_triggers_authenticated_mtu_recovery() {
    let (acl, routes, a, b) = setup();
    let relay = node(&acl, &routes);
    let discovery = UdpCarrier::new(u16::MAX).unwrap();
    let ingress = discovery.bind(local()).unwrap();
    let native_addr = ingress.local_addr().unwrap();
    let calibration = discovery.connect_from(local(), native_addr).await.unwrap();
    // Use the actual kernel ceiling also in sandboxes that set a 1500-byte
    // loopback MTU. The calibration packet is too large to reach the socket.
    let Err(CoreErr::MtuTooSmall(physical)) = calibration
        .send(PacketBuf::from_slice(&vec![0; u16::MAX as usize]))
        .await
    else {
        panic!("the kernel accepted a 65,535-byte IPv4 UDP payload")
    };
    drop(calibration);
    let advertised = physical.saturating_add(48);
    let carrier = UdpCarrier::new(advertised).unwrap();
    let native = tokio::spawn(ingress.serve(b.clone()));
    relay
        .register_datagram_channel(TAG, Arc::new(AuthAclWrapper::new(&relay, TAG, carrier)))
        .unwrap();
    let memory = MemDatagramChannel::new(advertised);
    let first = tokio::spawn(
        memory
            .listen(b"relay")
            .unwrap()
            .serve_datagram(relay.clone()),
    );
    a.register_datagram_channel(TAG, Arc::new(memory)).unwrap();
    route(
        &routes,
        &b,
        Plane::Datagram,
        EP,
        b"relay".to_vec(),
        vec![hop(&relay, native_addr.to_string().into_bytes())],
    );
    let target = UdpSocket::bind(local()).await.unwrap();
    let _published = b
        .publish_datagram(EP, 1232, Arc::new(UdpTarget(target.local_addr().unwrap())))
        .unwrap();
    let echo = start_udp_echo(target);
    let mut outcomes = routes.outcomes();
    let session = a
        .dial_datagram(b.public_key(), EP, 1232, &[])
        .await
        .unwrap();
    assert_eq!(session.max_payload(), usize::from(advertised) - 30);

    // This ciphertext exceeds the real DF limit on H → B, while the first
    // (in-memory) link accepts it intact.
    session
        .send(PacketBuf::from_slice(&vec![13; session.max_payload()]))
        .unwrap();
    timeout(WAIT, async {
        let mut saw_clamp = false;
        loop {
            match outcomes.recv().await.unwrap().1 {
                PathOutcome::MtuChanged { mtu: 1232 } => saw_clamp = true,
                PathOutcome::MtuChanged { mtu } if mtu == physical => {
                    assert!(saw_clamp);
                    break;
                }
                PathOutcome::Failed(error) => panic!("MTU recovery closed the circuit: {error}"),
                _ => {}
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(session.max_payload(), usize::from(physical) - 30);
    let max = vec![17; session.max_payload()];
    session.send(PacketBuf::from_slice(&max)).unwrap();
    assert_eq!(
        timeout(WAIT, session.recv())
            .await
            .unwrap()
            .unwrap()
            .as_slice(),
        &max
    );
    first.abort();
    native.abort();
    echo.abort();
}

#[tokio::test]
async fn native_udp_port_forward_flushes_packets_sent_during_setup() {
    let (_acl, routes, a, b) = setup();
    let carrier = UdpCarrier::new(1232).unwrap();
    let link_in = carrier.bind(local()).unwrap();
    let address = link_in.local_addr().unwrap();
    let network = tokio::spawn(link_in.serve(b.clone()));
    a.register_datagram_channel(TAG, Arc::new(carrier)).unwrap();
    route(
        &routes,
        &b,
        Plane::Datagram,
        EP,
        address.to_string().into_bytes(),
        vec![],
    );
    let target = UdpSocket::bind(local()).await.unwrap();
    let _published = b
        .publish_datagram(EP, 1232, Arc::new(UdpTarget(target.local_addr().unwrap())))
        .unwrap();
    let echo = start_udp_echo(target);

    let edge = UdpSocket::bind(local()).await.unwrap();
    let edge_addr = edge.local_addr().unwrap();
    let forwarding = tokio::spawn(serve_local_udp(edge, a, destination(&b, EP), 1232));
    let client = UdpSocket::bind(local()).await.unwrap();
    client.connect(edge_addr).await.unwrap();
    client.send(b"first").await.unwrap();
    client.send(b"second").await.unwrap();
    let mut bytes = [0; 16];
    for expected in [b"first".as_slice(), b"second".as_slice()] {
        let n = timeout(WAIT, client.recv(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[..n], expected);
    }
    forwarding.abort();
    network.abort();
    echo.abort();
}

#[tokio::test]
async fn passive_relay_uses_only_registered_streams_and_datagram_links() {
    let (acl, routes, a, b) = setup();
    let h = node(&acl, &routes);
    let passive = PassiveRelay::new(16384, 1232).unwrap();
    h.register_stream_channel(TAG, Arc::new(AuthAclWrapper::new(&h, TAG, passive.clone())))
        .unwrap();
    h.register_datagram_channel(TAG, Arc::new(AuthAclWrapper::new(&h, TAG, passive.clone())))
        .unwrap();

    let listener = TcpListener::bind(local()).await.unwrap();
    let b_to_h = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (registered, _) = listener.accept().await.unwrap();
    drop(listener);
    let name = b"opaque-presence";
    passive
        .register_stream(name, Box::new(TcpIo::new(registered, 16384).unwrap()))
        .unwrap();
    b.accept_stream(Box::new(TcpIo::new(b_to_h, 16384).unwrap()))
        .unwrap();

    let stream = MemStreamChannel::new(16384, 2048);
    let accept = tokio::spawn(stream.listen(b"relay").unwrap().serve_stream(h.clone()));
    a.register_stream_channel(TAG, Arc::new(stream)).unwrap();
    let tcp = TcpListener::bind(local()).await.unwrap();
    let _stream = b
        .publish_stream(EP, Arc::new(TcpTarget(tcp.local_addr().unwrap())))
        .unwrap();
    let tcp_echo = start_tcp_echo(tcp);
    route(
        &routes,
        &b,
        Plane::Stream,
        EP,
        b"relay".to_vec(),
        vec![hop(&h, name.to_vec())],
    );

    let session = a.dial_stream(b.public_key(), EP, &[]).await.unwrap();
    session.write_all(b"presence").await.unwrap();
    session.shutdown().await.unwrap();
    let mut bytes = [0; 16];
    let len = timeout(WAIT, session.read(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..len], b"presence");
    assert_eq!(session.read(&mut bytes).await.unwrap(), 0);
    tcp_echo.await.unwrap();
    assert!(matches!(
        passive.dial_stream(name).await,
        Err(CoreErr::TargetUnreachable)
    ));

    let (right, destination_link) = mem_datagram_pair(1232, 32);
    let _registered = passive.register_datagram(name, right).unwrap();
    let _datagram_ingress = b.attach_datagram(destination_link).unwrap();
    let datagram = MemDatagramChannel::new(1232);
    let incoming = tokio::spawn(datagram.listen(b"relay").unwrap().serve_datagram(h.clone()));
    a.register_datagram_channel(TAG, Arc::new(datagram))
        .unwrap();
    let udp = UdpSocket::bind(local()).await.unwrap();
    let _datagram = b
        .publish_datagram("udp", 1232, Arc::new(UdpTarget(udp.local_addr().unwrap())))
        .unwrap();
    let udp_echo = start_udp_echo(udp);
    route(
        &routes,
        &b,
        Plane::Datagram,
        "udp",
        b"relay".to_vec(),
        vec![hop(&h, name.to_vec())],
    );
    let (first, second) = tokio::join!(
        a.dial_datagram(b.public_key(), "udp", 1232, &[]),
        a.dial_datagram(b.public_key(), "udp", 1232, &[]),
    );
    let (first, second) = (first.unwrap(), second.unwrap());
    for (circuit, payload) in [
        (&first, b"first".as_slice()),
        (&second, b"second".as_slice()),
    ] {
        circuit.send(PacketBuf::from_slice(payload)).unwrap();
        assert_eq!(
            timeout(WAIT, circuit.recv())
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            payload
        );
    }
    drop(first);
    second.send(PacketBuf::from_slice(b"still active")).unwrap();
    assert_eq!(
        timeout(WAIT, second.recv())
            .await
            .unwrap()
            .unwrap()
            .as_slice(),
        b"still active"
    );
    accept.abort();
    incoming.abort();
    udp_echo.abort();
}

#[tokio::test]
async fn unix_admin_is_0600_and_lives_only_on_the_explicit_socket() {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    let (_acl, _routes, _, b) = setup();
    let path = std::env::temp_dir().join(format!("confluence-test-{}-admin", std::process::id()));
    let admin = AdminSocket::bind(&path).unwrap();
    let metadata = std::fs::symlink_metadata(&path).unwrap();
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert!(
        matches!(AdminSocket::bind(&path), Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists)
    );
    let worker = tokio::spawn(admin.serve(b));
    async fn command(path: &std::path::Path, command: &[u8]) -> String {
        let mut stream = UnixStream::connect(path).await.unwrap();
        stream.write_all(command).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }
    assert_eq!(
        command(&path, b"publish-stream test 127.0.0.1:1\n").await,
        "OK\n"
    );
    assert_eq!(command(&path, b"list\n").await, "OK test\n");
    assert_eq!(command(&path, b"unpublish test\n").await, "OK\n");
    assert_eq!(command(&path, b"list\n").await, "OK\n");
    worker.abort();
    let _ = worker.await;
    assert!(!path.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_ingress_protects_peer_capacity_and_multiplexes_outbound_carrier_links() {
    let (acl, routes, a, b) = setup();
    let carrier = UdpCarrier::new(1232).unwrap();
    // Only 1 admitted peer slot and 2 provisional slots: unauthenticated senders must
    // neither occupy the admitted slot nor pin provisional slots, while multiple
    // concurrent circuits from A must share one multiplexed outbound UDP link.
    let ingress = carrier.bind(local()).unwrap().with_limits(1, 2);
    let addr = ingress.local_addr().unwrap();
    let server = tokio::spawn(ingress.serve(b.clone()));

    let target = UdpSocket::bind(local()).await.unwrap();
    let _published = b
        .publish_datagram(EP, 1232, Arc::new(UdpTarget(target.local_addr().unwrap())))
        .unwrap();
    let echo = start_udp_echo(target);

    // Flood with 8 distinct unauthenticated/unauthorized peers carrying valid MAC1 +
    // follow-up non-FWD traffic that attempts to keep provisional slots alive.
    let mut attacker_sockets = Vec::new();
    for _ in 0..8 {
        let rogue_routes = Arc::new(StaticPathSource::default());
        let rogue = node(&acl, &rogue_routes);
        let rogue_carrier = UdpCarrier::new(1232).unwrap();
        let sock = rogue_carrier.connect_from(local(), addr).await.unwrap();
        let plain = confluence_core::crypto::noise_ik::endpoint_plaintext(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            EP,
            &[],
        )
        .unwrap();
        let mut body = confluence_core::wire::setup::prefix(
            Plane::Datagram,
            1232,
            None,
            confluence_core::wire::setup::SEGMENT_OVERHEAD + plain.len(),
            0,
        )
        .unwrap();
        let (seg, _) = confluence_core::crypto::noise_ik::initiate(
            &rogue.identity(),
            b.public_key(),
            &confluence_core::wire::setup::tail_aad(&body, &[]),
            &plain,
        )
        .unwrap();
        body.extend_from_slice(&seg);
        let mut wire = confluence_core::wire::setup::ForwardHeader {
            max_mtu: 1232,
            upstream: confluence_core::cid::Cid::from_raw(1),
        }
        .encode()
        .to_vec();
        wire.extend_from_slice(&body);
        sock.send(PacketBuf::from_slice(&wire)).await.unwrap();
        // Send follow-up non-FWD noise to prove it cannot pin/refresh provisional state.
        sock.send(PacketBuf::from_slice(&[0x20, 0, 0, 0, 1, 9, 9]))
            .await
            .unwrap();
        attacker_sockets.push(sock);
    }
    sleep(Duration::from_millis(50)).await;

    // Now legitimate peer A opens 3 concurrent datagram circuits to B using the single
    // admitted peer slot (proving both provisional eviction and UdpCarrier link reuse).
    a.register_datagram_channel(TAG, Arc::new(carrier)).unwrap();
    route(
        &routes,
        &b,
        Plane::Datagram,
        EP,
        addr.to_string().into_bytes(),
        vec![],
    );
    let (c1, c2, c3) = tokio::join!(
        a.dial_datagram(b.public_key(), EP, 1232, &[]),
        a.dial_datagram(b.public_key(), EP, 1232, &[]),
        a.dial_datagram(b.public_key(), EP, 1232, &[]),
    );
    let (c1, c2, c3) = (c1.unwrap(), c2.unwrap(), c3.unwrap());
    for (circuit, payload) in [
        (&c1, b"alpha".as_slice()),
        (&c2, b"beta".as_slice()),
        (&c3, b"gamma".as_slice()),
    ] {
        circuit.send(PacketBuf::from_slice(payload)).unwrap();
        let reply = timeout(WAIT, circuit.recv()).await.unwrap().unwrap();
        assert_eq!(reply.as_slice(), payload);
    }
    drop(attacker_sockets);
    server.abort();
    echo.abort();
}
