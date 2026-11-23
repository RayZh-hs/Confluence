use confluence_core::{
    AuthDenied, AuthRequest, Authorizer, BoxFut, CoreErr, ExplicitPath, Lease, PathOutcome,
    PathSource, Plane, PublicKey, ScopeKeypair, TargetRef,
};
use confluence_edge::{Destination, TcpTarget};
use confluence_net::TcpCarrier;
use confluence_runtime::{NodePlan, RuntimeError};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{net::TcpListener, time::timeout};

const EPHEMERAL: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
const WAIT: Duration = Duration::from_secs(5);

async fn free_address() -> SocketAddr {
    TcpListener::bind(EPHEMERAL)
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

fn listeners(first: SocketAddr, second: SocketAddr) -> NodePlan {
    let mut plan = NodePlan::new();
    plan.scope("app", ScopeKeypair::generate()).unwrap();
    plan.listen_tcp(first).listen_tcp(second);
    plan
}

#[tokio::test]
async fn occupied_port_fails_at_start_and_both_ports_can_be_reused() {
    let occupied = TcpListener::bind(EPHEMERAL).await.unwrap();
    let second = occupied.local_addr().unwrap();
    let first = free_address().await;
    let prepared = listeners(first, second).prepare().unwrap();
    let error = prepared.start().await.err().expect("bind should fail");
    assert!(
        matches!(error, RuntimeError::Io { source, .. } if source.kind() == io::ErrorKind::AddrInUse)
    );
    drop(occupied);

    let running = listeners(first, second)
        .prepare()
        .unwrap()
        .start()
        .await
        .unwrap();
    assert_eq!(running.tcp_listener_addrs(), &[first, second]);
    running.run_until(std::future::ready(Ok(()))).await.unwrap();
    TcpListener::bind(first).await.unwrap();
    TcpListener::bind(second).await.unwrap();
}

#[test]
fn one_relay_registration_key_cannot_serve_two_prefixes() {
    use confluence_relay::StaticRegistrationRules;

    let mut plan = NodePlan::new();
    let scope = plan.scope("relay", ScopeKeypair::generate()).unwrap();
    let verifier = Arc::new(StaticRegistrationRules::default());
    scope
        .publish_relay("first/", verifier.clone(), 16_384, 1400)
        .unwrap();
    let result = scope.publish_relay("second/", verifier, 16_384, 1400);
    assert!(matches!(result, Err(RuntimeError::Invalid(message))
        if message.contains("first/") && message.contains("second/") && message.contains("registration key")));
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn denied_registration_rolls_back_started_ingress_on_both_planes() {
    use confluence_net::UdpCarrier;
    use confluence_relay::{RegistrationRule, StaticRegistrationRules};
    use confluence_runtime::RelayPresence;
    use tokio::net::UdpSocket;

    let tcp_addr = free_address().await;
    let udp_addr = UdpSocket::bind(EPHEMERAL)
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let identity = ScopeKeypair::generate();
    let key = identity.public_key();
    let rules = StaticRegistrationRules::new(vec![RegistrationRule {
        peers: vec![key.to_string()],
        presence: Some("allowed".into()),
        plane: Some(Plane::Datagram),
        required_credential: None,
        ttl: Duration::from_secs(30),
    }]);
    let udp = UdpCarrier::new(1400).unwrap();
    let mut plan = NodePlan::new();
    plan.scope("relay", identity)
        .unwrap()
        .publish_relay("relay/", Arc::new(rules), 16_384, 1400)
        .unwrap()
        .register_relay_udp(
            udp_addr,
            RelayPresence::new(key, "allowed", Vec::new()),
            udp.clone(),
            Duration::from_secs(6),
        )
        .register_relay_tcp(tcp_addr, RelayPresence::new(key, "denied", Vec::new()), 1);
    plan.listen_tcp(tcp_addr).listen_udp(udp_addr, udp);

    let result = timeout(WAIT, plan.prepare().unwrap().start())
        .await
        .unwrap();
    let error = result.err().expect("relay startup should be denied");
    assert!(
        matches!(&error, RuntimeError::Core { operation, source: CoreErr::Denied }
        if operation.contains("denied")),
        "{error}"
    );
    TcpListener::bind(tcp_addr).await.unwrap();
    UdpSocket::bind(udp_addr).await.unwrap();
}

struct AllowPeer(PublicKey);

impl Authorizer for AllowPeer {
    fn authorize<'a>(&'a self, request: AuthRequest<'a>) -> BoxFut<'a, Result<Lease, AuthDenied>> {
        Box::pin(async move {
            match request.target {
                TargetRef::Endpoint {
                    name: "echo",
                    plane: Plane::Stream,
                } if request.peer == self.0 => Ok(Lease::new(Duration::from_secs(20))),
                _ => Err(AuthDenied::Denied),
            }
        })
    }
}

struct DirectPath(SocketAddr);

impl PathSource for DirectPath {
    fn resolve_path<'a>(
        &'a self,
        _: &'a PublicKey,
        _: &'a str,
        _: Plane,
    ) -> BoxFut<'a, Result<ExplicitPath, confluence_core::CoreErr>> {
        Box::pin(async move {
            Ok(ExplicitPath {
                id: 1,
                first_channel: "tcp".into(),
                first_locator: self.0.to_string().into_bytes(),
                min_mtu: 0,
                hops: Vec::new(),
            })
        })
    }

    fn report_outcome(&self, _: u64, _: PathOutcome) {}
}

#[tokio::test]
async fn custom_policy_and_path_work_and_shared_ingress_denies_by_default() {
    let backend = TcpListener::bind(EPHEMERAL).await.unwrap();
    let target = backend.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (socket, _) = backend.accept().await.unwrap();
        let (mut read, mut write) = socket.into_split();
        tokio::io::copy(&mut read, &mut write).await.unwrap();
    });
    let alice = ScopeKeypair::generate();
    let allowed = ScopeKeypair::generate();
    let denied = ScopeKeypair::generate();
    let allowed_peer = allowed.public_key();
    let denied_peer = denied.public_key();

    let mut bob = NodePlan::new();
    bob.scope("allowed", allowed)
        .unwrap()
        .authorizer(Arc::new(AllowPeer(alice.public_key())))
        .publish_stream("echo", Arc::new(TcpTarget(target)))
        .unwrap();
    bob.scope("denied", denied)
        .unwrap()
        .publish_stream("echo", Arc::new(TcpTarget(target)))
        .unwrap();
    bob.listen_tcp(EPHEMERAL);
    let bob = bob.prepare().unwrap().start().await.unwrap();

    let mut client = NodePlan::new();
    client
        .scope("client", alice)
        .unwrap()
        .path_source(Arc::new(DirectPath(bob.tcp_listener_addrs()[0])))
        .stream_carrier("tcp", Arc::new(TcpCarrier::default()))
        .unwrap();
    let client = client.prepare().unwrap().start().await.unwrap();
    let scope = client.scope("client").unwrap();
    let denied = timeout(WAIT, scope.dial_stream(denied_peer, "echo"))
        .await
        .unwrap();
    assert!(matches!(denied, Err(CoreErr::Denied)));

    let tunnel = timeout(WAIT, scope.dial_stream(allowed_peer, "echo"))
        .await
        .unwrap()
        .unwrap();
    tunnel.write_all(b"echo").await.unwrap();
    let mut response = [0; 4];
    let mut received = 0;
    while received < response.len() {
        let read = timeout(WAIT, tunnel.read(&mut response[received..]))
            .await
            .unwrap()
            .unwrap();
        assert!(read > 0);
        received += read;
    }
    assert_eq!(&response, b"echo");

    client.shutdown().await;
    bob.shutdown().await;
    echo.abort();
}

#[test]
fn prepare_reports_unknown_carrier_before_start() {
    let mut plan = NodePlan::new();
    plan.scope("app", ScopeKeypair::generate()).unwrap().route(
        Destination {
            peer: ScopeKeypair::generate().public_key(),
            endpoint: "echo".into(),
        },
        Plane::Stream,
        ExplicitPath {
            id: 1,
            first_channel: "missing".into(),
            first_locator: Vec::new(),
            min_mtu: 0,
            hops: Vec::new(),
        },
    );
    assert!(matches!(plan.prepare(), Err(RuntimeError::Invalid(message))
        if message.contains("unknown stream carrier \"missing\"")));
}
