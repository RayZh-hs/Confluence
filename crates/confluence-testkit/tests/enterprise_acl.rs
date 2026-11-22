//! End-to-end showcase of building an enterprise fine-grained access control & QoS system on
//! Confluence's modular auth architecture:
//! - Symmetric `CredentialProvider` ↔ `Authorizer` with short-lived signed capability tokens
//! - Zero credentials in routing (`PathSource`) or application `dial_*` calls
//! - Named transit hop (`"to-prod"`) hiding internal topology from callers
//! - `IntersectAuthorizer(LocalDbaPolicy, QosAuthorizer(CorpTokenAuthorizer))` preserving host
//!   sovereignty across TTL, `TrafficGate`, RAII concurrency `SessionGuard`s, and `AuthExtensions`
//! - Zero handler wrapping (`AnalyticsDbEndpoint` and transits are published directly)
//! - Live mid-session role downgrade on in-band token refresh via `SessionAuth::context`
//! - Instant offboarding revocation
//! - Shared 1:N `DatagramLink` multi-circuit `DatagramTransit` QoS isolation, control-frame
//!   immunity (`DG_RENEW` survives data floods), and live mid-session QoS updates on renewal

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use confluence_core::{
    AsyncStream, AuthDenied, AuthRequest, Authorizer, BoxFut, CoreErr, CredentialProvider,
    CredentialRequest, DATAGRAM_MTU, DatagramEndpointHandler, DatagramLinkExt, ExplicitPath,
    HopSpec, IntersectAuthorizer, Lease, PacketBuf, Plane, PublicKey, Revocation, ScopeInstance,
    ScopeKeypair, SessionAuth, StreamEndpointHandler, StreamReadExt, StreamWriteExt, TargetRef,
};
use confluence_plugins::{
    MemDatagramLink, MemStream, QosAuthorizer, QosLimits, RateGate, StaticPathSource, TokioSpawner,
    mem_datagram_pair, mem_stream_pair,
};
use confluence_testkit::{MemDatagramHub, MemStreamHub};
use parking_lot::RwLock;
use tokio::{
    sync::broadcast,
    time::{Instant, sleep, timeout},
};

const WAIT: Duration = Duration::from_secs(5);

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ============================================================================
// 1. Domain model: Verified user claims & compact signed capability tokens
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Role {
    Analyst = 1,
    Admin = 2,
}

impl Role {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Analyst),
            2 => Some(Self::Admin),
            _ => None,
        }
    }
}

/// Rich enterprise claims verified ONCE by `CorpTokenAuthorizer`, attached to `Lease::extensions`,
/// and observed live by `AnalyticsDbEndpoint` via `SessionAuth::context::<UserClaims>()`.
#[derive(Clone, Debug)]
struct UserClaims {
    user: String,
    role: Role,
    tenant: String,
    qos: QosLimits,
}

/// Separate local-host claim attached by `LocalDbaPolicy` to verify `AuthExtensions` preserves
/// both local and external typed claims under `IntersectAuthorizer`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalAuditCluster(&'static str);

struct CorpSigner {
    secret: [u8; 32],
}

impl CorpSigner {
    fn new(secret: [u8; 32]) -> Self {
        Self { secret }
    }

    fn tag(&self, peer: PublicKey, verifier: PublicKey, body: &[u8]) -> [u8; 16] {
        // Simple deterministic keyed 128-bit digest for testing (production uses Ed25519/BLAKE3).
        let mut h1: u64 = 0xcbf2_9ce4_8422_2325;
        let mut h2: u64 = 0x8422_2325_cbf2_9ce4;
        for &b in self
            .secret
            .iter()
            .chain(peer.0.iter())
            .chain(verifier.0.iter())
            .chain(body.iter())
        {
            h1 = (h1 ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
            h2 = h2.rotate_left(7) ^ u64::from(b).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        }
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&h1.to_be_bytes());
        out[8..].copy_from_slice(&h2.to_be_bytes());
        out
    }

    /// Encodes a compact capability token (`< 120 bytes`, fits comfortably inside Core's 512B cap):
    /// `[serial:8 | exp_ms:8 | role:1 | max_streams:2 | user_len:1 | user | tenant_len:1 | tenant
    ///   | target_len:1 | target | tag:16]`
    #[allow(clippy::too_many_arguments)]
    fn mint(
        &self,
        serial: u64,
        peer: PublicKey,
        verifier: PublicKey,
        user: &str,
        role: Role,
        tenant: &str,
        allowed_target: &str,
        max_concurrent_streams: u32,
        ttl: Duration,
    ) -> Vec<u8> {
        let exp_ms = now_ms().saturating_add(ttl.as_millis() as u64);
        let mut body = Vec::new();
        body.extend_from_slice(&serial.to_be_bytes());
        body.extend_from_slice(&exp_ms.to_be_bytes());
        body.push(role as u8);
        body.extend_from_slice(&(max_concurrent_streams as u16).to_be_bytes());
        body.push(user.len() as u8);
        body.extend_from_slice(user.as_bytes());
        body.push(tenant.len() as u8);
        body.extend_from_slice(tenant.as_bytes());
        body.push(allowed_target.len() as u8);
        body.extend_from_slice(allowed_target.as_bytes());
        let tag = self.tag(peer, verifier, &body);
        body.extend_from_slice(&tag);
        body
    }

    fn verify(
        &self,
        peer: PublicKey,
        verifier: PublicKey,
        token: &[u8],
    ) -> Option<(u64, u64, String, UserClaims)> {
        if token.len() < 16 + 22 {
            return None;
        }
        let (body, tag) = token.split_at(token.len() - 16);
        if self.tag(peer, verifier, body) != tag {
            return None;
        }
        let serial = u64::from_be_bytes(body[0..8].try_into().ok()?);
        let exp_ms = u64::from_be_bytes(body[8..16].try_into().ok()?);
        let role = Role::from_byte(body[16])?;
        let max_streams = u32::from(u16::from_be_bytes(body[17..19].try_into().ok()?));
        let mut off = 19;
        let read_str = |off: &mut usize| -> Option<String> {
            let len = usize::from(*body.get(*off)?);
            *off += 1;
            let s = std::str::from_utf8(body.get(*off..*off + len)?).ok()?;
            *off += len;
            Some(s.to_owned())
        };
        let user = read_str(&mut off)?;
        let tenant = read_str(&mut off)?;
        let allowed_target = read_str(&mut off)?;
        if off != body.len() {
            return None;
        }
        Some((
            serial,
            exp_ms,
            allowed_target,
            UserClaims {
                user,
                role,
                tenant,
                qos: QosLimits {
                    max_bytes_per_sec: 0,
                    max_datagrams_per_sec: 0,
                    max_concurrent_streams: max_streams,
                },
            },
        ))
    }
}

// ============================================================================
// 2. Originator-side `CredentialProvider` (auto-fetches & refreshes tokens)
// ============================================================================

struct BrokerCredentials {
    signer: Arc<CorpSigner>,
    local_peer: PublicKey,
    user: String,
    role: RwLock<Role>,
    tenant: String,
    max_streams: u32,
    token_ttl: Duration,
    next_serial: AtomicU64,
    refresh_count: AtomicUsize,
}

impl BrokerCredentials {
    fn set_role(&self, role: Role) {
        *self.role.write() = role;
    }
}

impl CredentialProvider for BrokerCredentials {
    fn credential<'a>(
        &'a self,
        req: CredentialRequest<'a>,
    ) -> BoxFut<'a, Result<Vec<u8>, CoreErr>> {
        if req.is_refresh {
            self.refresh_count.fetch_add(1, Ordering::Relaxed);
        }
        let serial = self.next_serial.fetch_add(1, Ordering::Relaxed);
        let role = *self.role.read();
        let token = self.signer.mint(
            serial,
            self.local_peer,
            req.verifier,
            &self.user,
            role,
            &self.tenant,
            req.target.name(),
            self.max_streams,
            self.token_ttl,
        );
        Box::pin(async move { Ok(token) })
    }
}

// ============================================================================
// 3. Verifier-side `Authorizer` (verifies tokens, attaches `UserClaims`)
// ============================================================================

struct CorpTokenAuthorizer {
    signer: Arc<CorpSigner>,
    local_verifier: PublicKey,
    revoked_peers: RwLock<HashSet<PublicKey>>,
    events: broadcast::Sender<Revocation>,
    evals: AtomicUsize,
}

impl CorpTokenAuthorizer {
    fn new(signer: Arc<CorpSigner>, local_verifier: PublicKey) -> Arc<Self> {
        Arc::new(Self {
            signer,
            local_verifier,
            revoked_peers: Default::default(),
            events: broadcast::channel(64).0,
            evals: AtomicUsize::new(0),
        })
    }

    fn offboard(&self, peer: PublicKey) {
        self.revoked_peers.write().insert(peer);
        let _ = self.events.send(Revocation::Peer(peer));
    }
}

impl Authorizer for CorpTokenAuthorizer {
    fn authorize<'a>(&'a self, req: AuthRequest<'a>) -> BoxFut<'a, Result<Lease, AuthDenied>> {
        self.evals.fetch_add(1, Ordering::Relaxed);
        let decision = (|| {
            if self.revoked_peers.read().contains(&req.peer) {
                return Err(AuthDenied::Denied);
            }
            let (_serial, exp_ms, allowed_target, claims) = self
                .signer
                .verify(req.peer, self.local_verifier, req.credential)
                .ok_or(AuthDenied::Denied)?;
            let remaining_ms = exp_ms
                .checked_sub(now_ms())
                .filter(|&ms| ms > 0)
                .ok_or(AuthDenied::Denied)?;
            if allowed_target != "*" && allowed_target != req.target.name() {
                return Err(AuthDenied::Denied);
            }
            Ok(Lease::new(Duration::from_millis(remaining_ms)).with_context(claims))
        })();
        Box::pin(async move { decision })
    }

    fn revocations(&self) -> Option<broadcast::Receiver<Revocation>> {
        Some(self.events.subscribe())
    }
}

// ============================================================================
// 4. Local DBA host-sovereignty policy (caps TTL, vetoes endpoints, tags cluster)
// ============================================================================

struct LocalDbaPolicy {
    allowed_endpoints: HashSet<String>,
    max_ttl: Duration,
    cluster_tag: &'static str,
}

impl Authorizer for LocalDbaPolicy {
    fn authorize<'a>(&'a self, req: AuthRequest<'a>) -> BoxFut<'a, Result<Lease, AuthDenied>> {
        let ok = match req.target {
            TargetRef::Endpoint { name, .. } => self.allowed_endpoints.contains(name),
            TargetRef::Transit { .. } => false,
        };
        let res = if ok {
            Ok(Lease::new(self.max_ttl).with_context(LocalAuditCluster(self.cluster_tag)))
        } else {
            Err(AuthDenied::Denied)
        };
        Box::pin(async move { res })
    }
}

// ============================================================================
// 5. Fine-grained RBAC application endpoint reading LIVE `SessionAuth::context`
// ============================================================================

/// Mini SQL-like endpoint:
/// Protocol (line-delimited UTF-8):
/// - `SELECT <tenant>` -> allowed if `role == Admin` OR `claims.tenant == tenant`
/// - `DROP <tenant>`   -> allowed ONLY if `role == Admin`
/// - `CLUSTER`         -> returns local host `LocalAuditCluster` tag (proving dual claims coexist!)
struct AnalyticsDbEndpoint {
    rows: Arc<RwLock<HashMap<String, String>>>,
}

impl StreamEndpointHandler for AnalyticsDbEndpoint {
    type Stream = MemStream;

    async fn open(&self, auth: SessionAuth) -> Result<MemStream, CoreErr> {
        // Verify required claims exist at open time, then keep `auth` live for per-query checks!
        if auth.context::<UserClaims>().is_none() {
            return Err(CoreErr::Denied);
        }
        let rows = self.rows.clone();
        let (server, app) = mem_stream_pair(16384, 4096);
        tokio::spawn(async move {
            let (mut r, mut w) = app.split();
            let mut buf = [0u8; 512];
            while let Ok(n) = r.read(&mut buf).await {
                if n == 0 {
                    let _ = w.shutdown().await;
                    break;
                }
                // Read LATEST claims on every query so mid-session renewals apply immediately!
                let Some(claims) = auth.context::<UserClaims>() else {
                    break;
                };
                let req = std::str::from_utf8(&buf[..n]).unwrap_or("").trim();
                let parts: Vec<_> = req.split_whitespace().collect();
                let reply = match parts.as_slice() {
                    ["SELECT", tenant] => {
                        if claims.role == Role::Admin || claims.tenant == *tenant {
                            match rows.read().get(*tenant) {
                                Some(val) => format!("OK {}:{val}\n", claims.user),
                                None => "EMPTY\n".into(),
                            }
                        } else {
                            "ERR_FORBIDDEN_TENANT\n".into()
                        }
                    }
                    ["DROP", tenant] => {
                        if claims.role == Role::Admin {
                            rows.write().remove(*tenant);
                            format!("DROPPED {tenant}\n")
                        } else {
                            "ERR_FORBIDDEN_ROLE\n".into()
                        }
                    }
                    ["CLUSTER"] => match auth.context::<LocalAuditCluster>() {
                        Some(tag) => format!("CLUSTER {}\n", tag.0),
                        None => "NO_CLUSTER\n".into(),
                    },
                    _ => "ERR_SYNTAX\n".into(),
                };
                if w.write_all(reply.as_bytes()).await.is_err() {
                    break;
                }
            }
        });
        Ok(server)
    }
}

async fn query(stream: &confluence_core::E2eStream, cmd: &str) -> Result<String, CoreErr> {
    stream.write_all(cmd.as_bytes()).await?;
    let mut buf = [0u8; 256];
    let n = timeout(WAIT, stream.read(&mut buf))
        .await
        .map_err(|_| CoreErr::Timeout)??;
    Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enterprise_rbac_live_claim_downgrade_lease_qos_and_instant_offboarding() {
    let signer = Arc::new(CorpSigner::new([0xA5; 32]));
    let spawner = Arc::new(TokioSpawner);

    // Identities
    let analyst_kp = ScopeKeypair::generate();
    let admin_kp = ScopeKeypair::generate();
    let bastion_kp = ScopeKeypair::generate();
    let prod_kp = ScopeKeypair::generate();

    let bastion_pk = bastion_kp.public_key();
    let prod_pk = prod_kp.public_key();

    // Bastion verifies Corp tokens for named transit "to-prod".
    let bastion_auth = CorpTokenAuthorizer::new(signer.clone(), bastion_pk);

    // Prod intersects LocalDbaPolicy (host sovereignty: only "analytics-db", max TTL 1.1s,
    // attaches LocalAuditCluster) with QosAuthorizer(CorpTokenAuthorizer) enforcing UserClaims::qos
    // directly on Lease (zero endpoint wrapping!).
    let prod_corp_auth = CorpTokenAuthorizer::new(signer.clone(), prod_pk);
    let prod_corp_with_qos = Arc::new(QosAuthorizer::new(prod_corp_auth.clone(), |_req, lease| {
        lease
            .context::<UserClaims>()
            .map(|c| c.qos)
            .unwrap_or_default()
    }));
    let local_dba = Arc::new(LocalDbaPolicy {
        allowed_endpoints: ["analytics-db".to_owned()].into_iter().collect(),
        max_ttl: Duration::from_millis(1100),
        cluster_tag: "prod-us-east",
    });
    let prod_auth = Arc::new(IntersectAuthorizer::new(local_dba, prod_corp_with_qos));

    // Pure routing table: ZERO credentials, ZERO Prod internal addresses known to Alice!
    let routes = Arc::new(StaticPathSource::default());
    for ep in ["analytics-db", "payroll-secret"] {
        routes.set(
            prod_pk,
            ep,
            Plane::Stream,
            ExplicitPath {
                id: 1,
                first_channel: "corp".into(),
                first_locator: b"bastion".to_vec(),
                min_mtu: 64,
                hops: vec![HopSpec {
                    peer: bastion_pk,
                    target: "to-prod".into(),
                }],
            },
        );
    }

    // Analyst Alice (tenant "acme", max 1 concurrent stream!) & Admin Bob (tenant "acme", 4 streams).
    let analyst_creds = Arc::new(BrokerCredentials {
        signer: signer.clone(),
        local_peer: analyst_kp.public_key(),
        user: "alice".into(),
        role: RwLock::new(Role::Analyst),
        tenant: "acme".into(),
        max_streams: 1,
        token_ttl: Duration::from_secs(10),
        next_serial: AtomicU64::new(1),
        refresh_count: AtomicUsize::new(0),
    });
    let admin_creds = Arc::new(BrokerCredentials {
        signer,
        local_peer: admin_kp.public_key(),
        user: "bob-admin".into(),
        role: RwLock::new(Role::Admin),
        tenant: "acme".into(),
        max_streams: 4,
        token_ttl: Duration::from_secs(10),
        next_serial: AtomicU64::new(100),
        refresh_count: AtomicUsize::new(0),
    });

    let alice = ScopeInstance::builder(analyst_kp, spawner.clone())
        .routes(routes.clone())
        .credentials(analyst_creds.clone())
        .build();
    let bob_admin = ScopeInstance::builder(admin_kp, spawner.clone())
        .routes(routes)
        .credentials(admin_creds.clone())
        .build();
    let bastion = ScopeInstance::builder(bastion_kp, spawner.clone())
        .authorizer(bastion_auth.clone())
        .build();
    let prod = ScopeInstance::builder(prod_kp, spawner)
        .authorizer(prod_auth)
        .build();

    let hub = MemStreamHub::new(4096, 8192);
    let alice_ch = hub.bind(b"alice");
    let admin_ch = hub.bind(b"admin");
    let bastion_ch = hub.bind(b"bastion");
    let prod_ch = hub.bind(b"prod-private-10-0-4-12");

    alice.register_stream_carrier("corp", alice_ch).unwrap();
    bob_admin.register_stream_carrier("corp", admin_ch).unwrap();
    // Bastion hides Prod's private address behind logical transit name "to-prod"!
    let _g_transit = bastion
        .publish_stream_route("to-prod", bastion_ch.clone(), b"prod-private-10-0-4-12")
        .unwrap();

    // Prod publishes AnalyticsDbEndpoint DIRECTLY (zero QosEndpoint wrapper needed!).
    let rows = Arc::new(RwLock::new(HashMap::from([
        ("acme".to_owned(), "q4_rev=42M".to_owned()),
        ("globex".to_owned(), "secret=99M".to_owned()),
        ("initech".to_owned(), "budget=12M".to_owned()),
    ])));
    let db = Arc::new(AnalyticsDbEndpoint { rows });
    let _g_db = prod.publish_stream("analytics-db", db.clone()).unwrap();
    let _g_payroll = prod.publish_stream("payroll-secret", db).unwrap();

    let b_c = bastion.clone();
    let p_c = prod.clone();
    let t1 = tokio::spawn(async move {
        let _ = b_c.serve_stream_listener(&*bastion_ch).await;
    });
    let t2 = tokio::spawn(async move {
        let _ = p_c.serve_stream_listener(&*prod_ch).await;
    });

    // 1. Local DBA host-sovereignty veto blocks "payroll-secret" before endpoint ever opens.
    assert_eq!(
        alice.dial_stream(prod_pk, "payroll-secret").await.err(),
        Some(CoreErr::Denied)
    );

    // 2. Application dials with ZERO credential arguments; Core + CredentialProvider handle both
    //    Bastion ("to-prod") and Prod ("analytics-db") transparently.
    let s_alice = alice.dial_stream(prod_pk, "analytics-db").await.unwrap();

    // 3. Lease-level QosAuthorizer enforces Analyst's max_concurrent_streams = 1 automatically
    //    (with ZERO handler wrapping!) and returns CoreErr::Busy.
    assert_eq!(
        alice.dial_stream(prod_pk, "analytics-db").await.err(),
        Some(CoreErr::Busy)
    );

    // 4. Both LocalAuditCluster (local host) AND UserClaims (external token) coexist via AuthExtensions!
    assert_eq!(
        query(&s_alice, "CLUSTER").await.unwrap(),
        "CLUSTER prod-us-east\n"
    );
    assert_eq!(
        query(&s_alice, "SELECT acme").await.unwrap(),
        "OK alice:q4_rev=42M\n"
    );
    assert_eq!(
        query(&s_alice, "SELECT globex").await.unwrap(),
        "ERR_FORBIDDEN_TENANT\n"
    );
    assert_eq!(
        query(&s_alice, "DROP acme").await.unwrap(),
        "ERR_FORBIDDEN_ROLE\n"
    );

    // 5. Admin Bob CAN read cross-tenant AND DROP:
    let s_admin = bob_admin
        .dial_stream(prod_pk, "analytics-db")
        .await
        .unwrap();
    assert_eq!(
        query(&s_admin, "SELECT globex").await.unwrap(),
        "OK bob-admin:secret=99M\n"
    );
    assert_eq!(
        query(&s_admin, "DROP globex").await.unwrap(),
        "DROPPED globex\n"
    );
    assert_eq!(query(&s_admin, "SELECT globex").await.unwrap(), "EMPTY\n");

    // 6. Live in-band credential refresh + LIVE mid-session role downgrade!
    //    Downgrade Bob from Admin -> Analyst in the broker; once his 1.1s lease renews in-band,
    //    his ALREADY-OPEN stream immediately loses DROP permission without reconnecting, while
    //    Alice's max_concurrent_streams = 1 slot survives renewal intact!
    admin_creds.set_role(Role::Analyst);
    for _ in 0..9 {
        assert_eq!(
            query(&s_alice, "SELECT acme").await.unwrap(),
            "OK alice:q4_rev=42M\n"
        );
        sleep(Duration::from_millis(200)).await;
    }
    assert!(
        analyst_creds.refresh_count.load(Ordering::Relaxed) >= 1,
        "expected automatic in-band credential refresh for Alice"
    );
    assert!(
        admin_creds.refresh_count.load(Ordering::Relaxed) >= 1,
        "expected automatic in-band credential refresh for Bob"
    );
    // Alice's initial concurrency slot MUST still be held after renewal!
    assert_eq!(
        alice.dial_stream(prod_pk, "analytics-db").await.err(),
        Some(CoreErr::Busy)
    );
    // Bob's live stream now reflects his downgraded Analyst role immediately!
    assert_eq!(
        query(&s_admin, "DROP initech").await.unwrap(),
        "ERR_FORBIDDEN_ROLE\n"
    );
    assert_eq!(
        query(&s_admin, "SELECT acme").await.unwrap(),
        "OK bob-admin:q4_rev=42M\n"
    );

    // 7. Instant offboarding revocation: CorpTokenAuthorizer revokes Alice -> live stream dies
    //    immediately and subsequent dials fail closed!
    prod_corp_auth.offboard(alice.public_key());
    assert!(
        timeout(WAIT, query(&s_alice, "SELECT acme"))
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(
        alice.dial_stream(prod_pk, "analytics-db").await.err(),
        Some(CoreErr::Denied)
    );

    // Admin Bob's session remains completely unaffected!
    assert_eq!(
        query(&s_admin, "SELECT acme").await.unwrap(),
        "OK bob-admin:q4_rev=42M\n"
    );

    t1.abort();
    t2.abort();
}

// ============================================================================
// 6. Shared 1:N DatagramLink transit QoS isolation + control-frame immunity + live swap
// ============================================================================

struct EchoDatagram;
impl DatagramEndpointHandler for EchoDatagram {
    type Link = Arc<MemDatagramLink>;

    async fn open(&self, _auth: SessionAuth) -> Result<Arc<MemDatagramLink>, CoreErr> {
        let (server, app) = mem_datagram_pair(u16::MAX, 64);
        tokio::spawn(async move {
            while let Ok(pkt) = app.recv().await {
                if app.send(pkt).await.is_err() {
                    break;
                }
            }
        });
        Ok(server)
    }
}

struct DynamicTransitQosAuthorizer {
    throttled_peer: PublicKey,
    throttle_active: AtomicBool,
    ttl: Duration,
    renewals: AtomicUsize,
}

impl Authorizer for DynamicTransitQosAuthorizer {
    fn authorize<'a>(&'a self, req: AuthRequest<'a>) -> BoxFut<'a, Result<Lease, AuthDenied>> {
        if req.is_renewal {
            self.renewals.fetch_add(1, Ordering::Relaxed);
        }
        let mut lease = Lease::new(self.ttl);
        if req.peer == self.throttled_peer && self.throttle_active.load(Ordering::Acquire) {
            lease = lease.with_gate(RateGate::directional(
                QosLimits {
                    max_datagrams_per_sec: 3,
                    ..Default::default()
                },
                QosLimits::default(),
            ));
        }
        Box::pin(async move { Ok(lease) })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_datagram_transit_per_circuit_qos_isolation_control_immunity_and_live_update() {
    let spawner = Arc::new(TokioSpawner);
    let routes = Arc::new(StaticPathSource::default());

    let alice_kp = ScopeKeypair::generate();
    let bob_kp = ScopeKeypair::generate();
    let hop_kp = ScopeKeypair::generate();
    let dest_kp = ScopeKeypair::generate();

    let alice_pk = alice_kp.public_key();
    let hop_pk = hop_kp.public_key();
    let dest_pk = dest_kp.public_key();

    // Hop throttles ONLY Alice to 3 ingress datagrams/sec while Bob is unlimited,
    // all over ONE shared 1:N DatagramLink from H -> B!
    let hop_auth = Arc::new(DynamicTransitQosAuthorizer {
        throttled_peer: alice_pk,
        throttle_active: AtomicBool::new(true),
        ttl: Duration::from_millis(1200),
        renewals: AtomicUsize::new(0),
    });
    let dest_auth = confluence_testkit::AuditAuthorizer::allow_all(Duration::from_secs(30));

    let alice = ScopeInstance::builder(alice_kp, spawner.clone())
        .routes(routes.clone())
        .build();
    let bob = ScopeInstance::builder(bob_kp, spawner.clone())
        .routes(routes.clone())
        .build();
    let hop = ScopeInstance::builder(hop_kp, spawner.clone())
        .authorizer(hop_auth.clone())
        .build();
    let dest = ScopeInstance::builder(dest_kp, spawner)
        .authorizer(dest_auth)
        .build();

    let hub = MemDatagramHub::new(1500);
    let alice_ch = hub.bind(b"alice");
    let bob_ch = hub.bind(b"bob");
    let hop_ch = hub.bind(b"hop");
    let dest_ch = hub.bind(b"dest");

    alice.register_datagram_carrier("dg", alice_ch).unwrap();
    bob.register_datagram_carrier("dg", bob_ch).unwrap();
    // Single named transit backed by ONE shared 1:N DatagramLink to dest!
    let _g_transit = hop
        .publish_datagram_route("to-dest", hop_ch.clone(), b"dest")
        .unwrap();
    let _g_ep = dest
        .publish_datagram("echo", DATAGRAM_MTU, Arc::new(EchoDatagram))
        .unwrap();

    let h_c = hop.clone();
    let d_c = dest.clone();
    let t1 = tokio::spawn(async move {
        let _ = h_c.serve_datagram_listener(&*hop_ch).await;
    });
    let t2 = tokio::spawn(async move {
        let _ = d_c.serve_datagram_listener(&*dest_ch).await;
    });

    routes.set(
        dest_pk,
        "echo",
        Plane::Datagram,
        ExplicitPath {
            id: 1,
            first_channel: "dg".into(),
            first_locator: b"hop".to_vec(),
            min_mtu: DATAGRAM_MTU,
            hops: vec![HopSpec {
                peer: hop_pk,
                target: "to-dest".into(),
            }],
        },
    );

    // Open BOTH circuits concurrently through the same shared H -> B DatagramLink.
    let dg_alice = timeout(WAIT, alice.dial_datagram(dest_pk, "echo", DATAGRAM_MTU))
        .await
        .unwrap()
        .unwrap();
    let dg_bob = timeout(WAIT, bob.dial_datagram(dest_pk, "echo", DATAGRAM_MTU))
        .await
        .unwrap()
        .unwrap();

    // 1. Alice blasts 15 packets immediately: Transit::pump drops excess DG_DATA packets
    //    strictly on Alice's circuit (capped to 3/s burst), without killing her session.
    for i in 0..15u8 {
        dg_alice.send(PacketBuf::from_slice(&[b'A', i])).unwrap();
    }
    let mut alice_received = 0usize;
    let drain_until = Instant::now() + Duration::from_millis(200);
    while let Ok(Ok(_)) = timeout(
        drain_until.saturating_duration_since(Instant::now()),
        dg_alice.recv(),
    )
    .await
    {
        alice_received += 1;
    }
    assert!(
        (1..=4).contains(&alice_received),
        "expected Alice to be capped around 3 PPS, got {alice_received}"
    );

    // 2. Simultaneously, Bob (sharing the EXACT same H -> B DatagramLink!) sends 20 packets
    //    and receives ALL 20 with zero packet stealing and zero throttling!
    for i in 0..20u8 {
        dg_bob.send(PacketBuf::from_slice(&[b'B', i])).unwrap();
        let reply = timeout(WAIT, dg_bob.recv()).await.unwrap().unwrap();
        assert_eq!(reply.as_slice(), &[b'B', i]);
    }

    // 3. Lift Alice's throttle and wait for her 1.2s hop lease to renew in-band:
    //    Control frames (DG_RENEW / DG_RENEW_OK) are immune to the prior data flood, and the
    //    swapped TrafficGate takes effect immediately on the SAME live circuit!
    hop_auth.throttle_active.store(false, Ordering::Release);
    sleep(Duration::from_millis(1400)).await;
    assert!(
        hop_auth.renewals.load(Ordering::Relaxed) >= 1,
        "expected hop in-band renewal to succeed despite prior data throttling"
    );
    for i in 0..15u8 {
        dg_alice.send(PacketBuf::from_slice(&[b'U', i])).unwrap();
        let reply = timeout(WAIT, dg_alice.recv()).await.unwrap().unwrap();
        assert_eq!(reply.as_slice(), &[b'U', i]);
    }

    t1.abort();
    t2.abort();
}

// ============================================================================
// 7. IntersectAuthorizer host-sovereignty QoS pacing on Streams (local wins!)
// ============================================================================

struct EchoStream;
impl StreamEndpointHandler for EchoStream {
    type Stream = MemStream;

    async fn open(&self, _auth: SessionAuth) -> Result<MemStream, CoreErr> {
        let (server, app) = mem_stream_pair(16384, 8192);
        tokio::spawn(async move {
            let (mut rx, mut tx) = app.split();
            let mut buf = [0u8; 4096];
            while let Ok(n) = rx.read(&mut buf).await {
                if n == 0 {
                    let _ = tx.shutdown().await;
                    break;
                }
                if tx.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
        Ok(server)
    }
}

struct RateOnlyAuthorizer {
    rate_bps: u64,
}

impl Authorizer for RateOnlyAuthorizer {
    fn authorize<'a>(&'a self, _req: AuthRequest<'a>) -> BoxFut<'a, Result<Lease, AuthDenied>> {
        let lease = Lease::new(Duration::from_secs(30)).with_gate(RateGate::new(QosLimits {
            max_bytes_per_sec: self.rate_bps,
            ..Default::default()
        }));
        Box::pin(async move { Ok(lease) })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn intersect_authorizer_enforces_stricter_local_stream_rate_cap() {
    let spawner = Arc::new(TokioSpawner);
    let routes = Arc::new(StaticPathSource::default());

    // Local host caps at 4 KB/s; external token allows 100 MB/s -> local 4 KB/s MUST win!
    let local = Arc::new(RateOnlyAuthorizer { rate_bps: 4000 });
    let external = Arc::new(RateOnlyAuthorizer {
        rate_bps: 100_000_000,
    });
    let combined = Arc::new(IntersectAuthorizer::new(local, external));

    let a = ScopeInstance::builder(ScopeKeypair::generate(), spawner.clone())
        .routes(routes.clone())
        .build();
    let b = ScopeInstance::builder(ScopeKeypair::generate(), spawner)
        .authorizer(combined)
        .build();

    let hub = MemStreamHub::new(4096, 8192);
    let a_ch = hub.bind(b"a");
    let b_ch = hub.bind(b"b");
    a.register_stream_carrier("st", a_ch).unwrap();
    let _ep = b.publish_stream("echo", Arc::new(EchoStream)).unwrap();

    let b_c = b.clone();
    let t = tokio::spawn(async move {
        let _ = b_c.serve_stream_listener(&*b_ch).await;
    });

    routes.set(
        b.public_key(),
        "echo",
        Plane::Stream,
        ExplicitPath {
            id: 1,
            first_channel: "st".into(),
            first_locator: b"b".to_vec(),
            min_mtu: 64,
            hops: vec![],
        },
    );

    let stream = timeout(WAIT, a.dial_stream(b.public_key(), "echo"))
        .await
        .unwrap()
        .unwrap();

    // Send 4000B (echoed = 8000B total ingress + egress across shared 4000 B/s bucket:
    // 4000B fits in 1s burst, next 4000B paces by ~1s).
    let start = Instant::now();
    let payload = vec![0x42u8; 4000];
    stream.write_all(&payload).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = timeout(WAIT, stream.read(&mut buf)).await.unwrap().unwrap();
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    let elapsed = start.elapsed();
    assert_eq!(got, payload);
    assert!(
        elapsed >= Duration::from_millis(800),
        "expected local 4 KB/s cap to pace echo (~1s), elapsed={elapsed:?}"
    );

    t.abort();
}
