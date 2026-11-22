//! Group-semantic [`Authorizer`], short-lived capability tokens, [`FnCredentials`], and
//! [`LocalHostPolicy`] for composing host sovereignty via Core's [`confluence_core::IntersectAuthorizer`].

use std::{
    collections::{HashMap, HashSet},
    sync::{
        RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use confluence_core::{
    AuthDenied, AuthRequest, Authorizer, BoxFut, CoreErr, CredentialProvider, CredentialRequest,
    Lease, MAX_LEASE_TTL, Plane, PublicKey, Revocation, TargetRef,
};
use confluence_plugins::{QosLimits, RateGate};
use subtle::ConstantTimeEq;
use tokio::sync::broadcast;

use crate::now_ms;

// ---------------------------------------------------------------------------
// 1. Group Semantic ACL + Short-Lived Capability Tokens ("Verifier, Not Issuer")
// ---------------------------------------------------------------------------

/// Role capability bitflags encoded inside a `GroupToken`.
pub mod caps {
    pub const ENDPOINT_STREAM: u32 = 1 << 0;
    pub const ENDPOINT_DATAGRAM: u32 = 1 << 1;
    pub const HOP_STREAM: u32 = 1 << 2;
    pub const HOP_DATAGRAM: u32 = 1 << 3;
    pub const ADMIN: u32 = 1 << 4;

    pub const MEMBER: u32 = ENDPOINT_STREAM | ENDPOINT_DATAGRAM | HOP_STREAM | HOP_DATAGRAM;
    pub const GUEST_ENDPOINT_ONLY: u32 = ENDPOINT_STREAM | ENDPOINT_DATAGRAM;
    pub const RELAY_ONLY: u32 = HOP_STREAM | HOP_DATAGRAM;
}

/// Compact 73-byte authenticated group capability token (fits well inside Core's 512 B cap).
pub const GROUP_TOKEN_LEN: usize = 73;
const TOKEN_VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupTokenClaims {
    pub group_id: u64,
    pub serial: u64,
    pub expires_at_ms: u64,
    pub capabilities: u32,
    /// `[0; 4]` means wildcard (all endpoints allowed by role); otherwise
    /// `BLAKE3("confluence-v1-ep-tag" || ep_name)[..4]`.
    pub endpoint_tag: [u8; 4],
    /// Optional per-token rate cap in bytes/sec (`0` = unlimited / defer to role).
    pub rate_bps: u64,
}

pub fn endpoint_tag(name: &str) -> [u8; 4] {
    let h = blake3::derive_key("confluence-v1-ep-tag", name.as_bytes());
    h[..4].try_into().unwrap()
}

fn token_mac(
    group_secret: &[u8; 32],
    group_id: u64,
    peer: &PublicKey,
    body: &[u8; 41],
) -> [u8; 32] {
    let key = blake3::derive_key("confluence-v1-group-token-mac", group_secret);
    let mut h = blake3::Hasher::new_keyed(&key);
    h.update(&group_id.to_be_bytes());
    h.update(&peer.0);
    h.update(body);
    *h.finalize().as_bytes()
}

/// Out-of-core group token issuer (CLI / invite broker / OIDC service).
/// Never runs inside `confluence-core`.
pub struct GroupIssuer {
    group_id: u64,
    secret: [u8; 32],
    next_serial: AtomicU64,
}

impl GroupIssuer {
    pub fn new(group_id: u64, secret: [u8; 32]) -> Self {
        Self {
            group_id,
            secret,
            next_serial: AtomicU64::new(1),
        }
    }

    pub fn group_id(&self) -> u64 {
        self.group_id
    }

    pub fn secret(&self) -> [u8; 32] {
        self.secret
    }

    /// Issue a short-lived capability token bound cryptographically to `(group_id, peer)`.
    pub fn issue(
        &self,
        peer: PublicKey,
        capabilities: u32,
        endpoint_scope: Option<&str>,
        ttl: Duration,
        rate_bps: u64,
    ) -> (u64, Vec<u8>) {
        let serial = self.next_serial.fetch_add(1, Ordering::Relaxed);
        let expires_at_ms = now_ms().saturating_add(ttl.as_millis() as u64);
        let ep_tag = endpoint_scope.map(endpoint_tag).unwrap_or([0; 4]);

        let mut body = [0u8; 41];
        body[0] = TOKEN_VERSION;
        body[1..9].copy_from_slice(&self.group_id.to_be_bytes());
        body[9..17].copy_from_slice(&serial.to_be_bytes());
        body[17..25].copy_from_slice(&expires_at_ms.to_be_bytes());
        body[25..29].copy_from_slice(&capabilities.to_be_bytes());
        body[29..33].copy_from_slice(&ep_tag);
        body[33..41].copy_from_slice(&rate_bps.to_be_bytes());

        let mac = token_mac(&self.secret, self.group_id, &peer, &body);
        let mut out = Vec::with_capacity(GROUP_TOKEN_LEN);
        out.extend_from_slice(&body);
        out.extend_from_slice(&mac);
        (serial, out)
    }
}

/// Group policy rule configured locally on a verifying node.
#[derive(Clone, Debug)]
pub struct GroupRule {
    pub required_caps: u32,
    pub allowed_endpoints: Option<HashSet<String>>,
    pub allowed_transits: Option<HashSet<String>>,
    pub max_ttl: Duration,
}

impl Default for GroupRule {
    fn default() -> Self {
        Self {
            required_caps: 0,
            allowed_endpoints: None,
            allowed_transits: None,
            max_ttl: Duration::from_secs(60),
        }
    }
}

struct GroupState {
    group_id: u64,
    secret: [u8; 32],
    min_serial: HashMap<PublicKey, u64>,
    kicked: HashSet<PublicKey>,
    rule: GroupRule,
    dissolved: bool,
}

/// Verifier-only [`Authorizer`] plugin implementing peer-owned Group semantics:
/// - Verifies short-lived `GroupToken`s bound to `(group_id, peer_pubkey)`
/// - Attaches verified [`GroupTokenClaims`] to `Lease::context` for downstream QoS or app RBAC
/// - Supports per-peer serial CRL, reversible member kick/unkick, and instant `Revocation::All`
pub struct GroupAcl {
    state: RwLock<GroupState>,
    events: broadcast::Sender<Revocation>,
}

impl GroupAcl {
    pub fn new(group_id: u64, secret: [u8; 32], rule: GroupRule) -> Self {
        Self {
            state: RwLock::new(GroupState {
                group_id,
                secret,
                min_serial: HashMap::new(),
                kicked: HashSet::new(),
                rule,
                dissolved: false,
            }),
            events: broadcast::channel(128).0,
        }
    }

    /// Kick a member from this group and immediately tear down all their live circuits.
    pub fn kick_member(&self, peer: PublicKey) {
        self.state.write().unwrap().kicked.insert(peer);
        let _ = self.events.send(Revocation::Peer(peer));
    }

    /// Re-admit a previously kicked member.
    pub fn unkick_member(&self, peer: PublicKey) {
        self.state.write().unwrap().kicked.remove(&peer);
    }

    /// Advance a peer's minimum valid token serial (CRL entry) and tear down active sessions.
    pub fn revoke_tokens_below(&self, peer: PublicKey, min_valid_serial: u64) {
        let mut st = self.state.write().unwrap();
        let entry = st.min_serial.entry(peer).or_insert(0);
        *entry = (*entry).max(min_valid_serial);
        drop(st);
        let _ = self.events.send(Revocation::Peer(peer));
    }

    /// Dissolve the entire group, invalidating every active lease in O(1) via `Revocation::All`.
    pub fn revoke_entire_group(&self) {
        self.state.write().unwrap().dissolved = true;
        let _ = self.events.send(Revocation::All);
    }

    fn parse_and_verify(
        state: &GroupState,
        peer: &PublicKey,
        credential: &[u8],
    ) -> Result<GroupTokenClaims, AuthDenied> {
        if credential.len() != GROUP_TOKEN_LEN {
            return Err(AuthDenied::Denied);
        }
        let body: &[u8; 41] = credential[..41].try_into().unwrap();
        let mac = &credential[41..73];
        let expected = token_mac(&state.secret, state.group_id, peer, body);
        if !bool::from(expected.ct_eq(mac)) {
            return Err(AuthDenied::Denied);
        }
        if body[0] != TOKEN_VERSION {
            return Err(AuthDenied::Denied);
        }
        let group_id = u64::from_be_bytes(body[1..9].try_into().unwrap());
        if group_id != state.group_id {
            return Err(AuthDenied::Denied);
        }
        let serial = u64::from_be_bytes(body[9..17].try_into().unwrap());
        let expires_at_ms = u64::from_be_bytes(body[17..25].try_into().unwrap());
        let capabilities = u32::from_be_bytes(body[25..29].try_into().unwrap());
        let endpoint_tag: [u8; 4] = body[29..33].try_into().unwrap();
        let rate_bps = u64::from_be_bytes(body[33..41].try_into().unwrap());
        Ok(GroupTokenClaims {
            group_id,
            serial,
            expires_at_ms,
            capabilities,
            endpoint_tag,
            rate_bps,
        })
    }
}

impl Authorizer for GroupAcl {
    fn authorize<'a>(&'a self, req: AuthRequest<'a>) -> BoxFut<'a, Result<Lease, AuthDenied>> {
        Box::pin(async move {
            let state = self.state.read().unwrap();
            if state.dissolved || state.kicked.contains(&req.peer) {
                return Err(AuthDenied::Denied);
            }
            let claims = Self::parse_and_verify(&state, &req.peer, req.credential)?;
            if state
                .min_serial
                .get(&req.peer)
                .is_some_and(|&min| claims.serial < min)
            {
                return Err(AuthDenied::Denied);
            }
            let now = now_ms();
            let remaining_ms = claims
                .expires_at_ms
                .checked_sub(now)
                .filter(|&ms| ms > 0)
                .ok_or(AuthDenied::Denied)?;
            if (claims.capabilities & state.rule.required_caps) != state.rule.required_caps {
                return Err(AuthDenied::Denied);
            }

            match req.target {
                TargetRef::Endpoint { name, plane } => {
                    let needed = match plane {
                        Plane::Stream => caps::ENDPOINT_STREAM,
                        Plane::Datagram => caps::ENDPOINT_DATAGRAM,
                    };
                    if claims.capabilities & needed == 0 {
                        return Err(AuthDenied::Denied);
                    }
                    if claims.endpoint_tag != [0; 4] && claims.endpoint_tag != endpoint_tag(name) {
                        return Err(AuthDenied::Denied);
                    }
                    if let Some(allowed) = &state.rule.allowed_endpoints
                        && !allowed.contains(name)
                    {
                        return Err(AuthDenied::Denied);
                    }
                }
                TargetRef::Transit { name, plane } => {
                    let needed = match plane {
                        Plane::Stream => caps::HOP_STREAM,
                        Plane::Datagram => caps::HOP_DATAGRAM,
                    };
                    if claims.capabilities & needed == 0 {
                        return Err(AuthDenied::Denied);
                    }
                    if let Some(allowed) = &state.rule.allowed_transits
                        && !allowed.contains(name)
                    {
                        return Err(AuthDenied::Denied);
                    }
                }
            }

            let ttl = Duration::from_millis(remaining_ms)
                .min(state.rule.max_ttl)
                .min(MAX_LEASE_TTL);
            let mut lease = Lease::new(ttl);
            if claims.rate_bps > 0 {
                lease = lease.with_gate(RateGate::new(QosLimits {
                    max_bytes_per_sec: claims.rate_bps,
                    ..Default::default()
                }));
            }
            Ok(lease.with_context(claims))
        })
    }

    fn revocations(&self) -> Option<broadcast::Receiver<Revocation>> {
        Some(self.events.subscribe())
    }
}

// ---------------------------------------------------------------------------
// 2. Local Endpoint-Scoped Allowlist (for Core's IntersectAuthorizer)
// ---------------------------------------------------------------------------

/// Local host allowlist restricting which endpoints/transits a host permits and capping lease TTL,
/// regardless of what an external Group/CA authorizer allows.
pub struct LocalHostPolicy {
    allowed_endpoints: RwLock<HashSet<String>>,
    allowed_transits: RwLock<Option<HashSet<String>>>,
    max_ttl: RwLock<Duration>,
    events: broadcast::Sender<Revocation>,
}

impl Default for LocalHostPolicy {
    fn default() -> Self {
        Self {
            allowed_endpoints: Default::default(),
            allowed_transits: Default::default(),
            max_ttl: RwLock::new(MAX_LEASE_TTL),
            events: broadcast::channel(128).0,
        }
    }
}

impl LocalHostPolicy {
    pub fn allow_endpoint(&self, ep: impl Into<String>) {
        self.allowed_endpoints.write().unwrap().insert(ep.into());
    }

    pub fn disallow_endpoint(&self, ep: &str) {
        self.allowed_endpoints.write().unwrap().remove(ep);
        let _ = self.events.send(Revocation::Endpoint(ep.to_owned()));
    }

    pub fn allow_transit(&self, name: impl Into<String>) {
        self.allowed_transits
            .write()
            .unwrap()
            .get_or_insert_with(HashSet::new)
            .insert(name.into());
    }

    pub fn set_max_ttl(&self, ttl: Duration) {
        *self.max_ttl.write().unwrap() = ttl;
    }
}

impl Authorizer for LocalHostPolicy {
    fn authorize<'a>(&'a self, req: AuthRequest<'a>) -> BoxFut<'a, Result<Lease, AuthDenied>> {
        Box::pin(async move {
            match req.target {
                TargetRef::Endpoint { name, .. } => {
                    if !self.allowed_endpoints.read().unwrap().contains(name) {
                        return Err(AuthDenied::Denied);
                    }
                }
                TargetRef::Transit { name, .. } => {
                    let allowed = self.allowed_transits.read().unwrap();
                    if !allowed.as_ref().is_some_and(|set| set.contains(name)) {
                        return Err(AuthDenied::Denied);
                    }
                }
            }
            Ok(Lease::new(*self.max_ttl.read().unwrap()))
        })
    }

    fn revocations(&self) -> Option<broadcast::Receiver<Revocation>> {
        Some(self.events.subscribe())
    }
}

/// Callback-backed [`CredentialProvider`] helper for dynamic token rotation in tests & meshes.
pub struct FnCredentials<F>(pub F);

impl<F> CredentialProvider for FnCredentials<F>
where
    F: Fn(CredentialRequest<'_>) -> Result<Vec<u8>, CoreErr> + Send + Sync + 'static,
{
    fn credential<'a>(
        &'a self,
        req: CredentialRequest<'a>,
    ) -> BoxFut<'a, Result<Vec<u8>, CoreErr>> {
        let res = (self.0)(req);
        Box::pin(async move { res })
    }
}
