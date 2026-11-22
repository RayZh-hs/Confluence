//! Seam 3: Symmetric Auth (`CredentialProvider` ↔ `Authorizer`), [`IntersectAuthorizer`] for
//! local host sovereignty, and Core's fail-closed [`AuthGate`].

use parking_lot::Mutex;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Semaphore, broadcast};

use crate::{
    BoxFut, CoreErr, Plane, PublicKey,
    lease::{
        Lease, LeaseHandle, MAX_LEASE_TTL, MAX_WIRE_LEASE_TTL, RevocationIndex, RevocationKey,
    },
};

/// Authenticated target requested on a node: either a published Endpoint or a named Transit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TargetRef<'a> {
    /// End-to-end destination service published on this scope (`A <-> B`).
    Endpoint { name: &'a str, plane: Plane },
    /// Named forwarding transit target published on this scope (`A <-> H`).
    Transit { name: &'a str, plane: Plane },
}

impl<'a> TargetRef<'a> {
    /// Returns the target name (endpoint name or transit target name).
    pub const fn name(self) -> &'a str {
        match self {
            Self::Endpoint { name, .. } | Self::Transit { name, .. } => name,
        }
    }

    /// Returns the traffic plane (`Stream` or `Datagram`).
    pub const fn plane(self) -> Plane {
        match self {
            Self::Endpoint { plane, .. } | Self::Transit { plane, .. } => plane,
        }
    }

    /// Returns `true` if this target is an end-to-end endpoint.
    pub const fn is_endpoint(self) -> bool {
        matches!(self, Self::Endpoint { .. })
    }

    /// Returns `true` if this target is a named forwarding transit.
    pub const fn is_transit(self) -> bool {
        matches!(self, Self::Transit { .. })
    }
}

/// Control-plane authorization request evaluated by an [`Authorizer`].
#[derive(Clone, Copy, Debug)]
pub struct AuthRequest<'a> {
    /// Cryptographically verified static public key of the calling peer.
    pub peer: PublicKey,
    /// Target endpoint or named transit being requested.
    pub target: TargetRef<'a>,
    /// Opaque caller-supplied credential (`0..=512` bytes), encrypted solely for this verifier.
    pub credential: &'a [u8],
    /// `true` during live in-band lease renewal; `false` during initial setup.
    pub is_renewal: bool,
}

/// Rejection returned by an [`Authorizer`] backend.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, thiserror::Error)]
pub enum AuthDenied {
    /// Policy denied access for this peer, target, or credential.
    #[default]
    #[error("authorization denied")]
    Denied,
    /// Identity and permissions were accepted, but a concurrency or quota limit was reached.
    #[error("authorization quota or concurrency limit reached")]
    Busy,
}

/// Asynchronous revocation event pushed from an [`Authorizer`] backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Revocation {
    /// Tear down all active sessions and transit circuits for this peer in this scope.
    Peer(PublicKey),
    /// Tear down all active sessions bound to this published endpoint.
    Endpoint(String),
    /// Tear down all active transit circuits bound to this named transit (exact or prefix).
    Transit(String),
    /// Invalidate all currently active leases in this scope.
    All,
}

/// Verifier-side Authorization seam ("verifier, never issuer").
///
/// Evaluated strictly on control events (setup and in-band renewal), never per data packet.
/// Always fails closed on error or timeout via [`AuthGate`].
pub trait Authorizer: Send + Sync + 'static {
    /// Evaluates whether authenticated `req.peer` may access `req.target` using `req.credential`.
    fn authorize<'a>(&'a self, req: AuthRequest<'a>) -> BoxFut<'a, Result<Lease, AuthDenied>>;

    /// Optional broadcast stream of live revocation events for this scope.
    fn revocations(&self) -> Option<broadcast::Receiver<Revocation>> {
        None
    }

    /// All live revocation streams produced by this authorizer.
    ///
    /// Combinators such as [`IntersectAuthorizer`] override this to collect child streams
    /// directly without spawning intermediate forwarding tasks.
    fn revocation_streams(&self) -> Vec<broadcast::Receiver<Revocation>> {
        self.revocations().into_iter().collect()
    }
}

/// Default fail-closed [`Authorizer`] denying every inbound request.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyAllAuthorizer;

impl Authorizer for DenyAllAuthorizer {
    fn authorize<'a>(&'a self, _req: AuthRequest<'a>) -> BoxFut<'a, Result<Lease, AuthDenied>> {
        Box::pin(async { Err(AuthDenied::Denied) })
    }
}

/// Host-sovereignty combinator intersecting a local [`Authorizer`] `L` with an external one `E`.
///
/// - Evaluates `L` first (local hard veto — external policy can never widen or override local denial).
/// - Fails closed if either authorizer denies.
/// - Intersects accepted leases via [`Lease::intersect`] (shorter TTL, composed `TrafficGate`,
///   both session RAII `guards`, and merged `AuthExtensions` with local precedence).
/// - Collects both child revocation streams with zero background tasks.
pub struct IntersectAuthorizer<L, E> {
    local: Arc<L>,
    external: Arc<E>,
}

impl<L, E> IntersectAuthorizer<L, E> {
    /// Combines `local` (host hard veto) with `external` (group/CA/enterprise verifier).
    pub fn new(local: Arc<L>, external: Arc<E>) -> Self {
        Self { local, external }
    }
}

impl<L: Authorizer, E: Authorizer> Authorizer for IntersectAuthorizer<L, E> {
    fn authorize<'a>(&'a self, req: AuthRequest<'a>) -> BoxFut<'a, Result<Lease, AuthDenied>> {
        Box::pin(async move {
            let local_lease = self.local.authorize(req).await?;
            let ext_lease = self.external.authorize(req).await?;
            Ok(local_lease.intersect(ext_lease))
        })
    }

    fn revocation_streams(&self) -> Vec<broadcast::Receiver<Revocation>> {
        let mut streams = self.local.revocation_streams();
        streams.extend(self.external.revocation_streams());
        streams
    }
}

/// Originator-side credential request supplied to [`CredentialProvider::credential`].
#[derive(Clone, Copy, Debug)]
pub struct CredentialRequest<'a> {
    /// Static public key of the node verifying this credential (a transit hop or the destination).
    pub verifier: PublicKey,
    /// Target endpoint or named transit being authorized by `verifier`.
    pub target: TargetRef<'a>,
    /// Final destination peer public key for the overall E2E connection.
    pub destination: PublicKey,
    /// Final destination endpoint name for the overall E2E connection.
    pub endpoint: &'a str,
    /// Caller-chosen path identifier supplied in [`crate::ExplicitPath::id`].
    pub path_id: u64,
    /// `true` during live in-band renewal; `false` during initial setup.
    pub is_refresh: bool,
    /// Previous credential presented to this verifier (empty on initial setup).
    pub previous: &'a [u8],
}

/// Originator-side credential acquisition and live in-band refresh seam.
///
/// Decouples credential lifecycles (SSO/OIDC brokers, short-lived capability tokens, static
/// secrets) from both routing ([`crate::PathSource`]) and application dial calls.
pub trait CredentialProvider: Send + Sync + 'static {
    /// Supplies an opaque credential (`0..=512` bytes) for `req`.
    fn credential<'a>(&'a self, req: CredentialRequest<'a>)
    -> BoxFut<'a, Result<Vec<u8>, CoreErr>>;
}

/// Default [`CredentialProvider`] returning empty credentials (for public-key-only topologies).
#[derive(Clone, Copy, Debug, Default)]
pub struct EmptyCredentials;

impl CredentialProvider for EmptyCredentials {
    fn credential<'a>(
        &'a self,
        _req: CredentialRequest<'a>,
    ) -> BoxFut<'a, Result<Vec<u8>, CoreErr>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

const DEFAULT_PER_PEER_PENDING: usize = 8;
const DEFAULT_AUTH_CONCURRENCY: usize = 32;
const DEFAULT_AUTH_TIMEOUT: Duration = Duration::from_millis(500);
const MIN_AUTH_TIMEOUT: Duration = Duration::from_millis(10);
const MAX_AUTH_TIMEOUT: Duration = Duration::from_secs(5);
const MIN_LEASE_TTL_CEILING: Duration = Duration::from_secs(1);

/// Configurable fail-closed resource and timing limits enforced by [`AuthGate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthLimits {
    /// Maximum unconfirmed setups allowed simultaneously per authenticated peer.
    pub per_peer_pending: usize,
    /// Maximum concurrent in-flight `Authorizer::authorize` evaluations.
    pub auth_concurrency: usize,
    /// Hard fail-closed timeout per `Authorizer::authorize` or `CredentialProvider::credential` call.
    pub auth_timeout: Duration,
    /// Upper bound on any accepted `Lease::ttl` (`1 s ..= 24 h`).
    pub max_lease_ttl: Duration,
}

impl Default for AuthLimits {
    fn default() -> Self {
        Self {
            per_peer_pending: DEFAULT_PER_PEER_PENDING,
            auth_concurrency: DEFAULT_AUTH_CONCURRENCY,
            auth_timeout: DEFAULT_AUTH_TIMEOUT,
            max_lease_ttl: MAX_LEASE_TTL,
        }
    }
}

impl AuthLimits {
    /// Clamps every field into its safe operational envelope.
    pub fn clamped(self) -> Self {
        Self {
            per_peer_pending: self.per_peer_pending.max(1),
            auth_concurrency: self.auth_concurrency.max(1),
            auth_timeout: self.auth_timeout.clamp(MIN_AUTH_TIMEOUT, MAX_AUTH_TIMEOUT),
            max_lease_ttl: self
                .max_lease_ttl
                .clamp(MIN_LEASE_TTL_CEILING, MAX_WIRE_LEASE_TTL),
        }
    }
}

/// Monotonic revocation epoch snapshot used to close TOCTOU races between async `authorize`
/// and lease tracking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthEpoch {
    global: u64,
    peer: u64,
    endpoint: u64,
    transit: u64,
    transit_prefix: u64,
}

#[derive(Default)]
struct HostState {
    vetoed: HashSet<PublicKey>,
    pending: HashMap<PublicKey, usize>,
    global_epoch: u64,
    peer_epochs: HashMap<PublicKey, u64>,
    endpoint_epochs: HashMap<String, u64>,
    transit_epochs: HashMap<(Plane, String), u64>,
}

/// Core enforcement wrapper around an [`Authorizer`] plugin.
///
/// Enforces hard evaluation timeouts, bounded concurrency, per-peer pending setup quotas,
/// local host hard veto, TOCTOU-free revocation epochs, and sharded instant lease cancellation.
pub struct AuthGate {
    authorizer: Arc<dyn Authorizer>,
    limits: AuthLimits,
    permits: Semaphore,
    host: Arc<Mutex<HostState>>,
    index: RevocationIndex,
}

/// RAII quota guard capping unconfirmed setups per peer.
pub struct PendingSetup {
    host: Arc<Mutex<HostState>>,
    peer: PublicKey,
}

impl Drop for PendingSetup {
    fn drop(&mut self) {
        let mut host = self.host.lock();
        if let Some(count) = host.pending.get_mut(&self.peer) {
            *count -= 1;
            if *count == 0 {
                host.pending.remove(&self.peer);
            }
        }
    }
}

impl AuthGate {
    /// Wraps `authorizer` in a bounded fail-closed gate using default [`AuthLimits`].
    pub fn new(authorizer: Arc<dyn Authorizer>) -> Self {
        Self::with_limits(authorizer, AuthLimits::default())
    }

    /// Wraps `authorizer` in a bounded fail-closed gate using clamped [`AuthLimits`].
    pub fn with_limits(authorizer: Arc<dyn Authorizer>, limits: AuthLimits) -> Self {
        let limits = limits.clamped();
        Self {
            authorizer,
            limits,
            permits: Semaphore::new(limits.auth_concurrency),
            host: Default::default(),
            index: Default::default(),
        }
    }

    /// Returns the active clamped [`AuthLimits`].
    pub fn limits(&self) -> AuthLimits {
        self.limits
    }

    /// Creates a [`LeaseHandle`] validated against this gate's `max_lease_ttl`.
    pub fn new_lease(&self, ttl: Duration) -> Result<LeaseHandle, CoreErr> {
        LeaseHandle::new_with_max_ttl(ttl, self.limits.max_lease_ttl)
    }

    /// Creates a full [`LeaseHandle`] (TTL, `TrafficGate`, RAII guards, and live claims)
    /// validated against this gate's `max_lease_ttl`.
    pub fn new_lease_from(&self, lease: Lease) -> Result<LeaseHandle, CoreErr> {
        LeaseHandle::from_lease_with_max_ttl(lease, self.limits.max_lease_ttl)
    }

    /// Renews an active [`LeaseHandle`]'s TTL validated against this gate's `max_lease_ttl`.
    pub fn renew_lease(&self, handle: &LeaseHandle, ttl: Duration) -> Result<(), CoreErr> {
        handle.renew_with_max_ttl(ttl, self.limits.max_lease_ttl)
    }

    /// Applies an in-band renewed [`Lease`] (TTL, swapped `TrafficGate`, updated claims, and any
    /// additional guards) to an active [`LeaseHandle`].
    pub fn renew_lease_from(&self, handle: &LeaseHandle, lease: Lease) -> Result<(), CoreErr> {
        handle.renew_lease_with_max_ttl(lease, self.limits.max_lease_ttl)
    }

    /// Returns all live revocation streams produced by the underlying [`Authorizer`].
    pub fn revocation_streams(&self) -> Vec<broadcast::Receiver<Revocation>> {
        self.authorizer.revocation_streams()
    }

    /// Reserves a per-peer pending-setup slot, failing immediately if `peer` is vetoed or saturated.
    pub fn pending(&self, peer: PublicKey) -> Result<PendingSetup, CoreErr> {
        let mut host = self.host.lock();
        if host.vetoed.contains(&peer) {
            return Err(CoreErr::Revoked);
        }
        let count = host.pending.entry(peer).or_default();
        if *count >= self.limits.per_peer_pending {
            return Err(CoreErr::Busy);
        }
        *count += 1;
        Ok(PendingSetup {
            host: self.host.clone(),
            peer,
        })
    }

    /// Evaluates `req` under the hard timeout and concurrency semaphore, failing closed on error.
    pub async fn authorize(&self, req: AuthRequest<'_>) -> Result<Lease, CoreErr> {
        if self.host.lock().vetoed.contains(&req.peer) {
            return Err(CoreErr::Revoked);
        }
        let deadline = tokio::time::Instant::now() + self.limits.auth_timeout;
        let lease = tokio::time::timeout_at(deadline, async {
            let _permit = self.permits.acquire().await.map_err(|_| CoreErr::Denied)?;
            self.authorizer
                .authorize(req)
                .await
                .map_err(|err| match err {
                    AuthDenied::Denied => CoreErr::Denied,
                    AuthDenied::Busy => CoreErr::Busy,
                })
        })
        .await
        .map_err(|_| {
            tracing::warn!(peer = %req.peer, target = req.target.name(), "authorization timed out");
            CoreErr::Timeout
        })??;
        if tokio::time::Instant::now() >= deadline {
            return Err(CoreErr::Timeout);
        }
        if self.host.lock().vetoed.contains(&req.peer) {
            return Err(CoreErr::Revoked);
        }
        lease.validate_with_max_ttl(self.limits.max_lease_ttl)
    }

    /// Returns `true` if `peer` is currently under a local hard veto.
    pub fn is_vetoed(&self, peer: &PublicKey) -> bool {
        self.host.lock().vetoed.contains(peer)
    }

    /// Captures a revocation epoch snapshot for an endpoint (or outbound peer session).
    pub fn epoch_for_endpoint(&self, peer: PublicKey, endpoint: Option<&str>) -> AuthEpoch {
        let host = self.host.lock();
        AuthEpoch {
            global: host.global_epoch,
            peer: host.peer_epochs.get(&peer).copied().unwrap_or(0),
            endpoint: endpoint
                .and_then(|name| host.endpoint_epochs.get(name).copied())
                .unwrap_or(0),
            transit: 0,
            transit_prefix: 0,
        }
    }

    /// Captures a revocation epoch snapshot for a named transit target (plus optional matched prefix).
    pub fn epoch_for_transit(
        &self,
        peer: PublicKey,
        plane: Plane,
        target: &str,
        prefix: Option<&str>,
    ) -> AuthEpoch {
        let host = self.host.lock();
        AuthEpoch {
            global: host.global_epoch,
            peer: host.peer_epochs.get(&peer).copied().unwrap_or(0),
            endpoint: 0,
            transit: host
                .transit_epochs
                .get(&(plane, target.to_owned()))
                .copied()
                .unwrap_or(0),
            transit_prefix: prefix
                .and_then(|p| host.transit_epochs.get(&(plane, p.to_owned())).copied())
                .unwrap_or(0),
        }
    }

    /// Registers an endpoint or outbound `lease` if no revocation raced against `epoch`.
    pub fn track_endpoint(
        &self,
        epoch: AuthEpoch,
        peer: PublicKey,
        endpoint: Option<&str>,
        lease: &Arc<LeaseHandle>,
    ) -> Result<(), CoreErr> {
        let host = self.host.lock();
        if Self::epoch_stale(&host, epoch, peer, endpoint, None, None) {
            return Err(CoreErr::Revoked);
        }
        self.index.track(RevocationKey::Peer(peer), lease);
        if let Some(endpoint) = endpoint {
            self.index
                .track(RevocationKey::Endpoint(endpoint.into()), lease);
        }
        Ok(())
    }

    /// Registers a transit circuit `lease` indexed by `peer`, `(plane, target)`, and optional `prefix`.
    pub fn track_transit(
        &self,
        epoch: AuthEpoch,
        peer: PublicKey,
        plane: Plane,
        target: &str,
        prefix: Option<&str>,
        lease: &Arc<LeaseHandle>,
    ) -> Result<(), CoreErr> {
        let host = self.host.lock();
        if Self::epoch_stale(
            &host,
            epoch,
            peer,
            None,
            Some((plane, target)),
            prefix.map(|p| (plane, p)),
        ) {
            return Err(CoreErr::Revoked);
        }
        self.index.track(RevocationKey::Peer(peer), lease);
        self.index
            .track(RevocationKey::Transit(plane, target.into()), lease);
        if let Some(prefix) = prefix
            && prefix != target
        {
            self.index
                .track(RevocationKey::Transit(plane, prefix.into()), lease);
        }
        Ok(())
    }

    fn epoch_stale(
        host: &HostState,
        epoch: AuthEpoch,
        peer: PublicKey,
        endpoint: Option<&str>,
        transit: Option<(Plane, &str)>,
        transit_prefix: Option<(Plane, &str)>,
    ) -> bool {
        host.global_epoch != epoch.global
            || host.vetoed.contains(&peer)
            || host.peer_epochs.get(&peer).copied().unwrap_or(0) != epoch.peer
            || endpoint.is_some_and(|name| {
                host.endpoint_epochs.get(name).copied().unwrap_or(0) != epoch.endpoint
            })
            || transit.is_some_and(|(plane, name)| {
                host.transit_epochs
                    .get(&(plane, name.to_owned()))
                    .copied()
                    .unwrap_or(0)
                    != epoch.transit
            })
            || transit_prefix.is_some_and(|(plane, name)| {
                host.transit_epochs
                    .get(&(plane, name.to_owned()))
                    .copied()
                    .unwrap_or(0)
                    != epoch.transit_prefix
            })
    }

    /// Imposes a local hard veto on `peer` and immediately cancels all active sessions/circuits.
    pub fn revoke_peer(&self, peer: PublicKey) {
        tracing::debug!(peer = %peer, "local hard veto applied to peer");
        let mut host = self.host.lock();
        host.vetoed.insert(peer);
        let entry = host.peer_epochs.entry(peer).or_default();
        *entry = entry.wrapping_add(1);
        self.index
            .revoke(&RevocationKey::Peer(peer), CoreErr::Revoked);
    }

    /// Lifts a previous local hard veto on `peer`, permitting future setups to be evaluated again.
    pub fn unrevoke_peer(&self, peer: PublicKey) {
        self.host.lock().vetoed.remove(&peer);
    }

    pub(crate) fn revoke_peer_sessions(&self, peer: PublicKey) {
        let mut host = self.host.lock();
        let entry = host.peer_epochs.entry(peer).or_default();
        *entry = entry.wrapping_add(1);
        self.index
            .revoke(&RevocationKey::Peer(peer), CoreErr::Revoked);
    }

    /// Immediately cancels all sessions bound to `endpoint`.
    pub fn revoke_endpoint(&self, endpoint: &str) {
        let mut host = self.host.lock();
        let entry = host.endpoint_epochs.entry(endpoint.to_owned()).or_default();
        *entry = entry.wrapping_add(1);
        self.index.revoke(
            &RevocationKey::Endpoint(endpoint.into()),
            CoreErr::Unpublished,
        );
    }

    /// Immediately cancels all transit circuits admitted through `transit` on `plane`.
    pub fn revoke_transit_plane(&self, plane: Plane, transit: &str, reason: CoreErr) {
        let mut host = self.host.lock();
        let entry = host
            .transit_epochs
            .entry((plane, transit.to_owned()))
            .or_default();
        *entry = entry.wrapping_add(1);
        self.index
            .revoke(&RevocationKey::Transit(plane, transit.into()), reason);
    }

    /// Immediately cancels all transit circuits admitted through `transit` across both planes.
    pub fn revoke_transit(&self, transit: &str, reason: CoreErr) {
        self.revoke_transit_plane(Plane::Stream, transit, reason.clone());
        self.revoke_transit_plane(Plane::Datagram, transit, reason);
    }

    pub(crate) fn invalidate(&self) {
        let mut host = self.host.lock();
        host.global_epoch = host.global_epoch.wrapping_add(1);
        self.index.invalidate();
    }
}
