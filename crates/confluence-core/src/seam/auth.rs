//! Seam 3: Symmetric credential acquisition, fail-closed authorization, leases, traffic gates, and live revocations.

use core::any::{Any, TypeId};
use core::fmt;
use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;

use crate::error::CoreError;
use crate::runtime::BoxFuture;
use crate::runtime::sync::{
    BroadcastReceiver, BroadcastRecvError, BroadcastSender, Watch, WatchReceiver,
};
use crate::types::{Credential, Direction, PublicKey, TargetRef};

// ---------------------------------------------------------------------------
// Seam 3A — Originator Credential Acquisition
// ---------------------------------------------------------------------------

/// Context supplied to [`CredentialProvider::credential`] during setup or in-band lease renewal.
#[derive(Debug, Clone, Copy)]
pub struct CredentialRequest<'a> {
    /// Public key of the verifier (Destination or intermediate Transit hop) receiving the credential.
    pub verifier: PublicKey,
    /// Logical target evaluated by `verifier` (`Endpoint` or `Transit`).
    pub target: TargetRef<'a>,
    /// Final destination public key of the connection.
    pub destination: PublicKey,
    /// Final destination endpoint name of the connection.
    pub endpoint: &'a str,
    /// Caller-assigned `ExplicitPath::id`.
    pub path_id: u64,
    /// `false` during initial setup, `true` during in-band lease renewal.
    pub is_refresh: bool,
    /// Last acknowledged credential bytes for this verifier (`&[]` on initial setup).
    pub prior: &'a [u8],
}

/// Out-of-core credential acquisition hook (Seam 3A).
///
/// Decoupled from routing and application dial calls; each verifier's credential is encrypted
/// solely for that verifier.
pub trait CredentialProvider: Send + Sync + 'static {
    /// Fetches or refreshes an opaque [`Credential`] (`0..=128` bytes) for `req`.
    fn credential<'a>(
        &'a self,
        req: CredentialRequest<'a>,
    ) -> BoxFuture<'a, Result<Credential, CoreError>>;
}

/// Default [`CredentialProvider`] supplying empty 0-byte credentials (public-key-only auth).
#[derive(Debug, Clone, Copy, Default)]
pub struct EmptyCredentials;

impl CredentialProvider for EmptyCredentials {
    fn credential<'a>(
        &'a self,
        _req: CredentialRequest<'a>,
    ) -> BoxFuture<'a, Result<Credential, CoreError>> {
        Box::pin(async { Ok(Credential::empty()) })
    }
}

// ---------------------------------------------------------------------------
// Seam 3B — Verifier Authorization, TrafficGate, Permits, Claims & Revocations
// ---------------------------------------------------------------------------

/// Authenticated control-plane authorization request evaluated by [`Authorizer::authorize`].
#[derive(Clone, Copy)]
pub struct AuthRequest<'a> {
    /// Cryptographically authenticated static public key of the originator `A`.
    pub peer: PublicKey,
    /// Logical target (`Endpoint` or full requested `Transit` name, never stripped to subtarget).
    pub target: TargetRef<'a>,
    /// Opaque credential bytes (`0..=128` bytes) decrypted for this verifier.
    pub credential: &'a [u8],
    /// `false` during initial setup, `true` during in-band lease renewal.
    pub is_renewal: bool,
}

impl fmt::Debug for AuthRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthRequest")
            .field("peer", &self.peer)
            .field("target", &self.target)
            .field("credential_len", &self.credential.len())
            .field("is_renewal", &self.is_renewal)
            .finish()
    }
}

/// Structured rejection returned by [`Authorizer::authorize`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthDenied {
    /// Policy explicitly denied access.
    Denied,
    /// Verifier or policy backend is temporarily overloaded (retryable on renewal).
    Busy,
}

impl From<AuthDenied> for CoreError {
    fn from(value: AuthDenied) -> Self {
        match value {
            AuthDenied::Denied => Self::Denied,
            AuthDenied::Busy => Self::Busy,
        }
    }
}

/// Out-of-band instant revocation signal emitted by an [`Authorizer`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Revocation {
    /// Revoke all active sessions/circuits for `PublicKey` (without adding to local permanent veto).
    Peer(PublicKey),
    /// Revoke all active sessions for the named endpoint (`Unpublished`).
    Endpoint(String),
    /// Revoke all active transit circuits matching `name` across both planes (`Revoked`).
    Transit(String),
    /// Revoke every active lease in the scope (`Revoked`).
    All,
}

/// Error returned by [`RevocationReceiver::recv`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationRecvError {
    /// Receiver fell behind the broadcast buffer and missed `u64` revocation events.
    ///
    /// Scopes MUST respond fail-closed by invalidating ALL active leases.
    Lagged(u64),
    /// All [`RevocationSender`] handles have been dropped.
    Closed,
}

/// Non-blocking publisher for live [`Revocation`] events.
#[derive(Clone)]
pub struct RevocationSender {
    inner: BroadcastSender<Revocation>,
}

impl RevocationSender {
    /// Broadcasts a [`Revocation`] event without blocking.
    pub fn send(&self, event: Revocation) {
        self.inner.send(event);
    }

    /// Creates a new [`RevocationReceiver`] subscribed to future revocations.
    #[must_use]
    pub fn subscribe(&self) -> RevocationReceiver {
        RevocationReceiver {
            inner: self.inner.subscribe(),
        }
    }
}

impl fmt::Debug for RevocationSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationSender").finish_non_exhaustive()
    }
}

/// Subscriber handle receiving live [`Revocation`] events with exact lag reporting.
pub struct RevocationReceiver {
    inner: BroadcastReceiver<Revocation>,
}

impl RevocationReceiver {
    /// Waits for the next [`Revocation`] event, surfacing exact lag counts via
    /// [`RevocationRecvError::Lagged`].
    pub async fn recv(&mut self) -> Result<Revocation, RevocationRecvError> {
        match self.inner.recv().await {
            Ok(ev) => Ok(ev),
            Err(BroadcastRecvError::Lagged(n)) => Err(RevocationRecvError::Lagged(n)),
            Err(BroadcastRecvError::Closed) => Err(RevocationRecvError::Closed),
        }
    }
}

impl fmt::Debug for RevocationReceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationReceiver").finish_non_exhaustive()
    }
}

/// Creates a bounded overflow-reporting revocation broadcast channel.
#[must_use]
pub fn revocation_channel(capacity: usize) -> (RevocationSender, RevocationReceiver) {
    let (tx, rx) = BroadcastSender::channel(capacity);
    (
        RevocationSender { inner: tx },
        RevocationReceiver { inner: rx },
    )
}

/// Synchronous data-plane decision for a single datagram `DATA` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatagramAction {
    /// Forward or deliver the datagram.
    Allow,
    /// Silently drop this datagram without closing the session/circuit.
    Drop,
    /// Immediately terminate the session/circuit with the supplied error.
    Close(CoreError),
}

/// Synchronous data-plane decision for a stream `ST_DATA` quantum or record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamAction {
    /// Forward or deliver the bytes immediately.
    Allow,
    /// Pace the data flow by sleeping for `Duration` on Core's injected [`crate::runtime::Clock`].
    Delay(Duration),
    /// Immediately terminate the session/circuit with the supplied error.
    Close(CoreError),
}

/// Algorithm-agnostic synchronous data-plane traffic hook attached to a [`Lease`].
///
/// Evaluated strictly on user `DATA` frames/quanta on verifiers (never on `SETUP*`,
/// `RENEW*`, `CLOSE`, `MTU*`, or `FIN` control frames).
pub trait TrafficGate: Send + Sync + 'static {
    /// Evaluates one datagram `DATA` packet of `bytes` in `dir`.
    fn check_datagram(&self, dir: Direction, bytes: usize) -> DatagramAction;

    /// Evaluates one stream `ST_DATA` quantum/record of `bytes` in `dir`.
    fn charge_stream(&self, dir: Direction, bytes: usize) -> StreamAction;
}

/// Marker trait for session-scoped RAII resource permits (e.g., concurrency slots).
///
/// Permits attached to a [`Lease`] remain alive across in-band renewals and drop only
/// when the session or circuit terminates.
pub trait SessionGuard: Send + Sync + 'static {}

impl<T: Send + Sync + 'static> SessionGuard for T {}

/// Immutable, cloneable type-map carrying verified typed application claims attached to a [`Lease`].
#[derive(Clone, Default)]
pub struct AuthExtensions {
    entries: Arc<HashMap<TypeId, Arc<dyn Any + Send + Sync>>>,
}

impl AuthExtensions {
    /// Creates an empty `AuthExtensions` map.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Alias for [`Self::empty`].
    #[must_use]
    pub fn new() -> Self {
        Self::empty()
    }

    /// Inserts a typed claim value, replacing any previous entry of the same type `T`.
    pub fn insert<T: Send + Sync + 'static>(&mut self, value: T) {
        self.insert_arc(Arc::new(value));
    }

    /// Inserts a pre-wrapped `Arc<T>` typed claim.
    pub fn insert_arc<T: Send + Sync + 'static>(&mut self, value: Arc<T>) {
        Arc::make_mut(&mut self.entries).insert(TypeId::of::<T>(), value);
    }

    /// Looks up a typed claim `T`.
    #[must_use]
    pub fn get<T: Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.entries
            .get(&TypeId::of::<T>())
            .and_then(|v| Arc::clone(v).downcast::<T>().ok())
    }

    /// Returns `true` if no typed claims are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of stored typed claim entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Merges `self` and `other`, strictly preserving `self`'s entries on same-type collisions.
    ///
    /// Used by host-sovereign `IntersectAuthorizer` so external policies can never overwrite
    /// local host claims.
    #[must_use]
    pub fn merge_prefer_self(&self, other: &Self) -> Self {
        if other.is_empty() {
            return self.clone();
        }
        if self.is_empty() {
            return other.clone();
        }
        let mut merged = (*other.entries).clone();
        for (k, v) in self.entries.iter() {
            merged.insert(*k, Arc::clone(v));
        }
        Self {
            entries: Arc::new(merged),
        }
    }
}

impl fmt::Debug for AuthExtensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthExtensions")
            .field("len", &self.entries.len())
            .finish()
    }
}

/// Time-bounded, revocable authorization decision returned by [`Authorizer::authorize`].
pub struct Lease {
    /// Granted lease lifetime (must be `>= 1 ms` and `<= AuthLimits::max_lease_ttl`).
    pub ttl: Duration,
    /// Optional algorithm-agnostic data-plane traffic gate (swapped atomically on renewal).
    pub gate: Option<Arc<dyn TrafficGate>>,
    /// Session-scoped RAII permits preserved across renewals until session close.
    pub guards: Vec<Box<dyn SessionGuard>>,
    /// Typed verified application claims surfaced live through [`SessionAuth`].
    pub extensions: AuthExtensions,
}

impl Lease {
    /// Creates a new `Lease` with lifetime `ttl` and no gate, guards, or claims.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            gate: None,
            guards: Vec::new(),
            extensions: AuthExtensions::empty(),
        }
    }

    /// Alias for [`Self::new`].
    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self::new(ttl)
    }

    /// Attaches an optional data-plane [`TrafficGate`].
    #[must_use]
    pub fn with_gate(mut self, gate: Arc<dyn TrafficGate>) -> Self {
        self.gate = Some(gate);
        self
    }

    /// Appends a session-scoped RAII [`SessionGuard`] permit.
    #[must_use]
    pub fn with_guard(mut self, guard: impl SessionGuard) -> Self {
        self.guards.push(Box::new(guard));
        self
    }

    /// Sets the [`AuthExtensions`] map on this lease.
    #[must_use]
    pub fn with_extensions(mut self, extensions: AuthExtensions) -> Self {
        self.extensions = extensions;
        self
    }

    /// Convenience builder inserting a single typed claim `T` into `self.extensions`.
    #[must_use]
    pub fn with_context<T: Send + Sync + 'static>(mut self, value: T) -> Self {
        self.extensions.insert(value);
        self
    }
}

impl fmt::Debug for Lease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lease")
            .field("ttl", &self.ttl)
            .field("has_gate", &self.gate.is_some())
            .field("guards", &self.guards.len())
            .field("extensions", &self.extensions)
            .finish()
    }
}

/// Live verified identity and claims handle passed to Endpoint and Transit handlers (Seam 4).
///
/// Automatically reflects updated [`AuthExtensions`] whenever an in-band lease renewal succeeds.
#[derive(Clone)]
pub struct SessionAuth {
    peer: PublicKey,
    rx: WatchReceiver<AuthExtensions>,
}

impl SessionAuth {
    /// Creates a static `SessionAuth` snapshot (useful for testing or standalone handlers).
    #[must_use]
    pub fn new(peer: PublicKey, extensions: AuthExtensions) -> Self {
        let (_tx, rx) = Watch::new(extensions);
        Self { peer, rx }
    }

    pub(crate) fn from_watch(peer: PublicKey, rx: WatchReceiver<AuthExtensions>) -> Self {
        Self { peer, rx }
    }

    /// Returns the cryptographically verified remote originator public key.
    #[must_use]
    pub const fn peer(&self) -> PublicKey {
        self.peer
    }

    /// Returns the latest verified [`AuthExtensions`] snapshot in $O(1)$.
    #[must_use]
    pub fn extensions(&self) -> AuthExtensions {
        self.rx.borrow_cloned()
    }

    /// Looks up a typed claim `T` from the latest verified [`AuthExtensions`].
    #[must_use]
    pub fn context<T: Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.rx.borrow_with(|ext| ext.get::<T>())
    }

    /// Waits for the next live [`AuthExtensions`] update published by an in-band lease renewal.
    ///
    /// Returns `true` when new claims are available, or `false` once the owning session closes.
    pub async fn changed(&mut self) -> bool {
        self.rx.changed().await
    }
}

impl fmt::Debug for SessionAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionAuth")
            .field("peer", &self.peer)
            .field("extensions", &self.extensions())
            .finish()
    }
}

/// Out-of-core fail-closed authorization verifier (Seam 3B).
///
/// Evaluated strictly on control-plane events (initial setup and in-band renewal, never per packet).
pub trait Authorizer: Send + Sync + 'static {
    /// Evaluates an authenticated control-plane request into a time-bounded [`Lease`].
    fn authorize<'a>(&'a self, req: AuthRequest<'a>) -> BoxFuture<'a, Result<Lease, AuthDenied>>;

    /// Optional live revocation streams monitored by the scope.
    fn revocation_streams(&self) -> Vec<RevocationReceiver> {
        Vec::new()
    }
}

/// Fail-closed default [`Authorizer`] denying every request with [`AuthDenied::Denied`].
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAllAuthorizer;

impl Authorizer for DenyAllAuthorizer {
    fn authorize<'a>(&'a self, _req: AuthRequest<'a>) -> BoxFuture<'a, Result<Lease, AuthDenied>> {
        Box::pin(async { Err(AuthDenied::Denied) })
    }
}
