//! Data-path Lease lifecycle (expiration, instant revocation, composable [`TrafficGate`] hook,
//! session-scoped RAII [`SessionGuard`] permits, and live [`AuthExtensions`]) plus sharded
//! sub-millisecond revocation tracking. Traffic-shaping algorithms stay cleanly outside
//! `confluence-core`.

use parking_lot::Mutex;
use std::{
    any::{Any, TypeId},
    collections::HashMap,
    fmt,
    hash::{DefaultHasher, Hash, Hasher},
    sync::{
        Arc, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::watch;

use crate::{CoreErr, Plane, PublicKey};

/// Default upper bound for any single Lease lifetime (`1 hour`).
pub const MAX_LEASE_TTL: Duration = Duration::from_secs(3600);

/// Hard protocol ceiling for wire-encoded lease lifetimes (`24 hours`).
pub const MAX_WIRE_LEASE_TTL: Duration = Duration::from_secs(86_400);

/// Traffic direction relative to the verifying node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Traffic flowing from the originator toward the destination.
    Ingress,
    /// Traffic flowing from the destination back toward the originator.
    Egress,
}

/// Per-packet decision returned by [`TrafficGate::check_datagram`] on `DATA` frames.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DatagramAction {
    /// Forward or deliver the datagram normally.
    Allow,
    /// Drop this datagram silently without closing the session or circuit.
    Drop,
    /// Immediately terminate the session or circuit with this error.
    Close(CoreErr),
}

/// Per-chunk decision returned by [`TrafficGate::charge_stream`] on `DATA` chunks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamAction {
    /// Forward or deliver the chunk immediately.
    Allow,
    /// Pace this chunk by `Duration` before forwarding or delivering it.
    Delay(Duration),
    /// Immediately terminate the session or circuit with this error.
    Close(CoreErr),
}

/// Algorithm-agnostic out-of-core data-plane policy hook attached to a [`Lease`].
///
/// Core invokes this strictly on `DATA` frames—never on `SETUP`, `RENEW`, `CLOSE`, `MTU_HINT`,
/// or `MTU_PROBE`—and strictly *after* per-circuit demultiplexing. This keeps QoS algorithms
/// (token buckets, quotas, aggregate per-peer shapers) completely outside `confluence-core`
/// while preserving per-circuit isolation over shared `DatagramLink`s, control-frame immunity,
/// live updates on renewal, and host sovereignty under [`crate::IntersectAuthorizer`].
pub trait TrafficGate: Send + Sync + 'static {
    /// Evaluates one `DATA` datagram of `bytes` moving in `dir`.
    fn check_datagram(&self, dir: Direction, bytes: usize) -> DatagramAction {
        let _ = (dir, bytes);
        DatagramAction::Allow
    }

    /// Charges one `DATA` stream chunk of exact size `bytes` moving in `dir`.
    fn charge_stream(&self, dir: Direction, bytes: usize) -> StreamAction {
        let _ = (dir, bytes);
        StreamAction::Allow
    }
}

struct IntersectGate {
    local: Arc<dyn TrafficGate>,
    external: Arc<dyn TrafficGate>,
}

impl TrafficGate for IntersectGate {
    fn check_datagram(&self, dir: Direction, bytes: usize) -> DatagramAction {
        match self.local.check_datagram(dir, bytes) {
            DatagramAction::Allow => self.external.check_datagram(dir, bytes),
            reject => reject,
        }
    }

    fn charge_stream(&self, dir: Direction, bytes: usize) -> StreamAction {
        let local = self.local.charge_stream(dir, bytes);
        if matches!(local, StreamAction::Close(_)) {
            return local;
        }
        let external = self.external.charge_stream(dir, bytes);
        match (local, external) {
            (_, StreamAction::Close(err)) | (StreamAction::Close(err), _) => {
                StreamAction::Close(err)
            }
            (StreamAction::Delay(a), StreamAction::Delay(b)) => StreamAction::Delay(a.max(b)),
            (StreamAction::Delay(d), StreamAction::Allow)
            | (StreamAction::Allow, StreamAction::Delay(d)) => StreamAction::Delay(d),
            (StreamAction::Allow, StreamAction::Allow) => StreamAction::Allow,
        }
    }
}

/// Opaque verified claim value stored inside [`AuthExtensions`].
pub type AuthContext = Arc<dyn Any + Send + Sync>;

/// Opaque session-scoped RAII permit (e.g., a concurrency slot) attached to a [`Lease`].
///
/// Permits acquired on initial setup (`is_renewal == false`) stay alive inside [`LeaseHandle`]
/// across in-band renewals and drop automatically when the session or circuit terminates.
pub type SessionGuard = Arc<dyn Any + Send + Sync>;

/// Type-keyed bag of verified claims attached to a [`Lease`] and surfaced live via [`SessionAuth`].
///
/// Unlike a single untyped slot, `AuthExtensions` lets composed authorizers
/// ([`crate::IntersectAuthorizer`]) each attach their own typed claims without overwriting one
/// another, with local-host precedence on same-type collisions.
#[derive(Clone, Default)]
pub struct AuthExtensions {
    entries: HashMap<TypeId, AuthContext>,
}

impl AuthExtensions {
    /// Creates an empty claims bag.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a typed claim value, replacing any previous entry of the same concrete type `T`.
    pub fn insert<T: Send + Sync + 'static>(&mut self, value: T) {
        self.entries.insert(TypeId::of::<T>(), Arc::new(value));
    }

    /// Inserts an already-shared typed claim value.
    pub fn insert_arc<T: Send + Sync + 'static>(&mut self, value: Arc<T>) {
        self.entries.insert(TypeId::of::<T>(), value);
    }

    /// Retrieves a verified claim of concrete type `T`, if present.
    pub fn get<T: Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.entries
            .get(&TypeId::of::<T>())?
            .clone()
            .downcast::<T>()
            .ok()
    }

    /// Returns `true` if no claims are attached.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of distinct typed claims attached.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Merges `other` into `self`, preserving `self`'s entries on same-type collisions so local
    /// host claims cannot be overwritten by an external authorizer.
    pub fn merge_prefer_self(mut self, other: Self) -> Self {
        for (ty, val) in other.entries {
            self.entries.entry(ty).or_insert(val);
        }
        self
    }
}

impl fmt::Debug for AuthExtensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthExtensions")
            .field("len", &self.entries.len())
            .finish()
    }
}

/// Verified session identity + live watchable claims handed to Endpoint and Transit handlers.
///
/// When an active session performs in-band lease renewal (`is_renewal: true`), Core publishes the
/// newly returned [`AuthExtensions`] so [`Self::context`] immediately reflects updated roles,
/// tenants, or permissions and [`Self::changed`] wakes listeners.
#[derive(Clone)]
pub struct SessionAuth {
    /// Cryptographically verified static public key of the calling peer.
    pub peer: PublicKey,
    extensions: watch::Receiver<Arc<AuthExtensions>>,
}

impl SessionAuth {
    /// Creates a static authenticated peer identity with empty claims.
    pub fn new(peer: PublicKey) -> Self {
        Self::from_extensions(peer, AuthExtensions::default())
    }

    /// Creates a static authenticated peer identity carrying `extensions`.
    pub fn from_extensions(peer: PublicKey, extensions: AuthExtensions) -> Self {
        let (_, rx) = watch::channel(Arc::new(extensions));
        Self {
            peer,
            extensions: rx,
        }
    }

    pub(crate) fn live(peer: PublicKey, extensions: watch::Receiver<Arc<AuthExtensions>>) -> Self {
        Self { peer, extensions }
    }

    /// Reads the latest verified claim of type `T` (automatically reflecting in-band renewals).
    pub fn context<T: Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.extensions.borrow().get::<T>()
    }

    /// Alias for [`Self::context`].
    pub fn context_as<T: Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.context::<T>()
    }

    /// Returns a snapshot of the latest [`AuthExtensions`].
    pub fn extensions(&self) -> Arc<AuthExtensions> {
        self.extensions.borrow().clone()
    }

    /// Waits until an in-band renewal publishes updated claims, returning `Err(CoreErr::Closed)`
    /// once the underlying session terminates.
    pub async fn changed(&mut self) -> Result<(), CoreErr> {
        self.extensions.changed().await.map_err(|_| CoreErr::Closed)
    }
}

impl fmt::Debug for SessionAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionAuth")
            .field("peer", &self.peer)
            .field("claims", &self.extensions.borrow().len())
            .finish()
    }
}

/// Time-bounded authorization returned by [`crate::Authorizer`] on control events.
///
/// * `ttl` — enforced by Core (`LeaseHandle`) with instant revocation and in-band renewal.
/// * `gate` — optional out-of-core [`TrafficGate`] invoked by Core strictly on `DATA` frames and
///   swapped live on renewal.
/// * `guards` — optional session-scoped RAII permits (e.g., concurrency slots) held across
///   renewals and dropped when the session or circuit closes.
/// * `extensions` — typed claims surfaced live to Endpoint/Transit handlers via [`SessionAuth`].
#[derive(Clone)]
pub struct Lease {
    /// Time until this lease expires unless renewed in-band.
    pub ttl: Duration,
    /// Optional out-of-core data-plane [`TrafficGate`] enforced strictly on `DATA` frames.
    pub gate: Option<Arc<dyn TrafficGate>>,
    /// Session-scoped RAII permits held until the session or circuit closes.
    pub guards: Vec<SessionGuard>,
    /// Typed verified claims forwarded live to the Endpoint or Transit handler.
    pub extensions: AuthExtensions,
}

impl fmt::Debug for Lease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lease")
            .field("ttl", &self.ttl)
            .field("has_gate", &self.gate.is_some())
            .field("guards", &self.guards.len())
            .field("claims", &self.extensions.len())
            .finish()
    }
}

impl Lease {
    /// Creates a lease valid for `ttl` with no traffic gate, guards, or claims.
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            gate: None,
            guards: Vec::new(),
            extensions: AuthExtensions::new(),
        }
    }

    /// Attaches a per-circuit or shared out-of-core [`TrafficGate`].
    ///
    /// If a gate is already attached, composes both with fail-closed intersection.
    pub fn with_gate<G: TrafficGate>(self, gate: G) -> Self {
        self.with_arc_gate(Arc::new(gate))
    }

    /// Attaches an already-shared [`TrafficGate`] (useful for per-peer or per-target aggregate limits).
    pub fn with_arc_gate(mut self, gate: Arc<dyn TrafficGate>) -> Self {
        self.gate = Some(match self.gate.take() {
            Some(existing) => Arc::new(IntersectGate {
                local: existing,
                external: gate,
            }),
            None => gate,
        });
        self
    }

    /// Attaches a session-scoped RAII guard (e.g., a concurrency slot) dropped on session close.
    pub fn with_guard<G: Send + Sync + 'static>(self, guard: G) -> Self {
        self.with_arc_guard(Arc::new(guard))
    }

    /// Attaches an already-erased [`SessionGuard`].
    pub fn with_arc_guard(mut self, guard: SessionGuard) -> Self {
        self.guards.push(guard);
        self
    }

    /// Attaches a typed verified claim forwarded live via [`SessionAuth::context`].
    pub fn with_context<T: Send + Sync + 'static>(mut self, ctx: T) -> Self {
        self.extensions.insert(ctx);
        self
    }

    /// Attaches an already-shared typed verified claim forwarded live via [`SessionAuth::context`].
    pub fn with_arc_context<T: Send + Sync + 'static>(mut self, ctx: Arc<T>) -> Self {
        self.extensions.insert_arc(ctx);
        self
    }

    /// Retrieves an attached claim of concrete type `T`, if present.
    pub fn context<T: Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.extensions.get::<T>()
    }

    /// Alias for [`Self::context`].
    pub fn context_as<T: Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.context::<T>()
    }

    /// Computes the host-sovereign intersection of two leases (`local.intersect(external)`):
    /// - Takes the shorter `ttl`.
    /// - Composes both [`TrafficGate`]s so neither can loosen the other's limits.
    /// - Keeps all session-scoped RAII `guards` from both authorizers.
    /// - Merges [`AuthExtensions`] from both authorizers, preserving `self` on same-type collisions.
    pub fn intersect(self, other: Self) -> Self {
        let gate = match (self.gate, other.gate) {
            (Some(local), Some(external)) => {
                Some(Arc::new(IntersectGate { local, external }) as Arc<dyn TrafficGate>)
            }
            (Some(g), None) | (None, Some(g)) => Some(g),
            (None, None) => None,
        };
        let mut guards = self.guards;
        guards.extend(other.guards);
        Self {
            ttl: self.ttl.min(other.ttl),
            gate,
            guards,
            extensions: self.extensions.merge_prefer_self(other.extensions),
        }
    }

    pub(crate) fn validate_with_max_ttl(self, max_ttl: Duration) -> Result<Self, CoreErr> {
        if self.ttl.as_millis() == 0 || self.ttl > max_ttl {
            return Err(CoreErr::Denied);
        }
        Ok(self)
    }

    pub(crate) fn wire_ttl_bytes(ttl: Duration) -> [u8; 8] {
        crate::wire::e2e::lease_bytes(ttl.as_millis() as u64)
    }

    pub(crate) fn from_wire_ttl(buf: &[u8]) -> Result<Duration, CoreErr> {
        let ttl_ms = crate::wire::e2e::parse_lease(buf)?;
        let ttl = Duration::from_millis(ttl_ms);
        if ttl.as_millis() == 0 || ttl > MAX_WIRE_LEASE_TTL {
            return Err(CoreErr::Denied);
        }
        Ok(ttl)
    }
}

fn clock_ns() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

/// Per-task hot-path cache of a [`LeaseHandle`]'s active [`TrafficGate`].
///
/// Between in-band renewals, checking for gate updates costs a single `AtomicU64` load with
/// zero mutex acquisitions and zero `Arc` reference-count traffic.
pub(crate) struct GateCache {
    seen_gen: u64,
    gate: Option<Arc<dyn TrafficGate>>,
}

impl GateCache {
    pub fn new(lease: &LeaseHandle) -> Self {
        let guard = lease.gate.lock();
        let seen_gen = lease.gate_gen.load(Ordering::Acquire);
        let gate = guard.clone();
        Self { seen_gen, gate }
    }

    #[inline]
    pub fn current(&mut self, lease: &LeaseHandle) -> Option<&Arc<dyn TrafficGate>> {
        let epoch = lease.gate_gen.load(Ordering::Acquire);
        if epoch != self.seen_gen {
            let guard = lease.gate.lock();
            self.seen_gen = lease.gate_gen.load(Ordering::Acquire);
            self.gate = guard.clone();
        }
        self.gate.as_ref()
    }
}

/// Lock-free lease lifetime, revocation, live [`TrafficGate`], RAII [`SessionGuard`]s, and
/// watchable [`AuthExtensions`] handle enforced on active E2E sessions and transit circuits.
#[repr(align(64))]
pub struct LeaseHandle {
    expires_at: AtomicU64,
    granted_ttl_ms: AtomicU64,
    revoked: AtomicBool,
    gate_gen: AtomicU64,
    changes: watch::Sender<Option<CoreErr>>,
    gate: Mutex<Option<Arc<dyn TrafficGate>>>,
    extensions: watch::Sender<Arc<AuthExtensions>>,
    guards: Mutex<Vec<SessionGuard>>,
}

impl LeaseHandle {
    /// Creates a live lease handle initialized with `ttl` (bounded by [`MAX_LEASE_TTL`]).
    pub fn new(ttl: Duration) -> Result<Self, CoreErr> {
        Self::new_with_max_ttl(ttl, MAX_LEASE_TTL)
    }

    /// Creates a live lease handle allowing lifetimes up to `max_ttl`.
    pub fn new_with_max_ttl(ttl: Duration, max_ttl: Duration) -> Result<Self, CoreErr> {
        Self::from_lease_with_max_ttl(Lease::new(ttl), max_ttl)
    }

    /// Creates a live lease handle from a full [`Lease`] (TTL, gate, RAII guards, and claims).
    pub fn from_lease_with_max_ttl(lease: Lease, max_ttl: Duration) -> Result<Self, CoreErr> {
        if lease.ttl.as_millis() == 0 || lease.ttl > max_ttl {
            return Err(CoreErr::Denied);
        }
        Ok(Self {
            expires_at: AtomicU64::new(clock_ns().saturating_add(lease.ttl.as_nanos() as u64)),
            granted_ttl_ms: AtomicU64::new(lease.ttl.as_millis() as u64),
            revoked: false.into(),
            gate_gen: AtomicU64::new(0),
            changes: watch::channel(None).0,
            gate: Mutex::new(lease.gate),
            extensions: watch::channel(Arc::new(lease.extensions)).0,
            guards: Mutex::new(lease.guards),
        })
    }

    /// Encodes the most recently granted `ttl_ms` for wire acknowledgments and hop trailers.
    pub(crate) fn wire_lease(&self) -> [u8; 8] {
        crate::wire::e2e::lease_bytes(self.granted_ttl_ms.load(Ordering::Acquire))
    }

    /// Creates a live [`SessionAuth`] subscribed to this lease's [`AuthExtensions`].
    pub fn session_auth(&self, peer: PublicKey) -> SessionAuth {
        SessionAuth::live(peer, self.extensions.subscribe())
    }

    /// Creates a lock-free per-task cache for reading this lease's active [`TrafficGate`].
    pub(crate) fn gate_cache(&self) -> GateCache {
        GateCache::new(self)
    }

    /// Extends this lease's TTL in place without modifying its gate, guards, or claims.
    pub fn renew_with_max_ttl(&self, ttl: Duration, max_ttl: Duration) -> Result<(), CoreErr> {
        if ttl.as_millis() == 0 || ttl > max_ttl {
            return Err(CoreErr::Denied);
        }
        self.remaining()?;
        self.granted_ttl_ms
            .store(ttl.as_millis() as u64, Ordering::Release);
        self.expires_at.store(
            clock_ns().saturating_add(ttl.as_nanos() as u64),
            Ordering::Release,
        );
        self.changes.send_modify(|_| {});
        Ok(())
    }

    /// Applies an in-band renewed [`Lease`] in place without pausing traffic:
    /// - Extends `ttl`
    /// - Swaps the active [`TrafficGate`] so updated QoS takes effect immediately
    /// - Publishes updated [`AuthExtensions`] to live [`SessionAuth`] holders
    /// - Preserves initial session-scoped RAII `guards` (appending any new guards)
    pub fn renew_lease_with_max_ttl(&self, lease: Lease, max_ttl: Duration) -> Result<(), CoreErr> {
        if lease.ttl.as_millis() == 0 || lease.ttl > max_ttl {
            return Err(CoreErr::Denied);
        }
        self.remaining()?;
        {
            let mut slot = self.gate.lock();
            *slot = lease.gate;
            self.gate_gen.fetch_add(1, Ordering::Release);
        }
        if !lease.guards.is_empty() {
            self.guards.lock().extend(lease.guards);
        }
        self.extensions.send_replace(Arc::new(lease.extensions));
        self.granted_ttl_ms
            .store(lease.ttl.as_millis() as u64, Ordering::Release);
        self.expires_at.store(
            clock_ns().saturating_add(lease.ttl.as_nanos() as u64),
            Ordering::Release,
        );
        self.changes.send_modify(|_| {});
        Ok(())
    }

    /// Immediately revokes this lease and wakes all active waiters.
    pub fn revoke(&self, reason: CoreErr) {
        if !self.revoked.swap(true, Ordering::AcqRel) {
            self.changes.send_replace(Some(reason));
        }
    }

    /// Returns the remaining lifetime of this lease, or an error if expired/revoked.
    pub fn remaining(&self) -> Result<Duration, CoreErr> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(self.changes.borrow().clone().unwrap_or(CoreErr::Revoked));
        }
        self.expires_at
            .load(Ordering::Acquire)
            .checked_sub(clock_ns())
            .filter(|time| *time > 0)
            .map(Duration::from_nanos)
            .ok_or(CoreErr::Expired)
    }

    /// Lock-free hot-path liveness check (`true` while neither revoked nor expired).
    #[inline]
    pub fn is_active(&self) -> bool {
        !self.revoked.load(Ordering::Acquire)
            && self.expires_at.load(Ordering::Acquire) > clock_ns()
    }

    /// Resolves with the terminal error as soon as this lease expires or is revoked.
    pub async fn cancelled(&self) -> CoreErr {
        let mut changes = self.changes.subscribe();
        loop {
            match self.remaining() {
                Err(error) => return error,
                Ok(remaining) => {
                    let _ = tokio::time::timeout(remaining, changes.changed()).await;
                }
            }
        }
    }
}

/// Key indexing live [`LeaseHandle`] instances for immediate revocation fan-out.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum RevocationKey {
    Peer(PublicKey),
    Endpoint(String),
    Transit(Plane, String),
}

type Shard = Mutex<HashMap<RevocationKey, Vec<Weak<LeaseHandle>>>>;

/// 16-way sharded weak-pointer registry for sub-millisecond cancellation without per-session tasks.
#[derive(Default)]
pub struct RevocationIndex {
    shards: [Shard; 16],
}

impl RevocationIndex {
    fn shard(&self, key: &RevocationKey) -> &Shard {
        let mut hash = DefaultHasher::new();
        key.hash(&mut hash);
        &self.shards[hash.finish() as usize % self.shards.len()]
    }

    pub fn track(&self, key: RevocationKey, lease: &Arc<LeaseHandle>) {
        let mut shard = self.shard(&key).lock();
        if !shard.contains_key(&key) && shard.len() >= 128 {
            shard.retain(|_, leases| {
                leases.retain(|lease| lease.strong_count() != 0);
                !leases.is_empty()
            });
        }
        let leases = shard.entry(key).or_default();
        leases.retain(|lease| lease.strong_count() != 0);
        leases.push(Arc::downgrade(lease));
    }

    pub fn revoke(&self, key: &RevocationKey, reason: CoreErr) {
        let leases = self.shard(key).lock().remove(key).unwrap_or_default();
        for lease in leases.into_iter().filter_map(|lease| lease.upgrade()) {
            lease.revoke(reason.clone());
        }
    }

    pub(crate) fn invalidate(&self) {
        for shard in &self.shards {
            let leases = std::mem::take(&mut *shard.lock());
            for lease in leases
                .into_values()
                .flatten()
                .filter_map(|lease| lease.upgrade())
            {
                lease.revoke(CoreErr::Revoked);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct FixedGate {
        dg: DatagramAction,
        st: StreamAction,
    }

    impl TrafficGate for FixedGate {
        fn check_datagram(&self, _dir: Direction, _bytes: usize) -> DatagramAction {
            self.dg.clone()
        }

        fn charge_stream(&self, _dir: Direction, _bytes: usize) -> StreamAction {
            self.st.clone()
        }
    }

    struct DropCounter(Arc<AtomicUsize>);
    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn lease_intersect_preserves_host_sovereignty_across_ttl_gates_guards_and_claims() {
        let drops = Arc::new(AtomicUsize::new(0));
        let local = Lease::new(Duration::from_secs(20))
            .with_context("local-tag")
            .with_context(10u32)
            .with_guard(DropCounter(drops.clone()))
            .with_gate(FixedGate {
                dg: DatagramAction::Drop,
                st: StreamAction::Delay(Duration::from_millis(50)),
            });
        let external = Lease::new(Duration::from_secs(60))
            .with_context(99u32)
            .with_context(true)
            .with_guard(DropCounter(drops.clone()))
            .with_gate(FixedGate {
                dg: DatagramAction::Allow,
                st: StreamAction::Delay(Duration::from_millis(10)),
            });

        let merged = local.intersect(external);
        assert_eq!(merged.ttl, Duration::from_secs(20));
        // Distinct types from both authorizers coexist; same-type collision prefers local.
        assert_eq!(
            merged.context::<&'static str>().as_deref(),
            Some(&"local-tag")
        );
        assert_eq!(merged.context::<u32>().as_deref(), Some(&10u32));
        assert_eq!(merged.context::<bool>().as_deref(), Some(&true));
        // Gate intersection takes local drop and stricter (max) delay.
        let gate = merged.gate.as_ref().unwrap();
        assert_eq!(
            gate.check_datagram(Direction::Ingress, 64),
            DatagramAction::Drop
        );
        assert_eq!(
            gate.charge_stream(Direction::Ingress, 64),
            StreamAction::Delay(Duration::from_millis(50))
        );
        // Both guards live until the merged lease drops.
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        drop(merged);
        assert_eq!(drops.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn lease_handle_renewal_swaps_gate_and_claims_while_preserving_guards() {
        let drops = Arc::new(AtomicUsize::new(0));
        let initial = Lease::new(Duration::from_secs(10))
            .with_context("role=admin")
            .with_guard(DropCounter(drops.clone()))
            .with_gate(FixedGate {
                dg: DatagramAction::Allow,
                st: StreamAction::Allow,
            });
        let handle = LeaseHandle::from_lease_with_max_ttl(initial, MAX_LEASE_TTL).unwrap();
        let mut auth = handle.session_auth(PublicKey([7; 32]));
        let mut cache = handle.gate_cache();

        assert_eq!(
            auth.context::<&'static str>().as_deref(),
            Some(&"role=admin")
        );
        assert_eq!(
            cache
                .current(&handle)
                .unwrap()
                .check_datagram(Direction::Ingress, 100),
            DatagramAction::Allow
        );

        let renewed = Lease::new(Duration::from_secs(30))
            .with_context("role=viewer")
            .with_gate(FixedGate {
                dg: DatagramAction::Drop,
                st: StreamAction::Delay(Duration::from_millis(25)),
            });
        handle
            .renew_lease_with_max_ttl(renewed, MAX_LEASE_TTL)
            .unwrap();

        // Initial session guard MUST survive renewal.
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        // Live SessionAuth sees updated claims and wakes changed().
        auth.changed().await.unwrap();
        assert_eq!(
            auth.context::<&'static str>().as_deref(),
            Some(&"role=viewer")
        );
        // GateCache picks up swapped gate immediately.
        assert_eq!(
            cache
                .current(&handle)
                .unwrap()
                .check_datagram(Direction::Ingress, 100),
            DatagramAction::Drop
        );

        drop(handle);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn lease_handle_is_active_until_revoked() {
        let lease = LeaseHandle::new(Duration::from_secs(30)).unwrap();
        assert!(lease.is_active());
        lease.revoke(CoreErr::Revoked);
        assert!(!lease.is_active());
        assert_eq!(lease.remaining(), Err(CoreErr::Revoked));
    }
}
