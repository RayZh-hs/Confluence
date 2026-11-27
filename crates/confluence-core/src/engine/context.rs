//! Shared scope execution context, limits, permit RAII guards, revocation listener, and
//! runtime-independent async combinators (Layer 4 foundation; zero imports from `host` or peer engines).

use core::future::{Future, poll_fn};
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

use futures_util::stream::{FuturesUnordered, StreamExt};

use crate::constants::{
    DEFAULT_MAX_DATAGRAM_PORTS, DEFAULT_SCOPE_MAX_PENDING, DEFAULT_SCOPE_MAX_SESSIONS,
};
use crate::crypto::cookie::CookieProtector;
use crate::crypto::identity::ScopeKeypair;
use crate::crypto::replay::SetupReplay;
use crate::error::CoreError;
use crate::runtime::sync::{CloseableSemaphore, SemaphorePermit, Watch, WatchReceiver};
use crate::runtime::{Clock, MonotonicTime, Runtime};
use crate::seam::auth::{
    Authorizer, CredentialProvider, Revocation, RevocationReceiver, RevocationRecvError,
};
use crate::seam::path::PathSource;
use crate::stats::{NodeMetrics, ScopeMetrics, should_warn_pow2};
use crate::trust::gate::{AuthGate, AuthLimits};
use crate::trust::registry::PublishRegistry;
use crate::types::{Plane, Role, ScopeKid};

// ---------------------------------------------------------------------------
// ScopeLimits
// ---------------------------------------------------------------------------

/// Clamped admission, active session, and datagram port capacity limits for a `ScopeInstance` (Spec §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeLimits {
    /// Maximum concurrent in-flight inbound setups (default `256`, min `1`).
    pub max_pending: usize,
    /// Maximum concurrent active sessions and transit circuits (default `4096`, min `1`).
    pub max_sessions: usize,
    /// Maximum attached standalone `DatagramPort` links (default `4096`, min `1`).
    pub max_datagram_ports: usize,
}

impl Default for ScopeLimits {
    fn default() -> Self {
        Self {
            max_pending: DEFAULT_SCOPE_MAX_PENDING,
            max_sessions: DEFAULT_SCOPE_MAX_SESSIONS,
            max_datagram_ports: DEFAULT_MAX_DATAGRAM_PORTS,
        }
    }
}

impl ScopeLimits {
    /// Returns a copy of these limits clamped to normative minimum bounds (`>= 1`).
    #[must_use]
    pub fn clamped(self) -> Self {
        Self {
            max_pending: self.max_pending.max(1),
            max_sessions: self.max_sessions.max(1),
            max_datagram_ports: self.max_datagram_ports.max(1),
        }
    }
}

// ---------------------------------------------------------------------------
// RAII Permit Guards
// ---------------------------------------------------------------------------

/// RAII guard for one scope-level pending setup permit.
pub(crate) struct PendingPermit {
    scope: Arc<ScopeCore>,
    _permit: SemaphorePermit,
}

impl Drop for PendingPermit {
    fn drop(&mut self) {
        self.scope
            .metrics
            .pending_setups
            .fetch_sub(1, Ordering::Relaxed);
        // Drop inner permit first? No, field drops happen after Drop::drop, so compute
        // post-release `used = in_use.saturating_sub(1)` for accurate hysteresis update.
        let used = self.scope.pending.in_use().saturating_sub(1);
        let active = self.scope.cookies.update_load(
            used,
            self.scope.limits.max_pending,
            self.scope.runtime.clock.now(),
        );
        self.scope.metrics.under_load.store(active, Ordering::Release);
    }
}

/// Shared node-level pending admission semaphore and metrics handle.
pub(crate) struct NodePendingGate {
    sem: Arc<CloseableSemaphore>,
    metrics: Arc<NodeMetrics>,
}

impl NodePendingGate {
    pub fn new(max_pending: usize, metrics: Arc<NodeMetrics>) -> Arc<Self> {
        Arc::new(Self {
            sem: CloseableSemaphore::new(max_pending.max(1)),
            metrics,
        })
    }

    pub fn close(&self) {
        self.sem.close();
        self.metrics.accepting.store(false, Ordering::Release);
    }

    pub fn is_closed(&self) -> bool {
        self.sem.is_closed()
    }

    pub fn try_acquire(self: &Arc<Self>) -> Result<NodePendingPermit, CoreError> {
        match self.sem.try_acquire() {
            Ok(permit) => {
                self.metrics.pending_setups.fetch_add(1, Ordering::Relaxed);
                Ok(NodePendingPermit {
                    gate: Arc::clone(self),
                    _permit: permit,
                })
            }
            Err(CoreError::Busy) => {
                let count = self
                    .metrics
                    .capacity_drops_total
                    .fetch_add(1, Ordering::Relaxed)
                    .saturating_add(1);
                if should_warn_pow2(count) {
                    tracing::warn!(
                        count,
                        error = CoreError::Busy.static_code(),
                        "node pending setup capacity saturated"
                    );
                }
                Err(CoreError::Busy)
            }
            Err(err) => Err(err),
        }
    }
}

/// RAII guard for one node-level pending setup permit.
pub(crate) struct NodePendingPermit {
    gate: Arc<NodePendingGate>,
    _permit: SemaphorePermit,
}

impl Drop for NodePendingPermit {
    fn drop(&mut self) {
        self.gate
            .metrics
            .pending_setups
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// RAII guard for one active session or transit circuit permit.
pub(crate) struct SessionPermit {
    scope: Arc<ScopeCore>,
    plane: Plane,
    role: Role,
    started_at: MonotonicTime,
    _permit: SemaphorePermit,
}

impl Drop for SessionPermit {
    fn drop(&mut self) {
        let elapsed_ms = u64::try_from(
            self.scope
                .runtime
                .clock
                .now()
                .saturating_duration_since(self.started_at)
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        self.scope
            .metrics
            .dec_active_session(self.plane, self.role, elapsed_ms);
    }
}

/// RAII guard tracking an active Destination Stream application bridge task for `is_drained()`.
pub(crate) struct BridgeGuard {
    scope: Arc<ScopeCore>,
}

impl BridgeGuard {
    pub fn acquire(scope: Arc<ScopeCore>) -> Self {
        scope.stream_bridges.fetch_add(1, Ordering::AcqRel);
        Self { scope }
    }
}

impl Drop for BridgeGuard {
    fn drop(&mut self) {
        self.scope.stream_bridges.fetch_sub(1, Ordering::AcqRel);
    }
}

// ---------------------------------------------------------------------------
// ScopeCore & ScopeResolver
// ---------------------------------------------------------------------------

/// Shared immutable/atomic execution core of a `ScopeInstance`.
pub(crate) struct ScopeCore {
    pub keypair: ScopeKeypair,
    pub runtime: Runtime,
    pub limits: ScopeLimits,
    pub auth_limits: AuthLimits,
    pub metrics: Arc<ScopeMetrics>,
    pub registry: Arc<PublishRegistry>,
    pub auth_gate: Arc<AuthGate>,
    pub credentials: Arc<dyn CredentialProvider>,
    pub path_source: Arc<dyn PathSource>,
    pub replay: Arc<SetupReplay>,
    pub cookies: Arc<CookieProtector>,
    pub pending: Arc<CloseableSemaphore>,
    pub sessions: Arc<CloseableSemaphore>,
    pub shutdown_tx: Watch<bool>,
    pub stream_bridges: AtomicUsize,
    pub mounted: AtomicBool,
    pub span: tracing::Span,
    /// Dropped automatically when the final `Arc<ScopeCore>` drops, waking background tasks cleanly.
    alive_tx: Watch<()>,
}

impl ScopeCore {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        keypair: ScopeKeypair,
        runtime: Runtime,
        limits: ScopeLimits,
        auth_limits: AuthLimits,
        cookie_rotation: Duration,
        authorizer: Arc<dyn Authorizer>,
        credentials: Arc<dyn CredentialProvider>,
        path_source: Arc<dyn PathSource>,
    ) -> Arc<Self> {
        let limits = limits.clamped();
        let auth_limits = auth_limits.clamped();
        let now = runtime.clock.now();
        let metrics = Arc::new(ScopeMetrics::new());
        let registry = Arc::new(PublishRegistry::new(Arc::clone(&metrics)));
        let auth_gate = Arc::new(AuthGate::new(
            Arc::clone(&authorizer),
            auth_limits,
            Arc::clone(&runtime.clock),
            Arc::clone(&registry),
            Arc::clone(&metrics),
        ));
        let replay = Arc::new(SetupReplay::new(now));
        let cookies = Arc::new(CookieProtector::with_rotation_interval(
            keypair.clone(),
            cookie_rotation,
            now,
        ));
        let pending = CloseableSemaphore::new(limits.max_pending);
        let sessions = CloseableSemaphore::new(limits.max_sessions);
        let (shutdown_tx, _shutdown_rx) = Watch::new(false);
        let (alive_tx, alive_rx) = Watch::new(());
        let span = tracing::info_span!("scope", kid = %keypair.scope_kid());

        let core = Arc::new(Self {
            keypair,
            runtime,
            limits,
            auth_limits,
            metrics,
            registry,
            auth_gate,
            credentials,
            path_source,
            replay,
            cookies,
            pending,
            sessions,
            shutdown_tx,
            stream_bridges: AtomicUsize::new(0),
            mounted: AtomicBool::new(false),
            span,
            alive_tx,
        });

        let rev_streams = authorizer.revocation_streams();
        if !rev_streams.is_empty() {
            spawn_revocation_listener(&core, rev_streams, alive_rx);
        }

        core
    }

    /// Updates automatic `under_load` hysteresis from current pending saturation and syncs metrics.
    pub fn update_load(&self) -> bool {
        let used = self.pending.in_use();
        let active = self
            .cookies
            .update_load(used, self.limits.max_pending, self.runtime.clock.now());
        self.metrics.under_load.store(active, Ordering::Release);
        active
    }

    /// Sets or clears (`None`) a manual `under_load` override and syncs metrics.
    pub fn set_under_load(&self, override_load: Option<bool>) {
        let active = self.cookies.set_under_load(override_load);
        self.metrics.under_load.store(active, Ordering::Release);
    }

    /// Acquires one pending setup permit non-blocking, updating load and capacity metrics.
    pub fn try_acquire_pending(self: &Arc<Self>) -> Result<PendingPermit, CoreError> {
        match self.pending.try_acquire() {
            Ok(permit) => {
                self.metrics.pending_setups.fetch_add(1, Ordering::Relaxed);
                let _ = self.update_load();
                Ok(PendingPermit {
                    scope: Arc::clone(self),
                    _permit: permit,
                })
            }
            Err(CoreError::Busy) => {
                let _ = self.update_load();
                let count = self.metrics.record_capacity_drop();
                if should_warn_pow2(count) {
                    tracing::warn!(
                        parent: &self.span,
                        count,
                        error = CoreError::Busy.static_code(),
                        "scope pending setup capacity saturated"
                    );
                }
                Err(CoreError::Busy)
            }
            Err(err) => Err(err),
        }
    }

    /// Acquires one active session/circuit permit non-blocking, updating session metrics.
    pub fn try_acquire_session(
        self: &Arc<Self>,
        plane: Plane,
        role: Role,
    ) -> Result<SessionPermit, CoreError> {
        match self.sessions.try_acquire() {
            Ok(permit) => {
                self.metrics.inc_active_session(plane, role);
                Ok(SessionPermit {
                    scope: Arc::clone(self),
                    plane,
                    role,
                    started_at: self.runtime.clock.now(),
                    _permit: permit,
                })
            }
            Err(CoreError::Busy) => {
                let count = self.metrics.record_capacity_drop();
                if should_warn_pow2(count) {
                    tracing::warn!(
                        parent: &self.span,
                        plane = plane.as_str(),
                        role = role.as_str(),
                        count,
                        error = CoreError::Busy.static_code(),
                        "scope active session capacity saturated"
                    );
                }
                Err(CoreError::Busy)
            }
            Err(err) => Err(err),
        }
    }

    /// Subscribes to the scope's graceful shutdown signal.
    pub fn subscribe_shutdown(&self) -> WatchReceiver<bool> {
        self.shutdown_tx.subscribe()
    }

    /// Initiates graceful scope shutdown (Spec §6.8).
    pub fn begin_shutdown(&self) {
        self.pending.close();
        self.sessions.close();
        self.metrics.accepting.store(false, Ordering::Release);
        self.shutdown_tx.send(true);
    }

    /// Returns `true` once all pending setups, active sessions, and destination stream bridges finished.
    pub fn is_drained(&self) -> bool {
        self.pending.in_use() == 0
            && self.sessions.in_use() == 0
            && self.stream_bridges.load(Ordering::Acquire) == 0
    }

    /// Creates a child structured tracing span for a session or transit circuit.
    pub fn session_span(&self, plane: Plane, role: Role) -> tracing::Span {
        tracing::debug_span!(
            parent: &self.span,
            "session",
            plane = plane.as_str(),
            role = role.as_str()
        )
    }

    #[allow(dead_code)]
    pub fn subscribe_alive(&self) -> WatchReceiver<()> {
        self.alive_tx.subscribe()
    }
}

/// Resolves an inbound `ScopeKid` to its target [`ScopeCore`] in $O(1)$.
pub(crate) trait ScopeResolver: Send + Sync + 'static {
    fn resolve(&self, kid: ScopeKid) -> Option<Arc<ScopeCore>>;
    fn record_unknown_scope(&self);
    fn record_mac1_drop(&self, matched_scope: Option<&ScopeCore>);
}

/// Single-scope [`ScopeResolver`] matching strictly one [`ScopeCore`].
pub(crate) struct SingleScopeResolver {
    scope: Arc<ScopeCore>,
}

impl SingleScopeResolver {
    pub fn new(scope: Arc<ScopeCore>) -> Arc<Self> {
        Arc::new(Self { scope })
    }
}

impl ScopeResolver for SingleScopeResolver {
    fn resolve(&self, kid: ScopeKid) -> Option<Arc<ScopeCore>> {
        if kid.ct_eq(&self.scope.keypair.scope_kid()) {
            Some(Arc::clone(&self.scope))
        } else {
            None
        }
    }

    fn record_unknown_scope(&self) {
        self.scope
            .metrics
            .mac1_drops_total
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_mac1_drop(&self, _matched_scope: Option<&ScopeCore>) {
        self.scope
            .metrics
            .mac1_drops_total
            .fetch_add(1, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Background Revocation Listener Task (Spec §7.5)
// ---------------------------------------------------------------------------

async fn next_revocation(
    mut rx: RevocationReceiver,
) -> (Result<Revocation, RevocationRecvError>, RevocationReceiver) {
    let res = rx.recv().await;
    (res, rx)
}

fn spawn_revocation_listener(
    core: &Arc<ScopeCore>,
    streams: Vec<RevocationReceiver>,
    mut alive_rx: WatchReceiver<()>,
) {
    let weak: Weak<ScopeCore> = Arc::downgrade(core);
    let span = core.span.clone();
    core.runtime.spawner.spawn(Box::pin(async move {
        let mut pending = FuturesUnordered::new();
        for rx in streams {
            pending.push(next_revocation(rx));
        }

        while !pending.is_empty() {
            match race2(pending.next(), alive_rx.changed()).await {
                Either::Right(_) => {
                    // All strong references to ScopeCore dropped -> exit cleanly.
                    break;
                }
                Either::Left(None) => break,
                Either::Left(Some((res, rx))) => {
                    let Some(scope) = weak.upgrade() else {
                        break;
                    };
                    match res {
                        Ok(Revocation::Peer(peer)) => {
                            // Authorizer Revocation::Peer revokes active sessions WITHOUT adding to vetoed.
                            scope.registry.revoke_peer_sessions_only(peer);
                            pending.push(next_revocation(rx));
                        }
                        Ok(Revocation::Endpoint(name)) => {
                            // Authorizer Revocation::Endpoint revokes active sessions with Unpublished.
                            scope.registry.revoke_endpoint(&name);
                            pending.push(next_revocation(rx));
                        }
                        Ok(Revocation::Transit(name)) => {
                            // Revokes transit circuits across BOTH planes with Revoked.
                            scope.registry.revoke_transit(&name);
                            pending.push(next_revocation(rx));
                        }
                        Ok(Revocation::All) => {
                            scope.registry.revoke_all(false);
                            pending.push(next_revocation(rx));
                        }
                        Err(RevocationRecvError::Lagged(skipped)) => {
                            // Fail-closed: invalidate ALL active leases in the scope immediately!
                            tracing::warn!(
                                parent: &span,
                                skipped,
                                "revocation broadcast lagged; invalidating all active scope leases"
                            );
                            scope.registry.revoke_all(true);
                            pending.push(next_revocation(rx));
                        }
                        Err(RevocationRecvError::Closed) => {
                            // Stream ended; stop polling this receiver.
                        }
                    }
                }
            }
        }
    }));
}

// ---------------------------------------------------------------------------
// Zero-Dependency Runtime-Independent Async Combinators
// ---------------------------------------------------------------------------

/// Result of racing two futures via [`race2`].
pub(crate) enum Either<A, B> {
    Left(A),
    Right(B),
}

/// Races two futures concurrently without heap allocation, biasing slightly toward `a`.
pub(crate) async fn race2<A, B, FA, FB>(a: FA, b: FB) -> Either<A, B>
where
    FA: Future<Output = A>,
    FB: Future<Output = B>,
{
    let mut a = core::pin::pin!(a);
    let mut b = core::pin::pin!(b);
    poll_fn(|cx| {
        if let Poll::Ready(val) = a.as_mut().poll(cx) {
            return Poll::Ready(Either::Left(val));
        }
        if let Poll::Ready(val) = b.as_mut().poll(cx) {
            return Poll::Ready(Either::Right(val));
        }
        Poll::Pending
    })
    .await
}

/// Runs `fut` (returning `Result<T, CoreError>`) bounded by a monotonic `deadline`.
pub(crate) async fn with_deadline<F, T>(
    clock: &dyn Clock,
    deadline: MonotonicTime,
    fut: F,
) -> Result<T, CoreError>
where
    F: Future<Output = Result<T, CoreError>>,
{
    if clock.now() >= deadline {
        return Err(CoreError::Timeout);
    }
    match race2(fut, clock.sleep_until(deadline)).await {
        Either::Left(res) => res,
        Either::Right(()) => Err(CoreError::Timeout),
    }
}

/// Runs any future `fut` (returning `T`) bounded by a monotonic `deadline`.
pub(crate) async fn with_deadline_val<F, T>(
    clock: &dyn Clock,
    deadline: MonotonicTime,
    fut: F,
) -> Result<T, CoreError>
where
    F: Future<Output = T>,
{
    if clock.now() >= deadline {
        return Err(CoreError::Timeout);
    }
    match race2(fut, clock.sleep_until(deadline)).await {
        Either::Left(val) => Ok(val),
        Either::Right(()) => Err(CoreError::Timeout),
    }
}

/// Future that waits until a `WatchReceiver<bool>` becomes `true` (never resolving if sender drops while `false`).
pub(crate) async fn wait_shutdown(rx: &mut WatchReceiver<bool>) {
    loop {
        if rx.borrow_cloned() {
            return;
        }
        if !rx.changed().await {
            if rx.borrow_cloned() {
                return;
            }
            core::future::pending::<()>().await;
        }
    }
}

/// Future that waits until a `WatchReceiver<bool>` becomes `true` OR all senders drop.
pub(crate) async fn wait_signal(rx: &mut WatchReceiver<bool>) {
    loop {
        if rx.borrow_cloned() {
            return;
        }
        if !rx.changed().await {
            return;
        }
    }
}

/// Future that waits until a live `MtuWatch` drops strictly below `floor`, returning the violating MTU.
pub(crate) async fn wait_mtu_below_floor(
    watch: &mut crate::seam::channel::MtuWatch,
    floor: u16,
) -> u16 {
    let cur = watch.sample();
    if cur < floor {
        return cur;
    }
    loop {
        match watch.changed().await {
            Some(mtu) if mtu < floor => return mtu,
            Some(_) => {}
            None => core::future::pending::<()>().await,
        }
    }
}

/// Future that waits for the next live `MtuWatch` update, remaining pending forever once fixed/closed.
pub(crate) async fn wait_mtu_change(watch: &mut crate::seam::channel::MtuWatch) -> u16 {
    match watch.changed().await {
        Some(mtu) => mtu,
        None => core::future::pending::<u16>().await,
    }
}

/// Helper future that never resolves when `Option<MonotonicTime>` is `None`.
pub(crate) async fn sleep_optional(clock: &dyn Clock, deadline: Option<MonotonicTime>) {
    match deadline {
        Some(dl) => clock.sleep_until(dl).await,
        None => core::future::pending::<()>().await,
    }
}

/// Boxed future fetching a refreshed credential for one renewal slot.
pub(crate) type CredFetchFut = Pin<
    Box<
        dyn Future<
                Output = (
                    crate::protocol::renewal::RenewalSlot,
                    Result<crate::types::Credential, CoreError>,
                ),
            > + Send,
    >,
>;

/// Boxed future evaluating verifier-side renewal authorization for one `renewal_id`.
pub(crate) type RenewalAuthFut =
    Pin<Box<dyn Future<Output = (u64, Result<crate::seam::auth::Lease, CoreError>)> + Send>>;

/// Polls an optional pinned future if present, returning `Poll::Pending` when `None`.
pub(crate) fn poll_optional<T>(
    slot: &mut Option<Pin<Box<dyn Future<Output = T> + Send>>>,
    cx: &mut Context<'_>,
) -> Poll<T> {
    if let Some(fut) = slot.as_mut() {
        if let Poll::Ready(val) = fut.as_mut().poll(cx) {
            *slot = None;
            return Poll::Ready(val);
        }
    }
    Poll::Pending
}
