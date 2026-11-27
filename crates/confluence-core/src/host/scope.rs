//! Single Trust Scope host facade (`ScopeInstance`, `WeakScope`, `ScopeBuilder`).

use core::fmt;
use core::time::Duration;
use std::sync::{Arc, Weak};

use crate::constants::COOKIE_ROTATION_INTERVAL;
use crate::crypto::identity::ScopeKeypair;
use crate::engine::context::{ScopeCore, ScopeLimits, SingleScopeResolver};
use crate::engine::datagram::inbound::InboundDatagramDispatcher;
use crate::engine::datagram::port::{PortMetricOwner, PortRegistry, PortSlot};
use crate::engine::datagram::session::E2eDatagram;
use crate::engine::origin::{StagedDatagram, StagedStream, stage_datagram, stage_stream};
use crate::engine::stream::session::E2eStream;
use crate::engine::stream::spawn_inbound_stream;
use crate::error::CoreError;
use crate::protocol::setup::precheck_datagram_setup_frame;
use crate::runtime::Runtime;
use crate::seam::auth::{Authorizer, CredentialProvider, DenyAllAuthorizer, EmptyCredentials};
use crate::seam::channel::{
    BoxedStream, DatagramCarrier, DatagramIngress, DatagramLink, DatagramListener,
    IntoStreamHalves, StreamCarrier, StreamListener,
};
use crate::seam::handler::{
    DatagramEndpointHandler, DatagramTransitHandler, StreamEndpointHandler, StreamTransitHandler,
};
use crate::seam::path::{ExplicitPath, NoRoutes, PathSource};
use crate::stats::ScopeStats;
use crate::trust::gate::AuthLimits;
use crate::trust::registry::PublishGuard;
use crate::types::{PublicKey, ScopeKid};

/// Builder configuring a [`ScopeInstance`] with fail-closed defaults
/// (`DenyAllAuthorizer`, `EmptyCredentials`, `NoRoutes`).
pub struct ScopeBuilder {
    keypair: ScopeKeypair,
    runtime: Runtime,
    limits: ScopeLimits,
    auth_limits: AuthLimits,
    cookie_rotation: Duration,
    authorizer: Arc<dyn Authorizer>,
    credentials: Arc<dyn CredentialProvider>,
    path_source: Arc<dyn PathSource>,
}

impl ScopeBuilder {
    /// Creates a new `ScopeBuilder` with fail-closed policy defaults.
    #[must_use]
    pub fn new(keypair: ScopeKeypair, runtime: Runtime) -> Self {
        Self {
            keypair,
            runtime,
            limits: ScopeLimits::default(),
            auth_limits: AuthLimits::default(),
            cookie_rotation: COOKIE_ROTATION_INTERVAL,
            authorizer: Arc::new(DenyAllAuthorizer),
            credentials: Arc::new(EmptyCredentials),
            path_source: Arc::new(NoRoutes),
        }
    }

    /// Configures the verifier [`Authorizer`] (default: [`DenyAllAuthorizer`]).
    #[must_use]
    pub fn with_authorizer(mut self, authorizer: Arc<dyn Authorizer>) -> Self {
        self.authorizer = authorizer;
        self
    }

    /// Configures the originator [`CredentialProvider`] (default: [`EmptyCredentials`]).
    #[must_use]
    pub fn with_credentials(mut self, credentials: Arc<dyn CredentialProvider>) -> Self {
        self.credentials = credentials;
        self
    }

    /// Configures the originator [`PathSource`] (default: [`NoRoutes`]).
    #[must_use]
    pub fn with_path_source(mut self, path_source: Arc<dyn PathSource>) -> Self {
        self.path_source = path_source;
        self
    }

    /// Configures scope capacity limits (clamped to normative minimums `>= 1`).
    #[must_use]
    pub const fn with_limits(mut self, limits: ScopeLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Configures authorization concurrency, timeout, per-peer pending, and lease TTL limits.
    #[must_use]
    pub const fn with_auth_limits(mut self, auth_limits: AuthLimits) -> Self {
        self.auth_limits = auth_limits;
        self
    }

    /// Configures the flood-cookie secret rotation interval (clamped to `>= 1 s`; default `120 s`).
    #[must_use]
    pub const fn with_cookie_rotation(mut self, interval: Duration) -> Self {
        self.cookie_rotation = interval;
        self
    }

    /// Builds the [`ScopeInstance`] and spawns its revocation listener task (if any streams exist).
    #[must_use]
    pub fn build(self) -> Arc<ScopeInstance> {
        let core = ScopeCore::new(
            self.keypair,
            self.runtime,
            self.limits,
            self.auth_limits,
            self.cookie_rotation,
            self.authorizer,
            self.credentials,
            self.path_source,
        );
        let resolver = SingleScopeResolver::new(Arc::clone(&core));
        let standalone_ports = PortRegistry::new(
            core.limits.max_datagram_ports,
            PortMetricOwner::Scope(Arc::clone(&core.metrics)),
            Arc::clone(&core.runtime.clock),
            Arc::clone(&core.runtime.spawner),
            resolver,
            InboundDatagramDispatcher::new(),
            None,
        );
        let ports = PortSlot::new(standalone_ports);

        Arc::new(ScopeInstance { core, ports })
    }
}

impl fmt::Debug for ScopeBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopeBuilder")
            .field("kid", &self.keypair.scope_kid())
            .field("limits", &self.limits)
            .field("auth_limits", &self.auth_limits)
            .finish_non_exhaustive()
    }
}

/// Isolated Trust Scope owning one independent X25519 identity keypair, publication tables,
/// authorization gate, revocation index, and Stream/Datagram plane engines.
pub struct ScopeInstance {
    pub(crate) core: Arc<ScopeCore>,
    pub(crate) ports: Arc<PortSlot>,
}

/// Weak non-owning handle to a [`ScopeInstance`] preventing `Arc` reference cycles in handlers.
#[derive(Clone)]
pub struct WeakScope {
    inner: Weak<ScopeInstance>,
}

impl WeakScope {
    /// Upgrades to a strong `Arc<ScopeInstance>` if the scope is still alive.
    #[must_use]
    pub fn upgrade(&self) -> Option<Arc<ScopeInstance>> {
        self.inner.upgrade()
    }
}

impl fmt::Debug for WeakScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WeakScope")
            .field("alive", &(self.inner.strong_count() > 0))
            .finish()
    }
}

impl ScopeInstance {
    /// Returns a [`ScopeBuilder`] initialized with fail-closed policy defaults.
    #[must_use]
    pub fn builder(keypair: ScopeKeypair, runtime: Runtime) -> ScopeBuilder {
        ScopeBuilder::new(keypair, runtime)
    }

    /// Creates a non-owning [`WeakScope`] reference to avoid `Arc` cycles in callbacks/handlers.
    #[must_use]
    pub fn downgrade(self: &Arc<Self>) -> WeakScope {
        WeakScope {
            inner: Arc::downgrade(self),
        }
    }

    /// Returns this scope's 32-byte static X25519 public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.core.keypair.public_key()
    }

    /// Returns this scope's unlinkable 8-byte [`ScopeKid`].
    #[must_use]
    pub fn scope_kid(&self) -> ScopeKid {
        self.core.keypair.scope_kid()
    }

    /// Returns the effective clamped [`ScopeLimits`].
    #[must_use]
    pub fn limits(&self) -> ScopeLimits {
        self.core.limits
    }

    /// Returns the effective clamped [`AuthLimits`].
    #[must_use]
    pub fn auth_limits(&self) -> AuthLimits {
        self.core.auth_limits
    }

    // -----------------------------------------------------------------------
    // Outbound First-Hop Carrier Registration (Default-Deny Forwarding)
    // -----------------------------------------------------------------------

    /// Registers an outbound Stream carrier for first-hop dials under `name` (`1..=255` UTF-8 bytes).
    ///
    /// Outbound carriers NEVER expose inbound forwarding (default-deny forwarding).
    pub fn register_stream_carrier<C: StreamCarrier>(
        &self,
        name: &str,
        carrier: C,
    ) -> Result<(), CoreError> {
        self.core.registry.register_stream_carrier(name, carrier)
    }

    /// Registers an outbound Datagram carrier for first-hop dials under `name` (`1..=255` UTF-8 bytes).
    ///
    /// Outbound carriers NEVER expose inbound forwarding (default-deny forwarding).
    pub fn register_datagram_carrier<C: DatagramCarrier>(
        &self,
        name: &str,
        carrier: C,
    ) -> Result<(), CoreError> {
        self.core.registry.register_datagram_carrier(name, carrier)
    }

    // -----------------------------------------------------------------------
    // Explicit Named Endpoint & Named Transit Publication
    // -----------------------------------------------------------------------

    /// Publishes a terminal Stream endpoint under `name` (`1..=255` UTF-8 bytes).
    ///
    /// Takes no `min_mtu` parameter (implicit floor `0`, clamped to `20` during setup, Spec §7.4).
    pub fn publish_stream_endpoint(
        &self,
        name: &str,
        handler: Arc<dyn StreamEndpointHandler>,
    ) -> Result<PublishGuard, CoreError> {
        self.core.registry.publish_stream_endpoint(name, handler)
    }

    /// Publishes a terminal Datagram endpoint under `name`, rejecting `min_mtu < 1152` immediately.
    pub fn publish_datagram_endpoint(
        &self,
        name: &str,
        min_mtu: u16,
        handler: Arc<dyn DatagramEndpointHandler>,
    ) -> Result<PublishGuard, CoreError> {
        self.core
            .registry
            .publish_datagram_endpoint(name, min_mtu, handler)
    }

    /// Publishes an exact-match Stream forwarding transit under `name`.
    pub fn publish_stream_transit(
        &self,
        name: &str,
        handler: Arc<dyn StreamTransitHandler>,
    ) -> Result<PublishGuard, CoreError> {
        self.core.registry.publish_stream_transit(name, handler)
    }

    /// Publishes a prefix-match Stream forwarding transit under `prefix` (non-empty suffix required).
    pub fn publish_stream_transit_prefix(
        &self,
        prefix: &str,
        handler: Arc<dyn StreamTransitHandler>,
    ) -> Result<PublishGuard, CoreError> {
        self.core
            .registry
            .publish_stream_transit_prefix(prefix, handler)
    }

    /// Publishes an exact-match Datagram forwarding transit under `name`.
    pub fn publish_datagram_transit(
        &self,
        name: &str,
        handler: Arc<dyn DatagramTransitHandler>,
    ) -> Result<PublishGuard, CoreError> {
        self.core.registry.publish_datagram_transit(name, handler)
    }

    /// Publishes a prefix-match Datagram forwarding transit under `prefix` (non-empty suffix required).
    pub fn publish_datagram_transit_prefix(
        &self,
        prefix: &str,
        handler: Arc<dyn DatagramTransitHandler>,
    ) -> Result<PublishGuard, CoreError> {
        self.core
            .registry
            .publish_datagram_transit_prefix(prefix, handler)
    }

    // -----------------------------------------------------------------------
    // Originator Dials (Stream & Datagram, Direct & Staged)
    // -----------------------------------------------------------------------

    /// Resolves a Stream path via `PathSource`, completes handshake, and confirms 1.0 RTT open.
    pub async fn dial_stream(
        &self,
        peer: PublicKey,
        endpoint: &str,
    ) -> Result<E2eStream, CoreError> {
        let staged = self.dial_stream_staged(peer, endpoint).await?;
        staged.confirm().await
    }

    /// Resolves a Stream path via `PathSource` and pauses before 1.0 RTT confirmation.
    pub async fn dial_stream_staged(
        &self,
        peer: PublicKey,
        endpoint: &str,
    ) -> Result<StagedStream, CoreError> {
        stage_stream(Arc::clone(&self.core), peer, endpoint, None).await
    }

    /// Executes an explicit Stream path and confirms 1.0 RTT open.
    pub async fn dial_stream_via(
        &self,
        peer: PublicKey,
        endpoint: &str,
        path: ExplicitPath,
    ) -> Result<E2eStream, CoreError> {
        let staged = self.dial_stream_staged_via(peer, endpoint, path).await?;
        staged.confirm().await
    }

    /// Executes an explicit Stream path and pauses before 1.0 RTT confirmation.
    pub async fn dial_stream_staged_via(
        &self,
        peer: PublicKey,
        endpoint: &str,
        path: ExplicitPath,
    ) -> Result<StagedStream, CoreError> {
        stage_stream(Arc::clone(&self.core), peer, endpoint, Some(path)).await
    }

    /// Resolves a Datagram path via `PathSource`, completes handshake, and confirms 1.0 RTT open.
    pub async fn dial_datagram(
        &self,
        peer: PublicKey,
        endpoint: &str,
        min_mtu: u16,
    ) -> Result<E2eDatagram, CoreError> {
        let staged = self.dial_datagram_staged(peer, endpoint, min_mtu).await?;
        staged.confirm().await
    }

    /// Resolves a Datagram path via `PathSource` and pauses before 1.0 RTT confirmation.
    pub async fn dial_datagram_staged(
        &self,
        peer: PublicKey,
        endpoint: &str,
        min_mtu: u16,
    ) -> Result<StagedDatagram, CoreError> {
        stage_datagram(
            Arc::clone(&self.core),
            Arc::clone(&self.ports),
            peer,
            endpoint,
            min_mtu,
            None,
        )
        .await
    }

    /// Executes an explicit Datagram path and confirms 1.0 RTT open.
    pub async fn dial_datagram_via(
        &self,
        peer: PublicKey,
        endpoint: &str,
        min_mtu: u16,
        path: ExplicitPath,
    ) -> Result<E2eDatagram, CoreError> {
        let staged = self
            .dial_datagram_staged_via(peer, endpoint, min_mtu, path)
            .await?;
        staged.confirm().await
    }

    /// Executes an explicit Datagram path and pauses before 1.0 RTT confirmation.
    pub async fn dial_datagram_staged_via(
        &self,
        peer: PublicKey,
        endpoint: &str,
        min_mtu: u16,
        path: ExplicitPath,
    ) -> Result<StagedDatagram, CoreError> {
        stage_datagram(
            Arc::clone(&self.core),
            Arc::clone(&self.ports),
            peer,
            endpoint,
            min_mtu,
            Some(path),
        )
        .await
    }

    // -----------------------------------------------------------------------
    // Inbound Ingress, Listeners & Stack-Only Precheck
    // -----------------------------------------------------------------------

    /// Admits one inbound pure byte stream for this scope.
    pub fn accept_stream<S: IntoStreamHalves>(&self, stream: S) -> Result<(), CoreError> {
        let permit = self.core.try_acquire_pending()?;
        let resolver = SingleScopeResolver::new(Arc::clone(&self.core));
        spawn_inbound_stream(
            resolver,
            Arc::clone(&self.core.runtime.clock),
            Arc::clone(&self.core.runtime.spawner),
            BoxedStream::from_stream(stream),
            Some(permit),
            None,
        );
        Ok(())
    }

    /// Attaches an inbound [`DatagramLink`] to this scope, returning its [`DatagramIngress`] handle.
    ///
    /// Deduplicates shared links by [`crate::LinkId`]. Observing `DatagramAdmission::Rejected`
    /// never auto-closes the port.
    pub fn attach_datagram<L: DatagramLink>(&self, link: L) -> Result<DatagramIngress, CoreError> {
        if self.core.pending.is_closed() {
            return Err(CoreError::Closed);
        }
        let registry = self.ports.current();
        registry.attach_inbound(Arc::new(link), Some(Arc::clone(&self.core)), false)
    }

    /// Runs an inbound Stream listener loop, ignoring per-connection admission errors and
    /// terminating only when `listener.accept()` fails (Spec §8.2 Rule 5).
    pub async fn serve_stream_listener<L: StreamListener>(&self, listener: L) -> CoreError {
        loop {
            match listener.accept().await {
                Ok(stream) => {
                    let _ = self.accept_stream(stream);
                }
                Err(err) => return err,
            }
        }
    }

    /// Runs an inbound Datagram listener loop, ignoring per-link admission errors and
    /// terminating only when `listener.accept_link()` fails (Spec §8.2 Rule 5).
    pub async fn serve_datagram_listener<L: DatagramListener>(&self, listener: L) -> CoreError {
        loop {
            match listener.accept_link().await {
                Ok(link) => {
                    let _ = self.attach_datagram(link);
                }
                Err(err) => return err,
            }
        }
    }

    /// Zero-allocation stack-only front-door precheck for shared UDP sockets (Spec §8.2 Rule 3).
    ///
    /// Accepts both unfragmented `SETUP_FWD` (`0x11`) and fragment 0 of `SETUP_FRAG` (`0x15`)
    /// matching this scope's `ScopeKid` + `mac1`. Returns `false` once admission is closed.
    #[must_use]
    pub fn precheck_datagram_setup(&self, wire: &[u8]) -> bool {
        if self.core.pending.is_closed() {
            return false;
        }
        precheck_datagram_setup_frame(wire, |kid, seg, has_mac2| {
            kid.ct_eq(&self.core.keypair.scope_kid())
                && self.core.cookies.verify_mac1_only(seg, has_mac2)
        })
    }

    // -----------------------------------------------------------------------
    // Local Host Administration, Shutdown & Telemetry
    // -----------------------------------------------------------------------

    /// Adds `peer` to this scope's permanent local hard veto set AND immediately revokes
    /// all active inbound and outbound sessions for `peer` with [`CoreError::Revoked`].
    pub fn revoke_peer(&self, peer: PublicKey) {
        self.core.registry.veto_peer(peer);
    }

    /// Removes `peer` from this scope's local hard veto set.
    pub fn unrevoke_peer(&self, peer: PublicKey) {
        self.core.registry.unveto_peer(peer);
    }

    /// Immediately revokes all active transit circuits matching `name` across BOTH planes.
    pub fn revoke_transit(&self, name: &str) {
        self.core.registry.revoke_transit(name);
    }

    /// Sets a manual `under_load` flood-cookie override, or restores automatic hysteresis (`None`).
    pub fn set_under_load(&self, override_load: Option<bool>) {
        self.core.set_under_load(override_load);
    }

    /// Initiates graceful shutdown: stops all new admissions/dials, initiates `ST_FIN` on active
    /// Stream sessions (with no imposed drain timeout), and closes Datagram sessions and Transits.
    pub fn begin_shutdown(&self) {
        self.core.begin_shutdown();
    }

    /// Returns `true` once all pending setups, active sessions/circuits, and destination stream
    /// bridges have finished and released their permits (Spec §6.8).
    #[must_use]
    pub fn is_drained(&self) -> bool {
        self.core.is_drained()
    }

    /// Captures a lock-free atomic telemetry snapshot for this scope.
    #[must_use]
    pub fn stats(&self) -> ScopeStats {
        self.core.metrics.snapshot()
    }
}

impl fmt::Debug for ScopeInstance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopeInstance")
            .field("kid", &self.scope_kid())
            .field("public_key", &self.public_key())
            .finish()
    }
}
