//! Seam 2: Route / Path Source (pure explicit single-path topology & structured outcome feedback).
//!
//! Routing is completely decoupled from credentials: [`HopSpec`] carries only the hop's identity
//! and published transit target name; credentials are supplied and refreshed by
//! [`crate::CredentialProvider`].

use crate::{BoxFut, CoreErr, Plane, PublicKey};

/// Routing-layer error alias.
pub type RouteErr = CoreErr;

/// One intermediate hop in an explicit multi-hop path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HopSpec {
    /// Static public key of the intermediate hop's [`crate::ScopeInstance`].
    pub peer: PublicKey,
    /// Named transit target published on that hop (e.g., `"to-prod"` or `"relay/bob"`).
    pub target: String,
}

impl HopSpec {
    /// Constructs a hop targeting `target` on `peer`.
    pub fn new(peer: PublicKey, target: impl Into<String>) -> Self {
        Self {
            peer,
            target: target.into(),
        }
    }
}

/// One explicit, single path supplied by [`PathSource`] for a dial attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplicitPath {
    /// Caller-chosen path identifier echoed back in [`PathSource::report_outcome`].
    pub id: u64,
    /// Local outbound carrier name registered on the originator's scope (e.g., `"tcp"`, `"udp"`).
    pub first_channel: String,
    /// First-hop locator passed to `first_channel`.
    pub first_locator: Vec<u8>,
    /// Minimum acceptable path MTU floor (`0` uses the plane minimum).
    pub min_mtu: u16,
    /// Ordered sequence of intermediate hops (`empty` for direct `A -> B`).
    pub hops: Vec<HopSpec>,
}

/// Structured lifecycle and payload-limit feedback reported upward to [`PathSource`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathOutcome {
    Established { mtu: u16 },
    MtuChanged { mtu: u16 },
    Failed(CoreErr),
    Closed,
}

/// Route / Path Source extension seam (Seam 2).
pub trait PathSource: Send + Sync + 'static {
    /// Resolves one explicit path for `(peer, endpoint, plane)`.
    fn resolve_path<'a>(
        &'a self,
        peer: &'a PublicKey,
        endpoint: &'a str,
        plane: Plane,
    ) -> BoxFut<'a, Result<ExplicitPath, RouteErr>>;

    /// Receives structured establishment, MTU-drift, failure, and close feedback.
    fn report_outcome(&self, path_id: u64, outcome: PathOutcome);
}

/// Default fail-closed [`PathSource`] returning [`CoreErr::NoPath`] for every dial.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoRoutes;

impl PathSource for NoRoutes {
    fn resolve_path<'a>(
        &'a self,
        _peer: &'a PublicKey,
        _endpoint: &'a str,
        _plane: Plane,
    ) -> BoxFut<'a, Result<ExplicitPath, RouteErr>> {
        Box::pin(async { Err(CoreErr::NoPath) })
    }

    fn report_outcome(&self, _path_id: u64, _outcome: PathOutcome) {}
}
