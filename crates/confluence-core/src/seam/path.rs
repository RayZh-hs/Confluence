//! Seam 2: Pure single-path routing (`PathSource`) with zero credentials and zero raw downstream addresses.

use crate::error::CoreError;
use crate::runtime::BoxFuture;
use crate::types::{Plane, PublicKey};

/// One intermediate named-transit hop along an [`ExplicitPath`].
///
/// Carries only the hop's cryptographic public key and logical transit target name —
/// never credentials or raw downstream network addresses (SSRF-safe by construction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopSpec {
    /// Static public key of intermediate hop `H_i`.
    pub peer: PublicKey,
    /// Logical UTF-8 transit target name published on `H_i` (`1..=255` bytes).
    pub target: String,
}

impl HopSpec {
    /// Creates a new `HopSpec`.
    #[must_use]
    pub fn new(peer: PublicKey, target: impl Into<String>) -> Self {
        Self {
            peer,
            target: target.into(),
        }
    }
}

/// Complete explicit single path supplied to Core for one dial attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplicitPath {
    /// Caller-assigned path identifier echoed back in [`PathSource::report_outcome`].
    pub id: u64,
    /// Locally registered outbound carrier name used to reach the first hop (or destination).
    pub first_channel: String,
    /// Carrier-specific opaque first-hop locator bytes.
    pub first_locator: Vec<u8>,
    /// Requested minimum wire MTU floor (clamped up to plane minimum during setup).
    pub min_mtu: u16,
    /// Ordered list of intermediate hops (`H_0, ..., H_{N-1}`; empty for direct `A -> B` paths).
    pub hops: Vec<HopSpec>,
}

impl ExplicitPath {
    /// Constructs a direct (`0`-hop) path with default `min_mtu = 0` (clamped to plane floor).
    #[must_use]
    pub fn direct(
        id: u64,
        first_channel: impl Into<String>,
        first_locator: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            id,
            first_channel: first_channel.into(),
            first_locator: first_locator.into(),
            min_mtu: 0,
            hops: Vec::new(),
        }
    }

    /// Sets the requested minimum wire MTU floor on this path.
    #[must_use]
    pub const fn with_min_mtu(mut self, min_mtu: u16) -> Self {
        self.min_mtu = min_mtu;
        self
    }

    /// Sets the ordered intermediate transit hops (`H_0 .. H_{N-1}`).
    #[must_use]
    pub fn with_hops(mut self, hops: Vec<HopSpec>) -> Self {
        self.hops = hops;
        self
    }
}

/// Structured lifecycle and root-cause feedback reported back to [`PathSource`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathOutcome {
    /// Session confirmed and established with authenticated end-to-end wire MTU `mtu`.
    Established {
        /// Authenticated effective wire MTU across all legs.
        mtu: u16,
    },
    /// Live end-to-end datagram path MTU changed mid-session while staying at or above floor.
    MtuChanged {
        /// Updated effective wire MTU across all legs.
        mtu: u16,
    },
    /// Staging, confirmation, or steady-state session failed abnormally.
    Failed(CoreError),
    /// Session or unconfirmed staged handle closed cleanly.
    Closed,
}

/// Out-of-core pure path selector (Seam 2).
///
/// Supplies one explicit path per dial and receives structured lifecycle outcomes without
/// ever touching credentials or authorization decisions.
pub trait PathSource: Send + Sync + 'static {
    /// Resolves one explicit candidate path to `(peer, endpoint)` on `plane`.
    fn resolve_path<'a>(
        &'a self,
        peer: PublicKey,
        endpoint: &'a str,
        plane: Plane,
    ) -> BoxFuture<'a, Result<ExplicitPath, CoreError>>;

    /// Receives structured outcome notifications for `path_id`.
    fn report_outcome(&self, path_id: u64, outcome: PathOutcome);
}

/// Fail-closed default [`PathSource`] returning [`CoreError::NoPath`] for every resolution.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRoutes;

impl PathSource for NoRoutes {
    fn resolve_path<'a>(
        &'a self,
        _peer: PublicKey,
        _endpoint: &'a str,
        _plane: Plane,
    ) -> BoxFuture<'a, Result<ExplicitPath, CoreError>> {
        Box::pin(async { Err(CoreError::NoPath) })
    }

    fn report_outcome(&self, _path_id: u64, _outcome: PathOutcome) {}
}
