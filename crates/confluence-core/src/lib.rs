//! # Confluence Core
//!
//! Cleanroom two-plane A-to-B connectivity engine (`#![forbid(unsafe_code)]`, zero OS socket or
//! runtime coupling), featuring:
//! - Strictly separated 1:1 end-to-end Stream and Datagram planes with zero implicit conversion.
//! - Pure transport channels (`StreamChannel` / `DatagramChannel`) with zero auth or policy logic.
//! - Route-integrity-bound 1-RTT single-pass multi-hop setup over named **Endpoints** and named
//!   **Transits**, with direct originator authentication at every hop and 1.0 RTT replay-safe
//!   deferred destination open.
//! - Symmetric pluggable auth (`CredentialProvider` ↔ `Authorizer`) returning revocable `Lease`s
//!   with composable out-of-core [`TrafficGate`] hooks, RAII [`SessionGuard`] permits, and live
//!   typed [`AuthExtensions`] surfaced via [`SessionAuth`] (keeping QoS algorithms and fine-grained
//!   application access control cleanly outside Core).

#![forbid(unsafe_code)]

pub mod buf;
pub mod cid;
pub mod crypto;
pub mod e2e;
pub mod lease;
pub mod node;
mod path;
pub mod scope;
pub mod seams;
pub mod wire;

use std::{
    fmt,
    future::Future,
    pin::Pin,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub use buf::PacketBuf;
pub use crypto::{PublicKey, ScopeKeypair, ScopeKid};
pub use e2e::{
    datagram::{E2eDatagram, StagedDatagram},
    stream::{E2eStream, StagedStream},
};
pub use lease::{
    AuthContext, AuthExtensions, DatagramAction, Direction, Lease, LeaseHandle, MAX_LEASE_TTL,
    SessionAuth, SessionGuard, StreamAction, TrafficGate,
};
pub use node::{Node, WeakNode};
pub use scope::{
    DatagramIngress, PublishGuard, ScopeBuilder, ScopeInstance, ScopeLimits, WeakScope,
};
pub use seams::*;

/// Boxed `Send` future alias used across dyn-safe seam traits.
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
/// Minimum supported Datagram Plane channel MTU (`1232` bytes).
pub const DATAGRAM_MTU: u16 = 1232;
/// Maximum Stream Plane hop chunk size (`16 KiB`).
pub const STREAM_CHUNK: usize = 16384;
/// Default setup / confirmation timeout (`3 s`).
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(3);

/// The two strictly separated traffic planes inside Confluence Core.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[repr(u8)]
pub enum Plane {
    Datagram = 1,
    Stream = 2,
}

impl Plane {
    /// Minimum wire MTU required to carry at least one E2E frame on this plane.
    pub const fn minimum_mtu(self) -> u16 {
        match self {
            Self::Datagram => DATAGRAM_MTU,
            Self::Stream => (wire::e2e::ST_OVERHEAD + 1) as u16,
        }
    }
}

impl fmt::Display for Plane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Datagram => f.write_str("datagram"),
            Self::Stream => f.write_str("stream"),
        }
    }
}

impl TryFrom<u8> for Plane {
    type Error = CoreErr;
    fn try_from(value: u8) -> Result<Self, CoreErr> {
        match value {
            1 => Ok(Self::Datagram),
            2 => Ok(Self::Stream),
            _ => Err(CoreErr::Malformed),
        }
    }
}

/// Structured errors surfaced honestly across Confluence Core and its extension seams.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CoreErr {
    #[error("invalid frame or parameter")]
    Malformed,
    #[error("authentication failed")]
    Authentication,
    #[error("setup timed out")]
    Timeout,
    #[error("pending setup limit reached")]
    Busy,
    #[error("access denied")]
    Denied,
    #[error("lease expired")]
    Expired,
    #[error("access revoked")]
    Revoked,
    #[error("endpoint or transit is unpublished")]
    Unpublished,
    #[error("a publication already exists with this name")]
    AlreadyPublished,
    #[error("wrong transport plane")]
    WrongPlane,
    #[error("MTU too small ({0} bytes)")]
    MtuTooSmall(u16),
    #[error("message too large (maximum {0} bytes)")]
    MessageTooLarge(usize),
    #[error("target refused the connection")]
    TargetRefused,
    #[error("target unreachable")]
    TargetUnreachable,
    #[error("carrier closed before authenticated FIN")]
    UnexpectedEof,
    #[error("session closed")]
    Closed,
    #[error("session send queue is full")]
    WouldBlock,
    #[error("no explicit path")]
    NoPath,
    #[error("hop {index} rejected setup: {reason}")]
    HopRejected { index: u8, reason: Box<CoreErr> },
    #[error("carrier error: {0}")]
    Carrier(String),
}

/// High-level root-cause classification of a [`CoreErr`] for smart [`PathSource`] failover routers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FailureClass {
    /// Transport, reachability, MTU, or intermediate-hop failure — switching paths may succeed.
    PathFailure,
    /// Destination policy/authorization rejection (`Denied`, `Revoked`, `Expired`, `Unpublished`).
    DestinationPolicy,
    /// Destination endpoint/service rejection (`TargetRefused`, `Busy`, `WrongPlane`).
    DestinationApp,
    /// Local or framing error (`Malformed`, `MessageTooLarge`, `NoPath`, `Closed`, `WouldBlock`).
    LocalInvalid,
}

impl CoreErr {
    /// Classifies this error so failover controllers can distinguish transport/hop failures
    /// from destination policy or application rejections.
    pub fn failure_class(&self) -> FailureClass {
        match self {
            Self::Timeout
            | Self::TargetUnreachable
            | Self::UnexpectedEof
            | Self::MtuTooSmall(_)
            | Self::Authentication
            | Self::Carrier(_)
            | Self::HopRejected { .. } => FailureClass::PathFailure,
            Self::Denied | Self::Revoked | Self::Expired | Self::Unpublished => {
                FailureClass::DestinationPolicy
            }
            Self::TargetRefused | Self::Busy | Self::WrongPlane => FailureClass::DestinationApp,
            Self::Malformed
            | Self::AlreadyPublished
            | Self::MessageTooLarge(_)
            | Self::Closed
            | Self::WouldBlock
            | Self::NoPath => FailureClass::LocalInvalid,
        }
    }

    /// Returns `true` if trying an alternate explicit path may resolve this error.
    pub fn is_path_failure(&self) -> bool {
        self.failure_class() == FailureClass::PathFailure
    }
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
