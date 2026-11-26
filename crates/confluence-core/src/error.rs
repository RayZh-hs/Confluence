//! Structured error taxonomy, failure classification, and retryability semantics.

use core::fmt;

/// High-level root-cause classification reported to out-of-core routing and failover controllers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FailureClass {
    /// Transport, hop, cryptographic, timeout, or path-MTU failure; trying another path may succeed.
    PathFailure,
    /// Destination authorization, revocation, expiration, or publication failure.
    DestinationPolicy,
    /// Destination application refusal, busy capacity, or plane mismatch.
    DestinationApp,
    /// Originator-local credential acquisition failure.
    LocalAuth,
    /// Caller API misuse, local shutdown, or invalid parameters.
    LocalInvalid,
}

/// Unified error type returned across `confluence-core`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// A bounded protocol, authorization, or carrier write deadline elapsed.
    Timeout,
    /// A peer, transit, or endpoint is temporarily at capacity.
    Busy,
    /// A non-blocking send queue or link is currently full.
    WouldBlock,
    /// Structured transport carrier error with explicit transience hint.
    CarrierFailure {
        /// Diagnostic description supplied by the carrier (never logged directly by Core).
        message: String,
        /// Whether retrying the operation may succeed.
        transient: bool,
    },
    /// Generic permanent transport carrier failure.
    Carrier(String),
    /// Downstream or local target could not be reached.
    TargetUnreachable,
    /// Underlying stream ended before an authenticated `ST_FIN`.
    UnexpectedEof,
    /// Effective path or link MTU (`u16` wire bytes) fell below the required floor.
    MtuTooSmall(u16),
    /// Cryptographic handshake, AEAD tag, or key-exchange verification failed.
    Authentication,
    /// Responder requires a valid flood cookie (or re-challenged the same node).
    CookieRequired,
    /// Pre-DH `ScopeKid` or `mac1` validation failed.
    BadMac,
    /// Wire framing or protocol state invariant was violated.
    Malformed,
    /// Setup wall-clock timestamp exceeded the `±30_000 ms` freshness window.
    ClockSkew,
    /// Setup ephemeral key or replay-protected sequence was already seen or bucket saturated.
    Replay,
    /// An intermediate transit hop (`index`) rejected or terminated the path.
    HopRejected {
        /// Zero-based hop index (`0..N-1`) along the explicit path.
        index: u8,
        /// Root error reported by that hop.
        reason: Box<CoreError>,
    },
    /// Authorization policy denied the request or returned an out-of-bounds TTL.
    Denied,
    /// Peer, target, publication, or scope was revoked.
    Revoked,
    /// Lease lifetime elapsed without a successful renewal.
    Expired,
    /// Requested endpoint, transit, or local outbound carrier is not published.
    Unpublished,
    /// Destination endpoint handler explicitly refused the connection.
    TargetRefused,
    /// Request targeted an endpoint or transit published on the opposite plane.
    WrongPlane,
    /// Originator-local `CredentialProvider` failed or produced an invalid credential.
    Credential(Box<CoreError>),
    /// Caller supplied an invalid name, length, MTU, clock, or parameter.
    InvalidParameter,
    /// Endpoint, transit, carrier, scope, or port is already registered.
    AlreadyPublished,
    /// Outbound datagram exceeded current `max_payload` (carried as payload byte limit).
    MessageTooLarge(usize),
    /// Session, handle, scope, or sequence counter has been closed.
    Closed,
    /// `PathSource` returned no candidate path to the destination.
    NoPath,
}

impl CoreError {
    /// Classifies this error for failover routing and structured telemetry (Spec §9.2).
    #[must_use]
    pub const fn failure_class(&self) -> FailureClass {
        match self {
            Self::Timeout
            | Self::CarrierFailure { .. }
            | Self::Carrier(_)
            | Self::TargetUnreachable
            | Self::UnexpectedEof
            | Self::MtuTooSmall(_)
            | Self::Authentication
            | Self::CookieRequired
            | Self::BadMac
            | Self::Malformed
            | Self::ClockSkew
            | Self::Replay
            | Self::HopRejected { .. } => FailureClass::PathFailure,

            Self::Denied | Self::Revoked | Self::Expired | Self::Unpublished => {
                FailureClass::DestinationPolicy
            }

            Self::Busy | Self::TargetRefused | Self::WrongPlane => FailureClass::DestinationApp,

            Self::Credential(_) => FailureClass::LocalAuth,

            Self::WouldBlock
            | Self::InvalidParameter
            | Self::AlreadyPublished
            | Self::MessageTooLarge(_)
            | Self::Closed
            | Self::NoPath => FailureClass::LocalInvalid,
        }
    }

    /// Returns `true` iff [`Self::failure_class`] is [`FailureClass::PathFailure`].
    #[must_use]
    pub const fn is_path_failure(&self) -> bool {
        matches!(self.failure_class(), FailureClass::PathFailure)
    }

    /// Returns whether retrying the failed operation may succeed (Spec §9.2).
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Timeout | Self::Busy | Self::WouldBlock => true,
            Self::CarrierFailure { transient, .. } => *transient,
            Self::Credential(inner) => {
                matches!(
                    inner.as_ref(),
                    Self::TargetUnreachable | Self::Carrier(_)
                ) || inner.is_retryable()
            }
            Self::Carrier(_)
            | Self::TargetUnreachable
            | Self::UnexpectedEof
            | Self::MtuTooSmall(_)
            | Self::Authentication
            | Self::CookieRequired
            | Self::BadMac
            | Self::Malformed
            | Self::ClockSkew
            | Self::Replay
            | Self::HopRejected { .. }
            | Self::Denied
            | Self::Revoked
            | Self::Expired
            | Self::Unpublished
            | Self::TargetRefused
            | Self::WrongPlane
            | Self::InvalidParameter
            | Self::AlreadyPublished
            | Self::MessageTooLarge(_)
            | Self::Closed
            | Self::NoPath => false,
        }
    }

    /// Returns a fixed lowercase diagnostic identifier safe to emit into `tracing` fields.
    ///
    /// Never leaks untrusted carrier or credential error text.
    #[must_use]
    pub const fn static_code(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Busy => "busy",
            Self::WouldBlock => "would_block",
            Self::CarrierFailure { transient: true, .. } => "carrier_transient",
            Self::CarrierFailure { transient: false, .. } => "carrier_permanent",
            Self::Carrier(_) => "carrier",
            Self::TargetUnreachable => "target_unreachable",
            Self::UnexpectedEof => "unexpected_eof",
            Self::MtuTooSmall(_) => "mtu_too_small",
            Self::Authentication => "authentication",
            Self::CookieRequired => "cookie_required",
            Self::BadMac => "bad_mac",
            Self::Malformed => "malformed",
            Self::ClockSkew => "clock_skew",
            Self::Replay => "replay",
            Self::HopRejected { .. } => "hop_rejected",
            Self::Denied => "denied",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Unpublished => "unpublished",
            Self::TargetRefused => "target_refused",
            Self::WrongPlane => "wrong_plane",
            Self::Credential(_) => "credential",
            Self::InvalidParameter => "invalid_parameter",
            Self::AlreadyPublished => "already_published",
            Self::MessageTooLarge(_) => "message_too_large",
            Self::Closed => "closed",
            Self::NoPath => "no_path",
        }
    }

    /// Convenience constructor for wrapping a credential acquisition failure.
    #[must_use]
    pub fn credential(inner: Self) -> Self {
        Self::Credential(Box::new(inner))
    }

    /// Convenience constructor for wrapping an intermediate hop rejection.
    #[must_use]
    pub fn hop_rejected(index: u8, reason: Self) -> Self {
        Self::HopRejected {
            index,
            reason: Box::new(reason),
        }
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("operation timed out"),
            Self::Busy => f.write_str("resource busy"),
            Self::WouldBlock => f.write_str("operation would block"),
            Self::CarrierFailure { message, transient } => {
                if *transient {
                    write!(f, "transient carrier failure: {message}")
                } else {
                    write!(f, "carrier failure: {message}")
                }
            }
            Self::Carrier(msg) => write!(f, "carrier error: {msg}"),
            Self::TargetUnreachable => f.write_str("target unreachable"),
            Self::UnexpectedEof => f.write_str("unexpected end of stream"),
            Self::MtuTooSmall(mtu) => write!(f, "path MTU too small ({mtu} bytes)"),
            Self::Authentication => f.write_str("authentication failed"),
            Self::CookieRequired => f.write_str("flood cookie required"),
            Self::BadMac => f.write_str("invalid MAC1"),
            Self::Malformed => f.write_str("malformed frame or protocol violation"),
            Self::ClockSkew => f.write_str("setup timestamp outside freshness window"),
            Self::Replay => f.write_str("replayed setup or sequence"),
            Self::HopRejected { index, reason } => {
                write!(f, "hop {index} rejected path: {reason}")
            }
            Self::Denied => f.write_str("authorization denied"),
            Self::Revoked => f.write_str("lease or peer revoked"),
            Self::Expired => f.write_str("lease expired"),
            Self::Unpublished => f.write_str("target not published"),
            Self::TargetRefused => f.write_str("target refused connection"),
            Self::WrongPlane => f.write_str("target published on opposite plane"),
            Self::Credential(inner) => write!(f, "credential acquisition failed: {inner}"),
            Self::InvalidParameter => f.write_str("invalid parameter"),
            Self::AlreadyPublished => f.write_str("name or resource already published"),
            Self::MessageTooLarge(max) => {
                write!(f, "datagram exceeds max payload ({max} bytes)")
            }
            Self::Closed => f.write_str("closed"),
            Self::NoPath => f.write_str("no route available"),
        }
    }
}

impl std::error::Error for CoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HopRejected { reason, .. } => Some(reason.as_ref()),
            Self::Credential(inner) => Some(inner.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_classification_and_retryability_matrix() {
        let cases: &[(CoreError, FailureClass, bool)] = &[
            (CoreError::Timeout, FailureClass::PathFailure, true),
            (CoreError::Busy, FailureClass::DestinationApp, true),
            (CoreError::WouldBlock, FailureClass::LocalInvalid, true),
            (
                CoreError::CarrierFailure {
                    message: "tmp".into(),
                    transient: true,
                },
                FailureClass::PathFailure,
                true,
            ),
            (
                CoreError::CarrierFailure {
                    message: "perm".into(),
                    transient: false,
                },
                FailureClass::PathFailure,
                false,
            ),
            (CoreError::Carrier("err".into()), FailureClass::PathFailure, false),
            (CoreError::TargetUnreachable, FailureClass::PathFailure, false),
            (CoreError::UnexpectedEof, FailureClass::PathFailure, false),
            (CoreError::MtuTooSmall(1100), FailureClass::PathFailure, false),
            (CoreError::Authentication, FailureClass::PathFailure, false),
            (CoreError::CookieRequired, FailureClass::PathFailure, false),
            (CoreError::BadMac, FailureClass::PathFailure, false),
            (CoreError::Malformed, FailureClass::PathFailure, false),
            (CoreError::ClockSkew, FailureClass::PathFailure, false),
            (CoreError::Replay, FailureClass::PathFailure, false),
            (
                CoreError::hop_rejected(0, CoreError::Denied),
                FailureClass::PathFailure,
                false,
            ),
            (
                CoreError::hop_rejected(1, CoreError::Timeout),
                FailureClass::PathFailure,
                false,
            ),
            (CoreError::Denied, FailureClass::DestinationPolicy, false),
            (CoreError::Revoked, FailureClass::DestinationPolicy, false),
            (CoreError::Expired, FailureClass::DestinationPolicy, false),
            (CoreError::Unpublished, FailureClass::DestinationPolicy, false),
            (CoreError::TargetRefused, FailureClass::DestinationApp, false),
            (CoreError::WrongPlane, FailureClass::DestinationApp, false),
            (
                CoreError::credential(CoreError::TargetUnreachable),
                FailureClass::LocalAuth,
                true,
            ),
            (
                CoreError::credential(CoreError::Carrier("broker down".into())),
                FailureClass::LocalAuth,
                true,
            ),
            (
                CoreError::credential(CoreError::Timeout),
                FailureClass::LocalAuth,
                true,
            ),
            (
                CoreError::credential(CoreError::Busy),
                FailureClass::LocalAuth,
                true,
            ),
            (
                CoreError::credential(CoreError::Denied),
                FailureClass::LocalAuth,
                false,
            ),
            (
                CoreError::credential(CoreError::InvalidParameter),
                FailureClass::LocalAuth,
                false,
            ),
            (CoreError::InvalidParameter, FailureClass::LocalInvalid, false),
            (CoreError::AlreadyPublished, FailureClass::LocalInvalid, false),
            (CoreError::MessageTooLarge(1200), FailureClass::LocalInvalid, false),
            (CoreError::Closed, FailureClass::LocalInvalid, false),
            (CoreError::NoPath, FailureClass::LocalInvalid, false),
        ];

        for (err, expected_class, expected_retry) in cases {
            assert_eq!(err.failure_class(), *expected_class, "class mismatch for {err:?}");
            assert_eq!(err.is_retryable(), *expected_retry, "retry mismatch for {err:?}");
            assert_eq!(
                err.is_path_failure(),
                *expected_class == FailureClass::PathFailure
            );
            assert!(!err.static_code().is_empty());
        }
    }
}
