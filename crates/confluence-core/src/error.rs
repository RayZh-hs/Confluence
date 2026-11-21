use crate::types::Plane;
use thiserror::Error;

/// Canonical result alias for `confluence-core`.
pub type Result<T> = std::result::Result<T, CoreError>;

/// Errors surfaced honestly across Confluence Core and its extension seams.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("validation error: {0}")]
    InvalidInput(String),

    #[error("plane mismatch: expected {expected}, got {actual}")]
    PlaneMismatch { expected: Plane, actual: Plane },

    #[error("channel capability mismatch: {0}")]
    CapabilityMismatch(String),

    #[error("channel unhealthy or unavailable: {0}")]
    ChannelUnhealthy(String),

    #[error("unknown trust scope: {0}")]
    ScopeNotFound(String),

    #[error("unknown channel: {0}")]
    ChannelNotFound(String),

    #[error("unknown target tag: {0}")]
    TargetNotFound(String),

    #[error("endpoint not published: {0}")]
    EndpointNotFound(String),

    #[error("cryptographic authentication failed")]
    AuthFailed,

    #[error("replay or stale timestamp rejected")]
    ReplayDetected,

    #[error("cookie challenge required from target {target_tag}")]
    CookieChallenge {
        target_tag: crate::types::TargetTag,
        challenge: Vec<u8>,
    },

    #[error("access denied: {0}")]
    AccessDenied(String),

    #[error("access control evaluation failed (fail-closed): {0}")]
    PolicyError(String),

    #[error("grant expired")]
    GrantExpired,

    #[error("grant revoked")]
    GrantRevoked,

    #[error("rate limit exceeded")]
    RateLimitExceeded,

    #[error("concurrent stream limit exceeded")]
    ConcurrencyLimitExceeded,

    #[error("path setup failed: {0}")]
    PathSetupFailed(String),

    #[error("wire framing error: {0}")]
    Framing(String),

    #[error("operation timed out")]
    Timeout,

    #[error("connection or channel closed: {0}")]
    Closed(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
