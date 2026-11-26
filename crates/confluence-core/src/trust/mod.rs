//! Trust, authorization enforcement, leases, revocation epochs, and publication registries (Layer 3, zero `protocol` dependency).

#[cfg_attr(feature = "test-support", allow(missing_docs))]
pub(crate) mod gate;
pub(crate) mod intersect;
#[cfg_attr(feature = "test-support", allow(missing_docs))]
pub(crate) mod lease;
#[cfg_attr(feature = "test-support", allow(missing_docs))]
pub(crate) mod registry;
#[cfg_attr(feature = "test-support", allow(missing_docs))]
pub(crate) mod revocation;

pub use gate::AuthLimits;
pub use intersect::IntersectAuthorizer;
pub use registry::{PublishGuard, TransitRevoker};
