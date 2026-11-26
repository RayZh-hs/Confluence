//! Pure synchronous protocol state machines (Layer 3, zero async I/O, zero `trust` dependency).

#[cfg_attr(feature = "test-support", allow(missing_docs))]
pub(crate) mod fragment;
#[cfg_attr(feature = "test-support", allow(missing_docs))]
pub(crate) mod mtu;
#[cfg_attr(feature = "test-support", allow(missing_docs))]
pub(crate) mod renewal;
#[cfg_attr(feature = "test-support", allow(missing_docs))]
pub(crate) mod setup;
#[cfg_attr(feature = "test-support", allow(missing_docs))]
pub(crate) mod slab;
