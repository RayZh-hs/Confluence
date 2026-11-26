//! Normative v1 cryptographic primitives (pure, zero async I/O, zero wire-module dependency).

#[cfg_attr(feature = "test-support", allow(missing_docs))]
pub(crate) mod cipher;
#[cfg_attr(feature = "test-support", allow(missing_docs))]
pub(crate) mod cookie;
#[cfg_attr(feature = "test-support", allow(missing_docs))]
pub(crate) mod identity;
#[cfg_attr(feature = "test-support", allow(missing_docs))]
pub(crate) mod noise;
#[cfg_attr(feature = "test-support", allow(missing_docs))]
pub(crate) mod replay;

pub use identity::{ScopeKeypair, SecretHex};
