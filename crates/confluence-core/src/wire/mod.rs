//! Normative v1 big-endian wire codecs (pure, zero async I/O, zero `crypto` dependency).

#[cfg_attr(feature = "test-support", allow(missing_docs))]
pub(crate) mod datagram;
#[cfg_attr(feature = "test-support", allow(missing_docs))]
pub(crate) mod opcodes;
#[cfg_attr(feature = "test-support", allow(missing_docs))]
pub(crate) mod setup;
#[cfg_attr(feature = "test-support", allow(missing_docs))]
pub(crate) mod stream;
