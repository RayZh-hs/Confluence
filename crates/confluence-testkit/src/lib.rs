//! Deterministic in-memory test fabric (`MemDatagramHub`, `MemStreamHub`) with fault injection,
//! wire-tap inspection, outbound-dial counters, and [`AuditAuthorizer`].

#![forbid(unsafe_code)]

pub mod datagram;
pub mod stream;
pub mod support;

pub use datagram::{HubDatagramChannel, MemDatagramHub};
pub use stream::{HubStreamChannel, MemStreamHub};
pub use support::{AuditAuthorizer, RecordedAuth};
