//! # Confluence Core
//!
//! Cleanroom two-plane A-to-B connectivity engine, blind single-pass path execution,
//! cryptographic & DoS-resilience primitives, and narrow extension seam contracts.
//!
//! `confluence-core` intentionally contains zero concrete transport sockets, zero passive relay
//! logic, zero static/external policy backends, zero route discovery, and zero application
//! protocol awareness.

#![forbid(unsafe_code)]

pub mod datagram_session;
pub mod error;
pub mod node;
pub mod scope;
pub mod seams;
pub mod security;
pub mod stream_session;
pub mod types;
pub mod wire;

pub use datagram_session::ConfluenceDatagramSession;
pub use error::{CoreError, Result};
pub use node::Node;
pub use scope::{PublishedDatagramEndpoint, PublishedStreamEndpoint, TrustScope};
pub use stream_session::ConfluenceStream;
pub use types::{
    ChannelAddr, ChannelId, CircuitId, EndpointName, HopLabel, OpaqueCredential, PeerId, Plane,
    ScopeId, StaticKeypair, TargetTag,
};
