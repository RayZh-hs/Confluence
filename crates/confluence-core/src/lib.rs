//! Runtime-independent two-plane A-to-B connectivity core (`confluence-core`).
//!
//! `confluence-core` connects an Originator `A` to an explicitly published named **Endpoint**
//! on Destination `B` across zero or more explicitly named **Transits** over pure pluggable
//! **Channels**, with strict two-plane separation (Stream vs. Datagram), direct per-hop
//! `Noise_IK` authentication with route-integrity AAD, stateless flood cookies, revocable
//! leases, and zero executor or OS-socket dependencies.
//!
//! # Module Organization
//!
//! - [`channel`] — Seam 1: pure composable Stream/Datagram channels, listeners, and live [`channel::MtuWatch`].
//! - [`path`] — Seam 2: pure single-path selection (`PathSource`, zero credentials).
//! - [`auth`] — Seam 3: symmetric credential acquisition, fail-closed `Authorizer`, `IntersectAuthorizer`, leases, and revocations.
//! - [`handler`] — Seam 4: terminal endpoint handlers and named transit forwarders.
//! - [`runtime`] — Executor-agnostic monotonic [`runtime::Clock`], [`runtime::TaskSpawner`], and [`runtime::Runtime`].
//! - [`stats`] — Immutable atomic telemetry snapshots (`ScopeStats`, `NodeStats`).
//! - [`constants`] — Normative v1 wire and behavioral protocol constants.
//!
//! # Quick Start Example
//!
//! (Requires the `test-support` feature for the in-memory channel & virtual runtime harness.)
//!
//! ```rust
//! # #[cfg(feature = "test-support")]
//! # fn main() {
//! use std::sync::Arc;
//! use std::time::Duration;
//! use confluence_core::auth::{AuthDenied, AuthRequest, Authorizer, Lease};
//! use confluence_core::channel::{BoxedStream, IntoStreamHalves, StreamReadExt, StreamWriteExt};
//! use confluence_core::handler::StreamEndpointHandler;
//! use confluence_core::path::ExplicitPath;
//! use confluence_core::runtime::BoxFuture;
//! use confluence_core::testing::{MemoryStreamPair, TestRuntime, memory_stream_channel};
//! use confluence_core::{Node, ScopeInstance, ScopeKeypair};
//!
//! struct AllowAll;
//! impl Authorizer for AllowAll {
//!     fn authorize<'a>(&'a self, _req: AuthRequest<'a>) -> BoxFuture<'a, Result<Lease, AuthDenied>> {
//!         Box::pin(async { Ok(Lease::new(Duration::from_secs(60))) })
//!     }
//! }
//!
//! struct EchoEndpoint {
//!     rt: TestRuntime,
//! }
//! impl StreamEndpointHandler for EchoEndpoint {
//!     fn open(&self, _auth: confluence_core::auth::SessionAuth) -> BoxFuture<'_, Result<BoxedStream, confluence_core::CoreError>> {
//!         Box::pin(async {
//!             let pair = MemoryStreamPair::pair(16_384);
//!             let (mut r, mut w) = pair.b.into_halves();
//!             self.rt.runtime.spawner.spawn(Box::pin(async move {
//!                 let mut buf = [0u8; 64];
//!                 while let Ok(n) = r.read(&mut buf).await {
//!                     if n == 0 {
//!                         let _ = w.shutdown().await;
//!                         break;
//!                     }
//!                     if w.write_all(&buf[..n]).await.is_err() {
//!                         break;
//!                     }
//!                 }
//!             }));
//!             Ok(BoxedStream::from_stream(pair.a))
//!         })
//!     }
//! }
//!
//! let tr = TestRuntime::new();
//! let origin = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone()).build();
//! let dest = ScopeInstance::builder(ScopeKeypair::generate(), tr.runtime.clone())
//!     .with_authorizer(Arc::new(AllowAll))
//!     .build();
//! let node = Node::builder(tr.runtime.clone()).build();
//! node.add_scope(Arc::clone(&dest)).unwrap();
//!
//! let (carrier, listener, _mtu) = memory_stream_channel(16_384);
//! origin.register_stream_carrier("mem", carrier).unwrap();
//! let _guard = dest.publish_stream_endpoint("echo", Arc::new(EchoEndpoint { rt: tr.clone() })).unwrap();
//!
//! let node_srv = Arc::clone(&node);
//! tr.runtime.spawner.spawn(Box::pin(async move {
//!     let _ = node_srv.serve_stream_listener(listener).await;
//! }));
//!
//! let res = tr.spawner.try_block_on(async {
//!     let path = ExplicitPath::direct(1, "mem", b"dest".to_vec());
//!     let mut st = origin.dial_stream_via(dest.public_key(), "echo", path).await?;
//!     st.write_all(b"hello").await?;
//!     st.shutdown().await?;
//!     let mut out = [0u8; 5];
//!     st.read_exact(&mut out).await?;
//!     assert_eq!(&out, b"hello");
//!     assert_eq!(st.read(&mut out).await?, 0);
//!     Ok::<(), confluence_core::CoreError>(())
//! });
//! assert_eq!(res, Some(Ok(())));
//! # }
//! # #[cfg(not(feature = "test-support"))]
//! # fn main() {}
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

// Layer 0 — Foundational types, constants, packet buffer, errors & telemetry
pub mod constants;
mod error;
mod packet;
pub mod stats;
mod types;

// Layer 1 — Runtime abstractions & extension seam contracts
pub mod runtime;
mod seam;

// Layer 2 — Pure v1 cryptography & wire codecs (zero async I/O, zero mutual dependency)
mod crypto;
mod wire;

// Layer 3 — Pure protocol state machines & trust/publication enforcement (zero mutual dependency)
mod protocol;
mod trust;

// Layer 4 — Async Stream & Datagram plane engines (zero imports from `host`)
mod engine;

// Layer 5 — Multi-scope `Node` container & `ScopeInstance` public facade
mod host;

// Deterministic testing harness (compiled for unit/integration tests and `test-support` feature)
#[cfg(any(test, feature = "test-support"))]
pub mod testing;

// ---------------------------------------------------------------------------
// Curated Public Extension Seam Submodules
// ---------------------------------------------------------------------------

/// Seam 1: Pure composable Stream and Datagram transport channels, listeners, and live MTU watches.
pub mod channel {
    pub use crate::seam::channel::{
        BoxedStream, ChannelCaps, DatagramAdmission, DatagramCarrier, DatagramIngress,
        DatagramLink, DatagramLinkExt, DatagramListener, IntoStreamHalves, MtuSender, MtuWatch,
        StreamCarrier, StreamListener, StreamRead, StreamReadExt, StreamWrite, StreamWriteExt,
    };
    pub use crate::types::LinkId;
}

/// Seam 2: Pure single-path routing (`PathSource`, zero credentials or raw downstream addresses).
pub mod path {
    pub use crate::seam::path::{ExplicitPath, HopSpec, NoRoutes, PathOutcome, PathSource};
}

/// Seam 3: Symmetric credential acquisition, fail-closed authorization, leases, and revocations.
pub mod auth {
    pub use crate::seam::auth::{
        AuthDenied, AuthExtensions, AuthRequest, Authorizer, CredentialProvider, CredentialRequest,
        DatagramAction, DenyAllAuthorizer, EmptyCredentials, Lease, Revocation, RevocationReceiver,
        RevocationRecvError, RevocationSender, SessionAuth, SessionGuard, StreamAction,
        TrafficGate, revocation_channel,
    };
    pub use crate::trust::intersect::IntersectAuthorizer;
    pub use crate::types::Credential;
}

/// Seam 4: Terminal endpoint handlers and named transit forwarders.
pub mod handler {
    pub use crate::seam::handler::{
        DatagramEndpointHandler, DatagramTransitHandler, DynamicTransit, StaticTransit,
        StreamEndpointHandler, StreamTransitHandler,
    };
}

// ---------------------------------------------------------------------------
// Curated Crate-Root Re-Exports
// ---------------------------------------------------------------------------

pub use crate::crypto::{ScopeKeypair, SecretHex};
pub use crate::engine::context::ScopeLimits;
pub use crate::engine::datagram::session::E2eDatagram;
pub use crate::engine::origin::{StagedDatagram, StagedStream};
pub use crate::engine::stream::session::{E2eStream, E2eStreamRead, E2eStreamWrite};
pub use crate::error::{CoreError, FailureClass};
pub use crate::host::{Node, NodeBuilder, NodeLimits, ScopeBuilder, ScopeInstance, WeakNode, WeakScope};
pub use crate::packet::PacketBuf;
pub use crate::seam::auth::{DenyAllAuthorizer, EmptyCredentials};
pub use crate::seam::handler::{DynamicTransit, StaticTransit};
pub use crate::seam::path::NoRoutes;
pub use crate::trust::{AuthLimits, IntersectAuthorizer, PublishGuard, TransitRevoker};
pub use crate::types::{
    Cid, Credential, Direction, LinkId, Plane, PublicationId, PublicKey, Role, ScopeKid, TargetRef,
    ValidatedName,
};

// ---------------------------------------------------------------------------
// Internal Test-Only White-Box Conformance Bridge
// ---------------------------------------------------------------------------
// Exposes internal Layer 2/3 pure primitives solely under `#[cfg(feature = "test-support")]`
// so external integration test binaries (`tests/primitives.rs`) with custom `#[global_allocator]`
// can directly verify zero-allocation hot paths and v1 wire conformance.
#[doc(hidden)]
#[cfg(feature = "test-support")]
#[allow(missing_docs)]
pub mod __conformance {
    pub use crate::crypto::cipher::{
        ControlCipher, DatagramRx, DatagramTx, ReplayWindow, StreamCipher,
    };
    pub use crate::crypto::cookie::{
        CookieDecision, CookieProtector, LoadTracker, unseal_cookie_challenge,
    };
    pub use crate::crypto::identity::{
        compute_mac1, compute_mac2, derive_cookie_enc_key, derive_mac1_key, derive_mac2_key,
        derive_scope_kid,
    };
    pub use crate::crypto::noise::{HopKey, Initiator, Responder, SessionKeys};
    pub use crate::crypto::replay::SetupReplay;
    pub use crate::protocol::fragment::{
        FeedOutcome, FragmentBurst, FragmentKey, FragmentReassembler, FragmentReceipt,
        OpeningVerdict, PreparedFlight,
    };
    pub use crate::protocol::mtu::{
        DestPathMtu, MtuChange, MtuReporter, OriginPathMtu, TransitMtuEvent, TransitPathMtu,
        advance_epoch,
    };
    pub use crate::protocol::renewal::{
        CredentialFetchOutcome, RenewalAction, RenewalDriver, RenewalSlot, RenewalVerifierState,
        VerifierRenewalAction,
    };
    pub use crate::protocol::setup::{
        HopFlightInput, HopOkRewriteParams, HopSetupRewrite, OriginEstablished, OriginSetupState,
        SetupFlightBuilder, SetupFlightParams, compute_tail_aad, precheck_datagram_setup_frame,
        validate_wire_ttl_ms,
    };
    pub use crate::protocol::slab::SlabTable;
    pub use crate::stats::internal::ScopeMetrics;
    pub use crate::trust::gate::{AuthGate, PendingSetup};
    pub use crate::trust::lease::{LeaseHandle, TrafficGateCache};
    pub use crate::trust::registry::PublishRegistry;
    pub use crate::trust::revocation::{
        AuthEpochSnapshot, AuthEpochTable, RevocationIndex, RevocationKey, TransitEpochTarget,
    };
    pub use crate::wire::datagram::{
        DgHopControlHeader, decode_mtu_ack_payload, decode_mtu_payload, decode_renew_ok_payload,
        decode_renew_payload, encode_mtu_ack_payload, encode_mtu_payload, encode_renew_ok_payload,
        encode_renew_payload, prepend_dg_data_header, rewrite_dg_data_cid, strip_dg_data_header,
    };
    pub use crate::wire::opcodes::{
        StreamOpenStatus, decode_wire_error, decode_wire_error_bytes, e2e_dg, e2e_st,
        encode_wire_error, encode_wire_error_bytes, outer,
    };
    pub use crate::wire::setup::{
        DispatchPrefix, ForwardHeader, LeadingSegment, MODE_DEST, MODE_HOP, MODE_MAC2,
        ParsedSegment, SetupCookieFrame, SetupErrFrame, SetupFragAck, SetupFragHeader,
        SetupOkHeader, SetupPlaintext, route_cid,
    };
    pub use crate::wire::stream::{StHopHeader, validate_st_e2e_body_len, validate_st_e2e_opcode};
}
