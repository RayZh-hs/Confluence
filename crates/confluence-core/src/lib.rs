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
// Consumed by Layer 4–5 engines (Phase 3B) and verified via `test-support` conformance tests.
#[cfg_attr(not(feature = "test-support"), allow(dead_code))]
mod crypto;
#[cfg_attr(not(feature = "test-support"), allow(dead_code))]
mod wire;

// Layer 3 — Pure protocol state machines & trust/publication enforcement (zero mutual dependency)
#[cfg_attr(not(feature = "test-support"), allow(dead_code))]
mod protocol;
#[cfg_attr(not(feature = "test-support"), allow(dead_code))]
mod trust;

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
pub use crate::error::{CoreError, FailureClass};
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
// or `#[cfg(test)]` so external integration test binaries (`tests/primitives.rs`) with custom
// `#[global_allocator]` can directly verify zero-allocation hot paths and v1 wire conformance.
#[doc(hidden)]
#[cfg(feature = "test-support")]
#[allow(missing_docs)]
pub mod __conformance {
    pub use crate::stats::internal::ScopeMetrics;
    pub use crate::crypto::cipher::{ControlCipher, DatagramRx, DatagramTx, ReplayWindow, StreamCipher};
    pub use crate::crypto::cookie::{CookieDecision, CookieProtector, LoadTracker, unseal_cookie_challenge};
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
