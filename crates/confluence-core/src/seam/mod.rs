//! The four narrow out-of-core extension seams.
//!
//! 1. [`channel`] — Pure composable Stream and Datagram channels & listeners.
//! 2. [`path`] — Pure single-path routing (`PathSource`, zero credentials).
//! 3. [`auth`] — Symmetric credential acquisition and fail-closed authorization.
//! 4. [`handler`] — Terminal endpoint handlers and named transit forwarders.

pub mod auth;
pub mod channel;
pub mod handler;
pub mod path;
