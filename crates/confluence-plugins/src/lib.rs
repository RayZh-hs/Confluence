//! Standard out-of-core Confluence plugins:
//! - [`StaticAuthorizer`], [`StaticPolicy`], [`StaticCredentials`], [`StaticPathSource`]:
//!   Declarative and programmatic auth, credential, and explicit-route plugins.
//! - [`QosLimits`], [`RateGate`], [`ConcurrencyLimiter`], [`QosAuthorizer`]: Out-of-core
//!   traffic shaping (byte rate, datagram PPS, and concurrent session caps) attached directly to
//!   [`confluence_core::Lease`] (`TrafficGate` + RAII `SessionGuard`).
//! - [`MemStreamChannel`], [`MemDatagramChannel`]: Lightweight in-memory transport carriers.
//! - [`TokioSpawner`]: Tokio runtime implementation of [`confluence_core::TaskSpawner`].

#![forbid(unsafe_code)]

mod memory;
pub mod qos;
mod static_config;

pub use memory::*;
pub use qos::*;
pub use static_config::*;

/// Spawns Confluence Core background workers onto the current Tokio runtime.
pub struct TokioSpawner;

impl confluence_core::TaskSpawner for TokioSpawner {
    fn spawn(&self, task: confluence_core::BoxFut<'static, ()>) {
        tokio::spawn(task);
    }
}
