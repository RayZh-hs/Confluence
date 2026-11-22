//! The narrow extension seams of Confluence Core plus the runtime-agnostic [`TaskSpawner`].

pub mod auth;
pub mod channel;
pub mod endpoint;
pub mod path_source;

pub use auth::*;
pub use channel::*;
pub use endpoint::*;
pub use path_source::*;

/// Schedules a scope-owned network-independent worker on the embedding runtime.
pub trait TaskSpawner: Send + Sync + 'static {
    fn spawn(&self, task: crate::BoxFut<'static, ()>);
}
