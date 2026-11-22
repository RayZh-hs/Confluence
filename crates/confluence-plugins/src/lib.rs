#![forbid(unsafe_code)]

mod auth;
mod memory;
mod static_config;

pub use auth::AuthAclWrapper;
pub use memory::*;
pub use static_config::*;

pub struct TokioSpawner;
impl confluence_core::TaskSpawner for TokioSpawner {
    fn spawn(&self, task: confluence_core::BoxFut<'static, ()>) {
        tokio::spawn(task);
    }
}
