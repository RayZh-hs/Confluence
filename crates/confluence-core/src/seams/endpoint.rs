use crate::{AsyncStream, BoxFut, CoreErr, DatagramLink, PublicKey};
use std::sync::Arc;

pub trait StreamEndpointHandler: Send + Sync + 'static {
    fn open(&self, peer: PublicKey) -> BoxFut<'_, Result<Box<dyn AsyncStream>, CoreErr>>;
}
pub trait DatagramEndpointHandler: Send + Sync + 'static {
    fn open(&self, peer: PublicKey) -> BoxFut<'_, Result<Arc<dyn DatagramLink>, CoreErr>>;
}
