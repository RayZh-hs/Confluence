//! Seam 4: Terminal endpoint handlers and named transit forwarders.

use std::sync::Arc;

use crate::error::CoreError;
use crate::runtime::BoxFuture;
use crate::seam::auth::SessionAuth;
use crate::seam::channel::{
    BoxedStream, ChannelCaps, DatagramCarrier, DatagramLink, StreamCarrier,
};

/// Terminal Stream endpoint handler invoked on Destination `B` strictly after 1.0 RTT confirmation.
pub trait StreamEndpointHandler: Send + Sync + 'static {
    /// Opens the local service stream for an authenticated and confirmed session.
    fn open(&self, auth: SessionAuth) -> BoxFuture<'_, Result<BoxedStream, CoreError>>;
}

/// Terminal Datagram endpoint handler invoked on Destination `B` strictly after 1.0 RTT confirmation.
pub trait DatagramEndpointHandler: Send + Sync + 'static {
    /// Opens the local datagram target link for an authenticated and confirmed session.
    fn open(&self, auth: SessionAuth) -> BoxFuture<'_, Result<Arc<dyn DatagramLink>, CoreError>>;
}

/// Named Stream transit forwarder published on intermediate hop `H`.
pub trait StreamTransitHandler: Send + Sync + 'static {
    /// Returns the outbound carrier's capabilities and live MTU watch.
    fn caps(&self) -> ChannelCaps;

    /// Opens an outbound stream toward the next hop for `target` (the exact name or matched prefix suffix).
    fn open<'a>(
        &'a self,
        target: &'a str,
        auth: SessionAuth,
    ) -> BoxFuture<'a, Result<BoxedStream, CoreError>>;
}

/// Named Datagram transit forwarder published on intermediate hop `H`.
///
/// Designed to return shared 1:N neighbor [`DatagramLink`] handles multiplexed by `DatagramPort`.
pub trait DatagramTransitHandler: Send + Sync + 'static {
    /// Returns the outbound carrier's capabilities and live MTU watch.
    fn caps(&self) -> ChannelCaps;

    /// Opens or returns a shared outbound datagram link toward the next hop for `target`.
    fn open<'a>(
        &'a self,
        target: &'a str,
        auth: SessionAuth,
    ) -> BoxFuture<'a, Result<Arc<dyn DatagramLink>, CoreError>>;
}

/// Built-in transit handler binding a pure carrier to one fixed opaque locator (ignoring `target`).
pub struct StaticTransit<C> {
    carrier: Arc<C>,
    locator: Vec<u8>,
}

impl<C> StaticTransit<C> {
    /// Creates a `StaticTransit` forwarding every admitted circuit to `locator` over `carrier`.
    #[must_use]
    pub fn new(carrier: Arc<C>, locator: impl Into<Vec<u8>>) -> Self {
        Self {
            carrier,
            locator: locator.into(),
        }
    }

    /// Returns the configured fixed locator bytes.
    #[must_use]
    pub fn locator(&self) -> &[u8] {
        &self.locator
    }
}

impl<C: StreamCarrier> StreamTransitHandler for StaticTransit<C> {
    fn caps(&self) -> ChannelCaps {
        self.carrier.caps()
    }

    fn open<'a>(
        &'a self,
        _target: &'a str,
        _auth: SessionAuth,
    ) -> BoxFuture<'a, Result<BoxedStream, CoreError>> {
        Box::pin(async move {
            let stream = self.carrier.dial_stream(&self.locator).await?;
            Ok(BoxedStream::from_stream(stream))
        })
    }
}

impl<C: DatagramCarrier> DatagramTransitHandler for StaticTransit<C> {
    fn caps(&self) -> ChannelCaps {
        self.carrier.caps()
    }

    fn open<'a>(
        &'a self,
        _target: &'a str,
        _auth: SessionAuth,
    ) -> BoxFuture<'a, Result<Arc<dyn DatagramLink>, CoreError>> {
        Box::pin(async move {
            let link = self.carrier.open_link(&self.locator).await?;
            Ok(Arc::new(link) as Arc<dyn DatagramLink>)
        })
    }
}

/// Built-in transit handler forwarding `target.as_bytes()` directly as the carrier locator.
pub struct DynamicTransit<C> {
    carrier: Arc<C>,
}

impl<C> DynamicTransit<C> {
    /// Creates a `DynamicTransit` routing each admitted `target` suffix to `carrier`.
    #[must_use]
    pub fn new(carrier: Arc<C>) -> Self {
        Self { carrier }
    }
}

impl<C: StreamCarrier> StreamTransitHandler for DynamicTransit<C> {
    fn caps(&self) -> ChannelCaps {
        self.carrier.caps()
    }

    fn open<'a>(
        &'a self,
        target: &'a str,
        _auth: SessionAuth,
    ) -> BoxFuture<'a, Result<BoxedStream, CoreError>> {
        Box::pin(async move {
            let stream = self.carrier.dial_stream(target.as_bytes()).await?;
            Ok(BoxedStream::from_stream(stream))
        })
    }
}

impl<C: DatagramCarrier> DatagramTransitHandler for DynamicTransit<C> {
    fn caps(&self) -> ChannelCaps {
        self.carrier.caps()
    }

    fn open<'a>(
        &'a self,
        target: &'a str,
        _auth: SessionAuth,
    ) -> BoxFuture<'a, Result<Arc<dyn DatagramLink>, CoreError>> {
        Box::pin(async move {
            let link = self.carrier.open_link(target.as_bytes()).await?;
            Ok(Arc::new(link) as Arc<dyn DatagramLink>)
        })
    }
}
