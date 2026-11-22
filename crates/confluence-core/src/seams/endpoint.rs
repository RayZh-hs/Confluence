//! Seam 4: Target Handlers — local Endpoints (invoked after 1.0 RTT confirmation) and named
//! Transits (forwarding exits hiding downstream carrier stacks and locators from originators).

use std::{future::Future, sync::Arc};

use crate::{
    AsyncStream, BoxFut, ChannelCaps, CoreErr, DatagramChannel, DatagramLink, DynAsyncStream,
    IntoDynDatagramLink, SessionAuth, StreamChannel,
};

/// Opens a local Stream service once Originator `auth.peer` has been mutually authenticated,
/// authorized, and replay-confirmed at `t = 1.0 RTT`.
pub trait StreamEndpointHandler: Send + Sync + 'static {
    type Stream: AsyncStream;

    fn open(
        &self,
        auth: SessionAuth,
    ) -> impl Future<Output = Result<Self::Stream, CoreErr>> + Send + '_;
}

/// Opens a local Datagram service once Originator `auth.peer` has been mutually authenticated,
/// authorized, and replay-confirmed at `t = 1.0 RTT`.
pub trait DatagramEndpointHandler: Send + Sync + 'static {
    type Link: IntoDynDatagramLink;

    fn open(
        &self,
        auth: SessionAuth,
    ) -> impl Future<Output = Result<Self::Link, CoreErr>> + Send + '_;
}

/// Dyn-safe boundary trait erased once when publishing a [`StreamEndpointHandler`].
pub trait DynStreamEndpointHandler: Send + Sync + 'static {
    fn dyn_open(&self, auth: SessionAuth) -> BoxFut<'_, Result<Box<dyn DynAsyncStream>, CoreErr>>;
}

impl<H: StreamEndpointHandler> DynStreamEndpointHandler for H {
    fn dyn_open(&self, auth: SessionAuth) -> BoxFut<'_, Result<Box<dyn DynAsyncStream>, CoreErr>> {
        Box::pin(async move {
            let stream = StreamEndpointHandler::open(self, auth).await?;
            Ok(stream.into_dyn_stream())
        })
    }
}

/// Dyn-safe boundary trait erased once when publishing a [`DatagramEndpointHandler`].
pub trait DynDatagramEndpointHandler: Send + Sync + 'static {
    fn dyn_open(&self, auth: SessionAuth) -> BoxFut<'_, Result<Arc<dyn DatagramLink>, CoreErr>>;
}

impl<H: DatagramEndpointHandler> DynDatagramEndpointHandler for H {
    fn dyn_open(&self, auth: SessionAuth) -> BoxFut<'_, Result<Arc<dyn DatagramLink>, CoreErr>> {
        Box::pin(async move {
            let link = DatagramEndpointHandler::open(self, auth).await?;
            Ok(link.into_dyn_link())
        })
    }
}

/// Opens an outbound next-hop Stream for an authorized named Transit target.
///
/// For exact-name publications (`publish_stream_transit("to-prod", ...)`), `target` is the
/// full target name. For prefix publications (`publish_stream_transit_prefix("relay/", ...)`),
/// `target` is the suffix after the matched prefix (e.g., `"bob-presence"`).
pub trait StreamTransitHandler: Send + Sync + 'static {
    type Stream: AsyncStream;

    fn caps(&self) -> ChannelCaps;

    fn open<'a>(
        &'a self,
        target: &'a str,
        auth: SessionAuth,
    ) -> impl Future<Output = Result<Self::Stream, CoreErr>> + Send + 'a;
}

/// Resolves an outbound next-hop Datagram link for an authorized named Transit target.
///
/// Unlike [`StreamTransitHandler`] (which opens a dedicated 1:1 stream per circuit), datagram
/// carriers naturally share a **1:N multiplexed [`DatagramLink`]** across many circuits via Core's
/// `DatagramPort` and per-link generational `Cid`s (e.g., native UDP sockets, NAT passive relays,
/// P2P links). Implementations should select or return the appropriate outbound neighbor link
/// (optionally consulting `auth` for policy-based routing) rather than wrapping a shared link with
/// per-circuit state; per-circuit QoS, quotas, and concurrency caps belong on [`crate::Lease`].
pub trait DatagramTransitHandler: Send + Sync + 'static {
    type Link: IntoDynDatagramLink;

    fn caps(&self) -> ChannelCaps;

    fn open<'a>(
        &'a self,
        target: &'a str,
        auth: SessionAuth,
    ) -> impl Future<Output = Result<Self::Link, CoreErr>> + Send + 'a;
}

/// Dyn-safe boundary trait erased once when publishing a [`StreamTransitHandler`].
pub trait DynStreamTransitHandler: Send + Sync + 'static {
    fn dyn_caps(&self) -> ChannelCaps;
    fn dyn_open<'a>(
        &'a self,
        target: &'a str,
        auth: SessionAuth,
    ) -> BoxFut<'a, Result<Box<dyn DynAsyncStream>, CoreErr>>;
}

impl<H: StreamTransitHandler> DynStreamTransitHandler for H {
    fn dyn_caps(&self) -> ChannelCaps {
        StreamTransitHandler::caps(self)
    }

    fn dyn_open<'a>(
        &'a self,
        target: &'a str,
        auth: SessionAuth,
    ) -> BoxFut<'a, Result<Box<dyn DynAsyncStream>, CoreErr>> {
        Box::pin(async move {
            let stream = StreamTransitHandler::open(self, target, auth).await?;
            Ok(stream.into_dyn_stream())
        })
    }
}

/// Dyn-safe boundary trait erased once when publishing a [`DatagramTransitHandler`].
pub trait DynDatagramTransitHandler: Send + Sync + 'static {
    fn dyn_caps(&self) -> ChannelCaps;
    fn dyn_open<'a>(
        &'a self,
        target: &'a str,
        auth: SessionAuth,
    ) -> BoxFut<'a, Result<Arc<dyn DatagramLink>, CoreErr>>;
}

impl<H: DatagramTransitHandler> DynDatagramTransitHandler for H {
    fn dyn_caps(&self) -> ChannelCaps {
        DatagramTransitHandler::caps(self)
    }

    fn dyn_open<'a>(
        &'a self,
        target: &'a str,
        auth: SessionAuth,
    ) -> BoxFut<'a, Result<Arc<dyn DatagramLink>, CoreErr>> {
        Box::pin(async move {
            let link = DatagramTransitHandler::open(self, target, auth).await?;
            Ok(link.into_dyn_link())
        })
    }
}

/// Named transit adapter binding a private outbound channel `C` to one fixed downstream `locator`.
///
/// Originators only name the published transit (e.g., `"to-prod"`); they never learn or control
/// the underlying carrier type, link encryption keys, or downstream network address.
pub struct StaticTransit<C> {
    channel: C,
    locator: Vec<u8>,
}

impl<C> StaticTransit<C> {
    /// Creates a fixed-destination transit forwarding onto `channel` at `locator`.
    pub fn new(channel: C, locator: impl Into<Vec<u8>>) -> Self {
        Self {
            channel,
            locator: locator.into(),
        }
    }

    /// Returns a reference to the wrapped channel.
    pub fn channel(&self) -> &C {
        &self.channel
    }
}

impl<C: StreamChannel> StreamTransitHandler for StaticTransit<C> {
    type Stream = C::Stream;

    fn caps(&self) -> ChannelCaps {
        self.channel.caps()
    }

    fn open<'a>(
        &'a self,
        _target: &'a str,
        _auth: SessionAuth,
    ) -> impl Future<Output = Result<Self::Stream, CoreErr>> + Send + 'a {
        self.channel.dial_stream(&self.locator)
    }
}

impl<C: DatagramChannel> DatagramTransitHandler for StaticTransit<C> {
    type Link = C::Link;

    fn caps(&self) -> ChannelCaps {
        self.channel.caps()
    }

    fn open<'a>(
        &'a self,
        _target: &'a str,
        _auth: SessionAuth,
    ) -> impl Future<Output = Result<Self::Link, CoreErr>> + Send + 'a {
        self.channel.open_link(&self.locator)
    }
}

/// Opt-in transit adapter forwarding the matched UTF-8 target string directly as the inner
/// channel's `locator` bytes (useful for prefix-mounted presence relays or explicitly filtered
/// dynamic egresses).
pub struct DynamicTransit<C>(pub C);

impl<C: StreamChannel> StreamTransitHandler for DynamicTransit<C> {
    type Stream = C::Stream;

    fn caps(&self) -> ChannelCaps {
        self.0.caps()
    }

    fn open<'a>(
        &'a self,
        target: &'a str,
        _auth: SessionAuth,
    ) -> impl Future<Output = Result<Self::Stream, CoreErr>> + Send + 'a {
        self.0.dial_stream(target.as_bytes())
    }
}

impl<C: DatagramChannel> DatagramTransitHandler for DynamicTransit<C> {
    type Link = C::Link;

    fn caps(&self) -> ChannelCaps {
        self.0.caps()
    }

    fn open<'a>(
        &'a self,
        target: &'a str,
        _auth: SessionAuth,
    ) -> impl Future<Output = Result<Self::Link, CoreErr>> + Send + 'a {
        self.0.open_link(target.as_bytes())
    }
}
