use crate::datagram_session::ConfluenceDatagramSession;
use crate::error::{CoreError, Result};
use crate::seams::access::AccessControl;
use crate::seams::edge::InboundStream;
use crate::security::cookie::CookieProtector;
use crate::security::replay::{Tai64nGenerator, Tai64nReplayWindow};
use crate::stream_session::ConfluenceStream;
use crate::types::{EndpointName, PeerId, ScopeId, StaticKeypair, TargetTag};
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

pub(crate) struct RegisteredStreamEndpoint {
    pub tx: mpsc::Sender<InboundStream<ConfluenceStream>>,
    pub unpublish_rx: watch::Receiver<bool>,
}

pub(crate) struct RegisteredDatagramEndpoint {
    pub tx: mpsc::Sender<Arc<ConfluenceDatagramSession>>,
    pub unpublish_rx: watch::Receiver<bool>,
}

/// Listener handle returned when publishing a Stream endpoint within a `TrustScope`.
/// Dropping or calling `unpublish()` immediately unpublishes the endpoint and terminates
/// all active streams bound to it (Cleanroom Invariant #9).
pub struct PublishedStreamEndpoint {
    scope_id: ScopeId,
    endpoint: EndpointName,
    rx: mpsc::Receiver<InboundStream<ConfluenceStream>>,
    registry: Arc<EndpointRegistry>,
    unpublish_tx: watch::Sender<bool>,
    unpublished: bool,
}

impl PublishedStreamEndpoint {
    pub fn scope(&self) -> &ScopeId {
        &self.scope_id
    }

    pub fn endpoint(&self) -> &EndpointName {
        &self.endpoint
    }

    /// Awaits the next authenticated and authorized inbound `ConfluenceStream`.
    pub async fn accept(&mut self) -> Result<InboundStream<ConfluenceStream>> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| CoreError::Closed("stream endpoint unpublished".into()))
    }

    /// Explicitly unpublishes this endpoint and immediately tears down all bound streams.
    pub fn unpublish(mut self) {
        self.do_unpublish();
    }

    fn do_unpublish(&mut self) {
        if !self.unpublished {
            self.unpublished = true;
            self.registry.stream_endpoints.remove(&self.endpoint);
            let _ = self.unpublish_tx.send(true);
        }
    }
}

impl Drop for PublishedStreamEndpoint {
    fn drop(&mut self) {
        self.do_unpublish();
    }
}

/// Listener handle returned when publishing a Datagram endpoint within a `TrustScope`.
/// Dropping or calling `unpublish()` immediately unpublishes the endpoint and terminates
/// all active datagram sessions bound to it (Cleanroom Invariant #9).
pub struct PublishedDatagramEndpoint {
    scope_id: ScopeId,
    endpoint: EndpointName,
    rx: mpsc::Receiver<Arc<ConfluenceDatagramSession>>,
    registry: Arc<EndpointRegistry>,
    unpublish_tx: watch::Sender<bool>,
    unpublished: bool,
}

impl PublishedDatagramEndpoint {
    pub fn scope(&self) -> &ScopeId {
        &self.scope_id
    }

    pub fn endpoint(&self) -> &EndpointName {
        &self.endpoint
    }

    /// Awaits the next authenticated and authorized inbound `ConfluenceDatagramSession`.
    pub async fn accept(&mut self) -> Result<Arc<ConfluenceDatagramSession>> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| CoreError::Closed("datagram endpoint unpublished".into()))
    }

    /// Explicitly unpublishes this endpoint and immediately tears down all bound sessions.
    pub fn unpublish(mut self) {
        self.do_unpublish();
    }

    fn do_unpublish(&mut self) {
        if !self.unpublished {
            self.unpublished = true;
            self.registry.datagram_endpoints.remove(&self.endpoint);
            let _ = self.unpublish_tx.send(true);
        }
    }
}

impl Drop for PublishedDatagramEndpoint {
    fn drop(&mut self) {
        self.do_unpublish();
    }
}

/// Per-scope registry of explicitly published Stream and Datagram endpoints.
/// Everything else on the host is unreachable by default.
#[derive(Default)]
pub struct EndpointRegistry {
    pub(crate) stream_endpoints: DashMap<EndpointName, RegisteredStreamEndpoint>,
    pub(crate) datagram_endpoints: DashMap<EndpointName, RegisteredDatagramEndpoint>,
}

/// An isolated Trust Scope mounted on a `Node`, holding its own cryptographic keypair,
/// `AccessControl` verifier, pre-auth DoS cookie protector, TAI64N replay window, and `EndpointRegistry`.
pub struct TrustScope {
    id: ScopeId,
    keypair: StaticKeypair,
    access: Arc<dyn AccessControl>,
    cookie_protector: CookieProtector,
    replay_window: Tai64nReplayWindow,
    ts_gen: Tai64nGenerator,
    endpoints: Arc<EndpointRegistry>,
}

impl TrustScope {
    pub fn new(id: ScopeId, keypair: StaticKeypair, access: Arc<dyn AccessControl>) -> Arc<Self> {
        let peer_id = keypair.peer_id();
        Arc::new(Self {
            id,
            keypair,
            access,
            cookie_protector: CookieProtector::new(peer_id, Duration::from_secs(120)),
            replay_window: Tai64nReplayWindow::default(),
            ts_gen: Tai64nGenerator::new(),
            endpoints: Arc::new(EndpointRegistry::default()),
        })
    }

    pub fn id(&self) -> &ScopeId {
        &self.id
    }

    pub fn peer_id(&self) -> PeerId {
        self.keypair.peer_id()
    }

    pub fn target_tag(&self) -> TargetTag {
        self.keypair.target_tag()
    }

    pub fn keypair(&self) -> &StaticKeypair {
        &self.keypair
    }

    pub fn access(&self) -> &Arc<dyn AccessControl> {
        &self.access
    }

    pub fn cookie_protector(&self) -> &CookieProtector {
        &self.cookie_protector
    }

    pub(crate) fn replay_window(&self) -> &Tai64nReplayWindow {
        &self.replay_window
    }

    pub(crate) fn next_timestamp(&self) -> crate::security::replay::Tai64nTimestamp {
        self.ts_gen.next()
    }

    pub(crate) fn endpoints(&self) -> &Arc<EndpointRegistry> {
        &self.endpoints
    }

    /// Publishes `endpoint` on the Stream Plane within this scope.
    pub fn publish_stream_endpoint(
        &self,
        endpoint: EndpointName,
    ) -> Result<PublishedStreamEndpoint> {
        if self.endpoints.stream_endpoints.contains_key(&endpoint) {
            return Err(CoreError::InvalidInput(format!(
                "stream endpoint '{endpoint}' already published in scope '{}'",
                self.id
            )));
        }
        let (tx, rx) = mpsc::channel(128);
        let (unpublish_tx, unpublish_rx) = watch::channel(false);
        self.endpoints.stream_endpoints.insert(
            endpoint.clone(),
            RegisteredStreamEndpoint { tx, unpublish_rx },
        );
        Ok(PublishedStreamEndpoint {
            scope_id: self.id.clone(),
            endpoint,
            rx,
            registry: Arc::clone(&self.endpoints),
            unpublish_tx,
            unpublished: false,
        })
    }

    /// Publishes `endpoint` on the Datagram Plane within this scope.
    pub fn publish_datagram_endpoint(
        &self,
        endpoint: EndpointName,
    ) -> Result<PublishedDatagramEndpoint> {
        if self.endpoints.datagram_endpoints.contains_key(&endpoint) {
            return Err(CoreError::InvalidInput(format!(
                "datagram endpoint '{endpoint}' already published in scope '{}'",
                self.id
            )));
        }
        let (tx, rx) = mpsc::channel(128);
        let (unpublish_tx, unpublish_rx) = watch::channel(false);
        self.endpoints.datagram_endpoints.insert(
            endpoint.clone(),
            RegisteredDatagramEndpoint { tx, unpublish_rx },
        );
        Ok(PublishedDatagramEndpoint {
            scope_id: self.id.clone(),
            endpoint,
            rx,
            registry: Arc::clone(&self.endpoints),
            unpublish_tx,
            unpublished: false,
        })
    }
}
