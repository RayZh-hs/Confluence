use confluence_core::{EndpointName, Node, PeerId, Result, ScopeId};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// Publishes a Stream endpoint in a `TrustScope` and forwards each authenticated inbound
/// `ConfluenceStream` to a local TCP `target_addr` (Seam 4 Inbound Stream Adapter).
///
/// Upholds Cleanroom Invariant #4: `TcpStream::connect(target_addr)` only executes *after*
/// end-to-end authentication and `OpenEndpoint` authorization have succeeded.
pub struct TcpInboundForwarder {
    stop_tx: watch::Sender<bool>,
}

impl TcpInboundForwarder {
    pub fn start(
        node: &Arc<Node>,
        scope: &ScopeId,
        endpoint: EndpointName,
        local_target: SocketAddr,
    ) -> Result<Self> {
        let mut published = node.publish_stream_endpoint(scope, endpoint)?;
        let (stop_tx, mut stop_rx) = watch::channel(false);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop_rx.changed() => {
                        published.unpublish();
                        break;
                    }
                    inbound_res = published.accept() => {
                        let Ok(mut inbound) = inbound_res else { break; };
                        tokio::spawn(async move {
                            let Ok(mut local_tcp) = TcpStream::connect(local_target).await else {
                                let _ = inbound.stream.close().await;
                                return;
                            };
                            let _ = local_tcp.set_nodelay(true);
                            let _ = tokio::io::copy_bidirectional(&mut inbound.stream, &mut local_tcp).await;
                            let _ = inbound.stream.close().await;
                        });
                    }
                }
            }
        });

        Ok(Self { stop_tx })
    }

    pub fn stop(self) {
        let _ = self.stop_tx.send(true);
    }
}

/// Binds a local TCP listener on `listen_addr` and tunnels each accepted local connection over
/// Confluence's Stream Plane to `(scope, target_peer, endpoint)` (Seam 4 Outbound Stream Adapter).
pub struct TcpOutboundForwarder {
    local_addr: SocketAddr,
    stop_tx: watch::Sender<bool>,
}

impl TcpOutboundForwarder {
    pub async fn bind(
        listen_addr: SocketAddr,
        node: Arc<Node>,
        scope: ScopeId,
        target_peer: PeerId,
        endpoint: EndpointName,
    ) -> Result<Self> {
        let listener = TcpListener::bind(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        let (stop_tx, mut stop_rx) = watch::channel(false);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop_rx.changed() => break,
                    accept_res = listener.accept() => {
                        let Ok((mut local_tcp, _)) = accept_res else { break; };
                        let _ = local_tcp.set_nodelay(true);
                        let n = Arc::clone(&node);
                        let sc = scope.clone();
                        let ep = endpoint.clone();
                        tokio::spawn(async move {
                            let Ok(mut remote_stream) = n.open_stream(&sc, target_peer, ep).await else {
                                return;
                            };
                            let _ = tokio::io::copy_bidirectional(&mut local_tcp, &mut remote_stream).await;
                            let _ = remote_stream.close().await;
                        });
                    }
                }
            }
        });

        Ok(Self {
            local_addr,
            stop_tx,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn stop(self) {
        let _ = self.stop_tx.send(true);
    }
}
