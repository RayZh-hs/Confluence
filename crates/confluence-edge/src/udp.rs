use confluence_core::seams::edge::DatagramSession;
use confluence_core::{ConfluenceDatagramSession, EndpointName, Node, PeerId, Result, ScopeId};
use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::watch;

/// Publishes a Datagram endpoint in a `TrustScope` and forwards discrete messages for each
/// authenticated `ConfluenceDatagramSession` to a local UDP `target_addr` via a per-session
/// ephemeral local UDP socket (Seam 4 Inbound Datagram Adapter).
pub struct UdpInboundForwarder {
    stop_tx: watch::Sender<bool>,
}

impl UdpInboundForwarder {
    pub fn start(
        node: &Arc<Node>,
        scope: &ScopeId,
        endpoint: EndpointName,
        local_target: SocketAddr,
    ) -> Result<Self> {
        let mut published = node.publish_datagram_endpoint(scope, endpoint)?;
        let (stop_tx, mut stop_rx) = watch::channel(false);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop_rx.changed() => {
                        published.unpublish();
                        break;
                    }
                    accept_res = published.accept() => {
                        let Ok(session) = accept_res else { break; };
                        let child_stop = stop_rx.clone();
                        tokio::spawn(async move {
                            let bind_ip = match local_target.ip() {
                                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
                            };
                            let Ok(local_sock) = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await else {
                                let _ = session.close().await;
                                return;
                            };
                            if local_sock.connect(local_target).await.is_err() {
                                let _ = session.close().await;
                                return;
                            }
                            let sock = Arc::new(local_sock);
                            let sock_rx = Arc::clone(&sock);
                            let sess_tx = Arc::clone(&session);
                            let mut stop_a = child_stop.clone();

                            // Local UDP service -> Confluence E2E Datagram Session
                            let reverse_task = tokio::spawn(async move {
                                let mut buf = vec![0u8; 65536];
                                loop {
                                    tokio::select! {
                                        _ = stop_a.changed() => break,
                                        res = sock_rx.recv(&mut buf) => {
                                            let Ok(n) = res else { break; };
                                            if sess_tx.send(&buf[..n]).await.is_err() {
                                                break;
                                            }
                                        }
                                    }
                                }
                            });

                            // Confluence E2E Datagram Session -> Local UDP service
                            let mut stop_b = child_stop;
                            loop {
                                tokio::select! {
                                    _ = stop_b.changed() => break,
                                    res = session.recv() => {
                                        let Ok(pkt) = res else { break; };
                                        if sock.send(&pkt).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                            reverse_task.abort();
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

/// Binds a local UDP socket on `listen_addr` and maps each local UDP client `SocketAddr` to an
/// end-to-end `ConfluenceDatagramSession` targeting `(scope, target_peer, endpoint)` (Seam 4 Outbound Datagram Adapter).
pub struct UdpOutboundForwarder {
    local_addr: SocketAddr,
    stop_tx: watch::Sender<bool>,
}

impl UdpOutboundForwarder {
    pub async fn bind(
        listen_addr: SocketAddr,
        node: Arc<Node>,
        scope: ScopeId,
        target_peer: PeerId,
        endpoint: EndpointName,
    ) -> Result<Self> {
        let sock = Arc::new(UdpSocket::bind(listen_addr).await?);
        let local_addr = sock.local_addr()?;
        let (stop_tx, mut stop_rx) = watch::channel(false);
        let client_sessions: Arc<DashMap<SocketAddr, Arc<ConfluenceDatagramSession>>> =
            Arc::new(DashMap::new());

        let sock_loop = Arc::clone(&sock);
        let sessions_loop = Arc::clone(&client_sessions);

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                tokio::select! {
                    _ = stop_rx.changed() => break,
                    recv_res = sock_loop.recv_from(&mut buf) => {
                        let Ok((n, client_sa)) = recv_res else { break; };
                        let payload = buf[..n].to_vec();

                        if let Some(existing) = sessions_loop.get(&client_sa).map(|r| Arc::clone(r.value())) {
                            if existing.send(&payload).await.is_ok() {
                                continue;
                            }
                            sessions_loop.remove(&client_sa);
                        }

                        let n_open = Arc::clone(&node);
                        let sc = scope.clone();
                        let ep = endpoint.clone();
                        let map_ref = Arc::clone(&sessions_loop);
                        let sock_reply = Arc::clone(&sock_loop);
                        let mut child_stop = stop_rx.clone();

                        tokio::spawn(async move {
                            let Ok(sess) = n_open.open_datagram(&sc, target_peer, ep).await else {
                                return;
                            };
                            map_ref.insert(client_sa, Arc::clone(&sess));
                            if sess.send(&payload).await.is_err() {
                                map_ref.remove(&client_sa);
                                return;
                            }

                            loop {
                                tokio::select! {
                                    _ = child_stop.changed() => break,
                                    res = sess.recv() => {
                                        let Ok(reply) = res else { break; };
                                        if sock_reply.send_to(&reply, client_sa).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                            map_ref.remove(&client_sa);
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
