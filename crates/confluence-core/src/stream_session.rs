use crate::error::{CoreError, Result};
use crate::seams::access::{AccessControl, AccessRequest, Action, Decision};
use crate::seams::channel::BoxedAsyncStream;
use crate::security::grant::{GrantEnforcedStream, GrantEnforcer, StreamPermit};
use crate::security::noise::{split_stream_ciphers, TransportKeys, MAX_STREAM_CHUNK_BYTES};
use crate::types::{EndpointName, OpaqueCredential, PeerId, Plane, ScopeId};
use crate::wire::{DataMsgType, InBandRenewReqPayload, InBandRenewRespPayload};
use dashmap::DashMap;
use parking_lot::Mutex;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::{mpsc, oneshot, watch};

enum CtrlCmd {
    Renew {
        req_id: u64,
        credential: Option<OpaqueCredential>,
    },
    Close,
}

/// End-to-end authenticated and AEAD-protected byte stream on the Stream Plane.
///
/// - Implements `AsyncRead + AsyncWrite + Unpin + Send` for seamless Edge Adapter integration.
/// - Protects against truncation attacks: only an AEAD-authenticated `Close` record yields clean EOF;
///   an unauthenticated transport drop surfaces `ConnectionReset` honestly (Cleanroom Invariant #8).
/// - Supports live in-band Grant renewal via [`ConfluenceStream::renew`] without interrupting I/O.
pub struct ConfluenceStream {
    remote_peer: PeerId,
    scope: ScopeId,
    endpoint: EndpointName,
    app_io: DuplexStream,
    ctrl_tx: mpsc::Sender<CtrlCmd>,
    pending_renews: Arc<DashMap<u64, oneshot::Sender<Result<Duration>>>>,
    next_req_id: AtomicU64,
    enforcer: Arc<GrantEnforcer>,
    terminal_error: Arc<Mutex<Option<io::ErrorKind>>>,
    error_wait: Pin<Box<dyn Future<Output = ()> + Send + Sync>>,
}

impl ConfluenceStream {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn spawn_new(
        raw_stream: BoxedAsyncStream,
        keys: TransportKeys,
        remote_peer: PeerId,
        scope: ScopeId,
        endpoint: EndpointName,
        enforcer: Arc<GrantEnforcer>,
        permit: Option<StreamPermit>,
        responder_access: Option<Arc<dyn AccessControl>>,
        mut unpublish_rx: Option<watch::Receiver<bool>>,
    ) -> Self {
        let (app_io, mut engine_io) = tokio::io::duplex(64 * 1024);
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<CtrlCmd>(16);
        let pending_renews: Arc<DashMap<u64, oneshot::Sender<Result<Duration>>>> =
            Arc::new(DashMap::new());
        let terminal_error: Arc<Mutex<Option<io::ErrorKind>>> = Arc::new(Mutex::new(None));
        let (err_tx, mut err_rx) = watch::channel(false);

        // Hook unpublish watcher into GrantEnforcer so unpublishing immediately revokes this stream.
        if let Some(mut up_rx) = unpublish_rx.take() {
            let enf = Arc::clone(&enforcer);
            tokio::spawn(async move {
                if up_rx.wait_for(|&u| u).await.is_ok() {
                    enf.revoke();
                }
            });
        }

        let guarded_wire = GrantEnforcedStream::new(raw_stream, Arc::clone(&enforcer), permit);
        let (mut wire_rd, mut wire_wr) = tokio::io::split(guarded_wire);
        let (mut write_cipher, mut read_cipher) = split_stream_ciphers(&keys);

        let enf_task = Arc::clone(&enforcer);
        let renews_task = Arc::clone(&pending_renews);
        let err_slot_task = Arc::clone(&terminal_error);
        let scope_task = scope.clone();
        let endpoint_task = endpoint.clone();

        tokio::spawn(async move {
            let mut app_buf = vec![0u8; MAX_STREAM_CHUNK_BYTES];
            let mut len_hdr = [0u8; 2];
            let mut closed_watch = enf_task.closed_watch();
            let mut app_eof_sent = false;

            let fail_with = |kind: io::ErrorKind,
                             slot: &Mutex<Option<io::ErrorKind>>,
                             tx: &watch::Sender<bool>,
                             renews: &DashMap<u64, oneshot::Sender<Result<Duration>>>| {
                let mut g = slot.lock();
                if g.is_none() {
                    *g = Some(kind);
                }
                let _ = tx.send(true);
                renews.clear();
            };

            loop {
                if *closed_watch.borrow() {
                    fail_with(io::ErrorKind::PermissionDenied, &err_slot_task, &err_tx, &renews_task);
                    break;
                }
                tokio::select! {
                    _ = closed_watch.changed() => {
                        if *closed_watch.borrow() {
                            fail_with(io::ErrorKind::PermissionDenied, &err_slot_task, &err_tx, &renews_task);
                            break;
                        }
                    }
                    cmd = ctrl_rx.recv() => {
                        match cmd {
                            Some(CtrlCmd::Renew { req_id, credential }) => {
                                let payload = InBandRenewReqPayload { req_id, credential }.encode();
                                match write_cipher.seal_record(DataMsgType::InBandRenewReq as u8, &payload) {
                                    Ok(rec) => {
                                        if let Err(e) = wire_wr.write_all(&rec).await {
                                            fail_with(e.kind(), &err_slot_task, &err_tx, &renews_task);
                                            break;
                                        }
                                        let _ = wire_wr.flush().await;
                                    }
                                    Err(_) => {
                                        fail_with(io::ErrorKind::InvalidData, &err_slot_task, &err_tx, &renews_task);
                                        break;
                                    }
                                }
                            }
                            Some(CtrlCmd::Close) | None => {
                                if !app_eof_sent {
                                    while let Ok(n) = engine_io.read(&mut app_buf).await {
                                        if n == 0 {
                                            break;
                                        }
                                        if let Ok(rec) = write_cipher
                                            .seal_record(DataMsgType::Data as u8, &app_buf[..n])
                                        {
                                            let _ = wire_wr.write_all(&rec).await;
                                        }
                                    }
                                    if let Ok(rec) =
                                        write_cipher.seal_record(DataMsgType::Close as u8, b"")
                                    {
                                        let _ = wire_wr.write_all(&rec).await;
                                    }
                                }
                                let _ = wire_wr.flush().await;
                                let _ = wire_wr.shutdown().await;
                                break;
                            }
                        }
                    }
                    read_res = engine_io.read(&mut app_buf), if !app_eof_sent => {
                        match read_res {
                            Ok(0) => {
                                // Caller shut down write half cleanly -> send authenticated Close record!
                                app_eof_sent = true;
                                if let Ok(rec) = write_cipher.seal_record(DataMsgType::Close as u8, b"") {
                                    if let Err(e) = wire_wr.write_all(&rec).await {
                                        fail_with(e.kind(), &err_slot_task, &err_tx, &renews_task);
                                        break;
                                    }
                                    let _ = wire_wr.flush().await;
                                }
                            }
                            Ok(n) => {
                                match write_cipher.seal_record(DataMsgType::Data as u8, &app_buf[..n]) {
                                    Ok(rec) => {
                                        if let Err(e) = wire_wr.write_all(&rec).await {
                                            fail_with(e.kind(), &err_slot_task, &err_tx, &renews_task);
                                            break;
                                        }
                                        let _ = wire_wr.flush().await;
                                    }
                                    Err(_) => {
                                        fail_with(io::ErrorKind::InvalidData, &err_slot_task, &err_tx, &renews_task);
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                fail_with(e.kind(), &err_slot_task, &err_tx, &renews_task);
                                break;
                            }
                        }
                    }
                    wire_hdr_res = wire_rd.read_exact(&mut len_hdr) => {
                        match wire_hdr_res {
                            Err(e) => {
                                // Unauthenticated EOF or severed link -> honest ConnectionReset / PermissionDenied!
                                let kind = if e.kind() == io::ErrorKind::UnexpectedEof {
                                    io::ErrorKind::ConnectionReset
                                } else {
                                    e.kind()
                                };
                                fail_with(kind, &err_slot_task, &err_tx, &renews_task);
                                break;
                            }
                            Ok(_) => {
                                let cipher_len = u16::from_be_bytes(len_hdr) as usize;
                                let mut body = vec![0u8; cipher_len];
                                if let Err(e) = wire_rd.read_exact(&mut body).await {
                                    let kind = if e.kind() == io::ErrorKind::UnexpectedEof {
                                        io::ErrorKind::ConnectionReset
                                    } else {
                                        e.kind()
                                    };
                                    fail_with(kind, &err_slot_task, &err_tx, &renews_task);
                                    break;
                                }
                                let (msg_ty_raw, pt) = match read_cipher.open_record(&body) {
                                    Ok(v) => v,
                                    Err(_) => {
                                        fail_with(io::ErrorKind::InvalidData, &err_slot_task, &err_tx, &renews_task);
                                        break;
                                    }
                                };
                                let Ok(msg_ty) = DataMsgType::from_u8(msg_ty_raw) else {
                                    fail_with(io::ErrorKind::InvalidData, &err_slot_task, &err_tx, &renews_task);
                                    break;
                                };

                                match msg_ty {
                                    DataMsgType::Data => {
                                        if engine_io.write_all(&pt).await.is_err() {
                                            break;
                                        }
                                    }
                                    DataMsgType::InBandRenewReq => {
                                        let Ok(req_payload) = InBandRenewReqPayload::decode(&pt) else {
                                            fail_with(io::ErrorKind::InvalidData, &err_slot_task, &err_tx, &renews_task);
                                            break;
                                        };
                                        let resp = if let Some(ref ac) = responder_access {
                                            let ac_req = AccessRequest {
                                                scope: scope_task.clone(),
                                                peer: remote_peer,
                                                credential: req_payload.credential,
                                                action: Action::RenewGrant {
                                                    target_action: Box::new(Action::OpenEndpoint {
                                                        endpoint: endpoint_task.clone(),
                                                        plane: Plane::Stream,
                                                    }),
                                                },
                                            };
                                            match ac.evaluate(ac_req).await {
                                                Ok(Decision::Allow(new_grant)) => {
                                                    let ttl_millis = new_grant
                                                        .expires_at
                                                        .saturating_duration_since(Instant::now())
                                                        .as_millis()
                                                        .min(u64::MAX as u128) as u64;
                                                    enf_task.update_grant(new_grant);
                                                    InBandRenewRespPayload::Accepted {
                                                        req_id: req_payload.req_id,
                                                        ttl_millis,
                                                    }
                                                }
                                                Ok(Decision::Deny { reason }) => InBandRenewRespPayload::Denied {
                                                    req_id: req_payload.req_id,
                                                    reason,
                                                },
                                                Err(e) => InBandRenewRespPayload::Denied {
                                                    req_id: req_payload.req_id,
                                                    reason: e.to_string(),
                                                },
                                            }
                                        } else {
                                            InBandRenewRespPayload::Denied {
                                                req_id: req_payload.req_id,
                                                reason: "renewal only accepted by endpoint responder".into(),
                                            }
                                        };
                                        if let Ok(rec) = write_cipher.seal_record(DataMsgType::InBandRenewResp as u8, &resp.encode()) {
                                            let _ = wire_wr.write_all(&rec).await;
                                            let _ = wire_wr.flush().await;
                                        }
                                    }
                                    DataMsgType::InBandRenewResp => {
                                        if let Ok(resp) = InBandRenewRespPayload::decode(&pt) {
                                            match resp {
                                                InBandRenewRespPayload::Accepted { req_id, ttl_millis } => {
                                                    if let Some((_, waiter)) = renews_task.remove(&req_id) {
                                                        let _ = waiter.send(Ok(Duration::from_millis(ttl_millis)));
                                                    }
                                                }
                                                InBandRenewRespPayload::Denied { req_id, reason } => {
                                                    if let Some((_, waiter)) = renews_task.remove(&req_id) {
                                                        let _ = waiter.send(Err(CoreError::AccessDenied(reason)));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    DataMsgType::Close => {
                                        // Authenticated graceful EOF from remote peer!
                                        let _ = engine_io.shutdown().await;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        let error_wait = Box::pin(async move {
            let _ = err_rx.wait_for(|&failed| failed).await;
        });

        Self {
            remote_peer,
            scope,
            endpoint,
            app_io,
            ctrl_tx,
            pending_renews,
            next_req_id: AtomicU64::new(1),
            enforcer,
            terminal_error,
            error_wait,
        }
    }

    pub fn remote_peer(&self) -> PeerId {
        self.remote_peer
    }

    pub fn scope(&self) -> &ScopeId {
        &self.scope
    }

    pub fn endpoint(&self) -> &EndpointName {
        &self.endpoint
    }

    /// Renews this stream's E2E authorization Grant in-band without interrupting live stream traffic.
    pub async fn renew(&self, credential: Option<OpaqueCredential>) -> Result<()> {
        let req_id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending_renews.insert(req_id, tx);

        if self
            .ctrl_tx
            .send(CtrlCmd::Renew { req_id, credential })
            .await
            .is_err()
        {
            self.pending_renews.remove(&req_id);
            return Err(CoreError::Closed("stream already closed".into()));
        }

        let ttl = tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .map_err(|_| {
                self.pending_renews.remove(&req_id);
                CoreError::Timeout
            })?
            .map_err(|_| CoreError::Closed("stream closed during renewal".into()))??;

        self.enforcer
            .update_grant(crate::seams::access::Grant::with_ttl(ttl));
        Ok(())
    }

    /// Flushes buffered data, sends an AEAD-authenticated `Close` record, and shuts down cleanly.
    pub async fn close(&mut self) -> Result<()> {
        self.app_io.shutdown().await?;
        let _ = self.ctrl_tx.send(CtrlCmd::Close).await;
        Ok(())
    }

    fn check_terminal_error(&mut self, cx: &mut Context<'_>) -> Option<io::Error> {
        let _ = self.error_wait.as_mut().poll(cx);
        self.terminal_error
            .lock()
            .map(|kind| io::Error::new(kind, "confluence stream terminated"))
    }
}

impl std::fmt::Debug for ConfluenceStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfluenceStream")
            .field("remote_peer", &self.remote_peer)
            .field("scope", &self.scope)
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for ConfluenceStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.app_io).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                // Drain any already-decrypted buffered data first; once empty, surface terminal error if any!
                if buf.filled().len() == before {
                    if let Some(err) = self.check_terminal_error(cx) {
                        return Poll::Ready(Err(err));
                    }
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                if let Some(err) = self.check_terminal_error(cx) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}

impl AsyncWrite for ConfluenceStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(err) = self.check_terminal_error(cx) {
            return Poll::Ready(Err(err));
        }
        Pin::new(&mut self.app_io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(err) = self.check_terminal_error(cx) {
            return Poll::Ready(Err(err));
        }
        Pin::new(&mut self.app_io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.app_io).poll_shutdown(cx)
    }
}
