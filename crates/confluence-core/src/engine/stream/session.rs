//! End-to-end encrypted Stream session (`E2eStream`, `E2eStreamRead`, `E2eStreamWrite`)
//! and steady-state bidirectional worker (Spec §5.8.2, §6.4, §6.7, §6.8).

use core::fmt;
use core::future::{Future, poll_fn};
use core::pin::Pin;
use core::task::{Context, Poll};
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use futures_core::Stream as FuturesStream;
use futures_util::stream::FuturesUnordered;
use rand_core::OsRng;
use zeroize::Zeroizing;

use crate::constants::{
    CREDENTIAL_MAX, MAX_WIRE_LEASE_TTL, ST_OVERHEAD, STREAM_CHUNK,
};
use crate::crypto::cipher::{ControlCipher, StreamCipher};
use crate::engine::context::{
    CredFetchFut, Either, RenewalAuthFut, ScopeCore, SessionPermit, poll_optional, race2,
    sleep_optional, wait_mtu_below_floor, wait_shutdown, with_deadline,
};
use crate::engine::stream::framing::{
    InboundStreamFrame, PriorityCtrlFrame, StreamFrameReader, StreamWriterHandle,
};
use crate::error::CoreError;
use crate::protocol::renewal::{
    CredentialFetchOutcome, RenewalAction, RenewalDriver, RenewalSlot, RenewalVerifierState,
    VerifierRenewalAction,
};
use crate::runtime::{Clock, MonotonicTime};
use crate::runtime::sync::{Watch, WatchReceiver};
use crate::seam::auth::{AuthRequest, CredentialRequest, Lease, StreamAction};
use crate::seam::channel::{
    ChannelCaps, IntoStreamHalves, MtuWatch, StreamRead, StreamReadExt, StreamWrite,
    StreamWriteExt,
};
use crate::seam::path::PathOutcome;
use crate::trust::lease::{LeaseHandle, TrafficGateCache};
use crate::types::{Credential, Direction, Plane, PublicKey, Role, TargetRef};
use crate::wire::datagram::{
    decode_renew_ok_payload, decode_renew_payload, encode_renew_ok_payload, encode_renew_payload,
};
use crate::wire::opcodes::{decode_wire_error_bytes, e2e_st, encode_wire_error_bytes, outer};
use crate::wire::stream::StHopHeader;

// ---------------------------------------------------------------------------
// Public Stream Handles (`E2eStream`, `E2eStreamRead`, `E2eStreamWrite`)
// ---------------------------------------------------------------------------

enum AppWriteMsg {
    Data(Vec<u8>),
    Flush(async_channel::Sender<Result<(), CoreError>>),
    Shutdown(async_channel::Sender<Result<(), CoreError>>),
}

type ReadChunkRx = Pin<Box<async_channel::Receiver<Result<Vec<u8>, CoreError>>>>;
type AckRx = Pin<Box<async_channel::Receiver<Result<(), CoreError>>>>;

/// Concurrent read half of an established [`E2eStream`] (obtained via [`E2eStream::split`]).
pub struct E2eStreamRead {
    rx: ReadChunkRx,
    buf: Vec<u8>,
    pos: usize,
    eof: bool,
    closed_err: WatchReceiver<Option<CoreError>>,
    peer: PublicKey,
}

impl E2eStreamRead {
    /// Returns the authenticated remote peer's static public key.
    #[must_use]
    pub const fn peer(&self) -> PublicKey {
        self.peer
    }

    /// Reads available plaintext bytes into `buf`, returning `Ok(0)` strictly after peer `ST_FIN`.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, CoreError> {
        StreamReadExt::read(self, buf).await
    }

    /// Reads exact `buf.len()` bytes, failing with [`CoreError::UnexpectedEof`] on premature EOF.
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), CoreError> {
        StreamReadExt::read_exact(self, buf).await
    }
}

impl StreamRead for E2eStreamRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut [u8],
    ) -> Poll<Result<usize, CoreError>> {
        if dst.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.pos < self.buf.len() {
            let avail = self.buf.len() - self.pos;
            let n = avail.min(dst.len());
            dst[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            if self.pos == self.buf.len() {
                self.buf.clear();
                self.pos = 0;
            }
            return Poll::Ready(Ok(n));
        }
        if self.eof {
            return Poll::Ready(Ok(0));
        }

        match self.rx.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                if chunk.is_empty() {
                    // Empty Vec sentinel marks authenticated peer ST_FIN -> clean EOF Ok(0)!
                    self.eof = true;
                    return Poll::Ready(Ok(0));
                }
                let n = chunk.len().min(dst.len());
                dst[..n].copy_from_slice(&chunk[..n]);
                if n < chunk.len() {
                    self.buf = chunk;
                    self.pos = n;
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Err(err)),
            Poll::Ready(None) => {
                let err = self
                    .closed_err
                    .borrow_cloned()
                    .unwrap_or(CoreError::UnexpectedEof);
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl fmt::Debug for E2eStreamRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("E2eStreamRead")
            .field("peer", &self.peer)
            .field("eof", &self.eof)
            .finish()
    }
}

type PendingSendFuture =
    Pin<Box<dyn Future<Output = Result<(), async_channel::SendError<AppWriteMsg>>> + Send>>;

/// Concurrent write half of an established [`E2eStream`] (obtained via [`E2eStream::split`]).
pub struct E2eStreamWrite {
    tx: async_channel::Sender<AppWriteMsg>,
    max_write_size: usize,
    closed_err: WatchReceiver<Option<CoreError>>,
    pending_send: Option<(PendingSendFuture, usize)>,
    flush_rx: Option<AckRx>,
    shutdown_rx: Option<AckRx>,
    shutdown_done: bool,
    peer: PublicKey,
}

impl E2eStreamWrite {
    /// Returns the authenticated remote peer's static public key.
    #[must_use]
    pub const fn peer(&self) -> PublicKey {
        self.peer
    }

    /// Returns the maximum single-record E2E plaintext write size fixed at setup.
    #[must_use]
    pub const fn max_write_size(&self) -> usize {
        self.max_write_size
    }

    /// Writes some prefix of `buf`.
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, CoreError> {
        StreamWriteExt::write(self, buf).await
    }

    /// Writes all bytes in `buf` (automatically splitting across `max_write_size` records).
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), CoreError> {
        StreamWriteExt::write_all(self, buf).await
    }

    /// Flushes all previously written records through the carrier.
    pub async fn flush(&mut self) -> Result<(), CoreError> {
        StreamWriteExt::flush(self).await
    }

    /// Sends an authenticated end-to-end `ST_FIN` half-close record and flushes it.
    pub async fn shutdown(&mut self) -> Result<(), CoreError> {
        StreamWriteExt::shutdown(self).await
    }

    fn terminal_err(&self) -> CoreError {
        self.closed_err.borrow_cloned().unwrap_or(CoreError::Closed)
    }
}

impl StreamWrite for E2eStreamWrite {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, CoreError>> {
        if self.shutdown_done || self.shutdown_rx.is_some() {
            return Poll::Ready(Err(CoreError::Closed));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if let Some((mut fut, accepted_len)) = self.pending_send.take() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => return Poll::Ready(Ok(accepted_len)),
                Poll::Ready(Err(_)) => return Poll::Ready(Err(self.terminal_err())),
                Poll::Pending => {
                    self.pending_send = Some((fut, accepted_len));
                    return Poll::Pending;
                }
            }
        }

        let len = buf.len().min(self.max_write_size.max(1));
        let msg = AppWriteMsg::Data(buf[..len].to_vec());
        match self.tx.try_send(msg) {
            Ok(()) => Poll::Ready(Ok(len)),
            Err(async_channel::TrySendError::Closed(_)) => Poll::Ready(Err(self.terminal_err())),
            Err(async_channel::TrySendError::Full(msg)) => {
                let tx = self.tx.clone();
                let mut fut: PendingSendFuture = Box::pin(async move { tx.send(msg).await });
                match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(len)),
                    Poll::Ready(Err(_)) => Poll::Ready(Err(self.terminal_err())),
                    Poll::Pending => {
                        self.pending_send = Some((fut, len));
                        Poll::Pending
                    }
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
        if let Some((mut fut, len)) = self.pending_send.take() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(_)) => return Poll::Ready(Err(self.terminal_err())),
                Poll::Pending => {
                    self.pending_send = Some((fut, len));
                    return Poll::Pending;
                }
            }
        }

        if self.flush_rx.is_none() {
            let (ack_tx, ack_rx) = async_channel::bounded(1);
            match self.tx.try_send(AppWriteMsg::Flush(ack_tx)) {
                Ok(()) => self.flush_rx = Some(Box::pin(ack_rx)),
                Err(async_channel::TrySendError::Closed(_)) => {
                    return Poll::Ready(Err(self.terminal_err()));
                }
                Err(async_channel::TrySendError::Full(msg)) => {
                    let tx = self.tx.clone();
                    let mut fut: PendingSendFuture = Box::pin(async move { tx.send(msg).await });
                    match fut.as_mut().poll(cx) {
                        Poll::Ready(Ok(())) => self.flush_rx = Some(Box::pin(ack_rx)),
                        Poll::Ready(Err(_)) => return Poll::Ready(Err(self.terminal_err())),
                        Poll::Pending => {
                            self.pending_send = Some((fut, 0));
                            self.flush_rx = Some(Box::pin(ack_rx));
                            return Poll::Pending;
                        }
                    }
                }
            }
        }

        if let Some(rx) = self.flush_rx.as_mut() {
            match rx.as_mut().poll_next(cx) {
                Poll::Ready(Some(res)) => {
                    self.flush_rx = None;
                    Poll::Ready(res)
                }
                Poll::Ready(None) => {
                    self.flush_rx = None;
                    Poll::Ready(Err(self.terminal_err()))
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
        if self.shutdown_done {
            return Poll::Ready(Ok(()));
        }
        if let Some((mut fut, len)) = self.pending_send.take() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(_)) => return Poll::Ready(Err(self.terminal_err())),
                Poll::Pending => {
                    self.pending_send = Some((fut, len));
                    return Poll::Pending;
                }
            }
        }

        if self.shutdown_rx.is_none() {
            let (ack_tx, ack_rx) = async_channel::bounded(1);
            match self.tx.try_send(AppWriteMsg::Shutdown(ack_tx)) {
                Ok(()) => self.shutdown_rx = Some(Box::pin(ack_rx)),
                Err(async_channel::TrySendError::Closed(_)) => {
                    // If session already closed cleanly after both FINs, report Ok(()).
                    if self.closed_err.borrow_cloned() == Some(CoreError::Closed) {
                        self.shutdown_done = true;
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(self.terminal_err()));
                }
                Err(async_channel::TrySendError::Full(msg)) => {
                    let tx = self.tx.clone();
                    let mut fut: PendingSendFuture = Box::pin(async move { tx.send(msg).await });
                    match fut.as_mut().poll(cx) {
                        Poll::Ready(Ok(())) => self.shutdown_rx = Some(Box::pin(ack_rx)),
                        Poll::Ready(Err(_)) => return Poll::Ready(Err(self.terminal_err())),
                        Poll::Pending => {
                            self.pending_send = Some((fut, 0));
                            self.shutdown_rx = Some(Box::pin(ack_rx));
                            return Poll::Pending;
                        }
                    }
                }
            }
        }

        if let Some(rx) = self.shutdown_rx.as_mut() {
            match rx.as_mut().poll_next(cx) {
                Poll::Ready(Some(res)) => {
                    self.shutdown_rx = None;
                    if res.is_ok() {
                        self.shutdown_done = true;
                    }
                    Poll::Ready(res)
                }
                Poll::Ready(None) => {
                    self.shutdown_rx = None;
                    if self.closed_err.borrow_cloned() == Some(CoreError::Closed) {
                        self.shutdown_done = true;
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Ready(Err(self.terminal_err()))
                    }
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

impl fmt::Debug for E2eStreamWrite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("E2eStreamWrite")
            .field("peer", &self.peer)
            .field("max_write_size", &self.max_write_size)
            .field("shutdown_done", &self.shutdown_done)
            .finish()
    }
}

/// Established end-to-end encrypted bidirectional byte stream (Stream Plane).
///
/// Supports direct async I/O (`read`, `write_all`, `shutdown`) as well as zero-cost concurrent
/// splitting via [`Self::split`] into independent [`E2eStreamRead`] and [`E2eStreamWrite`] halves.
pub struct E2eStream {
    read: E2eStreamRead,
    write: E2eStreamWrite,
    negotiated_mtu: u16,
    max_write_size: usize,
    peer: PublicKey,
}

impl E2eStream {
    /// Splits this stream into independent concurrent read and write halves (Refinement #4).
    #[must_use]
    pub fn split(self) -> (E2eStreamRead, E2eStreamWrite) {
        (self.read, self.write)
    }

    /// Returns the authenticated remote peer's static public key.
    #[must_use]
    pub const fn peer(&self) -> PublicKey {
        self.peer
    }

    /// Returns the authenticated wire MTU fixed at setup.
    #[must_use]
    pub const fn mtu(&self) -> u16 {
        self.negotiated_mtu
    }

    /// Returns the maximum single-record E2E plaintext write size fixed at setup.
    #[must_use]
    pub const fn max_write_size(&self) -> usize {
        self.max_write_size
    }

    /// Reads available plaintext bytes into `buf`, returning `Ok(0)` strictly after peer `ST_FIN`.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, CoreError> {
        self.read.read(buf).await
    }

    /// Reads exact `buf.len()` bytes, failing with [`CoreError::UnexpectedEof`] on premature EOF.
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), CoreError> {
        self.read.read_exact(buf).await
    }

    /// Writes some prefix of `buf`.
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, CoreError> {
        self.write.write(buf).await
    }

    /// Writes all bytes in `buf`.
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), CoreError> {
        self.write.write_all(buf).await
    }

    /// Flushes all buffered writes to the carrier.
    pub async fn flush(&mut self) -> Result<(), CoreError> {
        self.write.flush().await
    }

    /// Sends an authenticated end-to-end `ST_FIN` half-close record and flushes it.
    pub async fn shutdown(&mut self) -> Result<(), CoreError> {
        self.write.shutdown().await
    }
}

impl StreamRead for E2eStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, CoreError>> {
        Pin::new(&mut self.read).poll_read(cx, buf)
    }
}

impl StreamWrite for E2eStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, CoreError>> {
        Pin::new(&mut self.write).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
        Pin::new(&mut self.write).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), CoreError>> {
        Pin::new(&mut self.write).poll_shutdown(cx)
    }
}

impl IntoStreamHalves for E2eStream {
    type Read = E2eStreamRead;
    type Write = E2eStreamWrite;

    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(self.negotiated_mtu, true)
    }

    fn into_halves(self) -> (Self::Read, Self::Write) {
        self.split()
    }
}

impl fmt::Debug for E2eStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("E2eStream")
            .field("peer", &self.peer)
            .field("mtu", &self.negotiated_mtu)
            .field("max_write_size", &self.max_write_size)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Stream Session Role Configuration & Spawner
// ---------------------------------------------------------------------------

pub(crate) struct OriginStreamMeta {
    pub path_id: u64,
    pub endpoint: String,
    pub hops: Vec<(PublicKey, String, ControlCipher)>,
    pub terminal_ctrl: ControlCipher,
    pub renewals: RenewalDriver,
}

pub(crate) struct DestStreamMeta {
    pub endpoint: String,
    pub terminal_ctrl: ControlCipher,
    pub first_data: Option<Vec<u8>>,
}

pub(crate) enum StreamSessionRole {
    Origin(OriginStreamMeta),
    Destination(DestStreamMeta),
}

pub(crate) struct StreamSessionParams {
    pub scope: Arc<ScopeCore>,
    pub peer: PublicKey,
    pub negotiated_mtu: u16,
    pub floor: u16,
    pub reader: Box<dyn StreamRead>,
    pub frame_reader: StreamFrameReader,
    pub writer: Box<dyn StreamWrite>,
    pub mtu_watch: MtuWatch,
    pub tx_cipher: StreamCipher,
    pub rx_cipher: StreamCipher,
    pub lease: Arc<LeaseHandle>,
    pub session_permit: SessionPermit,
    pub role: StreamSessionRole,
}

enum InboundCtrlMsg {
    HopControl {
        hdr: StHopHeader,
        body: [u8; crate::constants::MAX_CONTROL],
        len: usize,
    },
    E2eRenew(Zeroizing<Vec<u8>>),
    E2eRenewOk(Vec<u8>),
    ReadError(CoreError),
}

enum InboundDataMsg {
    Data(Vec<u8>),
    Fin,
    CarrierEof,
}

/// Spawns the steady-state E2E Stream worker (with zero-mutex single-owner writer and
/// concurrent reader) and returns the [`E2eStream`] handle.
pub(crate) fn spawn_stream_session(params: StreamSessionParams) -> E2eStream {
    let max_write_size =
        usize::from(params.negotiated_mtu.min(STREAM_CHUNK as u16)).saturating_sub(ST_OVERHEAD);
    let (app_read_tx, app_read_rx) = async_channel::bounded::<Result<Vec<u8>, CoreError>>(16);
    let (app_write_tx, app_write_rx) = async_channel::bounded::<AppWriteMsg>(16);
    let (closed_tx, closed_rx) = Watch::new(None::<CoreError>);

    let peer = params.peer;
    let negotiated_mtu = params.negotiated_mtu;
    let spawner = Arc::clone(&params.scope.runtime.spawner);

    spawner.spawn(Box::pin(async move {
        run_stream_session(params, max_write_size, app_read_tx, app_write_rx, closed_tx).await;
    }));

    E2eStream {
        read: E2eStreamRead {
            rx: Box::pin(app_read_rx),
            buf: Vec::new(),
            pos: 0,
            eof: false,
            closed_err: closed_rx.clone(),
            peer,
        },
        write: E2eStreamWrite {
            tx: app_write_tx,
            max_write_size,
            closed_err: closed_rx,
            pending_send: None,
            flush_rx: None,
            shutdown_rx: None,
            shutdown_done: false,
            peer,
        },
        negotiated_mtu,
        max_write_size,
        peer,
    }
}

async fn run_stream_session(
    params: StreamSessionParams,
    max_write_size: usize,
    app_read_tx: async_channel::Sender<Result<Vec<u8>, CoreError>>,
    app_write_rx: async_channel::Receiver<AppWriteMsg>,
    closed_tx: Watch<Option<CoreError>>,
) {
    let StreamSessionParams {
        scope,
        peer,
        negotiated_mtu: _,
        floor,
        mut reader,
        mut frame_reader,
        writer,
        mut mtu_watch,
        mut tx_cipher,
        mut rx_cipher,
        lease,
        session_permit: _session_permit,
        mut role,
    } = params;

    let clock = Arc::clone(&scope.runtime.clock);
    let role_enum = match &role {
        StreamSessionRole::Origin(_) => Role::Origin,
        StreamSessionRole::Destination(_) => Role::Destination,
    };
    let span = scope.session_span(Plane::Stream, role_enum);

    // Pre-seed Destination's 1.0 RTT initial data (already TrafficGate-charged in serve.rs).
    if let StreamSessionRole::Destination(ref mut dest) = role {
        if let Some(first) = dest.first_data.take() {
            scope
                .metrics
                .record_rx(Plane::Stream, first.len() as u64, false);
            let _ = app_read_tx.try_send(Ok(first));
        }
    }

    // Spawn single-owner writer task (ZERO async mutexes).
    let writer_handle = StreamWriterHandle::spawn(
        writer,
        mtu_watch.clone(),
        floor,
        Arc::clone(&clock),
        &*scope.runtime.spawner,
    );

    // Spawn concurrent carrier reader task splitting control frames from ordered ST_DATA/ST_FIN.
    let (ctrl_in_tx, ctrl_in_rx) = async_channel::bounded::<InboundCtrlMsg>(32);
    let (data_in_tx, data_in_rx) = async_channel::bounded::<InboundDataMsg>(16);
    {
        let ctrl_tx = ctrl_in_tx.clone();
        let data_tx = data_in_tx.clone();
        scope.runtime.spawner.spawn(Box::pin(async move {
            loop {
                match frame_reader.next_frame(&mut *reader, &mut rx_cipher).await {
                    Ok(InboundStreamFrame::Eof) => {
                        let _ = data_tx.send(InboundDataMsg::CarrierEof).await;
                        break;
                    }
                    Ok(InboundStreamFrame::HopControl { hdr, body, len }) => {
                        if ctrl_tx
                            .send(InboundCtrlMsg::HopControl { hdr, body, len })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(InboundStreamFrame::E2eRenew(body)) => {
                        if ctrl_tx.send(InboundCtrlMsg::E2eRenew(body)).await.is_err() {
                            break;
                        }
                    }
                    Ok(InboundStreamFrame::E2eRecord { opcode, body }) => match opcode {
                        e2e_st::ST_DATA => {
                            if data_tx.send(InboundDataMsg::Data(body)).await.is_err() {
                                break;
                            }
                        }
                        e2e_st::ST_FIN => {
                            if !body.is_empty() {
                                let _ = ctrl_tx
                                    .send(InboundCtrlMsg::ReadError(CoreError::Malformed))
                                    .await;
                                break;
                            }
                            if data_tx.send(InboundDataMsg::Fin).await.is_err() {
                                break;
                            }
                        }
                        e2e_st::ST_RENEW => {
                            if ctrl_tx
                                .send(InboundCtrlMsg::E2eRenew(Zeroizing::new(body)))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        e2e_st::ST_RENEW_OK => {
                            if ctrl_tx.send(InboundCtrlMsg::E2eRenewOk(body)).await.is_err() {
                                break;
                            }
                        }
                        _ => {
                            let _ = ctrl_tx
                                .send(InboundCtrlMsg::ReadError(CoreError::Malformed))
                                .await;
                            break;
                        }
                    },
                    Err(err) => {
                        let _ = ctrl_tx.send(InboundCtrlMsg::ReadError(err)).await;
                        break;
                    }
                }
            }
        }));
    }
    drop(ctrl_in_tx);
    drop(data_in_tx);

    let mut shutdown_rx = scope.subscribe_shutdown();
    let mut gate_cache = TrafficGateCache::new();
    let mut e2e_scratch = Vec::with_capacity(4096);

    // Renewal state (Origin fetches concurrently via FuturesUnordered; Dest runs single-flight verifier).
    let mut cred_futs: FuturesUnordered<CredFetchFut> = FuturesUnordered::new();
    let mut dest_verifier = RenewalVerifierState::new();
    let mut dest_auth_fut: Option<RenewalAuthFut> = None;

    let mut sent_fin = false;
    let mut received_fin = false;
    let mut carrier_eof = false;
    let mut ctrl_in_closed = false;
    let mut shutdown_initiated = false;
    let mut deferred_shutdown_fin = false;
    let mut app_write_closed = false;

    // Paced TrafficGate delays (never stall control frames!).
    let mut delayed_ingress: Option<(Vec<u8>, MonotonicTime)> = None;
    let mut delayed_egress: Option<(Vec<u8>, MonotonicTime)> = None;
    let mut pending_app_read: Option<Pin<Box<dyn Future<Output = ()> + Send>>> = None;
    let mut pending_app_writes: VecDeque<AppWriteMsg> = VecDeque::new();

    // Check live MTU immediately at startup and synchronize watch baseline.
    let initial_mtu = mtu_watch.sample();
    let terminal_reason: CoreError = if initial_mtu < floor {
        CoreError::MtuTooSmall(initial_mtu)
    } else {
        loop {
            if sent_fin && received_fin && pending_app_read.is_none() {
                break CoreError::Closed;
            }
            if app_read_tx.is_closed() && app_write_closed {
                break CoreError::Closed;
            }

            // Compute next scheduled wake deadline across renewals and TrafficGate delays.
            let renewal_dl = match &role {
                StreamSessionRole::Origin(orig) => orig.renewals.next_deadline(),
                StreamSessionRole::Destination(_) => None,
            };
            let ingress_dl = delayed_ingress.as_ref().map(|(_, dl)| *dl);
            let egress_dl = delayed_egress.as_ref().map(|(_, dl)| *dl);
            let next_timer = [renewal_dl, ingress_dl, egress_dl]
                .into_iter()
                .flatten()
                .min();

            // Event step: poll all concurrent sources with zero locks!
            enum StepEvent {
                LeaseCancelled(CoreError),
                MtuBelowFloor(u16),
                WriterFailed(CoreError),
                ScopeShutdown,
                CtrlIn(Result<InboundCtrlMsg, async_channel::RecvError>),
                DataIn(Result<InboundDataMsg, async_channel::RecvError>),
                AppReadDrained,
                AppWrite(Result<AppWriteMsg, async_channel::RecvError>),
                CredFetched(RenewalSlot, Result<Credential, CoreError>),
                DestAuthDone(u64, Result<Lease, CoreError>),
                TimerFired,
            }

            let can_poll_data_in =
                !carrier_eof && delayed_ingress.is_none() && pending_app_read.is_none();
            let can_poll_app_write =
                delayed_egress.is_none() && !app_write_closed && !sent_fin && pending_app_writes.is_empty();

            let event = {
                let mut lease_fut = Box::pin(lease.cancelled());
                let mut mtu_fut = Box::pin(wait_mtu_below_floor(&mut mtu_watch, floor));
                let mut wfail_fut = Box::pin(writer_handle.failed());
                let mut shut_fut = Box::pin(async {
                    if shutdown_initiated {
                        core::future::pending::<()>().await;
                    } else {
                        wait_shutdown(&mut shutdown_rx).await;
                    }
                });
                let mut ctrl_fut = Box::pin(async {
                    if ctrl_in_closed {
                        core::future::pending().await
                    } else {
                        ctrl_in_rx.recv().await
                    }
                });
                let mut data_fut = Box::pin(async {
                    if can_poll_data_in {
                        data_in_rx.recv().await
                    } else {
                        core::future::pending().await
                    }
                });
                let mut app_w_fut = Box::pin(async {
                    if can_poll_app_write {
                        app_write_rx.recv().await
                    } else {
                        core::future::pending().await
                    }
                });
                let mut timer_fut = Box::pin(sleep_optional(&*clock, next_timer));

                poll_fn(|cx| {
                    if let Poll::Ready(err) = lease_fut.as_mut().poll(cx) {
                        return Poll::Ready(StepEvent::LeaseCancelled(err));
                    }
                    if let Poll::Ready(mtu) = mtu_fut.as_mut().poll(cx) {
                        return Poll::Ready(StepEvent::MtuBelowFloor(mtu));
                    }
                    if let Poll::Ready(err) = wfail_fut.as_mut().poll(cx) {
                        return Poll::Ready(StepEvent::WriterFailed(err));
                    }
                    if let Poll::Ready(()) = shut_fut.as_mut().poll(cx) {
                        return Poll::Ready(StepEvent::ScopeShutdown);
                    }
                    if let Poll::Ready(msg) = ctrl_fut.as_mut().poll(cx) {
                        return Poll::Ready(StepEvent::CtrlIn(msg));
                    }
                    if let Poll::Ready((id, res)) = poll_optional(&mut dest_auth_fut, cx) {
                        return Poll::Ready(StepEvent::DestAuthDone(id, res));
                    }
                    if !cred_futs.is_empty() {
                        if let Poll::Ready(Some((slot, res))) = Pin::new(&mut cred_futs).poll_next(cx) {
                            return Poll::Ready(StepEvent::CredFetched(slot, res));
                        }
                    }
                    if let Poll::Ready(()) = poll_optional(&mut pending_app_read, cx) {
                        return Poll::Ready(StepEvent::AppReadDrained);
                    }
                    if let Poll::Ready(()) = timer_fut.as_mut().poll(cx) {
                        return Poll::Ready(StepEvent::TimerFired);
                    }
                    if let Poll::Ready(msg) = data_fut.as_mut().poll(cx) {
                        return Poll::Ready(StepEvent::DataIn(msg));
                    }
                    if let Poll::Ready(msg) = app_w_fut.as_mut().poll(cx) {
                        return Poll::Ready(StepEvent::AppWrite(msg));
                    }
                    Poll::Pending
                })
                .await
            };

            match event {
                StepEvent::LeaseCancelled(err) => break err,
                StepEvent::MtuBelowFloor(mtu) => break CoreError::MtuTooSmall(mtu),
                StepEvent::WriterFailed(err) => {
                    if sent_fin && received_fin {
                        break CoreError::Closed;
                    }
                    break err;
                }
                StepEvent::ScopeShutdown => {
                    shutdown_initiated = true;
                    if !sent_fin {
                        if delayed_egress.is_some() {
                            deferred_shutdown_fin = true;
                        } else {
                            // Initiate authenticated ST_FIN with no drain timeout bound (Spec §6.8).
                            if let Err(err) =
                                seal_and_send_e2e(&mut tx_cipher, e2e_st::ST_FIN, &[], &mut e2e_scratch, &writer_handle).await
                            {
                                break err;
                            }
                            let _ = writer_handle.flush_fifo().await;
                            sent_fin = true;
                        }
                    }
                }
                StepEvent::CtrlIn(Err(_)) => {
                    ctrl_in_closed = true;
                    // Reader exited; data_in_rx will deliver any trailing Eof or Fin.
                    if received_fin && sent_fin {
                        break CoreError::Closed;
                    }
                }
                StepEvent::CtrlIn(Ok(InboundCtrlMsg::ReadError(err))) => {
                    if sent_fin && received_fin {
                        break CoreError::Closed;
                    }
                    break err;
                }
                StepEvent::CtrlIn(Ok(InboundCtrlMsg::HopControl { hdr, body, len })) => {
                    let wire_body = &body[..len];
                    match &mut role {
                        StreamSessionRole::Origin(orig) => {
                            let dist = usize::from(hdr.ttl_or_dist);
                            let n = orig.hops.len();
                            match hdr.kind {
                                outer::ST_CLOSE => {
                                    let opened = if dist == n {
                                        orig.terminal_ctrl.open(outer::ST_CLOSE, wire_body)
                                    } else if dist < n {
                                        orig.hops[dist].2.open(outer::ST_CLOSE, wire_body)
                                    } else {
                                        Err(CoreError::Authentication)
                                    };
                                    let pt = match opened {
                                        Ok(pt) => pt,
                                        Err(err) => break err,
                                    };
                                    let decoded = match decode_wire_error_bytes(&pt) {
                                        Ok(e) => e,
                                        Err(e) => break e,
                                    };
                                    if received_fin && sent_fin {
                                        break CoreError::Closed;
                                    }
                                    // Spec §6.4: Once ST_FIN is received, hop ST_CLOSE(Closed/UnexpectedEof)
                                    // does NOT abort outbound half until local ST_FIN is also sent.
                                    if received_fin
                                        && !sent_fin
                                        && matches!(decoded, CoreError::Closed | CoreError::UnexpectedEof)
                                    {
                                        continue;
                                    }
                                    if dist == n {
                                        break decoded;
                                    } else {
                                        break CoreError::hop_rejected(hdr.ttl_or_dist, decoded);
                                    }
                                }
                                outer::ST_RENEW_OK => {
                                    if dist >= n {
                                        break CoreError::Authentication;
                                    }
                                    let pt = match orig.hops[dist].2.open(outer::ST_RENEW_OK, wire_body) {
                                        Ok(pt) => pt,
                                        Err(err) => break err,
                                    };
                                    let (id, ttl) = match decode_renew_ok_payload(&pt) {
                                        Ok(v) => v,
                                        Err(err) => break err,
                                    };
                                    match orig.renewals.on_ack(
                                        RenewalSlot::Hop(dist),
                                        id,
                                        ttl,
                                        clock.now(),
                                        &mut OsRng,
                                    ) {
                                        Ok(true) => {
                                            scope
                                                .metrics
                                                .auth_transit
                                                .renewed
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        Ok(false) => {}
                                        Err(err) => {
                                            scope
                                                .metrics
                                                .auth_transit
                                                .renewal_failures
                                                .fetch_add(1, Ordering::Relaxed);
                                            break err;
                                        }
                                    }
                                }
                                _ => break CoreError::Malformed,
                            }
                        }
                        StreamSessionRole::Destination(dest) => {
                            if hdr.kind == outer::ST_CLOSE && hdr.ttl_or_dist == 0 {
                                let pt = match dest.terminal_ctrl.open(outer::ST_CLOSE, wire_body) {
                                    Ok(pt) => pt,
                                    Err(err) => break err,
                                };
                                let decoded = match decode_wire_error_bytes(&pt) {
                                    Ok(e) => e,
                                    Err(e) => break e,
                                };
                                if received_fin && sent_fin {
                                    break CoreError::Closed;
                                }
                                if received_fin
                                    && !sent_fin
                                    && matches!(decoded, CoreError::Closed | CoreError::UnexpectedEof)
                                {
                                    continue;
                                }
                                break decoded;
                            } else {
                                break CoreError::Malformed;
                            }
                        }
                    }
                }
                StepEvent::CtrlIn(Ok(InboundCtrlMsg::E2eRenew(body))) => {
                    let StreamSessionRole::Destination(dest) = &role else {
                        // Origin must never receive e2e::ST_RENEW (Spec §5.8.2).
                        break CoreError::Malformed;
                    };
                    let (id, cred) = match decode_renew_payload(&body) {
                        Ok(v) => v,
                        Err(err) => break err,
                    };
                    match dest_verifier.classify(id) {
                        VerifierRenewalAction::Malformed => break CoreError::Malformed,
                        VerifierRenewalAction::Ignore => {}
                        VerifierRenewalAction::ReplyIdempotent(ack_id) => {
                            let rem = match lease.remaining() {
                                Ok(d) => d,
                                Err(err) => break err,
                            };
                            let rem_ms = u64::try_from(rem.as_millis()).unwrap_or(u64::MAX).max(1);
                            let payload = encode_renew_ok_payload(ack_id, rem_ms);
                            if let Err(err) = seal_and_send_e2e(
                                &mut tx_cipher,
                                e2e_st::ST_RENEW_OK,
                                &payload,
                                &mut e2e_scratch,
                                &writer_handle,
                            )
                            .await
                            {
                                break err;
                            }
                        }
                        VerifierRenewalAction::AuthorizeNew(new_id) => {
                            let scope_c = Arc::clone(&scope);
                            let ep_name = dest.endpoint.clone();
                            let cred_owned = match Credential::from_slice(cred) {
                                Ok(c) => c,
                                Err(_) => break CoreError::Malformed,
                            };
                            dest_auth_fut = Some(Box::pin(async move {
                                let res = scope_c
                                    .auth_gate
                                    .authorize(AuthRequest {
                                        peer,
                                        target: TargetRef::Endpoint {
                                            name: &ep_name,
                                            plane: Plane::Stream,
                                        },
                                        credential: cred_owned.as_bytes(),
                                        is_renewal: true,
                                    })
                                    .await;
                                (new_id, res)
                            }));
                        }
                    }
                }
                StepEvent::CtrlIn(Ok(InboundCtrlMsg::E2eRenewOk(body))) => {
                    let StreamSessionRole::Origin(orig) = &mut role else {
                        // Destination must never receive e2e::ST_RENEW_OK (Spec §5.8.2).
                        break CoreError::Malformed;
                    };
                    let (id, ttl) = match decode_renew_ok_payload(&body) {
                        Ok(v) => v,
                        Err(err) => break err,
                    };
                    match orig.renewals.on_ack(
                        RenewalSlot::Endpoint,
                        id,
                        ttl,
                        clock.now(),
                        &mut OsRng,
                    ) {
                        Ok(true) => {
                            if let Err(err) = lease.renew_ttl_only(ttl, MAX_WIRE_LEASE_TTL) {
                                break err;
                            }
                            scope
                                .metrics
                                .auth_endpoint
                                .renewed
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(false) => {}
                        Err(err) => {
                            scope
                                .metrics
                                .auth_endpoint
                                .renewal_failures
                                .fetch_add(1, Ordering::Relaxed);
                            break err;
                        }
                    }
                }
                StepEvent::DestAuthDone(id, res) => match res {
                    Ok(new_lease) => {
                        if let Err(err) =
                            lease.renew_lease_with_max_ttl(new_lease, scope.auth_limits.max_lease_ttl)
                        {
                            scope
                                .metrics
                                .auth_endpoint
                                .renewal_failures
                                .fetch_add(1, Ordering::Relaxed);
                            break err;
                        }
                        dest_verifier.complete(id, true);
                        scope
                            .metrics
                            .auth_endpoint
                            .renewed
                            .fetch_add(1, Ordering::Relaxed);
                        let rem = match lease.remaining() {
                            Ok(d) => d,
                            Err(err) => break err,
                        };
                        let rem_ms = u64::try_from(rem.as_millis()).unwrap_or(u64::MAX).max(1);
                        let payload = encode_renew_ok_payload(id, rem_ms);
                        if let Err(err) = seal_and_send_e2e(
                            &mut tx_cipher,
                            e2e_st::ST_RENEW_OK,
                            &payload,
                            &mut e2e_scratch,
                            &writer_handle,
                        )
                        .await
                        {
                            break err;
                        }
                    }
                    Err(err) if err.is_retryable() => {
                        dest_verifier.complete(id, false);
                    }
                    Err(err) => {
                        dest_verifier.complete(id, false);
                        scope
                            .metrics
                            .auth_endpoint
                            .renewal_failures
                            .fetch_add(1, Ordering::Relaxed);
                        break err;
                    }
                },
                StepEvent::CredFetched(slot, res) => {
                    let StreamSessionRole::Origin(orig) = &mut role else {
                        continue;
                    };
                    match orig
                        .renewals
                        .on_credential_fetched(slot, res, clock.now(), &mut OsRng)
                    {
                        CredentialFetchOutcome::Send {
                            slot,
                            renewal_id,
                            credential,
                        } => {
                            if let Err(err) = send_origin_stream_renewal(
                                slot,
                                renewal_id,
                                &credential,
                                &mut tx_cipher,
                                &mut orig.hops,
                                &mut e2e_scratch,
                                &writer_handle,
                            )
                            .await
                            {
                                break err;
                            }
                        }
                        CredentialFetchOutcome::RetryScheduled => {}
                        CredentialFetchOutcome::Fatal(err) => {
                            let is_transit = matches!(slot, RenewalSlot::Hop(_));
                            scope
                                .metrics
                                .auth(is_transit)
                                .renewal_failures
                                .fetch_add(1, Ordering::Relaxed);
                            break err;
                        }
                    }
                }
                StepEvent::TimerFired => {
                    let now = clock.now();
                    // 1. Check delayed ingress delivery (Destination TrafficGate).
                    if let Some((_, dl)) = &delayed_ingress {
                        if now >= *dl {
                            if let Some((data, _)) = delayed_ingress.take() {
                                if let Err(err) = lease.remaining() {
                                    break err;
                                }
                                scope
                                    .metrics
                                    .record_rx(Plane::Stream, data.len() as u64, false);
                                enqueue_app_read(&app_read_tx, Ok(data), &mut pending_app_read);
                            }
                        }
                    }
                    // 2. Check delayed egress write (Destination TrafficGate).
                    if let Some((_, dl)) = &delayed_egress {
                        if now >= *dl {
                            if let Some((data, _)) = delayed_egress.take() {
                                if let Err(err) = lease.remaining() {
                                    break err;
                                }
                                let len = data.len();
                                if let Err(err) = seal_and_send_e2e(
                                    &mut tx_cipher,
                                    e2e_st::ST_DATA,
                                    &data,
                                    &mut e2e_scratch,
                                    &writer_handle,
                                )
                                .await
                                {
                                    break err;
                                }
                                scope.metrics.record_tx(Plane::Stream, len as u64, false);

                                if deferred_shutdown_fin && !sent_fin {
                                    deferred_shutdown_fin = false;
                                    if let Err(err) = seal_and_send_e2e(
                                        &mut tx_cipher,
                                        e2e_st::ST_FIN,
                                        &[],
                                        &mut e2e_scratch,
                                        &writer_handle,
                                    )
                                    .await
                                    {
                                        break err;
                                    }
                                    let _ = writer_handle.flush_fifo().await;
                                    sent_fin = true;
                                }
                            }
                        }
                    }
                    // 3. Poll Originator RenewalDriver actions.
                    if let StreamSessionRole::Origin(orig) = &mut role {
                        let actions = orig.renewals.poll_actions(now, &mut OsRng);
                        let mut fatal_err: Option<CoreError> = None;
                        for act in actions {
                            match act {
                                RenewalAction::Expired(slot) => {
                                    let is_transit = matches!(slot, RenewalSlot::Hop(_));
                                    scope
                                        .metrics
                                        .auth(is_transit)
                                        .renewal_failures
                                        .fetch_add(1, Ordering::Relaxed);
                                    fatal_err = Some(RenewalDriver::expiry_error(slot));
                                    break;
                                }
                                RenewalAction::FetchCredential {
                                    slot,
                                    prior,
                                    remaining,
                                    is_retry,
                                } => {
                                    let is_transit = matches!(slot, RenewalSlot::Hop(_));
                                    if is_retry {
                                        scope
                                            .metrics
                                            .auth(is_transit)
                                            .renewal_retries
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                    let (verifier, target_name) = match slot {
                                        RenewalSlot::Endpoint => (peer, orig.endpoint.clone()),
                                        RenewalSlot::Hop(i) => (orig.hops[i].0, orig.hops[i].1.clone()),
                                    };
                                    let timeout = scope
                                        .auth_limits
                                        .auth_timeout
                                        .min(remaining / 2);
                                    let deadline = clock.now().saturating_add(timeout);
                                    let creds = Arc::clone(&scope.credentials);
                                    let clk = Arc::clone(&clock);
                                    let ep_name = orig.endpoint.clone();
                                    let path_id = orig.path_id;
                                    cred_futs.push(Box::pin(async move {
                                        let target = if is_transit {
                                            TargetRef::Transit {
                                                name: &target_name,
                                                plane: Plane::Stream,
                                            }
                                        } else {
                                            TargetRef::Endpoint {
                                                name: &target_name,
                                                plane: Plane::Stream,
                                            }
                                        };
                                        let fut = creds.credential(CredentialRequest {
                                            verifier,
                                            target,
                                            destination: peer,
                                            endpoint: &ep_name,
                                            path_id,
                                            is_refresh: true,
                                            prior: prior.as_bytes(),
                                        });
                                        let res = match with_deadline(&*clk, deadline, fut).await {
                                            Ok(c) if c.len() <= CREDENTIAL_MAX => Ok(c),
                                            Ok(_) => Err(CoreError::credential(
                                                CoreError::InvalidParameter,
                                            )),
                                            Err(e) => Err(CoreError::credential(e)),
                                        };
                                        (slot, res)
                                    }));
                                }
                                RenewalAction::Send {
                                    slot,
                                    renewal_id,
                                    credential,
                                    is_retry,
                                } => {
                                    if is_retry {
                                        let is_transit = matches!(slot, RenewalSlot::Hop(_));
                                        scope
                                            .metrics
                                            .auth(is_transit)
                                            .renewal_retries
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                    if let Err(err) = send_origin_stream_renewal(
                                        slot,
                                        renewal_id,
                                        &credential,
                                        &mut tx_cipher,
                                        &mut orig.hops,
                                        &mut e2e_scratch,
                                        &writer_handle,
                                    )
                                    .await
                                    {
                                        fatal_err = Some(err);
                                        break;
                                    }
                                }
                            }
                        }
                        if let Some(err) = fatal_err {
                            break err;
                        }
                    }
                }
                StepEvent::AppReadDrained => {}
                StepEvent::DataIn(Err(_)) | StepEvent::DataIn(Ok(InboundDataMsg::CarrierEof)) => {
                    carrier_eof = true;
                    if !received_fin {
                        break CoreError::UnexpectedEof;
                    }
                    if sent_fin {
                        break CoreError::Closed;
                    }
                    // Spec §6.4: Once ST_FIN is received, carrier EOF does NOT abort outbound half
                    // until local ST_FIN is also sent!
                    data_in_rx.close();
                }
                StepEvent::DataIn(Ok(InboundDataMsg::Fin)) => {
                    if received_fin {
                        // Duplicate ST_FIN is Malformed (Spec §5.8.2).
                        break CoreError::Malformed;
                    }
                    received_fin = true;
                    enqueue_app_read(&app_read_tx, Ok(Vec::new()), &mut pending_app_read);
                }
                StepEvent::DataIn(Ok(InboundDataMsg::Data(body))) => {
                    if received_fin {
                        // ST_DATA after ST_FIN is Malformed (Spec §5.8.2).
                        break CoreError::Malformed;
                    }
                    if body.is_empty() {
                        // Empty ST_DATA in steady state is ignored (Spec §5.8.2).
                        continue;
                    }
                    if body.len() > max_write_size {
                        break CoreError::Malformed;
                    }
                    if matches!(role, StreamSessionRole::Destination(_)) {
                        if let Some(gate) = gate_cache.get(&lease) {
                            match gate.charge_stream(Direction::Ingress, body.len()) {
                                StreamAction::Allow => {}
                                StreamAction::Delay(d) => {
                                    let dl = clock.now().saturating_add(d);
                                    delayed_ingress = Some((body, dl));
                                    continue;
                                }
                                StreamAction::Close(err) => break err,
                            }
                        }
                    }
                    scope
                        .metrics
                        .record_rx(Plane::Stream, body.len() as u64, false);
                    enqueue_app_read(&app_read_tx, Ok(body), &mut pending_app_read);
                }
                StepEvent::AppWrite(Err(_)) => {
                    app_write_closed = true;
                    if app_read_tx.is_closed() {
                        break CoreError::Closed;
                    }
                }
                StepEvent::AppWrite(Ok(msg)) => {
                    pending_app_writes.push_back(msg);
                }
            }

            // Drain any pending app writes while not egress-delayed.
            let mut fatal_write: Option<CoreError> = None;
            while delayed_egress.is_none() {
                let Some(msg) = pending_app_writes.pop_front() else {
                    break;
                };
                match msg {
                    AppWriteMsg::Data(data) => {
                        if sent_fin {
                            continue;
                        }
                        if matches!(role, StreamSessionRole::Destination(_)) {
                            if let Some(gate) = gate_cache.get(&lease) {
                                match gate.charge_stream(Direction::Egress, data.len()) {
                                    StreamAction::Allow => {}
                                    StreamAction::Delay(d) => {
                                        let dl = clock.now().saturating_add(d);
                                        delayed_egress = Some((data, dl));
                                        break;
                                    }
                                    StreamAction::Close(err) => {
                                        fatal_write = Some(err);
                                        break;
                                    }
                                }
                            }
                        }
                        let len = data.len();
                        if let Err(err) = seal_and_send_e2e(
                            &mut tx_cipher,
                            e2e_st::ST_DATA,
                            &data,
                            &mut e2e_scratch,
                            &writer_handle,
                        )
                        .await
                        {
                            fatal_write = Some(err);
                            break;
                        }
                        scope.metrics.record_tx(Plane::Stream, len as u64, false);
                    }
                    AppWriteMsg::Flush(ack_tx) => {
                        let res = writer_handle.flush_fifo().await;
                        let _ = ack_tx.try_send(res.clone());
                        if let Err(err) = res {
                            fatal_write = Some(err);
                            break;
                        }
                    }
                    AppWriteMsg::Shutdown(ack_tx) => {
                        if !sent_fin {
                            if let Err(err) = seal_and_send_e2e(
                                &mut tx_cipher,
                                e2e_st::ST_FIN,
                                &[],
                                &mut e2e_scratch,
                                &writer_handle,
                            )
                            .await
                            {
                                let _ = ack_tx.try_send(Err(err.clone()));
                                fatal_write = Some(err);
                                break;
                            }
                            let res = writer_handle.flush_fifo().await;
                            let _ = ack_tx.try_send(res.clone());
                            if let Err(err) = res {
                                fatal_write = Some(err);
                                break;
                            }
                            sent_fin = true;
                        } else {
                            let _ = ack_tx.try_send(Ok(()));
                        }
                    }
                }
            }
            if let Some(err) = fatal_write {
                break err;
            }
        }
    };

    tracing::debug!(
        parent: &span,
        error = terminal_reason.static_code(),
        "stream session terminating"
    );

    // Notify local app handles of terminal status.
    closed_tx.send(Some(terminal_reason.clone()));
    if !received_fin {
        let _ = app_read_tx.try_send(Err(terminal_reason.clone()));
    }
    app_read_tx.close();
    app_write_rx.close();

    // Teardown per Spec §6.4:
    // - Origin: best-effort 50 ms hop::ST_CLOSE(reason) to hops N-1..0, shut down carrier, report PathOutcome.
    // - Destination: best-effort 50 ms hop::ST_CLOSE(reason) (ttl = 0, terminal_key) + carrier shutdown ONLY if reason != Closed.
    let err_bytes = encode_wire_error_bytes(&terminal_reason);
    match &mut role {
        StreamSessionRole::Origin(orig) => {
            let mut close_frames = Vec::with_capacity(orig.hops.len());
            for i in (0..orig.hops.len()).rev() {
                if let Ok(sealed) = orig.hops[i].2.seal(outer::ST_CLOSE, &err_bytes) {
                    if let Ok(ttl) = u8::try_from(i) {
                        if let Ok(frame) =
                            PriorityCtrlFrame::from_slice(outer::ST_CLOSE, ttl, &sealed)
                        {
                            close_frames.push(frame);
                        }
                    }
                }
            }
            writer_handle.teardown(close_frames, true, &*clock).await;
            let outcome = if terminal_reason == CoreError::Closed {
                PathOutcome::Closed
            } else {
                PathOutcome::Failed(terminal_reason)
            };
            scope.path_source.report_outcome(orig.path_id, outcome);
        }
        StreamSessionRole::Destination(dest) => {
            let mut close_frames = Vec::new();
            if terminal_reason != CoreError::Closed {
                if let Ok(sealed) = dest.terminal_ctrl.seal(outer::ST_CLOSE, &err_bytes) {
                    if let Ok(frame) = PriorityCtrlFrame::from_slice(outer::ST_CLOSE, 0, &sealed) {
                        close_frames.push(frame);
                    }
                }
                writer_handle.teardown(close_frames, true, &*clock).await;
            } else {
                // Clean close: flush carrier shutdown without sending hop::ST_CLOSE.
                writer_handle.teardown(close_frames, true, &*clock).await;
            }
        }
    }
}

fn enqueue_app_read(
    app_read_tx: &async_channel::Sender<Result<Vec<u8>, CoreError>>,
    item: Result<Vec<u8>, CoreError>,
    pending_slot: &mut Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
) {
    if let Err(async_channel::TrySendError::Full(item)) = app_read_tx.try_send(item) {
        let tx = app_read_tx.clone();
        *pending_slot = Some(Box::pin(async move {
            let _ = tx.send(item).await;
        }));
    }
}

async fn seal_and_send_e2e(
    tx_cipher: &mut StreamCipher,
    opcode: u8,
    body: &[u8],
    scratch: &mut Vec<u8>,
    writer: &StreamWriterHandle,
) -> Result<(), CoreError> {
    tx_cipher.seal_into(opcode, body, scratch)?;
    writer.send_e2e_bytes(scratch.clone()).await
}

async fn send_origin_stream_renewal(
    slot: RenewalSlot,
    renewal_id: u64,
    credential: &Credential,
    tx_cipher: &mut StreamCipher,
    hops: &mut [(PublicKey, String, ControlCipher)],
    scratch: &mut Vec<u8>,
    writer: &StreamWriterHandle,
) -> Result<(), CoreError> {
    let payload = encode_renew_payload(renewal_id, credential.as_bytes())?;
    match slot {
        RenewalSlot::Endpoint => {
            seal_and_send_e2e(tx_cipher, e2e_st::ST_RENEW, &payload, scratch, writer).await
        }
        RenewalSlot::Hop(i) => {
            let ttl = u8::try_from(i).map_err(|_| CoreError::Malformed)?;
            let sealed = hops
                .get_mut(i)
                .ok_or(CoreError::Malformed)?
                .2
                .seal(outer::ST_RENEW, &payload)?;
            let frame = PriorityCtrlFrame::from_slice(outer::ST_RENEW, ttl, &sealed)?;
            writer.send_hop_control(frame).await
        }
    }
}

/// Helper used by `StagedStream` drop-abort to send reverse hop `ST_CLOSE(Closed)` best-effort.
pub(crate) async fn abort_stream_hops(
    mut writer: Box<dyn StreamWrite>,
    mut hop_ctrls: Vec<ControlCipher>,
    clock: Arc<dyn Clock>,
) {
    let deadline = clock
        .now()
        .saturating_add(crate::constants::CLOSE_SEND_TIMEOUT);
    let err_bytes = encode_wire_error_bytes(&CoreError::Closed);
    for (i, ctrl) in hop_ctrls.iter_mut().enumerate().rev() {
        if let (Ok(ttl), Ok(sealed)) = (u8::try_from(i), ctrl.seal(outer::ST_CLOSE, &err_bytes)) {
            let _ = with_deadline(
                &*clock,
                deadline,
                crate::engine::stream::framing::write_hop_control(
                    &mut *writer,
                    outer::ST_CLOSE,
                    ttl,
                    &sealed,
                    &*clock,
                ),
            )
            .await;
        }
    }
    let _ = with_deadline(&*clock, deadline, writer.shutdown()).await;
}

/// Races a future against lease cancellation and live MTU floor drops (used in confirm/serve).
pub(crate) async fn race_session_guards<F, T>(
    fut: F,
    lease: &LeaseHandle,
    mtu_watch: &mut MtuWatch,
    floor: u16,
) -> Result<T, CoreError>
where
    F: Future<Output = Result<T, CoreError>>,
{
    match race2(
        fut,
        race2(lease.cancelled(), wait_mtu_below_floor(mtu_watch, floor)),
    )
    .await
    {
        Either::Left(res) => res,
        Either::Right(Either::Left(err)) => Err(err),
        Either::Right(Either::Right(mtu)) => Err(CoreError::MtuTooSmall(mtu)),
    }
}
