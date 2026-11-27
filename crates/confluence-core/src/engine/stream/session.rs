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
    sleep_optional, wait_mtu_below_floor, wait_shutdown, wait_signal, with_deadline,
};
use crate::engine::stream::framing::{
    InboundStreamFrame, PriorityCtrlFrame, StreamFrameReader, StreamWriterHandle, TryWriterSend,
    WriterDataCmd,
};
use crate::error::CoreError;
use crate::protocol::renewal::{
    CredentialFetchOutcome, RenewalAction, RenewalDriver, RenewalSlot, RenewalVerifierState,
    VerifierRenewalAction,
};
use crate::runtime::sync::{CloseableSemaphore, SemaphorePermit, Watch, WatchReceiver};
use crate::runtime::{Clock, MonotonicTime};
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

const APP_WRITE_CAPACITY: usize = 16;
const APP_WRITE_CHANNEL_CAPACITY: usize = 64;

enum AppWriteMsg {
    Data(Vec<u8>, SemaphorePermit),
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
    _alive: Watch<()>,
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

type PendingPermitFuture =
    Pin<Box<dyn Future<Output = Result<SemaphorePermit, CoreError>> + Send>>;
type PendingSendFuture =
    Pin<Box<dyn Future<Output = Result<(), async_channel::SendError<AppWriteMsg>>> + Send>>;

/// Concurrent write half of an established [`E2eStream`] (obtained via [`E2eStream::split`]).
pub struct E2eStreamWrite {
    tx: async_channel::Sender<AppWriteMsg>,
    data_sem: Arc<CloseableSemaphore>,
    max_write_size: usize,
    closed_err: WatchReceiver<Option<CoreError>>,
    /// Capacity waiter for backpressured `poll_write` (never captures caller bytes or length!).
    pending_permit: Option<PendingPermitFuture>,
    /// Separate pending control-send and ack states for `poll_flush` and `poll_shutdown`.
    pending_flush_send: Option<PendingSendFuture>,
    flush_rx: Option<AckRx>,
    pending_shutdown_send: Option<PendingSendFuture>,
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
        if self.shutdown_done
            || self.shutdown_rx.is_some()
            || self.pending_shutdown_send.is_some()
        {
            self.pending_permit = None;
            return Poll::Ready(Err(CoreError::Closed));
        }
        if self.data_sem.is_closed() {
            self.pending_permit = None;
            return Poll::Ready(Err(self.terminal_err()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Wait purely for a capacity permit before reading or copying `buf` (ST-03):
        // cancelling a backpressured write never leaks stale bytes or lengths into later calls.
        let permit = if let Some(mut fut) = self.pending_permit.take() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(permit)) => permit,
                Poll::Ready(Err(_)) => return Poll::Ready(Err(self.terminal_err())),
                Poll::Pending => {
                    self.pending_permit = Some(fut);
                    return Poll::Pending;
                }
            }
        } else {
            match self.data_sem.try_acquire() {
                Ok(permit) => permit,
                Err(CoreError::Closed) => return Poll::Ready(Err(self.terminal_err())),
                Err(_) => {
                    let sem = Arc::clone(&self.data_sem);
                    let mut fut: PendingPermitFuture = Box::pin(async move { sem.acquire().await });
                    match fut.as_mut().poll(cx) {
                        Poll::Ready(Ok(permit)) => permit,
                        Poll::Ready(Err(_)) => return Poll::Ready(Err(self.terminal_err())),
                        Poll::Pending => {
                            self.pending_permit = Some(fut);
                            return Poll::Pending;
                        }
                    }
                }
            }
        };

        let len = buf.len().min(self.max_write_size.max(1));
        let msg = AppWriteMsg::Data(buf[..len].to_vec(), permit);
        match self.tx.try_send(msg) {
            Ok(()) => {
                // Any previous uncompleted flush no longer covers this newly accepted data.
                self.pending_flush_send = None;
                self.flush_rx = None;
                Poll::Ready(Ok(len))
            }
            Err(async_channel::TrySendError::Closed(_)) => Poll::Ready(Err(self.terminal_err())),
            Err(async_channel::TrySendError::Full(_)) => Poll::Ready(Err(CoreError::Busy)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
        if let Some(mut fut) = self.pending_flush_send.take() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(_)) => {
                    self.flush_rx = None;
                    return Poll::Ready(Err(self.terminal_err()));
                }
                Poll::Pending => {
                    self.pending_flush_send = Some(fut);
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
                            self.pending_flush_send = Some(fut);
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
        self.pending_permit = None;

        if let Some(mut fut) = self.pending_shutdown_send.take() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(_)) => {
                    self.shutdown_rx = None;
                    if self.closed_err.borrow_cloned() == Some(CoreError::Closed) {
                        self.shutdown_done = true;
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(self.terminal_err()));
                }
                Poll::Pending => {
                    self.pending_shutdown_send = Some(fut);
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
                        Poll::Ready(Err(_)) => {
                            if self.closed_err.borrow_cloned() == Some(CoreError::Closed) {
                                self.shutdown_done = true;
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Ready(Err(self.terminal_err()));
                        }
                        Poll::Pending => {
                            self.pending_shutdown_send = Some(fut);
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

    /// Subscribes to this session's terminal close status (internal bridge supervision, ST-09).
    pub(crate) fn subscribe_closed(&self) -> WatchReceiver<Option<CoreError>> {
        self.read.closed_err.clone()
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
        after_seq: u64,
        hdr: StHopHeader,
        body: [u8; crate::constants::MAX_CONTROL],
        len: usize,
    },
    E2eRenew(Zeroizing<Vec<u8>>),
    E2eRenewOk(Vec<u8>),
    ReadError {
        after_seq: u64,
        err: CoreError,
    },
}

enum InboundDataMsg {
    Data(Vec<u8>),
    Fin,
    CarrierEof,
}

/// Terminal control/read event causally deferred until all preceding `data_in` records (`<= after_seq`)
/// have been processed (Spec §6.4 / ST-04).
enum DeferredTerminal {
    HopClose {
        after_seq: u64,
        dist: u8,
        reason: CoreError,
    },
    ReadError {
        after_seq: u64,
        err: CoreError,
    },
}

enum TerminalAction {
    Continue,
    Terminate(CoreError),
}

type UnitResultFut = Pin<Box<dyn Future<Output = Result<(), CoreError>> + Send>>;

/// Non-blocking outbound writer queue polled directly inside the session event loop (ST-01).
///
/// Preserves strict FIFO order for E2E `StreamCipher` records & `FlushAck`s while keeping
/// priority hop controls (`hop::ST_RENEW`) on an independent queue.
struct OutboundWriterQueue {
    writer: StreamWriterHandle,
    pending_ctrl: VecDeque<PriorityCtrlFrame>,
    in_flight_ctrl: Option<UnitResultFut>,
    pending_data: VecDeque<(WriterDataCmd, Option<SemaphorePermit>)>,
    in_flight_data: Option<UnitResultFut>,
}

impl OutboundWriterQueue {
    fn new(writer: StreamWriterHandle) -> Self {
        Self {
            writer,
            pending_ctrl: VecDeque::new(),
            in_flight_ctrl: None,
            pending_data: VecDeque::new(),
            in_flight_data: None,
        }
    }

    fn writer(&self) -> &StreamWriterHandle {
        &self.writer
    }

    fn is_data_idle(&self) -> bool {
        self.in_flight_data.is_none() && self.pending_data.is_empty()
    }

    fn enqueue_ctrl(&mut self, frame: PriorityCtrlFrame) -> Result<(), CoreError> {
        if self.in_flight_ctrl.is_none() && self.pending_ctrl.is_empty() {
            match self.writer.try_send_hop_control(frame) {
                TryWriterSend::Sent => Ok(()),
                TryWriterSend::Full(frame) => {
                    let wh = self.writer.clone();
                    self.in_flight_ctrl =
                        Some(Box::pin(async move { wh.send_hop_control(frame).await }));
                    Ok(())
                }
                TryWriterSend::Closed(err) => Err(err),
            }
        } else {
            self.pending_ctrl.push_back(frame);
            Ok(())
        }
    }

    fn pump_ctrl(&mut self) -> Result<(), CoreError> {
        while self.in_flight_ctrl.is_none() {
            let Some(frame) = self.pending_ctrl.pop_front() else {
                break;
            };
            match self.writer.try_send_hop_control(frame) {
                TryWriterSend::Sent => {}
                TryWriterSend::Full(frame) => {
                    let wh = self.writer.clone();
                    self.in_flight_ctrl =
                        Some(Box::pin(async move { wh.send_hop_control(frame).await }));
                    break;
                }
                TryWriterSend::Closed(err) => return Err(err),
            }
        }
        Ok(())
    }

    fn enqueue_data(
        &mut self,
        cmd: WriterDataCmd,
        permit: Option<SemaphorePermit>,
    ) -> Result<(), CoreError> {
        if self.in_flight_data.is_none() && self.pending_data.is_empty() {
            match self.writer.try_send_data(cmd) {
                TryWriterSend::Sent => {
                    drop(permit);
                    Ok(())
                }
                TryWriterSend::Full(cmd) => {
                    let wh = self.writer.clone();
                    self.in_flight_data = Some(Box::pin(async move {
                        let _permit = permit;
                        wh.send_data(cmd).await
                    }));
                    Ok(())
                }
                TryWriterSend::Closed(err) => Err(err),
            }
        } else {
            self.pending_data.push_back((cmd, permit));
            Ok(())
        }
    }

    fn pump_data(&mut self) -> Result<(), CoreError> {
        while self.in_flight_data.is_none() {
            let Some((cmd, permit)) = self.pending_data.pop_front() else {
                break;
            };
            match self.writer.try_send_data(cmd) {
                TryWriterSend::Sent => drop(permit),
                TryWriterSend::Full(cmd) => {
                    let wh = self.writer.clone();
                    self.in_flight_data = Some(Box::pin(async move {
                        let _permit = permit;
                        wh.send_data(cmd).await
                    }));
                    break;
                }
                TryWriterSend::Closed(err) => return Err(err),
            }
        }
        Ok(())
    }

    fn poll_ctrl(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
        poll_optional(&mut self.in_flight_ctrl, cx)
    }

    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
        poll_optional(&mut self.in_flight_data, cx)
    }

    fn fail_pending_waiters(&mut self, err: &CoreError) {
        self.in_flight_ctrl = None;
        self.in_flight_data = None;
        self.pending_ctrl.clear();
        while let Some((cmd, _)) = self.pending_data.pop_front() {
            if let WriterDataCmd::FlushAck(ack_tx) = cmd {
                let _ = ack_tx.try_send(Err(err.clone()));
            }
        }
    }
}

/// Spawns the steady-state E2E Stream worker (with zero-mutex single-owner writer and
/// concurrent reader) and returns the [`E2eStream`] handle.
pub(crate) fn spawn_stream_session(params: StreamSessionParams) -> E2eStream {
    let max_write_size =
        usize::from(params.negotiated_mtu.min(STREAM_CHUNK as u16)).saturating_sub(ST_OVERHEAD);
    let (app_read_tx, app_read_rx) = async_channel::bounded::<Result<Vec<u8>, CoreError>>(16);
    let (app_write_tx, app_write_rx) =
        async_channel::bounded::<AppWriteMsg>(APP_WRITE_CHANNEL_CAPACITY);
    let data_sem = CloseableSemaphore::new(APP_WRITE_CAPACITY);
    let (closed_tx, closed_rx) = Watch::new(None::<CoreError>);
    let (read_alive_tx, read_alive_rx) = Watch::new(());

    let peer = params.peer;
    let negotiated_mtu = params.negotiated_mtu;
    let spawner = Arc::clone(&params.scope.runtime.spawner);
    let worker_sem = Arc::clone(&data_sem);

    spawner.spawn(Box::pin(async move {
        run_stream_session(
            params,
            max_write_size,
            app_read_tx,
            app_write_rx,
            worker_sem,
            closed_tx,
            read_alive_rx,
        )
        .await;
    }));

    E2eStream {
        read: E2eStreamRead {
            rx: Box::pin(app_read_rx),
            buf: Vec::new(),
            pos: 0,
            eof: false,
            closed_err: closed_rx.clone(),
            _alive: read_alive_tx,
            peer,
        },
        write: E2eStreamWrite {
            tx: app_write_tx,
            data_sem,
            max_write_size,
            closed_err: closed_rx,
            pending_permit: None,
            pending_flush_send: None,
            flush_rx: None,
            pending_shutdown_send: None,
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
    data_sem: Arc<CloseableSemaphore>,
    closed_tx: Watch<Option<CoreError>>,
    mut read_alive_rx: WatchReceiver<()>,
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

    // Spawn single-owner writer task (ZERO async mutexes, interruptible teardown).
    let writer_handle = StreamWriterHandle::spawn(
        writer,
        mtu_watch.clone(),
        floor,
        Arc::clone(&clock),
        &*scope.runtime.spawner,
    );
    let mut outbound = OutboundWriterQueue::new(writer_handle.clone());

    // Spawn concurrent carrier reader task splitting renewal controls from ordered ST_DATA/ST_FIN
    // with causal `data_seq` tagging (ST-04) and session-termination cancellation (ST-08).
    let (ctrl_in_tx, ctrl_in_rx) = async_channel::bounded::<InboundCtrlMsg>(32);
    let (data_in_tx, data_in_rx) = async_channel::bounded::<(u64, InboundDataMsg)>(16);
    let (reader_cancel_tx, mut reader_cancel_rx) = Watch::new(false);
    let (reader_done_tx, mut reader_done_rx) = Watch::new(false);
    {
        let ctrl_tx = ctrl_in_tx.clone();
        let data_tx = data_in_tx.clone();
        scope.runtime.spawner.spawn(Box::pin(async move {
            let _ = race2(
                async move {
                    let mut data_seq: u64 = 0;
                    loop {
                        match frame_reader.next_frame(&mut *reader, &mut rx_cipher).await {
                            Ok(InboundStreamFrame::Eof) => {
                                data_seq = data_seq.saturating_add(1);
                                let _ = data_tx.send((data_seq, InboundDataMsg::CarrierEof)).await;
                                break;
                            }
                            Ok(InboundStreamFrame::HopControl { hdr, body, len }) => {
                                if ctrl_tx
                                    .send(InboundCtrlMsg::HopControl {
                                        after_seq: data_seq,
                                        hdr,
                                        body,
                                        len,
                                    })
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
                                    data_seq = data_seq.saturating_add(1);
                                    if data_tx
                                        .send((data_seq, InboundDataMsg::Data(body)))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                e2e_st::ST_FIN => {
                                    if !body.is_empty() {
                                        let _ = ctrl_tx
                                            .send(InboundCtrlMsg::ReadError {
                                                after_seq: data_seq,
                                                err: CoreError::Malformed,
                                            })
                                            .await;
                                        break;
                                    }
                                    data_seq = data_seq.saturating_add(1);
                                    if data_tx
                                        .send((data_seq, InboundDataMsg::Fin))
                                        .await
                                        .is_err()
                                    {
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
                                    if ctrl_tx
                                        .send(InboundCtrlMsg::E2eRenewOk(body))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                _ => {
                                    let _ = ctrl_tx
                                        .send(InboundCtrlMsg::ReadError {
                                            after_seq: data_seq,
                                            err: CoreError::Malformed,
                                        })
                                        .await;
                                    break;
                                }
                            },
                            Err(err) => {
                                let _ = ctrl_tx
                                    .send(InboundCtrlMsg::ReadError {
                                        after_seq: data_seq,
                                        err,
                                    })
                                    .await;
                                break;
                            }
                        }
                    }
                },
                wait_signal(&mut reader_cancel_rx),
            )
            .await;
            // `reader`, `frame_reader`, and `rx_cipher` are dropped above before signalling done.
            reader_done_tx.send(true);
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

    let mut fin_queued = false;
    let mut sent_fin = false;
    let mut received_fin = false;
    let mut carrier_eof = false;
    let mut ctrl_in_closed = false;
    let mut shutdown_initiated = false;
    let mut deferred_shutdown_fin = false;
    let mut app_read_closed = false;
    let mut app_write_closed = false;

    // Causal inbound ordering state (ST-04).
    let mut processed_data_seq: u64 = 0;
    let mut deferred_terminals: VecDeque<DeferredTerminal> = VecDeque::new();

    // Paced TrafficGate delays & non-blocking app/writer states (never stall control frames!).
    let mut delayed_ingress: Option<(Vec<u8>, MonotonicTime)> = None;
    let mut delayed_egress: Option<(Vec<u8>, SemaphorePermit, MonotonicTime)> = None;
    let mut pending_app_read: Option<Pin<Box<dyn Future<Output = ()> + Send>>> = None;
    let mut pending_app_writes: VecDeque<AppWriteMsg> = VecDeque::new();
    let mut pending_fin_ack: Option<UnitResultFut> = None;
    let mut pending_shutdown_waiters: Vec<async_channel::Sender<Result<(), CoreError>>> =
        Vec::new();

    // Check live MTU immediately at startup and synchronize watch baseline.
    let initial_mtu = mtu_watch.sample();
    let terminal_reason: CoreError = if initial_mtu < floor {
        CoreError::MtuTooSmall(initial_mtu)
    } else {
        loop {
            // 1. Evaluate any causally-deferred terminal events whose preceding data/FIN completed.
            let mut deferred_fatal: Option<CoreError> = None;
            while let Some(front) = deferred_terminals.front() {
                let ready = match front {
                    DeferredTerminal::HopClose { after_seq, .. } => {
                        processed_data_seq >= *after_seq
                    }
                    DeferredTerminal::ReadError { after_seq, .. } => {
                        processed_data_seq >= *after_seq
                            || pending_app_read.is_some()
                            || delayed_ingress.is_some()
                    }
                };
                if !ready {
                    break;
                }
                let Some(term) = deferred_terminals.pop_front() else {
                    break;
                };
                match term {
                    DeferredTerminal::HopClose { dist, reason, .. } => {
                        if let TerminalAction::Terminate(err) = eval_hop_close(
                            &role,
                            dist,
                            reason,
                            received_fin,
                            sent_fin,
                            pending_app_read.is_some(),
                        ) {
                            deferred_fatal = Some(err);
                            break;
                        }
                    }
                    DeferredTerminal::ReadError { err, .. } => {
                        if received_fin && sent_fin {
                            if pending_app_read.is_none() {
                                deferred_fatal = Some(CoreError::Closed);
                                break;
                            }
                        } else {
                            deferred_fatal = Some(err);
                            break;
                        }
                    }
                }
            }
            if let Some(err) = deferred_fatal {
                break err;
            }

            if sent_fin && received_fin && pending_app_read.is_none() {
                break CoreError::Closed;
            }
            if (app_read_closed || app_read_tx.is_closed()) && app_write_closed {
                break CoreError::Closed;
            }

            // Compute next scheduled wake deadline across renewals and TrafficGate delays.
            let renewal_dl = match &role {
                StreamSessionRole::Origin(orig) => orig.renewals.next_deadline(),
                StreamSessionRole::Destination(_) => None,
            };
            let ingress_dl = delayed_ingress.as_ref().map(|(_, dl)| *dl);
            let egress_dl = delayed_egress.as_ref().map(|(_, _, dl)| *dl);
            let next_timer = [renewal_dl, ingress_dl, egress_dl]
                .into_iter()
                .flatten()
                .min();

            // Event step: poll ALL concurrent sources including pending writer sends & FIN flush ack!
            enum StepEvent {
                LeaseCancelled(CoreError),
                MtuBelowFloor(u16),
                WriterFailed(CoreError),
                ScopeShutdown,
                WriterCtrlSent(Result<(), CoreError>),
                WriterDataSent(Result<(), CoreError>),
                FinFlushed(Result<(), CoreError>),
                CtrlIn(Result<InboundCtrlMsg, async_channel::RecvError>),
                DataIn(Result<(u64, InboundDataMsg), async_channel::RecvError>),
                AppReadDrained,
                AppReadClosed,
                AppWrite(Result<AppWriteMsg, async_channel::RecvError>),
                CredFetched(RenewalSlot, Result<Credential, CoreError>),
                DestAuthDone(u64, Result<Lease, CoreError>),
                TimerFired,
            }

            let can_poll_data_in =
                !carrier_eof && delayed_ingress.is_none() && pending_app_read.is_none();
            // Always observe app_write_rx until closed (even after ST_FIN / under backpressure, ST-06)!
            let can_poll_app_write = !app_write_closed;

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
                let mut read_alive_fut = Box::pin(async {
                    if app_read_closed {
                        core::future::pending::<()>().await;
                    } else {
                        while read_alive_rx.changed().await {}
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
                    if let Poll::Ready(res) = outbound.poll_ctrl(cx) {
                        return Poll::Ready(StepEvent::WriterCtrlSent(res));
                    }
                    if let Poll::Ready(res) = outbound.poll_data(cx) {
                        return Poll::Ready(StepEvent::WriterDataSent(res));
                    }
                    if let Poll::Ready(res) = poll_optional(&mut pending_fin_ack, cx) {
                        return Poll::Ready(StepEvent::FinFlushed(res));
                    }
                    if let Poll::Ready(msg) = ctrl_fut.as_mut().poll(cx) {
                        return Poll::Ready(StepEvent::CtrlIn(msg));
                    }
                    if let Poll::Ready((id, res)) = poll_optional(&mut dest_auth_fut, cx) {
                        return Poll::Ready(StepEvent::DestAuthDone(id, res));
                    }
                    if !cred_futs.is_empty() {
                        if let Poll::Ready(Some((slot, res))) =
                            Pin::new(&mut cred_futs).poll_next(cx)
                        {
                            return Poll::Ready(StepEvent::CredFetched(slot, res));
                        }
                    }
                    if let Poll::Ready(()) = poll_optional(&mut pending_app_read, cx) {
                        return Poll::Ready(StepEvent::AppReadDrained);
                    }
                    if let Poll::Ready(()) = read_alive_fut.as_mut().poll(cx) {
                        return Poll::Ready(StepEvent::AppReadClosed);
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
                    if sent_fin && received_fin && pending_app_read.is_none() {
                        break CoreError::Closed;
                    }
                    break err;
                }
                StepEvent::WriterCtrlSent(Ok(())) => {
                    if let Err(err) = outbound.pump_ctrl() {
                        break err;
                    }
                }
                StepEvent::WriterCtrlSent(Err(err)) | StepEvent::WriterDataSent(Err(err)) => {
                    if sent_fin && received_fin && pending_app_read.is_none() {
                        break CoreError::Closed;
                    }
                    break err;
                }
                StepEvent::WriterDataSent(Ok(())) => {
                    if let Err(err) = outbound.pump_data() {
                        break err;
                    }
                }
                StepEvent::FinFlushed(Ok(())) => {
                    sent_fin = true;
                    for tx in pending_shutdown_waiters.drain(..) {
                        let _ = tx.try_send(Ok(()));
                    }
                }
                StepEvent::FinFlushed(Err(err)) => {
                    if sent_fin && received_fin && pending_app_read.is_none() {
                        break CoreError::Closed;
                    }
                    break err;
                }
                StepEvent::ScopeShutdown => {
                    shutdown_initiated = true;
                    data_sem.close();
                    if !fin_queued {
                        if delayed_egress.is_some() {
                            deferred_shutdown_fin = true;
                        } else if let Err(err) = initiate_fin(
                            &data_sem,
                            &mut fin_queued,
                            &mut tx_cipher,
                            &mut e2e_scratch,
                            &mut outbound,
                            &mut pending_fin_ack,
                        ) {
                            break err;
                        }
                    }
                }
                StepEvent::CtrlIn(Err(_)) => {
                    ctrl_in_closed = true;
                    // Reader exited; data_in_rx will deliver any trailing Eof or Fin.
                    if received_fin && sent_fin && pending_app_read.is_none() {
                        break CoreError::Closed;
                    }
                }
                StepEvent::CtrlIn(Ok(InboundCtrlMsg::ReadError { after_seq, err })) => {
                    if processed_data_seq < after_seq
                        && pending_app_read.is_none()
                        && delayed_ingress.is_none()
                    {
                        deferred_terminals.push_back(DeferredTerminal::ReadError { after_seq, err });
                    } else if received_fin && sent_fin {
                        if pending_app_read.is_none() {
                            break CoreError::Closed;
                        }
                    } else {
                        break err;
                    }
                }
                StepEvent::CtrlIn(Ok(InboundCtrlMsg::HopControl {
                    after_seq,
                    hdr,
                    body,
                    len,
                })) => {
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
                                    let should_defer = processed_data_seq < after_seq
                                        && (matches!(
                                            decoded,
                                            CoreError::Closed | CoreError::UnexpectedEof
                                        ) || (sent_fin
                                            && pending_app_read.is_none()
                                            && delayed_ingress.is_none()));
                                    if should_defer {
                                        deferred_terminals.push_back(DeferredTerminal::HopClose {
                                            after_seq,
                                            dist: hdr.ttl_or_dist,
                                            reason: decoded,
                                        });
                                    } else if let TerminalAction::Terminate(err) = eval_hop_close(
                                        &role,
                                        hdr.ttl_or_dist,
                                        decoded,
                                        received_fin,
                                        sent_fin,
                                        pending_app_read.is_some(),
                                    ) {
                                        break err;
                                    }
                                }
                                outer::ST_RENEW_OK => {
                                    if dist >= n {
                                        break CoreError::Authentication;
                                    }
                                    let pt = match orig.hops[dist]
                                        .2
                                        .open(outer::ST_RENEW_OK, wire_body)
                                    {
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
                                let should_defer = processed_data_seq < after_seq
                                    && (matches!(
                                        decoded,
                                        CoreError::Closed | CoreError::UnexpectedEof
                                    ) || (sent_fin
                                        && pending_app_read.is_none()
                                        && delayed_ingress.is_none()));
                                if should_defer {
                                    deferred_terminals.push_back(DeferredTerminal::HopClose {
                                        after_seq,
                                        dist: 0,
                                        reason: decoded,
                                    });
                                } else if let TerminalAction::Terminate(err) = eval_hop_close(
                                    &role,
                                    0,
                                    decoded,
                                    received_fin,
                                    sent_fin,
                                    pending_app_read.is_some(),
                                ) {
                                    break err;
                                }
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
                            if let Err(err) = seal_and_queue_e2e(
                                &mut tx_cipher,
                                e2e_st::ST_RENEW_OK,
                                &payload,
                                &mut e2e_scratch,
                                &mut outbound,
                                None,
                            ) {
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
                        if let Err(err) = lease
                            .renew_lease_with_max_ttl(new_lease, scope.auth_limits.max_lease_ttl)
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
                        if let Err(err) = seal_and_queue_e2e(
                            &mut tx_cipher,
                            e2e_st::ST_RENEW_OK,
                            &payload,
                            &mut e2e_scratch,
                            &mut outbound,
                            None,
                        ) {
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
                            if let Err(err) = queue_origin_stream_renewal(
                                slot,
                                renewal_id,
                                &credential,
                                &mut tx_cipher,
                                &mut orig.hops,
                                &mut e2e_scratch,
                                &mut outbound,
                            ) {
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
                    if let Some((_, _, dl)) = &delayed_egress {
                        if now >= *dl {
                            if let Some((data, permit, _)) = delayed_egress.take() {
                                if let Err(err) = lease.remaining() {
                                    break err;
                                }
                                let len = data.len();
                                if let Err(err) = seal_and_queue_e2e(
                                    &mut tx_cipher,
                                    e2e_st::ST_DATA,
                                    &data,
                                    &mut e2e_scratch,
                                    &mut outbound,
                                    Some(permit),
                                ) {
                                    break err;
                                }
                                scope.metrics.record_tx(Plane::Stream, len as u64, false);

                                if deferred_shutdown_fin && !fin_queued {
                                    deferred_shutdown_fin = false;
                                    if let Err(err) = initiate_fin(
                                        &data_sem,
                                        &mut fin_queued,
                                        &mut tx_cipher,
                                        &mut e2e_scratch,
                                        &mut outbound,
                                        &mut pending_fin_ack,
                                    ) {
                                        break err;
                                    }
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
                                        RenewalSlot::Hop(i) => {
                                            (orig.hops[i].0, orig.hops[i].1.clone())
                                        }
                                    };
                                    let timeout =
                                        scope.auth_limits.auth_timeout.min(remaining / 2);
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
                                    if let Err(err) = queue_origin_stream_renewal(
                                        slot,
                                        renewal_id,
                                        &credential,
                                        &mut tx_cipher,
                                        &mut orig.hops,
                                        &mut e2e_scratch,
                                        &mut outbound,
                                    ) {
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
                StepEvent::AppReadClosed => {
                    app_read_closed = true;
                    if app_write_closed {
                        break CoreError::Closed;
                    }
                }
                StepEvent::DataIn(Err(_)) => {
                    carrier_eof = true;
                    processed_data_seq = u64::MAX;
                    if !received_fin {
                        break CoreError::UnexpectedEof;
                    }
                    if sent_fin && pending_app_read.is_none() {
                        break CoreError::Closed;
                    }
                    data_in_rx.close();
                }
                StepEvent::DataIn(Ok((seq, InboundDataMsg::CarrierEof))) => {
                    processed_data_seq = seq;
                    carrier_eof = true;
                    if !received_fin {
                        break CoreError::UnexpectedEof;
                    }
                    if sent_fin && pending_app_read.is_none() {
                        break CoreError::Closed;
                    }
                    // Spec §6.4: Once ST_FIN is received, carrier EOF does NOT abort outbound half
                    // until local ST_FIN is also sent!
                    data_in_rx.close();
                }
                StepEvent::DataIn(Ok((seq, InboundDataMsg::Fin))) => {
                    processed_data_seq = seq;
                    if received_fin {
                        // Duplicate ST_FIN is Malformed (Spec §5.8.2).
                        break CoreError::Malformed;
                    }
                    received_fin = true;
                    enqueue_app_read(&app_read_tx, Ok(Vec::new()), &mut pending_app_read);
                }
                StepEvent::DataIn(Ok((seq, InboundDataMsg::Data(body)))) => {
                    processed_data_seq = seq;
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
                    if app_read_closed || app_read_tx.is_closed() {
                        break CoreError::Closed;
                    }
                }
                StepEvent::AppWrite(Ok(msg)) => {
                    pending_app_writes.push_back(msg);
                }
            }

            // Drain pending app writes non-blockingly (ST-01, ST-06):
            // - Once `fin_queued` is true, immediately discard any stray Data and service Flush/Shutdown.
            // - Otherwise, drain while neither egress-delayed nor waiting on writer backpressure.
            let mut fatal_write: Option<CoreError> = None;
            loop {
                if fin_queued {
                    let Some(msg) = pending_app_writes.pop_front() else {
                        break;
                    };
                    match msg {
                        AppWriteMsg::Data(_, _permit) => {}
                        AppWriteMsg::Flush(ack_tx) => {
                            if sent_fin {
                                let _ = ack_tx.try_send(Ok(()));
                            } else if let Err(err) =
                                outbound.enqueue_data(WriterDataCmd::FlushAck(ack_tx), None)
                            {
                                fatal_write = Some(err);
                                break;
                            }
                        }
                        AppWriteMsg::Shutdown(ack_tx) => {
                            if sent_fin {
                                let _ = ack_tx.try_send(Ok(()));
                            } else {
                                pending_shutdown_waiters.push(ack_tx);
                            }
                        }
                    }
                    continue;
                }

                if delayed_egress.is_some() || !outbound.is_data_idle() {
                    break;
                }
                let Some(msg) = pending_app_writes.pop_front() else {
                    break;
                };
                match msg {
                    AppWriteMsg::Data(data, permit) => {
                        if deferred_shutdown_fin {
                            continue;
                        }
                        if matches!(role, StreamSessionRole::Destination(_)) {
                            if let Some(gate) = gate_cache.get(&lease) {
                                match gate.charge_stream(Direction::Egress, data.len()) {
                                    StreamAction::Allow => {}
                                    StreamAction::Delay(d) => {
                                        let dl = clock.now().saturating_add(d);
                                        delayed_egress = Some((data, permit, dl));
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
                        if let Err(err) = seal_and_queue_e2e(
                            &mut tx_cipher,
                            e2e_st::ST_DATA,
                            &data,
                            &mut e2e_scratch,
                            &mut outbound,
                            Some(permit),
                        ) {
                            fatal_write = Some(err);
                            break;
                        }
                        scope.metrics.record_tx(Plane::Stream, len as u64, false);
                    }
                    AppWriteMsg::Flush(ack_tx) => {
                        if let Err(err) =
                            outbound.enqueue_data(WriterDataCmd::FlushAck(ack_tx), None)
                        {
                            fatal_write = Some(err);
                            break;
                        }
                    }
                    AppWriteMsg::Shutdown(ack_tx) => {
                        if let Err(err) = initiate_fin(
                            &data_sem,
                            &mut fin_queued,
                            &mut tx_cipher,
                            &mut e2e_scratch,
                            &mut outbound,
                            &mut pending_fin_ack,
                        ) {
                            let _ = ack_tx.try_send(Err(err.clone()));
                            fatal_write = Some(err);
                            break;
                        }
                        pending_shutdown_waiters.push(ack_tx);
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

    // 1. Publish terminal status to local app handles & bridge supervisor BEFORE closing queues.
    closed_tx.send(Some(terminal_reason.clone()));
    data_sem.close();
    if !received_fin {
        let _ = app_read_tx.try_send(Err(terminal_reason.clone()));
    }
    app_read_tx.close();
    app_write_rx.close();

    // Wake any pending flush/shutdown waiters deterministically with the terminal error.
    for tx in pending_shutdown_waiters.drain(..) {
        let _ = tx.try_send(Err(terminal_reason.clone()));
    }
    while let Some(msg) = pending_app_writes.pop_front() {
        match msg {
            AppWriteMsg::Flush(tx) | AppWriteMsg::Shutdown(tx) => {
                let _ = tx.try_send(Err(terminal_reason.clone()));
            }
            AppWriteMsg::Data(_, _) => {}
        }
    }
    outbound.fail_pending_waiters(&terminal_reason);
    drop(pending_fin_ack);
    drop(pending_app_read);
    drop(delayed_egress);

    // 2. Cancel carrier reader task immediately (ST-08).
    reader_cancel_tx.send(true);
    ctrl_in_rx.close();
    data_in_rx.close();

    // 3. Teardown writer task (interrupting blocked carrier writes, ST-01) per Spec §6.4:
    //    - Origin: best-effort 50 ms hop::ST_CLOSE(reason) to hops N-1..0, shut down carrier, report PathOutcome.
    //    - Destination: best-effort 50 ms hop::ST_CLOSE(reason) (ttl = 0, terminal_key) ONLY if reason != Closed,
    //      plus carrier shutdown.
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
            writer_handle.teardown(close_frames, true).await;
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
            }
            writer_handle.teardown(close_frames, true).await;
        }
    }

    // 4. Await carrier reader task completion before releasing `_session_permit` (ST-08).
    wait_signal(&mut reader_done_rx).await;
}

fn eval_hop_close(
    role: &StreamSessionRole,
    dist: u8,
    reason: CoreError,
    received_fin: bool,
    sent_fin: bool,
    pending_app_read: bool,
) -> TerminalAction {
    if received_fin && sent_fin {
        return if pending_app_read {
            TerminalAction::Continue
        } else {
            TerminalAction::Terminate(CoreError::Closed)
        };
    }
    // Spec §6.4: Once ST_FIN is received, hop ST_CLOSE(Closed/UnexpectedEof)
    // does NOT abort outbound half until local ST_FIN is also sent.
    if received_fin
        && !sent_fin
        && matches!(reason, CoreError::Closed | CoreError::UnexpectedEof)
    {
        return TerminalAction::Continue;
    }
    let err = match role {
        StreamSessionRole::Origin(orig) => {
            if usize::from(dist) == orig.hops.len() {
                reason
            } else {
                CoreError::hop_rejected(dist, reason)
            }
        }
        StreamSessionRole::Destination(_) => reason,
    };
    TerminalAction::Terminate(err)
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

fn seal_and_queue_e2e(
    tx_cipher: &mut StreamCipher,
    opcode: u8,
    body: &[u8],
    scratch: &mut Vec<u8>,
    outbound: &mut OutboundWriterQueue,
    permit: Option<SemaphorePermit>,
) -> Result<(), CoreError> {
    tx_cipher.seal_into(opcode, body, scratch)?;
    outbound.enqueue_data(WriterDataCmd::E2eBytes(scratch.clone()), permit)
}

fn initiate_fin(
    data_sem: &CloseableSemaphore,
    fin_queued: &mut bool,
    tx_cipher: &mut StreamCipher,
    e2e_scratch: &mut Vec<u8>,
    outbound: &mut OutboundWriterQueue,
    pending_fin_ack: &mut Option<UnitResultFut>,
) -> Result<(), CoreError> {
    data_sem.close();
    if *fin_queued {
        return Ok(());
    }
    *fin_queued = true;
    tx_cipher.seal_into(e2e_st::ST_FIN, &[], e2e_scratch)?;
    outbound.enqueue_data(WriterDataCmd::E2eBytes(e2e_scratch.clone()), None)?;
    let (fin_tx, fin_rx) = async_channel::bounded::<Result<(), CoreError>>(1);
    outbound.enqueue_data(WriterDataCmd::FlushAck(fin_tx), None)?;
    let wh = outbound.writer().clone();
    *pending_fin_ack = Some(Box::pin(async move {
        match fin_rx.recv().await {
            Ok(res) => res,
            Err(_) => Err(wh.last_error().unwrap_or(CoreError::Closed)),
        }
    }));
    Ok(())
}

fn queue_origin_stream_renewal(
    slot: RenewalSlot,
    renewal_id: u64,
    credential: &Credential,
    tx_cipher: &mut StreamCipher,
    hops: &mut [(PublicKey, String, ControlCipher)],
    scratch: &mut Vec<u8>,
    outbound: &mut OutboundWriterQueue,
) -> Result<(), CoreError> {
    let payload = encode_renew_payload(renewal_id, credential.as_bytes())?;
    match slot {
        RenewalSlot::Endpoint => {
            seal_and_queue_e2e(tx_cipher, e2e_st::ST_RENEW, &payload, scratch, outbound, None)
        }
        RenewalSlot::Hop(i) => {
            let ttl = u8::try_from(i).map_err(|_| CoreError::Malformed)?;
            let sealed = hops
                .get_mut(i)
                .ok_or(CoreError::Malformed)?
                .2
                .seal(outer::ST_RENEW, &payload)?;
            let frame = PriorityCtrlFrame::from_slice(outer::ST_RENEW, ttl, &sealed)?;
            outbound.enqueue_ctrl(frame)
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
