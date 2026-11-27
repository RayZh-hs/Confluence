//! Stream setup reader (stack-only `mac1` precheck), reliable 3 s backoff `write_frame`,
//! E2E record chunker/reassembler with interleaved hop control demux, and zero-mutex single-owner writer.

use core::future::poll_fn;
use core::pin::Pin;
use core::task::Poll;
use core::time::Duration;
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::constants::{
    CLOSE_SEND_TIMEOUT, COOKIE_SIZE, ERR_SIZE, FWD_HEADER, HOP_ACK_SIZE, MAX_CONTROL,
    MAX_SETUP_SEGMENT, OK_SIZE, ST_HOP_HEADER, ST_OVERHEAD, STREAM_CHUNK,
    STREAM_WRITE_BACKOFF_CAP, STREAM_WRITE_BACKOFF_INITIAL, STREAM_WRITE_RETRY_BUDGET,
};
use crate::crypto::cipher::StreamCipher;
use crate::engine::context::{
    Either, ScopeCore, ScopeResolver, race2, wait_signal, with_deadline,
};
use crate::error::CoreError;
use crate::runtime::sync::{Watch, WatchReceiver};
use crate::runtime::{Clock, MonotonicTime, TaskSpawner};
use crate::seam::channel::{MtuWatch, StreamRead, StreamReadExt, StreamWrite, StreamWriteExt};
use crate::types::ScopeKid;
use crate::wire::opcodes::{e2e_st, outer};
use crate::wire::setup::{
    DispatchPrefix, ForwardHeader, MODE_DEST, MODE_HOP, SetupCookieFrame, SetupErrFrame,
};
use crate::wire::stream::{StHopHeader, validate_st_e2e_body_len};

// ---------------------------------------------------------------------------
// Stack-Buffered SETUP_FWD Reader (Spec §5.2 & §6.2 Stream Step 2)
// ---------------------------------------------------------------------------

/// Verified Stream `SETUP_FWD` read from an inbound carrier stream.
pub(crate) struct ReadSetupFwd {
    pub scope: Arc<ScopeCore>,
    pub hdr: ForwardHeader,
    pub prefix: DispatchPrefix,
    pub prefix_bytes: [u8; 8],
    pub prefix_len: usize,
    pub encrypted: Vec<u8>,
    pub tail: Vec<u8>,
}

/// Reads and pre-verifies a Stream `SETUP_FWD` within `deadline`.
///
/// Validates `ForwardHeader`, `DispatchPrefix`, Stream size bounds, `ScopeKid`, and `mac1`
/// purely on stack buffers (`[u8; 8]` and `[u8; 2048]`) BEFORE heap-allocating `tail`.
/// Invalid `mac1` or unknown `ScopeKid` fails with [`CoreError::BadMac`] and **0 heap allocations**.
pub(crate) async fn read_setup_fwd<R: StreamRead + ?Sized>(
    reader: &mut R,
    resolver: &dyn ScopeResolver,
    clock: &dyn Clock,
    deadline: MonotonicTime,
) -> Result<ReadSetupFwd, CoreError> {
    with_deadline(clock, deadline, async {
        let mut hdr_buf = [0u8; FWD_HEADER];
        reader.read_exact(&mut hdr_buf).await?;
        let hdr = ForwardHeader::parse(&hdr_buf)?;
        if !hdr.upstream.is_unbound() {
            return Err(CoreError::Malformed);
        }

        let mut prefix_buf = [0u8; 8];
        reader.read_exact(&mut prefix_buf[..6]).await?;
        let mode = prefix_buf[0];
        if (mode & !0x13) != 0 {
            return Err(CoreError::Malformed);
        }
        let prefix_len = match mode & 0x0f {
            MODE_HOP => {
                reader.read_exact(&mut prefix_buf[6..8]).await?;
                8
            }
            MODE_DEST => 6,
            _ => return Err(CoreError::Malformed),
        };
        let (prefix, _) = DispatchPrefix::parse(&prefix_buf[..prefix_len])?;

        let seg_len = usize::from(prefix.seg_len);
        let tail_len = usize::from(prefix.tail_len);
        if seg_len > MAX_SETUP_SEGMENT || FWD_HEADER + prefix.encoded_total_len() > STREAM_CHUNK {
            return Err(CoreError::Malformed);
        }

        let mut seg_buf = [0u8; MAX_SETUP_SEGMENT];
        reader.read_exact(&mut seg_buf[..seg_len]).await?;

        let mut kid_bytes = [0u8; 8];
        kid_bytes.copy_from_slice(&seg_buf[0..8]);
        let kid = ScopeKid::from_bytes(kid_bytes);

        let Some(scope) = resolver.resolve(kid) else {
            resolver.record_unknown_scope();
            return Err(CoreError::BadMac);
        };

        if !scope
            .cookies
            .verify_mac1_only(&seg_buf[..seg_len], prefix.has_mac2)
        {
            resolver.record_mac1_drop(Some(&scope));
            return Err(CoreError::BadMac);
        }

        // Only allocate heap buffers AFTER ScopeKid and mac1 succeeded on the stack.
        let mut tail = if tail_len > 0 {
            vec![0u8; tail_len]
        } else {
            Vec::new()
        };
        if !tail.is_empty() {
            reader.read_exact(&mut tail).await?;
        }

        Ok(ReadSetupFwd {
            scope,
            hdr,
            prefix,
            prefix_bytes: prefix_buf,
            prefix_len,
            encrypted: seg_buf[..seg_len].to_vec(),
            tail,
        })
    })
    .await
}

// ---------------------------------------------------------------------------
// Stream Setup Reply Reader (Originator & Transit)
// ---------------------------------------------------------------------------

/// Decoded Stream setup reply frame (`SETUP_OK`, `SETUP_ERR`, or `SETUP_COOKIE`).
pub(crate) enum StreamSetupReply {
    Ok(Vec<u8>),
    Err(SetupErrFrame),
    Cookie(SetupCookieFrame),
}

/// Reads a single Stream setup reply (`SETUP_OK`, `SETUP_ERR`, or `SETUP_COOKIE`) within `deadline`.
pub(crate) async fn read_setup_reply<R: StreamRead + ?Sized>(
    reader: &mut R,
    clock: &dyn Clock,
    deadline: MonotonicTime,
) -> Result<StreamSetupReply, CoreError> {
    with_deadline(clock, deadline, async {
        let mut first = [0u8; 1];
        reader.read_exact(&mut first).await?;
        match first[0] {
            outer::SETUP_ERR => {
                let mut buf = [0u8; ERR_SIZE];
                buf[0] = outer::SETUP_ERR;
                reader.read_exact(&mut buf[1..]).await?;
                Ok(StreamSetupReply::Err(SetupErrFrame::parse(&buf)?))
            }
            outer::SETUP_COOKIE => {
                let mut buf = [0u8; COOKIE_SIZE];
                buf[0] = outer::SETUP_COOKIE;
                reader.read_exact(&mut buf[1..]).await?;
                Ok(StreamSetupReply::Cookie(SetupCookieFrame::parse(&buf)?))
            }
            outer::SETUP_OK => {
                let mut hdr = [0u8; 12];
                hdr[0] = outer::SETUP_OK;
                reader.read_exact(&mut hdr[1..]).await?;
                let hop_acks = hdr[1];
                let total = OK_SIZE + HOP_ACK_SIZE * usize::from(hop_acks);
                if total > STREAM_CHUNK {
                    return Err(CoreError::Malformed);
                }
                let mut wire = vec![0u8; total];
                wire[..12].copy_from_slice(&hdr);
                reader.read_exact(&mut wire[12..]).await?;
                Ok(StreamSetupReply::Ok(wire))
            }
            _ => Err(CoreError::Malformed),
        }
    })
    .await
}

// ---------------------------------------------------------------------------
// Reliable Stream Frame Writing (Spec §6.4)
// ---------------------------------------------------------------------------

enum BudgetStep<T> {
    Expired,
    Done(Result<T, CoreError>),
}

/// Polls `fut`, enforcing `budget_deadline` once anchored across both wait time and completion
/// (`clock.now() >= deadline` fails closed with `BudgetStep::Expired`, Spec §6.4 / ST-02).
async fn await_budgeted<F, T>(
    clock: &dyn Clock,
    budget_deadline: Option<MonotonicTime>,
    fut: F,
) -> BudgetStep<T>
where
    F: core::future::Future<Output = Result<T, CoreError>>,
{
    let Some(deadline) = budget_deadline else {
        return BudgetStep::Done(fut.await);
    };
    if clock.now() >= deadline {
        return BudgetStep::Expired;
    }
    match race2(fut, clock.sleep_until(deadline)).await {
        Either::Left(res) => {
            if clock.now() >= deadline {
                BudgetStep::Expired
            } else {
                BudgetStep::Done(res)
            }
        }
        Either::Right(()) => BudgetStep::Expired,
    }
}

/// Writes `data` completely and flushes once, resuming exact unwritten slices across retryable
/// carrier errors with exponential backoff (`10 -> 20 -> 40 -> 80 -> 160 -> 200 ms`, resetting
/// to `10 ms` on any written byte) within a `3 s` budget from the first retryable error.
pub(crate) async fn write_frame<W: StreamWrite + ?Sized>(
    writer: &mut W,
    data: &[u8],
    clock: &dyn Clock,
) -> Result<(), CoreError> {
    let mut dirty = false;
    write_frame_tracked(writer, data, clock, &mut dirty).await
}

/// Same as [`write_frame`], additionally maintaining `frame_dirty == true` strictly while a
/// partial prefix (`0 < offset < data.len()`) has been committed to `writer`.
async fn write_frame_tracked<W: StreamWrite + ?Sized>(
    writer: &mut W,
    data: &[u8],
    clock: &dyn Clock,
    frame_dirty: &mut bool,
) -> Result<(), CoreError> {
    let mut offset = 0usize;
    let mut budget_deadline: Option<MonotonicTime> = None;
    let mut backoff = STREAM_WRITE_BACKOFF_INITIAL;

    while offset < data.len() {
        let step = await_budgeted(clock, budget_deadline, writer.write(&data[offset..])).await;
        match step {
            BudgetStep::Expired => return Err(CoreError::Timeout),
            BudgetStep::Done(Ok(0)) => return Err(CoreError::UnexpectedEof),
            BudgetStep::Done(Ok(n)) => {
                let advanced = n.min(data.len().saturating_sub(offset));
                offset += advanced;
                *frame_dirty = offset > 0 && offset < data.len();
                backoff = STREAM_WRITE_BACKOFF_INITIAL;
            }
            BudgetStep::Done(Err(err)) if err.is_retryable() => {
                let now = clock.now();
                let deadline = *budget_deadline
                    .get_or_insert_with(|| now.saturating_add(STREAM_WRITE_RETRY_BUDGET));
                if now >= deadline {
                    return Err(CoreError::Timeout);
                }
                let wake = now.saturating_add(backoff).min(deadline);
                clock.sleep_until(wake).await;
                if clock.now() >= deadline {
                    return Err(CoreError::Timeout);
                }
                backoff = backoff.saturating_mul(2).min(STREAM_WRITE_BACKOFF_CAP);
            }
            BudgetStep::Done(Err(err)) => return Err(err),
        }
    }

    loop {
        let step = await_budgeted(clock, budget_deadline, writer.flush()).await;
        match step {
            BudgetStep::Expired => return Err(CoreError::Timeout),
            BudgetStep::Done(Ok(())) => {
                *frame_dirty = false;
                return Ok(());
            }
            BudgetStep::Done(Err(err)) if err.is_retryable() => {
                let now = clock.now();
                let deadline = *budget_deadline
                    .get_or_insert_with(|| now.saturating_add(STREAM_WRITE_RETRY_BUDGET));
                if now >= deadline {
                    return Err(CoreError::Timeout);
                }
                let wake = now.saturating_add(backoff).min(deadline);
                clock.sleep_until(wake).await;
                if clock.now() >= deadline {
                    return Err(CoreError::Timeout);
                }
                backoff = backoff.saturating_mul(2).min(STREAM_WRITE_BACKOFF_CAP);
            }
            BudgetStep::Done(Err(err)) => return Err(err),
        }
    }
}

/// Best-effort bounded write (default `50 ms`) for terminal error/cookie/close frames.
pub(crate) async fn write_frame_best_effort<W: StreamWrite + ?Sized>(
    writer: &mut W,
    data: &[u8],
    clock: &dyn Clock,
) {
    let deadline = clock.now().saturating_add(CLOSE_SEND_TIMEOUT);
    let _ = with_deadline(clock, deadline, write_frame(writer, data, clock)).await;
}

/// Writes one hop control frame (`4 B` header + `24..=160 B` body) using a stack buffer.
pub(crate) async fn write_hop_control<W: StreamWrite + ?Sized>(
    writer: &mut W,
    kind: u8,
    ttl_or_dist: u8,
    body: &[u8],
    clock: &dyn Clock,
) -> Result<(), CoreError> {
    let mut dirty = false;
    write_hop_control_tracked(writer, kind, ttl_or_dist, body, clock, &mut dirty).await
}

async fn write_hop_control_tracked<W: StreamWrite + ?Sized>(
    writer: &mut W,
    kind: u8,
    ttl_or_dist: u8,
    body: &[u8],
    clock: &dyn Clock,
    frame_dirty: &mut bool,
) -> Result<(), CoreError> {
    let len = u16::try_from(body.len()).map_err(|_| CoreError::Malformed)?;
    let hdr = StHopHeader {
        kind,
        ttl_or_dist,
        len,
    };
    let mut stack = [0u8; ST_HOP_HEADER + MAX_CONTROL];
    let total = ST_HOP_HEADER + body.len();
    if total > stack.len() {
        return Err(CoreError::Malformed);
    }
    stack[..ST_HOP_HEADER].copy_from_slice(&hdr.encode());
    stack[ST_HOP_HEADER..total].copy_from_slice(body);
    write_frame_tracked(writer, &stack[..total], clock, frame_dirty).await
}

/// Seals one E2E stream record into `e2e_scratch` and writes it sliced across `ST_DATA` chunks
/// respecting `current_mtu` and `floor`, reusing `chunk_scratch` to avoid hot-path allocations.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn write_e2e_record<W: StreamWrite + ?Sized>(
    writer: &mut W,
    tx_cipher: &mut StreamCipher,
    opcode: u8,
    body: &[u8],
    current_mtu: u16,
    floor: u16,
    clock: &dyn Clock,
    e2e_scratch: &mut Vec<u8>,
    chunk_scratch: &mut Vec<u8>,
) -> Result<(), CoreError> {
    let chunk_cap = usize::from(current_mtu).min(STREAM_CHUNK);
    if current_mtu < floor || chunk_cap == 0 {
        return Err(CoreError::MtuTooSmall(current_mtu));
    }
    tx_cipher.seal_into(opcode, body, e2e_scratch)?;
    write_st_data_chunks(writer, e2e_scratch, chunk_cap, clock, chunk_scratch).await
}

/// Writes raw bytes sliced into `ST_DATA` hop chunks of at most `chunk_cap` bytes each.
pub(crate) async fn write_st_data_chunks<W: StreamWrite + ?Sized>(
    writer: &mut W,
    raw: &[u8],
    chunk_cap: usize,
    clock: &dyn Clock,
    chunk_scratch: &mut Vec<u8>,
) -> Result<(), CoreError> {
    let mut dirty = false;
    write_st_data_chunks_tracked(writer, raw, chunk_cap, clock, chunk_scratch, &mut dirty).await
}

async fn write_st_data_chunks_tracked<W: StreamWrite + ?Sized>(
    writer: &mut W,
    raw: &[u8],
    chunk_cap: usize,
    clock: &dyn Clock,
    chunk_scratch: &mut Vec<u8>,
    frame_dirty: &mut bool,
) -> Result<(), CoreError> {
    let limit = chunk_cap.clamp(1, STREAM_CHUNK);
    for slice in raw.chunks(limit) {
        let len = u16::try_from(slice.len()).map_err(|_| CoreError::Malformed)?;
        let hdr = StHopHeader {
            kind: outer::ST_DATA,
            ttl_or_dist: 0,
            len,
        };
        chunk_scratch.clear();
        chunk_scratch.reserve(ST_HOP_HEADER + slice.len());
        chunk_scratch.extend_from_slice(&hdr.encode());
        chunk_scratch.extend_from_slice(slice);
        write_frame_tracked(writer, chunk_scratch, clock, frame_dirty).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Inbound Stream Hop Frame & E2E Record Demuxer (Spec §5.7.2 & §5.8.2)
// ---------------------------------------------------------------------------

/// One demuxed inbound frame from a Stream carrier.
pub(crate) enum InboundStreamFrame {
    /// Clean carrier EOF at a frame boundary with no buffered partial E2E record bytes.
    Eof,
    /// Interleaved hop control frame (`ST_CLOSE`, `ST_RENEW`, `ST_RENEW_OK`).
    HopControl {
        hdr: StHopHeader,
        body: [u8; MAX_CONTROL],
        len: usize,
    },
    /// Authenticated, decrypted credential-bearing `e2e::ST_RENEW` body stored in zeroizing memory
    /// (the underlying receive buffer slice has already been wiped in place).
    E2eRenew(Zeroizing<Vec<u8>>),
    /// Authenticated, decrypted Stream E2E record (non-credential-bearing).
    E2eRecord { opcode: u8, body: Vec<u8> },
}

/// Stateful Stream E2E record reassembler that immediately surfaces interleaved hop control
/// frames (`ST_CLOSE`, `ST_RENEW`, `ST_RENEW_OK`) even mid-E2E record.
pub(crate) struct StreamFrameReader {
    e2e_buf: Vec<u8>,
    e2e_pos: usize,
}

impl StreamFrameReader {
    pub fn new() -> Self {
        Self {
            e2e_buf: Vec::with_capacity(4096),
            e2e_pos: 0,
        }
    }

    fn buffered_len(&self) -> usize {
        self.e2e_buf.len().saturating_sub(self.e2e_pos)
    }

    fn compact_if_needed(&mut self) {
        if self.e2e_pos == 0 {
            return;
        }
        if self.e2e_pos >= self.e2e_buf.len() {
            self.e2e_buf.clear();
            self.e2e_pos = 0;
        } else if self.e2e_pos >= 4096 || self.e2e_pos * 2 >= self.e2e_buf.len() {
            let remaining = self.e2e_buf.len() - self.e2e_pos;
            self.e2e_buf.copy_within(self.e2e_pos.., 0);
            self.e2e_buf.truncate(remaining);
            self.e2e_pos = 0;
        }
    }

    fn try_pop_e2e(
        &mut self,
        rx_cipher: &mut StreamCipher,
    ) -> Result<Option<InboundStreamFrame>, CoreError> {
        let avail = self.buffered_len();
        if avail < 2 {
            return Ok(None);
        }
        let body_len_u16 =
            u16::from_be_bytes([self.e2e_buf[self.e2e_pos], self.e2e_buf[self.e2e_pos + 1]]);
        let body_len = validate_st_e2e_body_len(body_len_u16)?;
        let rec_len = body_len + ST_OVERHEAD;
        if avail < rec_len {
            return Ok(None);
        }
        let start = self.e2e_pos;
        let end = start + rec_len;
        let opened = rx_cipher.open_record(&mut self.e2e_buf[start..end])?;
        let opcode = opened.opcode();
        let frame = if opcode == e2e_st::ST_RENEW {
            // Extracts body into Zeroizing<Vec<u8>> and immediately drops `opened`,
            // zeroizing `self.e2e_buf[start + 2..start + 3 + body_len]` in place (Spec §1.4).
            InboundStreamFrame::E2eRenew(opened.into_zeroizing_body())
        } else {
            let body = opened.body().to_vec();
            drop(opened);
            InboundStreamFrame::E2eRecord { opcode, body }
        };
        self.e2e_pos = end;
        if self.e2e_pos == self.e2e_buf.len() {
            self.e2e_buf.clear();
            self.e2e_pos = 0;
        }
        Ok(Some(frame))
    }

    /// Reads the next complete hop control frame, decrypted E2E record, or clean EOF.
    pub async fn next_frame<R: StreamRead + ?Sized>(
        &mut self,
        reader: &mut R,
        rx_cipher: &mut StreamCipher,
    ) -> Result<InboundStreamFrame, CoreError> {
        loop {
            if let Some(frame) = self.try_pop_e2e(rx_cipher)? {
                return Ok(frame);
            }
            self.compact_if_needed();

            // Read 4-byte hop header, distinguishing clean EOF at byte 0 from mid-frame EOF.
            let mut hdr_raw = [0u8; ST_HOP_HEADER];
            let first = reader.read(&mut hdr_raw[..1]).await?;
            if first == 0 {
                if self.buffered_len() == 0 {
                    return Ok(InboundStreamFrame::Eof);
                }
                return Err(CoreError::UnexpectedEof);
            }
            reader.read_exact(&mut hdr_raw[1..]).await?;
            let hdr = StHopHeader::parse(&hdr_raw)?;
            let frame_len = usize::from(hdr.len);

            if hdr.kind == outer::ST_DATA {
                let old_len = self.e2e_buf.len();
                self.e2e_buf.resize(old_len + frame_len, 0);
                reader.read_exact(&mut self.e2e_buf[old_len..]).await?;
            } else {
                let mut body = [0u8; MAX_CONTROL];
                reader.read_exact(&mut body[..frame_len]).await?;
                return Ok(InboundStreamFrame::HopControl {
                    hdr,
                    body,
                    len: frame_len,
                });
            }
        }
    }
}

/// Reads a single raw outer hop frame header for transit splicing (returns `Ok(None)` on clean EOF).
pub(crate) async fn read_hop_header<R: StreamRead + ?Sized>(
    reader: &mut R,
) -> Result<Option<StHopHeader>, CoreError> {
    let mut hdr_raw = [0u8; ST_HOP_HEADER];
    let first = reader.read(&mut hdr_raw[..1]).await?;
    if first == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut hdr_raw[1..]).await?;
    Ok(Some(StHopHeader::parse(&hdr_raw)?))
}

// ---------------------------------------------------------------------------
// Single-Owner Zero-Mutex Stream Frame Writer Actor (Refinement #6)
// ---------------------------------------------------------------------------

/// One hop control frame queued with priority on [`StreamWriterHandle`].
pub(crate) struct PriorityCtrlFrame {
    pub kind: u8,
    pub ttl_or_dist: u8,
    pub body: [u8; MAX_CONTROL],
    pub len: usize,
}

impl PriorityCtrlFrame {
    pub fn from_slice(kind: u8, ttl_or_dist: u8, bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() > MAX_CONTROL {
            return Err(CoreError::Malformed);
        }
        let mut body = [0u8; MAX_CONTROL];
        body[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            kind,
            ttl_or_dist,
            body,
            len: bytes.len(),
        })
    }
}

/// Priority outer hop control command processed before regular `ST_DATA` chunks.
///
/// Non-terminal hop controls (`ST_RENEW`, `ST_RENEW_OK`) use independent `ControlCipher`s and may
/// safely interleave between any two `ST_DATA` chunks without disturbing E2E `StreamCipher` order.
pub(crate) enum WriterCtrlCmd {
    /// Emit one outer hop control frame (`ST_RENEW`, `ST_RENEW_OK`, etc.).
    HopControl(PriorityCtrlFrame),
}

/// Strictly-FIFO data-plane command queued on [`StreamWriterHandle`].
///
/// All E2E stream records (`ST_DATA`, `ST_FIN`, `e2e::ST_RENEW`, `e2e::ST_RENEW_OK`),
/// FIFO-ordered reverse `ST_CLOSE` frames, and flush barriers pass through this single FIFO channel.
pub(crate) enum WriterDataCmd {
    /// Pre-sealed E2E record bytes sliced across `ST_DATA` chunks using live MTU.
    E2eBytes(Vec<u8>),
    /// Pre-framed outer `ST_DATA` chunk (already carries 4-byte `StHopHeader`, used by transit splice).
    PreFramed(Vec<u8>),
    /// FIFO-ordered outer hop control frame emitted strictly after preceding `ST_DATA` chunks.
    HopControl(Box<PriorityCtrlFrame>),
    /// Completes once all preceding FIFO items have been written and flushed to the carrier.
    FlushAck(async_channel::Sender<Result<(), CoreError>>),
}

/// Non-blocking enqueue outcome returned by [`StreamWriterHandle::try_send_hop_control`] and
/// [`StreamWriterHandle::try_send_data`].
pub(crate) enum TryWriterSend<T> {
    Sent,
    Full(T),
    Closed(CoreError),
}

struct TeardownRequest {
    close_frames: Vec<PriorityCtrlFrame>,
    shutdown_carrier: bool,
}

async fn wait_teardown(
    rx: &mut WatchReceiver<Option<Arc<TeardownRequest>>>,
) -> Option<Arc<TeardownRequest>> {
    loop {
        if let Some(req) = rx.borrow_cloned() {
            return Some(req);
        }
        if !rx.changed().await {
            return rx.borrow_cloned();
        }
    }
}

/// Handle to a single-owner Stream writer task (zero async mutexes!).
#[derive(Clone)]
pub(crate) struct StreamWriterHandle {
    ctrl_tx: async_channel::Sender<WriterCtrlCmd>,
    data_tx: async_channel::Sender<WriterDataCmd>,
    teardown_tx: Watch<Option<Arc<TeardownRequest>>>,
    err_rx: WatchReceiver<Option<CoreError>>,
    done_rx: WatchReceiver<bool>,
}

impl StreamWriterHandle {
    /// Spawns a dedicated single-owner task driving `writer` with priority control interleaving,
    /// interruptible teardown, and reusable scratch buffers.
    pub fn spawn(
        mut writer: Box<dyn StreamWrite>,
        mtu_watch: MtuWatch,
        floor: u16,
        clock: Arc<dyn Clock>,
        spawner: &dyn TaskSpawner,
    ) -> Self {
        let (ctrl_tx, ctrl_rx) = async_channel::bounded::<WriterCtrlCmd>(32);
        let (data_tx, data_rx) = async_channel::bounded::<WriterDataCmd>(16);
        let (teardown_tx, mut teardown_rx) = Watch::new(None::<Arc<TeardownRequest>>);
        let (err_tx, err_rx) = Watch::new(None::<CoreError>);
        let (done_tx, done_rx) = Watch::new(false);

        spawner.spawn(Box::pin(async move {
            let mut chunk_scratch = Vec::with_capacity(4096);
            let mut teardown_req: Option<Arc<TeardownRequest>> = None;
            let mut fatal_err: Option<CoreError> = None;
            let mut frame_dirty = false;

            loop {
                if let Some(req) = teardown_rx.borrow_cloned() {
                    teardown_req = Some(req);
                    break;
                }

                // Always prefer teardown over channel closure, and priority control over FIFO data.
                let next_cmd = if let Ok(c) = ctrl_rx.try_recv() {
                    Either::Right(Either::Left(Ok(c)))
                } else {
                    race2(
                        wait_teardown(&mut teardown_rx),
                        recv_priority(&ctrl_rx, &data_rx),
                    )
                    .await
                };

                let cmd = match next_cmd {
                    Either::Left(req) => {
                        teardown_req = req;
                        break;
                    }
                    Either::Right(cmd) => cmd,
                };

                match cmd {
                    Either::Left(Ok(WriterCtrlCmd::HopControl(frame))) => {
                        match race2(
                            write_hop_control_tracked(
                                &mut *writer,
                                frame.kind,
                                frame.ttl_or_dist,
                                &frame.body[..frame.len],
                                &*clock,
                                &mut frame_dirty,
                            ),
                            wait_teardown(&mut teardown_rx),
                        )
                        .await
                        {
                            Either::Left(Ok(())) => {}
                            Either::Left(Err(err)) => {
                                fatal_err = Some(err.clone());
                                err_tx.send(Some(err));
                                break;
                            }
                            Either::Right(req) => {
                                teardown_req = req;
                                break;
                            }
                        }
                    }
                    Either::Right(Ok(WriterDataCmd::E2eBytes(raw))) => {
                        let mtu = mtu_watch.current();
                        if mtu < floor {
                            let err = CoreError::MtuTooSmall(mtu);
                            fatal_err = Some(err.clone());
                            err_tx.send(Some(err));
                            break;
                        }
                        match race2(
                            write_st_data_chunks_tracked(
                                &mut *writer,
                                &raw,
                                usize::from(mtu).min(STREAM_CHUNK),
                                &*clock,
                                &mut chunk_scratch,
                                &mut frame_dirty,
                            ),
                            wait_teardown(&mut teardown_rx),
                        )
                        .await
                        {
                            Either::Left(Ok(())) => {}
                            Either::Left(Err(err)) => {
                                fatal_err = Some(err.clone());
                                err_tx.send(Some(err));
                                break;
                            }
                            Either::Right(req) => {
                                teardown_req = req;
                                break;
                            }
                        }
                    }
                    Either::Right(Ok(WriterDataCmd::PreFramed(raw))) => {
                        match race2(
                            write_frame_tracked(&mut *writer, &raw, &*clock, &mut frame_dirty),
                            wait_teardown(&mut teardown_rx),
                        )
                        .await
                        {
                            Either::Left(Ok(())) => {}
                            Either::Left(Err(err)) => {
                                fatal_err = Some(err.clone());
                                err_tx.send(Some(err));
                                break;
                            }
                            Either::Right(req) => {
                                teardown_req = req;
                                break;
                            }
                        }
                    }
                    Either::Right(Ok(WriterDataCmd::HopControl(frame))) => {
                        match race2(
                            write_hop_control_tracked(
                                &mut *writer,
                                frame.kind,
                                frame.ttl_or_dist,
                                &frame.body[..frame.len],
                                &*clock,
                                &mut frame_dirty,
                            ),
                            wait_teardown(&mut teardown_rx),
                        )
                        .await
                        {
                            Either::Left(Ok(())) => {}
                            Either::Left(Err(err)) => {
                                fatal_err = Some(err.clone());
                                err_tx.send(Some(err));
                                break;
                            }
                            Either::Right(req) => {
                                teardown_req = req;
                                break;
                            }
                        }
                    }
                    Either::Right(Ok(WriterDataCmd::FlushAck(ack_tx))) => {
                        let _ = ack_tx.try_send(Ok(()));
                    }
                    Either::Left(Err(_)) | Either::Right(Err(_)) => break,
                }
            }

            if fatal_err.is_none() && teardown_req.is_none() {
                teardown_req = teardown_rx.borrow_cloned();
            }

            if let Some(req) = teardown_req {
                if !frame_dirty && !req.close_frames.is_empty() {
                    let deadline = clock.now().saturating_add(CLOSE_SEND_TIMEOUT);
                    for frame in &req.close_frames {
                        let res = with_deadline(
                            &*clock,
                            deadline,
                            write_hop_control(
                                &mut *writer,
                                frame.kind,
                                frame.ttl_or_dist,
                                &frame.body[..frame.len],
                                &*clock,
                            ),
                        )
                        .await;
                        if res.is_err() {
                            break;
                        }
                    }
                }
                if req.shutdown_carrier {
                    let _ = with_deadline(
                        &*clock,
                        clock.now().saturating_add(CLOSE_SEND_TIMEOUT),
                        writer.shutdown(),
                    )
                    .await;
                }
            }

            ctrl_rx.close();
            data_rx.close();
            // Drain any queued FlushAck/commands immediately so callers awaiting flush_fifo() or
            // app Flush wake promptly with the exact terminal error even while handles remain alive.
            while ctrl_rx.try_recv().is_ok() {}
            while let Ok(cmd) = data_rx.try_recv() {
                if let WriterDataCmd::FlushAck(ack_tx) = cmd {
                    if let Some(ref err) = fatal_err {
                        let _ = ack_tx.try_send(Err(err.clone()));
                    }
                }
            }
            drop(writer);
            done_tx.send(true);
        }));

        Self {
            ctrl_tx,
            data_tx,
            teardown_tx,
            err_rx,
            done_rx,
        }
    }

    pub fn try_send_hop_control(
        &self,
        frame: PriorityCtrlFrame,
    ) -> TryWriterSend<PriorityCtrlFrame> {
        match self.ctrl_tx.try_send(WriterCtrlCmd::HopControl(frame)) {
            Ok(()) => TryWriterSend::Sent,
            Err(async_channel::TrySendError::Full(WriterCtrlCmd::HopControl(frame))) => {
                TryWriterSend::Full(frame)
            }
            Err(async_channel::TrySendError::Closed(_)) => {
                TryWriterSend::Closed(self.last_error().unwrap_or(CoreError::Closed))
            }
        }
    }

    pub async fn send_hop_control(&self, frame: PriorityCtrlFrame) -> Result<(), CoreError> {
        self.ctrl_tx
            .send(WriterCtrlCmd::HopControl(frame))
            .await
            .map_err(|_| self.last_error().unwrap_or(CoreError::Closed))
    }

    pub fn try_send_data(&self, cmd: WriterDataCmd) -> TryWriterSend<WriterDataCmd> {
        match self.data_tx.try_send(cmd) {
            Ok(()) => TryWriterSend::Sent,
            Err(async_channel::TrySendError::Full(cmd)) => TryWriterSend::Full(cmd),
            Err(async_channel::TrySendError::Closed(_)) => {
                TryWriterSend::Closed(self.last_error().unwrap_or(CoreError::Closed))
            }
        }
    }

    pub async fn send_data(&self, cmd: WriterDataCmd) -> Result<(), CoreError> {
        self.data_tx
            .send(cmd)
            .await
            .map_err(|_| self.last_error().unwrap_or(CoreError::Closed))
    }

    pub async fn send_preframed(&self, frame: Vec<u8>) -> Result<(), CoreError> {
        self.send_data(WriterDataCmd::PreFramed(frame)).await
    }

    pub async fn send_fifo_hop_control(&self, frame: PriorityCtrlFrame) -> Result<(), CoreError> {
        self.send_data(WriterDataCmd::HopControl(Box::new(frame)))
            .await
    }

    /// Waits until all previously enqueued FIFO data items have been written and flushed.
    pub async fn flush_fifo(&self) -> Result<(), CoreError> {
        let (tx, rx) = async_channel::bounded(1);
        self.data_tx
            .send(WriterDataCmd::FlushAck(tx))
            .await
            .map_err(|_| self.last_error().unwrap_or(CoreError::Closed))?;
        match rx.recv().await {
            Ok(res) => res,
            Err(_) => Err(self.last_error().unwrap_or(CoreError::Closed)),
        }
    }

    /// Interrupts any blocked carrier write immediately, executes best-effort teardown (sending
    /// final close frames within 50 ms when on a clean frame boundary and shutting down the
    /// carrier within 50 ms), and awaits writer task completion and carrier drop.
    pub async fn teardown(&self, close_frames: Vec<PriorityCtrlFrame>, shutdown_carrier: bool) {
        self.teardown_tx.send(Some(Arc::new(TeardownRequest {
            close_frames,
            shutdown_carrier,
        })));
        self.ctrl_tx.close();
        self.data_tx.close();
        let mut done = self.done_rx.clone();
        wait_signal(&mut done).await;
    }

    pub fn last_error(&self) -> Option<CoreError> {
        self.err_rx.borrow_cloned()
    }

    /// Resolves as soon as the writer task reports a fatal write error.
    pub async fn failed(&self) -> CoreError {
        let mut rx = self.err_rx.clone();
        loop {
            if let Some(err) = rx.borrow_cloned() {
                return err;
            }
            if !rx.changed().await {
                return rx.borrow_cloned().unwrap_or(CoreError::Closed);
            }
        }
    }
}

async fn recv_priority<C, D>(
    ctrl_rx: &async_channel::Receiver<C>,
    data_rx: &async_channel::Receiver<D>,
) -> Either<Result<C, async_channel::RecvError>, Result<D, async_channel::RecvError>> {
    let mut c_fut = Box::pin(ctrl_rx.recv());
    let mut d_fut = Box::pin(data_rx.recv());
    let mut ctrl_closed = false;
    let mut data_closed = false;
    poll_fn(|cx| {
        if !ctrl_closed {
            if let Poll::Ready(res) = Pin::new(&mut c_fut).poll(cx) {
                match res {
                    Ok(v) => return Poll::Ready(Either::Left(Ok(v))),
                    Err(e) => {
                        ctrl_closed = true;
                        if data_closed {
                            return Poll::Ready(Either::Left(Err(e)));
                        }
                    }
                }
            }
        }
        if !data_closed {
            if let Poll::Ready(res) = Pin::new(&mut d_fut).poll(cx) {
                match res {
                    Ok(v) => return Poll::Ready(Either::Right(Ok(v))),
                    Err(e) => {
                        data_closed = true;
                        if ctrl_closed {
                            return Poll::Ready(Either::Right(Err(e)));
                        }
                    }
                }
            }
        }
        Poll::Pending
    })
    .await
}

/// Ensures `sleep` delay respects `lease.cancelled()`, `mtu_watch < floor`, and `shutdown`.
pub(crate) async fn sleep_paced(
    delay: Duration,
    clock: &dyn Clock,
    lease: &crate::trust::lease::LeaseHandle,
    mtu_watch: &mut MtuWatch,
    floor: u16,
) -> Result<(), CoreError> {
    let deadline = clock.now().saturating_add(delay);
    match race2(
        clock.sleep_until(deadline),
        race2(
            lease.cancelled(),
            crate::engine::context::wait_mtu_below_floor(mtu_watch, floor),
        ),
    )
    .await
    {
        Either::Left(()) => {
            lease.remaining()?;
            Ok(())
        }
        Either::Right(Either::Left(err)) => Err(err),
        Either::Right(Either::Right(mtu)) => Err(CoreError::MtuTooSmall(mtu)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::testing::{MemoryStreamPair, TestRuntime};
    use crate::seam::channel::IntoStreamHalves;

    #[test]
    fn stream_frame_reader_wipes_e2e_renew_plaintext_in_receive_buffer() {
        let rt = TestRuntime::new();
        let pair = MemoryStreamPair::pair(16_384);
        let (mut r, mut w) = {
            let (_ra, wa) = pair.a.into_halves();
            let (rb, _wb) = pair.b.into_halves();
            (rb, wa)
        };

        let key = [0x44u8; 32];
        let mut tx = StreamCipher::new(&key);
        let mut rx = StreamCipher::new(&key);
        let secret = b"stream-renew-secret-credential-xyz";
        let mut renew_body = Vec::new();
        renew_body.extend_from_slice(&1u64.to_be_bytes());
        renew_body.extend_from_slice(secret);

        let mut rec1 = Vec::new();
        tx.seal_into(e2e_st::ST_RENEW, &renew_body, &mut rec1).unwrap();
        // Append a second record in the SAME ST_DATA chunk so `e2e_buf` is NOT cleared immediately!
        let mut rec2 = Vec::new();
        tx.seal_into(e2e_st::ST_DATA, b"trailing-app-data", &mut rec2).unwrap();
        let mut combined = rec1;
        combined.extend_from_slice(&rec2);

        let mut frame_reader = StreamFrameReader::new();
        let res = rt.spawner.try_block_on(async {
            let mut scratch = Vec::new();
            write_st_data_chunks(&mut w, &combined, 16_384, &*rt.clock, &mut scratch)
                .await
                .unwrap();
            let frame1 = frame_reader.next_frame(&mut r, &mut rx).await.unwrap();
            match frame1 {
                InboundStreamFrame::E2eRenew(body) => {
                    assert_eq!(&body[8..], secret);
                }
                _ => panic!("expected E2eRenew frame"),
            }
            // Even while trailing bytes remain in `e2e_buf`, the decrypted ST_RENEW plaintext
            // in `frame_reader.e2e_buf` MUST ALREADY be zeroed in place!
            assert!(
                !frame_reader
                    .e2e_buf
                    .windows(secret.len())
                    .any(|win| win == secret),
                "decrypted ST_RENEW credential leaked in StreamFrameReader::e2e_buf"
            );
            let frame2 = frame_reader.next_frame(&mut r, &mut rx).await.unwrap();
            match frame2 {
                InboundStreamFrame::E2eRecord { opcode, body } => {
                    assert_eq!(opcode, e2e_st::ST_DATA);
                    assert_eq!(body, b"trailing-app-data");
                }
                _ => panic!("expected trailing ST_DATA"),
            }
        });
        assert_eq!(res, Some(()));
    }

    #[test]
    fn write_frame_enforces_anchored_3s_deadline_on_stalled_and_late_completion() {
        use core::task::Context;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Case 1: First write returns a retryable error, anchoring the 3s budget; the second write
        // stalls forever (Poll::Pending). write_frame MUST fail with Timeout at exactly 3 s.
        struct StallAfterOneRetryable {
            calls: AtomicUsize,
        }
        impl StreamWrite for StallAfterOneRetryable {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &[u8],
            ) -> Poll<Result<usize, CoreError>> {
                if self.calls.fetch_add(1, Ordering::AcqRel) == 0 {
                    Poll::Ready(Err(CoreError::CarrierFailure {
                        message: "transient".into(),
                        transient: true,
                    }))
                } else {
                    Poll::Pending
                }
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Result<(), CoreError>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Result<(), CoreError>> {
                Poll::Ready(Ok(()))
            }
        }

        let rt = TestRuntime::new();
        let (tx, mut rx) = Watch::new(None::<Result<(), CoreError>>);
        let clk = Arc::clone(&rt.clock);
        rt.runtime.spawner.spawn(Box::pin(async move {
            let mut w = StallAfterOneRetryable {
                calls: AtomicUsize::new(0),
            };
            let res = write_frame(&mut w, b"hello", &*clk).await;
            tx.send(Some(res));
        }));

        rt.drive_until_idle();
        rt.advance_and_drive(Duration::from_millis(2_999));
        assert_eq!(
            rx.borrow_cloned(),
            None,
            "must not time out before 3s budget"
        );
        rt.advance_and_drive(Duration::from_millis(1));
        assert_eq!(rx.borrow_cloned(), Some(Err(CoreError::Timeout)));
        rx.mark_seen();

        // Case 2: First write returns a retryable error (anchoring 3s), second write succeeds,
        // then flush completes with Ok(()) AFTER the clock jumps past 3s -> MUST still return Timeout!
        struct LateFlushAfterRetryable {
            writes: AtomicUsize,
            clock: Arc<crate::testing::VirtualClock>,
        }
        impl StreamWrite for LateFlushAfterRetryable {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<Result<usize, CoreError>> {
                if self.writes.fetch_add(1, Ordering::AcqRel) == 0 {
                    Poll::Ready(Err(CoreError::CarrierFailure {
                        message: "transient".into(),
                        transient: true,
                    }))
                } else {
                    Poll::Ready(Ok(buf.len()))
                }
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Result<(), CoreError>> {
                // Simulate a slow synchronous flush completing at/past the 3s anchored budget.
                self.clock.advance(Duration::from_secs(3));
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Result<(), CoreError>> {
                Poll::Ready(Ok(()))
            }
        }

        let rt2 = TestRuntime::new();
        let (tx2, rx2) = Watch::new(None::<Result<(), CoreError>>);
        let clk2 = Arc::clone(&rt2.clock);
        let clk2_w = Arc::clone(&rt2.clock);
        rt2.runtime.spawner.spawn(Box::pin(async move {
            let mut w = LateFlushAfterRetryable {
                writes: AtomicUsize::new(0),
                clock: clk2_w,
            };
            let res = write_frame(&mut w, b"hello", &*clk2).await;
            tx2.send(Some(res));
        }));

        rt2.drive_until_idle();
        rt2.advance_and_drive(Duration::from_millis(10));
        assert_eq!(rx2.borrow_cloned(), Some(Err(CoreError::Timeout)));
    }
}
