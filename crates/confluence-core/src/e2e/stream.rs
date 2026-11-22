//! End-to-end authenticated Stream Plane session (`E2eStream`) with 1.0 RTT deferred destination
//! open, authenticated half-close (`E2E_FIN`), and automatic in-band hop & endpoint lease renewal.

use parking_lot::Mutex;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, mpsc, oneshot, watch};

use super::{
    AwaitingConfirm, EndpointAuth, Lifetime, cancellation, record_error,
    renewal::{Ack, LeaseSlot, Renewals, Request},
};
use crate::{
    CoreErr, Direction, DynStreamEndpointHandler, Lease, LeaseHandle, MtuWatch, PathOutcome,
    StreamAction, StreamReadExt, StreamWrite, StreamWriteExt,
    crypto::{
        aead::{ControlCipher, StreamCipher},
        noise_ik::SessionKeys,
    },
    path::{
        below_floor, best_effort,
        st_splice::{self, Carrier, Reader, Writer},
        timed,
    },
    read_exact,
    scope::Scope,
    wire::{e2e, hop, setup},
};

/// Handle to an end-to-end authenticated bidirectional byte stream.
#[derive(Clone)]
pub struct E2eStream {
    life: Arc<Lifetime>,
    input: Arc<AsyncMutex<Inbox>>,
    output: mpsc::Sender<Write>,
    maximum: usize,
}

struct Inbox {
    rx: mpsc::Receiver<Option<Vec<u8>>>,
    pending: Vec<u8>,
    offset: usize,
    fin: bool,
}

type Write = (Option<Vec<u8>>, oneshot::Sender<Result<(), CoreErr>>);

impl E2eStream {
    /// Maximum single-record write chunk size in bytes.
    pub fn max_write_size(&self) -> usize {
        self.maximum
    }

    /// Reads decrypted bytes into `buf`, returning `Ok(0)` only after an authenticated `E2E_FIN`.
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, CoreErr> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut inbox = self.input.lock().await;
        if inbox.fin {
            return Ok(0);
        }
        if let Some(error) = self.active_failure() {
            return Err(error);
        }
        while inbox.offset == inbox.pending.len() {
            match inbox.rx.recv().await {
                Some(Some(data)) => {
                    inbox.pending = data;
                    inbox.offset = 0;
                }
                Some(None) => {
                    inbox.fin = true;
                    return Ok(0);
                }
                None => return Err(self.failure()),
            }
        }
        if let Some(error) = self.active_failure() {
            return Err(error);
        }
        let amount = (inbox.pending.len() - inbox.offset).min(buf.len());
        buf[..amount].copy_from_slice(&inbox.pending[inbox.offset..inbox.offset + amount]);
        inbox.offset += amount;
        Ok(amount)
    }

    /// Writes up to [`Self::max_write_size`] bytes as one AEAD record.
    pub async fn write(&self, buf: &[u8]) -> Result<usize, CoreErr> {
        let amount = buf.len().min(self.maximum);
        if amount == 0 {
            return Ok(0);
        }
        self.command(Some(buf[..amount].to_vec())).await?;
        Ok(amount)
    }

    /// Writes all bytes in `buf`, splitting across AEAD records as needed.
    pub async fn write_all(&self, mut buf: &[u8]) -> Result<(), CoreErr> {
        while !buf.is_empty() {
            let count = self.write(buf).await?;
            buf = &buf[count..];
        }
        Ok(())
    }

    /// Sends an authenticated `E2E_FIN` half-close to the remote peer.
    pub async fn shutdown(&self) -> Result<(), CoreErr> {
        self.command(None).await
    }

    async fn command(&self, value: Option<Vec<u8>>) -> Result<(), CoreErr> {
        if let Some(error) = self.active_failure() {
            return Err(error);
        }
        let (done, result) = oneshot::channel();
        self.output
            .send((value, done))
            .await
            .map_err(|_| self.failure())?;
        result.await.map_err(|_| self.failure())?
    }

    fn active_failure(&self) -> Option<CoreErr> {
        self.life
            .0
            .borrow()
            .clone()
            .filter(|error| *error != CoreErr::Closed)
    }

    fn failure(&self) -> CoreErr {
        self.life
            .0
            .borrow()
            .clone()
            .unwrap_or(CoreErr::UnexpectedEof)
    }
}

struct WireReader {
    reader: Reader,
    cipher: StreamCipher,
    leftover: usize,
    bytes: Vec<u8>,
}

enum Event {
    Record(u8, Vec<u8>),
    Hop(u8, u8, Vec<u8>),
}

impl WireReader {
    fn new(reader: Reader, key: [u8; 32]) -> Self {
        Self {
            reader,
            cipher: StreamCipher::new(key),
            leftover: 0,
            bytes: Vec::new(),
        }
    }

    async fn next(&mut self) -> Result<Event, CoreErr> {
        loop {
            let target = if self.bytes.len() < 2 {
                2
            } else {
                e2e::stream_body_len(self.bytes[..2].try_into().unwrap())? + e2e::ST_OVERHEAD
            };
            if self.bytes.len() == target {
                let (kind, data) = self.cipher.open(std::mem::take(&mut self.bytes))?;
                return Ok(Event::Record(kind, data));
            }
            if self.leftover == 0 {
                let mut prefix = [0; 4];
                read_exact(&mut *self.reader, &mut prefix).await?;
                let (kind, ttl, len) = hop::parse_stream(prefix)?;
                if kind != hop::ST_DATA {
                    let mut body = vec![0; len];
                    read_exact(&mut *self.reader, &mut body).await?;
                    return Ok(Event::Hop(kind, ttl, body));
                }
                self.leftover = len;
            }
            let offset = self.bytes.len();
            let count = self.leftover.min(target - offset);
            self.bytes.resize(offset + count, 0);
            read_exact(&mut *self.reader, &mut self.bytes[offset..]).await?;
            self.leftover -= count;
        }
    }
}

struct WireWriter {
    writer: Writer,
    cipher: StreamCipher,
    mtu: MtuWatch,
    floor: u16,
}

impl WireWriter {
    fn new(writer: Box<dyn StreamWrite>, key: [u8; 32], mtu: MtuWatch, floor: u16) -> Self {
        Self {
            writer: Arc::new(AsyncMutex::new(writer)),
            cipher: StreamCipher::new(key),
            mtu,
            floor,
        }
    }

    async fn unavailable(&self) -> CoreErr {
        below_floor(self.mtu.clone(), self.floor).await
    }

    async fn record(&mut self, kind: u8, body: &[u8]) -> Result<(), CoreErr> {
        let wire = self.cipher.seal(kind, body)?;
        let limit = self.mtu.mtu().min(crate::STREAM_CHUNK as u16);
        if limit < self.floor {
            return Err(CoreErr::MtuTooSmall(limit));
        }
        for chunk in wire.chunks(usize::from(limit)) {
            st_splice::write_chunk(&self.writer, hop::ST_DATA, 0, chunk).await?;
        }
        Ok(())
    }

    async fn control(&self, kind: u8, ttl: u8, body: &[u8]) -> Result<(), CoreErr> {
        st_splice::write_chunk(&self.writer, kind, ttl, body).await
    }
}

enum Role {
    Origin(Renewals),
    Destination(EndpointAuth),
}

impl Role {
    fn lease_keys(&self) -> Vec<Mutex<ControlCipher>> {
        match self {
            Self::Origin(origin) => origin
                .hops
                .iter()
                .chain(std::iter::once(&origin.terminal))
                .map(|key| Mutex::new(key.control(true)))
                .collect(),
            Self::Destination(auth) => vec![Mutex::new(auth.terminal_key.control(false))],
        }
    }
}

/// A 1-RTT authenticated Stream session whose destination `EndpointHandler` has **not** yet
/// been invoked (`B` is still in `AwaitingConfirm`).
pub struct StagedStream {
    inner: Option<StagedStreamInner>,
}

struct StagedStreamInner {
    scope: Arc<Scope>,
    io: Carrier,
    keys: SessionKeys,
    limits: (u16, u16),
    lease: Arc<LeaseHandle>,
    origin: Renewals,
    session: OwnedSemaphorePermit,
}

impl StagedStream {
    pub(crate) fn new(
        scope: Arc<Scope>,
        io: Carrier,
        keys: SessionKeys,
        limits: (u16, u16),
        lease: Arc<LeaseHandle>,
        origin: Renewals,
        session: OwnedSemaphorePermit,
    ) -> Self {
        Self {
            inner: Some(StagedStreamInner {
                scope,
                io,
                keys,
                limits,
                lease,
                origin,
                session,
            }),
        }
    }

    /// Negotiated stream chunk MTU ceiling for this staged path.
    pub fn mtu(&self) -> u16 {
        self.inner.as_ref().map_or(0, |s| s.limits.0)
    }

    /// Caller-chosen path identifier supplied in `ExplicitPath::id`.
    pub fn path_id(&self) -> u64 {
        self.inner.as_ref().map_or(0, |s| s.origin.path_id)
    }

    /// Transmits the `ee`-authenticated confirmation record, awaits `B`'s status preamble,
    /// reports [`PathOutcome::Established`], and returns [`E2eStream`].
    pub async fn confirm(mut self) -> Result<E2eStream, CoreErr> {
        let inner = self.inner.take().ok_or(CoreErr::Closed)?;
        let mtu = inner.limits.0;
        let path_id = inner.origin.path_id;
        let source = inner.origin.source.clone();
        let connected = connect(
            &inner.scope,
            inner.io,
            inner.keys,
            inner.limits,
            inner.lease,
            inner.origin,
            inner.session,
        )
        .await?;
        source.report_outcome(path_id, PathOutcome::Established { mtu });
        Ok(connected)
    }
}

impl Drop for StagedStream {
    fn drop(&mut self) {
        let Some(inner) = self.inner.take() else {
            return;
        };
        inner.origin.report(PathOutcome::Closed);
        let tasks = inner.scope.tasks.clone();
        tasks.spawn(Box::pin(async move {
            let writer = Arc::new(AsyncMutex::new(inner.io.writer));
            let mut ciphers: Vec<_> = inner
                .origin
                .hops
                .iter()
                .map(|key| key.control(true))
                .collect();
            let close = async {
                for (index, cipher) in ciphers.iter_mut().enumerate().rev() {
                    if let Ok(body) = cipher.seal(hop::ST_CLOSE, &record_error(&CoreErr::Closed)) {
                        let _ = st_splice::write_chunk(&writer, hop::ST_CLOSE, index as u8, &body)
                            .await;
                    }
                }
                let _ = writer.lock().await.shutdown().await;
                Ok(())
            };
            best_effort(close).await;
        }));
    }
}

pub(crate) async fn connect(
    scope: &Scope,
    io: Carrier,
    keys: SessionKeys,
    (mtu, floor): (u16, u16),
    lease: Arc<LeaseHandle>,
    origin: Renewals,
    session: OwnedSemaphorePermit,
) -> Result<E2eStream, CoreErr> {
    let mut reader = WireReader::new(io.reader, keys.rx);
    let mut writer = WireWriter::new(io.writer, keys.tx, io.mtu, floor);
    let status = async {
        writer.record(e2e::ST_DATA, &[]).await?;
        loop {
            match reader.next().await? {
                Event::Record(e2e::OPEN_OK, body) if body.is_empty() => return Ok(()),
                Event::Record(e2e::TARGET_REFUSED, body) if body.is_empty() => {
                    return Err(CoreErr::TargetRefused);
                }
                Event::Record(e2e::TARGET_UNREACHABLE, body) if body.is_empty() => {
                    return Err(CoreErr::TargetUnreachable);
                }
                Event::Record(e2e::TARGET_BUSY, body) if body.is_empty() => {
                    return Err(CoreErr::Busy);
                }
                Event::Record(e2e::TARGET_DENIED, body) if body.is_empty() => {
                    return Err(CoreErr::Denied);
                }
                Event::Hop(hop::ST_CLOSE, index, body) => {
                    let key = if usize::from(index) == origin.hops.len() {
                        Some(&origin.terminal)
                    } else {
                        origin.hops.get(usize::from(index))
                    };
                    if let Some(key) = key
                        && let Ok(reason) = key.control(true).open(hop::ST_CLOSE, &body)
                    {
                        let reason = setup::decode_error(&reason)?;
                        return Err(if usize::from(index) == origin.hops.len() {
                            reason
                        } else {
                            CoreErr::HopRejected {
                                index,
                                reason: Box::new(reason),
                            }
                        });
                    }
                }
                _ => return Err(CoreErr::Malformed),
            }
        }
    };
    tokio::select! {
        error = lease.cancelled() => return Err(error),
        res = timed(status) => res?,
    }
    let (stream, pump) = worker(
        reader,
        writer,
        mtu,
        lease,
        Role::Origin(origin),
        Vec::new(),
        session,
    );
    scope.tasks.spawn(Box::pin(pump));
    Ok(stream)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve(
    io: Carrier,
    keys: SessionKeys,
    (mtu, floor): (u16, u16),
    handler: Arc<dyn DynStreamEndpointHandler>,
    auth: EndpointAuth,
    pending: AwaitingConfirm,
    session: OwnedSemaphorePermit,
) -> Result<(), CoreErr> {
    let mut reader = WireReader::new(io.reader, keys.rx);
    let mut writer = WireWriter::new(io.writer, keys.tx, io.mtu, floor);
    let lease = auth.lease.clone();
    let setup = async {
        match reader.next().await? {
            Event::Record(e2e::ST_DATA, data) => Ok(data),
            _ => Err(CoreErr::Authentication),
        }
    };
    let first = tokio::select! {
        error = lease.cancelled() => return Err(error),
        error = writer.unavailable() => return Err(error),
        res = crate::path::before(pending.deadline, setup) => res?,
    };
    let maximum = usize::from(mtu)
        .min(crate::STREAM_CHUNK)
        .saturating_sub(e2e::ST_OVERHEAD);
    if first.len() > maximum {
        return Err(CoreErr::Malformed);
    }
    lease.remaining()?;
    drop(pending);
    if !first.is_empty() {
        let mut gate = lease.gate_cache();
        if let Some(active_gate) = gate.current(&lease) {
            match active_gate.charge_stream(Direction::Ingress, first.len()) {
                StreamAction::Allow => {}
                StreamAction::Delay(delay) => {
                    tokio::select! {
                        error = lease.cancelled() => return Err(error),
                        error = writer.unavailable() => return Err(error),
                        _ = tokio::time::sleep(delay) => {}
                    }
                    lease.remaining()?;
                }
                StreamAction::Close(error) => return Err(error),
            }
        }
    }
    let session_auth = auth.session_auth();
    let app = tokio::select! {
        error = lease.cancelled() => {
            best_effort(writer.record(e2e::TARGET_UNREACHABLE, &[])).await;
            return Err(error);
        }
        error = writer.unavailable() => {
            best_effort(writer.record(e2e::TARGET_UNREACHABLE, &[])).await;
            return Err(error);
        }
        res = timed(handler.dyn_open(session_auth)) => match res {
            Ok(io) => io,
            Err(error) => {
                let code = match error {
                    CoreErr::TargetRefused => e2e::TARGET_REFUSED,
                    CoreErr::Busy => e2e::TARGET_BUSY,
                    CoreErr::Denied => e2e::TARGET_DENIED,
                    _ => e2e::TARGET_UNREACHABLE,
                };
                best_effort(writer.record(code, &[])).await;
                return Err(error);
            }
        }
    };
    timed(writer.record(e2e::OPEN_OK, &[])).await?;
    let tasks = auth.scope.tasks.clone();
    let (stream, pump) = worker(
        reader,
        writer,
        mtu,
        lease,
        Role::Destination(auth),
        first,
        session,
    );
    tasks.spawn(Box::pin(pump));
    let (mut app_read, mut app_write) = app.split_boxed();
    let upload = async {
        let mut buf = vec![0; stream.max_write_size()];
        loop {
            let size = app_read.read(&mut buf).await?;
            if size == 0 {
                return stream.shutdown().await;
            }
            stream.write_all(&buf[..size]).await?;
        }
    };
    let download = async {
        let mut buf = vec![0; stream.max_write_size()];
        loop {
            let size = stream.read(&mut buf).await?;
            if size == 0 {
                return app_write.shutdown().await;
            }
            app_write.write_all(&buf[..size]).await?;
        }
    };
    let mut upload = std::pin::pin!(upload);
    let mut download = std::pin::pin!(download);
    let bridge = async {
        tokio::select! {
            res = &mut upload => {
                res?;
                download.await
            }
            res = &mut download => {
                res?;
                upload.await
            }
        }
    };
    let failure = async {
        let error = cancellation(&stream.life.0).await;
        if error == CoreErr::Closed {
            std::future::pending().await
        } else {
            error
        }
    };
    tokio::select! {
        res = bridge => res,
        error = failure => Err(error),
    }
}

fn worker(
    reader: WireReader,
    writer: WireWriter,
    mtu: u16,
    lease: Arc<LeaseHandle>,
    role: Role,
    first: Vec<u8>,
    session: OwnedSemaphorePermit,
) -> (E2eStream, impl Future<Output = ()> + use<>) {
    let maximum =
        (usize::from(mtu).min(crate::STREAM_CHUNK) - e2e::ST_OVERHEAD).min(e2e::ST_MAX_BODY);
    let (input, rx) = mpsc::channel(2);
    if !first.is_empty() {
        let _ = input.try_send(Some(first));
    }
    let (output, writes) = mpsc::channel(1);
    let signal = watch::channel(None).0;
    let stream = E2eStream {
        life: Arc::new(Lifetime(signal.clone())),
        input: Arc::new(AsyncMutex::new(Inbox {
            rx,
            pending: Vec::new(),
            offset: 0,
            fin: false,
        })),
        output,
        maximum,
    };
    let pump = async move {
        let _session = session;
        let error = run(
            (reader, writer),
            lease,
            role,
            input,
            writes,
            &signal,
            maximum,
        )
        .await;
        signal.send_replace(Some(error));
    };
    (stream, pump)
}

async fn run(
    (mut reader, mut writer): (WireReader, WireWriter),
    lease: Arc<LeaseHandle>,
    mut role: Role,
    input: mpsc::Sender<Option<Vec<u8>>>,
    mut writes: mpsc::Receiver<Write>,
    signal: &watch::Sender<Option<CoreErr>>,
    maximum: usize,
) -> CoreErr {
    let controls = role.lease_keys();
    let origin = matches!(role, Role::Origin(_));
    let (requests, mut to_send) = mpsc::channel::<Request>(16);
    let (acks, replies) = mpsc::channel::<Ack>(16);
    let (verify, mut credentials) = mpsc::channel::<Vec<u8>>(1);
    let (results, mut verified) = mpsc::channel::<[u8; 8]>(1);
    const RECEIVED_FIN: u8 = 1;
    const SENT_FIN: u8 = 2;
    const BOTH_FINISHED: u8 = RECEIVED_FIN | SENT_FIN;
    let finished = AtomicU8::new(0);

    let inbound = async {
        let mut saw_fin = false;
        let mut in_gate = lease.gate_cache();
        loop {
            if finished.load(Ordering::Acquire) == BOTH_FINISHED {
                return Ok(());
            }
            let event = match reader.next().await {
                Err(CoreErr::UnexpectedEof) if saw_fin => {
                    if finished.load(Ordering::Acquire) == BOTH_FINISHED {
                        return Ok(());
                    }
                    return std::future::pending().await;
                }
                other => other?,
            };
            match event {
                Event::Record(e2e::ST_DATA, data) if !saw_fin && data.len() <= maximum => {
                    if data.is_empty() {
                        continue;
                    }
                    lease.remaining()?;
                    if !origin && let Some(active_gate) = in_gate.current(&lease) {
                        match active_gate.charge_stream(Direction::Ingress, data.len()) {
                            StreamAction::Allow => {}
                            StreamAction::Delay(delay) => {
                                tokio::time::sleep(delay).await;
                                lease.remaining()?;
                            }
                            StreamAction::Close(err) => return Err(err),
                        }
                    }
                    input.send(Some(data)).await.map_err(|_| CoreErr::Closed)?;
                }
                Event::Record(e2e::ST_FIN, data) if !saw_fin && data.is_empty() => {
                    input.send(None).await.map_err(|_| CoreErr::Closed)?;
                    saw_fin = true;
                    if finished.fetch_or(RECEIVED_FIN, Ordering::AcqRel) == SENT_FIN {
                        return Ok(());
                    }
                }
                Event::Record(e2e::ST_RENEW, data) if !origin => {
                    e2e::credential(&data)?;
                    let _ = verify.try_send(data);
                }
                Event::Record(e2e::ST_RENEW_OK, data) if origin => {
                    acks.send((LeaseSlot::Endpoint, Lease::from_wire_ttl(&data)?))
                        .await
                        .map_err(|_| CoreErr::Closed)?;
                }
                Event::Hop(kind, distance, body) if origin => {
                    let Some(key) = controls.get(usize::from(distance)) else {
                        continue;
                    };
                    let Ok(data) = key.lock().open(kind, &body) else {
                        continue;
                    };
                    if kind == hop::ST_CLOSE {
                        let reason = setup::decode_error(&data)?;
                        if finished.load(Ordering::Acquire) == BOTH_FINISHED {
                            return Ok(());
                        }
                        if saw_fin && matches!(reason, CoreErr::UnexpectedEof | CoreErr::Closed) {
                            return std::future::pending().await;
                        }
                        return Err(if usize::from(distance) + 1 == controls.len() {
                            reason
                        } else {
                            CoreErr::HopRejected {
                                index: distance,
                                reason: Box::new(reason),
                            }
                        });
                    }
                    if kind == hop::ST_RENEW_OK && usize::from(distance) + 1 < controls.len() {
                        acks.send((LeaseSlot::Hop(distance), Lease::from_wire_ttl(&data)?))
                            .await
                            .map_err(|_| CoreErr::Closed)?;
                    }
                }
                Event::Hop(hop::ST_CLOSE, 0, body) if !origin => {
                    if let Ok(plaintext) = controls[0].lock().open(hop::ST_CLOSE, &body) {
                        return Err(setup::decode_error(&plaintext)?);
                    }
                }
                Event::Hop(..) => {}
                _ => return Err(CoreErr::Malformed),
            }
        }
    };

    struct PendingWrite {
        data: Vec<u8>,
        signal: oneshot::Sender<Result<(), CoreErr>>,
        sleep: Pin<Box<tokio::time::Sleep>>,
    }

    let live_mtu = below_floor(writer.mtu.clone(), writer.floor);
    let outgoing = async {
        let mut sent_fin = false;
        let mut out_gate = lease.gate_cache();
        let mut pending_write: Option<PendingWrite> = None;
        loop {
            tokio::select! {
                req = to_send.recv() => match req {
                    Some((LeaseSlot::Endpoint, credential)) => {
                        writer.record(e2e::ST_RENEW, &credential).await?;
                    }
                    Some((LeaseSlot::Hop(index), credential)) => {
                        let body = controls[usize::from(index)]
                            .lock()
                            .seal(hop::ST_RENEW, &credential)?;
                        writer.control(hop::ST_RENEW, index, &body).await?;
                    }
                    None => return Err(CoreErr::Closed),
                },
                upd = verified.recv() => match upd {
                    Some(updated) => writer.record(e2e::ST_RENEW_OK, &updated).await?,
                    None => return Err(CoreErr::Closed),
                },
                _ = async { pending_write.as_mut().unwrap().sleep.as_mut().await }, if pending_write.is_some() => {
                    let PendingWrite { data, signal, .. } = pending_write.take().unwrap();
                    let result = match lease.remaining() {
                        Ok(_) => writer.record(e2e::ST_DATA, &data).await,
                        Err(err) => Err(err),
                    };
                    let _ = signal.send(result.clone());
                    result?;
                },
                item = writes.recv(), if pending_write.is_none() => match item {
                    Some((data, signal)) => {
                        let result = match data {
                            Some(data) if !sent_fin => {
                                lease.remaining()?;
                                if !origin
                                    && let Some(active_gate) = out_gate.current(&lease)
                                {
                                    match active_gate.charge_stream(Direction::Egress, data.len()) {
                                        StreamAction::Allow => writer.record(e2e::ST_DATA, &data).await,
                                        StreamAction::Delay(delay) => {
                                            pending_write = Some(PendingWrite {
                                                data,
                                                signal,
                                                sleep: Box::pin(tokio::time::sleep(delay)),
                                            });
                                            continue;
                                        }
                                        StreamAction::Close(err) => {
                                            let _ = signal.send(Err(err.clone()));
                                            return Err(err);
                                        }
                                    }
                                } else {
                                    writer.record(e2e::ST_DATA, &data).await
                                }
                            }
                            Some(_) => {
                                let _ = signal.send(Err(CoreErr::Closed));
                                continue;
                            }
                            None if !sent_fin => {
                                let result = writer.record(e2e::ST_FIN, &[]).await;
                                sent_fin = true;
                                if result.is_ok() {
                                    finished.fetch_or(SENT_FIN, Ordering::AcqRel);
                                }
                                result
                            }
                            None => Ok(()),
                        };
                        let _ = signal.send(result.clone());
                        result?;
                        if finished.load(Ordering::Acquire) == BOTH_FINISHED {
                            return Ok(());
                        }
                    }
                    None => return Err(CoreErr::Closed),
                },
            }
        }
    };

    let manage = async {
        match &mut role {
            Role::Origin(origin) => {
                let _results = results;
                let _credentials = credentials;
                origin.drive(requests, replies, &lease).await
            }
            Role::Destination(auth) => {
                let _requests = requests;
                let _replies = replies;
                while let Some(bytes) = credentials.recv().await {
                    let updated = auth.renewal(bytes).await?;
                    results.send(updated).await.map_err(|_| CoreErr::Closed)?;
                }
                Err(CoreErr::Closed)
            }
        }
    };

    let mut error = tokio::select! {
        err = cancellation(signal) => err,
        err = lease.cancelled() => err,
        err = live_mtu => err,
        res = manage => res.err().unwrap_or(CoreErr::Closed),
        res = inbound => res.err().unwrap_or(CoreErr::Closed),
        res = outgoing => res.err().unwrap_or(CoreErr::Closed),
    };

    if finished.load(Ordering::Acquire) == BOTH_FINISHED
        && (matches!(error, CoreErr::Closed | CoreErr::UnexpectedEof)
            || matches!(
                &error,
                CoreErr::HopRejected { reason, .. }
                    if matches!(reason.as_ref(), CoreErr::UnexpectedEof | CoreErr::Closed)
            ))
    {
        error = CoreErr::Closed;
    }

    if origin {
        if let Role::Origin(origin) = &role {
            let reason = record_error(&error);
            let close = async {
                for (index, control) in controls[..origin.hops.len()].iter().enumerate().rev() {
                    let body = control.lock().seal(hop::ST_CLOSE, &reason);
                    if let Ok(body) = body {
                        let _ = writer.control(hop::ST_CLOSE, index as u8, &body).await;
                    }
                }
                let _ = writer.writer.lock().await.shutdown().await;
                Ok(())
            };
            best_effort(close).await;
            origin.report(if error == CoreErr::Closed {
                PathOutcome::Closed
            } else {
                PathOutcome::Failed(error.clone())
            });
        }
    } else if error != CoreErr::Closed {
        let body = controls[0]
            .lock()
            .seal(hop::ST_CLOSE, &record_error(&error));
        if let Ok(body) = body {
            best_effort(writer.control(hop::ST_CLOSE, 0, &body)).await;
        }
        let _ = tokio::time::timeout(
            Duration::from_millis(50),
            writer.writer.lock().await.shutdown(),
        )
        .await;
    }
    error
}
