use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, mpsc, oneshot, watch};

use super::{
    AwaitingConfirm, EndpointAuth, Lifetime, cancellation, record_error,
    renewal::{Ack, Renewals, Request},
};
use crate::{
    CoreErr, CredentialTarget, Either, PathOutcome, StreamEndpointHandler, StreamWrite,
    crypto::{
        aead::{ControlCipher, StreamCipher},
        noise_ik::SessionKeys,
    },
    grant::{GrantEnforcer, GrantSpec},
    path::{
        below_floor, best_effort,
        st_splice::{self, Carrier, Reader, Writer},
        timed,
    },
    race, read_exact,
    scope::Scope,
    wire::{e2e, hop, setup},
};

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
    pub fn max_write_size(&self) -> usize {
        self.maximum
    }
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
    pub async fn write(&self, buf: &[u8]) -> Result<usize, CoreErr> {
        let amount = buf.len().min(self.maximum);
        if amount == 0 {
            return Ok(0);
        }
        self.command(Some(buf[..amount].to_vec())).await?;
        Ok(amount)
    }
    pub async fn write_all(&self, mut buf: &[u8]) -> Result<(), CoreErr> {
        while !buf.is_empty() {
            let count = self.write(buf).await?;
            buf = &buf[count..];
        }
        Ok(())
    }
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
    mtu: watch::Receiver<u16>,
    floor: u16,
}
impl WireWriter {
    fn new(
        writer: Box<dyn StreamWrite>,
        key: [u8; 32],
        mtu: watch::Receiver<u16>,
        floor: u16,
    ) -> Self {
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
        let limit = (*self.mtu.borrow()).min(crate::STREAM_CHUNK as u16);
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
    fn grant_keys(&self) -> Vec<Mutex<ControlCipher>> {
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

pub(crate) async fn connect(
    scope: &Scope,
    io: Carrier,
    keys: SessionKeys,
    (mtu, floor): (u16, u16),
    grant: Arc<GrantEnforcer>,
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
    match race(grant.cancelled(), timed(status)).await {
        Either::Left(error) => return Err(error),
        Either::Right(result) => result?,
    }
    let (stream, pump) = worker(
        reader,
        writer,
        mtu,
        grant,
        Role::Origin(origin),
        Vec::new(),
        session,
    );
    scope.tasks.spawn(Box::pin(pump));
    Ok(stream)
}

pub(crate) async fn serve(
    io: Carrier,
    keys: SessionKeys,
    (mtu, floor): (u16, u16),
    handler: Arc<dyn StreamEndpointHandler>,
    auth: EndpointAuth,
    pending: AwaitingConfirm,
    session: OwnedSemaphorePermit,
) -> Result<(), CoreErr> {
    let mut reader = WireReader::new(io.reader, keys.rx);
    let mut writer = WireWriter::new(io.writer, keys.tx, io.mtu, floor);
    let grant = auth.grant.clone();
    let setup = async {
        match reader.next().await? {
            Event::Record(e2e::ST_DATA, data) => Ok(data),
            _ => Err(CoreErr::Authentication),
        }
    };
    let first = match race(
        race(grant.cancelled(), writer.unavailable()),
        crate::path::before(pending.deadline, setup),
    )
    .await
    {
        Either::Left(Either::Left(error) | Either::Right(error)) => return Err(error),
        Either::Right(first) => first?,
    };
    let maximum = usize::from(mtu)
        .min(crate::STREAM_CHUNK)
        .saturating_sub(e2e::ST_OVERHEAD);
    if first.len() > maximum {
        return Err(CoreErr::Malformed);
    }
    if !first.is_empty() {
        grant.wait_charge(first.len()).await?;
    }
    drop(pending);
    let app = match race(
        race(grant.cancelled(), writer.unavailable()),
        timed(handler.open(auth.peer)),
    )
    .await
    {
        Either::Right(Ok(io)) => io,
        result => {
            let error = match result {
                Either::Left(Either::Left(error) | Either::Right(error))
                | Either::Right(Err(error)) => error,
                _ => unreachable!(),
            };
            let code = if error == CoreErr::TargetRefused {
                e2e::TARGET_REFUSED
            } else {
                e2e::TARGET_UNREACHABLE
            };
            best_effort(writer.record(code, &[])).await;
            return Err(error);
        }
    };
    timed(writer.record(e2e::OPEN_OK, &[])).await?;
    let tasks = auth.scope.tasks.clone();
    let (stream, pump) = worker(
        reader,
        writer,
        mtu,
        grant,
        Role::Destination(auth),
        first,
        session,
    );
    tasks.spawn(Box::pin(pump));
    let (mut app_read, mut app_write) = app.split();
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
        match race(&mut upload, &mut download).await {
            Either::Left(result) => {
                result?;
                download.await
            }
            Either::Right(result) => {
                result?;
                upload.await
            }
        }
    };
    // Revocation wakes even an app blocked in a local socket operation.
    let failure = async {
        let error = cancellation(&stream.life.0).await;
        if error == CoreErr::Closed {
            // Authenticated FIN can reach the bounded queue before the last
            // bytes have been handed to the local socket. Drain it normally.
            std::future::pending().await
        } else {
            error
        }
    };
    match race(bridge, failure).await {
        Either::Left(result) => result,
        Either::Right(error) => Err(error),
    }
}

fn worker(
    reader: WireReader,
    writer: WireWriter,
    mtu: u16,
    grant: Arc<GrantEnforcer>,
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
            grant,
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
    grant: Arc<GrantEnforcer>,
    mut role: Role,
    input: mpsc::Sender<Option<Vec<u8>>>,
    mut writes: mpsc::Receiver<Write>,
    signal: &watch::Sender<Option<CoreErr>>,
    maximum: usize,
) -> CoreErr {
    let controls = role.grant_keys();
    let origin = matches!(role, Role::Origin(_));
    let (requests, mut to_send) = mpsc::channel::<Request>(16);
    let (acks, replies) = mpsc::channel::<Ack>(16);
    let (verify, mut credentials) = mpsc::channel::<Vec<u8>>(1);
    let (results, mut verified) = mpsc::channel::<[u8; 16]>(1);
    const RECEIVED_FIN: u8 = 1;
    const SENT_FIN: u8 = 2;
    const BOTH_FINISHED: u8 = RECEIVED_FIN | SENT_FIN;
    let finished = AtomicU8::new(0);

    let inbound = async {
        let mut saw_fin = false;
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
                    grant.wait_charge(data.len()).await?;
                    input.send(Some(data)).await.map_err(|_| CoreErr::Closed)?;
                }
                Event::Record(e2e::ST_FIN, data) if !saw_fin && data.is_empty() => {
                    input.send(None).await.map_err(|_| CoreErr::Closed)?;
                    saw_fin = true;
                    // Finish before polling another frame from a closing relay.
                    if finished.fetch_or(RECEIVED_FIN, Ordering::AcqRel) == SENT_FIN {
                        return Ok(());
                    }
                }
                Event::Record(e2e::ST_RENEW, data) if !origin => {
                    e2e::credential(&data)?;
                    let _ = verify.try_send(data);
                }
                Event::Record(e2e::ST_RENEW_OK, data) if origin => {
                    acks.send((CredentialTarget::Endpoint, GrantSpec::from_wire(&data)?))
                        .await
                        .map_err(|_| CoreErr::Closed)?;
                }
                Event::Hop(kind, distance, body) if origin => {
                    let Some(key) = controls.get(usize::from(distance)) else {
                        continue;
                    };
                    let Ok(data) = key.lock().unwrap().open(kind, &body) else {
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
                        acks.send((
                            CredentialTarget::Hop(distance),
                            GrantSpec::from_wire(&data)?,
                        ))
                        .await
                        .map_err(|_| CoreErr::Closed)?;
                    }
                }
                Event::Hop(hop::ST_CLOSE, 0, body) if !origin => {
                    if let Ok(plaintext) = controls[0].lock().unwrap().open(hop::ST_CLOSE, &body) {
                        return Err(setup::decode_error(&plaintext)?);
                    }
                }
                Event::Hop(..) => {}
                _ => return Err(CoreErr::Malformed),
            }
        }
    };
    let live_mtu = below_floor(writer.mtu.clone(), writer.floor);
    let outgoing = async {
        let mut sent_fin = false;
        loop {
            match race(race(to_send.recv(), verified.recv()), writes.recv()).await {
                Either::Left(Either::Left(Some((CredentialTarget::Endpoint, credential)))) => {
                    writer.record(e2e::ST_RENEW, &credential).await?;
                }
                Either::Left(Either::Left(Some((CredentialTarget::Hop(index), credential)))) => {
                    let body = controls[usize::from(index)]
                        .lock()
                        .unwrap()
                        .seal(hop::ST_RENEW, &credential)?;
                    writer.control(hop::ST_RENEW, index, &body).await?;
                }
                Either::Left(Either::Right(Some(updated))) => {
                    writer.record(e2e::ST_RENEW_OK, &updated).await?
                }
                Either::Right(Some((data, signal))) => {
                    let result = match data {
                        Some(data) if !sent_fin => {
                            // Charge in the writer so the bounded queue also
                            // propagates backpressure to the application.
                            grant.wait_charge(data.len()).await?;
                            writer.record(e2e::ST_DATA, &data).await
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
                _ => return Err(CoreErr::Closed),
            }
        }
    };
    let manage = async {
        match &mut role {
            Role::Origin(origin) => {
                let _results = results;
                let _credentials = credentials;
                origin.drive(requests, replies, &grant).await
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
    let mut error = match race(
        race(cancellation(signal), async {
            match race(grant.cancelled(), live_mtu).await {
                Either::Left(error) | Either::Right(error) => error,
            }
        }),
        race(manage, race(inbound, outgoing)),
    )
    .await
    {
        Either::Left(Either::Left(error) | Either::Right(error)) => error,
        Either::Right(Either::Left(result) | Either::Right(Either::Left(result) | Either::Right(result))) => {
            result.err().unwrap_or(CoreErr::Closed)
        }
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
    signal.send_replace(Some(error.clone()));
    if let Role::Origin(origin) = &role {
        origin.report(if error == CoreErr::Closed {
            PathOutcome::Closed
        } else {
            PathOutcome::Failed(error.clone())
        });
    }

    let close = async {
        // Close the farthest hop first so upstream splicers stay available.
        if origin {
            let terminal = controls.len() - 1;
            if finished.load(Ordering::Relaxed) != BOTH_FINISHED {
                let reason = if error == CoreErr::Closed {
                    CoreErr::UnexpectedEof
                } else {
                    error.clone()
                };
                let body = controls[terminal]
                    .lock()
                    .unwrap()
                    .seal(hop::ST_CLOSE, &record_error(&reason))?;
                writer.control(hop::ST_CLOSE, terminal as u8, &body).await?;
            }
            for index in (0..terminal).rev() {
                let body = controls[index]
                    .lock()
                    .unwrap()
                    .seal(hop::ST_CLOSE, &record_error(&error))?;
                writer.control(hop::ST_CLOSE, index as u8, &body).await?;
            }
        } else if error != CoreErr::Closed {
            let body = controls[0]
                .lock()
                .unwrap()
                .seal(hop::ST_CLOSE, &record_error(&error))?;
            writer.control(hop::ST_CLOSE, 0, &body).await?;
        }
        writer.writer.lock().await.shutdown().await
    };
    let _ = tokio::time::timeout(Duration::from_millis(50), close).await;
    error
}
