use rand_core::{OsRng, RngCore};
use std::sync::{
    Arc,
    atomic::{AtomicU16, Ordering},
};
use std::time::Duration;
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, mpsc, watch},
    time::Instant,
};

use super::{
    AwaitingConfirm, EndpointAuth, Lifetime, cancellation, record_error,
    renewal::{Ack, Renewals, Request},
};
use crate::{
    CoreErr, CredentialTarget, DatagramEndpointHandler, Either, PacketBuf, PathOutcome,
    cid::Cid,
    crypto::{
        aead::{ControlCipher, DatagramRx, DatagramTx},
        noise_ik::SessionKeys,
    },
    grant::{GrantEnforcer, GrantSpec},
    path::{
        best_effort,
        dg_switch::{self, Binding},
        timed,
    },
    race,
    scope::Scope,
    wire::{e2e, hop, setup, u16_at, u64_at},
};

#[derive(Clone)]
pub struct E2eDatagram {
    life: Arc<Lifetime>,
    mtu: Arc<AtomicU16>,
    incoming: Arc<Mutex<mpsc::Receiver<PacketBuf>>>,
    outgoing: mpsc::Sender<PacketBuf>,
}
impl E2eDatagram {
    pub fn max_payload(&self) -> usize {
        usize::from(self.mtu.load(Ordering::Acquire)).saturating_sub(e2e::DG_OVERHEAD)
    }
    /// Check size and queue space synchronously. An oversize message leaves the
    /// connection open, and never enters the carrier's send queue.
    pub fn send(&self, packet: PacketBuf) -> Result<(), CoreErr> {
        self.check(&packet)?;
        self.outgoing.try_send(packet).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => CoreErr::WouldBlock,
            mpsc::error::TrySendError::Closed(_) => self.failure(),
        })
    }
    pub async fn send_wait(&self, packet: PacketBuf) -> Result<(), CoreErr> {
        self.check(&packet)?;
        let slot = self.outgoing.reserve().await.map_err(|_| self.failure())?;
        self.check(&packet)?;
        slot.send(packet);
        Ok(())
    }
    pub async fn recv(&self) -> Result<PacketBuf, CoreErr> {
        let mut incoming = self.incoming.lock().await;
        match race(cancellation(&self.life.0), incoming.recv()).await {
            Either::Left(error) => Err(error),
            Either::Right(packet) => packet.ok_or_else(|| self.failure()),
        }
    }
    fn check(&self, packet: &PacketBuf) -> Result<(), CoreErr> {
        if let Some(error) = self.life.0.borrow().clone() {
            return Err(error);
        }
        let max = self.max_payload();
        if packet.len() > max {
            return Err(CoreErr::MessageTooLarge(max));
        }
        Ok(())
    }
    fn failure(&self) -> CoreErr {
        self.life.0.borrow().clone().unwrap_or(CoreErr::Closed)
    }
}
pub(crate) struct Wire {
    binding: Binding,
    remote: Cid,
    tx: DatagramTx,
    rx: DatagramRx,
}
impl Wire {
    pub fn new(binding: Binding, remote: Cid, keys: SessionKeys) -> Self {
        Self {
            binding,
            remote,
            tx: DatagramTx::new(keys.tx),
            rx: DatagramRx::new(keys.rx),
        }
    }
    async fn record(&mut self, kind: u8, packet: PacketBuf) -> Result<(), CoreErr> {
        let mut frame = self.tx.seal(kind, packet)?;
        if !frame.prepend_header(&hop::datagram_data(self.remote)) {
            return Err(CoreErr::Malformed);
        }
        self.binding.send(frame).await
    }
    async fn control(&self, kind: u8, ttl: u8, body: &[u8]) -> Result<(), CoreErr> {
        self.binding
            .send(dg_switch::control(kind, ttl, self.remote, body))
            .await
    }
    fn decode(&mut self, mut packet: PacketBuf) -> Result<(u64, u8, PacketBuf), CoreErr> {
        if packet.as_slice().first() != Some(&hop::DG_DATA) || !packet.strip_header(5) {
            return Err(CoreErr::Malformed);
        }
        self.rx.open_sequenced(packet)
    }
}

pub(crate) struct Mtu {
    pub ceiling: u16,
    pub floor: u16,
}

pub(crate) async fn connect(
    scope: &Scope,
    mut wire: Wire,
    mtu: Mtu,
    grant: Arc<GrantEnforcer>,
    origin: Renewals,
    session: OwnedSemaphorePermit,
) -> Result<E2eDatagram, CoreErr> {
    timed(wire.record(e2e::DG_DATA, PacketBuf::from_slice(&[]))).await?;
    let (handle, worker) = worker(wire, mtu, grant, Role::Origin(origin), None, session);
    scope.tasks.spawn(Box::pin(worker));
    Ok(handle)
}
pub(crate) async fn serve(
    mut wire: Wire,
    mtu: Mtu,
    handler: Arc<dyn DatagramEndpointHandler>,
    auth: EndpointAuth,
    pending: AwaitingConfirm,
    session: OwnedSemaphorePermit,
) -> Result<(), CoreErr> {
    let grant = auth.grant.clone();
    let setup = async {
        loop {
            let frame = wire.binding.recv().await?;
            if frame.len() > usize::from(mtu.ceiling) {
                continue;
            }
            if let Ok((seq, e2e::DG_DATA, packet)) = wire.decode(frame) {
                if seq == 0 && packet.is_empty() {
                    return Ok(None);
                }
                if grant.check_and_deduct(packet.len()) {
                    return Ok(Some(packet));
                }
            }
        }
    };
    let first = match race(
        grant.cancelled(),
        crate::path::before(pending.deadline, setup),
    )
    .await
    {
        Either::Left(error) => return Err(error),
        Either::Right(result) => result?,
    };
    drop(pending);
    let app = match race(grant.cancelled(), timed(handler.open(auth.peer))).await {
        Either::Right(Ok(link)) => link,
        other => {
            let reason = match other {
                Either::Left(error) | Either::Right(Err(error)) => error,
                _ => unreachable!(),
            };
            best_effort(wire.record(e2e::DG_CLOSE, PacketBuf::from_slice(&record_error(&reason))))
                .await;
            return Err(reason);
        }
    };
    let tasks = auth.scope.tasks.clone();
    let (handle, worker) = worker(wire, mtu, grant, Role::Destination(auth), first, session);
    tasks.spawn(Box::pin(worker));
    let upload = async {
        loop {
            let packet = app.recv().await?;
            match handle.send_wait(packet).await {
                Ok(()) | Err(CoreErr::MessageTooLarge(_)) => {}
                Err(error) => return Err(error),
            }
        }
    };
    let download = async {
        loop {
            app.send(handle.recv().await?).await?;
        }
    };
    let application = async { same(race(upload, download).await) };
    match race(cancellation(&handle.life.0), application).await {
        Either::Left(error) => Err(error),
        Either::Right(result) => {
            if let Err(error) = &result {
                handle.life.0.send_replace(Some(error.clone()));
            }
            result
        }
    }
}
enum Role {
    Origin(Renewals),
    Destination(EndpointAuth),
}

fn worker(
    wire: Wire,
    limits: Mtu,
    grant: Arc<GrantEnforcer>,
    role: Role,
    first: Option<PacketBuf>,
    permit: OwnedSemaphorePermit,
) -> (E2eDatagram, impl Future<Output = ()> + use<>) {
    let (outgoing, outbound) = mpsc::channel(16);
    let (incoming, rx) = mpsc::channel(16);
    if let Some(first) = first {
        let _ = incoming.try_send(first);
    }
    let mtu = Arc::new(AtomicU16::new(limits.ceiling));
    let signal = watch::channel(None).0;
    let handle = E2eDatagram {
        life: Arc::new(Lifetime(signal.clone())),
        mtu: mtu.clone(),
        incoming: Arc::new(Mutex::new(rx)),
        outgoing,
    };
    let pump = async move {
        let _permit = permit;
        let mut session = Session {
            wire,
            max: limits.ceiling,
            min: limits.floor,
            mtu,
            grant,
            role,
            incoming,
            probe: None,
            last_hint: None,
        };
        session.run(outbound, &signal).await;
    };
    (handle, pump)
}

struct Session {
    wire: Wire,
    max: u16,
    min: u16,
    mtu: Arc<AtomicU16>,
    grant: Arc<GrantEnforcer>,
    role: Role,
    incoming: mpsc::Sender<PacketBuf>,
    probe: Option<Probe>,
    last_hint: Option<Instant>,
}
impl Session {
    async fn run(
        &mut self,
        outbound: mpsc::Receiver<PacketBuf>,
        signal: &watch::Sender<Option<CoreErr>>,
    ) {
        let mut ciphers: Vec<_> = match &self.role {
            Role::Origin(origin) => origin.hops.iter().map(|key| key.control(true)).collect(),
            Role::Destination(_) => Vec::new(),
        };
        let (requests, to_send) = mpsc::channel::<Request>(16);
        let (acks, replies) = mpsc::channel::<Ack>(16);
        let grant = self.grant.clone();
        let (manage, peer) = match &mut self.role {
            Role::Origin(origin) => (Some(origin), None),
            Role::Destination(auth) => (None, Some(auth)),
        };
        // Move the driver out of the I/O borrow so policy refresh and I/O are
        // independently pollable, including while receiving a burst of data.
        let origin = manage.is_some();
        let mut context = Context {
            origin,
            to_send,
            acks,
            outbound,
            ciphers: &mut ciphers,
            peer,
            policy: None,
            mtu_watch: self.wire.binding.port.link.caps().mtu_watch,
        };
        let mut pump = Pump {
            wire: &mut self.wire,
            min: self.min,
            max: self.max,
            mtu: &self.mtu,
            probe: &mut self.probe,
            last_hint: &mut self.last_hint,
            grant: &grant,
            incoming: &self.incoming,
            route: manage
                .as_ref()
                .map(|driver| (driver.source.clone(), driver.path_id)),
        };
        let drive = async {
            if let Some(driver) = manage {
                driver.drive(requests, replies, &grant).await
            } else {
                let (_requests, _replies) = (requests, replies);
                std::future::pending().await
            }
        };
        let result = match race(
            race(cancellation(signal), grant.cancelled()),
            race(drive, pump.run(&mut context)),
        )
        .await
        {
            Either::Left(Either::Left(error) | Either::Right(error)) => Err(error),
            Either::Right(Either::Left(result) | Either::Right(result)) => result,
        };
        let error = result.err().unwrap_or(CoreErr::Closed);
        signal.send_replace(Some(error.clone()));
        let wire = &mut self.wire;
        let close = async {
            // A received E2E_CLOSE can be echoed once without a loop: the
            // receiving session removes its CID when its worker returns.
            let _ = wire
                .record(e2e::DG_CLOSE, PacketBuf::from_slice(&record_error(&error)))
                .await;
            for (index, cipher) in ciphers.iter_mut().enumerate().rev() {
                let close = cipher.seal(hop::DG_CLOSE, &record_error(&error))?;
                let _ = wire.control(hop::DG_CLOSE, index as u8, &close).await;
            }
            Ok(())
        };
        best_effort(close).await;
        if let Role::Origin(origin) = &self.role {
            origin.report(if error == CoreErr::Closed {
                PathOutcome::Closed
            } else {
                PathOutcome::Failed(error)
            });
        }
    }
}

struct Context<'a> {
    origin: bool,
    to_send: mpsc::Receiver<Request>,
    acks: mpsc::Sender<Ack>,
    outbound: mpsc::Receiver<PacketBuf>,
    ciphers: &'a mut [ControlCipher],
    peer: Option<&'a mut EndpointAuth>,
    policy: Option<crate::BoxFut<'static, Result<[u8; 16], CoreErr>>>,
    mtu_watch: watch::Receiver<u16>,
}
struct Pump<'a> {
    wire: &'a mut Wire,
    min: u16,
    max: u16,
    mtu: &'a AtomicU16,
    probe: &'a mut Option<Probe>,
    last_hint: &'a mut Option<Instant>,
    grant: &'a GrantEnforcer,
    incoming: &'a mpsc::Sender<PacketBuf>,
    route: Option<(Arc<dyn crate::PathSource>, u64)>,
}
enum Work {
    Probe,
    Mtu,
    Grant(Result<[u8; 16], CoreErr>),
    Renewal(Option<Request>),
    App(Option<PacketBuf>),
    Wire(Result<PacketBuf, CoreErr>),
}
impl Pump<'_> {
    async fn run(&mut self, context: &mut Context<'_>) -> Result<(), CoreErr> {
        let mut prefer_app = false;
        loop {
            let timer = async {
                match self.probe.as_ref() {
                    Some(probe) => tokio::time::sleep_until(probe.deadline()).await,
                    None => std::future::pending().await,
                }
                Work::Probe
            };
            let mtu = async {
                dg_switch::mtu_changed(&mut context.mtu_watch).await;
                Work::Mtu
            };
            let policy = async {
                let result = match context.policy.as_mut() {
                    Some(policy) => policy.await,
                    None => std::future::pending().await,
                };
                Work::Grant(result)
            };
            let requests = async { Work::Renewal(context.to_send.recv().await) };
            let input = async { Work::Wire(self.wire.binding.recv().await) };
            let output = async { Work::App(context.outbound.recv().await) };
            let traffic = async {
                if prefer_app {
                    same(race(output, input).await)
                } else {
                    same(race(input, output).await)
                }
            };
            let work = same(
                race(timer, async {
                    same(
                        race(mtu, async {
                            same(race(policy, async { same(race(requests, traffic).await) }).await)
                        })
                        .await,
                    )
                })
                .await,
            );
            prefer_app = !prefer_app;
            match work {
                Work::Probe => self.probe_step().await?,
                Work::Mtu => {
                    let mtu = self.wire.binding.mtu();
                    if mtu < self.mtu.load(Ordering::Acquire) {
                        self.changed(mtu, context.origin).await?;
                    }
                }
                Work::Grant(result) => {
                    context.policy = None;
                    let body = PacketBuf::from_slice(&result?);
                    self.send(e2e::DG_RENEW_OK, body, context.origin).await?;
                }
                Work::Renewal(Some((CredentialTarget::Endpoint, value))) => {
                    self.send(e2e::DG_RENEW, PacketBuf::from_slice(&value), context.origin)
                        .await?;
                }
                Work::Renewal(Some((CredentialTarget::Hop(index), value))) => {
                    let body = context.ciphers[usize::from(index)].seal(hop::DG_RENEW, &value)?;
                    match self.wire.control(hop::DG_RENEW, index, &body).await {
                        Ok(()) | Err(CoreErr::WouldBlock) => {}
                        Err(error) => return Err(error),
                    }
                }
                Work::Renewal(None) | Work::App(None) => return Err(CoreErr::Closed),
                Work::App(Some(packet)) => {
                    if packet.len() + e2e::DG_OVERHEAD
                        <= usize::from(self.mtu.load(Ordering::Acquire))
                        && self.grant.check_and_deduct(packet.len())
                    {
                        self.send(e2e::DG_DATA, packet, context.origin).await?;
                    }
                }
                Work::Wire(packet) => self.receive(packet?, context).await?,
            }
        }
    }
    async fn send(&mut self, kind: u8, packet: PacketBuf, origin: bool) -> Result<(), CoreErr> {
        match self.wire.record(kind, packet).await {
            Ok(()) | Err(CoreErr::WouldBlock) => Ok(()),
            Err(CoreErr::MtuTooSmall(mtu)) => self.changed(mtu, origin).await,
            Err(error) => Err(error),
        }
    }
    async fn receive(
        &mut self,
        packet: PacketBuf,
        context: &mut Context<'_>,
    ) -> Result<(), CoreErr> {
        let wire = packet.as_slice();
        if wire[0] != hop::DG_DATA {
            if wire.len() < 6 || !context.origin {
                return Ok(());
            }
            let (kind, distance, body) = (wire[0], wire[1], &wire[6..]);
            if kind == hop::DG_MTU_HINT && body.len() == 2 {
                // A relay can advise a lower MTU, but only a local link or an
                // authenticated failure can tear the session down.
                if self.probe.is_none() {
                    self.changed(u16_at(body, 0).max(self.min), true).await?;
                }
            } else if let Some(cipher) = context.ciphers.get_mut(usize::from(distance))
                && let Ok(plaintext) = cipher.open(kind, body)
            {
                match kind {
                    hop::DG_CLOSE => {
                        let reason = setup::decode_error(&plaintext)?;
                        return Err(CoreErr::HopRejected {
                            index: distance,
                            reason: Box::new(reason),
                        });
                    }
                    hop::DG_RENEW_OK => {
                        let spec = GrantSpec::from_wire(&plaintext)?;
                        let _ = context
                            .acks
                            .try_send((CredentialTarget::Hop(distance), spec));
                    }
                    _ => {}
                }
            }
            return Ok(());
        }
        let Ok((seq, kind, body)) = self.wire.decode(packet) else {
            return Ok(());
        };
        match kind {
            e2e::DG_DATA => {
                if !(seq == 0 && body.is_empty() && !context.origin)
                    && body.len() + e2e::DG_OVERHEAD <= usize::from(self.max)
                    && self.grant.check_and_deduct(body.len())
                {
                    let _ = self.incoming.try_send(body);
                }
            }
            e2e::DG_RENEW if !context.origin => {
                e2e::credential(body.as_slice())?;
                if context.policy.is_none() {
                    context.policy = context
                        .peer
                        .as_ref()
                        .map(|peer| peer.renewal(body.as_slice().to_vec()));
                }
            }
            e2e::DG_RENEW_OK if context.origin => {
                let spec = GrantSpec::from_wire(body.as_slice())?;
                let _ = context.acks.try_send((CredentialTarget::Endpoint, spec));
            }
            e2e::DG_CLOSE => return Err(setup::decode_error(body.as_slice())?),
            e2e::MTU_PROBE
                if valid_probe(&body, self.max) && self.grant.check_and_deduct(body.len()) =>
            {
                self.send(e2e::MTU_PROBE_ACK, body, context.origin).await?;
            }
            e2e::MTU_PROBE_ACK if valid_probe(&body, self.max) => {
                if let Some(probe) = self.probe.as_mut()
                    && probe.ack(u64_at(body.as_slice(), 0), u16_at(body.as_slice(), 8))
                {
                    let low = probe.low;
                    self.set_mtu(low);
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn set_mtu(&self, mtu: u16) {
        if self.mtu.swap(mtu, Ordering::AcqRel) != mtu
            && let Some((source, id)) = &self.route
        {
            source.report_outcome(*id, PathOutcome::MtuChanged { mtu });
        }
    }
    async fn changed(&mut self, ceiling: u16, origin: bool) -> Result<(), CoreErr> {
        if ceiling < self.min {
            return Err(CoreErr::MtuTooSmall(ceiling));
        }
        let now = Instant::now();
        if self
            .last_hint
            .is_some_and(|last| now.duration_since(last) < Duration::from_millis(200))
        {
            return Ok(());
        }
        *self.last_hint = Some(now);
        self.set_mtu(self.min);
        if origin {
            let high = self.max.min(self.wire.binding.mtu());
            *self.probe = Some(Probe {
                low: self.min,
                high,
                pending: None,
            });
        } else {
            self.wire
                .control(hop::DG_MTU_HINT, 0, &ceiling.to_be_bytes())
                .await?;
            // Destination uses the same authenticated probing machinery for
            // its send path. The hint wakes the originator independently.
            *self.probe = Some(Probe {
                low: self.min,
                high: ceiling.min(self.max),
                pending: None,
            });
        }
        Ok(())
    }
    async fn probe_step(&mut self) -> Result<(), CoreErr> {
        let probe = self.probe.as_mut().unwrap();
        let retry = probe.pending.take().and_then(|pending| {
            if pending.attempt == 1 {
                probe.high = pending.size - 1;
                None
            } else {
                Some(pending.size)
            }
        });
        if probe.low >= probe.high {
            *self.probe = None;
            return Ok(());
        }
        let size = retry.unwrap_or_else(|| probe.low + (probe.high - probe.low).div_ceil(2));
        let token = OsRng.next_u64();
        let payload = usize::from(size) - e2e::DG_OVERHEAD;
        let mut body = PacketBuf::with_payload_cap(payload);
        body.spare_payload()[..8].copy_from_slice(&token.to_be_bytes());
        body.spare_payload()[8..10].copy_from_slice(&size.to_be_bytes());
        body.advance_payload(payload);
        match self.wire.record(e2e::MTU_PROBE, body).await {
            Ok(()) | Err(CoreErr::WouldBlock) => {
                probe.pending = Some(PendingProbe {
                    token,
                    size,
                    until: Instant::now() + Duration::from_millis(120),
                    attempt: u8::from(retry.is_some()),
                });
            }
            Err(CoreErr::MtuTooSmall(mtu)) if mtu >= self.min => probe.high = (size - 1).min(mtu),
            Err(error) => return Err(error),
        }
        Ok(())
    }
}
fn same<T>(value: Either<T, T>) -> T {
    match value {
        Either::Left(v) | Either::Right(v) => v,
    }
}
fn valid_probe(body: &PacketBuf, max: u16) -> bool {
    if body.len() < 10 {
        return false;
    }
    let size = u16_at(body.as_slice(), 8);
    size <= max && usize::from(size) == body.len() + e2e::DG_OVERHEAD
}
struct PendingProbe {
    token: u64,
    size: u16,
    until: Instant,
    attempt: u8,
}
struct Probe {
    low: u16,
    high: u16,
    pending: Option<PendingProbe>,
}
impl Probe {
    fn deadline(&self) -> Instant {
        self.pending
            .as_ref()
            .map_or_else(Instant::now, |probe| probe.until)
    }
    fn ack(&mut self, token: u64, size: u16) -> bool {
        if self
            .pending
            .as_ref()
            .is_some_and(|probe| probe.token == token && probe.size == size)
        {
            self.low = size;
            self.pending = None;
            return true;
        }
        false
    }
}
