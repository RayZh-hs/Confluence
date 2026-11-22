use super::{best_effort, inbound};
use crate::{
    CoreErr, DatagramLink, Either, HopAuthCtx, PacketBuf,
    cid::{Cid, SlabTable},
    crypto::aead::ControlCipher,
    race,
    scope::Scope,
    wire::{e2e, hop, setup, u16_at},
};
use std::{
    num::NonZeroUsize,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
};
use tokio::sync::{OwnedSemaphorePermit, mpsc, watch};

const MAILBOX: NonZeroUsize = NonZeroUsize::new(32).unwrap();
const ADMISSION_PENDING: u8 = 0;
const ADMISSION_ACCEPTED: u8 = 1;
const ADMISSION_REJECTED: u8 = 2;

pub(crate) struct DatagramPort {
    pub link: Arc<dyn DatagramLink>,
    slots: Mutex<SlabTable<mpsc::Sender<PacketBuf>>>,
    gone: watch::Sender<Option<CoreErr>>,
    count: Arc<AtomicUsize>,
    admission: AtomicU8,
    _stop: watch::Sender<()>,
}
impl Drop for DatagramPort {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::Relaxed);
    }
}
impl DatagramPort {
    pub fn attach(scope: &Arc<Scope>, link: Arc<dyn DatagramLink>) -> Result<Arc<Self>, CoreErr> {
        let id = Arc::as_ptr(&link).cast::<()>() as usize;
        let mut ports = scope.datagram_ports.lock().unwrap();
        if let Some(port) = ports.get(&id).and_then(|port| port.upgrade()) {
            return Ok(port);
        }
        if ports.len() >= 256 {
            ports.retain(|_, port| port.strong_count() != 0);
        }
        scope.reserve_port()?;
        let (stop, mut stop_rx) = watch::channel(());
        let port = Arc::new(Self {
            link: link.clone(),
            slots: Mutex::new(SlabTable::new(4096)),
            gone: watch::channel(None).0,
            count: scope.port_count.clone(),
            admission: AtomicU8::new(ADMISSION_PENDING),
            _stop: stop,
        });
        ports.insert(id, Arc::downgrade(&port));
        let weak_port = Arc::downgrade(&port);
        let weak_scope = Arc::downgrade(scope);
        scope.tasks.spawn(Box::pin(async move {
            loop {
                let Either::Left(packet) = race(link.recv(), stop_rx.changed()).await else {
                    return;
                };
                let Some(port) = weak_port.upgrade() else {
                    return;
                };
                let packet = match packet {
                    Ok(packet) => packet,
                    Err(error) => {
                        port.gone.send_replace(Some(error));
                        return;
                    }
                };
                if packet.len() > usize::from(link.caps().mtu()) {
                    continue;
                }
                let Some(cid) = hop::route_cid(packet.as_slice()) else {
                    continue;
                };
                if cid == Cid::UNBOUND {
                    if packet.as_slice()[0] != setup::FWD {
                        continue;
                    }
                    let Some(scope) = weak_scope.upgrade() else {
                        return;
                    };
                    if !scope.precheck_datagram_setup(packet.as_slice()) {
                        continue;
                    }
                    let Ok(permit) = scope.pending.clone().try_acquire_owned() else {
                        continue;
                    };
                    let tasks = scope.tasks.clone();
                    tasks.spawn(Box::pin(async move {
                        let _ = inbound::datagram(scope, port, packet, permit).await;
                    }));
                } else if let Some(queue) = port.slots.lock().unwrap().get(cid) {
                    let _ = queue.try_send(packet);
                }
            }
        }));
        Ok(port)
    }
    pub fn bind(self: &Arc<Self>) -> Result<Binding, CoreErr> {
        let (tx, rx) = mpsc::channel(MAILBOX.get());
        let cid = self.slots.lock().unwrap().insert(tx).ok_or(CoreErr::Busy)?;
        Ok(Binding {
            cid,
            port: self.clone(),
            rx,
        })
    }
    pub fn mark_admitted(&self) {
        self.admission.store(ADMISSION_ACCEPTED, Ordering::Release);
    }
    pub fn mark_rejected(&self) {
        let _ = self.admission.compare_exchange(
            ADMISSION_PENDING,
            ADMISSION_REJECTED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
    pub fn is_admitted(&self) -> bool {
        self.admission.load(Ordering::Acquire) == ADMISSION_ACCEPTED
    }
    pub fn is_rejected(&self) -> bool {
        self.admission.load(Ordering::Acquire) == ADMISSION_REJECTED
    }
    pub async fn closed(&self) -> CoreErr {
        let mut gone = self.gone.subscribe();
        loop {
            if let Some(error) = gone.borrow_and_update().clone() {
                return error;
            }
            if gone.changed().await.is_err() {
                return CoreErr::Closed;
            }
        }
    }
}

pub(crate) struct Binding {
    pub cid: Cid,
    pub port: Arc<DatagramPort>,
    rx: mpsc::Receiver<PacketBuf>,
}
impl Drop for Binding {
    fn drop(&mut self) {
        self.port.slots.lock().unwrap().remove(self.cid);
    }
}
impl Binding {
    pub async fn recv(&mut self) -> Result<PacketBuf, CoreErr> {
        match race(self.port.closed(), self.rx.recv()).await {
            Either::Left(error) => Err(error),
            Either::Right(value) => value.ok_or(CoreErr::Closed),
        }
    }
    pub fn mtu(&self) -> u16 {
        self.port.link.caps().mtu()
    }
    pub async fn send(&self, packet: PacketBuf) -> Result<(), CoreErr> {
        self.port.link.send(packet).await
    }
}

pub(crate) fn control(kind: u8, ttl: u8, cid: Cid, body: &[u8]) -> PacketBuf {
    let mut packet = PacketBuf::from_slice(body);
    packet.prepend_header(&hop::datagram_control(kind, ttl, cid));
    packet
}

pub(crate) struct Transit {
    pub left: Binding,
    pub right: Binding,
    pub caller: Cid,
    pub next: Cid,
    pub min_mtu: u16,
    pub auth: HopAuthCtx,
    pub _session: OwnedSemaphorePermit,
}

impl Transit {
    pub async fn run(mut self) -> Result<(), CoreErr> {
        self.auth.pending.take();
        let mut cipher = self.auth.hop_key.control(false);
        let grant = self.auth.grant.clone();
        let result = match race(grant.cancelled(), self.pump(&mut cipher)).await {
            Either::Left(error) => Err(error),
            Either::Right(result) => result,
        };
        if let Err(error) = &result {
            let (code, argument) = setup::error_code(error);
            let mut body = [0; 4];
            body[..2].copy_from_slice(&code.to_be_bytes());
            body[2..].copy_from_slice(&argument.to_be_bytes());
            if let Ok(body) = cipher.seal(hop::DG_CLOSE, &body) {
                best_effort(
                    self.left
                        .send(control(hop::DG_CLOSE, 0, self.caller, &body)),
                )
                .await;
            }
        }
        result
    }

    async fn pump(&mut self, cipher: &mut ControlCipher) -> Result<(), CoreErr> {
        let mut left_mtu = self.left.port.link.caps().mtu_watch;
        let mut right_mtu = self.right.port.link.caps().mtu_watch;
        let mut last_hint = None;
        let mut renewal: Option<crate::BoxFut<'static, Result<[u8; 16], CoreErr>>> = None;
        let mut prefer_left = true;
        loop {
            let incoming = async {
                if prefer_left {
                    match race(self.left.recv(), self.right.recv()).await {
                        Either::Left(packet) => (true, packet),
                        Either::Right(packet) => (false, packet),
                    }
                } else {
                    match race(self.right.recv(), self.left.recv()).await {
                        Either::Left(packet) => (false, packet),
                        Either::Right(packet) => (true, packet),
                    }
                }
            };
            let mtu_change = race(mtu_changed(&mut left_mtu), mtu_changed(&mut right_mtu));
            let (forward, mut packet) = match race(
                race(mtu_change, async {
                    match renewal.as_mut() {
                        Some(work) => work.await,
                        None => std::future::pending().await,
                    }
                }),
                incoming,
            )
            .await
            {
                Either::Right((forward, packet)) => (forward, packet?),
                Either::Left(Either::Right(grant)) => {
                    renewal = None;
                    let body = cipher.seal(hop::DG_RENEW_OK, &grant?)?;
                    self.left
                        .send(control(hop::DG_RENEW_OK, 0, self.caller, &body))
                        .await?;
                    continue;
                }
                Either::Left(Either::Left(_)) => {
                    let mtu = (*left_mtu.borrow()).min(*right_mtu.borrow());
                    self.report_mtu(mtu, &mut last_hint).await?;
                    continue;
                }
            };
            prefer_left = !forward;
            let (destination, cid) = if forward {
                (&self.right, self.next)
            } else {
                (&self.left, self.caller)
            };
            let kind = packet.as_slice()[0];
            if kind == hop::DG_DATA {
                if packet.len() < e2e::DG_OVERHEAD {
                    continue;
                }
                if packet.len() > usize::from(destination.mtu()) {
                    self.report_mtu(destination.mtu(), &mut last_hint).await?;
                    continue;
                }
                if !self.auth.grant.check_and_deduct(packet.len()) {
                    continue;
                }
                packet.as_mut_slice()[1..5].copy_from_slice(&cid.raw().to_be_bytes());
            } else if (hop::DG_RENEW..=hop::DG_MTU_HINT).contains(&kind) {
                if packet.len() < 6 {
                    continue;
                }
                let ttl = packet.as_slice()[1];
                let body = &packet.as_slice()[6..];
                if kind == hop::DG_MTU_HINT {
                    if forward || body.len() != 2 {
                        continue;
                    }
                    self.report_mtu(u16_at(body, 0).max(self.min_mtu), &mut last_hint)
                        .await?;
                    continue;
                }
                if !(24..=hop::MAX_CONTROL).contains(&body.len()) {
                    continue;
                }
                if forward {
                    if ttl == 0 {
                        let Ok(plaintext) = cipher.open(kind, body) else {
                            continue;
                        };
                        match kind {
                            hop::DG_RENEW => {
                                e2e::credential(&plaintext)?;
                                if renewal.is_none() {
                                    renewal = Some(self.auth.renewal(plaintext));
                                }
                            }
                            hop::DG_CLOSE => return Ok(()),
                            _ => {}
                        }
                        continue;
                    }
                    packet.as_mut_slice()[1] = ttl - 1;
                } else {
                    // Reverse controls carry sender distance, incremented at every
                    // upstream hop. Their AEAD authenticates the actual sender.
                    let Some(distance) = ttl.checked_add(1) else {
                        continue;
                    };
                    packet.as_mut_slice()[1] = distance;
                }
                packet.as_mut_slice()[2..6].copy_from_slice(&cid.raw().to_be_bytes());
            } else {
                continue;
            }
            match destination.send(packet).await {
                Ok(()) | Err(CoreErr::WouldBlock) => {}
                Err(CoreErr::MtuTooSmall(mtu)) => self.report_mtu(mtu, &mut last_hint).await?,
                Err(error) => return Err(error),
            }
        }
    }

    async fn report_mtu(
        &self,
        mtu: u16,
        previous: &mut Option<tokio::time::Instant>,
    ) -> Result<(), CoreErr> {
        if mtu < self.min_mtu {
            return Err(CoreErr::MtuTooSmall(mtu));
        }
        let now = tokio::time::Instant::now();
        if previous.is_none_or(|last| now.duration_since(last).as_millis() >= 200) {
            *previous = Some(now);
            self.left
                .send(control(
                    hop::DG_MTU_HINT,
                    0,
                    self.caller,
                    &mtu.to_be_bytes(),
                ))
                .await?;
        }
        Ok(())
    }
}

pub(crate) async fn mtu_changed(watch: &mut watch::Receiver<u16>) {
    if watch.changed().await.is_err() {
        std::future::pending::<()>().await;
    }
}
