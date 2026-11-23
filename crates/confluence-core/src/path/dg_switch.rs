use parking_lot::Mutex;
use std::{
    collections::HashMap,
    num::NonZeroUsize,
    sync::{
        Arc, Weak,
        atomic::{AtomicU8, Ordering},
    },
};
use tokio::sync::{OwnedSemaphorePermit, mpsc, watch};

use super::{
    best_effort,
    inbound::{self, HopSession},
};
use crate::{
    CoreErr, DatagramAction, DatagramLink, DatagramLinkExt, Direction, LinkId, MtuWatch, PacketBuf,
    Plane, ScopeKid,
    cid::{Cid, SlabTable},
    crypto::aead::ControlCipher,
    node::NodeInner,
    scope::Scope,
    wire::{e2e, hop, setup, u16_at},
};

const MAILBOX: NonZeroUsize = NonZeroUsize::new(32).unwrap();
const ADMISSION_PENDING: u8 = 0;
const ADMISSION_ACCEPTED: u8 = 1;
const ADMISSION_REJECTED: u8 = 2;

#[derive(Default)]
struct Ingress {
    node: Weak<NodeInner>,
    node_wide: bool,
    scopes: HashMap<ScopeKid, Weak<Scope>>,
}

impl Ingress {
    fn allow_scope(&mut self, scope: &Arc<Scope>) {
        let kid = scope.identity.kid();
        if self.scopes.len() >= 32 && !self.scopes.contains_key(&kid) {
            self.scopes.retain(|_, scope| scope.strong_count() != 0);
        }
        self.scopes.insert(kid, Arc::downgrade(scope));
    }
}

pub(crate) fn datagram_setup(wire: &[u8]) -> Option<(ScopeKid, setup::Segment<'_>)> {
    let hdr = setup::ForwardHeader::parse(wire).ok()?;
    if hdr.upstream == Cid::UNBOUND {
        return None;
    }
    let segment = setup::Segment::parse(&wire[setup::FWD_HEADER..]).ok()?;
    if segment.plane != Plane::Datagram {
        return None;
    }
    let kid = ScopeKid(segment.encrypted.get(..8)?.try_into().ok()?);
    Some((kid, segment))
}

fn reserve_port(
    ports: &mut HashMap<LinkId, Weak<DatagramPort>>,
    limit: usize,
) -> Result<(), CoreErr> {
    if ports.len() >= limit.min(256) {
        ports.retain(|_, port| port.strong_count() != 0);
    }
    if ports.len() >= limit {
        return Err(CoreErr::Busy);
    }
    Ok(())
}

pub(crate) struct DatagramPort {
    pub link: Arc<dyn DatagramLink>,
    pub mtu: MtuWatch,
    slots: Mutex<SlabTable<mpsc::Sender<PacketBuf>>>,
    ingress: Mutex<Ingress>,
    gone: watch::Sender<Option<CoreErr>>,
    admission: AtomicU8,
    _stop: watch::Sender<()>,
}

impl DatagramPort {
    pub fn attach_scope(
        scope: &Arc<Scope>,
        link: Arc<dyn DatagramLink>,
    ) -> Result<Arc<Self>, CoreErr> {
        let id = link.link_id();
        // Mount, unmount, and attachment take these locks in the same order.
        let membership = scope.node.lock();
        let mut ports = scope.datagram_ports.lock();
        if let Some(port) = ports.get(&id).and_then(Weak::upgrade) {
            port.ingress.lock().allow_scope(scope);
            return Ok(port);
        }
        reserve_port(&mut ports, scope.max_datagram_ports)?;
        let port = if let Some(node) = membership.as_ref().and_then(Weak::upgrade) {
            Self::attach_on_node(&node, link, Some(scope))?
        } else {
            let mut ingress = Ingress::default();
            ingress.allow_scope(scope);
            Self::spawn(link, &*scope.tasks, ingress)
        };
        ports.insert(id, Arc::downgrade(&port));
        Ok(port)
    }

    pub fn attach_node(
        node: &Arc<NodeInner>,
        link: Arc<dyn DatagramLink>,
    ) -> Result<Arc<Self>, CoreErr> {
        Self::attach_on_node(node, link, None)
    }

    fn attach_on_node(
        node: &Arc<NodeInner>,
        link: Arc<dyn DatagramLink>,
        scope: Option<&Arc<Scope>>,
    ) -> Result<Arc<Self>, CoreErr> {
        let id = link.link_id();
        let mut ports = node.datagram_ports.lock();
        if let Some(port) = ports.get(&id).and_then(Weak::upgrade) {
            let mut ingress = port.ingress.lock();
            if let Some(scope) = scope {
                ingress.allow_scope(scope);
            } else {
                ingress.node_wide = true;
            }
            drop(ingress);
            return Ok(port);
        }

        reserve_port(&mut ports, node.max_datagram_ports)?;
        let mut ingress = Ingress {
            node: Arc::downgrade(node),
            node_wide: scope.is_none(),
            ..Ingress::default()
        };
        if let Some(scope) = scope {
            ingress.allow_scope(scope);
        }
        let port = Self::spawn(link, &*node.tasks, ingress);
        ports.insert(id, Arc::downgrade(&port));
        Ok(port)
    }

    // The caller holds the scope membership lock, so its standalone registry cannot
    // change while we validate and adopt all its live dispatchers.
    pub(crate) fn mount_scope(node: &Arc<NodeInner>, scope: &Arc<Scope>) -> Result<(), CoreErr> {
        let scoped = scope.datagram_ports.lock();
        let mut registry = node.datagram_ports.lock();
        let live: Vec<_> = scoped
            .iter()
            .filter_map(|(&id, port)| Some((id, port.upgrade()?)))
            .collect();
        if live.is_empty() {
            return Ok(());
        }
        registry.retain(|_, port| port.strong_count() != 0);
        let mut added = 0;
        for (id, port) in &live {
            if port
                .ingress
                .lock()
                .node
                .upgrade()
                .is_some_and(|owner| !Arc::ptr_eq(&owner, node))
            {
                return Err(CoreErr::AlreadyPublished);
            }
            match registry.get(id).and_then(Weak::upgrade) {
                Some(existing) if !Arc::ptr_eq(&existing, port) => {
                    return Err(CoreErr::AlreadyPublished);
                }
                Some(_) => {}
                None => added += 1,
            }
        }
        if added > node.max_datagram_ports.saturating_sub(registry.len()) {
            return Err(CoreErr::Busy);
        }
        let owner = Arc::downgrade(node);
        for (id, port) in live {
            let mut ingress = port.ingress.lock();
            if !ingress.node.ptr_eq(&owner) {
                ingress.node_wide = false;
                ingress.node = owner.clone();
            }
            ingress.allow_scope(scope);
            registry.insert(id, Arc::downgrade(&port));
        }
        Ok(())
    }

    pub(crate) fn unmount_scope(scope: &Arc<Scope>) {
        let kid = scope.identity.kid();
        for port in scope
            .datagram_ports
            .lock()
            .values()
            .filter_map(Weak::upgrade)
        {
            port.ingress.lock().scopes.remove(&kid);
        }
    }

    fn resolve_scope(&self, wire: &[u8]) -> Option<Arc<Scope>> {
        let (kid, segment) = datagram_setup(wire)?;
        let (scope, node) = {
            let ingress = self.ingress.lock();
            (
                ingress.scopes.get(&kid).and_then(Weak::upgrade),
                ingress.node_wide.then(|| ingress.node.upgrade()).flatten(),
            )
        };
        let scope = scope.or_else(|| node?.scope_by_kid(kid))?;
        scope
            .identity
            .verify_mac1_with_flag(segment.encrypted, segment.has_mac2)
            .then_some(scope)
    }

    fn spawn(
        link: Arc<dyn DatagramLink>,
        tasks: &dyn crate::TaskSpawner,
        ingress: Ingress,
    ) -> Arc<Self> {
        let (stop, mut stop_rx) = watch::channel(());
        let mtu = link.caps().mtu_watch;
        let port = Arc::new(Self {
            link: link.clone(),
            mtu,
            slots: Mutex::new(SlabTable::new(4096)),
            ingress: Mutex::new(ingress),
            gone: watch::channel(None).0,
            admission: AtomicU8::new(ADMISSION_PENDING),
            _stop: stop,
        });
        let weak_port = Arc::downgrade(&port);
        tasks.spawn(Box::pin(async move {
            loop {
                let packet = tokio::select! {
                    biased;
                    _ = stop_rx.changed() => return,
                    packet = link.recv() => packet,
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
                if packet.len() > usize::from(port.mtu.mtu()) {
                    continue;
                }
                let Some(cid) = hop::route_cid(packet.as_slice()) else {
                    continue;
                };
                if cid == Cid::UNBOUND {
                    if packet.as_slice()[0] != setup::FWD {
                        continue;
                    }
                    let Some(scope) = port.resolve_scope(packet.as_slice()) else {
                        continue;
                    };
                    let Ok(permit) = scope.pending.clone().try_acquire_owned() else {
                        continue;
                    };
                    let spawner = scope.tasks.clone();
                    spawner.spawn(Box::pin(async move {
                        let _ = inbound::datagram(scope, port, packet, permit).await;
                    }));
                } else if let Some(queue) = port.slots.lock().get(cid) {
                    let _ = queue.try_send(packet);
                }
            }
        }));
        port
    }

    pub fn bind(self: &Arc<Self>) -> Result<Binding, CoreErr> {
        let (tx, rx) = mpsc::channel(MAILBOX.get());
        let cid = self.slots.lock().insert(tx).ok_or(CoreErr::Busy)?;
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
        self.port.slots.lock().remove(self.cid);
    }
}

impl Binding {
    pub async fn recv(&mut self) -> Result<PacketBuf, CoreErr> {
        tokio::select! {
            biased;
            error = self.port.closed() => Err(error),
            packet = self.rx.recv() => packet.ok_or(CoreErr::Closed),
        }
    }

    pub fn mtu(&self) -> u16 {
        self.port.mtu.mtu()
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
    pub auth: HopSession,
    pub _session: OwnedSemaphorePermit,
}

impl Transit {
    pub async fn run(mut self) -> Result<(), CoreErr> {
        self.auth.pending.take();
        let mut cipher = self.auth.hop_key.control(false);
        let lease = self.auth.lease.clone();
        let result = tokio::select! {
            error = lease.cancelled() => Err(error),
            res = self.pump(&mut cipher) => res,
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
        let mut left_mtu = self.left.port.mtu.clone();
        let mut right_mtu = self.right.port.mtu.clone();
        let mut last_hint = None;
        let mut renewal: Option<crate::BoxFut<'static, Result<[u8; 8], CoreErr>>> = None;
        let mut gate = self.auth.lease.gate_cache();

        loop {
            let (forward, mut packet) = tokio::select! {
                _ = mtu_changed(&mut left_mtu) => {
                    let mtu = left_mtu.mtu().min(right_mtu.mtu());
                    self.report_mtu(mtu, &mut last_hint).await?;
                    continue;
                }
                _ = mtu_changed(&mut right_mtu) => {
                    let mtu = left_mtu.mtu().min(right_mtu.mtu());
                    self.report_mtu(mtu, &mut last_hint).await?;
                    continue;
                }
                lease_wire = async { renewal.as_mut().unwrap().await }, if renewal.is_some() => {
                    renewal = None;
                    let body = cipher.seal(hop::DG_RENEW_OK, &lease_wire?)?;
                    self.left
                        .send(control(hop::DG_RENEW_OK, 0, self.caller, &body))
                        .await?;
                    continue;
                }
                pkt = self.left.recv() => (true, pkt?),
                pkt = self.right.recv() => (false, pkt?),
            };

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
                if !self.auth.lease.is_active() {
                    continue;
                }
                if let Some(active_gate) = gate.current(&self.auth.lease) {
                    let dir = if forward {
                        Direction::Ingress
                    } else {
                        Direction::Egress
                    };
                    match active_gate.check_datagram(dir, packet.len()) {
                        DatagramAction::Allow => {}
                        DatagramAction::Drop => continue,
                        DatagramAction::Close(err) => return Err(err),
                    }
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

pub(crate) async fn mtu_changed(watch: &mut MtuWatch) {
    if watch.changed().await.is_err() {
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BoxFut, ChannelCaps, Node, ScopeInstance, ScopeKeypair, TaskSpawner};

    struct NoTasks;

    impl TaskSpawner for NoTasks {
        fn spawn(&self, _task: BoxFut<'static, ()>) {}
    }

    struct SharedLink;

    impl DatagramLink for SharedLink {
        fn caps(&self) -> ChannelCaps {
            ChannelCaps::fixed(1500, false)
        }

        fn try_send(&self, _packet: PacketBuf) -> Result<(), CoreErr> {
            Ok(())
        }

        fn poll_recv(
            &self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<PacketBuf, CoreErr>> {
            std::task::Poll::Pending
        }
    }

    #[test]
    fn concurrent_first_attachments_share_one_port_and_cid_table() {
        let tasks = Arc::new(NoTasks);
        let node = Node::new(tasks.clone());
        let first = ScopeInstance::builder(ScopeKeypair::generate(), tasks.clone()).build();
        let second = ScopeInstance::builder(ScopeKeypair::generate(), tasks).build();
        node.add_scope(first.clone()).unwrap();
        node.add_scope(second.clone()).unwrap();
        let link: Arc<dyn DatagramLink> = Arc::new(SharedLink);
        let barrier = std::sync::Barrier::new(2);

        let (first_port, second_port) = std::thread::scope(|threads| {
            let first_attachment = threads.spawn(|| {
                barrier.wait();
                DatagramPort::attach_scope(&first.0, link.clone()).unwrap()
            });
            let second_attachment = threads.spawn(|| {
                barrier.wait();
                DatagramPort::attach_scope(&second.0, link.clone()).unwrap()
            });
            (
                first_attachment.join().unwrap(),
                second_attachment.join().unwrap(),
            )
        });

        assert!(Arc::ptr_eq(&first_port, &second_port));
        let first_circuit = first_port.bind().unwrap();
        let second_circuit = second_port.bind().unwrap();
        assert_ne!(first_circuit.cid, second_circuit.cid);
    }
}
