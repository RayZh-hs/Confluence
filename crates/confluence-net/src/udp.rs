use confluence_core::{
    ChannelCaps, CoreErr, DATAGRAM_MTU, DatagramChannel, DatagramIngress, DatagramLink, Node,
    PacketBuf, ScopeInstance, wire::setup,
};
use parking_lot::Mutex as SyncMutex;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, watch},
    time::Instant,
};

use super::{connect_error, io_error, locator, source_tag_for_addr};

const MAX_PEERS: usize = 1024;
const MAX_PROVISIONAL: usize = 64;
const PEER_QUEUE: usize = 16;
const PROVISIONAL_PACKETS: u8 = 8;
const IDLE: Duration = Duration::from_secs(120);
const PROVISIONAL_TTL: Duration = Duration::from_secs(3);
const MAX_WIRE_DATAGRAM: usize = u16::MAX as usize + 1;

/// Pure native UDP Datagram carrier with `DF=1` PMTU discovery on Linux (Seam 1B).
#[derive(Clone)]
pub struct UdpCarrier {
    mtu: u16,
    links: Arc<SyncMutex<HashMap<SocketAddr, Weak<UdpLink>>>>,
}

impl UdpCarrier {
    pub fn new(mtu: u16) -> Result<Self, CoreErr> {
        if mtu < DATAGRAM_MTU {
            return Err(CoreErr::MtuTooSmall(mtu));
        }
        Ok(Self {
            mtu,
            links: Default::default(),
        })
    }

    pub async fn connect_from(
        &self,
        local: SocketAddr,
        peer: SocketAddr,
    ) -> Result<Arc<UdpLink>, CoreErr> {
        if local.is_ipv4() != peer.is_ipv4() {
            return Err(CoreErr::Malformed);
        }
        let socket = socket(local)?;
        socket.connect(peer).await.map_err(connect_error)?;
        Ok(Arc::new(UdpLink::connected(socket, peer, self.mtu)))
    }

    pub fn bind(&self, addr: SocketAddr) -> Result<UdpIngress, CoreErr> {
        Ok(UdpIngress {
            socket: Arc::new(socket(addr)?),
            mtu: self.mtu,
            max_peers: MAX_PEERS,
            max_provisional: MAX_PROVISIONAL,
        })
    }
}

impl DatagramChannel for UdpCarrier {
    type Link = Arc<UdpLink>;

    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(self.mtu, false)
    }

    async fn open_link(&self, bytes: &[u8]) -> Result<Arc<UdpLink>, CoreErr> {
        let peer = locator(bytes)?;
        {
            let links = self.links.lock();
            if let Some(existing) = links
                .get(&peer)
                .and_then(Weak::upgrade)
                .filter(|link| link.caps().mtu() >= DATAGRAM_MTU)
            {
                return Ok(existing);
            }
        }
        let local = if peer.is_ipv4() {
            SocketAddr::from(([0; 4], 0))
        } else {
            SocketAddr::from(([0; 8], 0))
        };
        let created = self.connect_from(local, peer).await?;
        let mut links = self.links.lock();
        if links.len() >= 128 {
            links.retain(|_, link| link.strong_count() != 0);
        }
        if let Some(existing) = links
            .get(&peer)
            .and_then(Weak::upgrade)
            .filter(|link| link.caps().mtu() >= DATAGRAM_MTU)
        {
            return Ok(existing);
        }
        links.insert(peer, Arc::downgrade(&created));
        Ok(created)
    }
}

fn socket(addr: SocketAddr) -> Result<UdpSocket, CoreErr> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))
        .map_err(io_error)?;
    if addr.is_ipv6() {
        socket.set_only_v6(true).map_err(io_error)?;
    }
    df::enable(&socket, addr.is_ipv6()).map_err(io_error)?;
    socket.set_nonblocking(true).map_err(io_error)?;
    socket.bind(&addr.into()).map_err(io_error)?;
    UdpSocket::from_std(socket.into()).map_err(io_error)
}

/// Per-peer UDP [`DatagramLink`] reporting live kernel PMTU shrinks via `mtu_watch`.
pub struct UdpLink {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    source_tag: [u8; 16],
    mtu: watch::Sender<u16>,
    incoming: Option<SyncMutex<mpsc::Receiver<PacketBuf>>>,
}

impl UdpLink {
    fn connected(socket: UdpSocket, peer: SocketAddr, mtu: u16) -> Self {
        Self {
            socket: Arc::new(socket),
            peer,
            source_tag: source_tag_for_addr(peer),
            mtu: watch::channel(mtu).0,
            incoming: None,
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr, CoreErr> {
        self.socket.local_addr().map_err(io_error)
    }

    fn send_error(&self, error: io::Error, len: usize) -> CoreErr {
        if error.raw_os_error() != Some(libc::EMSGSIZE) {
            return io_error(error);
        }
        let bound = len.saturating_sub(1) as u16;
        let limit = if self.incoming.is_none() {
            df::payload_limit(&self.socket, self.peer.is_ipv6()).map_or(bound, |mtu| mtu.min(bound))
        } else {
            bound
        };
        self.mtu.send_if_modified(|mtu| {
            if limit < *mtu {
                *mtu = limit;
                true
            } else {
                false
            }
        });
        CoreErr::MtuTooSmall(*self.mtu.borrow())
    }
}

impl DatagramLink for UdpLink {
    fn caps(&self) -> ChannelCaps {
        ChannelCaps::dynamic(self.mtu.subscribe(), false)
    }

    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), CoreErr>> {
        self.socket.poll_send_ready(cx).map_err(io_error)
    }

    fn try_send(&self, packet: PacketBuf) -> Result<(), CoreErr> {
        let ceiling = *self.mtu.borrow();
        if packet.len() > usize::from(ceiling) {
            return Err(CoreErr::MtuTooSmall(ceiling));
        }
        let result = if self.incoming.is_none() {
            self.socket.try_send(packet.as_slice())
        } else {
            self.socket.try_send_to(packet.as_slice(), self.peer)
        };
        match result {
            Ok(amount) if amount == packet.len() => Ok(()),
            Ok(_) => Err(CoreErr::Carrier("short UDP send".into())),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Err(CoreErr::WouldBlock),
            Err(error) => Err(self.send_error(error, packet.len())),
        }
    }

    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<PacketBuf, CoreErr>> {
        if let Some(queue) = &self.incoming {
            return queue
                .lock()
                .poll_recv(cx)
                .map(|opt| opt.ok_or(CoreErr::Closed));
        }
        loop {
            match self.socket.poll_recv_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(io_error(error))),
                Poll::Ready(Ok(())) => {}
            }
            let ceiling = usize::from(*self.mtu.borrow());
            let mut packet = PacketBuf::with_payload_cap(ceiling + 1);
            match self.socket.try_recv(packet.spare_payload()) {
                Ok(count) => {
                    if count <= ceiling {
                        packet.advance_payload(count);
                        return Poll::Ready(Ok(packet));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) if error.raw_os_error() == Some(libc::EMSGSIZE) => {
                    if let Some(mtu) = df::payload_limit(&self.socket, self.peer.is_ipv6()) {
                        self.mtu.send_if_modified(|current| {
                            let changed = mtu < *current;
                            *current = (*current).min(mtu);
                            changed
                        });
                    }
                }
                Err(error) => return Poll::Ready(Err(io_error(error))),
            }
        }
    }

    fn source_tag(&self) -> [u8; 16] {
        self.source_tag
    }
}

/// Shared UDP ingress demultiplexing peers into bounded provisional and admitted per-peer links.
pub struct UdpIngress {
    socket: Arc<UdpSocket>,
    mtu: u16,
    max_peers: usize,
    max_provisional: usize,
}

struct Peer {
    queue: mpsc::Sender<PacketBuf>,
    _dispatcher: DatagramIngress,
    last_seen: Instant,
}

struct ProvisionalPeer {
    queue: mpsc::Sender<PacketBuf>,
    dispatcher: DatagramIngress,
    extra_admitted: Option<Arc<AtomicBool>>,
    created: Instant,
    forwarded: u8,
}

impl ProvisionalPeer {
    fn is_admitted(&self) -> bool {
        self.dispatcher.is_admitted()
            || self
                .extra_admitted
                .as_ref()
                .is_some_and(|flag| flag.load(Ordering::Acquire))
    }
}

/// Result returned by a custom transport-mux attach callback in [`UdpIngress::serve_custom`].
pub struct CustomUdpAttachment {
    pub ingress: DatagramIngress,
    /// Optional out-of-core admission signal (e.g., an authenticated transport-layer control
    /// handshake) that promotes a provisional UDP peer into the long-lived peer table.
    pub extra_admitted: Option<Arc<AtomicBool>>,
}

impl UdpIngress {
    pub fn local_addr(&self) -> Result<SocketAddr, CoreErr> {
        self.socket.local_addr().map_err(io_error)
    }

    pub fn with_limits(mut self, max_peers: usize, max_provisional: usize) -> Self {
        self.max_peers = max_peers.max(1);
        self.max_provisional = max_provisional.max(1);
        self
    }

    fn reconcile(
        max_peers: usize,
        peers: &mut HashMap<SocketAddr, Peer>,
        provisional: &mut HashMap<SocketAddr, ProvisionalPeer>,
        now: Instant,
    ) {
        peers
            .retain(|_, peer| now.duration_since(peer.last_seen) < IDLE && !peer.queue.is_closed());
        let promoted: Vec<_> = provisional
            .iter()
            .filter_map(|(addr, entry)| entry.is_admitted().then_some(*addr))
            .collect();
        for addr in promoted {
            if let Some(entry) = provisional.remove(&addr)
                && peers.len() < max_peers
                && !entry.queue.is_closed()
            {
                peers.insert(
                    addr,
                    Peer {
                        queue: entry.queue,
                        _dispatcher: entry.dispatcher,
                        last_seen: now,
                    },
                );
            }
        }
        provisional.retain(|_, entry| {
            !entry.dispatcher.is_rejected()
                && !entry.queue.is_closed()
                && now.duration_since(entry.created) < PROVISIONAL_TTL
        });
    }

    /// Serves this bound UDP socket into a single [`ScopeInstance`].
    pub async fn serve(self, scope: ScopeInstance) -> Result<(), CoreErr> {
        let pre = scope.clone();
        self.serve_custom(
            move |pkt| pkt[0] == setup::FWD && pre.precheck_datagram_setup(pkt),
            move |link| {
                Ok(CustomUdpAttachment {
                    ingress: scope.attach_datagram(link)?,
                    extra_admitted: None,
                })
            },
        )
        .await
    }

    /// Serves this bound UDP socket into a multi-scope [`Node`].
    pub async fn serve_node(self, node: Node) -> Result<(), CoreErr> {
        let pre = node.clone();
        self.serve_custom(
            move |pkt| pkt[0] == setup::FWD && pre.precheck_datagram_setup(pkt),
            move |link| {
                Ok(CustomUdpAttachment {
                    ingress: node.attach_datagram(link)?,
                    extra_admitted: None,
                })
            },
        )
        .await
    }

    /// Serves this bound UDP socket with custom opening-packet precheck and link-attachment hooks,
    /// enabling out-of-core transport multiplexers (e.g., passive relay registration) to share a
    /// single UDP port cleanly without adding protocol frames to `confluence-core`.
    pub async fn serve_custom<FPre, FAttach>(
        self,
        is_opening_packet: FPre,
        attach: FAttach,
    ) -> Result<(), CoreErr>
    where
        FPre: Fn(&[u8]) -> bool,
        FAttach: Fn(Arc<UdpLink>) -> Result<CustomUdpAttachment, CoreErr>,
    {
        let mut peers = HashMap::<SocketAddr, Peer>::new();
        let mut provisional = HashMap::<SocketAddr, ProvisionalPeer>::new();
        let mut reap = tokio::time::interval(Duration::from_secs(1));
        let mut receive = vec![0; MAX_WIRE_DATAGRAM];
        loop {
            let (size, address) = tokio::select! {
                _ = reap.tick() => {
                    Self::reconcile(self.max_peers, &mut peers, &mut provisional, Instant::now());
                    continue;
                }
                received = self.socket.recv_from(&mut receive) => received.map_err(io_error)?,
            };
            if size > usize::from(self.mtu) || size == 0 {
                continue;
            }
            let now = Instant::now();
            if let Some(peer) = peers.get_mut(&address) {
                peer.last_seen = now;
                let _ = peer.queue.try_send(PacketBuf::from_slice(&receive[..size]));
                continue;
            }
            if let Some(entry) = provisional.get_mut(&address) {
                if entry.is_admitted() {
                    let entry = provisional.remove(&address).unwrap();
                    if peers.len() < self.max_peers && !entry.queue.is_closed() {
                        let _ = entry
                            .queue
                            .try_send(PacketBuf::from_slice(&receive[..size]));
                        peers.insert(
                            address,
                            Peer {
                                queue: entry.queue,
                                _dispatcher: entry.dispatcher,
                                last_seen: now,
                            },
                        );
                    }
                    continue;
                }
                if entry.dispatcher.is_rejected()
                    || entry.queue.is_closed()
                    || now.duration_since(entry.created) >= PROVISIONAL_TTL
                {
                    provisional.remove(&address);
                } else {
                    if entry.forwarded < PROVISIONAL_PACKETS {
                        entry.forwarded += 1;
                        let _ = entry
                            .queue
                            .try_send(PacketBuf::from_slice(&receive[..size]));
                    }
                    continue;
                }
            }
            if !is_opening_packet(&receive[..size]) {
                continue;
            }
            if provisional.len() >= self.max_provisional || peers.len() >= self.max_peers {
                Self::reconcile(self.max_peers, &mut peers, &mut provisional, now);
            }
            if peers.len() < self.max_peers && provisional.len() < self.max_provisional {
                let (queue, incoming) = mpsc::channel(PEER_QUEUE);
                let link = Arc::new(UdpLink {
                    socket: self.socket.clone(),
                    peer: address,
                    source_tag: source_tag_for_addr(address),
                    mtu: watch::channel(self.mtu).0,
                    incoming: Some(SyncMutex::new(incoming)),
                });
                if let Ok(attached) = attach(link) {
                    let _ = queue.try_send(PacketBuf::from_slice(&receive[..size]));
                    provisional.insert(
                        address,
                        ProvisionalPeer {
                            queue,
                            dispatcher: attached.ingress,
                            extra_admitted: attached.extra_admitted,
                            created: now,
                            forwarded: 1,
                        },
                    );
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod df {
    use std::{
        io,
        mem::{self, size_of},
        os::fd::AsRawFd,
    };

    pub fn enable(socket: &socket2::Socket, ipv6: bool) -> io::Result<()> {
        let (level, option, value) = if ipv6 {
            (libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG, 1)
        } else {
            (
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                libc::IP_PMTUDISC_DO,
            )
        };
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                option,
                (&raw const value).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn payload_limit(socket: &tokio::net::UdpSocket, ipv6: bool) -> Option<u16> {
        let (level, option, overhead) = if ipv6 {
            (libc::IPPROTO_IPV6, libc::IPV6_MTU, 48)
        } else {
            (libc::IPPROTO_IP, libc::IP_MTU, 28)
        };
        let mut mtu: libc::c_int = 0;
        let mut len = size_of::<libc::c_int>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                level,
                option,
                (&raw mut mtu).cast(),
                &mut len,
            )
        };
        if result != 0 || len as usize != mem::size_of_val(&mtu) || mtu < overhead {
            return None;
        }
        let protocol_limit = if ipv6 { 65_527 } else { 65_507 };
        Some((mtu - overhead).min(protocol_limit) as u16)
    }
}

#[cfg(not(target_os = "linux"))]
mod df {
    use std::io;
    pub fn enable(_socket: &socket2::Socket, _ipv6: bool) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native DF UDP is implemented for Linux",
        ))
    }
    pub fn payload_limit(_socket: &tokio::net::UdpSocket, _ipv6: bool) -> Option<u16> {
        None
    }
}
