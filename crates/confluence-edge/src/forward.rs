use confluence_core::{CoreErr, PacketBuf, PublicKey, ScopeInstance};
use parking_lot::Mutex;
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Notify,
    task::JoinSet,
};

const MAX_FLOWS: usize = 1024;
const QUEUE_PACKETS: usize = 16;
const QUEUE_BYTES: usize = 16 * 1024;
const IDLE: Duration = Duration::from_secs(90);

#[derive(Clone, Debug)]
pub struct Destination {
    pub peer: PublicKey,
    pub endpoint: String,
}

/// Forwards each locally accepted TCP socket through a separate E2E stream.
pub async fn serve_local_tcp(
    listener: TcpListener,
    scope: ScopeInstance,
    destination: Destination,
) -> Result<(), CoreErr> {
    let destination = Arc::new(destination);
    let mut flows = JoinSet::new();
    loop {
        tokio::select! {
            joined = flows.join_next(), if !flows.is_empty() => { let _ = joined; }
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(confluence_net::connect_error)?;
                if flows.len() < MAX_FLOWS {
                    flows.spawn(tcp_flow(stream, scope.clone(), destination.clone()));
                }
            }
        }
    }
}
async fn tcp_flow(
    stream: TcpStream,
    scope: ScopeInstance,
    dst: Arc<Destination>,
) -> Result<(), CoreErr> {
    let tunnel = scope.dial_stream(dst.peer, &dst.endpoint).await?;
    let (mut local_read, mut local_write) = stream.into_split();
    let to_remote = async {
        let mut buf = vec![0; tunnel.max_write_size()];
        loop {
            let count = local_read
                .read(&mut buf)
                .await
                .map_err(confluence_net::connect_error)?;
            if count == 0 {
                return tunnel.shutdown().await;
            }
            tunnel.write_all(&buf[..count]).await?;
        }
    };
    let to_local = async {
        let mut buf = vec![0; tunnel.max_write_size()];
        loop {
            let count = tunnel.read(&mut buf).await?;
            if count == 0 {
                return local_write
                    .shutdown()
                    .await
                    .map_err(confluence_net::connect_error);
            }
            local_write
                .write_all(&buf[..count])
                .await
                .map_err(confluence_net::connect_error)?;
        }
    };
    tokio::try_join!(to_remote, to_local)?;
    Ok(())
}

/// Forwards each UDP source address through one datagram circuit. The same
/// bounded, tail-drop ring is used during setup and active forwarding.
pub async fn serve_local_udp(
    socket: UdpSocket,
    scope: ScopeInstance,
    destination: Destination,
    min_mtu: u16,
) -> Result<(), CoreErr> {
    let socket = Arc::new(socket);
    let destination = Arc::new(destination);
    let mut buf = vec![0; u16::MAX as usize + 1];
    let mut flows = JoinSet::new();
    let mut clients = HashMap::<SocketAddr, Arc<Queue>>::new();
    loop {
        tokio::select! {
            joined = flows.join_next(), if !flows.is_empty() => {
                if let Some(Ok((address, completed))) = joined
                    && clients.get(&address).is_some_and(|flow| Arc::ptr_eq(flow, &completed)) {
                    clients.remove(&address);
                }
                clients.retain(|_, queue| !queue.state.lock().closed);
            }
            incoming = socket.recv_from(&mut buf) => {
                let (length, address) = incoming.map_err(confluence_net::connect_error)?;
                if length > u16::MAX as usize { continue; }
                if let Some(queue) = clients.get(&address) && queue.push(&buf[..length]) { continue; }
                if length > QUEUE_BYTES || flows.len() >= MAX_FLOWS { continue; }
                let queue = Arc::new(Queue::default());
                queue.push(&buf[..length]);
                clients.insert(address, queue.clone());
                let (socket, scope, dst) = (socket.clone(), scope.clone(), destination.clone());
                flows.spawn(async move {
                    let closed = CloseQueue(queue.clone());
                    let _ = udp_flow(&socket, address, &scope, &dst, min_mtu, &queue).await;
                    drop(closed);
                    (address, queue)
                });
            }
        }
    }
}
async fn udp_flow(
    socket: &UdpSocket,
    local: SocketAddr,
    scope: &ScopeInstance,
    dst: &Destination,
    min_mtu: u16,
    queue: &Queue,
) -> Result<(), CoreErr> {
    let tunnel = scope
        .dial_datagram(dst.peer, &dst.endpoint, min_mtu)
        .await?;
    queue.state.lock().active = true;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(IDLE) => return Ok(()),
            outbound = queue.next() => {
                match tokio::time::timeout(IDLE, tunnel.send_wait(outbound)).await {
                    Ok(Ok(()) | Err(CoreErr::MessageTooLarge(_))) => {},
                    Ok(Err(error)) => return Err(error),
                    Err(_) => return Ok(()),
                }
            }
            inbound = tunnel.recv() => {
                let packet = inbound?;
                match tokio::time::timeout(IDLE, socket.send_to(packet.as_slice(), local)).await {
                    Ok(result) => { result.map_err(confluence_net::connect_error)?; }
                    Err(_) => return Ok(()),
                }
            }
        }
    }
}

#[derive(Default)]
struct Queue {
    state: Mutex<Staging>,
    available: Notify,
}
#[derive(Default)]
struct Staging {
    packets: VecDeque<PacketBuf>,
    bytes: usize,
    active: bool,
    closed: bool,
}
impl Queue {
    /// True also means a live full queue tail-dropped the incoming datagram.
    fn push(&self, payload: &[u8]) -> bool {
        let mut state = self.state.lock();
        if state.closed {
            return false;
        }
        if state.packets.len() < QUEUE_PACKETS
            && (state.active || state.bytes + payload.len() <= QUEUE_BYTES)
        {
            state.packets.push_back(PacketBuf::from_slice(payload));
            state.bytes += payload.len();
            self.available.notify_one();
        }
        true
    }
    async fn next(&self) -> PacketBuf {
        loop {
            let wake = self.available.notified();
            {
                let mut state = self.state.lock();
                if let Some(packet) = state.packets.pop_front() {
                    state.bytes -= packet.len();
                    return packet;
                }
            }
            wake.await;
        }
    }
}
struct CloseQueue(Arc<Queue>);
impl Drop for CloseQueue {
    fn drop(&mut self) {
        self.0.state.lock().closed = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn staging_is_fifo_and_tail_drops_by_bytes_or_packets() {
        let queue = Queue::default();
        queue.push(&vec![1; QUEUE_BYTES - 1]);
        queue.push(&[2, 2]);
        queue.push(&[3]);
        assert_eq!(queue.next().await.len(), QUEUE_BYTES - 1);
        assert_eq!(queue.next().await.as_slice(), &[3]);

        for value in 0..=QUEUE_PACKETS {
            queue.push(&[value as u8]);
        }
        for value in 0..QUEUE_PACKETS {
            assert_eq!(queue.next().await.as_slice(), &[value as u8]);
        }
        assert!(queue.state.lock().packets.is_empty());
        queue.state.lock().active = true;
        queue.push(&vec![4; QUEUE_BYTES + 1]);
        assert_eq!(queue.next().await.len(), QUEUE_BYTES + 1);
    }
}
