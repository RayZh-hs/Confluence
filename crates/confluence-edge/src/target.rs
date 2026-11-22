use confluence_core::{
    ChannelCaps, CoreErr, DatagramEndpointHandler, DatagramLink, PacketBuf, STREAM_CHUNK,
    SessionAuth, StreamEndpointHandler,
};
use confluence_net::{TcpIo, connect_error};
use std::{
    io,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::net::{TcpStream, UdpSocket};

/// Opens the local TCP service only when the Core calls the confirmed handler.
pub struct TcpTarget(pub SocketAddr);

impl StreamEndpointHandler for TcpTarget {
    type Stream = TcpIo;

    async fn open(&self, _auth: SessionAuth) -> Result<TcpIo, CoreErr> {
        let socket = TcpStream::connect(self.0).await.map_err(connect_error)?;
        TcpIo::new(socket, STREAM_CHUNK as u16)
    }
}

/// Opens a connected local UDP socket to the target service once confirmed.
pub struct UdpTarget(pub SocketAddr);

impl DatagramEndpointHandler for UdpTarget {
    type Link = Arc<LocalDatagrams>;

    async fn open(&self, _auth: SessionAuth) -> Result<Arc<LocalDatagrams>, CoreErr> {
        let local = if self.0.is_ipv4() {
            SocketAddr::from(([0; 4], 0))
        } else {
            SocketAddr::from(([0; 8], 0))
        };
        let socket = UdpSocket::bind(local).await.map_err(connect_error)?;
        socket.connect(self.0).await.map_err(connect_error)?;
        Ok(Arc::new(LocalDatagrams(socket)))
    }
}

/// Poll-based [`DatagramLink`] backed by a connected local [`UdpSocket`].
pub struct LocalDatagrams(UdpSocket);

impl DatagramLink for LocalDatagrams {
    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(u16::MAX, false)
    }

    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), CoreErr>> {
        self.0.poll_send_ready(cx).map_err(connect_error)
    }

    fn try_send(&self, packet: PacketBuf) -> Result<(), CoreErr> {
        match self.0.try_send(packet.as_slice()) {
            Ok(sent) if sent == packet.len() => Ok(()),
            Ok(_) => Err(CoreErr::Carrier("short local UDP send".into())),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Err(CoreErr::WouldBlock),
            Err(err) => Err(connect_error(err)),
        }
    }

    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<PacketBuf, CoreErr>> {
        loop {
            match self.0.poll_recv_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(connect_error(err))),
                Poll::Ready(Ok(())) => {}
            }
            let mut packet = PacketBuf::with_payload_cap(u16::MAX as usize);
            match self.0.try_recv(packet.spare_payload()) {
                Ok(n) => {
                    packet.advance_payload(n);
                    return Poll::Ready(Ok(packet));
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(err) => return Poll::Ready(Err(connect_error(err))),
            }
        }
    }
}
