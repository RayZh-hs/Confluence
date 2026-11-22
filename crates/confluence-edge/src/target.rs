use confluence_core::{
    AsyncStream, BoxFut, ChannelCaps, CoreErr, DatagramEndpointHandler, DatagramLink, PacketBuf,
    PublicKey, STREAM_CHUNK, StreamEndpointHandler,
};
use confluence_net::{TcpIo, connect_error};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::{TcpStream, UdpSocket};

/// Opens the local TCP service only when the Core calls the confirmed handler.
pub struct TcpTarget(pub SocketAddr);
impl StreamEndpointHandler for TcpTarget {
    fn open(&self, _peer: PublicKey) -> BoxFut<'_, Result<Box<dyn AsyncStream>, CoreErr>> {
        Box::pin(async {
            let socket = TcpStream::connect(self.0).await.map_err(connect_error)?;
            Ok(Box::new(TcpIo::new(socket, STREAM_CHUNK as u16)?) as Box<dyn AsyncStream>)
        })
    }
}
pub struct UdpTarget(pub SocketAddr);
impl DatagramEndpointHandler for UdpTarget {
    fn open(&self, _peer: PublicKey) -> BoxFut<'_, Result<Arc<dyn DatagramLink>, CoreErr>> {
        Box::pin(async {
            let local = if self.0.is_ipv4() {
                SocketAddr::from(([0; 4], 0))
            } else {
                SocketAddr::from(([0; 8], 0))
            };
            let socket = UdpSocket::bind(local).await.map_err(connect_error)?;
            socket.connect(self.0).await.map_err(connect_error)?;
            Ok(Arc::new(LocalDatagrams(socket)) as Arc<dyn DatagramLink>)
        })
    }
}
struct LocalDatagrams(UdpSocket);
impl DatagramLink for LocalDatagrams {
    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(u16::MAX, false)
    }
    fn send(&self, packet: PacketBuf) -> BoxFut<'_, Result<(), CoreErr>> {
        Box::pin(async move {
            let sent = self
                .0
                .send(packet.as_slice())
                .await
                .map_err(connect_error)?;
            if sent == packet.len() {
                Ok(())
            } else {
                Err(CoreErr::Carrier("short UDP send".into()))
            }
        })
    }
    fn recv(&self) -> BoxFut<'_, Result<PacketBuf, CoreErr>> {
        Box::pin(async {
            let mut packet = PacketBuf::with_payload_cap(u16::MAX as usize);
            let n = self
                .0
                .recv(packet.spare_payload())
                .await
                .map_err(connect_error)?;
            packet.advance_payload(n);
            Ok(packet)
        })
    }
}
