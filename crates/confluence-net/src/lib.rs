//! Pure native OS carriers: TCP streams and Linux `DF=1` UDP datagrams.

mod tcp;
mod udp;

pub use tcp::{
    TcpCarrier, TcpIo, TcpListenerSource, TcpReadHalf, TcpWriteHalf, serve_tcp, serve_tcp_node,
};
pub use udp::{CustomUdpAttachment, UdpCarrier, UdpIngress, UdpLink};

use confluence_core::CoreErr;
use std::{
    io,
    net::{IpAddr, SocketAddr},
};

fn locator(bytes: &[u8]) -> Result<SocketAddr, CoreErr> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|address| address.parse().ok())
        .ok_or(CoreErr::Malformed)
}

fn source_tag_for_ip(ip: IpAddr) -> [u8; 16] {
    let mut h = blake3::Hasher::new();
    match ip {
        IpAddr::V4(v4) => {
            h.update(&[4]);
            h.update(&v4.octets());
        }
        IpAddr::V6(v6) => {
            h.update(&[6]);
            h.update(&v6.octets());
        }
    }
    h.finalize().as_bytes()[..16]
        .try_into()
        .expect("blake3 output is 32 bytes")
}

fn source_tag_for_addr(addr: SocketAddr) -> [u8; 16] {
    let mut h = blake3::Hasher::new();
    match addr {
        SocketAddr::V4(v4) => {
            h.update(&[4]);
            h.update(&v4.ip().octets());
            h.update(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            h.update(&[6]);
            h.update(&v6.ip().octets());
            h.update(&v6.port().to_be_bytes());
        }
    }
    h.finalize().as_bytes()[..16]
        .try_into()
        .expect("blake3 output is 32 bytes")
}

fn io_error(error: io::Error) -> CoreErr {
    match error.kind() {
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::BrokenPipe => CoreErr::UnexpectedEof,
        _ => CoreErr::Carrier(error.to_string()),
    }
}

pub fn connect_error(error: io::Error) -> CoreErr {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => CoreErr::TargetRefused,
        io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::TimedOut => CoreErr::TargetUnreachable,
        _ => io_error(error),
    }
}
