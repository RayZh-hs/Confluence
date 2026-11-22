mod tcp;
mod udp;

pub use tcp::{TcpCarrier, TcpIo, serve_tcp};
pub use udp::{UdpCarrier, UdpIngress, UdpLink};

use confluence_core::CoreErr;
use std::{io, net::SocketAddr};

fn locator(bytes: &[u8]) -> Result<SocketAddr, CoreErr> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|address| address.parse().ok())
        .ok_or(CoreErr::Malformed)
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
