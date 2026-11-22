#![forbid(unsafe_code)]

#[cfg(unix)]
pub mod admin;
mod forward;
mod target;

pub use forward::{Destination, serve_local_tcp, serve_local_udp};
pub use target::{TcpTarget, UdpTarget};
