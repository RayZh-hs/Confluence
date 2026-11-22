//! Edge Adapters (Seam 4): local TCP/UDP port forwarders, target handlers,
//! [`E2eStreamIo`] (`tokio::io::AsyncRead + AsyncWrite`), and explicit `0600` Unix admin IPC.

#![forbid(unsafe_code)]

#[cfg(unix)]
pub mod admin;
mod forward;
mod io;
mod target;

pub use forward::{Destination, serve_local_tcp, serve_local_udp};
pub use io::E2eStreamIo;
pub use target::{TcpTarget, UdpTarget};
