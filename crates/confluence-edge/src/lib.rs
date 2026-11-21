#![forbid(unsafe_code)]
//! Local TCP and UDP port-forward Edge Adapters implementing Confluence Seam 4.
//!
//! Projects Confluence's Stream Plane onto local TCP sockets and Datagram Plane onto local UDP
//! sockets without application-protocol parsing or cross-plane conversion.

pub mod tcp;
pub mod udp;

pub use tcp::{TcpInboundForwarder, TcpOutboundForwarder};
pub use udp::{UdpInboundForwarder, UdpOutboundForwarder};
