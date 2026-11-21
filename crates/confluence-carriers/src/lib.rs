#![forbid(unsafe_code)]
//! Native UDP/TCP transport carriers (`UdpDatagramChannel`, `TcpStreamChannel`) and composable
//! vertical channel middleware (`NoiseAclDatagramChannel`, `NoiseAclStreamChannel`) implementing Seam 1.

pub mod noise_acl;
pub mod tcp;
pub mod udp;

pub use noise_acl::{NoiseAclDatagramChannel, NoiseAclStreamChannel};
pub use tcp::TcpStreamChannel;
pub use udp::UdpDatagramChannel;
