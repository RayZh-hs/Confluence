//! Datagram Plane Engine: `DatagramPort` multiplexer, inbound setup dispatcher,
//! 1.0 RTT Destination `serve`, zero-copy Transit switcher, and `E2eDatagram` sessions.

pub(crate) mod inbound;
pub(crate) mod port;
pub(crate) mod serve;
pub(crate) mod session;
pub(crate) mod transit;
