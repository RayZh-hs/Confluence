#![forbid(unsafe_code)]
//! Standalone Passive Relay channel plugin (`RelayDatagramChannel` & `RelayStreamChannel`)
//! plus passive presence registration clients (`RelayDatagramClient` & `RelayIngressStreamChannel`).
//!
//! Upholds Cleanroom Invariant #5: the relay server components hold **zero** outbound dialer
//! capability and forward exclusively to authenticated passive slots registered inbound by `B`.

pub mod datagram;
pub mod stream;

pub use datagram::{RelayDatagramChannel, RelayDatagramClient};
pub use stream::{RelayIngressStreamChannel, RelayStreamChannel};
