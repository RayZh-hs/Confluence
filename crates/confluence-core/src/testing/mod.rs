//! Deterministic testing utilities (`VirtualClock`, `FixedWallClock`, `TestSpawner`,
//! and controllable in-memory Stream/Datagram channels).
//!
//! Available in crate unit/integration tests and when compiled with the `test-support` feature.

pub mod channel;
pub mod clock;

pub use channel::{
    DatagramFaults, MemoryDatagramCarrier, MemoryDatagramLink, MemoryDatagramListener,
    MemoryDatagramPair, MemoryStream, MemoryStreamCarrier, MemoryStreamListener, MemoryStreamPair,
    MemoryStreamRead, MemoryStreamWrite, StreamFaults, memory_datagram_channel,
    memory_stream_channel,
};
pub use clock::{FixedWallClock, TestRuntime, TestSpawner, VirtualClock};
