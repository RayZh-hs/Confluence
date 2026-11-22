use crate::error::{CoreError, Result};
use crate::types::PeerId;
use parking_lot::Mutex;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Standard TAI64 epoch offset (`2^62`).
const TAI64_EPOCH_OFFSET: u64 = 0x4000_0000_0000_0000;

/// 12-byte big-endian TAI64N timestamp (`[secs: 8B BE][nanos: 4B BE]`).
/// Lexicographical byte order matches chronological order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tai64nTimestamp(pub [u8; 12]);

impl Tai64nTimestamp {
    pub const LEN: usize = 12;

    pub fn from_unix_duration(dur: Duration) -> Self {
        let secs = TAI64_EPOCH_OFFSET.saturating_add(dur.as_secs());
        let nanos = dur.subsec_nanos();
        Self::from_parts(secs, nanos)
    }

    pub const fn from_parts(tai_secs: u64, nanos: u32) -> Self {
        let mut out = [0u8; 12];
        let s = tai_secs.to_be_bytes();
        let n = nanos.to_be_bytes();
        out[0] = s[0];
        out[1] = s[1];
        out[2] = s[2];
        out[3] = s[3];
        out[4] = s[4];
        out[5] = s[5];
        out[6] = s[6];
        out[7] = s[7];
        out[8] = n[0];
        out[9] = n[1];
        out[10] = n[2];
        out[11] = n[3];
        Self(out)
    }

    pub fn to_parts(self) -> Result<(u64, u32)> {
        let secs = u64::from_be_bytes(self.0[..8].try_into().unwrap());
        let nanos = u32::from_be_bytes(self.0[8..12].try_into().unwrap());
        if nanos >= 1_000_000_000 {
            return Err(CoreError::ReplayDetected);
        }
        Ok((secs, nanos))
    }

    pub const fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

/// Strictly monotonic TAI64N timestamp generator safe under concurrent multi-threaded handshakes.
pub struct Tai64nGenerator {
    last: Mutex<(u64, u32)>,
}

impl Default for Tai64nGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl Tai64nGenerator {
    pub const fn new() -> Self {
        Self {
            last: Mutex::new((0, 0)),
        }
    }

    /// Generates a fresh `Tai64nTimestamp` guaranteed to be strictly greater than all previous
    /// timestamps emitted by this generator.
    pub fn next(&self) -> Tai64nTimestamp {
        let now_dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        let mut secs = TAI64_EPOCH_OFFSET.saturating_add(now_dur.as_secs());
        let mut nanos = now_dur.subsec_nanos();

        let mut guard = self.last.lock();
        if (secs, nanos) <= *guard {
            secs = guard.0;
            nanos = guard.1 + 1;
            if nanos >= 1_000_000_000 {
                secs = secs.saturating_add(1);
                nanos = 0;
            }
        }
        *guard = (secs, nanos);
        Tai64nTimestamp::from_parts(secs, nanos)
    }
}

struct PeerReplayEntry {
    seen: BTreeSet<Tai64nTimestamp>,
}

/// Bounded per-peer TAI64N replay cache for 0-RTT hop & E2E handshake authentication.
///
/// - Rejects exact replays (`100%` rejected).
/// - Rejects timestamps outside `±max_clock_skew` relative to verifier wall clock.
/// - Tolerates slight packet reordering among concurrent handshakes from the same `PeerId`
///   up to `max_per_peer_window` entries while strictly rejecting any timestamp at or below
///   the peer's sliding floor.
/// - Strictly bounds memory to `max_peers` tracked peers.
pub struct Tai64nReplayWindow {
    max_clock_skew_secs: u64,
    max_peers: usize,
    max_per_peer_window: usize,
    inner: Mutex<ReplayMapState>,
}

struct ReplayMapState {
    peers: HashMap<PeerId, PeerReplayEntry>,
    fifo_order: VecDeque<PeerId>,
}

impl Default for Tai64nReplayWindow {
    fn default() -> Self {
        Self::new(Duration::from_secs(120), 4096, 64)
    }
}

impl Tai64nReplayWindow {
    pub fn new(max_clock_skew: Duration, max_peers: usize, max_per_peer_window: usize) -> Self {
        Self {
            max_clock_skew_secs: max_clock_skew.as_secs().max(1),
            max_peers: max_peers.max(1),
            max_per_peer_window: max_per_peer_window.max(1),
            inner: Mutex::new(ReplayMapState {
                peers: HashMap::new(),
                fifo_order: VecDeque::new(),
            }),
        }
    }

    /// Checks and records `(peer, ts)` against the current system time.
    pub fn check_and_record(&self, peer: &PeerId, ts: Tai64nTimestamp) -> Result<()> {
        let now_dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        let now_tai_secs = TAI64_EPOCH_OFFSET.saturating_add(now_dur.as_secs());
        self.check_and_record_at(peer, ts, now_tai_secs)
    }

    /// Deterministic variant taking explicit `now_tai_secs` for unit testing.
    pub fn check_and_record_at(
        &self,
        peer: &PeerId,
        ts: Tai64nTimestamp,
        now_tai_secs: u64,
    ) -> Result<()> {
        let (ts_secs, _) = ts.to_parts()?;
        let diff = ts_secs.abs_diff(now_tai_secs);
        if diff > self.max_clock_skew_secs {
            return Err(CoreError::ReplayDetected);
        }

        let mut state = self.inner.lock();
        if !state.peers.contains_key(peer) && state.peers.len() >= self.max_peers {
            if let Some(evicted) = state.fifo_order.pop_front() {
                state.peers.remove(&evicted);
            }
        }

        if let Some(entry) = state.peers.get_mut(peer) {
            if entry.seen.contains(&ts) {
                return Err(CoreError::ReplayDetected);
            }
            if entry.seen.len() >= self.max_per_peer_window {
                if let Some(&lowest) = entry.seen.iter().next() {
                    if ts <= lowest {
                        return Err(CoreError::ReplayDetected);
                    }
                    entry.seen.remove(&lowest);
                }
            }
            entry.seen.insert(ts);
        } else {
            let mut seen = BTreeSet::new();
            seen.insert(ts);
            state.peers.insert(*peer, PeerReplayEntry { seen });
            state.fifo_order.push_back(*peer);
        }

        Ok(())
    }
}

/// 64-bit sliding anti-replay window for steady-state Datagram Plane nonces.
pub struct ReplayWindow64 {
    highest: Option<u64>,
    bitmap: u64,
}

impl Default for ReplayWindow64 {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow64 {
    pub const fn new() -> Self {
        Self {
            highest: None,
            bitmap: 0,
        }
    }

    /// Read-only check returning `true` if `seq` is not a known replay or behind the 64-packet window.
    pub fn check_possible(&self, seq: u64) -> bool {
        let Some(high) = self.highest else {
            return true;
        };
        if seq > high {
            return true;
        }
        let diff = high - seq;
        if diff >= 64 {
            return false;
        }
        (self.bitmap & (1u64 << diff)) == 0
    }

    /// Records `seq` into the sliding window, returning `false` if `seq` was already seen or too old.
    pub fn accept(&mut self, seq: u64) -> bool {
        let Some(high) = self.highest else {
            self.highest = Some(seq);
            self.bitmap = 1;
            return true;
        };

        if seq > high {
            let shift = seq - high;
            if shift >= 64 {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.highest = Some(seq);
            true
        } else {
            let diff = high - seq;
            if diff >= 64 {
                return false;
            }
            let mask = 1u64 << diff;
            if (self.bitmap & mask) != 0 {
                return false;
            }
            self.bitmap |= mask;
            true
        }
    }
}
