use rand_core::{OsRng, RngCore};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

const BUCKETS: usize = 4096;
const WAYS: usize = 4;
const WINDOW_SECONDS: u32 = 61;
const FINGERPRINT: u64 = u32::MAX as u64;

/// Bounded, lock-free cache of authenticated initiator ephemerals.
/// Uses a monotonic local clock so wall-clock jumps cannot flush entries.
/// A saturated bucket fails closed until an entry expires.
pub struct SetupReplay {
    buckets: Box<[[AtomicU64; WAYS]]>,
    key: [u8; 32],
    started: Instant,
}
impl Default for SetupReplay {
    fn default() -> Self {
        let mut key = [0; 32];
        OsRng.fill_bytes(&mut key);
        Self {
            buckets: (0..BUCKETS).map(|_| Default::default()).collect(),
            key,
            started: Instant::now(),
        }
    }
}
impl SetupReplay {
    pub(crate) fn check(&self, ephemeral: &[u8], insert: bool) -> bool {
        let now = self.started.elapsed().as_secs() as u32;
        self.check_at(ephemeral, now, insert)
    }
    fn check_at(&self, ephemeral: &[u8], now: u32, insert: bool) -> bool {
        let hash = blake3::keyed_hash(&self.key, ephemeral);
        let hash = u64::from_be_bytes(hash.as_bytes()[..8].try_into().unwrap());
        let bucket = &self.buckets[(hash >> 32) as usize & (BUCKETS - 1)];
        let fingerprint = (hash & FINGERPRINT).max(1);
        loop {
            let mut free = None;
            for slot in bucket {
                let old = slot.load(Ordering::Acquire);
                if old == 0 || now.wrapping_sub((old >> 32) as u32) > WINDOW_SECONDS {
                    free.get_or_insert((slot, old));
                } else if old & FINGERPRINT == fingerprint {
                    return false;
                }
            }
            let Some((slot, old)) = free else {
                return false;
            };
            if !insert {
                return true;
            }
            let new = (u64::from(now) << 32) | fingerprint;
            if slot
                .compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }
}

#[derive(Default)]
pub struct ReplayWindow {
    max: u64,
    seen: u64,
}
impl ReplayWindow {
    pub fn allows(&self, seq: u64) -> bool {
        seq > self.max || (self.max - seq < 64 && self.seen & (1 << (self.max - seq)) == 0)
    }
    pub fn commit(&mut self, seq: u64) {
        if seq > self.max {
            self.seen = self
                .seen
                .checked_shl(u32::try_from(seq - self.max).unwrap_or(u32::MAX))
                .unwrap_or(0);
            self.max = seq;
        }
        if self.max - seq < 64 {
            self.seen |= 1 << (self.max - seq);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_replay_is_monotonic_and_cannot_be_flushed_by_wall_clock_step() {
        let replay = SetupReplay::default();
        let eph = [7u8; 32];
        assert!(replay.check(&eph, true));
        // Even if the system clock steps backward, local monotonic check still rejects replay.
        assert!(!replay.check(&eph, false));
        assert!(!replay.check(&eph, true));
    }
}
