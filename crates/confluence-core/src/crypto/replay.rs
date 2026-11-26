//! Monotonic keyed-BLAKE3 set-associative setup ephemeral replay cache (Spec §4.7.1).

use std::sync::Mutex;

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::constants::{SETUP_REPLAY_BUCKETS, SETUP_REPLAY_TTL_SECS, SETUP_REPLAY_WAYS};
use crate::runtime::MonotonicTime;

#[derive(Clone, Copy, Default)]
struct ReplaySlot {
    fp: u32, // 0 = empty
    seen_secs: u64,
}

/// Bounded `4096 × 4` set-associative replay cache keyed by per-instance CSPRNG secret.
///
/// Uses monotonic seconds relative to instance creation so backward wall-clock jumps
/// can never flush live replay entries. Fails closed when all 4 ways in a bucket contain
/// unexpired non-matching entries.
pub struct SetupReplay {
    key: Zeroizing<[u8; 32]>,
    origin: MonotonicTime,
    buckets: Mutex<Vec<[ReplaySlot; SETUP_REPLAY_WAYS]>>,
}

impl SetupReplay {
    /// Creates a new `SetupReplay` table with a fresh CSPRNG hashing key.
    #[must_use]
    pub fn new(origin: MonotonicTime) -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self::with_key(key, origin)
    }

    /// Creates a `SetupReplay` with an explicit key (used for deterministic tests).
    #[must_use]
    pub fn with_key(key: [u8; 32], origin: MonotonicTime) -> Self {
        Self {
            key: Zeroizing::new(key),
            origin,
            buckets: Mutex::new(vec![[ReplaySlot::default(); SETUP_REPLAY_WAYS]; SETUP_REPLAY_BUCKETS]),
        }
    }

    #[inline]
    fn hash_ephemeral(&self, e_i: &[u8; 32]) -> (usize, u32) {
        let digest = blake3::keyed_hash(&self.key, e_i);
        let bytes = digest.as_bytes();
        let bucket =
            usize::from(u16::from_be_bytes([bytes[0], bytes[1]])) & (SETUP_REPLAY_BUCKETS - 1);
        let raw_fp = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let fp = if raw_fp == 0 { 1 } else { raw_fp };
        (bucket, fp)
    }

    #[inline]
    fn now_secs(&self, now: MonotonicTime) -> u64 {
        now.saturating_duration_since(self.origin).as_secs()
    }

    #[inline]
    const fn is_live(slot: ReplaySlot, now_secs: u64) -> bool {
        slot.fp != 0 && now_secs.saturating_sub(slot.seen_secs) <= SETUP_REPLAY_TTL_SECS
    }

    /// Phase 1 (`insert = false`): returns `true` iff `e_i` is not a live duplicate AND
    /// the target bucket has at least one free or expired slot. Never modifies the table.
    #[must_use]
    pub fn check(&self, e_i: &[u8; 32], now: MonotonicTime) -> bool {
        let (bucket_idx, fp) = self.hash_ephemeral(e_i);
        let now_secs = self.now_secs(now);
        let table = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bucket = &table[bucket_idx];

        let mut has_slot = false;
        for &slot in bucket {
            if Self::is_live(slot, now_secs) {
                if slot.fp == fp {
                    return false;
                }
            } else {
                has_slot = true;
            }
        }
        has_slot
    }

    /// Phase 2 (`insert = true`): atomically checks and inserts `e_i`.
    ///
    /// Returns `true` iff `e_i` was freshly inserted; returns `false` on duplicate or
    /// fail-closed bucket saturation.
    #[must_use]
    pub fn insert(&self, e_i: &[u8; 32], now: MonotonicTime) -> bool {
        let (bucket_idx, fp) = self.hash_ephemeral(e_i);
        let now_secs = self.now_secs(now);
        let mut table = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bucket = &mut table[bucket_idx];

        let mut free_idx: Option<usize> = None;
        for (i, &slot) in bucket.iter().enumerate() {
            if Self::is_live(slot, now_secs) {
                if slot.fp == fp {
                    return false;
                }
            } else if free_idx.is_none() {
                free_idx = Some(i);
            }
        }

        if let Some(i) = free_idx {
            bucket[i] = ReplaySlot {
                fp,
                seen_secs: now_secs,
            };
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use core::time::Duration;

    use super::*;

    #[test]
    fn two_phase_commit_expiry_and_saturation() {
        let t0 = MonotonicTime::from_nanos(10_000_000_000);
        let replay = SetupReplay::with_key([0xAA; 32], t0);
        let e1 = [1u8; 32];

        // Phase 1 check does not consume a slot.
        assert!(replay.check(&e1, t0));
        assert!(replay.check(&e1, t0));

        // Phase 2 inserts once; second insert fails.
        assert!(replay.insert(&e1, t0));
        assert!(!replay.check(&e1, t0));
        assert!(!replay.insert(&e1, t0));

        // Still live at exactly 61 s; expires at 62 s.
        let t61 = t0.saturating_add(Duration::from_secs(61));
        let t62 = t0.saturating_add(Duration::from_secs(62));
        assert!(!replay.check(&e1, t61));
        assert!(replay.check(&e1, t62));
        assert!(replay.insert(&e1, t62));

        // Find 5 distinct keys hashing to the same bucket to prove fail-closed saturation.
        let (target_bucket, _) = replay.hash_ephemeral(&e1);
        let mut colliding = Vec::new();
        let mut counter: u64 = 1;
        while colliding.len() < 4 {
            let mut candidate = [0u8; 32];
            candidate[0..8].copy_from_slice(&counter.to_be_bytes());
            counter += 1;
            if candidate != e1 && replay.hash_ephemeral(&candidate).0 == target_bucket {
                colliding.push(candidate);
            }
        }
        // Bucket already holds `e1` (1 of 4 ways); next 3 succeed, 4th saturates fail-closed.
        assert!(replay.insert(&colliding[0], t62));
        assert!(replay.insert(&colliding[1], t62));
        assert!(replay.insert(&colliding[2], t62));
        assert!(!replay.check(&colliding[3], t62));
        assert!(!replay.insert(&colliding[3], t62));

        // After 62 more seconds, expired entries free the bucket cleanly.
        let t124 = t62.saturating_add(Duration::from_secs(62));
        assert!(replay.insert(&colliding[3], t124));
    }
}
