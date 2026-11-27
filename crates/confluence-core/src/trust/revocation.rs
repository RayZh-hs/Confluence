//! 16-way sharded weak `RevocationIndex` and bounded TOCTOU-free `AuthEpochTable` (Spec §7.5).

use core::hash::{Hash, Hasher};
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use crate::constants::MAX_EPOCHS;
use crate::error::CoreError;
use crate::trust::lease::LeaseHandle;
use crate::types::{Plane, PublicationId, PublicKey};

const SHARDS: usize = 16;
/// Minimum insertions into a shard before triggering an amortized full-shard dead-entry sweep.
const SHARD_SWEEP_MIN_INSERTS: usize = 32;
/// Global insert cadence for crediting the next shard in round-robin cross-shard sweeping.
const RR_SWEEP_INTERVAL: usize = 32;
/// Work credits granted per round-robin visit (guarantees $O(1)$ amortized work per insert).
const RR_SWEEP_CREDITS: usize = 64;

/// Key indexing active leases inside [`RevocationIndex`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RevocationKey {
    Peer(PublicKey),
    Endpoint(String),
    Transit(Plane, String),
    Publication(PublicationId),
    PublicationTarget(PublicationId, String),
}

struct RevocationShard {
    map: HashMap<RevocationKey, Vec<Weak<LeaseHandle>>>,
    inserts_since_sweep: usize,
    next_sweep_threshold: usize,
    rr_work_budget: usize,
}

impl RevocationShard {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            inserts_since_sweep: 0,
            next_sweep_threshold: SHARD_SWEEP_MIN_INSERTS,
            rr_work_budget: 0,
        }
    }

    fn sweep(&mut self) {
        self.map.retain(|_, list| {
            list.retain(|w| w.strong_count() > 0);
            if list.is_empty() {
                false
            } else {
                if list.capacity() > list.len().saturating_mul(4).max(8) {
                    list.shrink_to(list.len().saturating_mul(2).max(4));
                }
                true
            }
        });
        if self.map.capacity() > self.map.len().saturating_mul(4).max(64) {
            self.map.shrink_to(self.map.len().saturating_mul(2).max(32));
        }
        self.inserts_since_sweep = 0;
        self.rr_work_budget = 0;
        self.next_sweep_threshold = self.map.len().max(SHARD_SWEEP_MIN_INSERTS);
    }
}

/// 16-way sharded weak-reference lease index for instant $O(1)$ scoped revocation (Spec §7.5).
///
/// Lock Level 4: never acquires higher locks, holds at most ONE shard lock at a time, and
/// ALWAYS releases its shard lock before calling [`LeaseHandle::revoke`].
///
/// Incrementally sweeps stale weak references and removes empty keys both per-shard and
/// round-robin across idle shards so historical sessions with distinct peers or transit
/// suffixes cannot grow the index unboundedly.
pub struct RevocationIndex {
    shards: [Mutex<RevocationShard>; SHARDS],
    rr_ops: AtomicUsize,
}

impl Default for RevocationIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl RevocationIndex {
    #[must_use]
    pub fn new() -> Self {
        Self {
            shards: core::array::from_fn(|_| Mutex::new(RevocationShard::new())),
            rr_ops: AtomicUsize::new(0),
        }
    }

    fn shard_for(key: &RevocationKey) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) & (SHARDS - 1)
    }

    /// Registers a weak reference to `lease` under `key`, lazily pruning dead weak entries
    /// and running $O(1)$-amortized shard sweeps so empty keys never accumulate indefinitely.
    pub fn insert(&self, key: RevocationKey, lease: &Arc<LeaseHandle>) {
        let shard_idx = Self::shard_for(&key);
        {
            let mut shard = self.shards[shard_idx]
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let list = shard.map.entry(key).or_default();
            list.retain(|w| w.strong_count() > 0);
            list.push(Arc::downgrade(lease));
            shard.inserts_since_sweep = shard.inserts_since_sweep.saturating_add(1);
            if shard.inserts_since_sweep >= shard.next_sweep_threshold {
                shard.sweep();
            }
        }

        // Cross-shard round-robin sweep strictly AFTER releasing `shard_idx` (at most one
        // Level-4 shard lock held at any time) so idle shards with dead historical keys are
        // also reclaimed in O(1) amortized time.
        let op = self.rr_ops.fetch_add(1, Ordering::Relaxed);
        if op % RR_SWEEP_INTERVAL == (RR_SWEEP_INTERVAL - 1) {
            let rr_idx = (op / RR_SWEEP_INTERVAL) & (SHARDS - 1);
            let mut shard = self.shards[rr_idx]
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !shard.map.is_empty() {
                shard.rr_work_budget = shard.rr_work_budget.saturating_add(RR_SWEEP_CREDITS);
                if shard.rr_work_budget >= shard.map.len() {
                    shard.sweep();
                }
            }
        }
    }

    /// Detaches all weak lease references indexed under `key` WITHOUT notifying them.
    ///
    /// Callers holding a Level-3 registry write lock invoke this inside the same transaction
    /// as epoch bumps, then pass the returned vector to [`Self::notify_revoked`] strictly
    /// after releasing all locks.
    pub fn detach_key(&self, key: &RevocationKey) -> Vec<Weak<LeaseHandle>> {
        let mut shard = self.shards[Self::shard_for(key)]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let removed = shard.map.remove(key).unwrap_or_default();
        if shard.map.is_empty() {
            shard.inserts_since_sweep = 0;
            shard.rr_work_budget = 0;
            shard.next_sweep_threshold = SHARD_SWEEP_MIN_INSERTS;
            if shard.map.capacity() > 64 {
                shard.map.shrink_to(32);
            }
        }
        removed
    }

    /// Detaches all weak lease references across all 16 shards WITHOUT notifying them.
    ///
    /// Locks shards one at a time in ascending order (never holding two shard locks at once).
    pub fn detach_all(&self) -> Vec<Weak<LeaseHandle>> {
        let mut out = Vec::new();
        for shard_lock in &self.shards {
            let mut shard = shard_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (_, mut weaks) in shard.map.drain() {
                out.append(&mut weaks);
            }
            shard.inserts_since_sweep = 0;
            shard.rr_work_budget = 0;
            shard.next_sweep_threshold = SHARD_SWEEP_MIN_INSERTS;
            if shard.map.capacity() > 64 {
                shard.map.shrink_to(32);
            }
        }
        out
    }

    /// Notifies every live lease in `weaks` with `reason`. MUST be called with no Level-3/4 locks held.
    pub fn notify_revoked(weaks: Vec<Weak<LeaseHandle>>, reason: &CoreError) -> usize {
        let mut count = 0usize;
        for w in weaks {
            if let Some(lease) = w.upgrade() {
                lease.revoke(reason.clone());
                count += 1;
            }
        }
        count
    }

    /// Removes `key` and immediately revokes every live lease indexed under it with `reason`.
    ///
    /// Returns the number of live leases notified.
    pub fn revoke_key(&self, key: &RevocationKey, reason: &CoreError) -> usize {
        let weaks = self.detach_key(key);
        Self::notify_revoked(weaks, reason)
    }

    /// Drains all 16 shards and revokes every live lease in the scope fail-closed.
    pub fn revoke_all(&self, reason: &CoreError) -> usize {
        let weaks = self.detach_all();
        Self::notify_revoked(weaks, reason)
    }

    /// Returns the total number of indexed keys currently stored across all 16 shards.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.shards
            .iter()
            .map(|s| {
                s.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .map
                    .len()
            })
            .sum()
    }

    /// Returns the total number of weak lease entries currently stored across all 16 shards.
    #[must_use]
    pub fn weak_count(&self) -> usize {
        self.shards
            .iter()
            .map(|s| {
                s.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .map
                    .values()
                    .map(Vec::len)
                    .sum::<usize>()
            })
            .sum()
    }
}

/// Captured pre-authorization epoch snapshot verified atomically before tracking a lease (Spec §7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthEpochSnapshot {
    pub global: u64,
    pub peer: u64,
    pub endpoint: Option<u64>,
    pub transit_full: Option<u64>,
    pub transit_prefix: Option<u64>,
    pub publication_target: Option<u64>,
}

/// Bounded fine-grained revocation epoch table preventing TOCTOU races between in-flight
/// `Authorizer::authorize` calls and concurrent revocations (Spec §7.5).
///
/// Total entries across all fine-grained maps are strictly bounded by [`MAX_EPOCHS`] (`16_384`);
/// reaching the cap increments `global` and clears all fine-grained maps.
#[derive(Debug, Default)]
pub struct AuthEpochTable {
    global: u64,
    peers: HashMap<PublicKey, u64>,
    endpoints: HashMap<String, u64>,
    transits: HashMap<(Plane, String), u64>,
    publication_targets: HashMap<(PublicationId, String), u64>,
}

/// Descriptor of a transit admission target for TOCTOU epoch capture and verification.
#[derive(Debug, Clone, Copy)]
pub struct TransitEpochTarget<'a> {
    pub peer: PublicKey,
    pub plane: Plane,
    pub full_name: &'a str,
    pub matched_prefix: Option<&'a str>,
    pub pub_id: PublicationId,
    pub subtarget: &'a str,
}

#[allow(dead_code)]
impl AuthEpochTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn total_entries(&self) -> usize {
        self.peers.len()
            + self.endpoints.len()
            + self.transits.len()
            + self.publication_targets.len()
    }

    #[must_use]
    pub const fn global_epoch(&self) -> u64 {
        self.global
    }

    fn clear_and_bump_global(&mut self) {
        self.global = self.global.wrapping_add(1);
        self.peers.clear();
        self.endpoints.clear();
        self.transits.clear();
        self.publication_targets.clear();
    }

    /// Bumps the scope-wide epoch (`Revocation::All` or broadcast lag).
    pub fn bump_all(&mut self) {
        self.clear_and_bump_global();
    }

    /// Bumps a peer's revocation epoch (falling back to global epoch if at `MAX_EPOCHS`).
    pub fn bump_peer(&mut self, peer: PublicKey) {
        if let Some(entry) = self.peers.get_mut(&peer) {
            *entry = entry.wrapping_add(1);
        } else if self.total_entries() >= MAX_EPOCHS {
            self.clear_and_bump_global();
        } else {
            self.peers.insert(peer, 1);
        }
    }

    /// Bumps an endpoint's revocation epoch.
    pub fn bump_endpoint(&mut self, endpoint: &str) {
        if let Some(entry) = self.endpoints.get_mut(endpoint) {
            *entry = entry.wrapping_add(1);
        } else if self.total_entries() >= MAX_EPOCHS {
            self.clear_and_bump_global();
        } else {
            self.endpoints.insert(endpoint.to_owned(), 1);
        }
    }

    /// Bumps a transit name's epoch across BOTH planes (Spec §7.5).
    pub fn bump_transit_both_planes(&mut self, name: &str) {
        self.bump_transit_plane(Plane::Stream, name);
        self.bump_transit_plane(Plane::Datagram, name);
    }

    /// Bumps a transit name's epoch on a single plane.
    pub fn bump_transit_plane(&mut self, plane: Plane, name: &str) {
        let key = (plane, name.to_owned());
        if let Some(entry) = self.transits.get_mut(&key) {
            *entry = entry.wrapping_add(1);
        } else if self.total_entries() >= MAX_EPOCHS {
            self.clear_and_bump_global();
        } else {
            self.transits.insert(key, 1);
        }
    }

    /// Bumps a `(PublicationId, subtarget)` epoch for [`crate::trust::TransitRevoker`].
    pub fn bump_publication_target(&mut self, pub_id: PublicationId, subtarget: &str) {
        let key = (pub_id, subtarget.to_owned());
        if let Some(entry) = self.publication_targets.get_mut(&key) {
            *entry = entry.wrapping_add(1);
        } else if self.total_entries() >= MAX_EPOCHS {
            self.clear_and_bump_global();
        } else {
            self.publication_targets.insert(key, 1);
        }
    }

    /// Captures an epoch snapshot for an endpoint dial (`endpoint = None` on Originator, `Some` on Destination).
    #[must_use]
    pub fn snapshot_endpoint(&self, peer: PublicKey, endpoint: Option<&str>) -> AuthEpochSnapshot {
        AuthEpochSnapshot {
            global: self.global,
            peer: self.peers.get(&peer).copied().unwrap_or(0),
            endpoint: endpoint.map(|ep| self.endpoints.get(ep).copied().unwrap_or(0)),
            transit_full: None,
            transit_prefix: None,
            publication_target: None,
        }
    }

    /// Verifies that no relevant endpoint/peer/global epoch changed since `snap`.
    #[must_use]
    pub fn matches_endpoint(
        &self,
        snap: &AuthEpochSnapshot,
        peer: PublicKey,
        endpoint: Option<&str>,
    ) -> bool {
        if self.global != snap.global {
            return false;
        }
        if self.peers.get(&peer).copied().unwrap_or(0) != snap.peer {
            return false;
        }
        if let (Some(ep), Some(expected)) = (endpoint, snap.endpoint) {
            if self.endpoints.get(ep).copied().unwrap_or(0) != expected {
                return false;
            }
        }
        true
    }

    /// Captures an epoch snapshot for a transit admission.
    #[must_use]
    pub fn snapshot_transit(&self, target: &TransitEpochTarget<'_>) -> AuthEpochSnapshot {
        let full_key = (target.plane, target.full_name.to_owned());
        let prefix_epoch = target.matched_prefix.map(|p| {
            self.transits
                .get(&(target.plane, p.to_owned()))
                .copied()
                .unwrap_or(0)
        });
        let pub_target_epoch = self
            .publication_targets
            .get(&(target.pub_id, target.subtarget.to_owned()))
            .copied()
            .unwrap_or(0);
        AuthEpochSnapshot {
            global: self.global,
            peer: self.peers.get(&target.peer).copied().unwrap_or(0),
            endpoint: None,
            transit_full: Some(self.transits.get(&full_key).copied().unwrap_or(0)),
            transit_prefix: prefix_epoch,
            publication_target: Some(pub_target_epoch),
        }
    }

    /// Verifies that no relevant transit/prefix/publication-target/peer/global epoch changed since `snap`.
    #[must_use]
    pub fn matches_transit(
        &self,
        snap: &AuthEpochSnapshot,
        target: &TransitEpochTarget<'_>,
    ) -> bool {
        if self.global != snap.global {
            return false;
        }
        if self.peers.get(&target.peer).copied().unwrap_or(0) != snap.peer {
            return false;
        }
        if let Some(expected_full) = snap.transit_full {
            let cur = self
                .transits
                .get(&(target.plane, target.full_name.to_owned()))
                .copied()
                .unwrap_or(0);
            if cur != expected_full {
                return false;
            }
        }
        if let (Some(prefix), Some(expected_prefix)) = (target.matched_prefix, snap.transit_prefix)
        {
            let cur = self
                .transits
                .get(&(target.plane, prefix.to_owned()))
                .copied()
                .unwrap_or(0);
            if cur != expected_prefix {
                return false;
            }
        }
        if let Some(expected_pt) = snap.publication_target {
            let cur = self
                .publication_targets
                .get(&(target.pub_id, target.subtarget.to_owned()))
                .copied()
                .unwrap_or(0);
            if cur != expected_pt {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use core::time::Duration;

    use super::*;
    use crate::seam::auth::Lease;
    use crate::testing::VirtualClock;

    #[test]
    fn auth_epoch_table_overflow_bumps_global_and_clears_maps() {
        let mut table = AuthEpochTable::new();
        for i in 0..MAX_EPOCHS {
            let mut pk = [0u8; 32];
            pk[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            table.bump_peer(PublicKey::from_bytes(pk));
        }
        assert_eq!(table.total_entries(), MAX_EPOCHS);
        assert_eq!(table.global_epoch(), 0);

        let snap = table.snapshot_endpoint(PublicKey::from_bytes([0xFF; 32]), Some("ep"));
        assert!(table.matches_endpoint(&snap, PublicKey::from_bytes([0xFF; 32]), Some("ep")));

        // Inserting one more distinct entry triggers global fallback & clear!
        table.bump_endpoint("overflow-trigger");
        assert_eq!(table.global_epoch(), 1);
        assert_eq!(table.total_entries(), 0);
        // Existing pre-overflow snapshot MUST now fail TOCTOU validation!
        assert!(!table.matches_endpoint(&snap, PublicKey::from_bytes([0xFF; 32]), Some("ep")));
    }

    #[test]
    fn revocation_index_prunes_dead_weaks_and_revokes_live_leases() {
        let clock = VirtualClock::new();
        let idx = RevocationIndex::new();
        let peer = PublicKey::from_bytes([2u8; 32]);

        let dead = LeaseHandle::new(peer, Lease::new(Duration::from_secs(10)), Duration::from_secs(60), clock.clone()).unwrap();
        idx.insert(RevocationKey::Peer(peer), &dead);
        drop(dead);

        let live = LeaseHandle::new(peer, Lease::new(Duration::from_secs(10)), Duration::from_secs(60), clock).unwrap();
        idx.insert(RevocationKey::Peer(peer), &live);
        assert!(live.is_active());

        let count = idx.revoke_key(&RevocationKey::Peer(peer), &CoreError::Revoked);
        assert_eq!(count, 1);
        assert!(!live.is_active());
        assert_eq!(live.remaining(), Err(CoreError::Revoked));
    }

    #[test]
    fn revocation_index_bounds_keys_across_distinct_historical_peers_and_idle_shards() {
        let clock = VirtualClock::new();
        let idx = RevocationIndex::new();
        let pub_id = PublicationId::next();

        // Phase 1: 4,000 closed historical sessions with distinct peers AND distinct transit suffixes.
        for i in 0..4_000u64 {
            let mut pk = [0u8; 32];
            pk[0..8].copy_from_slice(&i.to_be_bytes());
            let peer = PublicKey::from_bytes(pk);
            let lease = LeaseHandle::from_ttl(
                peer,
                Duration::from_secs(60),
                Duration::from_secs(60),
                clock.clone(),
            )
            .unwrap();
            idx.insert(RevocationKey::Peer(peer), &lease);
            idx.insert(
                RevocationKey::PublicationTarget(pub_id, format!("suffix-{i}")),
                &lease,
            );
            drop(lease);
        }
        // Incremental per-shard sweeps MUST keep keys strictly bounded (far below 8,000).
        assert!(
            idx.key_count() <= SHARDS * SHARD_SWEEP_MIN_INSERTS,
            "key_count grew unboundedly: {}",
            idx.key_count()
        );
        assert!(
            idx.weak_count() <= SHARDS * SHARD_SWEEP_MIN_INSERTS,
            "weak_count grew unboundedly: {}",
            idx.weak_count()
        );

        // Phase 2: Burst of 512 concurrent distinct-peer leases across all 16 shards, then all close,
        // followed by steady single-peer insertions into ONE shard. Round-robin cross-shard sweeping
        // MUST reclaim the 15 idle shards back down to the 1 active key!
        let mut burst = Vec::with_capacity(512);
        for i in 10_000..10_512u64 {
            let mut pk = [0u8; 32];
            pk[0..8].copy_from_slice(&i.to_be_bytes());
            let peer = PublicKey::from_bytes(pk);
            let lease = LeaseHandle::from_ttl(
                peer,
                Duration::from_secs(60),
                Duration::from_secs(60),
                clock.clone(),
            )
            .unwrap();
            idx.insert(RevocationKey::Peer(peer), &lease);
            burst.push(lease);
        }
        drop(burst);

        let steady_peer = PublicKey::from_bytes([0xEE; 32]);
        let mut last_live = None;
        for _ in 0..(SHARDS * RR_SWEEP_INTERVAL * 2) {
            let lease = LeaseHandle::from_ttl(
                steady_peer,
                Duration::from_secs(60),
                Duration::from_secs(60),
                clock.clone(),
            )
            .unwrap();
            last_live = Some(Arc::clone(&lease));
            idx.insert(RevocationKey::Peer(steady_peer), &lease);
        }
        assert!(last_live.as_ref().unwrap().is_active());
        assert_eq!(idx.key_count(), 1, "idle shards must be reclaimed to 1 live key");
        assert_eq!(idx.weak_count(), 1);
    }
}
