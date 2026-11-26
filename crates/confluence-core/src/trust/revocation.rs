//! 16-way sharded weak `RevocationIndex` and bounded TOCTOU-free `AuthEpochTable` (Spec §7.5).

use core::hash::{Hash, Hasher};
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::sync::{Arc, Mutex, Weak};

use crate::constants::MAX_EPOCHS;
use crate::error::CoreError;
use crate::trust::lease::LeaseHandle;
use crate::types::{Plane, PublicationId, PublicKey};

const SHARDS: usize = 16;

/// Key indexing active leases inside [`RevocationIndex`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RevocationKey {
    Peer(PublicKey),
    Endpoint(String),
    Transit(Plane, String),
    Publication(PublicationId),
    PublicationTarget(PublicationId, String),
}

/// 16-way sharded weak-reference lease index for instant $O(1)$ scoped revocation (Spec §7.5).
///
/// Lock Level 4: never acquires higher locks and ALWAYS releases its shard lock before calling
/// [`LeaseHandle::revoke`].
pub struct RevocationIndex {
    shards: [Mutex<HashMap<RevocationKey, Vec<Weak<LeaseHandle>>>>; SHARDS],
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
            shards: core::array::from_fn(|_| Mutex::new(HashMap::new())),
        }
    }

    fn shard_for(key: &RevocationKey) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) & (SHARDS - 1)
    }

    /// Registers a weak reference to `lease` under `key`, lazily pruning dead weak entries.
    pub fn insert(&self, key: RevocationKey, lease: &Arc<LeaseHandle>) {
        let shard = &self.shards[Self::shard_for(&key)];
        let mut map = shard
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let list = map.entry(key).or_default();
        list.retain(|w| w.strong_count() > 0);
        list.push(Arc::downgrade(lease));
    }

    /// Removes `key` and immediately revokes every live lease indexed under it with `reason`.
    ///
    /// Returns the number of live leases notified.
    pub fn revoke_key(&self, key: &RevocationKey, reason: &CoreError) -> usize {
        let shard = &self.shards[Self::shard_for(key)];
        let weaks = {
            let mut map = shard
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            map.remove(key)
        };
        let Some(weaks) = weaks else {
            return 0;
        };
        let mut count = 0usize;
        for w in weaks {
            if let Some(lease) = w.upgrade() {
                lease.revoke(reason.clone());
                count += 1;
            }
        }
        count
    }

    /// Drains all 16 shards and revokes every live lease in the scope fail-closed.
    pub fn revoke_all(&self, reason: &CoreError) -> usize {
        let mut total = 0usize;
        for shard in &self.shards {
            let drained: Vec<Vec<Weak<LeaseHandle>>> = {
                let mut map = shard
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                map.drain().map(|(_, v)| v).collect()
            };
            for weaks in drained {
                for w in weaks {
                    if let Some(lease) = w.upgrade() {
                        lease.revoke(reason.clone());
                        total += 1;
                    }
                }
            }
        }
        total
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
}
