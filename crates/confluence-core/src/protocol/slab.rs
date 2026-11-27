//! Generational per-link circuit table with 60 s FIFO CID wrap quarantine (Spec §6.5).

use std::collections::VecDeque;

use crate::constants::{SLAB_MAX_ACTIVE, SLAB_QUARANTINE_DURATION};
use crate::error::CoreError;
use crate::runtime::MonotonicTime;
use crate::types::Cid;

struct SlotEntry<T> {
    generation: u8, // ALWAYS in 1..=255
    value: Option<T>,
}

/// Generation and 60-second wrap-quarantine state preserved across idle port retirement (Spec §6.5).
#[derive(Debug, Clone)]
pub struct SlabHistory {
    generations: Vec<u8>,
    free_list: Vec<u32>,
    quarantine: VecDeque<(u32, MonotonicTime)>,
    retired_at: MonotonicTime,
}

#[allow(dead_code)]
impl SlabHistory {
    /// Returns `true` if no slots were ever allocated in this slab.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.generations.is_empty()
    }

    /// Returns the monotonic timestamp when this history was captured.
    #[must_use]
    pub const fn retired_at(&self) -> MonotonicTime {
        self.retired_at
    }

    /// Returns `true` once the 60-second idle quarantine cooldown has elapsed since retirement.
    #[must_use]
    pub fn is_expired(&self, now: MonotonicTime) -> bool {
        now.saturating_duration_since(self.retired_at) >= SLAB_QUARANTINE_DURATION
    }
}

/// Bounded per-link circuit table (`4096` active cap) issuing non-zero 32-bit [`Cid`]s
/// (`[generation: 8b (1..=255) | slot_idx: 24b]`) with a 60-second monotonic FIFO quarantine
/// whenever a slot's generation wraps from `255` back to `1` (Spec §6.5).
pub struct SlabTable<T> {
    max_active: usize,
    active_count: usize,
    slots: Vec<SlotEntry<T>>,
    free_list: Vec<u32>,
    quarantine: VecDeque<(u32, MonotonicTime)>,
}

impl<T> Default for SlabTable<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl<T> SlabTable<T> {
    /// Creates an empty `SlabTable` capped at `SLAB_MAX_ACTIVE` (`4096`) concurrent entries.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity_limit(SLAB_MAX_ACTIVE)
    }

    /// Creates an empty `SlabTable` with an explicit active limit (clamped to `>= 1`).
    #[must_use]
    pub fn with_capacity_limit(max_active: usize) -> Self {
        Self {
            max_active: max_active.max(1),
            active_count: 0,
            slots: Vec::new(),
            free_list: Vec::new(),
            quarantine: VecDeque::new(),
        }
    }

    /// Inserts `value` and returns its unique bound [`Cid`] (never [`Cid::UNBOUND`]).
    ///
    /// Allocation priority: free list -> expired `60 s` FIFO quarantine head -> new slot.
    pub fn insert(&mut self, value: T, now: MonotonicTime) -> Result<Cid, CoreError> {
        if self.active_count >= self.max_active {
            return Err(CoreError::Busy);
        }

        let idx: u32 = if let Some(idx) = self.free_list.pop() {
            idx
        } else if self.quarantine.front().is_some_and(|&(_, retired_at)| {
            now.saturating_duration_since(retired_at) >= SLAB_QUARANTINE_DURATION
        }) {
            match self.quarantine.pop_front() {
                Some((idx, _)) => idx,
                None => return Err(CoreError::Busy),
            }
        } else {
            let next_idx = u32::try_from(self.slots.len()).map_err(|_| CoreError::Busy)?;
            if next_idx > Cid::MAX_SLOT {
                return Err(CoreError::Busy);
            }
            self.slots.push(SlotEntry {
                generation: 1,
                value: None,
            });
            next_idx
        };

        let slot = self
            .slots
            .get_mut(idx as usize)
            .ok_or(CoreError::Malformed)?;
        let generation = slot.generation;
        let cid = Cid::from_parts(generation, idx).ok_or(CoreError::Malformed)?;
        slot.value = Some(value);
        self.active_count += 1;
        Ok(cid)
    }

    /// Looks up a live entry by [`Cid`] in $O(1)$, verifying exact generation equality.
    #[must_use]
    pub fn get(&self, cid: Cid) -> Option<&T> {
        if cid.is_unbound() {
            return None;
        }
        let slot = self.slots.get(cid.slot() as usize)?;
        if slot.generation != cid.generation() {
            return None;
        }
        slot.value.as_ref()
    }

    /// Mutably looks up a live entry by [`Cid`] in $O(1)$.
    #[must_use]
    pub fn get_mut(&mut self, cid: Cid) -> Option<&mut T> {
        if cid.is_unbound() {
            return None;
        }
        let slot = self.slots.get_mut(cid.slot() as usize)?;
        if slot.generation != cid.generation() {
            return None;
        }
        slot.value.as_mut()
    }

    /// Removes `cid` if live and matching generation.
    ///
    /// Increments `generation` (`< 255`) and returns the slot to the free list, OR resets
    /// `generation = 1` and places the slot into the `60 s` FIFO quarantine on `255 -> 1` wrap.
    pub fn remove(&mut self, cid: Cid, now: MonotonicTime) -> Option<T> {
        if cid.is_unbound() {
            return None;
        }
        let idx = cid.slot();
        let slot = self.slots.get_mut(idx as usize)?;
        if slot.generation != cid.generation() {
            return None;
        }
        let value = slot.value.take()?;
        self.active_count -= 1;

        if slot.generation < u8::MAX {
            slot.generation += 1;
            self.free_list.push(idx);
        } else {
            slot.generation = 1;
            self.quarantine.push_back((idx, now));
        }
        Some(value)
    }

    /// Returns the number of currently active entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.active_count
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.active_count == 0
    }

    /// Returns the total backing slot vector length (used to verify bounded memory growth).
    #[must_use]
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Returns the number of slots currently sitting in 60-second wrap quarantine.
    #[must_use]
    pub fn quarantined_len(&self) -> usize {
        self.quarantine.len()
    }

    /// Removes all active entries (advancing their generations and applying 60-second wrap
    /// quarantine identically to [`Self::remove`]) and extracts the table's generation history,
    /// resetting `self` to an empty table so subsequent bindings on the same logical link never
    /// immediately alias previously issued CIDs.
    pub fn drain_to_history(&mut self, now: MonotonicTime) -> SlabHistory {
        let mut generations = Vec::with_capacity(self.slots.len());
        let mut free_list = core::mem::take(&mut self.free_list);
        let mut quarantine = core::mem::take(&mut self.quarantine);

        for (idx_usize, mut slot) in self.slots.drain(..).enumerate() {
            if slot.value.take().is_some() {
                if let Ok(idx) = u32::try_from(idx_usize) {
                    if slot.generation < u8::MAX {
                        slot.generation += 1;
                        free_list.push(idx);
                    } else {
                        slot.generation = 1;
                        quarantine.push_back((idx, now));
                    }
                }
            }
            generations.push(slot.generation);
        }
        self.active_count = 0;

        SlabHistory {
            generations,
            free_list,
            quarantine,
            retired_at: now,
        }
    }

    /// Reconstructs an empty `SlabTable` preserving prior per-slot generations, free list,
    /// and 60-second wrap quarantine state from `history`.
    #[must_use]
    pub fn from_history(history: SlabHistory) -> Self {
        let slots = history
            .generations
            .into_iter()
            .map(|generation| SlotEntry {
                generation: generation.max(1),
                value: None,
            })
            .collect();
        Self {
            max_active: SLAB_MAX_ACTIVE,
            active_count: 0,
            slots,
            free_list: history.free_list,
            quarantine: history.quarantine,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use core::time::Duration;
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn slab_table_255_wrap_quarantine_and_bounded_memory() {
        let mut slab = SlabTable::<u32>::new();
        let mut t = MonotonicTime::ZERO;
        let mut seen_cids = HashSet::new();

        // Cycle slot 0 through all 255 generations (1..=255).
        for generation in 1..=255u8 {
            let cid = slab.insert(u32::from(generation), t).unwrap();
            assert!(!cid.is_unbound());
            assert_eq!(cid.slot(), 0);
            assert_eq!(cid.generation(), generation);
            assert!(seen_cids.insert(cid));
            assert_eq!(slab.get(cid), Some(&u32::from(generation)));
            assert_eq!(slab.remove(cid, t), Some(u32::from(generation)));
            // Stale CID returns None immediately after removal.
            assert_eq!(slab.get(cid), None);
        }

        // Slot 0 wrapped 255 -> 1 and is now quarantined for 60 s!
        assert_eq!(slab.quarantined_len(), 1);
        assert_eq!(slab.slot_count(), 1);

        // Inserting at t + 59 s MUST allocate slot 1 (NOT alias quarantined slot 0!).
        let t59 = t.saturating_add(Duration::from_secs(59));
        let cid_slot1 = slab.insert(999, t59).unwrap();
        assert_eq!(cid_slot1.slot(), 1);
        assert_eq!(cid_slot1.generation(), 1);
        assert_eq!(slab.slot_count(), 2);
        slab.remove(cid_slot1, t59);

        // Drain slot 1 through 255 too so free_list is empty and both slots sit in quarantine.
        for _ in 2..=255u8 {
            let c = slab.insert(0, t59).unwrap();
            assert_eq!(c.slot(), 1);
            slab.remove(c, t59);
        }
        assert_eq!(slab.quarantined_len(), 2);

        // At t + 60 s, slot 0's quarantine expires and slot 0 is reclaimed WITHOUT growing `slots`!
        t = t.saturating_add(Duration::from_secs(60));
        let reclaimed = slab.insert(777, t).unwrap();
        assert_eq!(reclaimed.slot(), 0);
        assert_eq!(reclaimed.generation(), 1);
        assert_eq!(slab.slot_count(), 2);
        assert_eq!(slab.quarantined_len(), 1);
    }

    #[test]
    fn slab_table_enforces_active_capacity() {
        let mut slab = SlabTable::<u32>::with_capacity_limit(2);
        let t0 = MonotonicTime::ZERO;
        let c1 = slab.insert(1, t0).unwrap();
        let _c2 = slab.insert(2, t0).unwrap();
        assert_eq!(slab.insert(3, t0), Err(CoreError::Busy));
        assert_eq!(slab.remove(c1, t0), Some(1));
        assert!(slab.insert(3, t0).is_ok());
    }

    #[test]
    fn slab_table_history_preserves_generations_and_quarantine_across_reattach() {
        let mut slab = SlabTable::<u32>::new();
        let t0 = MonotonicTime::ZERO;
        let c1 = slab.insert(10, t0).unwrap();
        assert_eq!((c1.slot(), c1.generation()), (0, 1));
        // Drain while slot 0 is still active -> advances generation to 2 and clears active entries.
        let hist = slab.drain_to_history(t0);
        assert!(slab.is_empty());
        assert!(!hist.is_empty());

        let mut restored = SlabTable::<u32>::from_history(hist);
        let c2 = restored.insert(20, t0.saturating_add(Duration::from_millis(50))).unwrap();
        assert_eq!((c2.slot(), c2.generation()), (0, 2));
        assert_ne!(c1, c2);
        restored.remove(c2, t0);

        // Advance slot 0 through 255 -> wrap into 60 s quarantine and persist across drain/restore.
        for _ in 3..=255u8 {
            let c = restored.insert(0, t0).unwrap();
            assert_eq!(c.slot(), 0);
            restored.remove(c, t0);
        }
        assert_eq!(restored.quarantined_len(), 1);
        let hist2 = restored.drain_to_history(t0);
        let mut restored2 = SlabTable::<u32>::from_history(hist2);
        let c_next = restored2
            .insert(99, t0.saturating_add(Duration::from_secs(30)))
            .unwrap();
        assert_eq!(c_next.slot(), 1);
        assert_eq!(c_next.generation(), 1);
    }
}
