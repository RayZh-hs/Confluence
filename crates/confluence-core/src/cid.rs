use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

const COOLDOWN: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Cid(u32);

impl Cid {
    pub const UNBOUND: Self = Self(0);
    pub const fn from_raw(value: u32) -> Self {
        Self(value)
    }
    pub const fn raw(self) -> u32 {
        self.0
    }
    pub const fn slot_idx(self) -> usize {
        (self.0 & 0x00ff_ffff) as usize
    }
    pub const fn generation(self) -> u8 {
        (self.0 >> 24) as u8
    }
}

struct Entry<T> {
    generation: u8,
    value: Option<T>,
    next_free: Option<usize>,
}

/// One table per inbound link. Wrapped generations enter a timed quarantine
/// before reuse so delayed packets cannot alias a live slot, without leaking
/// table entries unboundedly on long-lived links.
pub struct SlabTable<T> {
    entries: Vec<Entry<T>>,
    free: Option<usize>,
    quarantine: VecDeque<(usize, Instant)>,
    active: usize,
    limit: usize,
}
impl<T> SlabTable<T> {
    pub fn new(limit: usize) -> Self {
        Self {
            entries: Vec::new(),
            free: None,
            quarantine: VecDeque::new(),
            active: 0,
            limit,
        }
    }
    pub fn insert(&mut self, value: T) -> Option<Cid> {
        self.insert_at(value, Instant::now())
    }
    fn insert_at(&mut self, value: T, now: Instant) -> Option<Cid> {
        if self.active >= self.limit {
            return None;
        }
        let index =
            if let Some(index) = self.free {
                self.free = self.entries[index].next_free.take();
                self.entries[index].value = Some(value);
                index
            } else if self.quarantine.front().is_some_and(|(_, retired_at)| {
                now.saturating_duration_since(*retired_at) >= COOLDOWN
            }) {
                let (index, _) = self.quarantine.pop_front().unwrap();
                self.entries[index].value = Some(value);
                index
            } else {
                if self.entries.len() == 1 << 24 {
                    return None;
                }
                let index = self.entries.len();
                self.entries.push(Entry {
                    generation: 1,
                    value: Some(value),
                    next_free: None,
                });
                index
            };
        self.active += 1;
        Some(Cid::from_raw(
            (u32::from(self.entries[index].generation) << 24) | index as u32,
        ))
    }
    pub fn get(&self, cid: Cid) -> Option<&T> {
        let entry = self.entries.get(cid.slot_idx())?;
        if entry.generation == cid.generation() {
            entry.value.as_ref()
        } else {
            None
        }
    }
    pub fn remove(&mut self, cid: Cid) -> Option<T> {
        self.remove_at(cid, Instant::now())
    }
    fn remove_at(&mut self, cid: Cid, now: Instant) -> Option<T> {
        let index = cid.slot_idx();
        let entry = self.entries.get_mut(index)?;
        if entry.generation != cid.generation() {
            return None;
        }
        let value = entry.value.take()?;
        self.active -= 1;
        if let Some(generation) = entry.generation.checked_add(1) {
            entry.generation = generation;
            entry.next_free = self.free.replace(index);
        } else {
            entry.generation = 1;
            self.quarantine.push_back((index, now));
        }
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarantined_slots_reclaim_after_cooldown_without_unbounded_growth() {
        let mut table = SlabTable::new(1);
        let mut now = Instant::now();
        for _ in 0..3 {
            for _ in 0..255 {
                let cid = table.insert_at((), now).unwrap();
                table.remove_at(cid, now).unwrap();
            }
            now += COOLDOWN;
        }
        assert_eq!(table.entries.len(), 1);
    }
}
