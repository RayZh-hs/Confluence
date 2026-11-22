use std::{
    collections::HashMap,
    hash::{DefaultHasher, Hash, Hasher},
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::watch;

use crate::{CoreErr, PublicKey, STREAM_CHUNK, ScopeId};

pub const MAX_GRANT_TTL: Duration = Duration::from_secs(3600);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantSpec {
    pub ttl: Duration,
    /// Bytes per second. Zero means unlimited.
    pub rate_bps: u64,
}
impl GrantSpec {
    pub fn new(ttl: Duration, rate_bps: u64) -> Self {
        Self { ttl, rate_bps }
    }
    pub(crate) fn validate(self) -> Result<Self, CoreErr> {
        if self.ttl.as_millis() == 0 || self.ttl > MAX_GRANT_TTL {
            return Err(CoreErr::Denied);
        }
        Ok(self)
    }
    pub(crate) fn to_wire(self) -> [u8; 16] {
        crate::wire::e2e::grant_bytes(self.ttl.as_millis() as u64, self.rate_bps)
    }
    pub(crate) fn from_wire(buf: &[u8]) -> Result<Self, CoreErr> {
        let (ttl, rate) = crate::wire::e2e::parse_grant(buf)?;
        Self::new(Duration::from_millis(ttl), rate).validate()
    }
}
fn clock_ns() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

/// A virtual-time token bucket. The refill timestamp and charge live in a
/// single CAS word, so racing packets cannot claim the same credit twice.
#[repr(align(64))]
pub struct GrantEnforcer {
    expires_at: AtomicU64,
    rate_bps: AtomicU64,
    finish_ns: AtomicU64,
    revoked: std::sync::atomic::AtomicBool,
    changes: watch::Sender<Option<CoreErr>>,
}
impl GrantEnforcer {
    pub fn new(grant: GrantSpec) -> Result<Self, CoreErr> {
        let grant = grant.validate()?;
        Ok(Self {
            expires_at: AtomicU64::new(clock_ns().saturating_add(grant.ttl.as_nanos() as u64)),
            rate_bps: AtomicU64::new(grant.rate_bps),
            finish_ns: AtomicU64::new(0),
            revoked: false.into(),
            changes: watch::channel(None).0,
        })
    }
    pub fn renew(&self, grant: GrantSpec) -> Result<(), CoreErr> {
        let grant = grant.validate()?;
        self.remaining()?;
        self.rate_bps.store(grant.rate_bps, Ordering::Release);
        self.expires_at.store(
            clock_ns().saturating_add(grant.ttl.as_nanos() as u64),
            Ordering::Release,
        );
        self.changes.send_modify(|_| {});
        Ok(())
    }
    pub fn revoke(&self, reason: CoreErr) {
        if !self.revoked.swap(true, Ordering::AcqRel) {
            self.changes.send_replace(Some(reason));
        }
    }
    pub fn remaining(&self) -> Result<Duration, CoreErr> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(self.changes.borrow().clone().unwrap_or(CoreErr::Revoked));
        }
        self.expires_at
            .load(Ordering::Acquire)
            .checked_sub(clock_ns())
            .filter(|time| *time > 0)
            .map(Duration::from_nanos)
            .ok_or(CoreErr::Expired)
    }
    pub fn check_and_deduct(&self, bytes: usize) -> bool {
        matches!(self.charge(bytes), Ok(None))
    }
    fn charge(&self, bytes: usize) -> Result<Option<Duration>, CoreErr> {
        self.remaining()?;
        let mut last = self.finish_ns.load(Ordering::Relaxed);
        loop {
            let rate = self.rate_bps.load(Ordering::Acquire);
            if rate == 0 || bytes == 0 {
                return Ok(None);
            }
            let now = clock_ns();
            let time = |count: usize| {
                (count as u128 * 1_000_000_000)
                    .div_ceil(u128::from(rate))
                    .min(u128::from(u64::MAX)) as u64
            };
            let burst = time(STREAM_CHUNK.max(bytes));
            let finish = last.max(now).saturating_add(time(bytes));
            let available_by = now.saturating_add(burst);
            if finish > available_by {
                return Ok(Some(Duration::from_nanos(finish - available_by)));
            }
            match self.finish_ns.compare_exchange_weak(
                last,
                finish,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.remaining()?;
                    return Ok(None);
                }
                Err(next) => last = next,
            }
        }
    }
    pub(crate) async fn wait_charge(&self, bytes: usize) -> Result<(), CoreErr> {
        let mut changes = self.changes.subscribe();
        while let Some(delay) = self.charge(bytes)? {
            let remaining = self.remaining()?;
            let _ = tokio::time::timeout(delay.min(remaining), changes.changed()).await;
        }
        Ok(())
    }
    pub async fn cancelled(&self) -> CoreErr {
        let mut changes = self.changes.subscribe();
        loop {
            match self.remaining() {
                Err(error) => return error,
                Ok(remaining) => {
                    let _ = tokio::time::timeout(remaining, changes.changed()).await;
                }
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum RevocationKey {
    Peer(ScopeId, PublicKey),
    Endpoint(ScopeId, String),
}
type Shard = Mutex<HashMap<RevocationKey, Vec<Weak<GrantEnforcer>>>>;

#[derive(Default)]
pub struct RevocationIndex {
    shards: [Shard; 16],
}
impl RevocationIndex {
    fn shard(&self, key: &RevocationKey) -> &Shard {
        let mut hash = DefaultHasher::new();
        key.hash(&mut hash);
        &self.shards[hash.finish() as usize % self.shards.len()]
    }
    pub fn track(&self, key: RevocationKey, grant: &Arc<GrantEnforcer>) {
        let mut shard = self.shard(&key).lock().unwrap();
        // Prune inactive names/peers periodically on registration as well as on
        // revocation so a long-lived node doesn't retain historical identities.
        if !shard.contains_key(&key) && shard.len() >= 128 {
            shard.retain(|_, grants| {
                grants.retain(|grant| grant.strong_count() != 0);
                !grants.is_empty()
            });
        }
        let grants = shard.entry(key).or_default();
        grants.retain(|grant| grant.strong_count() != 0);
        grants.push(Arc::downgrade(grant));
    }
    pub fn revoke(&self, key: &RevocationKey, reason: CoreErr) {
        let grants = self
            .shard(key)
            .lock()
            .unwrap()
            .remove(key)
            .unwrap_or_default();
        for grant in grants.into_iter().filter_map(|grant| grant.upgrade()) {
            grant.revoke(reason.clone());
        }
    }
}

impl RevocationIndex {
    pub(crate) fn invalidate(&self) {
        for shard in &self.shards {
            let grants = std::mem::take(&mut *shard.lock().unwrap());
            for grant in grants
                .into_values()
                .flatten()
                .filter_map(|grant| grant.upgrade())
            {
                grant.revoke(CoreErr::Revoked);
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contention_cannot_spend_the_same_bucket_credit_twice() {
        let grant = GrantEnforcer::new(GrantSpec::new(Duration::from_secs(30), 1)).unwrap();
        let spent = std::thread::scope(|threads| {
            let workers: Vec<_> = (0..8)
                .map(|_| threads.spawn(|| (0..32).filter(|_| grant.check_and_deduct(256)).count()))
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .sum::<usize>()
        });
        assert_eq!(spent * 256, STREAM_CHUNK);
    }
}
