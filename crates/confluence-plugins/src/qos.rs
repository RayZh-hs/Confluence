//! Out-of-core QoS primitives (`QosLimits`, `RateBucket`, `RateGate`, `ConcurrencyLimiter`,
//! `QosAuthorizer`) enforcing per-circuit or aggregate per-peer byte rates, datagram-per-second
//! caps, and concurrent session limits via [`confluence_core::Lease`] (`TrafficGate` + RAII
//! `SessionGuard`)—keeping QoS algorithms completely outside `confluence-core`.

use confluence_core::{
    AuthDenied, AuthRequest, Authorizer, BoxFut, DatagramAction, Direction, Lease, Plane,
    PublicKey, Revocation, STREAM_CHUNK, StreamAction, TrafficGate,
};
use parking_lot::Mutex;
use std::{
    collections::HashMap,
    hash::Hash,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::broadcast;

/// Traffic-shaping and concurrency limits enforced out-of-core via [`RateGate`] and
/// [`ConcurrencyLimiter`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QosLimits {
    /// Sustained byte rate limit in bytes/sec (`0` = unlimited).
    pub max_bytes_per_sec: u64,
    /// Sustained discrete datagram rate limit in messages/sec (`0` = unlimited).
    pub max_datagrams_per_sec: u64,
    /// Maximum concurrent streams allowed (`0` = unlimited).
    pub max_concurrent_streams: u32,
}

impl QosLimits {
    /// Returns `true` if no QoS bounds are configured.
    pub const fn is_unlimited(self) -> bool {
        self.max_bytes_per_sec == 0
            && self.max_datagrams_per_sec == 0
            && self.max_concurrent_streams == 0
    }

    /// Returns `true` if a byte-rate or datagram-PPS limit is configured.
    pub const fn has_rate_limit(self) -> bool {
        self.max_bytes_per_sec > 0 || self.max_datagrams_per_sec > 0
    }

    /// Computes the tightest non-zero intersection of two [`QosLimits`].
    pub const fn intersect(self, other: Self) -> Self {
        Self {
            max_bytes_per_sec: min_nonzero_u64(self.max_bytes_per_sec, other.max_bytes_per_sec),
            max_datagrams_per_sec: min_nonzero_u64(
                self.max_datagrams_per_sec,
                other.max_datagrams_per_sec,
            ),
            max_concurrent_streams: min_nonzero_u32(
                self.max_concurrent_streams,
                other.max_concurrent_streams,
            ),
        }
    }
}

const fn min_nonzero_u64(a: u64, b: u64) -> u64 {
    match (a, b) {
        (0, r) => r,
        (l, 0) => l,
        (l, r) => {
            if l < r {
                l
            } else {
                r
            }
        }
    }
}

const fn min_nonzero_u32(a: u32, b: u32) -> u32 {
    match (a, b) {
        (0, r) => r,
        (l, 0) => l,
        (l, r) => {
            if l < r {
                l
            } else {
                r
            }
        }
    }
}

fn clock_ns() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

/// Lock-free virtual-time (GCRA) byte and datagram-PPS token bucket.
pub struct RateBucket {
    rate_bps: u64,
    finish_ns: AtomicU64,
    dg_rate_pps: u64,
    dg_finish_ns: AtomicU64,
}

impl RateBucket {
    pub fn new(limits: QosLimits) -> Self {
        Self {
            rate_bps: limits.max_bytes_per_sec,
            finish_ns: AtomicU64::new(0),
            dg_rate_pps: limits.max_datagrams_per_sec,
            dg_finish_ns: AtomicU64::new(0),
        }
    }

    #[inline]
    fn byte_time_ns(&self, count: usize) -> u64 {
        (count as u128 * 1_000_000_000)
            .div_ceil(u128::from(self.rate_bps))
            .min(u128::from(u64::MAX)) as u64
    }

    #[inline]
    fn byte_burst_ns(&self, bytes: usize) -> u64 {
        let burst_bytes = STREAM_CHUNK
            .min(usize::try_from(self.rate_bps).unwrap_or(usize::MAX))
            .max(bytes);
        self.byte_time_ns(burst_bytes)
    }

    /// Virtual-time stream pacer: atomically commits `bytes` to the schedule and returns
    /// `None` if within burst or `Some(delay)` specifying how long to wait before forwarding.
    pub fn pace_bytes(&self, bytes: usize) -> Option<Duration> {
        if self.rate_bps == 0 || bytes == 0 {
            return None;
        }
        let step = self.byte_time_ns(bytes);
        let burst = self.byte_burst_ns(bytes);
        let mut last = self.finish_ns.load(Ordering::Relaxed);
        loop {
            let now = clock_ns();
            let finish = last.max(now).saturating_add(step);
            match self.finish_ns.compare_exchange_weak(
                last,
                finish,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    let available_by = now.saturating_add(burst);
                    return (finish > available_by)
                        .then(|| Duration::from_nanos(finish - available_by));
                }
                Err(next) => last = next,
            }
        }
    }

    /// Non-blocking byte-rate deduction for discrete datagrams (does not charge on reject).
    pub fn allow_bytes(&self, bytes: usize) -> bool {
        if self.rate_bps == 0 || bytes == 0 {
            return true;
        }
        let step = self.byte_time_ns(bytes);
        let burst = self.byte_burst_ns(bytes);
        let mut last = self.finish_ns.load(Ordering::Relaxed);
        loop {
            let now = clock_ns();
            let finish = last.max(now).saturating_add(step);
            let available_by = now.saturating_add(burst);
            if finish > available_by {
                return false;
            }
            match self.finish_ns.compare_exchange_weak(
                last,
                finish,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(next) => last = next,
            }
        }
    }

    /// Non-blocking datagram check enforcing both `max_datagrams_per_sec` and `max_bytes_per_sec`.
    pub fn allow_datagram(&self, bytes: usize) -> bool {
        if self.dg_rate_pps > 0 {
            let step = 1_000_000_000u128
                .div_ceil(u128::from(self.dg_rate_pps))
                .min(u128::from(u64::MAX)) as u64;
            let burst = 1_000_000_000u64.max(step);
            let mut last = self.dg_finish_ns.load(Ordering::Relaxed);
            loop {
                let now = clock_ns();
                let finish = last.max(now).saturating_add(step);
                let available_by = now.saturating_add(burst);
                if finish > available_by {
                    return false;
                }
                match self.dg_finish_ns.compare_exchange_weak(
                    last,
                    finish,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(next) => last = next,
                }
            }
        }
        self.allow_bytes(bytes)
    }
}

enum GateBuckets {
    Shared(RateBucket),
    Directional {
        ingress: RateBucket,
        egress: RateBucket,
    },
}

/// Out-of-core [`TrafficGate`] backed by lock-free [`RateBucket`]s.
///
/// Attach per-session (`lease.with_gate(RateGate::new(limits))`) for per-circuit shaping, or share
/// one `Arc<RateGate>` across sessions (`lease.with_arc_gate(peer_gate)`) for aggregate per-peer
/// or per-target limits.
pub struct RateGate {
    buckets: GateBuckets,
}

impl RateGate {
    /// Creates a bidirectional [`RateGate`] enforcing `limits` across ingress and egress combined.
    pub fn new(limits: QosLimits) -> Self {
        Self {
            buckets: GateBuckets::Shared(RateBucket::new(limits)),
        }
    }

    /// Creates a directional [`RateGate`] with independent ingress and egress limits.
    pub fn directional(ingress: QosLimits, egress: QosLimits) -> Self {
        Self {
            buckets: GateBuckets::Directional {
                ingress: RateBucket::new(ingress),
                egress: RateBucket::new(egress),
            },
        }
    }

    #[inline]
    fn bucket(&self, dir: Direction) -> &RateBucket {
        match &self.buckets {
            GateBuckets::Shared(bucket) => bucket,
            GateBuckets::Directional { ingress, egress } => match dir {
                Direction::Ingress => ingress,
                Direction::Egress => egress,
            },
        }
    }
}

impl TrafficGate for RateGate {
    fn check_datagram(&self, dir: Direction, bytes: usize) -> DatagramAction {
        if self.bucket(dir).allow_datagram(bytes) {
            DatagramAction::Allow
        } else {
            DatagramAction::Drop
        }
    }

    fn charge_stream(&self, dir: Direction, bytes: usize) -> StreamAction {
        match self.bucket(dir).pace_bytes(bytes) {
            None => StreamAction::Allow,
            Some(delay) => StreamAction::Delay(delay),
        }
    }
}

/// Out-of-core per-key concurrency limiter producing RAII [`SessionSlot`] guards attached to
/// [`Lease::with_guard`]. Works symmetrically for both Stream and Datagram planes and for both
/// Endpoints and Transits.
pub struct ConcurrencyLimiter<K = PublicKey> {
    counts: Mutex<HashMap<K, u32>>,
}

impl<K> Default for ConcurrencyLimiter<K> {
    fn default() -> Self {
        Self {
            counts: Mutex::new(HashMap::new()),
        }
    }
}

impl<K: Eq + Hash + Clone + Send + Sync + 'static> ConcurrencyLimiter<K> {
    /// Creates an empty concurrency limiter.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Returns the number of currently active sessions tracked for `key`.
    pub fn active(&self, key: &K) -> u32 {
        self.counts.lock().get(key).copied().unwrap_or(0)
    }

    /// Enforces `max` concurrent sessions for `key`:
    /// - When `max == 0`: unlimited, returns `Ok(None)`.
    /// - On initial setup (`is_renewal == false`): reserves a slot or fails with [`AuthDenied::Busy`].
    /// - On in-band renewal (`is_renewal == true`): does *not* double-count the already-held slot
    ///   (which stays alive inside `LeaseHandle`), and fails with [`AuthDenied::Busy`] only if the
    ///   active count now exceeds a lowered `max`.
    pub fn acquire(
        self: &Arc<Self>,
        key: K,
        max: u32,
        is_renewal: bool,
    ) -> Result<Option<SessionSlot<K>>, AuthDenied> {
        if max == 0 {
            return Ok(None);
        }
        let mut counts = self.counts.lock();
        if is_renewal {
            let active = counts.get(&key).copied().unwrap_or(0);
            if active > max {
                return Err(AuthDenied::Busy);
            }
            return Ok(None);
        }
        let entry = counts.entry(key.clone()).or_default();
        if *entry >= max {
            return Err(AuthDenied::Busy);
        }
        *entry += 1;
        Ok(Some(SessionSlot {
            limiter: self.clone(),
            key,
        }))
    }
}

/// RAII concurrency permit held inside [`confluence_core::LeaseHandle`] across renewals and
/// automatically released when the session or circuit terminates.
pub struct SessionSlot<K: Eq + Hash + Send + Sync + 'static = PublicKey> {
    limiter: Arc<ConcurrencyLimiter<K>>,
    key: K,
}

impl<K: Eq + Hash + Send + Sync + 'static> Drop for SessionSlot<K> {
    fn drop(&mut self) {
        let mut counts = self.limiter.counts.lock();
        if let Some(count) = counts.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.key);
            }
        }
    }
}

type ConcurrencyKey = (PublicKey, Plane, String);

/// Composable [`Authorizer`] combinator attaching out-of-core [`RateGate`] and
/// [`ConcurrencyLimiter`] enforcement directly onto the [`Lease`] returned by any inner `A`.
///
/// Works identically for Stream & Datagram Endpoints and Named Transits with zero handler wrapping.
pub struct QosAuthorizer<A, F = fn(&AuthRequest<'_>, &Lease) -> QosLimits> {
    inner: Arc<A>,
    extract: F,
    limiter: Arc<ConcurrencyLimiter<ConcurrencyKey>>,
}

/// Default extractor reading [`QosLimits`] from `Lease::context::<QosLimits>()`.
pub fn qos_from_lease(_req: &AuthRequest<'_>, lease: &Lease) -> QosLimits {
    lease.context::<QosLimits>().map(|l| *l).unwrap_or_default()
}

impl<A> QosAuthorizer<A, fn(&AuthRequest<'_>, &Lease) -> QosLimits> {
    /// Wraps `inner`, extracting [`QosLimits`] directly from `Lease::context::<QosLimits>()`.
    pub fn from_lease(inner: Arc<A>) -> Self {
        Self::new(inner, qos_from_lease)
    }
}

impl<A, F> QosAuthorizer<A, F>
where
    F: Fn(&AuthRequest<'_>, &Lease) -> QosLimits + Send + Sync + 'static,
{
    /// Wraps `inner`, deriving [`QosLimits`] via `extract(&req, &lease)` on every control event.
    pub fn new(inner: Arc<A>, extract: F) -> Self {
        Self {
            inner,
            extract,
            limiter: ConcurrencyLimiter::new(),
        }
    }
}

impl<A, F> Authorizer for QosAuthorizer<A, F>
where
    A: Authorizer,
    F: Fn(&AuthRequest<'_>, &Lease) -> QosLimits + Send + Sync + 'static,
{
    fn authorize<'a>(&'a self, req: AuthRequest<'a>) -> BoxFut<'a, Result<Lease, AuthDenied>> {
        Box::pin(async move {
            let mut lease = self.inner.authorize(req).await?;
            let limits = (self.extract)(&req, &lease);
            if req.target.plane() == Plane::Stream && limits.max_concurrent_streams > 0 {
                let key = (req.peer, req.target.plane(), req.target.name().to_owned());
                if let Some(slot) =
                    self.limiter
                        .acquire(key, limits.max_concurrent_streams, req.is_renewal)?
                {
                    lease = lease.with_guard(slot);
                }
            }
            if limits.has_rate_limit() {
                lease = lease.with_gate(RateGate::new(limits));
            }
            Ok(lease)
        })
    }

    fn revocation_streams(&self) -> Vec<broadcast::Receiver<Revocation>> {
        self.inner.revocation_streams()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_bucket_enforces_pps_and_stream_pacing() {
        let pps = RateBucket::new(QosLimits {
            max_bytes_per_sec: 0,
            max_datagrams_per_sec: 5,
            max_concurrent_streams: 0,
        });
        let allowed = (0..20).filter(|_| pps.allow_datagram(64)).count();
        assert_eq!(allowed, 5);

        let bps = RateBucket::new(QosLimits {
            max_bytes_per_sec: 4000,
            max_datagrams_per_sec: 0,
            max_concurrent_streams: 0,
        });
        // First 4000B fits within 1s burst; second 4000B commits and schedules ~1s delay.
        assert_eq!(bps.pace_bytes(4000), None);
        let delay = bps.pace_bytes(4000).expect("second chunk must be paced");
        assert!(delay >= Duration::from_millis(900));
    }

    #[test]
    fn concurrency_limiter_handles_setup_renewal_shrink_and_drop() {
        let limiter = ConcurrencyLimiter::new();
        let peer = PublicKey([1; 32]);

        let s1 = limiter.acquire(peer, 2, false).unwrap().unwrap();
        let s2 = limiter.acquire(peer, 2, false).unwrap().unwrap();
        assert_eq!(limiter.active(&peer), 2);
        // 3rd setup fails with AuthDenied::Busy.
        assert_eq!(
            limiter.acquire(peer, 2, false).err(),
            Some(AuthDenied::Busy)
        );
        // Renewal under max=2 does not double-count.
        assert!(limiter.acquire(peer, 2, true).unwrap().is_none());
        // Renewal when limit shrinks to 1 rejects excess session.
        assert_eq!(limiter.acquire(peer, 1, true).err(), Some(AuthDenied::Busy));
        drop(s1);
        assert_eq!(limiter.active(&peer), 1);
        // Now renewal under max=1 passes cleanly.
        assert!(limiter.acquire(peer, 1, true).unwrap().is_none());
        drop(s2);
        assert_eq!(limiter.active(&peer), 0);
    }
}
