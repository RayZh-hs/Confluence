//! Runtime abstractions decoupling Confluence Core from executors and OS timers.
//!
//! All local deadlines, lease expirations, replay-cache aging, CID quarantine timers,
//! flood-cookie rotation, retry backoffs, and hysteresis timers use the injected
//! monotonic [`Clock`]. Cross-node setup freshness checks (`±30_000 ms`) read Unix
//! epoch milliseconds from [`WallClock`].

pub(crate) mod sync;

use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::time::Duration;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Heap-allocated, `Send`, dynamically dispatched future returned by object-safe runtime and seam traits.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Monotonic timestamp expressed in nanoseconds relative to a [`Clock`]'s origin.
///
/// Timestamps are comparable only within the same [`Clock`] domain.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MonotonicTime(u64);

impl MonotonicTime {
    /// Zero instant at a clock's origin.
    pub const ZERO: Self = Self(0);

    /// Constructs a `MonotonicTime` from raw nanoseconds since clock origin.
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// Returns nanoseconds elapsed since clock origin.
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// Returns whole seconds elapsed since clock origin.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0 / 1_000_000_000
    }

    /// Saturating addition of a [`Duration`].
    #[must_use]
    pub fn saturating_add(self, duration: Duration) -> Self {
        let delta = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        Self(self.0.saturating_add(delta))
    }

    /// Saturating subtraction of a [`Duration`].
    #[must_use]
    pub fn saturating_sub(self, duration: Duration) -> Self {
        let delta = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        Self(self.0.saturating_sub(delta))
    }

    /// Returns the duration elapsed since `earlier`, saturating at [`Duration::ZERO`] if `earlier > self`.
    #[must_use]
    pub const fn saturating_duration_since(self, earlier: Self) -> Duration {
        Duration::from_nanos(self.0.saturating_sub(earlier.0))
    }

    /// Returns `Some(self - earlier)` if `self >= earlier`, or `None` otherwise.
    #[must_use]
    pub const fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
        match self.0.checked_sub(earlier.0) {
            Some(ns) => Some(Duration::from_nanos(ns)),
            None => None,
        }
    }
}

impl fmt::Debug for MonotonicTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MonotonicTime({}ns)", self.0)
    }
}

/// Executor-agnostic monotonic clock and timer driver supplied by the embedding host.
pub trait Clock: Send + Sync + 'static {
    /// Returns the current non-decreasing monotonic timestamp without blocking.
    fn now(&self) -> MonotonicTime;

    /// Returns a future that resolves once `self.now() >= deadline`.
    ///
    /// If `deadline <= self.now()`, the future MUST resolve immediately. Dropping the
    /// future before completion MUST cancel the timer cleanly.
    fn sleep_until(&self, deadline: MonotonicTime) -> BoxFuture<'_, ()>;

    /// Convenience helper sleeping for `duration` relative to `self.now()`.
    fn sleep(&self, duration: Duration) -> BoxFuture<'_, ()> {
        self.sleep_until(self.now().saturating_add(duration))
    }
}

/// Executor-agnostic background task spawner supplied by the embedding host.
pub trait TaskSpawner: Send + Sync + 'static {
    /// Spawns a `'static + Send` background task owned by the host executor.
    fn spawn(&self, task: BoxFuture<'static, ()>);
}

/// Wall-clock source returning Unix epoch milliseconds for cross-node setup freshness (`±30_000 ms`).
pub trait WallClock: Send + Sync + 'static {
    /// Returns the current Unix epoch timestamp in milliseconds.
    fn unix_millis(&self) -> u64;
}

/// Default [`WallClock`] backed by [`std::time::SystemTime`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemWallClock;

impl WallClock for SystemWallClock {
    fn unix_millis(&self) -> u64 {
        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        u64::try_from(dur.as_millis()).unwrap_or(u64::MAX)
    }
}

/// Bundled runtime dependencies injected into scopes and nodes.
#[derive(Clone)]
pub struct Runtime {
    /// Monotonic clock and timer source (shared across all scopes in a `Node`).
    pub clock: Arc<dyn Clock>,
    /// Background task spawner.
    pub spawner: Arc<dyn TaskSpawner>,
    wall_clock: Arc<dyn WallClock>,
}

impl Runtime {
    /// Creates a `Runtime` using [`SystemWallClock`] for cross-node setup freshness.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>, spawner: Arc<dyn TaskSpawner>) -> Self {
        Self {
            clock,
            spawner,
            wall_clock: Arc::new(SystemWallClock),
        }
    }

    /// Replaces the wall-clock provider (useful for deterministic freshness tests).
    #[must_use]
    pub fn with_wall_clock(mut self, wall_clock: Arc<dyn WallClock>) -> Self {
        self.wall_clock = wall_clock;
        self
    }

    /// Reads current Unix epoch milliseconds from the configured [`WallClock`].
    #[must_use]
    pub fn wall_time_ms(&self) -> u64 {
        self.wall_clock.unix_millis()
    }

    /// Returns a reference to the configured [`WallClock`].
    #[must_use]
    pub fn wall_clock(&self) -> &Arc<dyn WallClock> {
        &self.wall_clock
    }
}

impl fmt::Debug for Runtime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Runtime").finish_non_exhaustive()
    }
}
