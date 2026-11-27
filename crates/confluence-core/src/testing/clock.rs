//! Deterministic [`VirtualClock`], [`FixedWallClock`], and [`TestSpawner`] executor.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::Wake;

use crate::runtime::{BoxFuture, Clock, MonotonicTime, Runtime, TaskSpawner, WallClock};

fn lock_unpoisoned<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// VirtualClock
// ---------------------------------------------------------------------------

struct VirtualClockState {
    now: MonotonicTime,
    next_id: u64,
    timers: BTreeMap<(MonotonicTime, u64), Waker>,
}

/// Deterministic monotonic [`Clock`] advancing strictly via explicit [`Self::advance`] calls.
///
/// Timers whose deadline is in the past resolve immediately; dropping a pending sleep future
/// cancels its timer cleanly without waking unrelated tasks.
pub struct VirtualClock {
    state: Mutex<VirtualClockState>,
}

impl VirtualClock {
    /// Creates a `VirtualClock` initialized at `MonotonicTime::ZERO`.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(VirtualClockState {
                now: MonotonicTime::ZERO,
                next_id: 1,
                timers: BTreeMap::new(),
            }),
        })
    }

    /// Advances virtual monotonic time by `delta` and wakes every timer whose deadline `<= now`.
    pub fn advance(&self, delta: Duration) {
        let to_wake = {
            let mut st = lock_unpoisoned(&self.state);
            st.now = st.now.saturating_add(delta);
            Self::drain_due_locked(&mut st)
        };
        for waker in to_wake {
            waker.wake();
        }
    }

    /// Advances virtual monotonic time forward to `target` (no-op if `target <= now`).
    pub fn advance_to(&self, target: MonotonicTime) {
        let to_wake = {
            let mut st = lock_unpoisoned(&self.state);
            if target <= st.now {
                return;
            }
            st.now = target;
            Self::drain_due_locked(&mut st)
        };
        for waker in to_wake {
            waker.wake();
        }
    }

    /// Returns the number of currently registered pending timers.
    #[must_use]
    pub fn pending_timers(&self) -> usize {
        lock_unpoisoned(&self.state).timers.len()
    }

    /// Returns the earliest registered pending timer deadline, if any.
    #[must_use]
    pub fn next_timer_deadline(&self) -> Option<MonotonicTime> {
        lock_unpoisoned(&self.state)
            .timers
            .keys()
            .next()
            .map(|&(t, _)| t)
    }

    fn drain_due_locked(st: &mut VirtualClockState) -> Vec<Waker> {
        let now = st.now;
        let due_keys: Vec<(MonotonicTime, u64)> = st
            .timers
            .keys()
            .take_while(|&&(t, _)| t <= now)
            .copied()
            .collect();
        let mut wakers = Vec::with_capacity(due_keys.len());
        for key in due_keys {
            if let Some(w) = st.timers.remove(&key) {
                wakers.push(w);
            }
        }
        wakers
    }
}

struct VirtualSleep<'a> {
    clock: &'a VirtualClock,
    deadline: MonotonicTime,
    id: Option<u64>,
}

impl Future for VirtualSleep<'_> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut st = lock_unpoisoned(&self.clock.state);
        if st.now >= self.deadline {
            if let Some(id) = self.id.take() {
                st.timers.remove(&(self.deadline, id));
            }
            return Poll::Ready(());
        }
        let id = match self.id {
            Some(existing) => existing,
            None => {
                let assigned = st.next_id;
                st.next_id = st.next_id.wrapping_add(1);
                self.id = Some(assigned);
                assigned
            }
        };
        st.timers.insert((self.deadline, id), cx.waker().clone());
        Poll::Pending
    }
}

impl Drop for VirtualSleep<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            let mut st = lock_unpoisoned(&self.clock.state);
            st.timers.remove(&(self.deadline, id));
        }
    }
}

impl Clock for VirtualClock {
    fn now(&self) -> MonotonicTime {
        lock_unpoisoned(&self.state).now
    }

    fn sleep_until(&self, deadline: MonotonicTime) -> BoxFuture<'_, ()> {
        Box::pin(VirtualSleep {
            clock: self,
            deadline,
            id: None,
        })
    }
}

// ---------------------------------------------------------------------------
// FixedWallClock
// ---------------------------------------------------------------------------

/// Controllable Unix epoch millisecond [`WallClock`] for testing freshness windows and clock jumps.
pub struct FixedWallClock {
    millis: AtomicU64,
}

impl FixedWallClock {
    /// Creates a `FixedWallClock` initialized to `unix_millis`.
    #[must_use]
    pub fn new(unix_millis: u64) -> Arc<Self> {
        Arc::new(Self {
            millis: AtomicU64::new(unix_millis),
        })
    }

    /// Sets the wall clock directly to `unix_millis`.
    pub fn set(&self, unix_millis: u64) {
        self.millis.store(unix_millis, Ordering::Release);
    }

    /// Advances the wall clock forward by `delta_ms`.
    pub fn advance_ms(&self, delta_ms: u64) {
        self.millis.fetch_add(delta_ms, Ordering::AcqRel);
    }

    /// Steps the wall clock backward by `delta_ms` (saturating at 0).
    pub fn step_back_ms(&self, delta_ms: u64) {
        let mut current = self.millis.load(Ordering::Acquire);
        loop {
            let next = current.saturating_sub(delta_ms);
            match self.millis.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }
}

impl WallClock for FixedWallClock {
    fn unix_millis(&self) -> u64 {
        self.millis.load(Ordering::Acquire)
    }
}

// ---------------------------------------------------------------------------
// TestSpawner (Deterministic Safe Rust Executor)
// ---------------------------------------------------------------------------

struct TaskNode {
    future: Mutex<Option<BoxFuture<'static, ()>>>,
    queued: AtomicBool,
    queue: Weak<Mutex<VecDeque<Arc<TaskNode>>>>,
}

impl Wake for TaskNode {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if !self.queued.swap(true, Ordering::AcqRel) {
            if let Some(q) = self.queue.upgrade() {
                lock_unpoisoned(&q).push_back(Arc::clone(self));
            }
        }
    }
}

struct RootWaker(AtomicBool);

impl Wake for RootWaker {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::Release);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::Release);
    }
}

/// Deterministic executor implementing [`TaskSpawner`] with zero OS threads or external runtimes.
pub struct TestSpawner {
    queue: Arc<Mutex<VecDeque<Arc<TaskNode>>>>,
    spawned: AtomicU64,
}

impl TestSpawner {
    /// Creates an empty `TestSpawner`.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            queue: Arc::new(Mutex::new(VecDeque::new())),
            spawned: AtomicU64::new(0),
        })
    }

    /// Returns the total number of tasks ever spawned onto this executor.
    #[must_use]
    pub fn spawn_count(&self) -> u64 {
        self.spawned.load(Ordering::Relaxed)
    }

    /// Polls all ready tasks in FIFO order until no ready tasks remain, returning poll count.
    pub fn drive_until_idle(&self) -> usize {
        let mut polls = 0usize;
        loop {
            let task = { lock_unpoisoned(&self.queue).pop_front() };
            let Some(task) = task else {
                break;
            };
            task.queued.store(false, Ordering::Release);
            let mut slot = lock_unpoisoned(&task.future);
            let Some(mut fut) = slot.take() else {
                continue;
            };
            drop(slot);

            let waker = Waker::from(Arc::clone(&task));
            let mut cx = Context::from_waker(&waker);
            polls += 1;
            if fut.as_mut().poll(&mut cx).is_pending() {
                let mut slot = lock_unpoisoned(&task.future);
                *slot = Some(fut);
            }
        }
        polls
    }

    /// Polls `fut` interleaved with [`Self::drive_until_idle`] until `fut` resolves or all
    /// tasks become idle (returning `None` if `fut` remains pending with no woken tasks).
    pub fn try_block_on<F: Future>(&self, fut: F) -> Option<F::Output> {
        let mut fut = core::pin::pin!(fut);
        let root_flag = Arc::new(RootWaker(AtomicBool::new(true)));
        let waker = Waker::from(Arc::clone(&root_flag));
        let mut cx = Context::from_waker(&waker);

        loop {
            if root_flag.0.swap(false, Ordering::AcqRel) {
                if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                    self.drive_until_idle();
                    return Some(out);
                }
            }
            let polls = self.drive_until_idle();
            if polls == 0 && !root_flag.0.load(Ordering::Acquire) {
                return None;
            }
        }
    }
}

impl TaskSpawner for TestSpawner {
    fn spawn(&self, task: BoxFuture<'static, ()>) {
        self.spawned.fetch_add(1, Ordering::Relaxed);
        let node = Arc::new(TaskNode {
            future: Mutex::new(Some(task)),
            queued: AtomicBool::new(true),
            queue: Arc::downgrade(&self.queue),
        });
        lock_unpoisoned(&self.queue).push_back(node);
    }
}

/// Convenience bundle combining [`VirtualClock`], [`TestSpawner`], [`FixedWallClock`], and [`Runtime`].
#[derive(Clone)]
pub struct TestRuntime {
    /// Deterministic monotonic clock.
    pub clock: Arc<VirtualClock>,
    /// Deterministic single-steppable executor.
    pub spawner: Arc<TestSpawner>,
    /// Controllable Unix-millisecond wall clock.
    pub wall_clock: Arc<FixedWallClock>,
    /// Pre-wired [`Runtime`] injecting all three test primitives.
    pub runtime: Runtime,
}

impl TestRuntime {
    /// Creates a `TestRuntime` initialized at `MonotonicTime::ZERO` and wall time `1_700_000_000_000 ms`.
    #[must_use]
    pub fn new() -> Self {
        let clock = VirtualClock::new();
        let spawner = TestSpawner::new();
        let wall_clock = FixedWallClock::new(1_700_000_000_000);
        let runtime = Runtime::new(clock.clone(), spawner.clone())
            .with_wall_clock(wall_clock.clone());
        Self {
            clock,
            spawner,
            wall_clock,
            runtime,
        }
    }

    /// Drives all ready spawned tasks until idle.
    pub fn drive_until_idle(&self) -> usize {
        self.spawner.drive_until_idle()
    }

    /// Advances virtual monotonic time by `delta` and drives all newly woken tasks until idle.
    pub fn advance_and_drive(&self, delta: Duration) -> usize {
        self.clock.advance(delta);
        self.spawner.drive_until_idle()
    }
}

impl Default for TestRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn virtual_clock_past_deadline_and_drop_cancellation() {
        let rt = TestRuntime::new();
        assert_eq!(rt.clock.now(), MonotonicTime::ZERO);

        // Past/current deadline resolves immediately without registering a timer.
        assert_eq!(
            rt.spawner.try_block_on(rt.clock.sleep_until(MonotonicTime::ZERO)),
            Some(())
        );
        assert_eq!(rt.clock.pending_timers(), 0);

        // Dropping a pending sleep future cancels its timer cleanly.
        let mut sleep = rt.clock.sleep(Duration::from_secs(5));
        let flag = Arc::new(RootWaker(AtomicBool::new(false)));
        let waker = Waker::from(flag);
        let mut cx = Context::from_waker(&waker);
        assert!(sleep.as_mut().poll(&mut cx).is_pending());
        assert_eq!(rt.clock.pending_timers(), 1);
        drop(sleep);
        assert_eq!(rt.clock.pending_timers(), 0);

        // Wall clock step back does not affect monotonic clock.
        rt.wall_clock.step_back_ms(60_000);
        assert_eq!(rt.wall_clock.unix_millis(), 1_700_000_000_000 - 60_000);
        assert_eq!(rt.clock.now(), MonotonicTime::ZERO);
    }
}
