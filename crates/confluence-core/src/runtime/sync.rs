//! Runtime-independent synchronization primitives owned by `confluence-core`.
//!
//! None of these wrappers leak third-party channel or lock types into public signatures.

use core::future::{Future, poll_fn};
use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_broadcast::{InactiveReceiver, Receiver as BcReceiver, Sender as BcSender};
use async_lock::{Semaphore, SemaphoreGuardArc};
use event_listener::{Event, EventListener};

use crate::error::CoreError;

fn lock_unpoisoned<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// CloseableSemaphore
// ---------------------------------------------------------------------------

/// Executor-agnostic bounded semaphore that supports atomic shutdown (`close()`),
/// immediately waking all waiting acquirers with [`CoreError::Closed`].
pub(crate) struct CloseableSemaphore {
    sem: Arc<Semaphore>,
    capacity: usize,
    in_use: AtomicUsize,
    closed: AtomicBool,
    close_event: Event,
}

/// RAII permit acquired from a [`CloseableSemaphore`].
pub(crate) struct SemaphorePermit {
    parent: Arc<CloseableSemaphore>,
    _guard: SemaphoreGuardArc,
}

impl Drop for SemaphorePermit {
    fn drop(&mut self) {
        self.parent.in_use.fetch_sub(1, Ordering::AcqRel);
    }
}

#[allow(dead_code)]
impl CloseableSemaphore {
    /// Creates a new open semaphore with `capacity` permits (clamped to at least 1).
    pub fn new(capacity: usize) -> Arc<Self> {
        let cap = capacity.max(1);
        Arc::new(Self {
            sem: Arc::new(Semaphore::new(cap)),
            capacity: cap,
            in_use: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            close_event: Event::new(),
        })
    }

    /// Closes the semaphore and immediately wakes all blocked [`Self::acquire`] callers.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.close_event.notify(usize::MAX);
    }

    /// Returns `true` after [`Self::close`] has been called.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Returns the total configured capacity.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the number of currently held permits.
    pub fn in_use(&self) -> usize {
        self.in_use.load(Ordering::Acquire)
    }

    /// Returns the number of currently available permits.
    pub fn available(&self) -> usize {
        self.capacity.saturating_sub(self.in_use())
    }

    /// Non-blocking permit acquisition.
    ///
    /// Returns [`CoreError::Closed`] if closed, or [`CoreError::Busy`] if saturated.
    pub fn try_acquire(self: &Arc<Self>) -> Result<SemaphorePermit, CoreError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(CoreError::Closed);
        }
        let Some(guard) = self.sem.try_acquire_arc() else {
            return if self.closed.load(Ordering::Acquire) {
                Err(CoreError::Closed)
            } else {
                Err(CoreError::Busy)
            };
        };
        // Dekker ordering against `close()` so `in_use == 0` after `close()` is never observed
        // prematurely while a permit is being handed out.
        self.in_use.fetch_add(1, Ordering::SeqCst);
        if self.closed.load(Ordering::SeqCst) {
            self.in_use.fetch_sub(1, Ordering::AcqRel);
            drop(guard);
            return Err(CoreError::Closed);
        }
        Ok(SemaphorePermit {
            parent: Arc::clone(self),
            _guard: guard,
        })
    }

    /// Asynchronously acquires a permit, aborting immediately with [`CoreError::Closed`]
    /// if the semaphore closes while waiting.
    pub async fn acquire(self: &Arc<Self>) -> Result<SemaphorePermit, CoreError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(CoreError::Closed);
        }

        let mut acq_fut = Box::pin(self.sem.acquire_arc());
        let mut close_listener: Option<EventListener> = None;

        let guard = poll_fn(|cx: &mut Context<'_>| {
            if self.closed.load(Ordering::Acquire) {
                return Poll::Ready(Err(CoreError::Closed));
            }
            if let Poll::Ready(guard) = acq_fut.as_mut().poll(cx) {
                return Poll::Ready(Ok(guard));
            }
            loop {
                let listener = close_listener.get_or_insert_with(|| self.close_event.listen());
                if self.closed.load(Ordering::Acquire) {
                    return Poll::Ready(Err(CoreError::Closed));
                }
                match Pin::new(listener).poll(cx) {
                    Poll::Ready(()) => {
                        close_listener = None;
                        if self.closed.load(Ordering::Acquire) {
                            return Poll::Ready(Err(CoreError::Closed));
                        }
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await?;

        self.in_use.fetch_add(1, Ordering::SeqCst);
        if self.closed.load(Ordering::SeqCst) {
            self.in_use.fetch_sub(1, Ordering::AcqRel);
            drop(guard);
            return Err(CoreError::Closed);
        }

        Ok(SemaphorePermit {
            parent: Arc::clone(self),
            _guard: guard,
        })
    }
}

// ---------------------------------------------------------------------------
// Watch<T> / WatchReceiver<T>
// ---------------------------------------------------------------------------

struct WatchState<T> {
    value: T,
    version: u64,
    senders: usize,
}

struct WatchInner<T> {
    state: Mutex<WatchState<T>>,
    event: Event,
}

/// Runtime-independent single-value watch publisher notifying all subscribers on update.
pub(crate) struct Watch<T> {
    inner: Arc<WatchInner<T>>,
}

/// Subscriber handle observing updates published through a [`Watch<T>`].
pub(crate) struct WatchReceiver<T> {
    inner: Arc<WatchInner<T>>,
    seen_version: u64,
}

#[allow(dead_code)]
impl<T> Watch<T> {
    /// Creates a watch pair initialized to `initial`.
    pub fn new(initial: T) -> (Self, WatchReceiver<T>) {
        let inner = Arc::new(WatchInner {
            state: Mutex::new(WatchState {
                value: initial,
                version: 0,
                senders: 1,
            }),
            event: Event::new(),
        });
        let rx = WatchReceiver {
            inner: Arc::clone(&inner),
            seen_version: 0,
        };
        (Self { inner }, rx)
    }

    /// Publishes a new value and wakes all waiting receivers.
    pub fn send(&self, value: T) {
        {
            let mut st = lock_unpoisoned(&self.inner.state);
            st.value = value;
            st.version = st.version.wrapping_add(1);
        }
        self.inner.event.notify(usize::MAX);
    }

    /// Mutates the value in place and notifies receivers iff `f` returns `true`.
    pub fn send_if_modified(&self, f: impl FnOnce(&mut T) -> bool) -> bool {
        let modified = {
            let mut st = lock_unpoisoned(&self.inner.state);
            if f(&mut st.value) {
                st.version = st.version.wrapping_add(1);
                true
            } else {
                false
            }
        };
        if modified {
            self.inner.event.notify(usize::MAX);
        }
        modified
    }

    /// Reads the current value by closure without cloning.
    pub fn borrow_with<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        let st = lock_unpoisoned(&self.inner.state);
        f(&st.value)
    }

    /// Creates a new [`WatchReceiver`] positioned at the current version.
    pub fn subscribe(&self) -> WatchReceiver<T> {
        let version = lock_unpoisoned(&self.inner.state).version;
        WatchReceiver {
            inner: Arc::clone(&self.inner),
            seen_version: version,
        }
    }
}

impl<T: Clone> Watch<T> {
    /// Returns a clone of the current value.
    pub fn borrow_cloned(&self) -> T {
        lock_unpoisoned(&self.inner.state).value.clone()
    }
}

impl<T> Clone for Watch<T> {
    fn clone(&self) -> Self {
        {
            let mut st = lock_unpoisoned(&self.inner.state);
            st.senders = st.senders.saturating_add(1);
        }
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T> Drop for Watch<T> {
    fn drop(&mut self) {
        let notify = {
            let mut st = lock_unpoisoned(&self.inner.state);
            st.senders = st.senders.saturating_sub(1);
            st.senders == 0
        };
        if notify {
            self.inner.event.notify(usize::MAX);
        }
    }
}

#[allow(dead_code)]
impl<T> WatchReceiver<T> {
    /// Reads the current value via closure.
    pub fn borrow_with<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        let st = lock_unpoisoned(&self.inner.state);
        f(&st.value)
    }

    /// Returns `true` if a newer value has been published since this receiver last marked seen.
    pub fn has_changed(&self) -> bool {
        lock_unpoisoned(&self.inner.state).version != self.seen_version
    }

    /// Marks the current version as seen.
    pub fn mark_seen(&mut self) {
        self.seen_version = lock_unpoisoned(&self.inner.state).version;
    }

    /// Waits for a newer value than last seen.
    ///
    /// Returns `true` when a new value is available (and marks it seen), or `false` if all
    /// [`Watch`] senders have been dropped with no unseen value remaining.
    pub async fn changed(&mut self) -> bool {
        loop {
            {
                let st = lock_unpoisoned(&self.inner.state);
                if st.version != self.seen_version {
                    self.seen_version = st.version;
                    return true;
                }
                if st.senders == 0 {
                    return false;
                }
            }
            let listener = self.inner.event.listen();
            {
                let st = lock_unpoisoned(&self.inner.state);
                if st.version != self.seen_version {
                    self.seen_version = st.version;
                    return true;
                }
                if st.senders == 0 {
                    return false;
                }
            }
            listener.await;
        }
    }
}

impl<T: Clone> WatchReceiver<T> {
    /// Returns a clone of the current value.
    pub fn borrow_cloned(&self) -> T {
        lock_unpoisoned(&self.inner.state).value.clone()
    }
}

impl<T> Clone for WatchReceiver<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            seen_version: self.seen_version,
        }
    }
}

// ---------------------------------------------------------------------------
// Overflow-Reporting Broadcast Channel (backs RevocationSender / RevocationReceiver)
// ---------------------------------------------------------------------------

/// Error returned by [`BroadcastReceiver::recv`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BroadcastRecvError {
    /// Receiver fell behind and missed exactly `u64` broadcast messages.
    Lagged(u64),
    /// All senders were dropped and no buffered messages remain.
    Closed,
}

/// Bounded overflow-mode broadcast publisher that never blocks senders and tracks exact receiver lag.
pub(crate) struct BroadcastSender<T> {
    tx: BcSender<T>,
    _keep_alive: InactiveReceiver<T>,
}

impl<T: Clone> Clone for BroadcastSender<T> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            _keep_alive: self._keep_alive.clone(),
        }
    }
}

/// Subscriber handle for [`BroadcastSender<T>`].
pub(crate) struct BroadcastReceiver<T> {
    rx: BcReceiver<T>,
}

impl<T: Clone> BroadcastSender<T> {
    /// Creates an overflow-mode broadcast channel with `capacity` (clamped to at least 1).
    pub fn channel(capacity: usize) -> (Self, BroadcastReceiver<T>) {
        let cap = capacity.max(1);
        let (mut tx, rx) = async_broadcast::broadcast(cap);
        tx.set_overflow(true);
        tx.set_await_active(false);
        let keep_alive = tx.new_receiver().deactivate();
        let sender = Self {
            tx,
            _keep_alive: keep_alive,
        };
        (sender, BroadcastReceiver { rx })
    }

    /// Broadcasts `item` without blocking. If any receiver's buffer is full, oldest unread items
    /// are overwritten and that receiver will observe [`BroadcastRecvError::Lagged`].
    pub fn send(&self, item: T) {
        let _ = self.tx.try_broadcast(item);
    }

    /// Creates a new active subscriber starting from future broadcasts.
    pub fn subscribe(&self) -> BroadcastReceiver<T> {
        BroadcastReceiver {
            rx: self.tx.new_receiver(),
        }
    }
}

impl<T: Clone> BroadcastReceiver<T> {
    /// Receives the next broadcast item, reporting exact lag counts on overflow.
    pub async fn recv(&mut self) -> Result<T, BroadcastRecvError> {
        match self.rx.recv_direct().await {
            Ok(item) => Ok(item),
            Err(async_broadcast::RecvError::Overflowed(skipped)) => {
                Err(BroadcastRecvError::Lagged(skipped))
            }
            Err(async_broadcast::RecvError::Closed) => Err(BroadcastRecvError::Closed),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::runtime::TaskSpawner;
    use crate::testing::TestSpawner;

    #[test]
    fn closeable_semaphore_wakes_waiters_on_close() {
        let spawner = TestSpawner::new();
        let sem = CloseableSemaphore::new(1);
        let p1 = sem.try_acquire().unwrap();
        assert_eq!(sem.in_use(), 1);
        assert_eq!(sem.available(), 0);
        assert!(matches!(sem.try_acquire(), Err(CoreError::Busy)));

        let sem2 = Arc::clone(&sem);
        let (tx, mut rx) = Watch::new(None::<Result<(), CoreError>>);
        spawner.spawn(Box::pin(async move {
            let res = sem2.acquire().await.map(|_| ());
            tx.send(Some(res));
        }));
        spawner.drive_until_idle();
        assert!(rx.borrow_cloned().is_none());

        sem.close();
        assert!(sem.is_closed());
        spawner.drive_until_idle();
        assert_eq!(rx.borrow_cloned(), Some(Err(CoreError::Closed)));
        assert!(matches!(sem.try_acquire(), Err(CoreError::Closed)));

        drop(p1);
        assert_eq!(sem.in_use(), 0);
        assert!(rx.has_changed());
        rx.mark_seen();
        assert!(!rx.has_changed());
    }

    #[test]
    fn watch_notifies_and_closes_on_sender_drop() {
        let spawner = TestSpawner::new();
        let (tx, mut rx) = Watch::new(10u32);
        let tx2 = tx.clone();

        tx.send(20);
        assert!(rx.has_changed());
        assert_eq!(spawner.try_block_on(rx.changed()), Some(true));
        assert_eq!(rx.borrow_cloned(), 20);
        assert!(!rx.has_changed());

        drop(tx);
        tx2.send(30);
        assert_eq!(spawner.try_block_on(rx.changed()), Some(true));
        assert_eq!(rx.borrow_cloned(), 30);

        drop(tx2);
        assert_eq!(spawner.try_block_on(rx.changed()), Some(false));
    }

    #[test]
    fn broadcast_reports_exact_lag_and_handles_zero_subscribers() {
        let spawner = TestSpawner::new();
        let (tx, mut rx) = BroadcastSender::<u32>::channel(2);

        // Overflow capacity 2 by sending 5 items: items 1, 2, 3 are overwritten (3 lagged).
        for i in 1..=5 {
            tx.send(i);
        }
        assert_eq!(
            spawner.try_block_on(rx.recv()),
            Some(Err(BroadcastRecvError::Lagged(3)))
        );
        assert_eq!(spawner.try_block_on(rx.recv()), Some(Ok(4)));
        assert_eq!(spawner.try_block_on(rx.recv()), Some(Ok(5)));

        // Dropping all active receivers must NOT prevent sending or later subscribing.
        drop(rx);
        tx.send(6);
        let mut rx2 = tx.subscribe();
        tx.send(7);
        assert_eq!(spawner.try_block_on(rx2.recv()), Some(Ok(7)));

        drop(tx);
        assert_eq!(
            spawner.try_block_on(rx2.recv()),
            Some(Err(BroadcastRecvError::Closed))
        );
    }
}
