use crate::error::{CoreError, Result};
use crate::seams::access::{Grant, RevocationEvent};
use crate::types::{EndpointName, PeerId, ScopeId};
use parking_lot::Mutex;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{broadcast, watch};

struct TokenBucket {
    rate_per_sec: u64,
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rate_per_sec: u64, now: Instant) -> Self {
        Self {
            rate_per_sec,
            tokens: rate_per_sec as f64,
            last_refill: now,
        }
    }

    fn update_rate(&mut self, new_rate: u64, now: Instant) {
        self.refill(now);
        self.rate_per_sec = new_rate;
        if self.tokens > new_rate as f64 {
            self.tokens = new_rate as f64;
        }
    }

    fn refill(&mut self, now: Instant) {
        if now > self.last_refill {
            let elapsed = now.duration_since(self.last_refill).as_secs_f64();
            self.last_refill = now;
            let cap = self.rate_per_sec as f64;
            self.tokens = (self.tokens + elapsed * cap).min(cap);
        }
    }

    /// Attempts to consume `amount` immediately, returning `Ok(())` or `Err(wait_duration)`.
    fn try_consume(&mut self, amount: u64, now: Instant) -> std::result::Result<(), Duration> {
        if self.rate_per_sec == 0 {
            return Err(Duration::from_secs(1));
        }
        self.refill(now);
        // Clamp single-chunk demand to bucket burst capacity so a chunk <= 16KiB on a low-rate
        // stream still makes forward progress after waiting for refill.
        let needed = (amount as f64).min(self.rate_per_sec as f64);
        if self.tokens >= needed {
            self.tokens -= needed;
            Ok(())
        } else {
            let deficit = needed - self.tokens;
            let secs = deficit / (self.rate_per_sec as f64);
            Err(Duration::from_secs_f64(secs.max(0.001)))
        }
    }
}

struct RateState {
    bytes_bucket: Option<TokenBucket>,
    dgram_bucket: Option<TokenBucket>,
}

/// Shared runtime enforcement primitive for `Grant` bounds (expiry, byte/datagram rate limits,
/// concurrent stream caps, in-place renewal, and immediate revocation teardown).
pub struct GrantEnforcer {
    epoch: Instant,
    expires_offset_nanos: AtomicU64,
    revoked: AtomicBool,
    active_streams: AtomicU32,
    max_concurrent_streams: AtomicU32, // u32::MAX means unlimited
    rates: Mutex<RateState>,
    closed_tx: watch::Sender<bool>,
    closed_rx: watch::Receiver<bool>,
}

impl GrantEnforcer {
    pub fn new(grant: Grant) -> Arc<Self> {
        let now = Instant::now();
        let offset_nanos = grant
            .expires_at
            .checked_duration_since(now)
            .unwrap_or(Duration::ZERO)
            .as_nanos()
            .min(u64::MAX as u128) as u64;

        let (closed_tx, closed_rx) = watch::channel(false);

        Arc::new(Self {
            epoch: now,
            expires_offset_nanos: AtomicU64::new(offset_nanos),
            revoked: AtomicBool::new(false),
            active_streams: AtomicU32::new(0),
            max_concurrent_streams: AtomicU32::new(
                grant.max_concurrent_streams.unwrap_or(u32::MAX),
            ),
            rates: Mutex::new(RateState {
                bytes_bucket: grant.max_bytes_per_sec.map(|r| TokenBucket::new(r, now)),
                dgram_bucket: grant
                    .max_datagrams_per_sec
                    .map(|r| TokenBucket::new(r, now)),
            }),
            closed_tx,
            closed_rx,
        })
    }

    /// Subscribes `this` enforcer to an `AccessControl` revocation broadcast channel,
    /// immediately revoking `this` when a matching `RevocationEvent` arrives.
    pub fn spawn_revocation_watcher(
        self: &Arc<Self>,
        mut rx: broadcast::Receiver<RevocationEvent>,
        scope: ScopeId,
        peer: PeerId,
        endpoint: Option<EndpointName>,
    ) {
        let weak = Arc::downgrade(self);
        let mut closed_rx = self.closed_rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = closed_rx.changed() => {
                        if *closed_rx.borrow() {
                            break;
                        }
                    }
                    ev = rx.recv() => {
                        match ev {
                            Ok(event) => {
                                let Some(strong) = weak.upgrade() else { break; };
                                if event.matches(&scope, &peer, endpoint.as_ref()) {
                                    strong.revoke();
                                    break;
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            }
        });
    }

    /// Atomically updates the live `Grant` during in-band renewal without interrupting data flow.
    pub fn update_grant(&self, new_grant: Grant) {
        let offset_nanos = new_grant
            .expires_at
            .checked_duration_since(self.epoch)
            .unwrap_or(Duration::ZERO)
            .as_nanos()
            .min(u64::MAX as u128) as u64;
        self.expires_offset_nanos
            .store(offset_nanos, Ordering::Release);
        self.max_concurrent_streams.store(
            new_grant.max_concurrent_streams.unwrap_or(u32::MAX),
            Ordering::Release,
        );

        let now = Instant::now();
        let mut guard = self.rates.lock();
        guard.bytes_bucket = match (guard.bytes_bucket.take(), new_grant.max_bytes_per_sec) {
            (Some(mut b), Some(r)) => {
                b.update_rate(r, now);
                Some(b)
            }
            (None, Some(r)) => Some(TokenBucket::new(r, now)),
            (_, None) => None,
        };
        guard.dgram_bucket = match (guard.dgram_bucket.take(), new_grant.max_datagrams_per_sec) {
            (Some(mut b), Some(r)) => {
                b.update_rate(r, now);
                Some(b)
            }
            (None, Some(r)) => Some(TokenBucket::new(r, now)),
            (_, None) => None,
        };
    }

    /// Immediately revokes this grant and wakes all subscribed streams/circuits.
    pub fn revoke(&self) {
        if !self.revoked.swap(true, Ordering::AcqRel) {
            let _ = self.closed_tx.send(true);
        }
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }

    pub fn closed_watch(&self) -> watch::Receiver<bool> {
        self.closed_rx.clone()
    }

    /// Checks revocation and expiry at `now`.
    pub fn check_liveness(&self, now: Instant) -> Result<()> {
        if self.is_revoked() {
            return Err(CoreError::GrantRevoked);
        }
        let elapsed = now
            .checked_duration_since(self.epoch)
            .unwrap_or(Duration::ZERO)
            .as_nanos()
            .min(u64::MAX as u128) as u64;
        if elapsed >= self.expires_offset_nanos.load(Ordering::Acquire) {
            return Err(CoreError::GrantExpired);
        }
        Ok(())
    }

    /// Non-blocking check & token deduction for discrete Datagram Plane packets.
    pub fn check_and_record_datagram(&self, byte_len: usize) -> Result<()> {
        let now = Instant::now();
        self.check_liveness(now)?;

        let mut guard = self.rates.lock();
        if let Some(ref mut db) = guard.dgram_bucket {
            if db.try_consume(1, now).is_err() {
                return Err(CoreError::RateLimitExceeded);
            }
        }
        if let Some(ref mut bb) = guard.bytes_bucket {
            if bb.try_consume(byte_len as u64, now).is_err() {
                return Err(CoreError::RateLimitExceeded);
            }
        }
        Ok(())
    }

    /// Attempts to consume `byte_len` bytes on a stream, returning `Ok(None)` if allowed immediately,
    /// `Ok(Some(delay))` if pacing is needed, or `Err(...)` if expired/revoked.
    pub fn poll_stream_bytes(&self, byte_len: usize) -> Result<Option<Duration>> {
        let now = Instant::now();
        self.check_liveness(now)?;
        let mut guard = self.rates.lock();
        if let Some(ref mut bb) = guard.bytes_bucket {
            if let Err(wait) = bb.try_consume(byte_len as u64, now) {
                return Ok(Some(wait));
            }
        }
        Ok(None)
    }

    /// Acquires a concurrency permit if `active_streams < max_concurrent_streams`.
    pub fn try_acquire_stream(self: &Arc<Self>) -> Result<StreamPermit> {
        self.check_liveness(Instant::now())?;
        loop {
            let current = self.active_streams.load(Ordering::Acquire);
            let max = self.max_concurrent_streams.load(Ordering::Acquire);
            if current >= max {
                return Err(CoreError::ConcurrencyLimitExceeded);
            }
            if self
                .active_streams
                .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(StreamPermit {
                    enforcer: Arc::clone(self),
                });
            }
        }
    }
}

/// RAII concurrency guard decrementing `active_streams` when a stream closes.
pub struct StreamPermit {
    enforcer: Arc<GrantEnforcer>,
}

impl Drop for StreamPermit {
    fn drop(&mut self) {
        self.enforcer.active_streams.fetch_sub(1, Ordering::AcqRel);
    }
}

use std::future::Future;

/// Wraps any `AsyncRead + AsyncWrite` stream with live `GrantEnforcer` expiry, immediate
/// revocation cancellation (even while idle!), concurrency permit tracking, and token-bucket byte rate pacing.
pub struct GrantEnforcedStream<S> {
    inner: S,
    enforcer: Arc<GrantEnforcer>,
    _permit: Option<StreamPermit>,
    read_sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    write_sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    closed_wait: Pin<Box<dyn Future<Output = ()> + Send + Sync>>,
}

impl<S> GrantEnforcedStream<S> {
    pub fn new(inner: S, enforcer: Arc<GrantEnforcer>, permit: Option<StreamPermit>) -> Self {
        let mut rx = enforcer.closed_watch();
        let closed_wait = Box::pin(async move {
            let _ = rx.wait_for(|&closed| closed).await;
        });
        Self {
            inner,
            enforcer,
            _permit: permit,
            read_sleep: None,
            write_sleep: None,
            closed_wait,
        }
    }

    fn map_err_to_io(err: CoreError) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, err.to_string())
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for GrantEnforcedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Poll::Ready(()) = self.closed_wait.as_mut().poll(cx) {
            return Poll::Ready(Err(Self::map_err_to_io(CoreError::GrantRevoked)));
        }
        if let Err(e) = self.enforcer.check_liveness(Instant::now()) {
            return Poll::Ready(Err(Self::map_err_to_io(e)));
        }

        if let Some(ref mut sleep) = self.read_sleep {
            match sleep.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => self.read_sleep = None,
            }
        }

        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                let n = buf.filled().len().saturating_sub(before);
                if n > 0 {
                    match self.enforcer.poll_stream_bytes(n) {
                        Ok(None) => {}
                        Ok(Some(delay)) => {
                            self.read_sleep = Some(Box::pin(tokio::time::sleep(delay)));
                        }
                        Err(e) => return Poll::Ready(Err(Self::map_err_to_io(e))),
                    }
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for GrantEnforcedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Poll::Ready(()) = self.closed_wait.as_mut().poll(cx) {
            return Poll::Ready(Err(Self::map_err_to_io(CoreError::GrantRevoked)));
        }
        if let Err(e) = self.enforcer.check_liveness(Instant::now()) {
            return Poll::Ready(Err(Self::map_err_to_io(e)));
        }

        if let Some(ref mut sleep) = self.write_sleep {
            match sleep.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => self.write_sleep = None,
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let capped_len = buf.len().min(16 * 1024);
        match self.enforcer.poll_stream_bytes(capped_len) {
            Ok(None) => Pin::new(&mut self.inner).poll_write(cx, &buf[..capped_len]),
            Ok(Some(delay)) => {
                let mut sleep = Box::pin(tokio::time::sleep(delay));
                let _ = sleep.as_mut().poll(cx);
                self.write_sleep = Some(sleep);
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(Self::map_err_to_io(e))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(e) = self.enforcer.check_liveness(Instant::now()) {
            return Poll::Ready(Err(Self::map_err_to_io(e)));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
