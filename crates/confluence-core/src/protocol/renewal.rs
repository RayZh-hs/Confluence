//! Pure synchronous idempotent in-band lease renewal state machines (Spec §6.7).

use core::time::Duration;

use rand_core::RngCore;

use crate::constants::{
    RENEWAL_BACKOFF_CAP, RENEWAL_BACKOFF_MIN, RENEWAL_DATAGRAM_BACKOFF_BASE,
    RENEWAL_JITTER_MAX_PCT, RENEWAL_JITTER_MIN_PCT, RENEWAL_STREAM_BACKOFF_BASE,
};
use crate::error::CoreError;
use crate::runtime::MonotonicTime;
use crate::types::{Credential, Plane};

/// Identifies one independent renewal target along a session (`1` Endpoint + `N` Hops).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RenewalSlot {
    /// Destination endpoint (`e2e::ST_RENEW` / `e2e::DG_RENEW`).
    Endpoint,
    /// Intermediate transit hop `0..N-1` (`hop::ST_RENEW` / `hop::DG_RENEW` with `ttl = index`).
    Hop(usize),
}

struct SlotState {
    slot: RenewalSlot,
    credential: Credential,
    refresh_at: MonotonicTime,
    expires_at: MonotonicTime,
    retries: u32,
    acknowledged: u64,
    in_flight: Option<(u64, Credential)>,
    fetching: bool,
}

impl SlotState {
    fn new(
        slot: RenewalSlot,
        ttl: Duration,
        credential: Credential,
        now: MonotonicTime,
        rng: &mut impl RngCore,
    ) -> Self {
        let mut s = Self {
            slot,
            credential,
            refresh_at: now,
            expires_at: now,
            retries: 0,
            acknowledged: 0,
            in_flight: None,
            fetching: false,
        };
        s.apply_ttl(ttl, now, rng);
        s
    }

    fn apply_ttl(&mut self, ttl: Duration, now: MonotonicTime, rng: &mut impl RngCore) {
        self.retries = 0;
        self.expires_at = now.saturating_add(ttl);
        let span = RENEWAL_JITTER_MAX_PCT - RENEWAL_JITTER_MIN_PCT + 1;
        let pct = RENEWAL_JITTER_MIN_PCT + (rng.next_u64() % span);
        let refresh_ns = ttl.as_nanos().saturating_mul(u128::from(pct)) / 100;
        let refresh_dur = Duration::from_nanos(u64::try_from(refresh_ns).unwrap_or(u64::MAX));
        self.refresh_at = now.saturating_add(refresh_dur);
    }

    fn schedule_retry(&mut self, plane: Plane, now: MonotonicTime, rng: &mut impl RngCore) {
        let base_ms: u64 = match plane {
            Plane::Stream => RENEWAL_STREAM_BACKOFF_BASE.as_millis() as u64,
            Plane::Datagram => RENEWAL_DATAGRAM_BACKOFF_BASE.as_millis() as u64,
        };
        let cap_ms = RENEWAL_BACKOFF_CAP.as_millis() as u64;
        let min_ms = RENEWAL_BACKOFF_MIN.as_millis() as u64;

        let shift = self.retries.min(6);
        let ceiling_ms = (base_ms << shift).min(cap_ms);
        let half = ceiling_ms / 2;
        let span = ceiling_ms.saturating_sub(half).max(1);
        let jitter_ms = half + (rng.next_u64() % span);

        let remaining_ms = self.expires_at.saturating_duration_since(now).as_millis();
        let third_remaining_ms = u64::try_from(remaining_ms / 3).unwrap_or(u64::MAX);
        let delay_ms = jitter_ms.min(third_remaining_ms).max(min_ms);

        self.refresh_at = now.saturating_add(Duration::from_millis(delay_ms));
        self.retries = self.retries.saturating_add(1);
    }
}

/// Action emitted by [`RenewalDriver::poll_actions`] for the async session worker to execute.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum RenewalAction {
    /// A slot's lease reached `expires_at` without renewal -> terminate session.
    Expired(RenewalSlot),
    /// Invoke `CredentialProvider::credential` (`is_refresh: true`) bounded by `min(auth_timeout, remaining / 2)`.
    FetchCredential {
        slot: RenewalSlot,
        prior: Credential,
        remaining: Duration,
        is_retry: bool,
    },
    /// Re-transmit an already-fetched `(renewal_id, credential)` without re-querying `CredentialProvider`.
    Send {
        slot: RenewalSlot,
        renewal_id: u64,
        credential: Credential,
        is_retry: bool,
    },
}

/// Outcome of delivering a completed `CredentialProvider::credential` result into [`RenewalDriver`].
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum CredentialFetchOutcome {
    /// Transmit this newly assigned `(renewal_id, credential)`.
    Send {
        slot: RenewalSlot,
        renewal_id: u64,
        credential: Credential,
    },
    /// Retryable credential failure: retry backoff scheduled.
    RetryScheduled,
    /// Non-retryable failure (or `renewal_id` exhaustion): immediately terminate the session.
    Fatal(CoreError),
}

/// Originator-side renewal scheduler managing `1 + N` independent slots (Spec §6.7).
#[allow(dead_code)]
pub struct RenewalDriver {
    plane: Plane,
    slots: Vec<SlotState>,
}

#[allow(dead_code)]
impl RenewalDriver {
    /// Initializes `Endpoint` plus `N` `Hop(0..N-1)` slots from the TTLs authenticated in `SETUP_OK`.
    #[must_use]
    pub fn new(
        plane: Plane,
        dest_ttl: Duration,
        dest_cred: Credential,
        hop_ttls_and_creds: Vec<(Duration, Credential)>,
        now: MonotonicTime,
        rng: &mut impl RngCore,
    ) -> Self {
        let mut slots = Vec::with_capacity(1 + hop_ttls_and_creds.len());
        slots.push(SlotState::new(
            RenewalSlot::Endpoint,
            dest_ttl,
            dest_cred,
            now,
            rng,
        ));
        for (i, (ttl, cred)) in hop_ttls_and_creds.into_iter().enumerate() {
            slots.push(SlotState::new(RenewalSlot::Hop(i), ttl, cred, now, rng));
        }
        Self { plane, slots }
    }

    fn slot_mut(&mut self, slot: RenewalSlot) -> Option<&mut SlotState> {
        let idx = match slot {
            RenewalSlot::Endpoint => 0,
            RenewalSlot::Hop(i) => 1 + i,
        };
        self.slots.get_mut(idx)
    }

    /// Returns the earliest monotonic wake deadline across all `1 + N` slots.
    #[must_use]
    pub fn next_deadline(&self) -> Option<MonotonicTime> {
        let mut earliest: Option<MonotonicTime> = None;
        for s in &self.slots {
            let candidate = if s.fetching {
                s.expires_at
            } else {
                s.expires_at.min(s.refresh_at)
            };
            earliest = Some(match earliest {
                Some(cur) => cur.min(candidate),
                None => candidate,
            });
        }
        earliest
    }

    /// Evaluates all slots at `now`, returning expiration or due fetch/retransmit actions.
    pub fn poll_actions(&mut self, now: MonotonicTime, rng: &mut impl RngCore) -> Vec<RenewalAction> {
        for s in &self.slots {
            if now >= s.expires_at {
                return vec![RenewalAction::Expired(s.slot)];
            }
        }

        let mut actions = Vec::new();
        for s in &mut self.slots {
            if s.fetching || now < s.refresh_at {
                continue;
            }
            let is_retry = s.retries > 0;
            if let Some((id, cred)) = &s.in_flight {
                let id = *id;
                let cred = cred.clone();
                s.schedule_retry(self.plane, now, rng);
                actions.push(RenewalAction::Send {
                    slot: s.slot,
                    renewal_id: id,
                    credential: cred,
                    is_retry,
                });
            } else {
                s.fetching = true;
                let remaining = s.expires_at.saturating_duration_since(now);
                actions.push(RenewalAction::FetchCredential {
                    slot: s.slot,
                    prior: s.credential.clone(),
                    remaining,
                    is_retry,
                });
            }
        }
        actions
    }

    /// Processes the result of an asynchronous `CredentialProvider::credential` fetch for `slot`.
    pub fn on_credential_fetched(
        &mut self,
        slot: RenewalSlot,
        result: Result<Credential, CoreError>,
        now: MonotonicTime,
        rng: &mut impl RngCore,
    ) -> CredentialFetchOutcome {
        let plane = self.plane;
        let Some(s) = self.slot_mut(slot) else {
            return CredentialFetchOutcome::Fatal(CoreError::Malformed);
        };
        s.fetching = false;
        if now >= s.expires_at {
            return CredentialFetchOutcome::Fatal(Self::expiry_error(slot));
        }

        match result {
            Ok(cred) => {
                let Some(id) = s.acknowledged.checked_add(1) else {
                    return CredentialFetchOutcome::Fatal(CoreError::Closed);
                };
                s.in_flight = Some((id, cred.clone()));
                s.schedule_retry(plane, now, rng);
                CredentialFetchOutcome::Send {
                    slot,
                    renewal_id: id,
                    credential: cred,
                }
            }
            Err(err) => {
                if !err.is_retryable() {
                    CredentialFetchOutcome::Fatal(err)
                } else {
                    s.schedule_retry(plane, now, rng);
                    CredentialFetchOutcome::RetryScheduled
                }
            }
        }
    }

    /// Applies an incoming `RENEW_OK(renewal_id, ttl)` ONLY if `slot` has not already expired
    /// (`now < slot.expires_at`) and `slot.in_flight` matches `renewal_id` (Spec §6.7 Steps 4 & 6).
    ///
    /// Returns:
    /// - `Err(Self::expiry_error(slot))` if `now >= slot.expires_at` (never reviving an expired slot
    ///   even if the receive event is polled before the expiration timer),
    /// - `Ok(true)` when accepted (caller updates local endpoint lease and increments
    ///   `lease_renewals_total`),
    /// - `Ok(false)` when stale/mismatched and ignored.
    pub fn on_ack(
        &mut self,
        slot: RenewalSlot,
        renewal_id: u64,
        ttl: Duration,
        now: MonotonicTime,
        rng: &mut impl RngCore,
    ) -> Result<bool, CoreError> {
        let Some(s) = self.slot_mut(slot) else {
            return Ok(false);
        };
        if now >= s.expires_at {
            return Err(Self::expiry_error(slot));
        }
        let matches = s
            .in_flight
            .as_ref()
            .is_some_and(|&(in_flight_id, _)| in_flight_id == renewal_id);
        if !matches {
            return Ok(false);
        }
        if let Some((id, cred)) = s.in_flight.take() {
            s.acknowledged = id;
            s.credential = cred;
            s.apply_ttl(ttl, now, rng);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Returns the error to report when `slot` expires (Spec §6.7 Step 4).
    #[must_use]
    pub fn expiry_error(slot: RenewalSlot) -> CoreError {
        match slot {
            RenewalSlot::Endpoint => CoreError::Expired,
            RenewalSlot::Hop(i) => {
                let idx = u8::try_from(i).unwrap_or(u8::MAX);
                CoreError::hop_rejected(idx, CoreError::Expired)
            }
        }
    }
}

/// Classification of an incoming `RENEW` frame at a verifier (Destination or Transit).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierRenewalAction {
    /// `renewal_id == 0` -> malformed frame.
    Malformed,
    /// `renewal_id == applied + 1` -> invoke `AuthGate::authorize(..., is_renewal: true)`.
    AuthorizeNew(u64),
    /// `renewal_id == applied` (duplicate of latest applied) -> reply `RENEW_OK(id, remaining)`
    /// WITHOUT re-invoking `Authorizer` and WITHOUT extending the lease.
    ReplyIdempotent(u64),
    /// Out-of-order, older, or concurrent while another renewal is in progress -> silently ignore.
    Ignore,
}

/// Pure verifier-side idempotency state machine for in-band lease renewals (Spec §6.7).
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct RenewalVerifierState {
    applied: u64,
    in_progress: bool,
}

#[allow(dead_code)]
impl RenewalVerifierState {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            applied: 0,
            in_progress: false,
        }
    }

    /// Classifies an incoming `renewal_id`, enforcing single-flight evaluation per session/circuit.
    pub fn classify(&mut self, renewal_id: u64) -> VerifierRenewalAction {
        if renewal_id == 0 {
            return VerifierRenewalAction::Malformed;
        }
        if self.in_progress {
            return VerifierRenewalAction::Ignore;
        }
        if self.applied < u64::MAX && renewal_id == self.applied + 1 {
            self.in_progress = true;
            VerifierRenewalAction::AuthorizeNew(renewal_id)
        } else if self.applied > 0 && renewal_id == self.applied {
            VerifierRenewalAction::ReplyIdempotent(renewal_id)
        } else {
            VerifierRenewalAction::Ignore
        }
    }

    /// Completes an in-flight `AuthorizeNew` evaluation, advancing `applied` iff `succeeded == true`.
    pub fn complete(&mut self, renewal_id: u64, succeeded: bool) {
        self.in_progress = false;
        if succeeded && renewal_id == self.applied.saturating_add(1) {
            self.applied = renewal_id;
        }
    }

    #[must_use]
    pub const fn applied(&self) -> u64 {
        self.applied
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    struct DeterministicRng(u64);
    impl RngCore for DeterministicRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            self.0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for b in dest.iter_mut() {
                *b = self.next_u64() as u8;
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    #[test]
    fn renewal_driver_jitter_idempotent_retry_and_late_ack_rejection() {
        let mut rng = DeterministicRng(7);
        let t0 = MonotonicTime::ZERO;
        let ttl = Duration::from_secs(10);
        let mut drv = RenewalDriver::new(
            Plane::Datagram,
            ttl,
            Credential::from_slice(b"v0").unwrap(),
            vec![(Duration::from_secs(20), Credential::from_slice(b"h0").unwrap())],
            t0,
            &mut rng,
        );

        // No immediate renewal burst at t = 0.
        assert!(drv.poll_actions(t0, &mut rng).is_empty());

        // Endpoint refresh falls within [7.0 s, 8.0 s].
        let first_dl = drv.next_deadline().unwrap();
        let elapsed = first_dl.saturating_duration_since(t0);
        assert!(elapsed >= Duration::from_secs(7) && elapsed <= Duration::from_secs(8));

        let actions = drv.poll_actions(first_dl, &mut rng);
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            RenewalAction::FetchCredential {
                slot: RenewalSlot::Endpoint,
                is_retry: false,
                ..
            }
        ));

        // Deliver fetched credential -> assigns renewal_id = 1.
        let cred1 = Credential::from_slice(b"v1").unwrap();
        let out = drv.on_credential_fetched(
            RenewalSlot::Endpoint,
            Ok(cred1.clone()),
            first_dl,
            &mut rng,
        );
        assert_eq!(
            out,
            CredentialFetchOutcome::Send {
                slot: RenewalSlot::Endpoint,
                renewal_id: 1,
                credential: cred1.clone(),
            }
        );

        // Retry before ACK MUST reuse exact (id = 1, cred = "v1") without re-querying CredentialProvider!
        let retry_dl = drv.next_deadline().unwrap();
        let retry_actions = drv.poll_actions(retry_dl, &mut rng);
        assert_eq!(
            retry_actions,
            vec![RenewalAction::Send {
                slot: RenewalSlot::Endpoint,
                renewal_id: 1,
                credential: cred1,
                is_retry: true,
            }]
        );

        // Wrong/stale renewal_id ACK ignored.
        assert_eq!(drv.on_ack(RenewalSlot::Endpoint, 2, ttl, retry_dl, &mut rng), Ok(false));
        // Matching ACK accepted.
        assert_eq!(drv.on_ack(RenewalSlot::Endpoint, 1, ttl, retry_dl, &mut rng), Ok(true));
        // Late duplicate ACK for id = 1 ignored once completed.
        assert_eq!(drv.on_ack(RenewalSlot::Endpoint, 1, ttl, retry_dl, &mut rng), Ok(false));

        // Non-retryable credential error fails immediately.
        let next_ep_dl = retry_dl.saturating_add(Duration::from_secs(8));
        let _ = drv.poll_actions(next_ep_dl, &mut rng);
        let fatal = drv.on_credential_fetched(
            RenewalSlot::Endpoint,
            Err(CoreError::credential(CoreError::Denied)),
            next_ep_dl,
            &mut rng,
        );
        assert!(matches!(fatal, CredentialFetchOutcome::Fatal(_)));
    }

    #[test]
    fn renewal_verifier_idempotency_and_single_flight() {
        let mut v = RenewalVerifierState::new();
        assert_eq!(v.classify(0), VerifierRenewalAction::Malformed);
        assert_eq!(v.classify(2), VerifierRenewalAction::Ignore);

        assert_eq!(v.classify(1), VerifierRenewalAction::AuthorizeNew(1));
        // Concurrent request while in progress ignored.
        assert_eq!(v.classify(1), VerifierRenewalAction::Ignore);
        assert_eq!(v.classify(2), VerifierRenewalAction::Ignore);

        // Retryable failure does not advance applied.
        v.complete(1, false);
        assert_eq!(v.applied(), 0);

        // Re-delivery of id = 1 triggers AuthorizeNew again.
        assert_eq!(v.classify(1), VerifierRenewalAction::AuthorizeNew(1));
        v.complete(1, true);
        assert_eq!(v.applied(), 1);

        // Duplicate id = 1 replies idempotently without re-authorizing!
        assert_eq!(v.classify(1), VerifierRenewalAction::ReplyIdempotent(1));
        assert_eq!(v.classify(2), VerifierRenewalAction::AuthorizeNew(2));
        v.complete(2, true);
        // Older id = 1 now silently ignored.
        assert_eq!(v.classify(1), VerifierRenewalAction::Ignore);
    }

    #[test]
    fn late_renewal_ack_at_or_after_expiry_never_revives_hop_or_endpoint() {
        let mut rng = DeterministicRng(42);
        let t0 = MonotonicTime::ZERO;
        let ep_ttl = Duration::from_secs(20);
        let hop_ttl = Duration::from_secs(10);
        let mut drv = RenewalDriver::new(
            Plane::Datagram,
            ep_ttl,
            Credential::from_slice(b"ep0").unwrap(),
            vec![(hop_ttl, Credential::from_slice(b"hop0").unwrap())],
            t0,
            &mut rng,
        );

        // Trigger hop 0 renewal before its 10 s expiry.
        let refresh_t = t0.saturating_add(Duration::from_secs(8));
        let actions = drv.poll_actions(refresh_t, &mut rng);
        assert!(actions.iter().any(|a| matches!(
            a,
            RenewalAction::FetchCredential {
                slot: RenewalSlot::Hop(0),
                ..
            }
        )));
        let fetched = drv.on_credential_fetched(
            RenewalSlot::Hop(0),
            Ok(Credential::from_slice(b"hop1").unwrap()),
            refresh_t,
            &mut rng,
        );
        assert!(matches!(
            fetched,
            CredentialFetchOutcome::Send {
                slot: RenewalSlot::Hop(0),
                renewal_id: 1,
                ..
            }
        ));

        // Deliver matching authenticated ACK at EXACTLY expires_at (before timer poll runs!).
        let hop_expiry = t0.saturating_add(hop_ttl);
        assert_eq!(
            drv.on_ack(RenewalSlot::Hop(0), 1, hop_ttl, hop_expiry, &mut rng),
            Err(CoreError::hop_rejected(0, CoreError::Expired))
        );
        // Slot MUST remain expired on subsequent poll (NOT revived!).
        assert_eq!(
            drv.poll_actions(hop_expiry, &mut rng),
            vec![RenewalAction::Expired(RenewalSlot::Hop(0))]
        );

        // Same guarantee for Endpoint slot after its expiry.
        let mut drv2 = RenewalDriver::new(
            Plane::Stream,
            Duration::from_secs(10),
            Credential::from_slice(b"ep0").unwrap(),
            vec![],
            t0,
            &mut rng,
        );
        let _ = drv2.poll_actions(t0.saturating_add(Duration::from_secs(8)), &mut rng);
        let _ = drv2.on_credential_fetched(
            RenewalSlot::Endpoint,
            Ok(Credential::from_slice(b"ep1").unwrap()),
            t0.saturating_add(Duration::from_secs(8)),
            &mut rng,
        );
        let after_ep_expiry = t0.saturating_add(Duration::from_secs(10) + Duration::from_millis(1));
        assert_eq!(
            drv2.on_ack(
                RenewalSlot::Endpoint,
                1,
                Duration::from_secs(10),
                after_ep_expiry,
                &mut rng
            ),
            Err(CoreError::Expired)
        );
        assert_eq!(
            drv2.poll_actions(after_ep_expiry, &mut rng),
            vec![RenewalAction::Expired(RenewalSlot::Endpoint)]
        );
    }
}
