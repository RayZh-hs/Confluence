//! Stateless `MAC1` / rotating `MAC2` flood-cookie protection and `under_load` hysteresis (Spec §4.8).

use core::time::Duration;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::constants::{
    CHALLENGE_LEN, COOKIE_LEN, COOKIE_ROTATION_INTERVAL, COOKIE_ROTATION_MIN,
    LOAD_HYSTERESIS_DURATION, MAC_LEN, SEGMENT_OVERHEAD,
};
use crate::crypto::identity::{ScopeKeypair, compute_mac2, derive_cookie_enc_key};
use crate::error::CoreError;
use crate::runtime::MonotonicTime;
use crate::types::PublicKey;

/// Result of pre-DH `mac1`/`mac2` validation inside [`CookieProtector::verify_segment`].
#[derive(Debug, PartialEq, Eq)]
pub enum CookieDecision<'a> {
    /// Segment passed `mac1` (and `mac2` when under load); carries stripped base segment slice.
    Verified(&'a [u8]),
    /// Responder is under load and requires a valid `mac2`; emit `SETUP_COOKIE` with this challenge.
    Challenge([u8; CHALLENGE_LEN]),
    /// Invalid `ScopeKid` or `mac1`; drop silently with zero allocations and zero DH operations.
    Drop,
}

/// Automatic `under_load` hysteresis tracker (75% ON, `<= 25%` continuously for `5 s` OFF)
/// with optional host manual override (Spec §4.8.5).
#[derive(Debug, Clone, Default)]
pub struct LoadTracker {
    manual_override: Option<bool>,
    auto_under_load: bool,
    below_since: Option<MonotonicTime>,
}

impl LoadTracker {
    /// Creates a fresh tracker in automatic mode (`under_load == false`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            manual_override: None,
            auto_under_load: false,
            below_since: None,
        }
    }

    /// Sets or clears (`None`) a manual `under_load` override.
    pub fn set_override(&mut self, override_load: Option<bool>) {
        self.manual_override = override_load;
    }

    /// Returns the effective `under_load` state (manual override if set, else automatic state).
    #[must_use]
    pub const fn is_under_load(&self) -> bool {
        match self.manual_override {
            Some(v) => v,
            None => self.auto_under_load,
        }
    }

    /// Updates automatic hysteresis from `(used, max_pending, now)` and returns effective `under_load`.
    pub fn update(&mut self, used: usize, max_pending: usize, now: MonotonicTime) -> bool {
        let cap = max_pending.max(1);
        let high_threshold = cap.saturating_sub(cap.div_ceil(4));
        let low_threshold = cap / 4;

        if used > high_threshold {
            self.auto_under_load = true;
            self.below_since = None;
        } else if self.auto_under_load {
            if used <= low_threshold {
                match self.below_since {
                    None => self.below_since = Some(now),
                    Some(since)
                        if now.saturating_duration_since(since) >= LOAD_HYSTERESIS_DURATION =>
                    {
                        self.auto_under_load = false;
                        self.below_since = None;
                    }
                    Some(_) => {}
                }
            } else {
                // Hysteresis band (25%..=75%): reset low-load timer while staying active.
                self.below_since = None;
            }
        }

        self.is_under_load()
    }
}

struct CookieSecretState {
    current: Zeroizing<[u8; 32]>,
    previous: Option<Zeroizing<[u8; 32]>>,
    rotated_at: MonotonicTime,
    load: LoadTracker,
}

impl CookieSecretState {
    fn maybe_rotate(&mut self, now: MonotonicTime, interval: Duration) {
        let elapsed = now.saturating_duration_since(self.rotated_at);
        if elapsed < interval {
            return;
        }
        let mut next = [0u8; 32];
        OsRng.fill_bytes(&mut next);

        // If two or more full rotation intervals elapsed, both current and previous secrets are stale.
        if elapsed >= interval.saturating_mul(2) {
            self.previous = None;
        } else {
            let old_current = core::mem::replace(&mut self.current, Zeroizing::new(next));
            self.previous = Some(old_current);
            self.rotated_at = now;
            return;
        }
        self.current = Zeroizing::new(next);
        self.rotated_at = now;
    }
}

/// Pre-DH `MAC1` / rotating `MAC2` flood-cookie protector owned by a scope (Spec §4.8).
pub struct CookieProtector {
    keypair: ScopeKeypair,
    rotation_interval: Duration,
    under_load_cached: AtomicBool,
    state: Mutex<CookieSecretState>,
}

#[allow(dead_code)]
impl CookieProtector {
    /// Creates a `CookieProtector` with default `120 s` secret rotation interval.
    #[must_use]
    pub fn new(keypair: ScopeKeypair, now: MonotonicTime) -> Self {
        Self::with_rotation_interval(keypair, COOKIE_ROTATION_INTERVAL, now)
    }

    /// Creates a `CookieProtector` with a custom rotation interval (clamped to `>= 1 s`).
    #[must_use]
    pub fn with_rotation_interval(
        keypair: ScopeKeypair,
        rotation_interval: Duration,
        now: MonotonicTime,
    ) -> Self {
        let interval = rotation_interval.max(COOKIE_ROTATION_MIN);
        let mut current = [0u8; 32];
        OsRng.fill_bytes(&mut current);
        Self {
            keypair,
            rotation_interval: interval,
            under_load_cached: AtomicBool::new(false),
            state: Mutex::new(CookieSecretState {
                current: Zeroizing::new(current),
                previous: None,
                rotated_at: now,
                load: LoadTracker::new(),
            }),
        }
    }

    /// Updates automatic `under_load` hysteresis and returns the current effective load flag.
    pub fn update_load(&self, used: usize, max_pending: usize, now: MonotonicTime) -> bool {
        let mut st = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let active = st.load.update(used, max_pending, now);
        self.under_load_cached.store(active, Ordering::Release);
        active
    }

    /// Sets or clears (`None`) a manual `under_load` override.
    pub fn set_under_load(&self, override_load: Option<bool>) -> bool {
        let mut st = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        st.load.set_override(override_load);
        let active = st.load.is_under_load();
        self.under_load_cached.store(active, Ordering::Release);
        active
    }

    /// Returns the cached `under_load` state without locking.
    #[must_use]
    pub fn is_under_load(&self) -> bool {
        self.under_load_cached.load(Ordering::Acquire)
    }

    /// Pre-DH zero-allocation `ScopeKid` + `mac1` check without load/cookie state.
    #[must_use]
    pub fn verify_mac1_only(&self, segment: &[u8], has_mac2: bool) -> bool {
        self.keypair.verify_segment_mac1(segment, has_mac2).is_ok()
    }

    /// Executes full `MAC1` / `MAC2` validation and challenge generation (Spec §4.8).
    ///
    /// Invalid `ScopeKid` or `mac1` returns [`CookieDecision::Drop`] with **zero heap allocations**
    /// and **zero mutex locks**. When `!under_load`, valid `mac1` immediately returns
    /// [`CookieDecision::Verified`] (0-RTT).
    pub fn verify_segment<'a>(
        &self,
        source_tag: &[u8; 16],
        segment: &'a [u8],
        has_mac2: bool,
        now: MonotonicTime,
    ) -> CookieDecision<'a> {
        let min_len = SEGMENT_OVERHEAD + if has_mac2 { MAC_LEN } else { 0 };
        if segment.len() < min_len {
            return CookieDecision::Drop;
        }
        let (base, sent_mac2) = if has_mac2 {
            let split = segment.len() - MAC_LEN;
            (&segment[..split], Some(&segment[split..]))
        } else {
            (segment, None)
        };

        if !self.keypair.verify_base_mac1(base) {
            return CookieDecision::Drop;
        }

        // Fast lock-free path when not under load.
        if !self.under_load_cached.load(Ordering::Acquire) {
            return CookieDecision::Verified(base);
        }

        let mut st = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !st.load.is_under_load() {
            self.under_load_cached.store(false, Ordering::Release);
            return CookieDecision::Verified(base);
        }

        st.maybe_rotate(now, self.rotation_interval);

        let curr_cookie = derive_source_cookie(&st.current, source_tag);
        let prev_cookie = st
            .previous
            .as_ref()
            .map(|p| derive_source_cookie(p, source_tag));
        drop(st);

        if let Some(m2) = sent_mac2 {
            let matches_curr = compute_mac2(&curr_cookie, base).ct_eq(m2);
            let matches_prev = match &prev_cookie {
                Some(prev) => compute_mac2(prev, base).ct_eq(m2),
                None => subtle::Choice::from(0u8),
            };
            if bool::from(matches_curr | matches_prev) {
                return CookieDecision::Verified(base);
            }
        }

        // Issue a 56-byte stateless XChaCha20-Poly1305 challenge bound to `sent_mac1` AAD.
        let sent_mac1 = &base[base.len() - MAC_LEN..];
        let challenge = seal_cookie_challenge(
            self.keypair.cookie_enc_key(),
            sent_mac1,
            &curr_cookie,
        );
        CookieDecision::Challenge(challenge)
    }
}

fn derive_source_cookie(secret: &[u8; 32], source_tag: &[u8; 16]) -> Zeroizing<[u8; COOKIE_LEN]> {
    let hash = blake3::keyed_hash(secret, source_tag);
    let mut cookie = Zeroizing::new([0u8; COOKIE_LEN]);
    cookie.copy_from_slice(&hash.as_bytes()[0..COOKIE_LEN]);
    cookie
}

fn seal_cookie_challenge(
    cookie_enc_key: &[u8; 32],
    sent_mac1: &[u8],
    cookie: &[u8; COOKIE_LEN],
) -> [u8; CHALLENGE_LEN] {
    let mut xnonce = [0u8; 24];
    OsRng.fill_bytes(&mut xnonce);

    let mut ct = *cookie;
    let cipher = XChaCha20Poly1305::new(cookie_enc_key.into());
    let tag_bytes: [u8; 16] = match cipher.encrypt_in_place_detached(
        XNonce::from_slice(&xnonce),
        sent_mac1,
        &mut ct,
    ) {
        Ok(t) => t.into(),
        Err(_) => [0u8; 16],
    };

    let mut out = [0u8; CHALLENGE_LEN];
    out[0..24].copy_from_slice(&xnonce);
    out[24..40].copy_from_slice(&ct);
    out[40..56].copy_from_slice(&tag_bytes);
    out
}

/// Originator unsealing of a 56-byte `SETUP_COOKIE` challenge (Spec §4.8.4).
pub fn unseal_cookie_challenge(
    target_pk: &PublicKey,
    sent_mac1: &[u8; MAC_LEN],
    challenge: &[u8],
) -> Result<Zeroizing<[u8; COOKIE_LEN]>, CoreError> {
    if challenge.len() != CHALLENGE_LEN {
        return Err(CoreError::Authentication);
    }
    let key = Zeroizing::new(derive_cookie_enc_key(target_pk));
    let xnonce = XNonce::from_slice(&challenge[0..24]);
    let mut pt = Zeroizing::new([0u8; COOKIE_LEN]);
    pt.copy_from_slice(&challenge[24..40]);
    let tag = Tag::from_slice(&challenge[40..56]);

    let cipher = XChaCha20Poly1305::new((&*key).into());
    cipher
        .decrypt_in_place_detached(xnonce, sent_mac1, &mut *pt, tag)
        .map_err(|_| CoreError::Authentication)?;
    Ok(pt)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::noise::Initiator;

    fn make_segment(
        origin: &ScopeKeypair,
        dest: &ScopeKeypair,
        cookie: Option<&[u8; 16]>,
    ) -> (Initiator, Vec<u8>) {
        let mut pt = Vec::new();
        pt.extend_from_slice(&1_700_000_000_000u64.to_be_bytes());
        pt.push(2);
        pt.extend_from_slice(b"ep");
        pt.extend_from_slice(&0u16.to_be_bytes());
        Initiator::build_message1(origin, dest.public_key(), &[0x33; 32], &pt, cookie).unwrap()
    }

    #[test]
    fn cookie_challenge_rotation_grace_and_source_tag_binding() {
        let origin = ScopeKeypair::generate();
        let dest = ScopeKeypair::generate();
        let t0 = MonotonicTime::ZERO;
        let protector = CookieProtector::new(dest.clone(), t0);
        let src_a = [0xAA; 16];
        let src_b = [0xBB; 16];

        // 0-RTT when not under load.
        let (init0, seg0) = make_segment(&origin, &dest, None);
        assert!(matches!(
            protector.verify_segment(&src_a, &seg0, false, t0),
            CookieDecision::Verified(_)
        ));

        // Under load: issues 56B challenge bound to sent_mac1 + source_tag.
        protector.set_under_load(Some(true));
        let challenge = match protector.verify_segment(&src_a, &seg0, false, t0) {
            CookieDecision::Challenge(c) => c,
            other => panic!("expected challenge, got {other:?}"),
        };

        // Wrong sent_mac1 fails unseal.
        let mut wrong_mac1 = *init0.sent_mac1();
        wrong_mac1[0] ^= 0x01;
        assert_eq!(
            unseal_cookie_challenge(&dest.public_key(), &wrong_mac1, &challenge),
            Err(CoreError::Authentication)
        );

        let cookie =
            unseal_cookie_challenge(&dest.public_key(), init0.sent_mac1(), &challenge).unwrap();
        let (_init1, seg1) = make_segment(&origin, &dest, Some(&cookie));

        // Matching source_tag succeeds; different source_tag re-challenges.
        assert!(matches!(
            protector.verify_segment(&src_a, &seg1, true, t0),
            CookieDecision::Verified(_)
        ));
        assert!(matches!(
            protector.verify_segment(&src_b, &seg1, true, t0),
            CookieDecision::Challenge(_)
        ));

        // After 1 rotation period (120 s): previous secret still accepted (grace period).
        let t1 = t0.saturating_add(Duration::from_secs(120));
        assert!(matches!(
            protector.verify_segment(&src_a, &seg1, true, t1),
            CookieDecision::Verified(_)
        ));

        // After 2 rotation periods (240 s): original cookie rejected with new challenge.
        let t2 = t1.saturating_add(Duration::from_secs(120));
        assert!(matches!(
            protector.verify_segment(&src_a, &seg1, true, t2),
            CookieDecision::Challenge(_)
        ));
    }

    #[test]
    fn load_tracker_hysteresis_75_25_5s() {
        let mut tracker = LoadTracker::new();
        let t0 = MonotonicTime::ZERO;

        // max_pending = 100 => high_threshold = 75 (activates at >= 76), low_threshold = 25.
        assert!(!tracker.update(75, 100, t0));
        assert!(tracker.update(76, 100, t0));

        // Drop to 50% (hysteresis band): stays active.
        let t1 = t0.saturating_add(Duration::from_secs(10));
        assert!(tracker.update(50, 100, t1));

        // Drop to 25%: starts 5s timer.
        assert!(tracker.update(25, 100, t1));
        let t2 = t1.saturating_add(Duration::from_secs(4));
        assert!(tracker.update(20, 100, t2));

        // Bounce back to 30% resets the 5s timer!
        let t3 = t1.saturating_add(Duration::from_millis(4500));
        assert!(tracker.update(30, 100, t3));
        assert!(tracker.update(25, 100, t3));
        // 4.9 s after t3 is still active.
        assert!(tracker.update(10, 100, t3.saturating_add(Duration::from_millis(4999))));
        // Exactly 5.0 s after t3 clears!
        assert!(!tracker.update(10, 100, t3.saturating_add(Duration::from_secs(5))));
    }
}
