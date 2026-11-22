//! Stateless pre-authentication DoS protection via WireGuard-style `MAC1` + rotating `MAC2`
//! flood cookies, built on Confluence's fixed BLAKE3 + XChaCha20-Poly1305 suite.

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use parking_lot::Mutex;
use rand_core::{OsRng, RngCore};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

use super::{PublicKey, ScopeKid, mac_key, mac1, scope_kid};
use crate::CoreErr;

/// Byte length of `mac1` and `mac2` tags.
pub const MAC_LEN: usize = 16;
/// Byte length of a stateless flood cookie.
pub const COOKIE_LEN: usize = 16;
/// Byte length of an encrypted cookie challenge (`24B XNonce + 16B cookie + 16B Poly1305 tag`).
pub const CHALLENGE_LEN: usize = 56;
/// Default secret rotation period for per-source flood cookies.
pub const DEFAULT_ROTATION_INTERVAL: Duration = Duration::from_secs(120);

fn cookie_enc_key(target: PublicKey) -> [u8; 32] {
    blake3::derive_key("confluence-v1-cookie", &target.0)
}

fn mac2_key(cookie: &[u8; COOKIE_LEN]) -> [u8; 32] {
    blake3::derive_key("confluence-v1-mac2", cookie)
}

/// Computes the 16-byte `mac2` tag over `segment_through_mac1` using `cookie`.
pub fn compute_mac2(cookie: &[u8; COOKIE_LEN], segment_through_mac1: &[u8]) -> [u8; MAC_LEN] {
    let key = mac2_key(cookie);
    blake3::keyed_hash(&key, segment_through_mac1).as_bytes()[..MAC_LEN]
        .try_into()
        .expect("blake3 output is 32 bytes")
}

/// Appends a 16-byte `mac2` tag to a segment that already ends in `mac1`.
pub fn append_mac2(segment_with_mac1: &mut Vec<u8>, cookie: &[u8; COOKIE_LEN]) {
    let tag = compute_mac2(cookie, segment_with_mac1);
    segment_with_mac1.extend_from_slice(&tag);
}

/// Decrypts a 56-byte stateless cookie challenge from `target`, verifying AAD binding to the
/// initiator's original `sent_mac1`.
pub fn unseal_cookie_challenge(
    target: PublicKey,
    sent_mac1: &[u8; MAC_LEN],
    challenge: &[u8],
) -> Result<[u8; COOKIE_LEN], CoreErr> {
    if challenge.len() != CHALLENGE_LEN {
        return Err(CoreErr::Authentication);
    }
    let key = cookie_enc_key(target);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = XNonce::from_slice(&challenge[..24]);
    let mut cookie = [0u8; COOKIE_LEN];
    cookie.copy_from_slice(&challenge[24..40]);
    let tag = chacha20poly1305::Tag::from_slice(&challenge[40..56]);
    cipher
        .decrypt_in_place_detached(nonce, sent_mac1, &mut cookie, tag)
        .map_err(|_| CoreErr::Authentication)?;
    Ok(cookie)
}

/// Result of stack-only pre-DH verification of a setup segment.
pub enum CookieCheck<'a> {
    /// `scope_kid`, `mac1`, and (when `under_load`) `mac2` verified; slice is the segment through `mac1`.
    Verified(&'a [u8]),
    /// Responder is under load and `mac2` was missing or stale; return this stateless challenge.
    Challenge([u8; CHALLENGE_LEN]),
    /// Framing, `scope_kid`, or `mac1` failed; silently drop without touching X25519.
    Drop,
}

struct VerifiedMac1<'a> {
    base: &'a [u8],
    sent_mac1: &'a [u8],
    sent_mac2: Option<&'a [u8]>,
}

struct RotatingSecret {
    current: [u8; 32],
    previous: Option<[u8; 32]>,
    rotated_at: Instant,
}

/// Stateless pre-DH DoS protector combining fast `mac1` filtering with rotating `mac2` cookies.
///
/// When `under_load` is `false` (default), valid `mac1` segments proceed in 0-RTT with zero
/// extra wire overhead. When `under_load` is enabled, initiators must prove return routability
/// via a stateless `mac2` cookie before any X25519 scalar multiplication or replay cache update.
pub struct CookieProtector {
    kid: ScopeKid,
    mac1_key: [u8; 32],
    cookie_enc_key: [u8; 32],
    rotation_interval: Duration,
    under_load: AtomicBool,
    secret: Mutex<RotatingSecret>,
}

impl CookieProtector {
    /// Creates a protector bound to `target` with the given cookie-secret rotation interval.
    pub fn new(target: PublicKey, rotation_interval: Duration) -> Self {
        let mut initial = [0u8; 32];
        OsRng.fill_bytes(&mut initial);
        Self {
            kid: scope_kid(target),
            mac1_key: mac_key(target),
            cookie_enc_key: cookie_enc_key(target),
            rotation_interval: rotation_interval.max(Duration::from_secs(1)),
            under_load: AtomicBool::new(false),
            secret: Mutex::new(RotatingSecret {
                current: initial,
                previous: None,
                rotated_at: Instant::now(),
            }),
        }
    }

    /// Toggles flood-cookie enforcement.
    pub fn set_under_load(&self, under_load: bool) {
        self.under_load.store(under_load, Ordering::Release);
    }

    /// Returns `true` if `MAC2` flood cookies are currently required.
    pub fn is_under_load(&self) -> bool {
        self.under_load.load(Ordering::Acquire)
    }

    /// Fast stack-only `scope_kid` + `mac1` precheck (ignoring `mac2` state).
    pub fn precheck_mac1(&self, segment: &[u8], has_mac2: bool) -> bool {
        self.strip_and_verify_mac1(segment, has_mac2).is_some()
    }

    /// Verifies `scope_kid`, `mac1`, and (when `under_load`) rotating `mac2` in constant time
    /// with zero heap allocations.
    pub fn verify_segment<'a>(
        &self,
        source_tag: &[u8],
        segment: &'a [u8],
        has_mac2: bool,
    ) -> CookieCheck<'a> {
        let Some(verified) = self.strip_and_verify_mac1(segment, has_mac2) else {
            return CookieCheck::Drop;
        };
        if !self.is_under_load() {
            return CookieCheck::Verified(verified.base);
        }

        let (curr_cookie, prev_cookie) = self.cookies_for_source(source_tag);
        if let Some(mac2) = verified.sent_mac2 {
            let expected_curr = compute_mac2(&curr_cookie, verified.base);
            if bool::from(mac2.ct_eq(&expected_curr)) {
                return CookieCheck::Verified(verified.base);
            }
            if let Some(prev) = prev_cookie {
                let expected_prev = compute_mac2(&prev, verified.base);
                if bool::from(mac2.ct_eq(&expected_prev)) {
                    return CookieCheck::Verified(verified.base);
                }
            }
        }

        CookieCheck::Challenge(self.build_challenge(&curr_cookie, verified.sent_mac1))
    }

    fn strip_and_verify_mac1<'a>(
        &self,
        segment: &'a [u8],
        has_mac2: bool,
    ) -> Option<VerifiedMac1<'a>> {
        let (base, mac2) = if has_mac2 {
            if segment.len() < crate::wire::setup::SEGMENT_OVERHEAD + MAC_LEN {
                return None;
            }
            let split = segment.len() - MAC_LEN;
            (&segment[..split], Some(&segment[split..]))
        } else {
            if segment.len() < crate::wire::setup::SEGMENT_OVERHEAD {
                return None;
            }
            (segment, None)
        };
        if !bool::from(self.kid.0.ct_eq(&base[..8])) {
            return None;
        }
        let (body, sent_mac1) = base.split_at(base.len() - MAC_LEN);
        if !bool::from(mac1(&self.mac1_key, body).ct_eq(sent_mac1)) {
            return None;
        }
        Some(VerifiedMac1 {
            base,
            sent_mac1,
            sent_mac2: mac2,
        })
    }

    fn cookies_for_source(
        &self,
        source_tag: &[u8],
    ) -> ([u8; COOKIE_LEN], Option<[u8; COOKIE_LEN]>) {
        let mut guard = self.secret.lock();
        let now = Instant::now();
        if now.duration_since(guard.rotated_at) >= self.rotation_interval {
            let mut next = [0u8; 32];
            OsRng.fill_bytes(&mut next);
            let old = std::mem::replace(&mut guard.current, next);
            guard.previous = Some(old);
            guard.rotated_at = now;
        }
        let curr: [u8; COOKIE_LEN] = blake3::keyed_hash(&guard.current, source_tag).as_bytes()
            [..COOKIE_LEN]
            .try_into()
            .expect("blake3 output is 32 bytes");
        let prev = guard.previous.as_ref().map(|p| {
            blake3::keyed_hash(p, source_tag).as_bytes()[..COOKIE_LEN]
                .try_into()
                .expect("blake3 output is 32 bytes")
        });
        (curr, prev)
    }

    fn build_challenge(&self, cookie: &[u8; COOKIE_LEN], sent_mac1: &[u8]) -> [u8; CHALLENGE_LEN] {
        let mut out = [0u8; CHALLENGE_LEN];
        let (nonce_bytes, rest) = out.split_at_mut(24);
        let (ct, tag_out) = rest.split_at_mut(COOKIE_LEN);
        OsRng.fill_bytes(nonce_bytes);
        ct.copy_from_slice(cookie);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.cookie_enc_key));
        let nonce = XNonce::from_slice(nonce_bytes);
        let tag = cipher
            .encrypt_in_place_detached(nonce, sent_mac1, ct)
            .expect("16-byte cookie always seals");
        tag_out.copy_from_slice(tag.as_slice());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScopeKeypair;
    use crate::crypto::noise_ik;

    #[test]
    fn mac2_cookie_challenge_roundtrip_and_rotation() {
        let a = ScopeKeypair::generate();
        let b = ScopeKeypair::generate();
        let protector = CookieProtector::new(b.public_key(), Duration::from_secs(60));
        let (mut seg, _) = noise_ik::initiate(&a, b.public_key(), &[0; 32], b"hello").unwrap();

        // Not under load: passes in 0-RTT without MAC2.
        assert!(matches!(
            protector.verify_segment(b"127.0.0.1:1234", &seg, false),
            CookieCheck::Verified(_)
        ));

        // Under load without MAC2 -> stateless encrypted challenge.
        protector.set_under_load(true);
        let sent_mac1: [u8; 16] = seg[seg.len() - 16..].try_into().unwrap();
        let challenge = match protector.verify_segment(b"127.0.0.1:1234", &seg, false) {
            CookieCheck::Challenge(ch) => ch,
            _ => panic!("expected challenge"),
        };

        // Wrong mac1 cannot unseal the challenge.
        let mut wrong_mac1 = sent_mac1;
        wrong_mac1[0] ^= 1;
        assert!(unseal_cookie_challenge(b.public_key(), &wrong_mac1, &challenge).is_err());

        // Legitimate initiator unseals cookie and retries with MAC2.
        let cookie = unseal_cookie_challenge(b.public_key(), &sent_mac1, &challenge).unwrap();
        append_mac2(&mut seg, &cookie);

        // Matching source succeeds; spoofed source is re-challenged.
        assert!(matches!(
            protector.verify_segment(b"127.0.0.1:1234", &seg, true),
            CookieCheck::Verified(_)
        ));
        assert!(matches!(
            protector.verify_segment(b"10.0.0.99:9999", &seg, true),
            CookieCheck::Challenge(_)
        ));
    }
}
