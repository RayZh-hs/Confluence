use crate::error::{CoreError, Result};
use crate::types::PeerId;
use blake2::{Blake2s256, Digest};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use hmac::{Mac, SimpleHmac};
use parking_lot::Mutex;
use rand::{rngs::OsRng, RngCore};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

/// Byte length of MAC1 and MAC2 tags on handshake envelopes.
pub const HANDSHAKE_MAC_BYTES: usize = 16;

/// Byte length of a stateless cookie.
pub const COOKIE_BYTES: usize = 16;

type HmacBlake2s = SimpleHmac<Blake2s256>;

fn derive_label_key(label: &[u8], responder_pubkey: &PeerId) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(label);
    hasher.update(responder_pubkey.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn compute_mac16(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = <HmacBlake2s as Mac>::new_from_slice(key).expect("HMAC accepts arbitrary key len");
    mac.update(data);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// Seals a `Noise_IK` Message 1 with pre-DH `MAC1` and optional DoS-cookie `MAC2`.
///
/// Envelope layout:
/// `[ inner_len: u16 BE ][ inner_noise_msg1 ][ mac1: 16B ][ mac2: 16B ]`
///
/// Returns `(envelope_bytes, mac1)` so the initiator can authenticate a subsequent
/// `CookieChallenge` bound to `mac1` if the responder is under flood.
pub fn seal_handshake_envelope(
    responder_pubkey: &PeerId,
    inner_noise_msg1: &[u8],
    cookie: Option<&[u8; COOKIE_BYTES]>,
) -> Result<(Vec<u8>, [u8; HANDSHAKE_MAC_BYTES])> {
    let len_u16 = u16::try_from(inner_noise_msg1.len())
        .map_err(|_| CoreError::Framing("handshake message exceeds u16".into()))?;

    let mut out = Vec::with_capacity(2 + inner_noise_msg1.len() + 2 * HANDSHAKE_MAC_BYTES);
    out.extend_from_slice(&len_u16.to_be_bytes());
    out.extend_from_slice(inner_noise_msg1);

    let mac1_key = derive_label_key(b"conf-mac1----", responder_pubkey);
    let mac1 = compute_mac16(&mac1_key, &out);
    out.extend_from_slice(&mac1);

    let mac2 = match cookie {
        Some(c) => compute_mac16(c, &out),
        None => [0u8; HANDSHAKE_MAC_BYTES],
    };
    out.extend_from_slice(&mac2);

    Ok((out, mac1))
}

/// Unseals an XChaCha20Poly1305 encrypted cookie challenge returned by a responder under load,
/// verifying AAD binding to the initiator's original `sent_mac1`.
pub fn unseal_cookie_challenge(
    responder_pubkey: &PeerId,
    sent_mac1: &[u8; HANDSHAKE_MAC_BYTES],
    challenge: &[u8],
) -> Result<[u8; COOKIE_BYTES]> {
    // 24B XNonce + 16B cookie + 16B Poly1305 tag = 56 bytes.
    if challenge.len() != 24 + COOKIE_BYTES + 16 {
        return Err(CoreError::AuthFailed);
    }
    let cookie_key = derive_label_key(b"conf-cookie--", responder_pubkey);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&cookie_key));
    let xnonce = XNonce::from_slice(&challenge[..24]);
    let pt = cipher
        .decrypt(
            xnonce,
            Payload {
                msg: &challenge[24..],
                aad: sent_mac1,
            },
        )
        .map_err(|_| CoreError::AuthFailed)?;

    let mut cookie = [0u8; COOKIE_BYTES];
    cookie.copy_from_slice(&pt);
    Ok(cookie)
}

struct RotatingSecret {
    current: [u8; 32],
    previous: Option<[u8; 32]>,
    rotated_at: Instant,
}

/// Outcome of fast pre-DH verification of a handshake envelope.
pub enum EnvelopeCheck<'a> {
    /// Envelope `MAC1` (and `MAC2` if under load) verified; slice is `inner_noise_msg1`.
    Verified(&'a [u8]),
    /// Responder is under flood and `MAC2` was missing/invalid; send stateless `challenge` back.
    Challenge(Vec<u8>),
    /// Invalid framing or `MAC1` mismatch — discard silently before touching X25519!
    Drop,
}

/// Stateless pre-authentication DoS protector implementing WireGuard-style `MAC1` + rotating `MAC2` cookies.
pub struct CookieProtector {
    mac1_key: [u8; 32],
    cookie_enc_key: [u8; 32],
    rotation_interval: Duration,
    under_load: AtomicBool,
    secret: Mutex<RotatingSecret>,
}

impl CookieProtector {
    pub fn new(responder_pubkey: PeerId, rotation_interval: Duration) -> Self {
        let mut initial = [0u8; 32];
        OsRng.fill_bytes(&mut initial);
        Self {
            mac1_key: derive_label_key(b"conf-mac1----", &responder_pubkey),
            cookie_enc_key: derive_label_key(b"conf-cookie--", &responder_pubkey),
            rotation_interval: rotation_interval.max(Duration::from_secs(1)),
            under_load: AtomicBool::new(false),
            secret: Mutex::new(RotatingSecret {
                current: initial,
                previous: None,
                rotated_at: Instant::now(),
            }),
        }
    }

    /// Toggles flood mode (`under_load`). When `true`, valid `MAC2` cookies are required before any X25519 DH.
    pub fn set_under_load(&self, under_load: bool) {
        self.under_load.store(under_load, Ordering::Relaxed);
    }

    pub fn is_under_load(&self) -> bool {
        self.under_load.load(Ordering::Relaxed)
    }

    /// Verifies `MAC1` (always) and `MAC2` (when `under_load`) in constant time before any X25519 DH.
    pub fn verify_envelope<'a>(
        &self,
        source_addr_bytes: &[u8],
        envelope: &'a [u8],
    ) -> EnvelopeCheck<'a> {
        if envelope.len() < 2 + 2 * HANDSHAKE_MAC_BYTES {
            return EnvelopeCheck::Drop;
        }
        let inner_len = u16::from_be_bytes([envelope[0], envelope[1]]) as usize;
        if envelope.len() != 2 + inner_len + 2 * HANDSHAKE_MAC_BYTES {
            return EnvelopeCheck::Drop;
        }

        let msg_through_inner = &envelope[..2 + inner_len];
        let mac1_slice = &envelope[2 + inner_len..2 + inner_len + HANDSHAKE_MAC_BYTES];
        let mac2_slice = &envelope[2 + inner_len + HANDSHAKE_MAC_BYTES..];

        // 1. Always verify MAC1 before spending CPU on cookies or X25519 DH.
        let expected_mac1 = compute_mac16(&self.mac1_key, msg_through_inner);
        if !bool::from(mac1_slice.ct_eq(&expected_mac1)) {
            return EnvelopeCheck::Drop;
        }

        // 2. If not under load, proceed immediately in 0-RTT.
        if !self.is_under_load() {
            return EnvelopeCheck::Verified(&envelope[2..2 + inner_len]);
        }

        // 3. Under load: require valid stateless MAC2 derived from source address.
        let (curr_cookie, prev_cookie) = self.cookies_for_source(source_addr_bytes);
        let msg_through_mac1 = &envelope[..2 + inner_len + HANDSHAKE_MAC_BYTES];
        let expected_curr = compute_mac16(&curr_cookie, msg_through_mac1);
        if bool::from(mac2_slice.ct_eq(&expected_curr)) {
            return EnvelopeCheck::Verified(&envelope[2..2 + inner_len]);
        }
        if let Some(prev) = prev_cookie {
            let expected_prev = compute_mac16(&prev, msg_through_mac1);
            if bool::from(mac2_slice.ct_eq(&expected_prev)) {
                return EnvelopeCheck::Verified(&envelope[2..2 + inner_len]);
            }
        }

        // Issue stateless XChaCha20Poly1305 encrypted cookie reply bound to initiator's MAC1.
        match self.build_challenge(&curr_cookie, mac1_slice) {
            Ok(challenge) => EnvelopeCheck::Challenge(challenge),
            Err(_) => EnvelopeCheck::Drop,
        }
    }

    fn cookies_for_source(
        &self,
        source_addr_bytes: &[u8],
    ) -> ([u8; COOKIE_BYTES], Option<[u8; COOKIE_BYTES]>) {
        let mut guard = self.secret.lock();
        let now = Instant::now();
        if now.duration_since(guard.rotated_at) >= self.rotation_interval {
            let mut next = [0u8; 32];
            OsRng.fill_bytes(&mut next);
            let old = std::mem::replace(&mut guard.current, next);
            guard.previous = Some(old);
            guard.rotated_at = now;
        }
        let curr = compute_mac16(&guard.current, source_addr_bytes);
        let prev = guard
            .previous
            .as_ref()
            .map(|p| compute_mac16(p, source_addr_bytes));
        (curr, prev)
    }

    fn build_challenge(&self, cookie: &[u8; COOKIE_BYTES], mac1: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.cookie_enc_key));
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: cookie,
                    aad: mac1,
                },
            )
            .map_err(|_| CoreError::AuthFailed)?;

        let mut out = Vec::with_capacity(24 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }
}
