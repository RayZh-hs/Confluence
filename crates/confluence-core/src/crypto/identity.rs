//! Trust Scope X25519 identity keypair and normative v1 pre-DH BLAKE3 derivations (Spec §4.1–4.2).

use core::fmt;
use core::ops::Deref;

use rand_core::OsRng;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::constants::{COOKIE_LEN, MAC_LEN, SEGMENT_OVERHEAD};
use crate::error::CoreError;
use crate::types::{PublicKey, ScopeKid, decode_hex_exact, encode_hex_lower_string};

/// BLAKE3 KDF context for deriving the 8-byte unlinkable [`ScopeKid`].
pub(crate) const KID_CONTEXT: &str = "confluence-v1-kid";

/// BLAKE3 KDF context for deriving the 32-byte `mac1` key.
pub(crate) const MAC1_CONTEXT: &str = "confluence-v1-mac1";

/// BLAKE3 KDF context for deriving the 32-byte cookie encryption key.
pub(crate) const COOKIE_ENC_CONTEXT: &str = "confluence-v1-cookie";

/// BLAKE3 KDF context for deriving the 32-byte `mac2` key from a 16-byte cookie.
pub(crate) const MAC2_CONTEXT: &str = "confluence-v1-mac2";

/// Zeroized 64-character lowercase hex export of a [`ScopeKeypair`] private key.
///
/// Redacts its contents in `Debug` and zeroizes the string buffer on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretHex(String);

impl SecretHex {
    /// Returns the 64-character lowercase hex string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for SecretHex {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for SecretHex {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretHex([REDACTED])")
    }
}

/// Derives the normative 8-byte [`ScopeKid`] for a public key:
/// `BLAKE3_derive_key("confluence-v1-kid", pk)[0..8]`.
#[must_use]
pub fn derive_scope_kid(pk: &PublicKey) -> ScopeKid {
    let full = blake3::derive_key(KID_CONTEXT, pk.as_bytes());
    let mut kid = [0u8; 8];
    kid.copy_from_slice(&full[0..8]);
    ScopeKid::from_bytes(kid)
}

/// Derives the normative 32-byte `mac1` key for a public key:
/// `BLAKE3_derive_key("confluence-v1-mac1", pk)`.
#[must_use]
pub fn derive_mac1_key(pk: &PublicKey) -> [u8; 32] {
    blake3::derive_key(MAC1_CONTEXT, pk.as_bytes())
}

/// Computes the 16-byte `mac1` tag using a pre-derived `mac1` key.
#[must_use]
pub fn compute_mac1_with_key(mac1_key: &[u8; 32], data: &[u8]) -> [u8; MAC_LEN] {
    let hash = blake3::keyed_hash(mac1_key, data);
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&hash.as_bytes()[0..MAC_LEN]);
    out
}

/// Computes the normative 16-byte `mac1` tag directly for `target_pk`.
#[must_use]
pub fn compute_mac1(target_pk: &PublicKey, data: &[u8]) -> [u8; MAC_LEN] {
    let key = Zeroizing::new(derive_mac1_key(target_pk));
    compute_mac1_with_key(&key, data)
}

/// Derives the normative 32-byte cookie encryption key for a public key:
/// `BLAKE3_derive_key("confluence-v1-cookie", pk)`.
#[must_use]
pub fn derive_cookie_enc_key(pk: &PublicKey) -> [u8; 32] {
    blake3::derive_key(COOKIE_ENC_CONTEXT, pk.as_bytes())
}

/// Derives the normative 32-byte `mac2` key from a 16-byte flood cookie:
/// `BLAKE3_derive_key("confluence-v1-mac2", cookie)`.
#[must_use]
pub fn derive_mac2_key(cookie: &[u8; COOKIE_LEN]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(MAC2_CONTEXT, cookie))
}

/// Computes the normative 16-byte `mac2` tag for `data` under `cookie`.
#[must_use]
pub fn compute_mac2(cookie: &[u8; COOKIE_LEN], data: &[u8]) -> [u8; MAC_LEN] {
    let key = derive_mac2_key(cookie);
    let hash = blake3::keyed_hash(&key, data);
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&hash.as_bytes()[0..MAC_LEN]);
    out
}

/// Independent X25519 static identity keypair owned by one Trust Scope.
///
/// Pre-computes [`ScopeKid`], `mac1_key`, and `cookie_enc_key` so pre-DH packet filtering
/// executes in constant time with zero heap allocations. All secret material is zeroized on drop.
pub struct ScopeKeypair {
    secret: StaticSecret,
    public: PublicKey,
    kid: ScopeKid,
    mac1_key: Zeroizing<[u8; 32]>,
    cookie_enc_key: Zeroizing<[u8; 32]>,
}

impl ScopeKeypair {
    /// Generates a fresh random X25519 identity keypair from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        Self::from_static_secret(secret)
    }

    /// Constructs a `ScopeKeypair` from a 32-byte raw X25519 secret scalar.
    #[must_use]
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let mut owned = Zeroizing::new(bytes);
        let secret = StaticSecret::from(*owned);
        owned.zeroize();
        Self::from_static_secret(secret)
    }

    /// Parses a 64-character hex string (whitespace trimmed, case-insensitive) into a `ScopeKeypair`.
    pub fn from_secret_hex(hex: &str) -> Result<Self, CoreError> {
        let raw = Zeroizing::new(decode_hex_exact::<32>(hex)?);
        Ok(Self::from_secret_bytes(*raw))
    }

    fn from_static_secret(secret: StaticSecret) -> Self {
        let x_pub = X25519PublicKey::from(&secret);
        let public = PublicKey::from_bytes(x_pub.to_bytes());
        let kid = derive_scope_kid(&public);
        let mac1_key = Zeroizing::new(derive_mac1_key(&public));
        let cookie_enc_key = Zeroizing::new(derive_cookie_enc_key(&public));
        Self {
            secret,
            public,
            kid,
            mac1_key,
            cookie_enc_key,
        }
    }

    /// Exports the 32-byte secret scalar as a zeroizing 64-character lowercase hex string.
    #[must_use]
    pub fn to_secret_hex(&self) -> SecretHex {
        let raw = Zeroizing::new(self.secret.to_bytes());
        SecretHex(encode_hex_lower_string(&*raw))
    }

    /// Returns the 32-byte static public key.
    #[must_use]
    pub const fn public_key(&self) -> PublicKey {
        self.public
    }

    /// Returns the derived 8-byte unlinkable [`ScopeKid`].
    #[must_use]
    pub const fn scope_kid(&self) -> ScopeKid {
        self.kid
    }

    #[allow(dead_code)]
    pub(crate) fn mac1_key(&self) -> &[u8; 32] {
        &self.mac1_key
    }

    pub(crate) fn cookie_enc_key(&self) -> &[u8; 32] {
        &self.cookie_enc_key
    }

    pub(crate) fn clone_static_secret(&self) -> StaticSecret {
        let raw = Zeroizing::new(self.secret.to_bytes());
        StaticSecret::from(*raw)
    }

    pub(crate) fn diffie_hellman_raw(&self, peer_bytes: &[u8; 32]) -> [u8; 32] {
        let peer = X25519PublicKey::from(*peer_bytes);
        self.secret.diffie_hellman(&peer).to_bytes()
    }

    /// Constant-time, zero-allocation verification of `ScopeKid` and `mac1` on a base segment
    /// (with any trailing `mac2` already stripped).
    #[must_use]
    pub(crate) fn verify_base_mac1(&self, base_segment: &[u8]) -> bool {
        if base_segment.len() < SEGMENT_OVERHEAD {
            return false;
        }
        let kid_ok = base_segment[0..8].ct_eq(self.kid.as_bytes());
        let (body, sent_mac1) = base_segment.split_at(base_segment.len() - MAC_LEN);
        let expected = compute_mac1_with_key(&self.mac1_key, body);
        let mac_ok = expected.ct_eq(sent_mac1);
        bool::from(kid_ok & mac_ok)
    }

    /// Constant-time, zero-allocation verification of a full segment (`has_mac2` controls
    /// whether the final 16 bytes are stripped before checking `mac1`).
    pub(crate) fn verify_segment_mac1<'a>(
        &self,
        segment: &'a [u8],
        has_mac2: bool,
    ) -> Result<&'a [u8], CoreError> {
        let min_len = SEGMENT_OVERHEAD + if has_mac2 { MAC_LEN } else { 0 };
        if segment.len() < min_len {
            return Err(CoreError::BadMac);
        }
        let base = if has_mac2 {
            &segment[..segment.len() - MAC_LEN]
        } else {
            segment
        };
        if self.verify_base_mac1(base) {
            Ok(base)
        } else {
            Err(CoreError::BadMac)
        }
    }
}

impl Clone for ScopeKeypair {
    fn clone(&self) -> Self {
        Self::from_static_secret(self.clone_static_secret())
    }
}

impl fmt::Debug for ScopeKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopeKeypair")
            .field("kid", &self.kid)
            .field("public", &self.public)
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn blake3_domain_derivations_match_spec_exact() {
        let kp = ScopeKeypair::from_secret_bytes([0x42; 32]);
        let pk = kp.public_key();

        let expected_kid = &blake3::derive_key("confluence-v1-kid", pk.as_bytes())[0..8];
        assert_eq!(kp.scope_kid().as_bytes(), expected_kid);

        let expected_mac1_key = blake3::derive_key("confluence-v1-mac1", pk.as_bytes());
        assert_eq!(kp.mac1_key(), &expected_mac1_key);

        let expected_cookie_key = blake3::derive_key("confluence-v1-cookie", pk.as_bytes());
        assert_eq!(kp.cookie_enc_key(), &expected_cookie_key);

        let msg = b"segment body bytes";
        let mac1_hash = blake3::keyed_hash(&expected_mac1_key, msg);
        assert_eq!(&compute_mac1(&pk, msg), &mac1_hash.as_bytes()[0..16]);

        let cookie = [0x99u8; 16];
        let expected_mac2_key = blake3::derive_key("confluence-v1-mac2", &cookie);
        let mac2_hash = blake3::keyed_hash(&expected_mac2_key, msg);
        assert_eq!(&compute_mac2(&cookie, msg), &mac2_hash.as_bytes()[0..16]);
    }

    #[test]
    fn secret_hex_roundtrip_and_redacted_debug() {
        let kp = ScopeKeypair::generate();
        let hex = kp.to_secret_hex();
        assert_eq!(hex.len(), 64);
        assert!(format!("{hex:?}").contains("REDACTED"));
        assert!(!format!("{kp:?}").contains(hex.as_str()));

        let restored = ScopeKeypair::from_secret_hex(&hex).unwrap();
        assert_eq!(restored.public_key(), kp.public_key());
        assert_eq!(restored.scope_kid(), kp.scope_kid());
    }
}
