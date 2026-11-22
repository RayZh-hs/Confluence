//! Cryptographic primitives for Confluence Core v1 (X25519 + ChaCha20-Poly1305 + BLAKE3).

pub mod aead;
pub mod cookie;
pub mod noise_ik;
pub mod replay;

use rand_core::OsRng;
use std::{fmt, str::FromStr};
use subtle::ConstantTimeEq;
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;

use crate::CoreErr;

/// A 32-byte X25519 static public key identifying a peer within a Trust Scope or channel.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    /// Returns the raw 32-byte key material.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Computes the unlinkable 8-byte key identifier (`scope_kid`) for this public key.
    pub fn kid(&self) -> ScopeKid {
        scope_kid(*self)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", encode_hex(&self.0[..8]))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode_hex(&self.0))
    }
}

impl FromStr for PublicKey {
    type Err = CoreErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out = [0u8; 32];
        decode_hex(s.trim(), &mut out)?;
        Ok(Self(out))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Unlinkable 8-byte key identifier (`BLAKE3_derive_key("confluence-v1-kid", pubkey)[..8]`)
/// used for $O(1)$ scope and channel dispatch without exposing public keys in cleartext.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopeKid(pub [u8; 8]);

impl fmt::Debug for ScopeKid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ScopeKid({})", encode_hex(&self.0))
    }
}

impl fmt::Display for ScopeKid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode_hex(&self.0))
    }
}

impl FromStr for ScopeKid {
    type Err = CoreErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out = [0u8; 8];
        decode_hex(s.trim(), &mut out)?;
        Ok(Self(out))
    }
}

/// Per-scope or per-channel X25519 static identity keypair (zeroized on drop).
pub struct ScopeKeypair {
    secret: StaticSecret,
    public: PublicKey,
    kid: ScopeKid,
    mac_key: [u8; 32],
}

impl fmt::Debug for ScopeKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopeKeypair")
            .field("public", &self.public)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl Drop for ScopeKeypair {
    fn drop(&mut self) {
        self.mac_key.zeroize();
    }
}

impl ScopeKeypair {
    /// Generates a fresh cryptographically random X25519 static keypair.
    pub fn generate() -> Self {
        Self::from_secret(StaticSecret::random_from_rng(OsRng))
    }

    /// Constructs a keypair from 32 raw secret bytes.
    pub fn from_bytes(mut secret: [u8; 32]) -> Self {
        let kp = Self::from_secret(secret.into());
        secret.zeroize();
        kp
    }

    /// Parses a 64-character hex-encoded X25519 secret key.
    pub fn from_secret_hex(hex_str: &str) -> Result<Self, CoreErr> {
        let mut raw = [0u8; 32];
        decode_hex(hex_str.trim(), &mut raw)?;
        Ok(Self::from_bytes(raw))
    }

    /// Exports the 32-byte secret key (for keygen / explicit local persistence only).
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Exports the secret key as lowercase 64-character hex.
    pub fn secret_hex(&self) -> String {
        let mut raw = self.secret_bytes();
        let encoded = encode_hex(&raw);
        raw.zeroize();
        encoded
    }

    fn from_secret(secret: StaticSecret) -> Self {
        let public = PublicKey(x25519_dalek::PublicKey::from(&secret).to_bytes());
        Self {
            secret,
            public,
            kid: scope_kid(public),
            mac_key: mac_key(public),
        }
    }

    /// Returns the public key for this identity.
    pub fn public_key(&self) -> PublicKey {
        self.public
    }

    /// Returns the unlinkable 8-byte `ScopeKid` derived from this identity's public key.
    pub fn kid(&self) -> ScopeKid {
        self.kid
    }

    /// Stack-only, zero-allocation pre-DH verification of `scope_kid` and `mac1`.
    /// The mutable routing header is not part of the segment and can be rewritten by upstream nodes.
    pub fn verify_mac1(&self, segment: &[u8]) -> bool {
        if segment.len() < crate::wire::setup::SEGMENT_OVERHEAD {
            return false;
        }
        if !bool::from(self.kid.0.ct_eq(&segment[..8])) {
            return false;
        }
        let (body, mac) = segment.split_at(segment.len() - 16);
        bool::from(mac1(&self.mac_key, body).ct_eq(mac))
    }

    /// Stack-only pre-DH verification supporting segments with or without a trailing 16B `mac2`.
    pub fn verify_mac1_with_flag(&self, segment: &[u8], has_mac2: bool) -> bool {
        if has_mac2 {
            if segment.len() < crate::wire::setup::SEGMENT_OVERHEAD + cookie::MAC_LEN {
                return false;
            }
            self.verify_mac1(&segment[..segment.len() - cookie::MAC_LEN])
        } else {
            self.verify_mac1(segment)
        }
    }
}

/// Computes the 8-byte unlinkable `ScopeKid` for `key`.
pub fn scope_kid(key: PublicKey) -> ScopeKid {
    ScopeKid(
        blake3::derive_key("confluence-v1-kid", &key.0)[..8]
            .try_into()
            .expect("blake3 output is 32 bytes"),
    )
}

pub(crate) fn mac_key(key: PublicKey) -> [u8; 32] {
    blake3::derive_key("confluence-v1-mac1", &key.0)
}

pub(crate) fn mac1(key: &[u8; 32], bytes: &[u8]) -> [u8; 16] {
    blake3::keyed_hash(key, bytes).as_bytes()[..16]
        .try_into()
        .expect("blake3 output is 32 bytes")
}

fn encode_hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex(input: &str, out: &mut [u8]) -> Result<(), CoreErr> {
    if input.len() != out.len() * 2 {
        return Err(CoreErr::Malformed);
    }
    let bytes = input.as_bytes();
    for (idx, dst) in out.iter_mut().enumerate() {
        let hi = hex_nibble(bytes[idx * 2])?;
        let lo = hex_nibble(bytes[idx * 2 + 1])?;
        *dst = (hi << 4) | lo;
    }
    Ok(())
}

fn hex_nibble(c: u8) -> Result<u8, CoreErr> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(CoreErr::Malformed),
    }
}
