pub mod aead;
pub mod noise_ik;
pub mod replay;

use rand_core::OsRng;
use subtle::ConstantTimeEq;
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ScopeKid(pub [u8; 8]);

pub struct ScopeKeypair {
    secret: StaticSecret,
    public: PublicKey,
    kid: ScopeKid,
    mac_key: [u8; 32],
}
impl Drop for ScopeKeypair {
    fn drop(&mut self) {
        self.mac_key.zeroize();
    }
}
impl ScopeKeypair {
    pub fn generate() -> Self {
        Self::from_secret(StaticSecret::random_from_rng(OsRng))
    }
    pub fn from_bytes(secret: [u8; 32]) -> Self {
        Self::from_secret(secret.into())
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
    pub fn public_key(&self) -> PublicKey {
        self.public
    }
    pub fn kid(&self) -> ScopeKid {
        self.kid
    }

    /// Stack-only, before X25519 or policy. The mutable routing header is not
    /// part of the segment and can be rewritten by upstream nodes.
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
}
pub fn scope_kid(key: PublicKey) -> ScopeKid {
    ScopeKid(
        blake3::derive_key("confluence-v1-kid", &key.0)[..8]
            .try_into()
            .unwrap(),
    )
}
fn mac_key(key: PublicKey) -> [u8; 32] {
    blake3::derive_key("confluence-v1-mac1", &key.0)
}
fn mac1(key: &[u8; 32], bytes: &[u8]) -> [u8; 16] {
    blake3::keyed_hash(key, bytes).as_bytes()[..16]
        .try_into()
        .unwrap()
}
