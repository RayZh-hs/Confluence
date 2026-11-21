use crate::error::{CoreError, Result};
use blake2::{Blake2s256, Digest};
use rand::rngs::OsRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Maximum permitted byte length of an opaque credential on the wire.
pub const MAX_CREDENTIAL_BYTES: usize = 256;

/// Maximum permitted UTF-8 byte length of a published endpoint name.
pub const MAX_ENDPOINT_NAME_BYTES: usize = 128;

/// Maximum permitted UTF-8 byte length of a channel address descriptor.
pub const MAX_CHANNEL_ADDR_BYTES: usize = 256;

/// The two strictly separated traffic planes in Confluence Core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Plane {
    Datagram,
    Stream,
}

impl fmt::Display for Plane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Plane::Datagram => f.write_str("datagram"),
            Plane::Stream => f.write_str("stream"),
        }
    }
}

/// A 32-byte X25519 static public key identifying a peer within a Trust Scope or a forwardable channel.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId(pub [u8; 32]);

impl PeerId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Computes the deterministic 8-byte opaque `target_tag = BLAKE2s256(pubkey)[..8]`
    /// used for single-listener demultiplexing across scopes and forwardable channels.
    pub fn target_tag(&self) -> TargetTag {
        TargetTag::from_pubkey(self)
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for PeerId {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self> {
        let raw = hex::decode(s.trim())
            .map_err(|e| CoreError::InvalidInput(format!("invalid PeerId hex: {e}")))?;
        let arr: [u8; 32] = raw.try_into().map_err(|_| {
            CoreError::InvalidInput("PeerId must decode to exactly 32 bytes".into())
        })?;
        Ok(Self(arr))
    }
}

impl Serialize for PeerId {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PeerId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// 8-byte opaque target identifier (`BLAKE2s256(static_pubkey)[..8]`) used to dispatch
/// setup and control segments without revealing endpoint or hop structure on the wire.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TargetTag(pub [u8; 8]);

impl TargetTag {
    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    pub fn from_pubkey(pubkey: &PeerId) -> Self {
        let digest = Blake2s256::digest(pubkey.as_bytes());
        let mut tag = [0u8; 8];
        tag.copy_from_slice(&digest[..8]);
        Self(tag)
    }

    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl fmt::Debug for TargetTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TargetTag({})", hex::encode(self.0))
    }
}

impl fmt::Display for TargetTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for TargetTag {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self> {
        let raw = hex::decode(s.trim())
            .map_err(|e| CoreError::InvalidInput(format!("invalid TargetTag hex: {e}")))?;
        let arr: [u8; 8] = raw.try_into().map_err(|_| {
            CoreError::InvalidInput("TargetTag must decode to exactly 8 bytes".into())
        })?;
        Ok(Self(arr))
    }
}

impl Serialize for TargetTag {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for TargetTag {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// An X25519 static keypair used for a Trust Scope or a forwardable channel.
/// Secret material is automatically zeroized when dropped.
#[derive(Clone)]
pub struct StaticKeypair {
    secret: StaticSecret,
    peer_id: PeerId,
}

impl StaticKeypair {
    /// Generates a fresh cryptographically random X25519 static keypair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            secret,
            peer_id: PeerId(public.to_bytes()),
        }
    }

    /// Reconstructs an X25519 static keypair from 32 raw secret bytes.
    pub fn from_secret_bytes(mut bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        bytes.zeroize();
        let public = PublicKey::from(&secret);
        Self {
            secret,
            peer_id: PeerId(public.to_bytes()),
        }
    }

    /// Parses a hex-encoded 32-byte secret key.
    pub fn from_secret_hex(hex_str: &str) -> Result<Self> {
        let mut raw = hex::decode(hex_str.trim())
            .map_err(|e| CoreError::InvalidInput(format!("invalid secret key hex: {e}")))?;
        let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
            CoreError::InvalidInput("secret key must decode to exactly 32 bytes".into())
        })?;
        raw.zeroize();
        Ok(Self::from_secret_bytes(arr))
    }

    /// Exports the 32-byte secret key (for keygen / explicit persistence only).
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Returns the public `PeerId` corresponding to this keypair.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the 8-byte `TargetTag` derived from this keypair's public key.
    pub fn target_tag(&self) -> TargetTag {
        self.peer_id.target_tag()
    }

    /// Computes X25519 Diffie-Hellman shared secret, rejecting low-order points in constant time.
    pub fn diffie_hellman(&self, remote_pub: &PeerId) -> Result<[u8; 32]> {
        let pk = PublicKey::from(remote_pub.0);
        let shared = self.secret.diffie_hellman(&pk);
        let bytes = shared.to_bytes();
        if bool::from(bytes.ct_eq(&[0u8; 32])) {
            return Err(CoreError::AuthFailed);
        }
        Ok(bytes)
    }
}

impl fmt::Debug for StaticKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticKeypair")
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
}

/// Local identifier for an isolated Trust Scope on a Node.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ScopeId(pub String);

impl ScopeId {
    pub fn new(id: impl Into<String>) -> Result<Self> {
        let s = id.into();
        if s.is_empty() || s.len() > 128 {
            return Err(CoreError::InvalidInput(
                "ScopeId must be 1..=128 bytes".into(),
            ));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ScopeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Local identifier for a mounted channel or transport carrier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ChannelId(pub String);

impl ChannelId {
    pub fn new(id: impl Into<String>) -> Result<Self> {
        let s = id.into();
        if s.is_empty() || s.len() > 128 {
            return Err(CoreError::InvalidInput(
                "ChannelId must be 1..=128 bytes".into(),
            ));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ChannelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Transport-level address or slot target interpreted only by the owning channel plugin.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ChannelAddr(pub String);

impl ChannelAddr {
    pub fn new(addr: impl Into<String>) -> Result<Self> {
        let s = addr.into();
        if s.is_empty() || s.len() > MAX_CHANNEL_ADDR_BYTES {
            return Err(CoreError::InvalidInput(format!(
                "ChannelAddr must be 1..={MAX_CHANNEL_ADDR_BYTES} bytes"
            )));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Display for ChannelAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Name of an explicitly published endpoint within a Trust Scope.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EndpointName(pub String);

impl EndpointName {
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let s = name.into();
        if s.is_empty() || s.len() > MAX_ENDPOINT_NAME_BYTES {
            return Err(CoreError::InvalidInput(format!(
                "EndpointName must be 1..={MAX_ENDPOINT_NAME_BYTES} bytes"
            )));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EndpointName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Bounded opaque credential passed untouched through Core to an `AccessControl` verifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OpaqueCredential(Vec<u8>);

impl OpaqueCredential {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > MAX_CREDENTIAL_BYTES {
            return Err(CoreError::InvalidInput(format!(
                "OpaqueCredential exceeds maximum {MAX_CREDENTIAL_BYTES} bytes"
            )));
        }
        Ok(Self(bytes))
    }

    pub fn from_utf8(token: impl AsRef<str>) -> Result<Self> {
        Self::new(token.as_ref().as_bytes().to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// 4-byte flat datagram forwarding/session label.
/// `HopLabel(0)` is reserved exclusively for control-plane packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HopLabel(pub u32);

impl HopLabel {
    pub const CONTROL: Self = Self(0);

    pub const fn is_control(self) -> bool {
        self.0 == 0
    }

    pub const fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    pub const fn from_be_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }
}

/// 16-byte random identifier correlating single-pass setup and renewal for a circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CircuitId(pub [u8; 16]);

impl CircuitId {
    pub fn random() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}
