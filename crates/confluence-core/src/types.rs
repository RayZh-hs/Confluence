//! Foundational identity, plane, circuit, publication, and credential value types.

use core::borrow::Borrow;
use core::fmt;
use core::ops::Deref;
use core::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::constants::{
    CREDENTIAL_MAX, DATAGRAM_MIN_MTU, NAME_MAX_LEN, NAME_MIN_LEN, STREAM_MIN_MTU,
};
use crate::error::CoreError;

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

fn format_hex_lower(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut pair = [0u8; 2];
    for &b in bytes {
        pair[0] = HEX_LOWER[(b >> 4) as usize];
        pair[1] = HEX_LOWER[(b & 0x0f) as usize];
        if let Ok(s) = core::str::from_utf8(&pair) {
            f.write_str(s)?;
        }
    }
    Ok(())
}

pub(crate) fn encode_hex_lower_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX_LOWER[(b >> 4) as usize]));
        out.push(char::from(HEX_LOWER[(b & 0x0f) as usize]));
    }
    out
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn decode_hex_exact<const N: usize>(input: &str) -> Result<[u8; N], CoreError> {
    let trimmed = input.trim();
    let raw = trimmed.as_bytes();
    if raw.len() != N * 2 {
        return Err(CoreError::InvalidParameter);
    }
    let mut out = [0u8; N];
    for (slot, pair) in out.iter_mut().zip(raw.chunks_exact(2)) {
        let hi = hex_nibble(pair[0]).ok_or(CoreError::InvalidParameter)?;
        let lo = hex_nibble(pair[1]).ok_or(CoreError::InvalidParameter)?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

/// 32-byte X25519 static public key identifying a Trust Scope.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Constructs a `PublicKey` from 32 raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw 32-byte key representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constant-time equality check against another `PublicKey`.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl From<[u8; 32]> for PublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_hex_lower(&self.0, f)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

impl FromStr for PublicKey {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        decode_hex_exact::<32>(s).map(Self)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&encode_hex_lower_string(&self.0))
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// 8-byte unlinkable key identifier derived from a Trust Scope's public key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopeKid([u8; 8]);

impl ScopeKid {
    /// Constructs a `ScopeKid` from 8 raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    /// Returns the raw 8-byte scope identifier.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    /// Constant-time equality check against another `ScopeKid`.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl From<[u8; 8]> for ScopeKid {
    fn from(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for ScopeKid {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for ScopeKid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_hex_lower(&self.0, f)
    }
}

impl fmt::Debug for ScopeKid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ScopeKid({self})")
    }
}

impl FromStr for ScopeKid {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        decode_hex_exact::<8>(s).map(Self)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ScopeKid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&encode_hex_lower_string(&self.0))
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ScopeKid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Transport plane selector. Stream and Datagram planes never mix inside Core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum Plane {
    /// Discrete, unreliable, message-oriented datagrams (wire value `1`).
    Datagram = 1,
    /// Reliable, ordered, continuous byte streams (wire value `2`).
    Stream = 2,
}

impl Plane {
    /// Parses a wire plane discriminator byte (`1` = Datagram, `2` = Stream).
    pub const fn from_u8(raw: u8) -> Result<Self, CoreError> {
        match raw {
            1 => Ok(Self::Datagram),
            2 => Ok(Self::Stream),
            _ => Err(CoreError::Malformed),
        }
    }

    /// Encodes the plane as its normative v1 wire byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Returns the normative minimum effective wire MTU for this plane.
    #[must_use]
    pub const fn minimum_mtu(self) -> u16 {
        match self {
            Self::Datagram => DATAGRAM_MIN_MTU,
            Self::Stream => STREAM_MIN_MTU,
        }
    }

    /// Returns a static lowercase label safe for structured tracing.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Datagram => "datagram",
            Self::Stream => "stream",
        }
    }
}

/// Data-plane traffic direction relative to a verifier (Destination or Transit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Direction {
    /// Traffic flowing from Originator toward Destination.
    Ingress,
    /// Traffic flowing from Destination toward Originator.
    Egress,
}

/// Role of a local scope in an active session or transit circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Role {
    /// Session initiator (`A`).
    Origin,
    /// Terminal endpoint host (`B`).
    Destination,
    /// Intermediate named-transit forwarder (`H_i`).
    Transit,
}

impl Role {
    /// Returns a static lowercase label safe for structured tracing.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Origin => "origin",
            Self::Destination => "destination",
            Self::Transit => "transit",
        }
    }
}

/// Per-link 32-bit datagram circuit identifier (`[generation: 8b | slot: 24b]`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cid(u32);

impl Cid {
    /// Unbound CID (`0`), used for setup frames and on the Stream plane.
    pub const UNBOUND: Self = Self(0);

    /// Maximum 24-bit slot index representable inside a `Cid`.
    pub const MAX_SLOT: u32 = 0x00ff_ffff;

    /// Constructs a `Cid` from its raw big-endian wire value.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Constructs a bound `Cid` from a non-zero 8-bit generation and 24-bit slot index.
    #[must_use]
    pub const fn from_parts(generation: u8, slot: u32) -> Option<Self> {
        if generation == 0 || slot > Self::MAX_SLOT {
            return None;
        }
        Some(Self(((generation as u32) << 24) | slot))
    }

    /// Returns the raw 32-bit value.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Returns `true` iff this CID is [`Self::UNBOUND`].
    #[must_use]
    pub const fn is_unbound(self) -> bool {
        self.0 == 0
    }

    /// Extracts the 8-bit generation counter (`1..=255` for valid bound CIDs).
    #[must_use]
    pub const fn generation(self) -> u8 {
        (self.0 >> 24) as u8
    }

    /// Extracts the 24-bit slot index.
    #[must_use]
    pub const fn slot(self) -> u32 {
        self.0 & Self::MAX_SLOT
    }
}

impl fmt::Debug for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cid(0x{:08x})", self.0)
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

static NEXT_LINK_ID: AtomicU64 = AtomicU64::new(1);

/// Stable logical identifier deduplicating shared [`crate::channel::DatagramLink`] instances.
///
/// Allocated IDs reserve bit 63 (`(1 << 63) | seq`) while pointer-derived fallback IDs
/// clear bit 63 (`ptr & !(1 << 63)`), structurally guaranteeing disjointness.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkId(u64);

impl LinkId {
    const ALLOCATED_BIT: u64 = 1u64 << 63;

    /// Allocates a globally unique logical `LinkId` with bit 63 set.
    #[must_use]
    pub fn allocate() -> Self {
        let seq = NEXT_LINK_ID.fetch_add(1, Ordering::Relaxed);
        Self(Self::ALLOCATED_BIT | (seq & !Self::ALLOCATED_BIT))
    }

    /// Derives a fallback `LinkId` from an `Arc` allocation address with bit 63 cleared.
    #[must_use]
    pub fn from_arc<T: ?Sized>(arc: &Arc<T>) -> Self {
        let addr = Arc::as_ptr(arc) as *const () as usize as u64;
        Self(addr & !Self::ALLOCATED_BIT)
    }

    /// Returns the raw 64-bit identifier.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for LinkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LinkId(0x{:016x})", self.0)
    }
}

static NEXT_PUBLICATION_ID: AtomicU64 = AtomicU64::new(1);

/// Monotonic unique identifier assigned to each published Endpoint or Transit instance.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PublicationId(u64);

impl PublicationId {
    /// Allocates the next monotonic non-zero `PublicationId`.
    #[must_use]
    pub fn next() -> Self {
        Self(NEXT_PUBLICATION_ID.fetch_add(1, Ordering::Relaxed))
    }

    /// Returns the raw 64-bit publication identifier.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Borrowed reference to a logical Endpoint or Transit target on a specific plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetRef<'a> {
    /// Terminal endpoint published on destination `B`.
    Endpoint {
        /// Logical UTF-8 endpoint name (`1..=255` bytes).
        name: &'a str,
        /// Transport plane.
        plane: Plane,
    },
    /// Forwarding exit published on an intermediate transit hop `H_i`.
    Transit {
        /// Full logical UTF-8 transit name requested by the originator (`1..=255` bytes).
        name: &'a str,
        /// Transport plane.
        plane: Plane,
    },
}

impl<'a> TargetRef<'a> {
    /// Returns the logical target name.
    #[must_use]
    pub const fn name(&self) -> &'a str {
        match self {
            Self::Endpoint { name, .. } | Self::Transit { name, .. } => name,
        }
    }

    /// Returns the target plane.
    #[must_use]
    pub const fn plane(&self) -> Plane {
        match self {
            Self::Endpoint { plane, .. } | Self::Transit { plane, .. } => *plane,
        }
    }

    /// Returns `true` if this reference names a Transit target.
    #[must_use]
    pub const fn is_transit(&self) -> bool {
        matches!(self, Self::Transit { .. })
    }
}

/// Validated UTF-8 identifier enforcing the normative `1..=255` byte length bound.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValidatedName(String);

impl ValidatedName {
    /// Validates a borrowed string slice against the normative `1..=255` UTF-8 byte bound.
    pub fn validate_str(name: &str) -> Result<&str, CoreError> {
        let len = name.len();
        if (NAME_MIN_LEN..=NAME_MAX_LEN).contains(&len) {
            Ok(name)
        } else {
            Err(CoreError::InvalidParameter)
        }
    }

    /// Constructs a `ValidatedName`, failing with [`CoreError::InvalidParameter`] if empty or `> 255` bytes.
    pub fn new(name: impl Into<String>) -> Result<Self, CoreError> {
        let s = name.into();
        Self::validate_str(&s)?;
        Ok(Self(s))
    }

    /// Returns the validated string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper and returns the inner `String`.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Deref for ValidatedName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Borrow<str> for ValidatedName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ValidatedName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ValidatedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Crate-owned opaque caller credential (`0..=128` bytes), zeroized on drop and redacted in `Debug`.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct Credential(Vec<u8>);

impl Credential {
    /// Creates an empty 0-byte credential (public-key-only authentication).
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Constructs a `Credential` from owned bytes, enforcing `<= 128` bytes.
    ///
    /// If validation fails, the oversized input buffer is zeroized before returning.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, CoreError> {
        let mut buf = bytes.into();
        if buf.len() > CREDENTIAL_MAX {
            buf.zeroize();
            return Err(CoreError::InvalidParameter);
        }
        Ok(Self(buf))
    }

    /// Constructs a `Credential` by copying a byte slice, enforcing `<= 128` bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() > CREDENTIAL_MAX {
            return Err(CoreError::InvalidParameter);
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Returns the raw credential bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the byte length of the credential (`0..=128`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the credential is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl PartialEq for Credential {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.as_slice().ct_eq(other.0.as_slice()))
    }
}

impl Eq for Credential {}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Credential([REDACTED; {} bytes])", self.0.len())
    }
}

impl TryFrom<Vec<u8>> for Credential {
    type Error = CoreError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&[u8]> for Credential {
    type Error = CoreError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn public_key_and_scope_kid_hex_roundtrip() {
        let bytes = [
            0x00, 0x01, 0x0a, 0xab, 0xcd, 0xef, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
            0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0xff, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf1, 0x23, 0x45,
        ];
        let pk = PublicKey::from_bytes(bytes);
        let hex = pk.to_string();
        assert_eq!(hex.len(), 64);
        assert_eq!(hex, hex.to_ascii_lowercase());

        let upper_padded = format!("  {} \n\t", hex.to_ascii_uppercase());
        let parsed: PublicKey = upper_padded.parse().unwrap();
        assert_eq!(parsed, pk);
        assert!(parsed.ct_eq(&pk));

        assert!("deadbeef".parse::<PublicKey>().is_err());
        assert!(format!("{hex}00").parse::<PublicKey>().is_err());

        let kid = ScopeKid::from_bytes([0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67]);
        let kid_hex = kid.to_string();
        assert_eq!(kid_hex, "deadbeef01234567");
        assert_eq!("  DEADBEEF01234567 ".parse::<ScopeKid>().unwrap(), kid);
        assert!("deadbeef".parse::<ScopeKid>().is_err());
    }

    #[test]
    fn link_id_allocated_and_arc_are_structurally_disjoint() {
        let alloc1 = LinkId::allocate();
        let alloc2 = LinkId::allocate();
        assert_ne!(alloc1, alloc2);
        assert_ne!(alloc1.raw() & (1u64 << 63), 0);

        let arc = Arc::new(42u64);
        let fallback = LinkId::from_arc(&arc);
        assert_eq!(fallback.raw() & (1u64 << 63), 0);
        assert_ne!(alloc1, fallback);
    }

    #[test]
    fn credential_bounds_and_redacted_debug() {
        assert!(Credential::from_slice(&[0u8; 128]).is_ok());
        assert_eq!(
            Credential::from_slice(&[0u8; 129]),
            Err(CoreError::InvalidParameter)
        );
        let cred = Credential::new(b"super-secret-token".to_vec()).unwrap();
        let dbg = format!("{cred:?}");
        assert!(!dbg.contains("super-secret-token"));
        assert!(dbg.contains("REDACTED"));
    }

    #[test]
    fn cid_parts_and_plane_floors() {
        assert!(Cid::UNBOUND.is_unbound());
        assert_eq!(Cid::from_parts(0, 1), None);
        assert_eq!(Cid::from_parts(1, Cid::MAX_SLOT + 1), None);
        let cid = Cid::from_parts(255, 0x12_3456).unwrap();
        assert_eq!(cid.generation(), 255);
        assert_eq!(cid.slot(), 0x12_3456);
        assert!(!cid.is_unbound());

        assert_eq!(Plane::Datagram.minimum_mtu(), 1152);
        assert_eq!(Plane::Stream.minimum_mtu(), 20);
        assert_eq!(Plane::from_u8(1), Ok(Plane::Datagram));
        assert_eq!(Plane::from_u8(2), Ok(Plane::Stream));
        assert_eq!(Plane::from_u8(3), Err(CoreError::Malformed));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_hex_roundtrip() {
        let pk = PublicKey::from_bytes([0xab; 32]);
        let json = serde_json::to_string(&pk).unwrap();
        assert_eq!(json, format!("\"{}\"", "ab".repeat(32)));
        let back: PublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pk);

        let kid = ScopeKid::from_bytes([0x0f; 8]);
        let kid_json = serde_json::to_string(&kid).unwrap();
        assert_eq!(kid_json, format!("\"{}\"", "0f".repeat(8)));
        let kid_back: ScopeKid = serde_json::from_str(&kid_json).unwrap();
        assert_eq!(kid_back, kid);
    }
}
