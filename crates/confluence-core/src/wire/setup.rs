//! Zero-copy codecs for single-pass `SETUP_FWD`, `SETUP_OK`, `SETUP_ERR`, and `SETUP_COOKIE` frames.

use crate::{
    CoreErr, Plane,
    cid::Cid,
    crypto::cookie::{CHALLENGE_LEN, MAC_LEN},
    wire::{u16_at, u32_at},
};

pub const FWD: u8 = 0x11;
pub const OK: u8 = 0x12;
pub const ERR: u8 = 0x13;
/// Stateless rotating-cookie challenge returned when a responder or hop is under DoS load.
pub const COOKIE: u8 = 0x14;

pub const FWD_HEADER: usize = 8;
/// Base `SETUP_OK` size: `12B OkHeader + 58B Noise_IK reply (32B eph + 10B ack + 16B tag)`.
pub const OK_SIZE: usize = 70;
/// Size of one per-hop encrypted `ttl_ms` lease trailer appended to `SETUP_OK` (`8B + 16B tag`).
pub const HOP_ACK_SIZE: usize = 24;
pub const ERR_SIZE: usize = 36;
pub const COOKIE_SIZE: usize = 8 + CHALLENGE_LEN;

pub const SEGMENT_OVERHEAD: usize = 120;
pub const MAX_SETUP: usize = FWD_HEADER + 8 + 2 * u16::MAX as usize;

/// Mode bit indicating the segment carries a trailing 16-byte `mac2` flood cookie tag.
pub const MODE_MAC2: u8 = 0x10;

#[derive(Clone, Copy, Debug)]
pub struct ForwardHeader {
    pub max_mtu: u16,
    pub upstream: Cid,
}

impl ForwardHeader {
    pub fn parse(buf: &[u8]) -> Result<Self, CoreErr> {
        if buf.len() < FWD_HEADER || buf[0] != FWD || buf[1] != 0 {
            return Err(CoreErr::Malformed);
        }
        Ok(Self {
            max_mtu: u16_at(buf, 2),
            upstream: Cid::from_raw(u32_at(buf, 4)),
        })
    }

    pub fn encode(self) -> [u8; FWD_HEADER] {
        let mut buf = [0; FWD_HEADER];
        buf[0] = FWD;
        buf[2..4].copy_from_slice(&self.max_mtu.to_be_bytes());
        buf[4..8].copy_from_slice(&self.upstream.raw().to_be_bytes());
        buf
    }
}

/// Parsed leading segment of a `SETUP_FWD` flight.
pub struct Segment<'a> {
    /// `true` for an intermediate transit hop (`mode = 1`), `false` for destination (`mode = 2`).
    pub is_hop: bool,
    pub plane: Plane,
    pub min_mtu: u16,
    pub has_mac2: bool,
    pub prefix: &'a [u8],
    pub encrypted: &'a [u8],
    pub tail: &'a [u8],
}

pub fn prefix_size(mode: u8) -> Result<usize, CoreErr> {
    if mode & !0x13 != 0 {
        return Err(CoreErr::Malformed);
    }
    match mode & 0x0f {
        1 => Ok(8),
        2 => Ok(6),
        _ => Err(CoreErr::Malformed),
    }
}

pub fn mode_has_mac2(mode: u8) -> bool {
    (mode & MODE_MAC2) != 0
}

pub fn encoded_size(prefix: &[u8]) -> Result<usize, CoreErr> {
    let mode = *prefix.first().ok_or(CoreErr::Malformed)?;
    let size = prefix_size(mode)?;
    if prefix.len() != size {
        return Err(CoreErr::Malformed);
    }
    let segment = u16_at(prefix, 4) as usize;
    let tail = if size == 8 {
        u16_at(prefix, 6) as usize
    } else {
        0
    };
    let min_seg = SEGMENT_OVERHEAD + if mode_has_mac2(mode) { MAC_LEN } else { 0 };
    if segment < min_seg || (size == 8 && tail < 6 + SEGMENT_OVERHEAD) {
        return Err(CoreErr::Malformed);
    }
    Ok(size + segment + tail)
}

pub fn prefix(
    plane: Plane,
    min_mtu: u16,
    is_hop: bool,
    len: usize,
    tail: usize,
) -> Result<Vec<u8>, CoreErr> {
    prefix_with_mac2(plane, min_mtu, is_hop, false, len, tail)
}

pub fn prefix_with_mac2(
    plane: Plane,
    min_mtu: u16,
    is_hop: bool,
    has_mac2: bool,
    len: usize,
    tail: usize,
) -> Result<Vec<u8>, CoreErr> {
    let len = u16::try_from(len).map_err(|_| CoreErr::Malformed)?;
    let tail = u16::try_from(tail).map_err(|_| CoreErr::Malformed)?;
    let mode = if is_hop { 1 } else { 2 } | if has_mac2 { MODE_MAC2 } else { 0 };
    let mut buf = Vec::with_capacity(if is_hop { 8 } else { 6 });
    buf.push(mode);
    buf.push(plane as u8);
    buf.extend_from_slice(&min_mtu.to_be_bytes());
    buf.extend_from_slice(&len.to_be_bytes());
    if is_hop {
        buf.extend_from_slice(&tail.to_be_bytes());
    }
    Ok(buf)
}

impl<'a> Segment<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Self, CoreErr> {
        let mode = *buf.first().ok_or(CoreErr::Malformed)?;
        let size = prefix_size(mode)?;
        let prefix = buf.get(..size).ok_or(CoreErr::Malformed)?;
        if encoded_size(prefix)? != buf.len() {
            return Err(CoreErr::Malformed);
        }
        let end = size + u16_at(prefix, 4) as usize;
        Ok(Self {
            is_hop: size == 8,
            plane: prefix[1].try_into()?,
            min_mtu: u16_at(prefix, 2),
            has_mac2: mode_has_mac2(mode),
            prefix,
            encrypted: &buf[size..end],
            tail: &buf[end..],
        })
    }

    pub fn aad(&self) -> [u8; 32] {
        tail_aad(self.prefix, self.tail)
    }
}

/// Computes the route-integrity AEAD Associated Data binding the dispatch prefix and
/// entire immutable downstream tail.
pub fn tail_aad(prefix: &[u8], tail: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(prefix);
    h.update(tail);
    *h.finalize().as_bytes()
}

#[derive(Clone, Copy, Debug)]
pub struct OkHeader {
    /// Number of appended 24-byte per-hop encrypted lease trailers (in reverse hop order).
    pub hop_acks: u8,
    pub reverse_mtu: u16,
    pub target: Cid,
    pub responder: Cid,
}

impl OkHeader {
    /// Parses only the 12-byte `SETUP_OK` header (useful when reading variable-length replies on streams).
    pub fn parse_header(buf: &[u8]) -> Result<Self, CoreErr> {
        if buf.len() < 12 || buf[0] != OK {
            return Err(CoreErr::Malformed);
        }
        Ok(Self {
            hop_acks: buf[1],
            reverse_mtu: u16_at(buf, 2),
            target: Cid::from_raw(u32_at(buf, 4)),
            responder: Cid::from_raw(u32_at(buf, 8)),
        })
    }

    pub fn parse(buf: &[u8]) -> Result<Self, CoreErr> {
        let header = Self::parse_header(buf)?;
        let expected = OK_SIZE + usize::from(header.hop_acks) * HOP_ACK_SIZE;
        if buf.len() != expected {
            return Err(CoreErr::Malformed);
        }
        Ok(header)
    }

    pub fn encode(self) -> [u8; 12] {
        let mut buf = [0; 12];
        buf[0] = OK;
        buf[1] = self.hop_acks;
        buf[2..4].copy_from_slice(&self.reverse_mtu.to_be_bytes());
        buf[4..8].copy_from_slice(&self.target.raw().to_be_bytes());
        buf[8..12].copy_from_slice(&self.responder.raw().to_be_bytes());
        buf
    }
}

pub fn error_header(distance: u8, target: Cid) -> [u8; 8] {
    let mut buf = [ERR, distance, 0, 0, 0, 0, 0, 0];
    buf[4..8].copy_from_slice(&target.raw().to_be_bytes());
    buf
}

pub fn parse_error(buf: &[u8]) -> Result<(u8, Cid, &[u8]), CoreErr> {
    if buf.len() != ERR_SIZE || buf[0] != ERR || buf[2..4] != [0, 0] {
        return Err(CoreErr::Malformed);
    }
    Ok((buf[1], Cid::from_raw(u32_at(buf, 4)), &buf[8..]))
}

pub fn encode_cookie(
    distance: u8,
    target: Cid,
    challenge: &[u8; CHALLENGE_LEN],
) -> [u8; COOKIE_SIZE] {
    let mut buf = [0; COOKIE_SIZE];
    buf[0] = COOKIE;
    buf[1] = distance;
    buf[4..8].copy_from_slice(&target.raw().to_be_bytes());
    buf[8..].copy_from_slice(challenge);
    buf
}

pub fn parse_cookie(buf: &[u8]) -> Result<(u8, Cid, &[u8]), CoreErr> {
    if buf.len() != COOKIE_SIZE || buf[0] != COOKIE || buf[2..4] != [0, 0] {
        return Err(CoreErr::Malformed);
    }
    Ok((buf[1], Cid::from_raw(u32_at(buf, 4)), &buf[8..]))
}

pub fn error_code(error: &CoreErr) -> (u16, u16) {
    match error {
        CoreErr::MtuTooSmall(mtu) => (1, *mtu),
        CoreErr::Denied => (2, 0),
        CoreErr::Unpublished => (3, 0),
        CoreErr::WrongPlane => (4, 0),
        CoreErr::Timeout => (5, 0),
        CoreErr::Busy => (6, 0),
        CoreErr::Revoked => (7, 0),
        CoreErr::Expired => (8, 0),
        CoreErr::Closed => (9, 0),
        CoreErr::TargetRefused => (11, 0),
        CoreErr::TargetUnreachable => (12, 0),
        CoreErr::UnexpectedEof => (13, 0),
        _ => (10, 0),
    }
}

pub fn decode_error(bytes: &[u8]) -> Result<CoreErr, CoreErr> {
    if bytes.len() != 4 {
        return Err(CoreErr::Malformed);
    }
    Ok(match u16_at(bytes, 0) {
        1 => CoreErr::MtuTooSmall(u16_at(bytes, 2)),
        2 => CoreErr::Denied,
        3 => CoreErr::Unpublished,
        4 => CoreErr::WrongPlane,
        5 => CoreErr::Timeout,
        6 => CoreErr::Busy,
        7 => CoreErr::Revoked,
        8 => CoreErr::Expired,
        9 => CoreErr::Closed,
        10 => CoreErr::Carrier("remote carrier failure".into()),
        11 => CoreErr::TargetRefused,
        12 => CoreErr::TargetUnreachable,
        13 => CoreErr::UnexpectedEof,
        _ => return Err(CoreErr::Malformed),
    })
}
