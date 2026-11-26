//! Setup, cookie, error, fragment, and CID-routing wire codecs (Spec §5.2–5.7.1).

use zeroize::Zeroizing;

use crate::constants::{
    CHALLENGE_LEN, COOKIE_SIZE, CREDENTIAL_MAX, ERR_BODY_SIZE, ERR_SIZE, FRAG_HEADER, FWD_HEADER,
    HOP_ACK_SIZE, MAC_LEN, MAX_FRAGS, MIN_FRAGS, NAME_MAX_LEN, NAME_MIN_LEN, OK_SIZE, REPLY_LEN,
    SEGMENT_OVERHEAD, SETUP_PLAINTEXT_MAX, SETUP_PLAINTEXT_MIN,
};
use crate::error::CoreError;
use crate::packet::PacketBuf;
use crate::types::{Cid, Plane, ScopeKid};
use crate::wire::opcodes::outer;

/// Transit hop segment dispatch mode (`mode & 0x0f == 1`).
pub const MODE_HOP: u8 = 0x01;
/// Destination endpoint segment dispatch mode (`mode & 0x0f == 2`).
pub const MODE_DEST: u8 = 0x02;
/// Bit flag indicating a trailing 16-byte `mac2` tag is appended to the segment.
pub const MODE_MAC2: u8 = 0x10;

/// 8-byte `SETUP_FWD` (`0x11`) outer forward header (Spec §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardHeader {
    pub max_mtu: u16,
    pub upstream: Cid,
}

impl ForwardHeader {
    #[must_use]
    pub fn encode(self) -> [u8; FWD_HEADER] {
        let mut out = [0u8; FWD_HEADER];
        out[0] = outer::SETUP_FWD;
        out[1] = 0x00;
        out[2..4].copy_from_slice(&self.max_mtu.to_be_bytes());
        out[4..8].copy_from_slice(&self.upstream.raw().to_be_bytes());
        out
    }

    pub fn parse(buf: &[u8]) -> Result<Self, CoreError> {
        if buf.len() < FWD_HEADER || buf[0] != outer::SETUP_FWD || buf[1] != 0x00 {
            return Err(CoreError::Malformed);
        }
        let max_mtu = u16::from_be_bytes([buf[2], buf[3]]);
        let upstream = Cid::from_raw(u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]));
        Ok(Self { max_mtu, upstream })
    }
}

/// 6-byte (destination) or 8-byte (hop) segment dispatch prefix (Spec §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchPrefix {
    pub is_hop: bool,
    pub has_mac2: bool,
    pub plane: Plane,
    pub min_mtu: u16,
    pub seg_len: u16,
    pub tail_len: u16,
}

impl DispatchPrefix {
    /// Minimum valid `tail_len` for a hop segment (`6` dest prefix + `120` base segment).
    pub const MIN_HOP_TAIL_LEN: usize = 6 + SEGMENT_OVERHEAD;

    #[must_use]
    pub const fn prefix_len(&self) -> usize {
        if self.is_hop { 8 } else { 6 }
    }

    /// Total encoded length of this prefix + encrypted segment + downstream tail.
    #[must_use]
    pub const fn encoded_total_len(&self) -> usize {
        self.prefix_len() + (self.seg_len as usize) + (self.tail_len as usize)
    }

    #[must_use]
    pub const fn mode_byte(&self) -> u8 {
        let base = if self.is_hop { MODE_HOP } else { MODE_DEST };
        if self.has_mac2 { base | MODE_MAC2 } else { base }
    }

    /// Encodes the prefix into `out` and returns the slice length (`6` or `8`).
    pub fn encode(&self, out: &mut [u8; 8]) -> usize {
        out[0] = self.mode_byte();
        out[1] = self.plane.as_u8();
        out[2..4].copy_from_slice(&self.min_mtu.to_be_bytes());
        out[4..6].copy_from_slice(&self.seg_len.to_be_bytes());
        if self.is_hop {
            out[6..8].copy_from_slice(&self.tail_len.to_be_bytes());
            8
        } else {
            6
        }
    }

    /// Parses a dispatch prefix from the start of `buf`, returning `(prefix, raw_prefix_bytes)`.
    pub fn parse(buf: &[u8]) -> Result<(Self, &[u8]), CoreError> {
        if buf.len() < 6 {
            return Err(CoreError::Malformed);
        }
        let mode = buf[0];
        if (mode & !0x13) != 0 {
            return Err(CoreError::Malformed);
        }
        let is_hop = match mode & 0x0f {
            MODE_HOP => true,
            MODE_DEST => false,
            _ => return Err(CoreError::Malformed),
        };
        let has_mac2 = (mode & MODE_MAC2) != 0;
        let plane = Plane::from_u8(buf[1])?;
        let min_mtu = u16::from_be_bytes([buf[2], buf[3]]);
        let seg_len = u16::from_be_bytes([buf[4], buf[5]]);
        let min_seg = SEGMENT_OVERHEAD + if has_mac2 { MAC_LEN } else { 0 };
        if usize::from(seg_len) < min_seg {
            return Err(CoreError::Malformed);
        }

        if is_hop {
            if buf.len() < 8 {
                return Err(CoreError::Malformed);
            }
            let tail_len = u16::from_be_bytes([buf[6], buf[7]]);
            if usize::from(tail_len) < Self::MIN_HOP_TAIL_LEN {
                return Err(CoreError::Malformed);
            }
            let prefix = Self {
                is_hop,
                has_mac2,
                plane,
                min_mtu,
                seg_len,
                tail_len,
            };
            Ok((prefix, &buf[..8]))
        } else {
            let prefix = Self {
                is_hop,
                has_mac2,
                plane,
                min_mtu,
                seg_len,
                tail_len: 0,
            };
            Ok((prefix, &buf[..6]))
        }
    }
}

/// Borrowed leading segment view (used for stack-only fragment-0 and stream prechecks before `tail`).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct LeadingSegment<'a> {
    pub prefix: DispatchPrefix,
    pub prefix_bytes: &'a [u8],
    pub encrypted: &'a [u8],
}

impl<'a> LeadingSegment<'a> {
    /// Parses prefix and leading encrypted segment without requiring `tail` to be present yet.
    pub fn parse_leading(buf: &'a [u8]) -> Result<Self, CoreError> {
        let (prefix, prefix_bytes) = DispatchPrefix::parse(buf)?;
        let start = prefix.prefix_len();
        let end = start + usize::from(prefix.seg_len);
        if buf.len() < end {
            return Err(CoreError::Malformed);
        }
        Ok(Self {
            prefix,
            prefix_bytes,
            encrypted: &buf[start..end],
        })
    }

    /// Extracts the leading 8-byte [`ScopeKid`] (guaranteed present since `seg_len >= 120`).
    #[must_use]
    pub fn scope_kid(&self) -> ScopeKid {
        let mut kid = [0u8; 8];
        kid.copy_from_slice(&self.encrypted[0..8]);
        ScopeKid::from_bytes(kid)
    }
}

/// Complete borrowed segment view with exact length verification against `prefix` (Spec §5.2).
#[derive(Debug, Clone, Copy)]
pub struct ParsedSegment<'a> {
    pub prefix: DispatchPrefix,
    pub prefix_bytes: &'a [u8],
    pub encrypted: &'a [u8],
    pub tail: &'a [u8],
}

impl<'a> ParsedSegment<'a> {
    /// Parses a complete segment buffer (immediately following the 8-byte `ForwardHeader`).
    pub fn parse_full(buf: &'a [u8]) -> Result<Self, CoreError> {
        let (prefix, prefix_bytes) = DispatchPrefix::parse(buf)?;
        if buf.len() != prefix.encoded_total_len() {
            return Err(CoreError::Malformed);
        }
        let seg_start = prefix.prefix_len();
        let seg_end = seg_start + usize::from(prefix.seg_len);
        Ok(Self {
            prefix,
            prefix_bytes,
            encrypted: &buf[seg_start..seg_end],
            tail: &buf[seg_end..],
        })
    }

    /// Extracts the leading 8-byte [`ScopeKid`].
    #[must_use]
    pub fn scope_kid(&self) -> ScopeKid {
        let mut kid = [0u8; 8];
        kid.copy_from_slice(&self.encrypted[0..8]);
        ScopeKid::from_bytes(kid)
    }
}

/// Decrypted Noise_IK Message 1 setup plaintext codec (Spec §4.6).
pub struct SetupPlaintext;

impl SetupPlaintext {
    /// Encodes `[ts_ms:8 | name_len:1 | name | cred_len:2 | cred]` into a zeroizing buffer.
    pub fn encode(
        ts_ms: u64,
        name: &str,
        credential: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        let name_bytes = name.as_bytes();
        if !(NAME_MIN_LEN..=NAME_MAX_LEN).contains(&name_bytes.len())
            || credential.len() > CREDENTIAL_MAX
        {
            return Err(CoreError::InvalidParameter);
        }
        let name_len = u8::try_from(name_bytes.len()).map_err(|_| CoreError::InvalidParameter)?;
        let cred_len = u16::try_from(credential.len()).map_err(|_| CoreError::InvalidParameter)?;

        let mut out = Zeroizing::new(Vec::with_capacity(11 + name_bytes.len() + credential.len()));
        out.extend_from_slice(&ts_ms.to_be_bytes());
        out.push(name_len);
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(&cred_len.to_be_bytes());
        out.extend_from_slice(credential);
        Ok(out)
    }

    /// Parses and strictly validates exact length, UTF-8 name, and `<= 128 B` credential.
    pub fn parse(buf: &[u8]) -> Result<(u64, &str, &[u8]), CoreError> {
        if !(SETUP_PLAINTEXT_MIN..=SETUP_PLAINTEXT_MAX).contains(&buf.len()) {
            return Err(CoreError::Malformed);
        }
        let ts_ms = u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
        let name_len = usize::from(buf[8]);
        if name_len < NAME_MIN_LEN || buf.len() < 11 + name_len {
            return Err(CoreError::Malformed);
        }
        let name = core::str::from_utf8(&buf[9..9 + name_len]).map_err(|_| CoreError::Malformed)?;
        let cred_len_pos = 9 + name_len;
        let cred_len =
            usize::from(u16::from_be_bytes([buf[cred_len_pos], buf[cred_len_pos + 1]]));
        if cred_len > CREDENTIAL_MAX || buf.len() != 11 + name_len + cred_len {
            return Err(CoreError::Malformed);
        }
        Ok((ts_ms, name, &buf[11 + name_len..]))
    }
}

/// 12-byte `SETUP_OK` (`0x12`) outer header (Spec §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupOkHeader {
    pub hop_acks: u8,
    pub reverse_mtu: u16,
    pub target_cid: Cid,
    pub responder_cid: Cid,
}

impl SetupOkHeader {
    /// Encodes a base 70-byte `SETUP_OK` frame (header + 58-byte Noise reply).
    #[must_use]
    pub fn encode_base(self, reply: &[u8; REPLY_LEN]) -> Vec<u8> {
        let mut out = Vec::with_capacity(OK_SIZE);
        out.push(outer::SETUP_OK);
        out.push(self.hop_acks);
        out.extend_from_slice(&self.reverse_mtu.to_be_bytes());
        out.extend_from_slice(&self.target_cid.raw().to_be_bytes());
        out.extend_from_slice(&self.responder_cid.raw().to_be_bytes());
        out.extend_from_slice(reply);
        out
    }

    /// Writes updated header fields into the leading 12 bytes of an existing `SETUP_OK` buffer.
    pub fn write_into(self, wire: &mut [u8]) -> Result<(), CoreError> {
        if wire.len() < 12 {
            return Err(CoreError::Malformed);
        }
        wire[0] = outer::SETUP_OK;
        wire[1] = self.hop_acks;
        wire[2..4].copy_from_slice(&self.reverse_mtu.to_be_bytes());
        wire[4..8].copy_from_slice(&self.target_cid.raw().to_be_bytes());
        wire[8..12].copy_from_slice(&self.responder_cid.raw().to_be_bytes());
        Ok(())
    }

    /// Parses a complete `SETUP_OK` frame and verifies `wire.len() == 70 + 26 * hop_acks`.
    pub fn parse(wire: &[u8]) -> Result<(Self, &[u8; REPLY_LEN], &[u8]), CoreError> {
        if wire.len() < OK_SIZE || wire[0] != outer::SETUP_OK {
            return Err(CoreError::Malformed);
        }
        let hop_acks = wire[1];
        let expected_len = OK_SIZE + HOP_ACK_SIZE * usize::from(hop_acks);
        if wire.len() != expected_len {
            return Err(CoreError::Malformed);
        }
        let reverse_mtu = u16::from_be_bytes([wire[2], wire[3]]);
        let target_cid = Cid::from_raw(u32::from_be_bytes([wire[4], wire[5], wire[6], wire[7]]));
        let responder_cid =
            Cid::from_raw(u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]));
        let reply: &[u8; REPLY_LEN] = wire[12..OK_SIZE]
            .try_into()
            .map_err(|_| CoreError::Malformed)?;
        let trailers = &wire[OK_SIZE..];
        Ok((
            Self {
                hop_acks,
                reverse_mtu,
                target_cid,
                responder_cid,
            },
            reply,
            trailers,
        ))
    }
}

/// 36-byte `SETUP_ERR` (`0x13`) frame (Spec §5.4).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupErrFrame {
    pub distance: u8,
    pub target_cid: Cid,
    pub body: [u8; ERR_BODY_SIZE],
}

#[allow(dead_code)]
impl SetupErrFrame {
    #[must_use]
    pub fn encode(self) -> [u8; ERR_SIZE] {
        let mut out = [0u8; ERR_SIZE];
        out[0] = outer::SETUP_ERR;
        out[1] = self.distance;
        out[2] = 0x00;
        out[3] = 0x00;
        out[4..8].copy_from_slice(&self.target_cid.raw().to_be_bytes());
        out[8..ERR_SIZE].copy_from_slice(&self.body);
        out
    }

    pub fn parse(wire: &[u8]) -> Result<Self, CoreError> {
        if wire.len() != ERR_SIZE
            || wire[0] != outer::SETUP_ERR
            || wire[2] != 0x00
            || wire[3] != 0x00
        {
            return Err(CoreError::Malformed);
        }
        let distance = wire[1];
        let target_cid = Cid::from_raw(u32::from_be_bytes([wire[4], wire[5], wire[6], wire[7]]));
        let mut body = [0u8; ERR_BODY_SIZE];
        body.copy_from_slice(&wire[8..ERR_SIZE]);
        Ok(Self {
            distance,
            target_cid,
            body,
        })
    }
}

/// 64-byte `SETUP_COOKIE` (`0x14`) frame (Spec §5.5).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupCookieFrame {
    pub distance: u8,
    pub target_cid: Cid,
    pub challenge: [u8; CHALLENGE_LEN],
}

#[allow(dead_code)]
impl SetupCookieFrame {
    #[must_use]
    pub fn encode(self) -> [u8; COOKIE_SIZE] {
        let mut out = [0u8; COOKIE_SIZE];
        out[0] = outer::SETUP_COOKIE;
        out[1] = self.distance;
        out[2] = 0x00;
        out[3] = 0x00;
        out[4..8].copy_from_slice(&self.target_cid.raw().to_be_bytes());
        out[8..COOKIE_SIZE].copy_from_slice(&self.challenge);
        out
    }

    pub fn parse(wire: &[u8]) -> Result<Self, CoreError> {
        if wire.len() != COOKIE_SIZE
            || wire[0] != outer::SETUP_COOKIE
            || wire[2] != 0x00
            || wire[3] != 0x00
        {
            return Err(CoreError::Malformed);
        }
        let distance = wire[1];
        let target_cid = Cid::from_raw(u32::from_be_bytes([wire[4], wire[5], wire[6], wire[7]]));
        let mut challenge = [0u8; CHALLENGE_LEN];
        challenge.copy_from_slice(&wire[8..COOKIE_SIZE]);
        Ok(Self {
            distance,
            target_cid,
            challenge,
        })
    }
}

/// 16-byte `SETUP_FRAG` (`0x15`) header (Spec §5.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupFragHeader {
    pub index: u8,
    pub count: u8,
    pub upstream_cid: Cid,
    pub message_id: u64,
}

impl SetupFragHeader {
    #[must_use]
    pub fn encode_header(self) -> [u8; FRAG_HEADER] {
        let mut out = [0u8; FRAG_HEADER];
        out[0] = outer::SETUP_FRAG;
        out[1] = self.index;
        out[2] = self.count;
        out[3] = 0x00;
        out[4..8].copy_from_slice(&self.upstream_cid.raw().to_be_bytes());
        out[8..16].copy_from_slice(&self.message_id.to_be_bytes());
        out
    }

    #[must_use]
    pub fn encode_packet(self, payload: &[u8]) -> PacketBuf {
        let mut pkt = PacketBuf::with_capacity(FRAG_HEADER + payload.len());
        let hdr = self.encode_header();
        let spare = pkt.spare_payload();
        spare[..FRAG_HEADER].copy_from_slice(&hdr);
        spare[FRAG_HEADER..FRAG_HEADER + payload.len()].copy_from_slice(payload);
        let _ = pkt.advance_payload(FRAG_HEADER + payload.len());
        pkt
    }

    pub fn parse(wire: &[u8]) -> Result<(Self, &[u8]), CoreError> {
        if wire.len() <= FRAG_HEADER || wire[0] != outer::SETUP_FRAG || wire[3] != 0x00 {
            return Err(CoreError::Malformed);
        }
        let index = wire[1];
        let count = wire[2];
        if !(MIN_FRAGS..=MAX_FRAGS).contains(&usize::from(count)) || index >= count {
            return Err(CoreError::Malformed);
        }
        let upstream_cid =
            Cid::from_raw(u32::from_be_bytes([wire[4], wire[5], wire[6], wire[7]]));
        if upstream_cid.is_unbound() {
            return Err(CoreError::Malformed);
        }
        let message_id = u64::from_be_bytes([
            wire[8], wire[9], wire[10], wire[11], wire[12], wire[13], wire[14], wire[15],
        ]);
        Ok((
            Self {
                index,
                count,
                upstream_cid,
                message_id,
            },
            &wire[FRAG_HEADER..],
        ))
    }
}

/// Exact 16-byte `SETUP_FRAG_ACK` (`0x16`) receipt (Spec §5.6).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupFragAck {
    pub upstream_cid: Cid,
    pub message_id: u64,
}

#[allow(dead_code)]
impl SetupFragAck {
    #[must_use]
    pub fn encode(self) -> [u8; FRAG_HEADER] {
        let mut out = [0u8; FRAG_HEADER];
        out[0] = outer::SETUP_FRAG_ACK;
        out[1] = 0x00;
        out[2] = 0x00;
        out[3] = 0x00;
        out[4..8].copy_from_slice(&self.upstream_cid.raw().to_be_bytes());
        out[8..16].copy_from_slice(&self.message_id.to_be_bytes());
        out
    }

    pub fn parse(wire: &[u8]) -> Result<Self, CoreError> {
        if wire.len() != FRAG_HEADER
            || wire[0] != outer::SETUP_FRAG_ACK
            || wire[1..4] != [0x00, 0x00, 0x00]
        {
            return Err(CoreError::Malformed);
        }
        let upstream_cid =
            Cid::from_raw(u32::from_be_bytes([wire[4], wire[5], wire[6], wire[7]]));
        if upstream_cid.is_unbound() {
            return Err(CoreError::Malformed);
        }
        let message_id = u64::from_be_bytes([
            wire[8], wire[9], wire[10], wire[11], wire[12], wire[13], wire[14], wire[15],
        ]);
        Ok(Self {
            upstream_cid,
            message_id,
        })
    }
}

/// Extracts the inbound datagram dispatch CID per Spec §5.7.1 (`route_cid`).
///
/// Returns `Some(Cid::UNBOUND)` for setup/fragment packets (`0x11`, `0x15`), `Some(cid)` for
/// bound circuit packets (`0x12..=0x14`, `0x16`, `0x20`, `0x23..=0x27`), and `None` for
/// reserved, unknown, or truncated packets.
#[must_use]
pub fn route_cid(packet: &[u8]) -> Option<Cid> {
    let &op = packet.first()?;
    if outer::is_reserved(op) {
        return None;
    }
    match op {
        outer::DG_DATA => {
            if packet.len() < 5 {
                return None;
            }
            Some(Cid::from_raw(u32::from_be_bytes([
                packet[1], packet[2], packet[3], packet[4],
            ])))
        }
        outer::DG_CLOSE
        | outer::DG_MTU
        | outer::DG_RENEW
        | outer::DG_RENEW_OK
        | outer::DG_MTU_ACK => {
            if packet.len() < 6 {
                return None;
            }
            Some(Cid::from_raw(u32::from_be_bytes([
                packet[2], packet[3], packet[4], packet[5],
            ])))
        }
        outer::SETUP_OK | outer::SETUP_ERR | outer::SETUP_COOKIE | outer::SETUP_FRAG_ACK => {
            if packet.len() < 8 {
                return None;
            }
            Some(Cid::from_raw(u32::from_be_bytes([
                packet[4], packet[5], packet[6], packet[7],
            ])))
        }
        outer::SETUP_FWD | outer::SETUP_FRAG => Some(Cid::UNBOUND),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn route_cid_matches_all_normative_offsets_and_rejects_reserved() {
        let cid = Cid::from_parts(3, 0x0001_0203).unwrap();
        let cb = cid.raw().to_be_bytes();

        // 0x20: offset 1
        assert_eq!(route_cid(&[0x20, cb[0], cb[1], cb[2], cb[3]]), Some(cid));
        assert_eq!(route_cid(&[0x20, 1, 2, 3]), None);

        // 0x23..=0x27: offset 2
        for op in [0x23u8, 0x24, 0x25, 0x26, 0x27] {
            assert_eq!(
                route_cid(&[op, 0, cb[0], cb[1], cb[2], cb[3]]),
                Some(cid)
            );
            assert_eq!(route_cid(&[op, 0, 1, 2, 3]), None);
        }

        // 0x12, 0x13, 0x14, 0x16: offset 4
        for op in [0x12u8, 0x13, 0x14, 0x16] {
            assert_eq!(
                route_cid(&[op, 0, 0, 0, cb[0], cb[1], cb[2], cb[3]]),
                Some(cid)
            );
            assert_eq!(route_cid(&[op, 0, 0, 0, 1, 2, 3]), None);
        }

        // 0x11, 0x15 -> UNBOUND
        assert_eq!(route_cid(&[0x11]), Some(Cid::UNBOUND));
        assert_eq!(route_cid(&[0x15]), Some(Cid::UNBOUND));

        // Reserved & stream opcodes -> None
        for op in [0x21u8, 0x22, 0x30, 0x31, 0x32, 0x33, 0xFF] {
            assert_eq!(route_cid(&[op, 0, 0, 0, 1, 2, 3, 4]), None);
        }
        assert_eq!(route_cid(&[]), None);
    }

    #[test]
    fn setup_plaintext_strict_bounds_and_utf8() {
        let pt = SetupPlaintext::encode(123456, "echo", b"tok").unwrap();
        assert_eq!(pt.len(), 11 + 4 + 3);
        let (ts, name, cred) = SetupPlaintext::parse(&pt).unwrap();
        assert_eq!((ts, name, cred), (123456, "echo", &b"tok"[..]));

        // Trailing garbage rejected.
        let mut with_extra = pt.to_vec();
        with_extra.push(0);
        assert_eq!(SetupPlaintext::parse(&with_extra), Err(CoreError::Malformed));

        // Zero name_len rejected.
        let mut zero_name = vec![0u8; 12];
        zero_name[8] = 0;
        assert_eq!(SetupPlaintext::parse(&zero_name), Err(CoreError::Malformed));

        // Credential > 128 rejected.
        assert_eq!(
            SetupPlaintext::encode(1, "a", &[0u8; 129]),
            Err(CoreError::InvalidParameter)
        );
    }

    #[test]
    fn dispatch_prefix_validation_rules() {
        let mut buf = [0u8; 8];
        let dest = DispatchPrefix {
            is_hop: false,
            has_mac2: true,
            plane: Plane::Datagram,
            min_mtu: 1152,
            seg_len: 136,
            tail_len: 0,
        };
        assert_eq!(dest.encode(&mut buf), 6);
        let (parsed, raw) = DispatchPrefix::parse(&buf[..6]).unwrap();
        assert_eq!(parsed, dest);
        assert_eq!(raw.len(), 6);

        // seg_len < 136 when MODE_MAC2 set -> Malformed.
        buf[4..6].copy_from_slice(&135u16.to_be_bytes());
        assert_eq!(DispatchPrefix::parse(&buf[..6]), Err(CoreError::Malformed));

        // Bad reserved mode bits -> Malformed.
        let mut bad = buf;
        bad[0] = 0x21;
        assert_eq!(DispatchPrefix::parse(&bad), Err(CoreError::Malformed));
    }
}
