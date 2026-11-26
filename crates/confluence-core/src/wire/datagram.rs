//! Datagram hop framing (`DG_DATA` 5 B, control 6 B) and MTU/Renewal payload codecs (Spec §5.7.1, §5.8.1, §6.6–6.7).

use core::time::Duration;

use zeroize::Zeroizing;

use crate::constants::{
    CREDENTIAL_MAX, DG_HOP_CTRL_HEADER, DG_HOP_DATA_HEADER, MAX_CONTROL, MAX_WIRE_LEASE_TTL_MS,
    MIN_CONTROL, MIN_WIRE_LEASE_TTL_MS,
};
use crate::error::CoreError;
use crate::packet::PacketBuf;
use crate::types::Cid;
use crate::wire::opcodes::outer;

/// Prepends the 5-byte `DG_DATA` hop header (`[0x20 | cid: u32 BE]`) in place with zero allocations.
#[allow(dead_code)]
#[inline]
pub fn prepend_dg_data_header(pkt: &mut PacketBuf, cid: Cid) -> Result<(), CoreError> {
    let mut hdr = [0u8; DG_HOP_DATA_HEADER];
    hdr[0] = outer::DG_DATA;
    hdr[1..5].copy_from_slice(&cid.raw().to_be_bytes());
    pkt.prepend_header(&hdr)
}

/// Rewrites bytes `1..5` of an in-place `DG_DATA` packet to `new_cid` (zero-copy transit switching).
#[allow(dead_code)]
#[inline]
pub fn rewrite_dg_data_cid(pkt: &mut PacketBuf, new_cid: Cid) -> Result<(), CoreError> {
    let payload = pkt.payload_mut();
    if payload.len() < DG_HOP_DATA_HEADER || payload[0] != outer::DG_DATA {
        return Err(CoreError::Malformed);
    }
    payload[1..5].copy_from_slice(&new_cid.raw().to_be_bytes());
    Ok(())
}

/// Strips the 5-byte `DG_DATA` hop header in place and returns the embedded `Cid`.
#[allow(dead_code)]
#[inline]
pub fn strip_dg_data_header(pkt: &mut PacketBuf) -> Result<Cid, CoreError> {
    if pkt.len() < DG_HOP_DATA_HEADER || pkt.payload()[0] != outer::DG_DATA {
        return Err(CoreError::Malformed);
    }
    let hdr = pkt.strip_header(DG_HOP_DATA_HEADER)?;
    Ok(Cid::from_raw(u32::from_be_bytes([
        hdr[1], hdr[2], hdr[3], hdr[4],
    ])))
}

/// 6-byte Datagram hop control header (`0x23..=0x27`, Spec §5.7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DgHopControlHeader {
    pub kind: u8,
    pub ttl_or_dist: u8,
    pub cid: Cid,
}

#[allow(dead_code)]
impl DgHopControlHeader {
    #[must_use]
    pub fn encode(self) -> [u8; DG_HOP_CTRL_HEADER] {
        let mut out = [0u8; DG_HOP_CTRL_HEADER];
        out[0] = self.kind;
        out[1] = self.ttl_or_dist;
        out[2..6].copy_from_slice(&self.cid.raw().to_be_bytes());
        out
    }

    /// Parses a complete Datagram hop control packet (`6 B` header + `24..=160 B` body).
    pub fn parse(packet: &[u8]) -> Result<(Self, &[u8]), CoreError> {
        if packet.len() < DG_HOP_CTRL_HEADER || !outer::is_dg_control(packet[0]) {
            return Err(CoreError::Malformed);
        }
        let body = &packet[DG_HOP_CTRL_HEADER..];
        if !(MIN_CONTROL..=MAX_CONTROL).contains(&body.len()) {
            return Err(CoreError::Malformed);
        }
        let cid = Cid::from_raw(u32::from_be_bytes([
            packet[2], packet[3], packet[4], packet[5],
        ]));
        Ok((
            Self {
                kind: packet[0],
                ttl_or_dist: packet[1],
                cid,
            },
            body,
        ))
    }

    /// Encodes a complete hop control frame into a [`PacketBuf`].
    #[must_use]
    pub fn encode_packet(self, body: &[u8]) -> PacketBuf {
        let mut pkt = PacketBuf::with_capacity(DG_HOP_CTRL_HEADER + body.len());
        let hdr = self.encode();
        let spare = pkt.spare_payload();
        spare[..DG_HOP_CTRL_HEADER].copy_from_slice(&hdr);
        spare[DG_HOP_CTRL_HEADER..DG_HOP_CTRL_HEADER + body.len()].copy_from_slice(body);
        let _ = pkt.advance_payload(DG_HOP_CTRL_HEADER + body.len());
        pkt
    }
}

// ---------------------------------------------------------------------------
// Shared MTU & Lease Renewal Control Payloads (Spec §5.8.1, §6.6, §6.7)
// ---------------------------------------------------------------------------

/// Encodes `[epoch: u32 BE | mtu: u16 BE]` (6 bytes).
#[allow(dead_code)]
#[must_use]
pub fn encode_mtu_payload(epoch: u32, mtu: u16) -> [u8; 6] {
    let mut out = [0u8; 6];
    out[0..4].copy_from_slice(&epoch.to_be_bytes());
    out[4..6].copy_from_slice(&mtu.to_be_bytes());
    out
}

/// Decodes an exact 6-byte MTU advertisement payload into `(epoch, mtu)`.
#[allow(dead_code)]
pub fn decode_mtu_payload(bytes: &[u8]) -> Result<(u32, u16), CoreError> {
    if bytes.len() != 6 {
        return Err(CoreError::Malformed);
    }
    let epoch = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let mtu = u16::from_be_bytes([bytes[4], bytes[5]]);
    Ok((epoch, mtu))
}

/// Encodes `[epoch: u32 BE]` (4 bytes).
#[allow(dead_code)]
#[must_use]
pub fn encode_mtu_ack_payload(epoch: u32) -> [u8; 4] {
    epoch.to_be_bytes()
}

/// Decodes an exact 4-byte MTU ACK payload into `epoch`.
#[allow(dead_code)]
pub fn decode_mtu_ack_payload(bytes: &[u8]) -> Result<u32, CoreError> {
    if bytes.len() != 4 {
        return Err(CoreError::Malformed);
    }
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Encodes `[renewal_id: u64 BE | credential: 0..=128 B]` into a zeroizing buffer (Spec §6.7).
#[allow(dead_code)]
pub fn encode_renew_payload(
    renewal_id: u64,
    credential: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    if renewal_id == 0 || credential.len() > CREDENTIAL_MAX {
        return Err(CoreError::InvalidParameter);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(8 + credential.len()));
    out.extend_from_slice(&renewal_id.to_be_bytes());
    out.extend_from_slice(credential);
    Ok(out)
}

/// Decodes `[renewal_id: u64 BE | credential: 0..=128 B]`, rejecting `renewal_id == 0` or `> 128 B`.
#[allow(dead_code)]
pub fn decode_renew_payload(bytes: &[u8]) -> Result<(u64, &[u8]), CoreError> {
    if bytes.len() < 8 || bytes.len() > 8 + CREDENTIAL_MAX {
        return Err(CoreError::Malformed);
    }
    let id = u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    if id == 0 {
        return Err(CoreError::Malformed);
    }
    Ok((id, &bytes[8..]))
}

/// Encodes `[renewal_id: u64 BE | remaining_ttl_ms: u64 BE]` (16 bytes).
#[allow(dead_code)]
#[must_use]
pub fn encode_renew_ok_payload(renewal_id: u64, ttl_ms: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&renewal_id.to_be_bytes());
    out[8..16].copy_from_slice(&ttl_ms.to_be_bytes());
    out
}

/// Decodes `[renewal_id: u64 BE | remaining_ttl_ms: u64 BE]` (Spec §6.7).
///
/// `renewal_id == 0` or `ttl_ms == 0` returns [`CoreError::Malformed`];
/// `ttl_ms > 24 h` returns [`CoreError::Denied`].
#[allow(dead_code)]
pub fn decode_renew_ok_payload(bytes: &[u8]) -> Result<(u64, Duration), CoreError> {
    if bytes.len() != 16 {
        return Err(CoreError::Malformed);
    }
    let id = u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    let ttl_ms = u64::from_be_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);
    if id == 0 || ttl_ms < MIN_WIRE_LEASE_TTL_MS {
        return Err(CoreError::Malformed);
    }
    if ttl_ms > MAX_WIRE_LEASE_TTL_MS {
        return Err(CoreError::Denied);
    }
    Ok((id, Duration::from_millis(ttl_ms)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn renewal_and_mtu_payload_codecs() {
        let mtu = encode_mtu_payload(42, 1200);
        assert_eq!(decode_mtu_payload(&mtu), Ok((42, 1200)));
        assert_eq!(decode_mtu_payload(&mtu[..5]), Err(CoreError::Malformed));

        let ack = encode_mtu_ack_payload(42);
        assert_eq!(decode_mtu_ack_payload(&ack), Ok(42));

        let req = encode_renew_payload(1, b"abc").unwrap();
        assert_eq!(decode_renew_payload(&req), Ok((1, &b"abc"[..])));
        assert_eq!(decode_renew_payload(&[0u8; 8]), Err(CoreError::Malformed));

        let ok = encode_renew_ok_payload(1, 5000);
        assert_eq!(
            decode_renew_ok_payload(&ok),
            Ok((1, Duration::from_millis(5000)))
        );
        // ttl_ms == 0 -> Malformed; ttl_ms > 24h -> Denied.
        assert_eq!(
            decode_renew_ok_payload(&encode_renew_ok_payload(1, 0)),
            Err(CoreError::Malformed)
        );
        assert_eq!(
            decode_renew_ok_payload(&encode_renew_ok_payload(1, MAX_WIRE_LEASE_TTL_MS + 1)),
            Err(CoreError::Denied)
        );
    }
}
