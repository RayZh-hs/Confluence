//! Stream hop framing (`4 B` header) and E2E record framing validators (Spec §5.7.2 & §5.8.2).

use crate::constants::{MAX_CONTROL, MIN_CONTROL, ST_HOP_HEADER, ST_MAX_BODY, STREAM_CHUNK};
use crate::error::CoreError;
use crate::wire::opcodes::{e2e_st, outer};

/// 4-byte Stream outer hop frame header (`[kind:1 | ttl_or_dist:1 | len:2 BE]`, Spec §5.7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StHopHeader {
    pub kind: u8,
    pub ttl_or_dist: u8,
    pub len: u16,
}

#[allow(dead_code)]
impl StHopHeader {
    #[must_use]
    pub fn encode(self) -> [u8; ST_HOP_HEADER] {
        let mut out = [0u8; ST_HOP_HEADER];
        out[0] = self.kind;
        out[1] = self.ttl_or_dist;
        out[2..4].copy_from_slice(&self.len.to_be_bytes());
        out
    }

    /// Parses and validates a 4-byte Stream outer hop header.
    ///
    /// Rejects reserved opcodes (`0x31`, `0x32`), unknown opcodes, non-zero `ttl` on `ST_DATA`,
    /// `ST_DATA` lengths outside `1..=16384`, and hop control lengths outside `24..=160`.
    pub fn parse(raw: &[u8; ST_HOP_HEADER]) -> Result<Self, CoreError> {
        let kind = raw[0];
        let ttl_or_dist = raw[1];
        let len = u16::from_be_bytes([raw[2], raw[3]]);
        let len_usize = usize::from(len);

        if outer::is_reserved(kind) {
            return Err(CoreError::Malformed);
        }

        match kind {
            outer::ST_DATA => {
                if ttl_or_dist != 0 || !(1..=STREAM_CHUNK).contains(&len_usize) {
                    return Err(CoreError::Malformed);
                }
            }
            outer::ST_CLOSE | outer::ST_RENEW | outer::ST_RENEW_OK => {
                if !(MIN_CONTROL..=MAX_CONTROL).contains(&len_usize) {
                    return Err(CoreError::Malformed);
                }
            }
            _ => return Err(CoreError::Malformed),
        }

        Ok(Self {
            kind,
            ttl_or_dist,
            len,
        })
    }
}

/// Validates a Stream E2E record body length (`<= ST_MAX_BODY = 16365`).
#[allow(dead_code)]
pub const fn validate_st_e2e_body_len(body_len: u16) -> Result<usize, CoreError> {
    let len = body_len as usize;
    if len <= ST_MAX_BODY {
        Ok(len)
    } else {
        Err(CoreError::Malformed)
    }
}

/// Validates that a Stream E2E record opcode is a known non-reserved v1 opcode (Spec §5.8.2).
#[allow(dead_code)]
pub const fn validate_st_e2e_opcode(op: u8) -> Result<u8, CoreError> {
    if e2e_st::is_reserved(op) {
        return Err(CoreError::Malformed);
    }
    match op {
        e2e_st::OPEN_OK
        | e2e_st::TARGET_REFUSED
        | e2e_st::TARGET_UNREACHABLE
        | e2e_st::TARGET_BUSY
        | e2e_st::TARGET_DENIED
        | e2e_st::ST_DATA
        | e2e_st::ST_FIN
        | e2e_st::ST_RENEW
        | e2e_st::ST_RENEW_OK => Ok(op),
        _ => Err(CoreError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn st_hop_header_enforces_reserved_and_length_bounds() {
        let data = StHopHeader {
            kind: outer::ST_DATA,
            ttl_or_dist: 0,
            len: 16_384,
        };
        assert_eq!(StHopHeader::parse(&data.encode()), Ok(data));

        // ST_DATA with ttl != 0 or len == 0 or len > 16384 -> Malformed.
        assert_eq!(
            StHopHeader::parse(&[outer::ST_DATA, 1, 0, 10]),
            Err(CoreError::Malformed)
        );
        assert_eq!(
            StHopHeader::parse(&[outer::ST_DATA, 0, 0, 0]),
            Err(CoreError::Malformed)
        );
        assert_eq!(
            StHopHeader::parse(&[outer::ST_DATA, 0, 0x40, 0x01]),
            Err(CoreError::Malformed)
        );

        // Reserved opcodes 0x31, 0x32 -> Malformed.
        assert_eq!(StHopHeader::parse(&[0x31, 0, 0, 24]), Err(CoreError::Malformed));
        assert_eq!(StHopHeader::parse(&[0x32, 0, 0, 24]), Err(CoreError::Malformed));

        // Control bounds 24..=160.
        assert_eq!(
            StHopHeader::parse(&[outer::ST_CLOSE, 2, 0, 23]),
            Err(CoreError::Malformed)
        );
        assert!(StHopHeader::parse(&[outer::ST_CLOSE, 2, 0, 24]).is_ok());
        assert!(StHopHeader::parse(&[outer::ST_RENEW, 0, 0, 160]).is_ok());
        assert_eq!(
            StHopHeader::parse(&[outer::ST_RENEW_OK, 0, 0, 161]),
            Err(CoreError::Malformed)
        );

        // E2E reserved opcodes 0x12, 0x13 rejected.
        assert_eq!(validate_st_e2e_opcode(0x12), Err(CoreError::Malformed));
        assert_eq!(validate_st_e2e_opcode(0x13), Err(CoreError::Malformed));
        assert_eq!(validate_st_e2e_opcode(e2e_st::ST_FIN), Ok(e2e_st::ST_FIN));
    }
}
