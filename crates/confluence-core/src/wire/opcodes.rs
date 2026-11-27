//! Normative v1 outer opcodes, E2E opcodes, and wire error code table `1..=13` (Spec §5.1, §5.4, §5.8).

use crate::error::CoreError;

/// Outer frame opcodes (byte 0 of every outer wire frame, Spec §5.1).
#[allow(dead_code)]
pub mod outer {
    pub const SETUP_FWD: u8 = 0x11;
    pub const SETUP_OK: u8 = 0x12;
    pub const SETUP_ERR: u8 = 0x13;
    pub const SETUP_COOKIE: u8 = 0x14;
    pub const SETUP_FRAG: u8 = 0x15;
    pub const SETUP_FRAG_ACK: u8 = 0x16;

    pub const DG_DATA: u8 = 0x20;
    pub const DG_CLOSE: u8 = 0x23;
    pub const DG_MTU: u8 = 0x24;
    pub const DG_RENEW: u8 = 0x25;
    pub const DG_RENEW_OK: u8 = 0x26;
    pub const DG_MTU_ACK: u8 = 0x27;

    pub const ST_DATA: u8 = 0x30;
    pub const ST_CLOSE: u8 = 0x33;
    pub const ST_RENEW: u8 = 0x34;
    pub const ST_RENEW_OK: u8 = 0x35;

    /// Returns `true` for reserved outer opcodes that MUST be rejected/ignored.
    #[inline]
    #[must_use]
    pub const fn is_reserved(op: u8) -> bool {
        matches!(op, 0x21 | 0x22 | 0x31 | 0x32)
    }

    /// Returns `true` for valid Datagram hop control opcodes (`0x23..=0x27`).
    #[inline]
    #[must_use]
    pub const fn is_dg_control(op: u8) -> bool {
        matches!(op, DG_CLOSE | DG_MTU | DG_RENEW | DG_RENEW_OK | DG_MTU_ACK)
    }

    /// Returns `true` for valid Stream hop control opcodes (`0x33..=0x35`).
    #[inline]
    #[must_use]
    pub const fn is_st_control(op: u8) -> bool {
        matches!(op, ST_CLOSE | ST_RENEW | ST_RENEW_OK)
    }
}

/// End-to-end Datagram record opcodes inside encrypted `DG_DATA` payloads (Spec §5.8.1).
#[allow(dead_code)]
pub mod e2e_dg {
    pub const DG_DATA: u8 = 0x01;
    pub const DG_CLOSE: u8 = 0x04;
    pub const DG_MTU: u8 = 0x05;
    pub const DG_MTU_ACK: u8 = 0x06;
    pub const DG_RENEW: u8 = crate::constants::E2E_DG_RENEW_OPCODE;
    pub const DG_RENEW_OK: u8 = 0x08;

    #[inline]
    #[must_use]
    pub const fn is_reserved(op: u8) -> bool {
        matches!(op, 0x02 | 0x03)
    }
}

/// End-to-end Stream record opcodes inside encrypted `ST_DATA` byte streams (Spec §5.8.2).
#[allow(dead_code)]
pub mod e2e_st {
    pub const OPEN_OK: u8 = 0x00;
    pub const TARGET_REFUSED: u8 = 0x01;
    pub const TARGET_UNREACHABLE: u8 = 0x02;
    pub const TARGET_BUSY: u8 = 0x03;
    pub const TARGET_DENIED: u8 = 0x04;
    pub const ST_DATA: u8 = 0x10;
    pub const ST_FIN: u8 = 0x11;
    pub const ST_RENEW: u8 = crate::constants::E2E_ST_RENEW_OPCODE;
    pub const ST_RENEW_OK: u8 = 0x15;

    #[inline]
    #[must_use]
    pub const fn is_reserved(op: u8) -> bool {
        matches!(op, 0x12 | 0x13)
    }
}

/// Stream 1.0 RTT confirmation status preamble emitted by Destination `B` (Spec §5.8.2 & §6.3).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamOpenStatus {
    OpenOk,
    TargetRefused,
    TargetUnreachable,
    TargetBusy,
    TargetDenied,
}

#[allow(dead_code)]
impl StreamOpenStatus {
    #[must_use]
    pub const fn opcode(self) -> u8 {
        match self {
            Self::OpenOk => e2e_st::OPEN_OK,
            Self::TargetRefused => e2e_st::TARGET_REFUSED,
            Self::TargetUnreachable => e2e_st::TARGET_UNREACHABLE,
            Self::TargetBusy => e2e_st::TARGET_BUSY,
            Self::TargetDenied => e2e_st::TARGET_DENIED,
        }
    }

    pub const fn from_opcode(op: u8) -> Result<Self, CoreError> {
        match op {
            e2e_st::OPEN_OK => Ok(Self::OpenOk),
            e2e_st::TARGET_REFUSED => Ok(Self::TargetRefused),
            e2e_st::TARGET_UNREACHABLE => Ok(Self::TargetUnreachable),
            e2e_st::TARGET_BUSY => Ok(Self::TargetBusy),
            e2e_st::TARGET_DENIED => Ok(Self::TargetDenied),
            _ => Err(CoreError::Malformed),
        }
    }

    /// Maps a local `StreamEndpointHandler::open` error to its wire `TARGET_*` opcode (Spec §6.3).
    #[must_use]
    pub const fn from_handler_error(err: &CoreError) -> Self {
        match err {
            CoreError::TargetRefused => Self::TargetRefused,
            CoreError::Busy => Self::TargetBusy,
            CoreError::Denied => Self::TargetDenied,
            _ => Self::TargetUnreachable,
        }
    }

    /// Converts a received status preamble into `Ok(())` or the corresponding `CoreError`.
    pub const fn into_result(self) -> Result<(), CoreError> {
        match self {
            Self::OpenOk => Ok(()),
            Self::TargetRefused => Err(CoreError::TargetRefused),
            Self::TargetUnreachable => Err(CoreError::TargetUnreachable),
            Self::TargetBusy => Err(CoreError::Busy),
            Self::TargetDenied => Err(CoreError::Denied),
        }
    }
}

/// Encodes a [`CoreError`] into the normative `[code: u16, arg: u16]` wire error table (Spec §5.4).
///
/// Always writes `arg = 0` for codes `2..=13`. Unlisted variants encode as catch-all `(10, 0)`.
#[must_use]
pub const fn encode_wire_error(err: &CoreError) -> (u16, u16) {
    match err {
        CoreError::MtuTooSmall(mtu) => (1, *mtu),
        CoreError::Denied => (2, 0),
        CoreError::Unpublished => (3, 0),
        CoreError::WrongPlane => (4, 0),
        CoreError::Timeout => (5, 0),
        CoreError::Busy => (6, 0),
        CoreError::Revoked => (7, 0),
        CoreError::Expired => (8, 0),
        CoreError::Closed => (9, 0),
        CoreError::TargetRefused => (11, 0),
        CoreError::TargetUnreachable => (12, 0),
        CoreError::UnexpectedEof => (13, 0),
        _ => (10, 0),
    }
}

/// Encodes a [`CoreError`] into a 4-byte big-endian `[code: u16 BE | arg: u16 BE]` payload.
#[must_use]
pub fn encode_wire_error_bytes(err: &CoreError) -> [u8; 4] {
    let (code, arg) = encode_wire_error(err);
    let mut out = [0u8; 4];
    out[0..2].copy_from_slice(&code.to_be_bytes());
    out[2..4].copy_from_slice(&arg.to_be_bytes());
    out
}

/// Decodes a wire `(code, arg)` pair per Spec §5.4.
///
/// Reads `arg` exclusively for code `1` (`MtuTooSmall(arg)`), ignores `arg` for codes `2..=13`,
/// decodes code `10` to permanent `CoreError::Carrier` (`PathFailure`, non-retryable), and
/// returns `Err(CoreError::Malformed)` for unknown codes outside `1..=13`.
pub fn decode_wire_error(code: u16, arg: u16) -> Result<CoreError, CoreError> {
    match code {
        1 => Ok(CoreError::MtuTooSmall(arg)),
        2 => Ok(CoreError::Denied),
        3 => Ok(CoreError::Unpublished),
        4 => Ok(CoreError::WrongPlane),
        5 => Ok(CoreError::Timeout),
        6 => Ok(CoreError::Busy),
        7 => Ok(CoreError::Revoked),
        8 => Ok(CoreError::Expired),
        9 => Ok(CoreError::Closed),
        10 => Ok(CoreError::Carrier("remote failure".into())),
        11 => Ok(CoreError::TargetRefused),
        12 => Ok(CoreError::TargetUnreachable),
        13 => Ok(CoreError::UnexpectedEof),
        _ => Err(CoreError::Malformed),
    }
}

/// Decodes a decrypted 4-byte wire error payload (`SETUP_ERR`, `ST_CLOSE`, `DG_CLOSE`, `e2e::DG_CLOSE`).
pub fn decode_wire_error_bytes(bytes: &[u8]) -> Result<CoreError, CoreError> {
    if bytes.len() != 4 {
        return Err(CoreError::Malformed);
    }
    let code = u16::from_be_bytes([bytes[0], bytes[1]]);
    let arg = u16::from_be_bytes([bytes[2], bytes[3]]);
    decode_wire_error(code, arg)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::error::FailureClass;

    #[test]
    fn wire_error_table_roundtrips_and_ignores_arg_on_2_through_13() {
        let mapped = [
            (CoreError::MtuTooSmall(1200), 1u16, 1200u16),
            (CoreError::Denied, 2, 0),
            (CoreError::Unpublished, 3, 0),
            (CoreError::WrongPlane, 4, 0),
            (CoreError::Timeout, 5, 0),
            (CoreError::Busy, 6, 0),
            (CoreError::Revoked, 7, 0),
            (CoreError::Expired, 8, 0),
            (CoreError::Closed, 9, 0),
            (CoreError::TargetRefused, 11, 0),
            (CoreError::TargetUnreachable, 12, 0),
            (CoreError::UnexpectedEof, 13, 0),
        ];
        for (err, code, arg) in mapped {
            assert_eq!(encode_wire_error(&err), (code, arg));
            let bytes = encode_wire_error_bytes(&err);
            assert_eq!(decode_wire_error_bytes(&bytes), Ok(err.clone()));
            if (2..=13).contains(&code) {
                // Non-zero arg on 2..=13 MUST be ignored on decode!
                assert_eq!(decode_wire_error(code, 0xBEEF), Ok(err));
            }
        }

        // Catch-all code 10: encodes unlisted errors as (10, 0), decodes to permanent Carrier.
        assert_eq!(encode_wire_error(&CoreError::ClockSkew), (10, 0));
        assert_eq!(encode_wire_error(&CoreError::Replay), (10, 0));
        let remote = decode_wire_error(10, 99).unwrap();
        assert!(matches!(remote, CoreError::Carrier(_)));
        assert_eq!(remote.failure_class(), FailureClass::PathFailure);
        assert!(!remote.is_retryable());

        // Unknown codes and wrong byte lengths fail with Malformed.
        assert_eq!(decode_wire_error(0, 0), Err(CoreError::Malformed));
        assert_eq!(decode_wire_error(14, 0), Err(CoreError::Malformed));
        assert_eq!(decode_wire_error_bytes(&[0, 2, 0]), Err(CoreError::Malformed));
        assert_eq!(
            decode_wire_error_bytes(&[0, 2, 0, 0, 0]),
            Err(CoreError::Malformed)
        );
    }
}
