use crate::{
    CoreErr,
    wire::{u16_at, u64_at},
};

pub const DG_DATA: u8 = 0x01;
pub const DG_RENEW: u8 = 0x02;
pub const DG_RENEW_OK: u8 = 0x03;
pub const DG_CLOSE: u8 = 0x04;
pub const MTU_PROBE: u8 = 0x05;
pub const MTU_PROBE_ACK: u8 = 0x06;
pub const DG_OVERHEAD: usize = 30;

pub const OPEN_OK: u8 = 0x00;
pub const TARGET_REFUSED: u8 = 0x01;
pub const TARGET_UNREACHABLE: u8 = 0x02;
pub const ST_DATA: u8 = 0x10;
pub const ST_FIN: u8 = 0x11;
pub const ST_RENEW: u8 = 0x12;
pub const ST_RENEW_OK: u8 = 0x13;
pub const ST_OVERHEAD: usize = 19;
pub const ST_MAX_BODY: usize = 16365;
pub const CREDENTIAL_MAX: usize = 96;

pub fn grant_bytes(ttl_ms: u64, rate_bps: u64) -> [u8; 16] {
    let mut buf = [0; 16];
    buf[..8].copy_from_slice(&ttl_ms.to_be_bytes());
    buf[8..].copy_from_slice(&rate_bps.to_be_bytes());
    buf
}
pub fn parse_grant(buf: &[u8]) -> Result<(u64, u64), CoreErr> {
    if buf.len() != 16 || u64_at(buf, 0) == 0 {
        return Err(CoreErr::Malformed);
    }
    Ok((u64_at(buf, 0), u64_at(buf, 8)))
}
pub fn credential(buf: &[u8]) -> Result<&[u8], CoreErr> {
    if buf.len() > CREDENTIAL_MAX {
        return Err(CoreErr::Malformed);
    }
    Ok(buf)
}
pub fn stream_body_len(prefix: [u8; 2]) -> Result<usize, CoreErr> {
    let len = u16_at(&prefix, 0) as usize;
    if len <= ST_MAX_BODY {
        Ok(len)
    } else {
        Err(CoreErr::Malformed)
    }
}
