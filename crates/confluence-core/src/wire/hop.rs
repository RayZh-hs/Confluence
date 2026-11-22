use crate::{
    CoreErr, STREAM_CHUNK,
    cid::Cid,
    wire::{u16_at, u32_at},
};

pub const DG_DATA: u8 = 0x20;
pub const DG_RENEW: u8 = 0x21;
pub const DG_RENEW_OK: u8 = 0x22;
pub const DG_CLOSE: u8 = 0x23;
pub const DG_MTU_HINT: u8 = 0x24;
pub const ST_DATA: u8 = 0x30;
pub const ST_RENEW: u8 = 0x31;
pub const ST_RENEW_OK: u8 = 0x32;
pub const ST_CLOSE: u8 = 0x33;
pub const MAX_CONTROL: usize = 128;

pub fn datagram_data(cid: Cid) -> [u8; 5] {
    let mut buf = [DG_DATA; 5];
    buf[1..].copy_from_slice(&cid.raw().to_be_bytes());
    buf
}
pub fn datagram_control(kind: u8, ttl: u8, cid: Cid) -> [u8; 6] {
    let mut buf = [kind, ttl, 0, 0, 0, 0];
    buf[2..].copy_from_slice(&cid.raw().to_be_bytes());
    buf
}
pub fn route_cid(buf: &[u8]) -> Option<Cid> {
    let offset = match *buf.first()? {
        DG_DATA => 1,
        DG_RENEW..=DG_MTU_HINT => 2,
        super::setup::OK | super::setup::ERR => 4,
        super::setup::FWD => return Some(Cid::UNBOUND),
        _ => return None,
    };
    (buf.len() >= offset + 4).then(|| Cid::from_raw(u32_at(buf, offset)))
}
pub fn stream_header(kind: u8, ttl: u8, len: usize) -> Result<[u8; 4], CoreErr> {
    if len > u16::MAX as usize {
        return Err(CoreErr::Malformed);
    }
    let length = (len as u16).to_be_bytes();
    let header = [kind, ttl, length[0], length[1]];
    parse_stream(header)?;
    Ok(header)
}
pub fn parse_stream(header: [u8; 4]) -> Result<(u8, u8, usize), CoreErr> {
    let kind = header[0];
    let ttl = header[1];
    let len = u16_at(&header, 2) as usize;
    match kind {
        ST_DATA if ttl == 0 && (1..=STREAM_CHUNK).contains(&len) => Ok((kind, ttl, len)),
        ST_RENEW..=ST_CLOSE if (24..=MAX_CONTROL).contains(&len) => Ok((kind, ttl, len)),
        _ => Err(CoreErr::Malformed),
    }
}
