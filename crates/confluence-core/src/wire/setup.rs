use crate::{
    CoreErr, Plane,
    cid::Cid,
    wire::{u16_at, u32_at, u64_at},
};

pub const FWD: u8 = 0x11;
pub const OK: u8 = 0x12;
pub const ERR: u8 = 0x13;
pub const FWD_HEADER: usize = 8;
pub const OK_SIZE: usize = 78;
pub const ERR_SIZE: usize = 36;
pub const SEGMENT_OVERHEAD: usize = 120;
pub const MAX_SETUP: usize = FWD_HEADER + 16 + 2 * u16::MAX as usize;

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

pub struct Segment<'a> {
    pub plane: Plane,
    pub min_mtu: u16,
    pub channel: Option<u64>,
    pub prefix: &'a [u8],
    pub encrypted: &'a [u8],
    pub tail: &'a [u8],
}

pub fn prefix_size(mode: u8) -> Result<usize, CoreErr> {
    match mode {
        1 => Ok(16),
        2 => Ok(6),
        _ => Err(CoreErr::Malformed),
    }
}
pub fn encoded_size(prefix: &[u8]) -> Result<usize, CoreErr> {
    let size = prefix_size(*prefix.first().ok_or(CoreErr::Malformed)?)?;
    if prefix.len() != size {
        return Err(CoreErr::Malformed);
    }
    let segment = u16_at(prefix, if size == 16 { 12 } else { 4 }) as usize;
    let tail = if size == 16 {
        u16_at(prefix, 14) as usize
    } else {
        0
    };
    if segment < SEGMENT_OVERHEAD || (size == 16 && tail < 6 + SEGMENT_OVERHEAD) {
        return Err(CoreErr::Malformed);
    }
    Ok(size + segment + tail)
}
pub fn prefix(
    plane: Plane,
    min_mtu: u16,
    channel: Option<u64>,
    len: usize,
    tail: usize,
) -> Result<Vec<u8>, CoreErr> {
    let len = u16::try_from(len).map_err(|_| CoreErr::Malformed)?;
    let tail = u16::try_from(tail).map_err(|_| CoreErr::Malformed)?;
    let mut buf = vec![if channel.is_some() { 1 } else { 2 }, plane as u8];
    buf.extend_from_slice(&min_mtu.to_be_bytes());
    if let Some(tag) = channel {
        buf.extend_from_slice(&tag.to_be_bytes());
    }
    buf.extend_from_slice(&len.to_be_bytes());
    if channel.is_some() {
        buf.extend_from_slice(&tail.to_be_bytes());
    }
    Ok(buf)
}
impl<'a> Segment<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Self, CoreErr> {
        let size = prefix_size(*buf.first().ok_or(CoreErr::Malformed)?)?;
        let prefix = buf.get(..size).ok_or(CoreErr::Malformed)?;
        if encoded_size(prefix)? != buf.len() {
            return Err(CoreErr::Malformed);
        }
        let end = size + u16_at(prefix, if size == 16 { 12 } else { 4 }) as usize;
        Ok(Self {
            plane: prefix[1].try_into()?,
            min_mtu: u16_at(prefix, 2),
            channel: (size == 16).then(|| u64_at(prefix, 4)),
            prefix,
            encrypted: &buf[size..end],
            tail: &buf[end..],
        })
    }
    pub fn aad(&self) -> [u8; 32] {
        tail_aad(self.prefix, self.tail)
    }
}

pub fn tail_aad(prefix: &[u8], tail: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(prefix);
    h.update(tail);
    *h.finalize().as_bytes()
}
#[derive(Clone, Copy, Debug)]
pub struct OkHeader {
    pub reverse_mtu: u16,
    pub target: Cid,
    pub responder: Cid,
}
impl OkHeader {
    pub fn parse(buf: &[u8]) -> Result<Self, CoreErr> {
        if buf.len() != OK_SIZE || buf[0] != OK || buf[1] != 0 {
            return Err(CoreErr::Malformed);
        }
        Ok(Self {
            reverse_mtu: u16_at(buf, 2),
            target: Cid::from_raw(u32_at(buf, 4)),
            responder: Cid::from_raw(u32_at(buf, 8)),
        })
    }
    pub fn encode(self) -> [u8; 12] {
        let mut buf = [0; 12];
        buf[0] = OK;
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
