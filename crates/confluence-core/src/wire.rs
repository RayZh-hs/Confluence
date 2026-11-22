//! Binary wire codecs for Confluence setup segments, control packets, and in-band renewal records.

use crate::error::{CoreError, Result};
use crate::security::replay::Tai64nTimestamp;
use crate::types::{
    ChannelAddr, CircuitId, EndpointName, HopLabel, OpaqueCredential, Plane, TargetTag,
    MAX_CHANNEL_ADDR_BYTES, MAX_CREDENTIAL_BYTES, MAX_ENDPOINT_NAME_BYTES,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum permitted byte length of a single setup or control segment on the wire.
pub const MAX_WIRE_SEGMENT_BYTES: usize = 2048;

/// AEAD inner message discriminator shared by both Datagram Plane and Stream Plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DataMsgType {
    Data = 0x01,
    InBandRenewReq = 0x02,
    InBandRenewResp = 0x03,
    Close = 0x04,
}

impl DataMsgType {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(Self::Data),
            0x02 => Ok(Self::InBandRenewReq),
            0x03 => Ok(Self::InBandRenewResp),
            0x04 => Ok(Self::Close),
            other => Err(CoreError::Framing(format!(
                "unknown data message type 0x{other:02x}"
            ))),
        }
    }
}

fn plane_to_u8(plane: Plane) -> u8 {
    match plane {
        Plane::Datagram => 0x01,
        Plane::Stream => 0x02,
    }
}

fn plane_from_u8(v: u8) -> Result<Plane> {
    match v {
        0x01 => Ok(Plane::Datagram),
        0x02 => Ok(Plane::Stream),
        other => Err(CoreError::Framing(format!(
            "invalid wire plane 0x{other:02x}"
        ))),
    }
}

/// Encrypted inner payload of the final `A -> B` E2E `Noise_IK` Message 1.
#[derive(Debug, Clone)]
pub struct E2eHandshakeReq {
    pub timestamp: Tai64nTimestamp,
    pub plane: Plane,
    pub endpoint: EndpointName,
    pub credential: Option<OpaqueCredential>,
}

impl E2eHandshakeReq {
    pub fn encode(&self) -> Vec<u8> {
        let ep_bytes = self.endpoint.as_str().as_bytes();
        let cred_len = self
            .credential
            .as_ref()
            .map(|c| 2 + c.as_bytes().len())
            .unwrap_or(0);
        let mut out = Vec::with_capacity(12 + 1 + 1 + ep_bytes.len() + 1 + cred_len);
        out.extend_from_slice(self.timestamp.as_bytes());
        out.push(plane_to_u8(self.plane));
        out.push(ep_bytes.len() as u8);
        out.extend_from_slice(ep_bytes);
        match self.credential {
            Some(ref cred) => {
                out.push(1);
                out.extend_from_slice(&(cred.as_bytes().len() as u16).to_be_bytes());
                out.extend_from_slice(cred.as_bytes());
            }
            None => out.push(0),
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 15 {
            return Err(CoreError::Framing("E2eHandshakeReq too short".into()));
        }
        let mut ts_arr = [0u8; 12];
        ts_arr.copy_from_slice(&buf[..12]);
        let plane = plane_from_u8(buf[12])?;
        let ep_len = buf[13] as usize;
        if ep_len == 0 || ep_len > MAX_ENDPOINT_NAME_BYTES || buf.len() < 14 + ep_len + 1 {
            return Err(CoreError::Framing(
                "invalid E2eHandshakeReq endpoint len".into(),
            ));
        }
        let ep_str = std::str::from_utf8(&buf[14..14 + ep_len])
            .map_err(|_| CoreError::Framing("non-utf8 endpoint name".into()))?;
        let endpoint = EndpointName::new(ep_str)?;
        let mut pos = 14 + ep_len;
        let has_cred = buf[pos];
        pos += 1;
        let credential = match has_cred {
            0 => {
                if pos != buf.len() {
                    return Err(CoreError::Framing(
                        "trailing bytes in E2eHandshakeReq".into(),
                    ));
                }
                None
            }
            1 => {
                if buf.len() < pos + 2 {
                    return Err(CoreError::Framing("truncated credential len".into()));
                }
                let clen = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
                pos += 2;
                if clen > MAX_CREDENTIAL_BYTES || buf.len() != pos + clen {
                    return Err(CoreError::Framing("invalid credential length".into()));
                }
                Some(OpaqueCredential::new(buf[pos..pos + clen].to_vec())?)
            }
            _ => return Err(CoreError::Framing("invalid credential flag".into())),
        };
        Ok(Self {
            timestamp: Tai64nTimestamp(ts_arr),
            plane,
            endpoint,
            credential,
        })
    }
}

/// Encrypted inner payload of `B -> A` E2E `Noise_IK` Message 2.
#[derive(Debug, Clone, Copy)]
pub struct E2eHandshakeResp {
    pub granted_ttl_millis: u64,
}

impl E2eHandshakeResp {
    pub fn encode(&self) -> [u8; 8] {
        self.granted_ttl_millis.to_be_bytes()
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() != 8 {
            return Err(CoreError::Framing("invalid E2eHandshakeResp length".into()));
        }
        Ok(Self {
            granted_ttl_millis: u64::from_be_bytes(buf.try_into().unwrap()),
        })
    }
}

/// Reusable inner payload codec for `channel <-> originator` hop setup (`NoiseAclChannel` & `confluence-relay`).
#[derive(Debug, Clone)]
pub struct HopHandshakeReq {
    pub timestamp: Tai64nTimestamp,
    pub plane: Plane,
    pub next_addr: ChannelAddr,
    pub credential: Option<OpaqueCredential>,
}

impl HopHandshakeReq {
    pub fn encode(&self) -> Vec<u8> {
        let addr_bytes = self.next_addr.as_bytes();
        let cred_len = self
            .credential
            .as_ref()
            .map(|c| 2 + c.as_bytes().len())
            .unwrap_or(0);
        let mut out = Vec::with_capacity(12 + 1 + 2 + addr_bytes.len() + 1 + cred_len);
        out.extend_from_slice(self.timestamp.as_bytes());
        out.push(plane_to_u8(self.plane));
        out.extend_from_slice(&(addr_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(addr_bytes);
        match self.credential {
            Some(ref cred) => {
                out.push(1);
                out.extend_from_slice(&(cred.as_bytes().len() as u16).to_be_bytes());
                out.extend_from_slice(cred.as_bytes());
            }
            None => out.push(0),
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 16 {
            return Err(CoreError::Framing("HopHandshakeReq too short".into()));
        }
        let mut ts_arr = [0u8; 12];
        ts_arr.copy_from_slice(&buf[..12]);
        let plane = plane_from_u8(buf[12])?;
        let addr_len = u16::from_be_bytes([buf[13], buf[14]]) as usize;
        if addr_len == 0 || addr_len > MAX_CHANNEL_ADDR_BYTES || buf.len() < 15 + addr_len + 1 {
            return Err(CoreError::Framing(
                "invalid HopHandshakeReq addr len".into(),
            ));
        }
        let addr_str = std::str::from_utf8(&buf[15..15 + addr_len])
            .map_err(|_| CoreError::Framing("non-utf8 HopHandshakeReq addr".into()))?;
        let next_addr = ChannelAddr::new(addr_str)?;
        let mut pos = 15 + addr_len;
        let has_cred = buf[pos];
        pos += 1;
        let credential = match has_cred {
            0 => {
                if pos != buf.len() {
                    return Err(CoreError::Framing(
                        "trailing bytes in HopHandshakeReq".into(),
                    ));
                }
                None
            }
            1 => {
                if buf.len() < pos + 2 {
                    return Err(CoreError::Framing("truncated hop credential".into()));
                }
                let clen = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
                pos += 2;
                if clen > MAX_CREDENTIAL_BYTES || buf.len() != pos + clen {
                    return Err(CoreError::Framing("invalid hop credential len".into()));
                }
                Some(OpaqueCredential::new(buf[pos..pos + clen].to_vec())?)
            }
            _ => return Err(CoreError::Framing("invalid hop credential flag".into())),
        };
        Ok(Self {
            timestamp: Tai64nTimestamp(ts_arr),
            plane,
            next_addr,
            credential,
        })
    }
}

/// In-band E2E Grant renewal request (`DataMsgType::InBandRenewReq`).
#[derive(Debug, Clone)]
pub struct InBandRenewReqPayload {
    pub req_id: u64,
    pub credential: Option<OpaqueCredential>,
}

impl InBandRenewReqPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.req_id.to_be_bytes());
        match self.credential {
            Some(ref c) => {
                out.push(1);
                out.extend_from_slice(&(c.as_bytes().len() as u16).to_be_bytes());
                out.extend_from_slice(c.as_bytes());
            }
            None => out.push(0),
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 9 {
            return Err(CoreError::Framing("InBandRenewReq too short".into()));
        }
        let req_id = u64::from_be_bytes(buf[..8].try_into().unwrap());
        let credential = match buf[8] {
            0 => {
                if buf.len() != 9 {
                    return Err(CoreError::Framing(
                        "trailing bytes in InBandRenewReq".into(),
                    ));
                }
                None
            }
            1 => {
                if buf.len() < 11 {
                    return Err(CoreError::Framing("truncated InBandRenewReq cred".into()));
                }
                let clen = u16::from_be_bytes([buf[9], buf[10]]) as usize;
                if clen > MAX_CREDENTIAL_BYTES || buf.len() != 11 + clen {
                    return Err(CoreError::Framing("invalid InBandRenewReq cred len".into()));
                }
                Some(OpaqueCredential::new(buf[11..].to_vec())?)
            }
            _ => return Err(CoreError::Framing("invalid InBandRenewReq flag".into())),
        };
        Ok(Self { req_id, credential })
    }
}

/// In-band E2E Grant renewal response (`DataMsgType::InBandRenewResp`).
#[derive(Debug, Clone)]
pub enum InBandRenewRespPayload {
    Accepted { req_id: u64, ttl_millis: u64 },
    Denied { req_id: u64, reason: String },
}

impl InBandRenewRespPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Accepted { req_id, ttl_millis } => {
                out.extend_from_slice(&req_id.to_be_bytes());
                out.push(1);
                out.extend_from_slice(&ttl_millis.to_be_bytes());
            }
            Self::Denied { req_id, reason } => {
                out.extend_from_slice(&req_id.to_be_bytes());
                out.push(0);
                let rb = reason.as_bytes();
                let rlen = rb.len().min(256);
                out.extend_from_slice(&(rlen as u16).to_be_bytes());
                out.extend_from_slice(&rb[..rlen]);
            }
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 9 {
            return Err(CoreError::Framing("InBandRenewResp too short".into()));
        }
        let req_id = u64::from_be_bytes(buf[..8].try_into().unwrap());
        match buf[8] {
            1 => {
                if buf.len() != 17 {
                    return Err(CoreError::Framing(
                        "invalid Accepted InBandRenewResp len".into(),
                    ));
                }
                let ttl_millis = u64::from_be_bytes(buf[9..17].try_into().unwrap());
                Ok(Self::Accepted { req_id, ttl_millis })
            }
            0 => {
                if buf.len() < 11 {
                    return Err(CoreError::Framing(
                        "truncated Denied InBandRenewResp".into(),
                    ));
                }
                let rlen = u16::from_be_bytes([buf[9], buf[10]]) as usize;
                if buf.len() != 11 + rlen {
                    return Err(CoreError::Framing(
                        "invalid Denied InBandRenewResp len".into(),
                    ));
                }
                let reason = String::from_utf8_lossy(&buf[11..]).into_owned();
                Ok(Self::Denied { req_id, reason })
            }
            _ => Err(CoreError::Framing("invalid InBandRenewResp status".into())),
        }
    }
}

/// Packs a sequence of `(TargetTag, payload)` segments into a contiguous chain tail.
pub fn pack_chain_segments(segments: &[(TargetTag, Vec<u8>)]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for (tag, payload) in segments {
        if payload.len() > MAX_WIRE_SEGMENT_BYTES {
            return Err(CoreError::Framing(
                "setup segment exceeds max wire size".into(),
            ));
        }
        out.extend_from_slice(tag.as_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
    }
    Ok(out)
}

/// Pops the leading `(TargetTag, seg_payload)` from a packed chain tail, returning `(tag, seg, remaining_tail)`.
pub fn pop_chain_segment(tail: &[u8]) -> Result<(TargetTag, Vec<u8>, Vec<u8>)> {
    if tail.len() < 10 {
        return Err(CoreError::Framing("chain tail too short".into()));
    }
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&tail[..8]);
    let seg_len = u16::from_be_bytes([tail[8], tail[9]]) as usize;
    if seg_len > MAX_WIRE_SEGMENT_BYTES || tail.len() < 10 + seg_len {
        return Err(CoreError::Framing("invalid chain segment length".into()));
    }
    let seg = tail[10..10 + seg_len].to_vec();
    let rem = tail[10 + seg_len..].to_vec();
    Ok((TargetTag(tag), seg, rem))
}

/// Control-plane packets carried with `HopLabel(0)` on the Datagram Plane.
#[derive(Debug, Clone)]
pub enum DgramCtrlPacket {
    ChainSetup {
        circuit_id: CircuitId,
        sender_return_label: u32,
        target_tag: TargetTag,
        seg_payload: Vec<u8>,
        remaining_tail: Vec<u8>,
    },
    ChainSetupResp {
        circuit_id: CircuitId,
        responder_label: u32,
        msg2: Vec<u8>,
    },
    ChainSetupChallenge {
        circuit_id: CircuitId,
        target_tag: TargetTag,
        challenge: Vec<u8>,
    },
    ChainSetupReject {
        circuit_id: CircuitId,
        target_tag: TargetTag,
        reason: String,
    },
    ChannelControl {
        req_id: u64,
        target_tag: TargetTag,
        payload: Vec<u8>,
    },
    ChannelControlResp {
        req_id: u64,
        target_tag: TargetTag,
        payload: Vec<u8>,
    },
    CircuitRenew {
        circuit_id: CircuitId,
        target_tag: TargetTag,
        payload: Vec<u8>,
    },
    CircuitRenewResp {
        circuit_id: CircuitId,
        target_tag: TargetTag,
        payload: Vec<u8>,
    },
}

impl DgramCtrlPacket {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&HopLabel::CONTROL.to_be_bytes());
        match self {
            Self::ChainSetup {
                circuit_id,
                sender_return_label,
                target_tag,
                seg_payload,
                remaining_tail,
            } => {
                if seg_payload.len() > MAX_WIRE_SEGMENT_BYTES {
                    return Err(CoreError::Framing("ChainSetup segment too large".into()));
                }
                out.push(0x10);
                out.extend_from_slice(circuit_id.as_bytes());
                out.extend_from_slice(&sender_return_label.to_be_bytes());
                out.extend_from_slice(target_tag.as_bytes());
                out.extend_from_slice(&(seg_payload.len() as u16).to_be_bytes());
                out.extend_from_slice(seg_payload);
                out.extend_from_slice(remaining_tail);
            }
            Self::ChainSetupResp {
                circuit_id,
                responder_label,
                msg2,
            } => {
                out.push(0x11);
                out.extend_from_slice(circuit_id.as_bytes());
                out.extend_from_slice(&responder_label.to_be_bytes());
                out.extend_from_slice(&(msg2.len() as u16).to_be_bytes());
                out.extend_from_slice(msg2);
            }
            Self::ChainSetupChallenge {
                circuit_id,
                target_tag,
                challenge,
            } => {
                out.push(0x12);
                out.extend_from_slice(circuit_id.as_bytes());
                out.extend_from_slice(target_tag.as_bytes());
                out.extend_from_slice(&(challenge.len() as u16).to_be_bytes());
                out.extend_from_slice(challenge);
            }
            Self::ChainSetupReject {
                circuit_id,
                target_tag,
                reason,
            } => {
                let rb = reason.as_bytes();
                let rlen = rb.len().min(512);
                out.push(0x13);
                out.extend_from_slice(circuit_id.as_bytes());
                out.extend_from_slice(target_tag.as_bytes());
                out.extend_from_slice(&(rlen as u16).to_be_bytes());
                out.extend_from_slice(&rb[..rlen]);
            }
            Self::ChannelControl {
                req_id,
                target_tag,
                payload,
            } => {
                out.push(0x20);
                out.extend_from_slice(&req_id.to_be_bytes());
                out.extend_from_slice(target_tag.as_bytes());
                out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                out.extend_from_slice(payload);
            }
            Self::ChannelControlResp {
                req_id,
                target_tag,
                payload,
            } => {
                out.push(0x21);
                out.extend_from_slice(&req_id.to_be_bytes());
                out.extend_from_slice(target_tag.as_bytes());
                out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                out.extend_from_slice(payload);
            }
            Self::CircuitRenew {
                circuit_id,
                target_tag,
                payload,
            } => {
                out.push(0x30);
                out.extend_from_slice(circuit_id.as_bytes());
                out.extend_from_slice(target_tag.as_bytes());
                out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                out.extend_from_slice(payload);
            }
            Self::CircuitRenewResp {
                circuit_id,
                target_tag,
                payload,
            } => {
                out.push(0x31);
                out.extend_from_slice(circuit_id.as_bytes());
                out.extend_from_slice(target_tag.as_bytes());
                out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                out.extend_from_slice(payload);
            }
        }
        Ok(out)
    }

    /// Decodes a `HopLabel(0)` packet (`raw` includes the 4-byte leading `0u32` label).
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() < 5 {
            return Err(CoreError::Framing("control packet too short".into()));
        }
        let body = &raw[5..];
        match raw[4] {
            0x10 => {
                if body.len() < 16 + 4 + 8 + 2 {
                    return Err(CoreError::Framing("ChainSetup too short".into()));
                }
                let mut cid = [0u8; 16];
                cid.copy_from_slice(&body[..16]);
                let sender_return_label = u32::from_be_bytes(body[16..20].try_into().unwrap());
                let mut tag = [0u8; 8];
                tag.copy_from_slice(&body[20..28]);
                let seg_len = u16::from_be_bytes([body[28], body[29]]) as usize;
                if seg_len > MAX_WIRE_SEGMENT_BYTES || body.len() < 30 + seg_len {
                    return Err(CoreError::Framing("ChainSetup invalid seg_len".into()));
                }
                Ok(Self::ChainSetup {
                    circuit_id: CircuitId(cid),
                    sender_return_label,
                    target_tag: TargetTag(tag),
                    seg_payload: body[30..30 + seg_len].to_vec(),
                    remaining_tail: body[30 + seg_len..].to_vec(),
                })
            }
            0x11 => {
                if body.len() < 16 + 4 + 2 {
                    return Err(CoreError::Framing("ChainSetupResp too short".into()));
                }
                let mut cid = [0u8; 16];
                cid.copy_from_slice(&body[..16]);
                let responder_label = u32::from_be_bytes(body[16..20].try_into().unwrap());
                let mlen = u16::from_be_bytes([body[20], body[21]]) as usize;
                if body.len() != 22 + mlen {
                    return Err(CoreError::Framing("ChainSetupResp length mismatch".into()));
                }
                Ok(Self::ChainSetupResp {
                    circuit_id: CircuitId(cid),
                    responder_label,
                    msg2: body[22..].to_vec(),
                })
            }
            0x12 => {
                if body.len() < 16 + 8 + 2 {
                    return Err(CoreError::Framing("ChainSetupChallenge too short".into()));
                }
                let mut cid = [0u8; 16];
                cid.copy_from_slice(&body[..16]);
                let mut tag = [0u8; 8];
                tag.copy_from_slice(&body[16..24]);
                let clen = u16::from_be_bytes([body[24], body[25]]) as usize;
                if body.len() != 26 + clen {
                    return Err(CoreError::Framing(
                        "ChainSetupChallenge length mismatch".into(),
                    ));
                }
                Ok(Self::ChainSetupChallenge {
                    circuit_id: CircuitId(cid),
                    target_tag: TargetTag(tag),
                    challenge: body[26..].to_vec(),
                })
            }
            0x13 => {
                if body.len() < 16 + 8 + 2 {
                    return Err(CoreError::Framing("ChainSetupReject too short".into()));
                }
                let mut cid = [0u8; 16];
                cid.copy_from_slice(&body[..16]);
                let mut tag = [0u8; 8];
                tag.copy_from_slice(&body[16..24]);
                let rlen = u16::from_be_bytes([body[24], body[25]]) as usize;
                if body.len() != 26 + rlen {
                    return Err(CoreError::Framing(
                        "ChainSetupReject length mismatch".into(),
                    ));
                }
                Ok(Self::ChainSetupReject {
                    circuit_id: CircuitId(cid),
                    target_tag: TargetTag(tag),
                    reason: String::from_utf8_lossy(&body[26..]).into_owned(),
                })
            }
            0x20 | 0x21 => {
                if body.len() < 8 + 8 + 2 {
                    return Err(CoreError::Framing("ChannelControl too short".into()));
                }
                let req_id = u64::from_be_bytes(body[..8].try_into().unwrap());
                let mut tag = [0u8; 8];
                tag.copy_from_slice(&body[8..16]);
                let plen = u16::from_be_bytes([body[16], body[17]]) as usize;
                if plen > MAX_WIRE_SEGMENT_BYTES || body.len() != 18 + plen {
                    return Err(CoreError::Framing("ChannelControl length mismatch".into()));
                }
                if raw[4] == 0x20 {
                    Ok(Self::ChannelControl {
                        req_id,
                        target_tag: TargetTag(tag),
                        payload: body[18..].to_vec(),
                    })
                } else {
                    Ok(Self::ChannelControlResp {
                        req_id,
                        target_tag: TargetTag(tag),
                        payload: body[18..].to_vec(),
                    })
                }
            }
            0x30 | 0x31 => {
                if body.len() < 16 + 8 + 2 {
                    return Err(CoreError::Framing("CircuitRenew too short".into()));
                }
                let mut cid = [0u8; 16];
                cid.copy_from_slice(&body[..16]);
                let mut tag = [0u8; 8];
                tag.copy_from_slice(&body[16..24]);
                let plen = u16::from_be_bytes([body[24], body[25]]) as usize;
                if plen > MAX_WIRE_SEGMENT_BYTES || body.len() != 26 + plen {
                    return Err(CoreError::Framing("CircuitRenew length mismatch".into()));
                }
                if raw[4] == 0x30 {
                    Ok(Self::CircuitRenew {
                        circuit_id: CircuitId(cid),
                        target_tag: TargetTag(tag),
                        payload: body[26..].to_vec(),
                    })
                } else {
                    Ok(Self::CircuitRenewResp {
                        circuit_id: CircuitId(cid),
                        target_tag: TargetTag(tag),
                        payload: body[26..].to_vec(),
                    })
                }
            }
            other => Err(CoreError::Framing(format!(
                "unknown datagram control type 0x{other:02x}"
            ))),
        }
    }
}

/// Leading discriminator on Stream Plane pipelined setup / control segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamSegmentMode {
    FinalE2e = 0x01,
    ForwardHop = 0x02,
    ChannelControl = 0x03,
}

impl StreamSegmentMode {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(Self::FinalE2e),
            0x02 => Ok(Self::ForwardHop),
            0x03 => Ok(Self::ChannelControl),
            other => Err(CoreError::Framing(format!(
                "unknown stream segment mode 0x{other:02x}"
            ))),
        }
    }
}

/// Appends one `[mode: 1B][target_tag: 8B][len: 2B BE][payload]` segment to a buffer.
pub fn append_stream_segment(
    out: &mut Vec<u8>,
    mode: StreamSegmentMode,
    target_tag: TargetTag,
    payload: &[u8],
) -> Result<()> {
    if payload.len() > MAX_WIRE_SEGMENT_BYTES {
        return Err(CoreError::Framing("stream setup segment too large".into()));
    }
    out.push(mode as u8);
    out.extend_from_slice(target_tag.as_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// Reads exactly one leading `[mode: 1B][target_tag: 8B][len: 2B BE][payload]` segment from `stream`,
/// leaving all subsequent pipelined bytes untouched on `stream` for immediate raw splicing!
pub async fn read_stream_segment<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<(StreamSegmentMode, TargetTag, Vec<u8>)> {
    let mut hdr = [0u8; 11];
    stream.read_exact(&mut hdr).await?;
    let mode = StreamSegmentMode::from_u8(hdr[0])?;
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&hdr[1..9]);
    let len = u16::from_be_bytes([hdr[9], hdr[10]]) as usize;
    if len > MAX_WIRE_SEGMENT_BYTES {
        return Err(CoreError::Framing(
            "stream setup segment exceeds limit".into(),
        ));
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    Ok((mode, TargetTag(tag), payload))
}

/// Response written upstream at the end of a single-pass Stream setup chain.
#[derive(Debug, Clone)]
pub enum StreamSetupReply {
    Accept {
        target_tag: TargetTag,
        msg2: Vec<u8>,
    },
    Challenge {
        target_tag: TargetTag,
        challenge: Vec<u8>,
    },
    Reject {
        target_tag: TargetTag,
        reason: String,
    },
}

pub async fn write_stream_reply<W: AsyncWrite + Unpin>(
    stream: &mut W,
    reply: &StreamSetupReply,
) -> Result<()> {
    let mut out = Vec::new();
    match reply {
        StreamSetupReply::Accept { target_tag, msg2 } => {
            out.push(0x01);
            out.extend_from_slice(target_tag.as_bytes());
            out.extend_from_slice(&(msg2.len() as u16).to_be_bytes());
            out.extend_from_slice(msg2);
        }
        StreamSetupReply::Challenge {
            target_tag,
            challenge,
        } => {
            out.push(0x02);
            out.extend_from_slice(target_tag.as_bytes());
            out.extend_from_slice(&(challenge.len() as u16).to_be_bytes());
            out.extend_from_slice(challenge);
        }
        StreamSetupReply::Reject { target_tag, reason } => {
            let rb = reason.as_bytes();
            let rlen = rb.len().min(512);
            out.push(0x03);
            out.extend_from_slice(target_tag.as_bytes());
            out.extend_from_slice(&(rlen as u16).to_be_bytes());
            out.extend_from_slice(&rb[..rlen]);
        }
    }
    stream.write_all(&out).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn read_stream_reply<R: AsyncRead + Unpin>(stream: &mut R) -> Result<StreamSetupReply> {
    let mut hdr = [0u8; 11];
    stream.read_exact(&mut hdr).await?;
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&hdr[1..9]);
    let len = u16::from_be_bytes([hdr[9], hdr[10]]) as usize;
    if len > MAX_WIRE_SEGMENT_BYTES {
        return Err(CoreError::Framing(
            "stream setup reply exceeds limit".into(),
        ));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    match hdr[0] {
        0x01 => Ok(StreamSetupReply::Accept {
            target_tag: TargetTag(tag),
            msg2: body,
        }),
        0x02 => Ok(StreamSetupReply::Challenge {
            target_tag: TargetTag(tag),
            challenge: body,
        }),
        0x03 => Ok(StreamSetupReply::Reject {
            target_tag: TargetTag(tag),
            reason: String::from_utf8_lossy(&body).into_owned(),
        }),
        other => Err(CoreError::Framing(format!(
            "unknown stream setup reply status 0x{other:02x}"
        ))),
    }
}
