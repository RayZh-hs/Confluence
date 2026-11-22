use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag, aead::AeadInPlace};

use super::replay::ReplayWindow;
use crate::{
    CoreErr, PacketBuf,
    wire::{e2e, u64_at},
};

fn nonce(sequence: u64) -> Nonce {
    let mut buf = [0; 12];
    buf[4..].copy_from_slice(&sequence.to_be_bytes());
    buf.into()
}
fn seal_with(cipher: &ChaCha20Poly1305, seq: u64, aad: &[u8], body: &mut [u8]) -> [u8; 16] {
    cipher
        .encrypt_in_place_detached(&nonce(seq), aad, body)
        .expect("bounded record length")
        .into()
}
fn open_with(
    cipher: &ChaCha20Poly1305,
    seq: u64,
    aad: &[u8],
    body: &mut [u8],
    tag: &[u8],
) -> Result<(), CoreErr> {
    if tag.len() != 16 {
        return Err(CoreErr::Malformed);
    }
    cipher
        .decrypt_in_place_detached(&nonce(seq), aad, body, Tag::from_slice(tag))
        .map_err(|_| CoreErr::Authentication)
}
pub(crate) fn seal(key: &[u8; 32], seq: u64, aad: &[u8], body: &mut [u8]) -> [u8; 16] {
    seal_with(&ChaCha20Poly1305::new(key.into()), seq, aad, body)
}
pub(crate) fn open(
    key: &[u8; 32],
    seq: u64,
    aad: &[u8],
    body: &mut [u8],
    tag: &[u8],
) -> Result<(), CoreErr> {
    open_with(&ChaCha20Poly1305::new(key.into()), seq, aad, body, tag)
}
fn take_sequence(seq: &mut u64) -> Result<u64, CoreErr> {
    let current = *seq;
    *seq = seq.checked_add(1).ok_or(CoreErr::Closed)?;
    Ok(current)
}
pub struct ControlCipher {
    tx: ChaCha20Poly1305,
    rx: ChaCha20Poly1305,
    seq: u64,
    replay: ReplayWindow,
}
impl ControlCipher {
    pub(crate) fn new(tx: [u8; 32], rx: [u8; 32]) -> Self {
        Self {
            tx: ChaCha20Poly1305::new((&tx).into()),
            rx: ChaCha20Poly1305::new((&rx).into()),
            seq: 0,
            replay: ReplayWindow::default(),
        }
    }
    pub fn seal(&mut self, kind: u8, plaintext: &[u8]) -> Result<Vec<u8>, CoreErr> {
        let seq = take_sequence(&mut self.seq)?;
        let mut wire = seq.to_be_bytes().to_vec();
        wire.extend_from_slice(plaintext);
        let tag = seal_with(&self.tx, seq, &[kind], &mut wire[8..]);
        wire.extend_from_slice(&tag);
        Ok(wire)
    }
    pub fn open(&mut self, kind: u8, wire: &[u8]) -> Result<Vec<u8>, CoreErr> {
        if !(24..=crate::wire::hop::MAX_CONTROL).contains(&wire.len()) {
            return Err(CoreErr::Malformed);
        }
        let seq = u64_at(wire, 0);
        if !self.replay.allows(seq) {
            return Err(CoreErr::Authentication);
        }
        let end = wire.len() - 16;
        let mut body = wire[8..end].to_vec();
        open_with(&self.rx, seq, &[kind], &mut body, &wire[end..])?;
        self.replay.commit(seq);
        Ok(body)
    }
}

pub struct DatagramTx {
    cipher: ChaCha20Poly1305,
    seq: u64,
}
pub struct DatagramRx {
    cipher: ChaCha20Poly1305,
    replay: ReplayWindow,
}
impl DatagramTx {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new((&key).into()),
            seq: 0,
        }
    }
    pub fn seal(&mut self, kind: u8, mut buf: PacketBuf) -> Result<PacketBuf, CoreErr> {
        let seq = take_sequence(&mut self.seq)?;
        if !buf.prepend_header(&[kind]) {
            return Err(CoreErr::Malformed);
        }
        let bytes = seq.to_be_bytes();
        let tag = seal_with(&self.cipher, seq, &bytes, buf.as_mut_slice());
        if !buf.append_tag(&tag) || !buf.prepend_header(&bytes) {
            return Err(CoreErr::Malformed);
        }
        Ok(buf)
    }
}
impl DatagramRx {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new((&key).into()),
            replay: ReplayWindow::default(),
        }
    }
    pub fn open(&mut self, buf: PacketBuf) -> Result<(u8, PacketBuf), CoreErr> {
        self.open_sequenced(buf).map(|(_, kind, body)| (kind, body))
    }
    pub(crate) fn open_sequenced(
        &mut self,
        mut buf: PacketBuf,
    ) -> Result<(u64, u8, PacketBuf), CoreErr> {
        if buf.len() < e2e::DG_OVERHEAD - 5 {
            return Err(CoreErr::Malformed);
        }
        let header: [u8; 8] = buf.as_slice()[..8].try_into().unwrap();
        let seq = u64::from_be_bytes(header);
        if !self.replay.allows(seq) {
            return Err(CoreErr::Authentication);
        }
        let slice = buf.as_mut_slice();
        let end = slice.len() - 16;
        let (ciphertext, tag) = slice.split_at_mut(end);
        open_with(&self.cipher, seq, &header, &mut ciphertext[8..], tag)?;
        self.replay.commit(seq);
        let kind = buf.as_slice()[8];
        buf.strip_header(9);
        buf.strip_tail(16);
        Ok((seq, kind, buf))
    }
}

pub struct StreamCipher {
    cipher: ChaCha20Poly1305,
    seq: u64,
}
impl StreamCipher {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new((&key).into()),
            seq: 0,
        }
    }
    pub fn seal(&mut self, kind: u8, body: &[u8]) -> Result<Vec<u8>, CoreErr> {
        if body.len() > e2e::ST_MAX_BODY {
            return Err(CoreErr::Malformed);
        }
        let seq = take_sequence(&mut self.seq)?;
        let aad = (body.len() as u16).to_be_bytes();
        let mut wire = Vec::with_capacity(body.len() + e2e::ST_OVERHEAD);
        wire.extend_from_slice(&aad);
        wire.push(kind);
        wire.extend_from_slice(body);
        let tag = seal_with(&self.cipher, seq, &aad, &mut wire[2..]);
        wire.extend_from_slice(&tag);
        Ok(wire)
    }
    pub fn open(&mut self, mut wire: Vec<u8>) -> Result<(u8, Vec<u8>), CoreErr> {
        let prefix = wire.get(..2).ok_or(CoreErr::Malformed)?;
        let aad: [u8; 2] = prefix.try_into().unwrap();
        let body_len = e2e::stream_body_len(aad)?;
        if wire.len() != body_len + e2e::ST_OVERHEAD {
            return Err(CoreErr::Malformed);
        }
        let seq = take_sequence(&mut self.seq)?;
        let (body, tag) = wire.split_at_mut(3 + body_len);
        open_with(&self.cipher, seq, &aad, &mut body[2..], tag)?;
        let kind = wire[2];
        wire.copy_within(3..3 + body_len, 0);
        wire.truncate(body_len);
        Ok((kind, wire))
    }
}
