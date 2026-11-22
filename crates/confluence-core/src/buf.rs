use bytes::BytesMut;

pub const HEADROOM_BYTES: usize = 64;
pub const TAILROOM_BYTES: usize = 16;

/// A single-owner packet with space reserved for in-place framing and AEAD tags.
#[derive(Debug)]
pub struct PacketBuf {
    buf: BytesMut,
    head: usize,
    tail: usize,
}
impl PacketBuf {
    pub fn with_payload_cap(capacity: usize) -> Self {
        Self {
            buf: BytesMut::zeroed(HEADROOM_BYTES + capacity + TAILROOM_BYTES),
            head: HEADROOM_BYTES,
            tail: HEADROOM_BYTES,
        }
    }
    pub fn from_slice(payload: &[u8]) -> Self {
        let mut buf = Self::with_payload_cap(payload.len());
        buf.spare_payload()[..payload.len()].copy_from_slice(payload);
        buf.tail += payload.len();
        buf
    }
    pub fn spare_payload(&mut self) -> &mut [u8] {
        let end = self.buf.len().saturating_sub(TAILROOM_BYTES).max(self.tail);
        &mut self.buf[self.tail..end]
    }
    pub fn advance_payload(&mut self, count: usize) -> bool {
        if count > self.spare_payload().len() {
            return false;
        }
        self.tail += count;
        true
    }
    pub fn prepend_header(&mut self, header: &[u8]) -> bool {
        let Some(head) = self.head.checked_sub(header.len()) else {
            return false;
        };
        self.buf[head..self.head].copy_from_slice(header);
        self.head = head;
        true
    }
    pub fn strip_header(&mut self, count: usize) -> bool {
        if count > self.len() {
            return false;
        }
        self.head += count;
        true
    }
    pub fn strip_tail(&mut self, count: usize) -> bool {
        if count > self.len() {
            return false;
        }
        self.tail -= count;
        true
    }
    pub(crate) fn append_tag(&mut self, tag: &[u8; TAILROOM_BYTES]) -> bool {
        if self.buf.len() - self.tail < tag.len() {
            return false;
        }
        self.buf[self.tail..self.tail + tag.len()].copy_from_slice(tag);
        self.tail += tag.len();
        true
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[self.head..self.tail]
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf[self.head..self.tail]
    }
    pub fn len(&self) -> usize {
        self.tail - self.head
    }
    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }
}
