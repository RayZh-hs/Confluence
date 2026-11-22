use bytes::BytesMut;

pub const HEADROOM_BYTES: usize = 64;
/// Tailroom reserved for up to four stacked 16-byte AEAD tags (E2E + outer link wrappers).
pub const TAILROOM_BYTES: usize = 64;

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
    /// Appends a 16-byte AEAD tag into reserved tailroom in place.
    pub fn append_tag(&mut self, tag: &[u8; 16]) -> bool {
        self.extend_tail(tag)
    }
    /// Appends `bytes` into reserved tailroom in place without reallocating.
    pub fn extend_tail(&mut self, bytes: &[u8]) -> bool {
        if self.buf.len() - self.tail < bytes.len() {
            return false;
        }
        self.buf[self.tail..self.tail + bytes.len()].copy_from_slice(bytes);
        self.tail += bytes.len();
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
    /// Remaining reserved headroom bytes available for [`Self::prepend_header`].
    pub fn headroom(&self) -> usize {
        self.head
    }
    /// Remaining reserved tailroom bytes available for [`Self::extend_tail`] / [`Self::append_tag`].
    pub fn tailroom(&self) -> usize {
        self.buf.len() - self.tail
    }
}
