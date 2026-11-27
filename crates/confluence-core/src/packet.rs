//! Zero-copy packet buffer with reserved headroom and tailroom for in-place framing.

use core::fmt;
use core::ops::Range;

use zeroize::Zeroize;

use crate::constants::{HEADROOM_BYTES, TAILROOM_BYTES};
use crate::error::CoreError;

/// Contiguous packet buffer with [`HEADROOM_BYTES`] (`64 B`) leading headroom and
/// [`TAILROOM_BYTES`] (`64 B`) trailing tailroom for zero-allocation in-place framing
/// and stacked AEAD encryption.
pub struct PacketBuf {
    buf: Vec<u8>,
    head: usize,
    tail: usize,
    /// Optional raw backing-buffer range `[start..end]` containing sensitive credential plaintext
    /// that MUST be zeroized in place before buffer reuse (`reset`) or drop (Spec §1.4 & §6.7).
    sensitive_range: Option<(usize, usize)>,
}

impl Clone for PacketBuf {
    fn clone(&self) -> Self {
        Self {
            buf: self.buf.clone(),
            head: self.head,
            tail: self.tail,
            sensitive_range: self.sensitive_range,
        }
    }
}

impl PartialEq for PacketBuf {
    fn eq(&self, other: &Self) -> bool {
        self.head == other.head && self.tail == other.tail && self.buf == other.buf
    }
}

impl Eq for PacketBuf {}

impl Drop for PacketBuf {
    #[inline]
    fn drop(&mut self) {
        self.wipe_sensitive();
    }
}

impl PacketBuf {
    /// Allocates an empty `PacketBuf` with room for `payload_capacity` payload bytes plus
    /// `64 B` headroom and `64 B` tailroom.
    #[must_use]
    pub fn with_capacity(payload_capacity: usize) -> Self {
        let total = HEADROOM_BYTES
            .saturating_add(payload_capacity)
            .saturating_add(TAILROOM_BYTES);
        Self {
            buf: vec![0u8; total],
            head: HEADROOM_BYTES,
            tail: HEADROOM_BYTES,
            sensitive_range: None,
        }
    }

    /// Allocates a `PacketBuf` with `payload_len` zeroed payload bytes plus headroom and tailroom.
    #[must_use]
    pub fn with_payload_len(payload_len: usize) -> Self {
        let mut pkt = Self::with_capacity(payload_len);
        pkt.tail = HEADROOM_BYTES + payload_len;
        pkt
    }

    /// Allocates a `PacketBuf` initialized with a copy of `payload`, preserving `64 B`
    /// headroom before and `64 B` tailroom after the payload.
    #[must_use]
    pub fn from_payload(payload: &[u8]) -> Self {
        let mut pkt = Self::with_capacity(payload.len());
        let end = HEADROOM_BYTES + payload.len();
        pkt.buf[HEADROOM_BYTES..end].copy_from_slice(payload);
        pkt.tail = end;
        pkt
    }

    /// Returns the active payload bytes.
    #[must_use]
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.buf[self.head..self.tail]
    }

    /// Returns a mutable slice of the active payload bytes.
    #[must_use]
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.head..self.tail]
    }

    /// Returns the active payload length in bytes.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        self.tail - self.head
    }

    /// Returns `true` when the active payload length is zero.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Returns the remaining leading headroom available for [`Self::prepend_header`].
    #[must_use]
    #[inline]
    pub const fn headroom(&self) -> usize {
        self.head
    }

    /// Returns the remaining trailing tailroom available for [`Self::extend_tail`] / [`Self::append_tag`].
    #[must_use]
    #[inline]
    pub fn tailroom(&self) -> usize {
        self.buf.len() - self.tail
    }

    /// Prepends `header` into reserved headroom without copying the payload or reallocating.
    pub fn prepend_header(&mut self, header: &[u8]) -> Result<(), CoreError> {
        if header.len() > self.head {
            return Err(CoreError::InvalidParameter);
        }
        let new_head = self.head - header.len();
        self.buf[new_head..self.head].copy_from_slice(header);
        self.head = new_head;
        Ok(())
    }

    /// Reserves `len` bytes in front of the current payload and returns them for in-place writes.
    pub fn prepend_mut(&mut self, len: usize) -> Result<&mut [u8], CoreError> {
        if len > self.head {
            return Err(CoreError::InvalidParameter);
        }
        let new_head = self.head - len;
        let old_head = self.head;
        self.head = new_head;
        Ok(&mut self.buf[new_head..old_head])
    }

    /// Strips `len` bytes from the front of the active payload and returns the stripped slice.
    pub fn strip_header(&mut self, len: usize) -> Result<&[u8], CoreError> {
        if len > self.len() {
            return Err(CoreError::Malformed);
        }
        let start = self.head;
        self.head += len;
        Ok(&self.buf[start..self.head])
    }

    /// Appends `data` into reserved tailroom without copying the payload or reallocating.
    pub fn extend_tail(&mut self, data: &[u8]) -> Result<(), CoreError> {
        if data.len() > self.tailroom() {
            return Err(CoreError::InvalidParameter);
        }
        let new_tail = self.tail + data.len();
        self.buf[self.tail..new_tail].copy_from_slice(data);
        self.tail = new_tail;
        Ok(())
    }

    /// Appends a 16-byte AEAD authentication tag into reserved tailroom in place.
    pub fn append_tag(&mut self, tag: &[u8; 16]) -> Result<(), CoreError> {
        self.extend_tail(tag)
    }

    /// Strips `len` bytes from the end of the active payload and returns the stripped slice.
    pub fn strip_tail(&mut self, len: usize) -> Result<&[u8], CoreError> {
        if len > self.len() {
            return Err(CoreError::Malformed);
        }
        let old_tail = self.tail;
        self.tail -= len;
        Ok(&self.buf[self.tail..old_tail])
    }

    /// Returns the writable spare payload region after `tail` while preserving [`TAILROOM_BYTES`].
    #[must_use]
    pub fn spare_payload(&mut self) -> &mut [u8] {
        let limit = self.buf.len().saturating_sub(TAILROOM_BYTES);
        if self.tail >= limit {
            &mut []
        } else {
            &mut self.buf[self.tail..limit]
        }
    }

    /// Advances `tail` by `written` bytes after writing into [`Self::spare_payload`].
    pub fn advance_payload(&mut self, written: usize) -> Result<(), CoreError> {
        let limit = self.buf.len().saturating_sub(TAILROOM_BYTES);
        let available = limit.saturating_sub(self.tail);
        if written > available {
            return Err(CoreError::InvalidParameter);
        }
        self.tail += written;
        Ok(())
    }

    /// Truncates the active payload to `new_len` bytes without moving `head`.
    pub fn truncate(&mut self, new_len: usize) -> Result<(), CoreError> {
        if new_len > self.len() {
            return Err(CoreError::InvalidParameter);
        }
        self.tail = self.head + new_len;
        Ok(())
    }

    /// Zeroizes the active payload bytes (plus any tracked sensitive range) in place with
    /// zero heap allocations.
    #[inline]
    pub fn zeroize_payload(&mut self) {
        self.buf[self.head..self.tail].zeroize();
        self.wipe_sensitive();
    }

    /// Zeroizes a payload-relative byte `range` in place with zero heap allocations.
    ///
    /// Out-of-bounds endpoints are clamped to the active payload length without panicking.
    #[inline]
    pub fn zeroize_range(&mut self, range: Range<usize>) {
        let len = self.len();
        let start = range.start.min(len);
        let end = range.end.min(len);
        if start < end {
            self.buf[self.head + start..self.head + end].zeroize();
        }
    }

    /// Marks the active payload range (plus any immediately preceding E2E opcode byte if present)
    /// as sensitive so [`Self::reset`] and [`Drop`] automatically zeroize it in place.
    #[inline]
    pub(crate) fn mark_payload_sensitive(&mut self) {
        let start = self.head;
        let end = self.tail;
        if start >= end {
            return;
        }
        self.sensitive_range = Some(match self.sensitive_range {
            Some((prev_start, prev_end)) => (prev_start.min(start), prev_end.max(end)),
            None => (start, end),
        });
    }

    #[inline]
    fn wipe_sensitive(&mut self) {
        if let Some((start, end)) = self.sensitive_range.take() {
            let clamped_end = end.min(self.buf.len());
            if start < clamped_end {
                self.buf[start..clamped_end].zeroize();
            }
        }
    }

    /// Resets cursors back to the default `HEADROOM_BYTES` origin so the backing buffer can be reused.
    ///
    /// Automatically zeroizes any tracked sensitive range before releasing cursors.
    pub fn reset(&mut self) {
        self.wipe_sensitive();
        let origin = HEADROOM_BYTES.min(self.buf.len());
        self.head = origin;
        self.tail = origin;
    }

    #[cfg(test)]
    pub(crate) fn raw_backing_bytes(&self) -> &[u8] {
        &self.buf
    }

    #[cfg(test)]
    pub(crate) fn has_sensitive_range(&self) -> bool {
        self.sensitive_range.is_some()
    }
}

impl AsRef<[u8]> for PacketBuf {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.payload()
    }
}

impl fmt::Debug for PacketBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketBuf")
            .field("len", &self.len())
            .field("headroom", &self.headroom())
            .field("tailroom", &self.tailroom())
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn packet_buf_preserves_pointer_and_bounds() {
        let mut pkt = PacketBuf::from_payload(b"hello confluence");
        let orig_ptr = pkt.payload().as_ptr();
        assert_eq!(pkt.headroom(), HEADROOM_BYTES);
        assert_eq!(pkt.tailroom(), TAILROOM_BYTES);

        // Prepend 9B E2E header + 5B hop header + 12B outer wrapper, append 4 x 16B tags.
        pkt.prepend_header(&[1u8; 9]).unwrap();
        pkt.prepend_header(&[2u8; 5]).unwrap();
        pkt.prepend_header(&[3u8; 12]).unwrap();
        for i in 0..4u8 {
            pkt.append_tag(&[i; 16]).unwrap();
        }
        assert_eq!(pkt.tailroom(), 0);
        assert_eq!(pkt.append_tag(&[0; 16]), Err(CoreError::InvalidParameter));

        // Strip everything back and confirm original payload pointer is identical.
        assert_eq!(pkt.strip_header(12).unwrap(), &[3u8; 12]);
        assert_eq!(pkt.strip_header(5).unwrap(), &[2u8; 5]);
        assert_eq!(pkt.strip_header(9).unwrap(), &[1u8; 9]);
        for i in (0..4u8).rev() {
            assert_eq!(pkt.strip_tail(16).unwrap(), &[i; 16]);
        }
        assert_eq!(pkt.payload(), b"hello confluence");
        assert_eq!(pkt.payload().as_ptr(), orig_ptr);
    }

    #[test]
    fn spare_payload_preserves_tailroom() {
        let mut pkt = PacketBuf::with_capacity(128);
        assert_eq!(pkt.spare_payload().len(), 128);
        pkt.spare_payload()[..5].copy_from_slice(b"abcde");
        pkt.advance_payload(5).unwrap();
        assert_eq!(pkt.payload(), b"abcde");
        assert_eq!(pkt.tailroom(), 123 + TAILROOM_BYTES);
        assert_eq!(pkt.advance_payload(124), Err(CoreError::InvalidParameter));
    }

    #[test]
    fn packet_buf_zeroize_payload_range_and_sensitive_reset() {
        let secret = b"01234567secret-cred-bytes";
        let mut pkt = PacketBuf::from_payload(secret);
        let orig_ptr = pkt.payload().as_ptr();

        // Partial range wipe (with out-of-bounds clamp safety).
        pkt.zeroize_range(8..100);
        assert_eq!(&pkt.payload()[..8], b"01234567");
        assert!(pkt.payload()[8..].iter().all(|&b| b == 0));
        assert_eq!(pkt.payload().as_ptr(), orig_ptr);

        // Full payload wipe.
        pkt.zeroize_payload();
        assert!(pkt.payload().iter().all(|&b| b == 0));

        // Sensitive range automatically wipes backing storage on reset().
        let mut sens = PacketBuf::from_payload(b"sensitive-renew-token");
        sens.mark_payload_sensitive();
        assert!(sens.has_sensitive_range());
        sens.reset();
        assert!(!sens.has_sensitive_range());
        assert!(
            sens.raw_backing_bytes().iter().all(|&b| b == 0),
            "backing storage must be zeroed on reset of sensitive PacketBuf"
        );
    }
}
