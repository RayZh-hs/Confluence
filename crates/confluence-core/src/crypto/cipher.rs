//! Steady-state authenticated ciphers and 64-packet sliding anti-replay window (Spec §4.3, §4.5.3, §4.7.2, §5.8).

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Tag};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::constants::{
    DG_E2E_MIN_LEN, E2E_DG_RENEW_OPCODE, E2E_ST_RENEW_OPCODE, MAC_LEN, MAX_CONTROL, MIN_CONTROL,
    REPLAY_WINDOW_PACKETS, ST_MAX_BODY, ST_OVERHEAD,
};
use crate::crypto::noise::nonce_from_seq;
use crate::error::CoreError;
use crate::packet::PacketBuf;

// Compile-time proof that AEAD cipher structs zeroize key material on drop (Spec §1.4).
const _: fn() = || {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<ChaCha20Poly1305>();
    assert_zeroize_on_drop::<chacha20poly1305::XChaCha20Poly1305>();
    assert_zeroize_on_drop::<ControlCipher>();
    assert_zeroize_on_drop::<DatagramTx>();
    assert_zeroize_on_drop::<DatagramRx>();
    assert_zeroize_on_drop::<StreamCipher>();
};

/// Checked sequence allocator: yields `0, 1, ..., u64::MAX - 1` and fails with [`CoreError::Closed`]
/// once `seq == u64::MAX` rather than wrapping or reusing a nonce (Spec §4.3).
#[inline]
fn take_seq(seq: &mut u64) -> Result<u64, CoreError> {
    let next = seq.checked_add(1).ok_or(CoreError::Closed)?;
    let current = *seq;
    *seq = next;
    Ok(current)
}

/// 64-packet sliding anti-replay bitmap used by [`ControlCipher`] and [`DatagramRx`] (Spec §4.7.2).
///
/// Callers MUST invoke [`Self::allows`] before AEAD decryption and [`Self::commit`] ONLY
/// after AEAD authentication succeeds.
#[derive(Debug, Clone, Default)]
pub struct ReplayWindow {
    max: u64,
    seen: u64,
}

impl ReplayWindow {
    /// Creates an empty replay window initialized to `(max = 0, seen = 0)`.
    #[must_use]
    pub const fn new() -> Self {
        Self { max: 0, seen: 0 }
    }

    /// Returns `true` iff `seq` is fresh (either strictly newer than `max`, or within the
    /// 64-packet window and not yet marked seen).
    #[must_use]
    pub const fn allows(&self, seq: u64) -> bool {
        if seq > self.max {
            return true;
        }
        let diff = self.max - seq;
        diff < REPLAY_WINDOW_PACKETS && (self.seen & (1u64 << diff)) == 0
    }

    /// Records `seq` as authenticated and seen. MUST only be called after AEAD decryption succeeds.
    pub fn commit(&mut self, seq: u64) {
        if seq > self.max {
            let shift = seq - self.max;
            if shift >= REPLAY_WINDOW_PACKETS {
                self.seen = 0;
            } else {
                self.seen <<= shift;
            }
            self.max = seq;
        }
        let diff = self.max - seq;
        if diff < REPLAY_WINDOW_PACKETS {
            self.seen |= 1u64 << diff;
        }
    }
}

/// Bidirectional per-hop authenticated control cipher (`CLOSE`, `MTU`, `MTU_ACK`, `RENEW`, `RENEW_OK`).
pub struct ControlCipher {
    tx: ChaCha20Poly1305,
    rx: ChaCha20Poly1305,
    tx_seq: u64,
    rx_window: ReplayWindow,
}

impl ZeroizeOnDrop for ControlCipher {}

impl ControlCipher {
    /// Creates a directional `ControlCipher` from 32-byte TX and RX keys.
    #[must_use]
    pub fn new(tx_key: &[u8; 32], rx_key: &[u8; 32]) -> Self {
        Self {
            tx: ChaCha20Poly1305::new(tx_key.into()),
            rx: ChaCha20Poly1305::new(rx_key.into()),
            tx_seq: 0,
            rx_window: ReplayWindow::new(),
        }
    }

    /// Seals `plaintext` bound to outer hop opcode `kind` into `[be64(seq) | ct | tag[16]]`.
    pub fn seal(&mut self, kind: u8, plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
        let mut out = Vec::with_capacity(plaintext.len() + MIN_CONTROL);
        self.seal_into(kind, plaintext, &mut out)?;
        Ok(out)
    }

    /// Seals `plaintext` into a reusable `out` buffer (`[be64(seq) | ct | tag[16]]`).
    pub fn seal_into(
        &mut self,
        kind: u8,
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CoreError> {
        let wire_len = plaintext.len().saturating_add(MIN_CONTROL);
        if wire_len > MAX_CONTROL {
            return Err(CoreError::InvalidParameter);
        }
        let seq = take_seq(&mut self.tx_seq)?;
        out.clear();
        out.reserve(wire_len);
        out.extend_from_slice(&seq.to_be_bytes());
        let ct_start = out.len();
        out.extend_from_slice(plaintext);
        let tag = match self
            .tx
            .encrypt_in_place_detached(&nonce_from_seq(seq), &[kind], &mut out[ct_start..])
        {
            Ok(tag) => tag,
            Err(_) => {
                out[ct_start..].zeroize();
                out.clear();
                return Err(CoreError::Authentication);
            }
        };
        out.extend_from_slice(tag.as_slice());
        Ok(())
    }

    /// Authenticates and opens a `24..=160` byte control body bound to outer opcode `kind`.
    ///
    /// Commits `seq` to the replay window strictly after AEAD authentication succeeds.
    pub fn open(&mut self, kind: u8, wire: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        if !(MIN_CONTROL..=MAX_CONTROL).contains(&wire.len()) {
            return Err(CoreError::Malformed);
        }
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&wire[0..8]);
        let seq = u64::from_be_bytes(seq_bytes);

        if !self.rx_window.allows(seq) {
            return Err(CoreError::Authentication);
        }

        let ct_end = wire.len() - MAC_LEN;
        let tag = Tag::from_slice(&wire[ct_end..]);
        let mut pt = Zeroizing::new(wire[8..ct_end].to_vec());
        if self
            .rx
            .decrypt_in_place_detached(&nonce_from_seq(seq), &[kind], &mut pt, tag)
            .is_err()
        {
            return Err(CoreError::Authentication);
        }
        self.rx_window.commit(seq);
        Ok(pt)
    }

    #[cfg(test)]
    pub(crate) fn set_tx_seq_for_test(&mut self, seq: u64) {
        self.tx_seq = seq;
    }
}

/// Zero-allocation in-place end-to-end Datagram transmit cipher (Spec §5.8.1 & §8.3).
pub struct DatagramTx {
    cipher: ChaCha20Poly1305,
    seq: u64,
}

impl ZeroizeOnDrop for DatagramTx {}

impl DatagramTx {
    /// Creates a `DatagramTx` cipher initialized to `seq = 0`.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(key.into()),
            seq: 0,
        }
    }

    /// Seals `pkt` in place as `[be64(seq) | Enc(opcode || payload) | tag[16]]`.
    ///
    /// Performs **zero heap allocations** and keeps the interior payload pointer stable.
    pub fn seal(&mut self, opcode: u8, pkt: &mut PacketBuf) -> Result<u64, CoreError> {
        if pkt.headroom() < 9 || pkt.tailroom() < MAC_LEN {
            return Err(CoreError::InvalidParameter);
        }
        let seq = take_seq(&mut self.seq)?;
        let aad = seq.to_be_bytes();

        pkt.prepend_header(&[opcode])?;
        let tag = match self
            .cipher
            .encrypt_in_place_detached(&nonce_from_seq(seq), &aad, pkt.payload_mut())
        {
            Ok(tag) => tag,
            Err(_) => {
                pkt.zeroize_payload();
                return Err(CoreError::Authentication);
            }
        };
        pkt.prepend_header(&aad)?;
        let tag_bytes: [u8; 16] = tag.into();
        pkt.append_tag(&tag_bytes)?;
        Ok(seq)
    }

    #[cfg(test)]
    pub(crate) fn set_seq_for_test(&mut self, seq: u64) {
        self.seq = seq;
    }
}

/// Zero-allocation in-place end-to-end Datagram receive cipher with 64-packet anti-replay window.
pub struct DatagramRx {
    cipher: ChaCha20Poly1305,
    window: ReplayWindow,
}

impl ZeroizeOnDrop for DatagramRx {}

impl DatagramRx {
    /// Creates a `DatagramRx` cipher with an empty 64-packet sliding [`ReplayWindow`].
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(key.into()),
            window: ReplayWindow::new(),
        }
    }

    /// Opens an E2E datagram record in place (after stripping the 5-byte `DG_DATA` hop header).
    ///
    /// Returns `(seq, e2e_opcode)` with `pkt.payload()` restored to the exact interior body
    /// pointer and **zero heap allocations**. Never advances replay state on authentication failure.
    pub fn open(&mut self, pkt: &mut PacketBuf) -> Result<(u64, u8), CoreError> {
        if pkt.len() < DG_E2E_MIN_LEN {
            return Err(CoreError::Malformed);
        }
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&pkt.payload()[0..8]);
        let seq = u64::from_be_bytes(seq_bytes);

        if !self.window.allows(seq) {
            return Err(CoreError::Replay);
        }

        let len = pkt.len();
        let ct_end = len - MAC_LEN;
        let mut tag_bytes = [0u8; 16];
        tag_bytes.copy_from_slice(&pkt.payload()[ct_end..len]);

        let aad = seq_bytes;
        self.cipher
            .decrypt_in_place_detached(
                &nonce_from_seq(seq),
                &aad,
                &mut pkt.payload_mut()[8..ct_end],
                Tag::from_slice(&tag_bytes),
            )
            .map_err(|_| CoreError::Authentication)?;

        self.window.commit(seq);
        let opcode = pkt.payload()[8];
        pkt.strip_header(9)?;
        pkt.strip_tail(MAC_LEN)?;
        if opcode == E2E_DG_RENEW_OPCODE {
            // Spec §1.4 & §6.7: Track decrypted renewal credential range so reuse/drop
            // automatically wipes plaintext in place with zero heap allocations.
            pkt.mark_payload_sensitive();
        }
        Ok((seq, opcode))
    }
}

/// Borrowed guard over a decrypted Stream E2E record stored in place inside a receive buffer.
///
/// When the record carries a credential-bearing renewal opcode (`e2e_st::ST_RENEW`), dropping
/// this guard automatically zeroizes the decrypted plaintext slice in place before the receive
/// buffer can be reused or dropped (Spec §1.4 & §6.7).
pub struct OpenedStreamRecord<'a> {
    opcode: u8,
    body_len: usize,
    plaintext_region: &'a mut [u8],
    wipe_on_drop: bool,
}

#[allow(dead_code)]
impl OpenedStreamRecord<'_> {
    /// Returns the authenticated E2E Stream opcode.
    #[inline]
    #[must_use]
    pub const fn opcode(&self) -> u8 {
        self.opcode
    }

    /// Returns the decrypted record body slice (`0..=ST_MAX_BODY` bytes).
    #[inline]
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.plaintext_region[1..1 + self.body_len]
    }

    /// Returns `true` when this record carries sensitive renewal credential bytes that will be
    /// zeroized in place when the guard drops.
    #[inline]
    #[must_use]
    pub const fn is_sensitive(&self) -> bool {
        self.wipe_on_drop
    }

    /// Copies the decrypted body into a [`Zeroizing<Vec<u8>>`] and immediately drops `self`,
    /// wiping the original receive buffer slice if sensitive.
    #[must_use]
    pub fn into_zeroizing_body(self) -> Zeroizing<Vec<u8>> {
        let out = Zeroizing::new(self.body().to_vec());
        drop(self);
        out
    }
}

impl Drop for OpenedStreamRecord<'_> {
    #[inline]
    fn drop(&mut self) {
        if self.wipe_on_drop {
            self.plaintext_region.zeroize();
        }
    }
}

/// Directional end-to-end Stream record cipher with reusable scratch-buffer support (Spec §5.8.2).
pub struct StreamCipher {
    cipher: ChaCha20Poly1305,
    seq: u64,
}

impl ZeroizeOnDrop for StreamCipher {}

#[allow(dead_code)]
impl StreamCipher {
    /// Creates a directional `StreamCipher` starting at implicit `seq = 0`.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(key.into()),
            seq: 0,
        }
    }

    /// Seals `(opcode, body)` into a reusable `out` buffer as
    /// `[be16(body_len) | Enc(opcode || body) | tag[16]]`.
    pub fn seal_into(
        &mut self,
        opcode: u8,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CoreError> {
        if body.len() > ST_MAX_BODY {
            return Err(CoreError::Malformed);
        }
        let seq = take_seq(&mut self.seq)?;
        let body_len = u16::try_from(body.len()).map_err(|_| CoreError::Malformed)?;
        let aad = body_len.to_be_bytes();

        out.clear();
        out.reserve(body.len() + ST_OVERHEAD);
        out.extend_from_slice(&aad);
        let pt_start = out.len();
        out.push(opcode);
        out.extend_from_slice(body);
        let tag = match self
            .cipher
            .encrypt_in_place_detached(&nonce_from_seq(seq), &aad, &mut out[pt_start..])
        {
            Ok(tag) => tag,
            Err(_) => {
                out[pt_start..].zeroize();
                out.clear();
                return Err(CoreError::Authentication);
            }
        };
        out.extend_from_slice(tag.as_slice());
        Ok(())
    }

    /// Authenticates and decrypts a complete Stream E2E record in place (`record.len() == body_len + 19`).
    ///
    /// On success, returns `(opcode, body_len)` with the decrypted body stored at `record[3..3 + body_len]`.
    /// Callers processing credential-bearing renewal records (`e2e_st::ST_RENEW`) SHOULD prefer
    /// [`Self::open_record`] so the decrypted plaintext region is zeroized automatically on drop.
    pub fn open_in_place(&mut self, record: &mut [u8]) -> Result<(u8, usize), CoreError> {
        if record.len() < ST_OVERHEAD {
            return Err(CoreError::Malformed);
        }
        let aad = [record[0], record[1]];
        let body_len = usize::from(u16::from_be_bytes(aad));
        if body_len > ST_MAX_BODY || record.len() != body_len + ST_OVERHEAD {
            return Err(CoreError::Malformed);
        }
        let seq = take_seq(&mut self.seq)?;
        let ct_end = 2 + 1 + body_len;
        let mut tag_bytes = [0u8; 16];
        tag_bytes.copy_from_slice(&record[ct_end..ct_end + MAC_LEN]);

        self.cipher
            .decrypt_in_place_detached(
                &nonce_from_seq(seq),
                &aad,
                &mut record[2..ct_end],
                Tag::from_slice(&tag_bytes),
            )
            .map_err(|_| CoreError::Authentication)?;

        Ok((record[2], body_len))
    }

    /// Authenticates and decrypts a complete Stream E2E record in place, returning an
    /// [`OpenedStreamRecord`] guard that automatically zeroizes the decrypted plaintext slice
    /// in `record` on drop when the record is a credential-bearing `e2e_st::ST_RENEW` (Spec §1.4).
    pub fn open_record<'a>(
        &mut self,
        record: &'a mut [u8],
    ) -> Result<OpenedStreamRecord<'a>, CoreError> {
        let (opcode, body_len) = self.open_in_place(record)?;
        let pt_end = 2 + 1 + body_len;
        Ok(OpenedStreamRecord {
            opcode,
            body_len,
            plaintext_region: &mut record[2..pt_end],
            wipe_on_drop: opcode == E2E_ST_RENEW_OPCODE,
        })
    }

    #[cfg(test)]
    pub(crate) fn set_seq_for_test(&mut self, seq: u64) {
        self.seq = seq;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_handles_zero_ooo_duplicates_and_boundary() {
        let mut win = ReplayWindow::new();
        assert!(win.allows(0));
        win.commit(0);
        assert!(!win.allows(0));

        assert!(win.allows(63));
        win.commit(63);
        assert!(!win.allows(63));
        assert!(!win.allows(0));
        assert!(win.allows(1));
        assert!(win.allows(32));
        win.commit(32);
        assert!(!win.allows(32));

        // Advance to 64: seq 0 falls outside 64-pkt window; seq 1 is still allowed.
        assert!(win.allows(64));
        win.commit(64);
        assert!(!win.allows(0));
        assert!(win.allows(1));
        win.commit(1);
        assert!(!win.allows(1));

        // Large jump >= 64 clears bitmap cleanly without overflow.
        win.commit(200);
        assert!(!win.allows(136));
        assert!(win.allows(137));
    }

    #[test]
    fn corrupted_tag_does_not_advance_datagram_or_control_replay_window() {
        let key = [0x11u8; 32];
        let mut tx = DatagramTx::new(&key);
        let mut rx = DatagramRx::new(&key);

        let mut p0 = PacketBuf::from_payload(b"pkt0");
        let mut p1 = PacketBuf::from_payload(b"pkt1");
        assert_eq!(tx.seal(0x01, &mut p0).unwrap(), 0);
        assert_eq!(tx.seal(0x01, &mut p1).unwrap(), 1);

        // Corrupt p1 and try to open -> must fail and NOT advance replay window!
        let mut bad_p1 = p1.clone();
        bad_p1.payload_mut()[10] ^= 0xFF;
        assert_eq!(rx.open(&mut bad_p1), Err(CoreError::Authentication));

        // Genuine p1 and p0 still succeed!
        assert_eq!(rx.open(&mut p1).unwrap(), (1, 0x01));
        assert_eq!(p1.payload(), b"pkt1");
        assert_eq!(rx.open(&mut p0).unwrap(), (0, 0x01));
        assert_eq!(p0.payload(), b"pkt0");

        // ControlCipher same guarantee.
        let mut c_init = ControlCipher::new(&key, &[0x22u8; 32]);
        let mut c_resp = ControlCipher::new(&[0x22u8; 32], &key);
        let wire = c_init.seal(0x25, b"hello").unwrap();
        let mut bad = wire.clone();
        bad[9] ^= 0x01;
        assert_eq!(c_resp.open(0x25, &bad), Err(CoreError::Authentication));
        assert_eq!(c_resp.open(0x23, &wire), Err(CoreError::Authentication));
        assert_eq!(&*c_resp.open(0x25, &wire).unwrap(), b"hello");
        assert_eq!(c_resp.open(0x25, &wire), Err(CoreError::Authentication));
    }

    #[test]
    fn sequence_exhaustion_returns_closed_without_wrap() {
        let key = [0x55u8; 32];

        let mut dtx = DatagramTx::new(&key);
        dtx.set_seq_for_test(u64::MAX);
        let mut pkt = PacketBuf::from_payload(b"x");
        assert_eq!(dtx.seal(0x01, &mut pkt), Err(CoreError::Closed));

        let mut st = StreamCipher::new(&key);
        st.set_seq_for_test(u64::MAX);
        let mut scratch = Vec::new();
        assert_eq!(st.seal_into(0x10, b"x", &mut scratch), Err(CoreError::Closed));

        let mut ctrl = ControlCipher::new(&key, &key);
        ctrl.set_tx_seq_for_test(u64::MAX);
        assert_eq!(ctrl.seal(0x23, b"abcd"), Err(CoreError::Closed));
    }

    #[test]
    fn stream_cipher_roundtrip_reusing_scratch() {
        let key = [0x77u8; 32];
        let mut tx = StreamCipher::new(&key);
        let mut rx = StreamCipher::new(&key);
        let mut scratch = Vec::new();

        for payload in [&b""[..], b"a", b"hello world", &[0xAB; 16_365][..]] {
            tx.seal_into(0x10, payload, &mut scratch).unwrap();
            let (op, len) = rx.open_in_place(&mut scratch).unwrap();
            assert_eq!(op, 0x10);
            assert_eq!(len, payload.len());
            assert_eq!(&scratch[3..3 + len], payload);
        }
    }

    #[test]
    fn datagram_and_stream_e2e_renewal_wipe_decrypted_credentials_in_place() {
        let key = [0x91u8; 32];
        let secret = b"very-secret-renewal-credential-9876543210";
        let mut renew_body = Vec::new();
        renew_body.extend_from_slice(&1u64.to_be_bytes());
        renew_body.extend_from_slice(secret);

        // 1. Datagram E2E DG_RENEW: open marks PacketBuf sensitive; both zeroize_payload()
        //    and reset() wipe decrypted bytes in place in the original backing storage.
        let mut dg_tx = DatagramTx::new(&key);
        let mut dg_rx = DatagramRx::new(&key);

        let mut pkt1 = PacketBuf::from_payload(&renew_body);
        dg_tx.seal(E2E_DG_RENEW_OPCODE, &mut pkt1).unwrap();
        let (_seq1, op1) = dg_rx.open(&mut pkt1).unwrap();
        assert_eq!(op1, E2E_DG_RENEW_OPCODE);
        assert!(pkt1.has_sensitive_range());
        assert_eq!(&pkt1.payload()[8..], secret);
        pkt1.zeroize_payload();
        assert!(
            !pkt1.raw_backing_bytes().windows(secret.len()).any(|w| w == secret),
            "credential bytes must be wiped from PacketBuf after zeroize_payload()"
        );

        let mut pkt2 = PacketBuf::from_payload(&renew_body);
        dg_tx.seal(E2E_DG_RENEW_OPCODE, &mut pkt2).unwrap();
        let (_seq2, op2) = dg_rx.open(&mut pkt2).unwrap();
        assert_eq!(op2, E2E_DG_RENEW_OPCODE);
        assert!(pkt2.has_sensitive_range());
        pkt2.reset();
        assert!(
            !pkt2.raw_backing_bytes().windows(secret.len()).any(|w| w == secret),
            "credential bytes must be wiped from PacketBuf on reset()"
        );

        // 2. Stream E2E ST_RENEW: open_record guard wipes decrypted plaintext slice in place on drop!
        let mut st_tx = StreamCipher::new(&key);
        let mut st_rx = StreamCipher::new(&key);
        let mut record = Vec::new();
        st_tx
            .seal_into(E2E_ST_RENEW_OPCODE, &renew_body, &mut record)
            .unwrap();
        {
            let opened = st_rx.open_record(&mut record).unwrap();
            assert_eq!(opened.opcode(), E2E_ST_RENEW_OPCODE);
            assert!(opened.is_sensitive());
            assert_eq!(&opened.body()[8..], secret);
            let copied = opened.into_zeroizing_body();
            assert_eq!(&copied[8..], secret);
        }
        assert!(
            record[2..3 + renew_body.len()].iter().all(|&b| b == 0),
            "StreamCipher::open_record must zeroize decrypted ST_RENEW plaintext in place on drop"
        );
    }
}
