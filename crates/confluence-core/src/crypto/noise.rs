//! Normative v1 `Noise_IK` handshake, `HopKey`, and `SessionKeys` (Spec §4.4–4.5).

use core::fmt;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::constants::{
    COOKIE_LEN, ERR_BODY_SIZE, HOP_ACK_SIZE, MAC_LEN, REPLY_LEN, SEGMENT_OVERHEAD,
    SETUP_FRESHNESS_WINDOW_MS,
};
use crate::crypto::cipher::ControlCipher;
use crate::crypto::identity::{ScopeKeypair, compute_mac1, compute_mac2, derive_scope_kid};
use crate::crypto::replay::SetupReplay;
use crate::error::CoreError;
use crate::runtime::MonotonicTime;
use crate::types::PublicKey;

const NOISE_PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE3+confluence-v1";
const LABEL_CHAINING_KEY: &[u8] = b"chaining key";
const LABEL_CIPHER_KEY: &[u8] = b"cipher key";
const LABEL_HOP_CONTROL: &[u8] = b"confluence-v1 hop control";
const LABEL_INIT_TO_RESP: &[u8] = b"initiator to responder";
const LABEL_RESP_TO_INIT: &[u8] = b"responder to initiator";
const AAD_SETUP_ERROR: &[u8] = b"confluence-v1 setup error";
const LABEL_HOP_SETUP_ACK: &[u8] = b"hop setup ack";
const AAD_SETUP_HOP_ACK: &[u8] = b"confluence-v1 setup hop ack";
#[allow(dead_code)]
const LABEL_HOP_FORWARD: &[u8] = b"hop forward";
#[allow(dead_code)]
const LABEL_HOP_REVERSE: &[u8] = b"hop reverse";

/// Constructs the normative 12-byte ChaCha20-Poly1305 nonce: `[0, 0, 0, 0] || be64(seq)`.
#[inline]
pub(crate) fn nonce_from_seq(seq: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..12].copy_from_slice(&seq.to_be_bytes());
    n.into()
}

/// Symmetric Noise_IK state zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct NoiseState {
    ck: [u8; 32],
    h: [u8; 32],
    k: [u8; 32],
    n: u64,
}

impl NoiseState {
    /// Initializes symmetric state with `tail_aad` mixed STRICTLY BEFORE `target_pk` (Spec §4.4.1).
    fn initialize(target_pk: &PublicKey, tail_aad: &[u8; 32]) -> Self {
        let initial = *blake3::hash(NOISE_PROTOCOL_NAME).as_bytes();
        let mut state = Self {
            ck: initial,
            h: initial,
            k: [0u8; 32],
            n: 0,
        };
        state.mix_hash(tail_aad);
        state.mix_hash(target_pk.as_bytes());
        state
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.h);
        hasher.update(data);
        self.h = *hasher.finalize().as_bytes();
    }

    fn mix_ciphertext(&mut self, ct: &[u8], tag: &[u8; 16]) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.h);
        hasher.update(ct);
        hasher.update(tag);
        self.h = *hasher.finalize().as_bytes();
    }

    /// Mixes an X25519 DH shared secret, aborting in constant time if all-zero (Spec §4.4.1).
    fn mix_key(&mut self, dh_output: [u8; 32]) -> Result<(), CoreError> {
        let dh = Zeroizing::new(dh_output);
        if bool::from(dh.ct_eq(&[0u8; 32])) {
            return Err(CoreError::Authentication);
        }
        let prk = Zeroizing::new(*blake3::keyed_hash(&self.ck, &*dh).as_bytes());
        self.ck = *blake3::keyed_hash(&prk, LABEL_CHAINING_KEY).as_bytes();
        self.k = *blake3::keyed_hash(&prk, LABEL_CIPHER_KEY).as_bytes();
        self.n = 0;
        Ok(())
    }

    fn encrypt_into(&mut self, pt: &[u8], out_ct: &mut [u8]) -> Result<[u8; 16], CoreError> {
        let next_n = self.n.checked_add(1).ok_or(CoreError::Closed)?;
        let seq = self.n;
        out_ct.copy_from_slice(pt);
        let cipher = ChaCha20Poly1305::new((&self.k).into());
        let tag = cipher
            .encrypt_in_place_detached(&nonce_from_seq(seq), &self.h, out_ct)
            .map_err(|_| CoreError::Authentication)?;
        self.n = next_n;
        let tag_bytes: [u8; 16] = tag.into();
        self.mix_ciphertext(out_ct, &tag_bytes);
        Ok(tag_bytes)
    }

    fn decrypt_into(
        &mut self,
        ct: &[u8],
        tag: &[u8; 16],
        out_pt: &mut [u8],
    ) -> Result<(), CoreError> {
        let next_n = self.n.checked_add(1).ok_or(CoreError::Closed)?;
        let seq = self.n;
        out_pt.copy_from_slice(ct);
        let cipher = ChaCha20Poly1305::new((&self.k).into());
        if cipher
            .decrypt_in_place_detached(&nonce_from_seq(seq), &self.h, out_pt, Tag::from_slice(tag))
            .is_err()
        {
            out_pt.zeroize();
            return Err(CoreError::Authentication);
        }
        self.n = next_n;
        self.mix_ciphertext(ct, tag);
        Ok(())
    }

    fn derive_hop_key(&self) -> HopKey {
        let transcript = Zeroizing::new(*blake3::keyed_hash(&self.ck, &self.h).as_bytes());
        let key = *blake3::keyed_hash(&transcript, LABEL_HOP_CONTROL).as_bytes();
        HopKey(key)
    }

    fn split_session_keys(&self, is_initiator: bool) -> SessionKeys {
        let root = Zeroizing::new(*blake3::keyed_hash(&self.ck, &self.h).as_bytes());
        let fwd = *blake3::keyed_hash(&root, LABEL_INIT_TO_RESP).as_bytes();
        let rev = *blake3::keyed_hash(&root, LABEL_RESP_TO_INIT).as_bytes();
        if is_initiator {
            SessionKeys { tx: fwd, rx: rev }
        } else {
            SessionKeys { tx: rev, rx: fwd }
        }
    }
}

/// Per-hop symmetric control key derived immediately after Noise_IK Message 1 (Spec §4.4.3 & §4.5).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HopKey([u8; 32]);

#[allow(dead_code)]
impl HopKey {
    /// Seals a 4-byte `[code: u16 BE | arg: u16 BE]` setup error into a 28-byte wire body
    /// using a fresh CSPRNG `u64` nonce counter.
    pub fn seal_setup_error(&self, code: u16, arg: u16) -> [u8; ERR_BODY_SIZE] {
        let nonce_ctr = OsRng.next_u64();
        let mut pt = [0u8; 4];
        pt[0..2].copy_from_slice(&code.to_be_bytes());
        pt[2..4].copy_from_slice(&arg.to_be_bytes());

        let cipher = ChaCha20Poly1305::new((&self.0).into());
        let mut ct = pt;
        let tag_bytes: [u8; 16] = match cipher.encrypt_in_place_detached(
            &nonce_from_seq(nonce_ctr),
            AAD_SETUP_ERROR,
            &mut ct,
        ) {
            Ok(t) => t.into(),
            // ChaCha20Poly1305 encryption of a 4-byte buffer cannot fail.
            Err(_) => [0u8; 16],
        };

        let mut out = [0u8; ERR_BODY_SIZE];
        out[0..8].copy_from_slice(&nonce_ctr.to_be_bytes());
        out[8..12].copy_from_slice(&ct);
        out[12..28].copy_from_slice(&tag_bytes);
        out
    }

    /// Authenticates and decrypts a 28-byte `SETUP_ERR` body into `(code, arg)`.
    pub fn open_setup_error(&self, body: &[u8; ERR_BODY_SIZE]) -> Result<(u16, u16), CoreError> {
        let mut nonce_bytes = [0u8; 8];
        nonce_bytes.copy_from_slice(&body[0..8]);
        let nonce_ctr = u64::from_be_bytes(nonce_bytes);

        let mut pt = [0u8; 4];
        pt.copy_from_slice(&body[8..12]);
        let tag = Tag::from_slice(&body[12..28]);

        let cipher = ChaCha20Poly1305::new((&self.0).into());
        cipher
            .decrypt_in_place_detached(&nonce_from_seq(nonce_ctr), AAD_SETUP_ERROR, &mut pt, tag)
            .map_err(|_| CoreError::Authentication)?;

        let code = u16::from_be_bytes([pt[0], pt[1]]);
        let arg = u16::from_be_bytes([pt[2], pt[3]]);
        Ok((code, arg))
    }

    /// Seals a 26-byte `SETUP_OK` hop trailer carrying `(hop_mtu, lease_ttl_ms)`.
    pub fn seal_setup_hop_ack(&self, hop_mtu: u16, lease_ttl_ms: u64) -> [u8; HOP_ACK_SIZE] {
        let ack_key = Zeroizing::new(*blake3::keyed_hash(&self.0, LABEL_HOP_SETUP_ACK).as_bytes());
        let mut buf = [0u8; 10];
        buf[0..2].copy_from_slice(&hop_mtu.to_be_bytes());
        buf[2..10].copy_from_slice(&lease_ttl_ms.to_be_bytes());

        let cipher = ChaCha20Poly1305::new((&*ack_key).into());
        let tag_bytes: [u8; 16] = match cipher.encrypt_in_place_detached(
            &nonce_from_seq(0),
            AAD_SETUP_HOP_ACK,
            &mut buf,
        ) {
            Ok(t) => t.into(),
            Err(_) => [0u8; 16],
        };

        let mut out = [0u8; HOP_ACK_SIZE];
        out[0..10].copy_from_slice(&buf);
        out[10..26].copy_from_slice(&tag_bytes);
        out
    }

    /// Authenticates and decrypts a 26-byte `SETUP_OK` hop trailer into `(hop_mtu, lease_ttl_ms)`.
    pub fn open_setup_hop_ack(&self, trailer: &[u8; HOP_ACK_SIZE]) -> Result<(u16, u64), CoreError> {
        let ack_key = Zeroizing::new(*blake3::keyed_hash(&self.0, LABEL_HOP_SETUP_ACK).as_bytes());
        let mut pt = [0u8; 10];
        pt.copy_from_slice(&trailer[0..10]);
        let tag = Tag::from_slice(&trailer[10..26]);

        let cipher = ChaCha20Poly1305::new((&*ack_key).into());
        cipher
            .decrypt_in_place_detached(&nonce_from_seq(0), AAD_SETUP_HOP_ACK, &mut pt, tag)
            .map_err(|_| CoreError::Authentication)?;

        let mtu = u16::from_be_bytes([pt[0], pt[1]]);
        let mut ttl_bytes = [0u8; 8];
        ttl_bytes.copy_from_slice(&pt[2..10]);
        Ok((mtu, u64::from_be_bytes(ttl_bytes)))
    }

    /// Derives the bidirectional [`ControlCipher`] for this hop (`is_initiator = true` on Origin).
    #[must_use]
    pub fn control_cipher(&self, is_initiator: bool) -> ControlCipher {
        let fwd = Zeroizing::new(*blake3::keyed_hash(&self.0, LABEL_HOP_FORWARD).as_bytes());
        let rev = Zeroizing::new(*blake3::keyed_hash(&self.0, LABEL_HOP_REVERSE).as_bytes());
        if is_initiator {
            ControlCipher::new(&fwd, &rev)
        } else {
            ControlCipher::new(&rev, &fwd)
        }
    }
}

impl fmt::Debug for HopKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HopKey([REDACTED])")
    }
}

/// Asymmetric end-to-end session keys established after Noise_IK Message 2 (Spec §4.4.5).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    tx: [u8; 32],
    rx: [u8; 32],
}

#[allow(dead_code)]
impl SessionKeys {
    #[must_use]
    pub const fn tx_key(&self) -> &[u8; 32] {
        &self.tx
    }

    #[must_use]
    pub const fn rx_key(&self) -> &[u8; 32] {
        &self.rx
    }
}

impl fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKeys([REDACTED])")
    }
}

/// Initiator side of one Noise_IK segment (held per hop and destination during setup).
pub struct Initiator {
    state: NoiseState,
    ephemeral: StaticSecret,
    static_secret: StaticSecret,
    hop_key: HopKey,
    sent_mac1: [u8; MAC_LEN],
}

impl Initiator {
    /// Builds Noise_IK Message 1 for `target_pk` bound to `tail_aad` and optional flood `cookie`.
    ///
    /// Output length is `120 + plaintext.len()` (or `136 + plaintext.len()` if `cookie` is `Some`).
    pub fn build_message1(
        local: &ScopeKeypair,
        target_pk: PublicKey,
        tail_aad: &[u8; 32],
        plaintext: &[u8],
        cookie: Option<&[u8; COOKIE_LEN]>,
    ) -> Result<(Self, Vec<u8>), CoreError> {
        let ephemeral = StaticSecret::random_from_rng(OsRng);
        let eph_pub = X25519PublicKey::from(&ephemeral).to_bytes();
        let target_x = X25519PublicKey::from(*target_pk.as_bytes());

        let mut state = NoiseState::initialize(&target_pk, tail_aad);
        state.mix_hash(&eph_pub);
        state.mix_key(ephemeral.diffie_hellman(&target_x).to_bytes())?;

        let mut enc_s = [0u8; 32];
        let tag_s = state.encrypt_into(local.public_key().as_bytes(), &mut enc_s)?;

        state.mix_key(local.diffie_hellman_raw(target_pk.as_bytes()))?;

        let mut enc_p = vec![0u8; plaintext.len()];
        let tag_p = state.encrypt_into(plaintext, &mut enc_p)?;

        let hop_key = state.derive_hop_key();

        let total_len =
            SEGMENT_OVERHEAD + plaintext.len() + if cookie.is_some() { MAC_LEN } else { 0 };
        let mut seg = Vec::with_capacity(total_len);
        seg.extend_from_slice(derive_scope_kid(&target_pk).as_bytes());
        seg.extend_from_slice(&eph_pub);
        seg.extend_from_slice(&enc_s);
        seg.extend_from_slice(&tag_s);
        seg.extend_from_slice(&enc_p);
        seg.extend_from_slice(&tag_p);

        let sent_mac1 = compute_mac1(&target_pk, &seg);
        seg.extend_from_slice(&sent_mac1);

        if let Some(c) = cookie {
            let mac2 = compute_mac2(c, &seg);
            seg.extend_from_slice(&mac2);
        }

        let init = Self {
            state,
            ephemeral,
            static_secret: local.clone_static_secret(),
            hop_key,
            sent_mac1,
        };
        Ok((init, seg))
    }

    #[must_use]
    pub const fn hop_key(&self) -> &HopKey {
        &self.hop_key
    }

    #[must_use]
    pub const fn sent_mac1(&self) -> &[u8; MAC_LEN] {
        &self.sent_mac1
    }

    #[must_use]
    pub fn into_hop_key(self) -> HopKey {
        self.hop_key
    }

    /// Non-consuming verification of Destination's 58-byte Noise_IK Message 2 reply.
    ///
    /// Used on the Datagram plane so spoofed/corrupted `SETUP_OK` packets can be silently
    /// ignored without consuming the active handshake state (Spec §6.1 Step 7).
    pub fn try_finish_message2(
        &self,
        reply: &[u8; REPLY_LEN],
    ) -> Result<(u16, u64, SessionKeys), CoreError> {
        let mut state = self.state.clone();
        let mut e_r_bytes = [0u8; 32];
        e_r_bytes.copy_from_slice(&reply[0..32]);
        let e_r = X25519PublicKey::from(e_r_bytes);

        let mut tag = [0u8; 16];
        tag.copy_from_slice(&reply[42..58]);

        state.mix_hash(&e_r_bytes);
        state.mix_key(self.ephemeral.diffie_hellman(&e_r).to_bytes())?;
        state.mix_key(self.static_secret.diffie_hellman(&e_r).to_bytes())?;

        let mut ack = [0u8; 10];
        state.decrypt_into(&reply[32..42], &tag, &mut ack)?;

        let dest_mtu = u16::from_be_bytes([ack[0], ack[1]]);
        let mut ttl_bytes = [0u8; 8];
        ttl_bytes.copy_from_slice(&ack[2..10]);
        let dest_ttl_ms = u64::from_be_bytes(ttl_bytes);
        let keys = state.split_session_keys(true);
        Ok((dest_mtu, dest_ttl_ms, keys))
    }

    /// Processes Destination's 58-byte Noise_IK Message 2 reply and derives `(dest_mtu, dest_ttl_ms, SessionKeys)`.
    pub fn finish_message2(
        self,
        reply: &[u8; REPLY_LEN],
    ) -> Result<(u16, u64, SessionKeys, HopKey), CoreError> {
        let (dest_mtu, dest_ttl_ms, keys) = self.try_finish_message2(reply)?;
        Ok((dest_mtu, dest_ttl_ms, keys, self.hop_key))
    }
}

/// Responder side of one Noise_IK segment with two-phase replay commit (Spec §4.4.2 & §4.7.1).
pub struct Responder {
    state: NoiseState,
    peer_static: PublicKey,
    peer_ephemeral: [u8; 32],
    hop_key: HopKey,
    ts_ms: u64,
    committed: bool,
}

impl Responder {
    /// Phase 1: Verifies `mac1`, checks replay without inserting (`insert = false`),
    /// decrypts Message 1, and enforces the `±30_000 ms` wall-clock freshness window.
    ///
    /// Invalid `mac1` returns [`CoreError::BadMac`] with **zero heap allocations** and
    /// **zero X25519 DH operations**.
    pub fn authenticate(
        local: &ScopeKeypair,
        replay: &SetupReplay,
        base_segment: &[u8],
        tail_aad: &[u8; 32],
        now_mono: MonotonicTime,
        now_wall_ms: u64,
    ) -> Result<(Self, Zeroizing<Vec<u8>>), CoreError> {
        // Zero-allocation pre-DH verification.
        if !local.verify_base_mac1(base_segment) {
            return Err(CoreError::BadMac);
        }

        let mut e_i = [0u8; 32];
        e_i.copy_from_slice(&base_segment[8..40]);

        // Phase 1 replay check (read-only: does NOT consume a bucket slot).
        if !replay.check(&e_i, now_mono) {
            return Err(CoreError::Replay);
        }

        let mut state = NoiseState::initialize(&local.public_key(), tail_aad);
        state.mix_hash(&e_i);
        state.mix_key(local.diffie_hellman_raw(&e_i))?;

        let mut tag_s = [0u8; 16];
        tag_s.copy_from_slice(&base_segment[72..88]);
        let mut s_i = [0u8; 32];
        state.decrypt_into(&base_segment[40..72], &tag_s, &mut s_i)?;

        state.mix_key(local.diffie_hellman_raw(&s_i))?;

        let ct_end = base_segment.len() - 32;
        let pt_len = ct_end - 88;
        let mut tag_p = [0u8; 16];
        tag_p.copy_from_slice(&base_segment[ct_end..ct_end + 16]);

        let mut plaintext = Zeroizing::new(vec![0u8; pt_len]);
        state.decrypt_into(&base_segment[88..ct_end], &tag_p, &mut plaintext)?;

        if plaintext.len() < 8 {
            return Err(CoreError::ClockSkew);
        }
        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&plaintext[0..8]);
        let ts_ms = u64::from_be_bytes(ts_bytes);
        if now_wall_ms.abs_diff(ts_ms) > SETUP_FRESHNESS_WINDOW_MS {
            return Err(CoreError::ClockSkew);
        }

        let hop_key = state.derive_hop_key();
        let responder = Self {
            state,
            peer_static: PublicKey::from_bytes(s_i),
            peer_ephemeral: e_i,
            hop_key,
            ts_ms,
            committed: false,
        };
        Ok((responder, plaintext))
    }

    #[must_use]
    pub const fn peer_static(&self) -> PublicKey {
        self.peer_static
    }

    #[must_use]
    pub const fn hop_key(&self) -> &HopKey {
        &self.hop_key
    }

    /// Phase 2: Re-checks wall-clock freshness (`±30_000 ms`) and atomically inserts `E_i` into `replay`.
    pub fn commit(
        &mut self,
        replay: &SetupReplay,
        now_mono: MonotonicTime,
        now_wall_ms: u64,
    ) -> Result<(), CoreError> {
        if self.committed {
            return Ok(());
        }
        if now_wall_ms.abs_diff(self.ts_ms) > SETUP_FRESHNESS_WINDOW_MS {
            return Err(CoreError::ClockSkew);
        }
        if !replay.insert(&self.peer_ephemeral, now_mono) {
            return Err(CoreError::Replay);
        }
        self.committed = true;
        Ok(())
    }

    /// Generates Destination's 58-byte Noise_IK Message 2 reply carrying `(dest_local_mtu, dest_ttl_ms)`.
    pub fn build_message2(
        mut self,
        dest_local_mtu: u16,
        dest_ttl_ms: u64,
    ) -> Result<([u8; REPLY_LEN], SessionKeys, HopKey), CoreError> {
        let e_r = StaticSecret::random_from_rng(OsRng);
        let e_r_pub = X25519PublicKey::from(&e_r).to_bytes();

        let e_i = X25519PublicKey::from(self.peer_ephemeral);
        let s_i = X25519PublicKey::from(*self.peer_static.as_bytes());

        self.state.mix_hash(&e_r_pub);
        self.state.mix_key(e_r.diffie_hellman(&e_i).to_bytes())?;
        self.state.mix_key(e_r.diffie_hellman(&s_i).to_bytes())?;

        let mut ack = [0u8; 10];
        ack[0..2].copy_from_slice(&dest_local_mtu.to_be_bytes());
        ack[2..10].copy_from_slice(&dest_ttl_ms.to_be_bytes());

        let mut enc_ack = [0u8; 10];
        let tag = self.state.encrypt_into(&ack, &mut enc_ack)?;

        let mut reply = [0u8; REPLY_LEN];
        reply[0..32].copy_from_slice(&e_r_pub);
        reply[32..42].copy_from_slice(&enc_ack);
        reply[42..58].copy_from_slice(&tag);

        let keys = self.state.split_session_keys(false);
        Ok((reply, keys, self.hop_key))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn sample_pt(ts_ms: u64) -> Vec<u8> {
        let mut pt = Vec::new();
        pt.extend_from_slice(&ts_ms.to_be_bytes());
        pt.push(4);
        pt.extend_from_slice(b"echo");
        pt.extend_from_slice(&0u16.to_be_bytes());
        pt
    }

    #[test]
    fn noise_ik_roundtrip_asymmetric_keys_and_aad_binding() {
        let origin = ScopeKeypair::generate();
        let dest = ScopeKeypair::generate();
        let replay = SetupReplay::new(MonotonicTime::ZERO);
        let aad = *blake3::hash(b"prefix||tail").as_bytes();
        let now_wall = 1_700_000_000_000u64;
        let pt = sample_pt(now_wall);

        let (init, seg) =
            Initiator::build_message1(&origin, dest.public_key(), &aad, &pt, None).unwrap();
        assert_eq!(seg.len(), SEGMENT_OVERHEAD + pt.len());

        // Flip 1 bit of AAD -> MUST fail with Authentication.
        let mut bad_aad = aad;
        bad_aad[0] ^= 0x01;
        assert!(matches!(
            Responder::authenticate(&dest, &replay, &seg, &bad_aad, MonotonicTime::ZERO, now_wall),
            Err(CoreError::Authentication)
        ));

        let (mut resp, dec_pt) =
            Responder::authenticate(&dest, &replay, &seg, &aad, MonotonicTime::ZERO, now_wall)
                .unwrap();
        assert_eq!(&*dec_pt, &pt);
        assert_eq!(resp.peer_static(), origin.public_key());
        resp.commit(&replay, MonotonicTime::ZERO, now_wall).unwrap();

        let (reply, resp_keys, resp_hk) = resp.build_message2(1232, 60_000).unwrap();
        let (mtu, ttl_ms, init_keys, init_hk) = init.finish_message2(&reply).unwrap();

        assert_eq!(mtu, 1232);
        assert_eq!(ttl_ms, 60_000);
        assert_eq!(init_keys.tx_key(), resp_keys.rx_key());
        assert_eq!(init_keys.rx_key(), resp_keys.tx_key());
        assert_ne!(init_keys.tx_key(), init_keys.rx_key());

        // HopKey ack and error authenticate and reject 1-bit flips.
        let mut ack = resp_hk.seal_setup_hop_ack(1200, 30_000);
        assert_eq!(init_hk.open_setup_hop_ack(&ack), Ok((1200, 30_000)));
        ack[0] ^= 0x80;
        assert_eq!(init_hk.open_setup_hop_ack(&ack), Err(CoreError::Authentication));

        let mut err = resp_hk.seal_setup_error(1, 1152);
        assert_eq!(init_hk.open_setup_error(&err), Ok((1, 1152)));
        err[10] ^= 0x01;
        assert_eq!(init_hk.open_setup_error(&err), Err(CoreError::Authentication));
    }

    #[test]
    fn all_zero_dh_output_is_rejected() {
        let origin = ScopeKeypair::generate();
        let low_order_pk = PublicKey::from_bytes([0u8; 32]);
        let aad = [0u8; 32];
        let pt = sample_pt(1_700_000_000_000);
        assert!(matches!(
            Initiator::build_message1(&origin, low_order_pk, &aad, &pt, None),
            Err(CoreError::Authentication)
        ));
    }

    #[test]
    fn freshness_boundary_exact_30000_ms() {
        let origin = ScopeKeypair::generate();
        let dest = ScopeKeypair::generate();
        let replay = SetupReplay::new(MonotonicTime::ZERO);
        let aad = [7u8; 32];
        let ts = 1_700_000_000_000u64;
        let pt = sample_pt(ts);
        let (_init, seg) =
            Initiator::build_message1(&origin, dest.public_key(), &aad, &pt, None).unwrap();

        // Exactly ±30_000 ms is accepted.
        assert!(
            Responder::authenticate(&dest, &replay, &seg, &aad, MonotonicTime::ZERO, ts + 30_000)
                .is_ok()
        );
        assert!(
            Responder::authenticate(&dest, &replay, &seg, &aad, MonotonicTime::ZERO, ts - 30_000)
                .is_ok()
        );
        // 30_001 ms fails with ClockSkew.
        assert!(matches!(
            Responder::authenticate(&dest, &replay, &seg, &aad, MonotonicTime::ZERO, ts + 30_001),
            Err(CoreError::ClockSkew)
        ));
        assert!(matches!(
            Responder::authenticate(&dest, &replay, &seg, &aad, MonotonicTime::ZERO, ts - 30_001),
            Err(CoreError::ClockSkew)
        ));
    }
}
