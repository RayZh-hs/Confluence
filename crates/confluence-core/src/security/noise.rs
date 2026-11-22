use crate::error::{CoreError, Result};
use crate::security::replay::ReplayWindow64;
use crate::types::{PeerId, StaticKeypair};
use blake2::{Blake2s256, Digest};
use chacha20poly1305::{
    aead::{Aead, AeadInPlace, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce, Tag,
};
use hmac::{Mac, SimpleHmac};
use parking_lot::Mutex;
use rand::rngs::OsRng;
use std::sync::atomic::{AtomicU64, Ordering};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Exact Noise protocol suite name per Noise Protocol Framework Specification (Rev 34).
pub const NOISE_PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Standard Confluence Noise prologue binding protocol version.
pub const DEFAULT_PROLOGUE: &[u8] = b"confluence-v1";

/// Maximum plaintext chunk size per Stream Plane AEAD record (16 KiB).
pub const MAX_STREAM_CHUNK_BYTES: usize = 16 * 1024;

/// AEAD authentication tag size (16 bytes for Poly1305).
pub const AEAD_TAG_BYTES: usize = 16;

/// Constant Datagram Plane wire overhead: 4B `HopLabel` + 8B `nonce` + 1B `msg_type` + 16B `tag` = 29 bytes.
pub const DATAGRAM_WIRE_OVERHEAD_BYTES: usize = 4 + 8 + 1 + AEAD_TAG_BYTES;

type HmacBlake2s = SimpleHmac<Blake2s256>;

fn blake2s_hash(data: &[u8]) -> [u8; 32] {
    let digest = Blake2s256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hmac_blake2s(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacBlake2s as Mac>::new_from_slice(key).expect("32-byte HMAC key is valid");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn hkdf2(chaining_key: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut temp_key = hmac_blake2s(chaining_key, ikm);
    let out1 = hmac_blake2s(&temp_key, &[0x01]);
    let mut in2 = [0u8; 33];
    in2[..32].copy_from_slice(&out1);
    in2[32] = 0x02;
    let out2 = hmac_blake2s(&temp_key, &in2);
    temp_key.zeroize();
    in2.zeroize();
    (out1, out2)
}

fn noise_nonce(counter: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[4..12].copy_from_slice(&counter.to_le_bytes());
    Nonce::from(bytes)
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct SymmetricState {
    ck: [u8; 32],
    h: [u8; 32],
    k: [u8; 32],
    has_key: bool,
    n: u64,
}

impl SymmetricState {
    fn initialize(protocol_name: &[u8]) -> Self {
        let h = if protocol_name.len() <= 32 {
            let mut buf = [0u8; 32];
            buf[..protocol_name.len()].copy_from_slice(protocol_name);
            buf
        } else {
            blake2s_hash(protocol_name)
        };
        Self {
            ck: h,
            h,
            k: [0u8; 32],
            has_key: false,
            n: 0,
        }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Blake2s256::new();
        hasher.update(self.h);
        hasher.update(data);
        let digest = hasher.finalize();
        self.h.copy_from_slice(&digest);
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, temp_k) = hkdf2(&self.ck, ikm);
        self.ck = ck;
        self.k = temp_k;
        self.has_key = true;
        self.n = 0;
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if !self.has_key {
            self.mix_hash(plaintext);
            return Ok(plaintext.to_vec());
        }
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.k));
        let nonce = noise_nonce(self.n);
        self.n = self.n.checked_add(1).ok_or(CoreError::AuthFailed)?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &self.h,
                },
            )
            .map_err(|_| CoreError::AuthFailed)?;
        self.mix_hash(&ciphertext);
        Ok(ciphertext)
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if !self.has_key {
            self.mix_hash(ciphertext);
            return Ok(ciphertext.to_vec());
        }
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.k));
        let nonce = noise_nonce(self.n);
        self.n = self.n.checked_add(1).ok_or(CoreError::AuthFailed)?;
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &self.h,
                },
            )
            .map_err(|_| CoreError::AuthFailed)?;
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    fn split(&self) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let (k1, k2) = hkdf2(&self.ck, &[]);
        (k1, k2, self.h)
    }
}

fn dh_secret(secret: &StaticSecret, remote_pub: &[u8; 32]) -> Result<[u8; 32]> {
    let pk = PublicKey::from(*remote_pub);
    let shared = secret.diffie_hellman(&pk).to_bytes();
    if bool::from(shared.ct_eq(&[0u8; 32])) {
        return Err(CoreError::AuthFailed);
    }
    Ok(shared)
}

/// Directional symmetric session keys produced by a completed `Noise_IK` handshake.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TransportKeys {
    pub tx_key: [u8; 32],
    pub rx_key: [u8; 32],
    pub handshake_hash: [u8; 32],
}

/// In-flight Initiator state waiting for Responder's `Noise_IK` Message 2 (`<- e, ee, se`).
pub struct InitiatorHandshake {
    sym: SymmetricState,
    local_static: StaticKeypair,
    ephemeral_secret: StaticSecret,
    remote_static: PeerId,
}

impl InitiatorHandshake {
    /// Builds `Noise_IK` Message 1 (`-> e, es, s, ss` + encrypted `payload`).
    /// Wire size is `96 + payload.len()` bytes.
    pub fn initiate(
        local_static: &StaticKeypair,
        remote_static: PeerId,
        prologue: &[u8],
        payload: &[u8],
    ) -> Result<(Self, Vec<u8>)> {
        let mut sym = SymmetricState::initialize(NOISE_PROTOCOL_NAME);
        sym.mix_hash(prologue);
        // Pre-message `<- s`
        sym.mix_hash(remote_static.as_bytes());

        // `e`
        let e_sec = StaticSecret::random_from_rng(OsRng);
        let e_pub = PublicKey::from(&e_sec).to_bytes();
        sym.mix_hash(&e_pub);

        // `es`
        let mut es = dh_secret(&e_sec, remote_static.as_bytes())?;
        sym.mix_key(&es);
        es.zeroize();

        // `s`
        let enc_s = sym.encrypt_and_hash(local_static.peer_id().as_bytes())?;

        // `ss`
        let mut ss = local_static.diffie_hellman(&remote_static)?;
        sym.mix_key(&ss);
        ss.zeroize();

        // Encrypted payload
        let enc_payload = sym.encrypt_and_hash(payload)?;

        let mut msg1 = Vec::with_capacity(32 + enc_s.len() + enc_payload.len());
        msg1.extend_from_slice(&e_pub);
        msg1.extend_from_slice(&enc_s);
        msg1.extend_from_slice(&enc_payload);

        Ok((
            Self {
                sym,
                local_static: local_static.clone(),
                ephemeral_secret: e_sec,
                remote_static,
            },
            msg1,
        ))
    }

    /// Processes Responder's `Noise_IK` Message 2 (`<- e, ee, se` + encrypted response payload)
    /// and splits into `(TransportKeys, decrypted_resp_payload)`.
    pub fn finalize(mut self, msg2: &[u8]) -> Result<(TransportKeys, Vec<u8>)> {
        if msg2.len() < 32 + AEAD_TAG_BYTES {
            return Err(CoreError::AuthFailed);
        }
        let mut re_pub = [0u8; 32];
        re_pub.copy_from_slice(&msg2[..32]);

        // `e`
        self.sym.mix_hash(&re_pub);

        // `ee`
        let mut ee = dh_secret(&self.ephemeral_secret, &re_pub)?;
        self.sym.mix_key(&ee);
        ee.zeroize();

        // `se`
        let mut se = self.local_static.diffie_hellman(&PeerId(re_pub))?;
        self.sym.mix_key(&se);
        se.zeroize();

        // Decrypt response payload
        let resp_payload = self.sym.decrypt_and_hash(&msg2[32..])?;
        let (tx_key, rx_key, handshake_hash) = self.sym.split();

        Ok((
            TransportKeys {
                tx_key,
                rx_key,
                handshake_hash,
            },
            resp_payload,
        ))
    }

    pub fn remote_peer(&self) -> PeerId {
        self.remote_static
    }
}

/// Responder state after authenticating `Noise_IK` Message 1 (`-> e, es, s, ss`),
/// allowing the caller to inspect `(initiator_peer_id, decrypted_payload)` and check
/// replay/ACL BEFORE generating Message 2!
pub struct VerifiedInitiation {
    sym: SymmetricState,
    initiator_peer: PeerId,
    initiator_ephemeral: [u8; 32],
    payload: Vec<u8>,
}

impl VerifiedInitiation {
    /// Verifies and decrypts `Noise_IK` Message 1 (`-> e, es, s, ss`).
    pub fn read_msg1(
        responder_static: &StaticKeypair,
        prologue: &[u8],
        msg1: &[u8],
    ) -> Result<Self> {
        // 32B `e` + 48B encrypted `s` + at least 16B payload AEAD tag = 96 bytes minimum.
        if msg1.len() < 96 {
            return Err(CoreError::AuthFailed);
        }

        let mut sym = SymmetricState::initialize(NOISE_PROTOCOL_NAME);
        sym.mix_hash(prologue);
        // Pre-message `<- s`
        sym.mix_hash(responder_static.peer_id().as_bytes());

        // `e`
        let mut ie_pub = [0u8; 32];
        ie_pub.copy_from_slice(&msg1[..32]);
        sym.mix_hash(&ie_pub);

        // `es`
        let mut es = responder_static.diffie_hellman(&PeerId(ie_pub))?;
        sym.mix_key(&es);
        es.zeroize();

        // `s`
        let is_bytes = sym.decrypt_and_hash(&msg1[32..80])?;
        let is_arr: [u8; 32] = is_bytes
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::AuthFailed)?;
        let initiator_peer = PeerId(is_arr);

        // `ss`
        let mut ss = responder_static.diffie_hellman(&initiator_peer)?;
        sym.mix_key(&ss);
        ss.zeroize();

        // Payload
        let payload = sym.decrypt_and_hash(&msg1[80..])?;

        Ok(Self {
            sym,
            initiator_peer,
            initiator_ephemeral: ie_pub,
            payload,
        })
    }

    /// Cryptographically verified static `PeerId` of the initiator.
    pub fn initiator_peer(&self) -> PeerId {
        self.initiator_peer
    }

    /// Decrypted handshake payload from Message 1.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Completes the Responder side of `Noise_IK` (`<- e, ee, se` + encrypted `resp_payload`),
    /// returning `(TransportKeys, msg2_bytes)`.
    pub fn respond(mut self, resp_payload: &[u8]) -> Result<(TransportKeys, Vec<u8>)> {
        let re_sec = StaticSecret::random_from_rng(OsRng);
        let re_pub = PublicKey::from(&re_sec).to_bytes();

        // `e`
        self.sym.mix_hash(&re_pub);

        // `ee`
        let mut ee = dh_secret(&re_sec, &self.initiator_ephemeral)?;
        self.sym.mix_key(&ee);
        ee.zeroize();

        // `se`
        let mut se = dh_secret(&re_sec, self.initiator_peer.as_bytes())?;
        self.sym.mix_key(&se);
        se.zeroize();

        let enc_resp = self.sym.encrypt_and_hash(resp_payload)?;
        // Note: Noise Split() returns `(k_initiator_to_responder, k_responder_to_initiator)`.
        let (rx_key, tx_key, handshake_hash) = self.sym.split();

        let mut msg2 = Vec::with_capacity(32 + enc_resp.len());
        msg2.extend_from_slice(&re_pub);
        msg2.extend_from_slice(&enc_resp);

        Ok((
            TransportKeys {
                tx_key,
                rx_key,
                handshake_hash,
            },
            msg2,
        ))
    }
}

/// Thread-safe AEAD cipher for a Datagram Plane E2E session.
///
/// Wire body after 4B `HopLabel`:
/// `[ nonce: 8B BE ][ ChaCha20Poly1305(msg_type: 1B || payload) ][ tag: 16B ]`
/// Total wire overhead including 4B `HopLabel` = **29 bytes**.
pub struct DatagramSessionCipher {
    tx_cipher: ChaCha20Poly1305,
    rx_cipher: ChaCha20Poly1305,
    tx_nonce: AtomicU64,
    rx_window: Mutex<ReplayWindow64>,
    handshake_hash: [u8; 32],
}

impl DatagramSessionCipher {
    pub fn new(keys: TransportKeys) -> Self {
        Self {
            tx_cipher: ChaCha20Poly1305::new(Key::from_slice(&keys.tx_key)),
            rx_cipher: ChaCha20Poly1305::new(Key::from_slice(&keys.rx_key)),
            tx_nonce: AtomicU64::new(0),
            rx_window: Mutex::new(ReplayWindow64::new()),
            handshake_hash: keys.handshake_hash,
        }
    }

    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }

    /// Seals `(msg_type, payload)` prefixed with `hop_label` (4B) into a single flat wire datagram.
    pub fn seal_packet(&self, hop_label: u32, msg_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let nonce_val = self.tx_nonce.fetch_add(1, Ordering::Relaxed);
        if nonce_val == u64::MAX {
            return Err(CoreError::Closed("datagram nonce space exhausted".into()));
        }

        let mut out = Vec::with_capacity(DATAGRAM_WIRE_OVERHEAD_BYTES + payload.len());
        out.extend_from_slice(&hop_label.to_be_bytes());
        out.extend_from_slice(&nonce_val.to_be_bytes());
        let body_start = out.len();
        out.push(msg_type);
        out.extend_from_slice(payload);

        let tag = self
            .tx_cipher
            .encrypt_in_place_detached(&noise_nonce(nonce_val), &[], &mut out[body_start..])
            .map_err(|_| CoreError::AuthFailed)?;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Verifies anti-replay window + AEAD tag on `packet_after_label` (`[nonce: 8B][ciphertext][tag: 16B]`),
    /// returning `(msg_type, plaintext)` without advancing the window if AEAD authentication fails.
    pub fn open_packet(&self, packet_after_label: &[u8]) -> Result<(u8, Vec<u8>)> {
        // Minimum: 8B nonce + 1B msg_type + 16B tag = 25 bytes.
        if packet_after_label.len() < 8 + 1 + AEAD_TAG_BYTES {
            return Err(CoreError::Framing("datagram too short".into()));
        }

        let nonce_val = u64::from_be_bytes(
            packet_after_label[..8]
                .try_into()
                .expect("8-byte slice length checked"),
        );

        // Pre-check replay window BEFORE AEAD decryption (read-only check).
        if !self.rx_window.lock().check_possible(nonce_val) {
            return Err(CoreError::ReplayDetected);
        }

        let tag_offset = packet_after_label.len() - AEAD_TAG_BYTES;
        let mut body = packet_after_label[8..tag_offset].to_vec();
        let tag = Tag::from_slice(&packet_after_label[tag_offset..]);

        self.rx_cipher
            .decrypt_in_place_detached(&noise_nonce(nonce_val), &[], &mut body, tag)
            .map_err(|_| CoreError::AuthFailed)?;

        // Commit nonce to sliding window atomically (handles concurrent packet races safely).
        if !self.rx_window.lock().accept(nonce_val) {
            return Err(CoreError::ReplayDetected);
        }

        let msg_type = body[0];
        let plaintext = body[1..].to_vec();
        Ok((msg_type, plaintext))
    }
}

/// Ordered outbound frame encryptor for a Stream Plane E2E session.
pub struct StreamWriteCipher {
    cipher: ChaCha20Poly1305,
    nonce: u64,
}

/// Ordered inbound frame decryptor for a Stream Plane E2E session.
pub struct StreamReadCipher {
    cipher: ChaCha20Poly1305,
    nonce: u64,
}

/// Splits `TransportKeys` into `(StreamWriteCipher, StreamReadCipher)`.
pub fn split_stream_ciphers(keys: &TransportKeys) -> (StreamWriteCipher, StreamReadCipher) {
    (
        StreamWriteCipher {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&keys.tx_key)),
            nonce: 0,
        },
        StreamReadCipher {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&keys.rx_key)),
            nonce: 0,
        },
    )
}

impl StreamWriteCipher {
    /// Seals `(msg_type, payload)` into `[cipher_len: 2B BE][AEAD(msg_type || payload)][tag: 16B]`.
    pub fn seal_record(&mut self, msg_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() > MAX_STREAM_CHUNK_BYTES {
            return Err(CoreError::Framing(format!(
                "stream chunk {} exceeds max {}",
                payload.len(),
                MAX_STREAM_CHUNK_BYTES
            )));
        }
        let nonce_val = self.nonce;
        self.nonce = self
            .nonce
            .checked_add(1)
            .ok_or_else(|| CoreError::Closed("stream nonce space exhausted".into()))?;

        let cipher_len = 1 + payload.len() + AEAD_TAG_BYTES;
        let cipher_len_u16 = u16::try_from(cipher_len)
            .map_err(|_| CoreError::Framing("stream frame exceeds u16 length".into()))?;

        let mut out = Vec::with_capacity(2 + cipher_len);
        out.extend_from_slice(&cipher_len_u16.to_be_bytes());
        out.push(msg_type);
        out.extend_from_slice(payload);

        let tag = self
            .cipher
            .encrypt_in_place_detached(&noise_nonce(nonce_val), &[], &mut out[2..])
            .map_err(|_| CoreError::AuthFailed)?;
        out.extend_from_slice(&tag);
        Ok(out)
    }
}

impl StreamReadCipher {
    /// Opens an encrypted frame body (after the 2-byte `cipher_len` prefix), verifying strict monotonic order.
    pub fn open_record(&mut self, frame_body: &[u8]) -> Result<(u8, Vec<u8>)> {
        if frame_body.len() < 1 + AEAD_TAG_BYTES
            || frame_body.len() > 1 + MAX_STREAM_CHUNK_BYTES + AEAD_TAG_BYTES
        {
            return Err(CoreError::Framing("invalid stream record length".into()));
        }

        let nonce_val = self.nonce;
        self.nonce = self
            .nonce
            .checked_add(1)
            .ok_or_else(|| CoreError::Closed("stream nonce space exhausted".into()))?;

        let tag_offset = frame_body.len() - AEAD_TAG_BYTES;
        let mut body = frame_body[..tag_offset].to_vec();
        let tag = Tag::from_slice(&frame_body[tag_offset..]);

        self.cipher
            .decrypt_in_place_detached(&noise_nonce(nonce_val), &[], &mut body, tag)
            .map_err(|_| CoreError::AuthFailed)?;

        let msg_type = body[0];
        let plaintext = body[1..].to_vec();
        Ok((msg_type, plaintext))
    }
}
