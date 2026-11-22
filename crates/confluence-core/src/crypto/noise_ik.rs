//! Noise IK token order with Confluence's fixed BLAKE3-based symmetric suite.
use rand_core::OsRng;
use x25519_dalek::PublicKey as XPublic;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::aead::{open, seal};
use super::{PublicKey, ScopeKeypair, mac_key, mac1, replay::SetupReplay, scope_kid};
use crate::{CoreErr, wire::e2e::CREDENTIAL_MAX, wire::u16_at, wire::u64_at};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    pub tx: [u8; 32],
    pub rx: [u8; 32],
}
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HopKey([u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct State {
    ck: [u8; 32],
    hash: [u8; 32],
    key: [u8; 32],
    nonce: u64,
}
impl State {
    fn new(target: PublicKey, aad: &[u8; 32]) -> Self {
        let initial = *blake3::hash(b"Noise_IK_25519_ChaChaPoly_BLAKE3+confluence-v1").as_bytes();
        let mut s = Self {
            ck: initial,
            hash: initial,
            key: [0; 32],
            nonce: 0,
        };
        s.mix_hash(aad);
        s.mix_hash(&target.0);
        s
    }
    fn mix_hash(&mut self, value: &[u8]) {
        let mut h = blake3::Hasher::new();
        h.update(&self.hash);
        h.update(value);
        self.hash = *h.finalize().as_bytes();
    }
    fn mix_ciphertext(&mut self, ciphertext: &[u8], tag: &[u8]) {
        let mut h = blake3::Hasher::new();
        h.update(&self.hash);
        h.update(ciphertext);
        h.update(tag);
        self.hash = *h.finalize().as_bytes();
    }
    fn mix_key(&mut self, secret: &[u8; 32]) -> Result<(), CoreErr> {
        if !bool::from(subtle::ConstantTimeEq::ct_eq(&secret[..], &[0; 32])) {
            let prk = blake3::keyed_hash(&self.ck, secret);
            self.ck = *blake3::keyed_hash(prk.as_bytes(), b"chaining key").as_bytes();
            self.key = *blake3::keyed_hash(prk.as_bytes(), b"cipher key").as_bytes();
            self.nonce = 0;
            Ok(())
        } else {
            Err(CoreErr::Authentication)
        }
    }
    fn encrypt(&mut self, data: &mut [u8]) -> [u8; 16] {
        let tag = seal(&self.key, self.nonce, &self.hash, data);
        self.nonce += 1;
        self.mix_ciphertext(data, &tag);
        tag
    }
    fn decrypt(&mut self, encrypted: &[u8], out: &mut [u8]) -> Result<(), CoreErr> {
        if encrypted.len() != out.len() + 16 {
            return Err(CoreErr::Authentication);
        }
        let (ciphertext, tag) = encrypted.split_at(out.len());
        out.copy_from_slice(ciphertext);
        open(&self.key, self.nonce, &self.hash, out, tag)?;
        self.nonce += 1;
        self.mix_ciphertext(ciphertext, tag);
        Ok(())
    }
    fn hop_key(&self) -> HopKey {
        let transcript = blake3::keyed_hash(&self.ck, &self.hash);
        HopKey(*blake3::keyed_hash(transcript.as_bytes(), b"confluence-v1 hop control").as_bytes())
    }
    fn split(&self, initiator: bool) -> SessionKeys {
        let root = blake3::keyed_hash(&self.ck, &self.hash);
        let fwd = *blake3::keyed_hash(root.as_bytes(), b"initiator to responder").as_bytes();
        let rev = *blake3::keyed_hash(root.as_bytes(), b"responder to initiator").as_bytes();
        if initiator {
            SessionKeys { tx: fwd, rx: rev }
        } else {
            SessionKeys { tx: rev, rx: fwd }
        }
    }
}

impl HopKey {
    pub fn setup_error(&self, plaintext: [u8; 4]) -> [u8; 28] {
        let mut body = [0; 28];
        body[8..12].copy_from_slice(&plaintext);
        let tag = seal(&self.0, 0, b"confluence-v1 setup error", &mut body[8..12]);
        body[12..].copy_from_slice(&tag);
        body
    }
    pub fn open_setup_error(&self, body: &[u8]) -> Result<[u8; 4], CoreErr> {
        if body.len() != 28 {
            return Err(CoreErr::Malformed);
        }
        let mut plaintext: [u8; 4] = body[8..12].try_into().unwrap();
        open(
            &self.0,
            u64_at(body, 0),
            b"confluence-v1 setup error",
            &mut plaintext,
            &body[12..],
        )?;
        Ok(plaintext)
    }
    pub fn control(&self, initiator: bool) -> super::aead::ControlCipher {
        let fwd = *blake3::keyed_hash(&self.0, b"hop forward").as_bytes();
        let rev = *blake3::keyed_hash(&self.0, b"hop reverse").as_bytes();
        if initiator {
            super::aead::ControlCipher::new(fwd, rev)
        } else {
            super::aead::ControlCipher::new(rev, fwd)
        }
    }
}

/// The initiator needs its ephemeral secret again for both ee and se. A static
/// secret generated for one use supplies the reusable X25519 operations.
pub struct Initiator {
    state: State,
    ephemeral: x25519_dalek::StaticSecret,
}
pub fn initiate(
    identity: &ScopeKeypair,
    target: PublicKey,
    aad: &[u8; 32],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Initiator), CoreErr> {
    let mut state = State::new(target, aad);
    let ephemeral = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let e = XPublic::from(&ephemeral);
    let target_public = XPublic::from(target.0);
    let mut frame = Vec::with_capacity(120 + plaintext.len());
    frame.extend_from_slice(&scope_kid(target).0);
    frame.extend_from_slice(e.as_bytes());
    state.mix_hash(e.as_bytes());

    state.mix_key(ephemeral.diffie_hellman(&target_public).as_bytes())?;
    frame.extend_from_slice(&identity.public.0);
    let tag = state.encrypt(&mut frame[40..72]);
    frame.extend_from_slice(&tag);
    state.mix_key(identity.secret.diffie_hellman(&target_public).as_bytes())?;
    frame.extend_from_slice(plaintext);
    let tag = state.encrypt(&mut frame[88..]);
    frame.extend_from_slice(&tag);
    let mac = mac1(&mac_key(target), &frame);
    frame.extend_from_slice(&mac);
    Ok((frame, Initiator { state, ephemeral }))
}
impl Initiator {
    pub fn hop_key(&self) -> HopKey {
        self.state.hop_key()
    }
    pub fn finish(
        &self,
        identity: &ScopeKeypair,
        reply: &[u8],
    ) -> Result<([u8; 18], SessionKeys), CoreErr> {
        if reply.len() != 66 {
            return Err(CoreErr::Malformed);
        }
        let ephemeral = XPublic::from(<[u8; 32]>::try_from(&reply[..32]).unwrap());
        let mut state = self.state.clone();
        state.mix_hash(ephemeral.as_bytes());
        state.mix_key(self.ephemeral.diffie_hellman(&ephemeral).as_bytes())?;
        state.mix_key(identity.secret.diffie_hellman(&ephemeral).as_bytes())?;
        let mut ack = [0; 18];
        state.decrypt(&reply[32..], &mut ack)?;
        Ok((ack, state.split(true)))
    }
}

pub struct Responder {
    state: State,
    pub peer: PublicKey,
    originator_ephemeral: XPublic,
    pub plaintext: Vec<u8>,
}
impl Responder {
    pub fn accept(
        identity: &ScopeKeypair,
        replay: &SetupReplay,
        segment: &[u8],
        aad: &[u8; 32],
        now_ms: u64,
    ) -> Result<Self, CoreErr> {
        if !identity.verify_mac1(segment) || !replay.check(&segment[8..40], false) {
            return Err(CoreErr::Authentication);
        }
        let mut state = State::new(identity.public, aad);
        let originator_ephemeral = XPublic::from(<[u8; 32]>::try_from(&segment[8..40]).unwrap());
        state.mix_hash(originator_ephemeral.as_bytes());
        state.mix_key(
            identity
                .secret
                .diffie_hellman(&originator_ephemeral)
                .as_bytes(),
        )?;
        let mut peer = [0; 32];
        state.decrypt(&segment[40..88], &mut peer)?;
        state.mix_key(
            identity
                .secret
                .diffie_hellman(&XPublic::from(peer))
                .as_bytes(),
        )?;
        let mut plaintext = vec![0; segment.len() - 120];
        state.decrypt(&segment[88..segment.len() - 16], &mut plaintext)?;

        // The timestamp is inside the authenticated ciphertext on the v1 wire.
        if plaintext.len() < 8
            || now_ms.abs_diff(u64_at(&plaintext, 0)) > 30_000
            || !replay.check(originator_ephemeral.as_bytes(), true)
        {
            return Err(CoreErr::Authentication);
        }
        Ok(Self {
            state,
            peer: PublicKey(peer),
            originator_ephemeral,
            plaintext,
        })
    }
    pub fn hop_key(&self) -> HopKey {
        self.state.hop_key()
    }
    pub fn reply(mut self, ack: &[u8; 18]) -> Result<([u8; 66], SessionKeys), CoreErr> {
        let eph = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let public = XPublic::from(&eph);
        self.state.mix_hash(public.as_bytes());
        self.state
            .mix_key(eph.diffie_hellman(&self.originator_ephemeral).as_bytes())?;
        self.state
            .mix_key(eph.diffie_hellman(&XPublic::from(self.peer.0)).as_bytes())?;
        let mut reply = [0; 66];
        reply[..32].copy_from_slice(public.as_bytes());
        reply[32..50].copy_from_slice(ack);
        let tag = self.state.encrypt(&mut reply[32..50]);
        reply[50..].copy_from_slice(&tag);
        Ok((reply, self.state.split(false)))
    }
}

pub fn hop_plaintext(
    timestamp: u64,
    credential: &[u8],
    locator: &[u8],
) -> Result<Vec<u8>, CoreErr> {
    let locator_len = u16::try_from(locator.len()).map_err(|_| CoreErr::Malformed)?;
    if credential.len() > CREDENTIAL_MAX {
        return Err(CoreErr::Malformed);
    }
    let mut data = timestamp.to_be_bytes().to_vec();
    data.extend_from_slice(&(credential.len() as u16).to_be_bytes());
    data.extend_from_slice(credential);
    data.extend_from_slice(&locator_len.to_be_bytes());
    data.extend_from_slice(locator);
    Ok(data)
}
pub fn parse_hop(data: &[u8]) -> Result<(&[u8], &[u8]), CoreErr> {
    if data.len() < 12 {
        return Err(CoreErr::Malformed);
    }
    let cred = u16_at(data, 8) as usize;
    if cred > CREDENTIAL_MAX || data.len() < 12 + cred {
        return Err(CoreErr::Malformed);
    }
    let locator = u16_at(data, 10 + cred) as usize;
    if data.len() != 12 + cred + locator {
        return Err(CoreErr::Malformed);
    }
    Ok((&data[10..10 + cred], &data[12 + cred..]))
}
pub fn endpoint_plaintext(
    timestamp: u64,
    name: &str,
    credential: &[u8],
) -> Result<Vec<u8>, CoreErr> {
    if name.is_empty() || name.len() > 255 || credential.len() > CREDENTIAL_MAX {
        return Err(CoreErr::Malformed);
    }
    let mut data = timestamp.to_be_bytes().to_vec();
    data.push(name.len() as u8);
    data.extend_from_slice(name.as_bytes());
    data.extend_from_slice(&(credential.len() as u16).to_be_bytes());
    data.extend_from_slice(credential);
    Ok(data)
}
pub fn parse_endpoint(data: &[u8]) -> Result<(&str, &[u8]), CoreErr> {
    if data.len() < 11 {
        return Err(CoreErr::Malformed);
    }
    let name = data[8] as usize;
    if name == 0 || data.len() < 11 + name {
        return Err(CoreErr::Malformed);
    }
    let cred = u16_at(data, 9 + name) as usize;
    if cred > CREDENTIAL_MAX || data.len() != 11 + name + cred {
        return Err(CoreErr::Malformed);
    }
    Ok((
        std::str::from_utf8(&data[9..9 + name]).map_err(|_| CoreErr::Malformed)?,
        &data[11 + name..],
    ))
}
