//! Back-to-front setup flight builder, responder/hop rewriters, and stack-only datagram precheck (Spec §5.2–5.5, §6.1–6.2, §8.2.3).

use core::time::Duration;
use std::collections::HashMap;

use zeroize::Zeroizing;

use crate::constants::{
    COOKIE_LEN, COOKIE_SIZE, ERR_SIZE, FRAG_HEADER, FWD_HEADER, HOP_ACK_SIZE, MAC_LEN, MAX_HOPS,
    MAX_SEGMENT, MAX_SETUP, MAX_WIRE_LEASE_TTL_MS, MIN_WIRE_LEASE_TTL_MS, OK_SIZE,
    SEGMENT_OVERHEAD, STREAM_CHUNK,
};
use crate::crypto::cookie::unseal_cookie_challenge;
use crate::crypto::identity::ScopeKeypair;
use crate::crypto::noise::{HopKey, Initiator, SessionKeys};
use crate::error::CoreError;
use crate::types::{Cid, Plane, PublicKey, ScopeKid};
use crate::wire::opcodes::{decode_wire_error, outer};
use crate::wire::setup::{
    DispatchPrefix, ForwardHeader, LeadingSegment, ParsedSegment, SetupCookieFrame, SetupErrFrame,
    SetupFragHeader, SetupOkHeader, SetupPlaintext,
};

/// Computes the normative route-integrity AAD: `BLAKE3_hash(dispatch_prefix || tail)` (Spec §5.2).
#[must_use]
pub fn compute_tail_aad(prefix_bytes: &[u8], tail: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prefix_bytes);
    hasher.update(tail);
    *hasher.finalize().as_bytes()
}

/// Validates a wire millisecond lease TTL (`1 ms ..= 24 h`).
///
/// `0` returns [`CoreError::Malformed`]; values `> 24 h` return [`CoreError::Denied`].
pub const fn validate_wire_ttl_ms(ttl_ms: u64) -> Result<Duration, CoreError> {
    if ttl_ms < MIN_WIRE_LEASE_TTL_MS {
        return Err(CoreError::Malformed);
    }
    if ttl_ms > MAX_WIRE_LEASE_TTL_MS {
        return Err(CoreError::Denied);
    }
    Ok(Duration::from_millis(ttl_ms))
}

/// One intermediate hop entry passed to [`SetupFlightBuilder::build`].
pub struct HopFlightInput<'a> {
    pub peer: PublicKey,
    pub target: &'a str,
    pub credential: &'a [u8],
}

/// Inputs required to construct a complete nested `SETUP_FWD` flight.
pub struct SetupFlightParams<'a> {
    pub local: &'a ScopeKeypair,
    pub plane: Plane,
    pub origin_local_mtu: u16,
    pub min_mtu: u16,
    pub upstream_cid: Cid,
    pub destination: PublicKey,
    pub endpoint: &'a str,
    pub dest_credential: &'a [u8],
    pub hops: &'a [HopFlightInput<'a>],
    pub cookies: &'a HashMap<usize, Zeroizing<[u8; COOKIE_LEN]>>,
    pub wall_time_ms: u64,
}

struct HopInitSlot {
    peer: PublicKey,
    initiator: Initiator,
}

/// Pure back-to-front builder for nested `SETUP_FWD` flights (Spec §5.2).
pub struct SetupFlightBuilder;

impl SetupFlightBuilder {
    /// Builds a nested `SETUP_FWD` wire flight back-to-front (Destination first, then `H_{N-1}..H_0`)
    /// using one shared `wall_time_ms` timestamp across all segments.
    pub fn build(params: &SetupFlightParams<'_>) -> Result<(OriginSetupState, Vec<u8>), CoreError> {
        let hop_count = params.hops.len();
        if hop_count > MAX_HOPS {
            return Err(CoreError::InvalidParameter);
        }
        match params.plane {
            Plane::Stream if !params.upstream_cid.is_unbound() => {
                return Err(CoreError::InvalidParameter);
            }
            Plane::Datagram if params.upstream_cid.is_unbound() => {
                return Err(CoreError::InvalidParameter);
            }
            _ => {}
        }

        // Step 1: Build destination segment (node index = N).
        let dest_pt = SetupPlaintext::encode(
            params.wall_time_ms,
            params.endpoint,
            params.dest_credential,
        )?;
        let dest_cookie = params.cookies.get(&hop_count);
        let dest_has_mac2 = dest_cookie.is_some();
        let dest_seg_len = SEGMENT_OVERHEAD
            + dest_pt.len()
            + if dest_has_mac2 { MAC_LEN } else { 0 };
        let dest_prefix = DispatchPrefix {
            is_hop: false,
            has_mac2: dest_has_mac2,
            plane: params.plane,
            min_mtu: params.min_mtu,
            seg_len: u16::try_from(dest_seg_len).map_err(|_| CoreError::Malformed)?,
            tail_len: 0,
        };
        let mut prefix_buf = [0u8; 8];
        let dest_prefix_len = dest_prefix.encode(&mut prefix_buf);
        let dest_aad = compute_tail_aad(&prefix_buf[..dest_prefix_len], &[]);
        let (dest_init, dest_seg) = Initiator::build_message1(
            params.local,
            params.destination,
            &dest_aad,
            &dest_pt,
            dest_cookie.map(|c| &**c),
        )?;

        let mut chain = Vec::with_capacity(dest_prefix_len + dest_seg.len());
        chain.extend_from_slice(&prefix_buf[..dest_prefix_len]);
        chain.extend_from_slice(&dest_seg);

        // Step 2: Wrap intermediate hops back-to-front (H_{N-1} down to H_0).
        let mut rev_hops: Vec<HopInitSlot> = Vec::with_capacity(hop_count);
        for i in (0..hop_count).rev() {
            let hop = &params.hops[i];
            let hop_pt =
                SetupPlaintext::encode(params.wall_time_ms, hop.target, hop.credential)?;
            let hop_cookie = params.cookies.get(&i);
            let hop_has_mac2 = hop_cookie.is_some();
            let hop_seg_len = SEGMENT_OVERHEAD
                + hop_pt.len()
                + if hop_has_mac2 { MAC_LEN } else { 0 };
            let tail_len = u16::try_from(chain.len()).map_err(|_| CoreError::Malformed)?;
            let hop_prefix = DispatchPrefix {
                is_hop: true,
                has_mac2: hop_has_mac2,
                plane: params.plane,
                min_mtu: params.min_mtu,
                seg_len: u16::try_from(hop_seg_len).map_err(|_| CoreError::Malformed)?,
                tail_len,
            };
            let hop_prefix_len = hop_prefix.encode(&mut prefix_buf);
            let hop_aad = compute_tail_aad(&prefix_buf[..hop_prefix_len], &chain);
            let (hop_init, hop_seg) = Initiator::build_message1(
                params.local,
                hop.peer,
                &hop_aad,
                &hop_pt,
                hop_cookie.map(|c| &**c),
            )?;

            let mut wrapped = Vec::with_capacity(hop_prefix_len + hop_seg.len() + chain.len());
            wrapped.extend_from_slice(&prefix_buf[..hop_prefix_len]);
            wrapped.extend_from_slice(&hop_seg);
            wrapped.extend_from_slice(&chain);
            chain = wrapped;

            rev_hops.push(HopInitSlot {
                peer: hop.peer,
                initiator: hop_init,
            });
        }
        rev_hops.reverse();

        // Step 3: Prepend ForwardHeader and check plane framing limits.
        let total_wire = FWD_HEADER + chain.len();
        match params.plane {
            Plane::Stream if total_wire > STREAM_CHUNK => {
                return Err(CoreError::MessageTooLarge(STREAM_CHUNK));
            }
            Plane::Datagram if total_wire > MAX_SETUP => {
                return Err(CoreError::MessageTooLarge(MAX_SETUP));
            }
            _ => {}
        }

        let hdr = ForwardHeader {
            max_mtu: params.origin_local_mtu,
            upstream: params.upstream_cid,
        };
        let mut wire = Vec::with_capacity(total_wire);
        wire.extend_from_slice(&hdr.encode());
        wire.extend_from_slice(&chain);

        let state = OriginSetupState {
            plane: params.plane,
            origin_local_mtu: params.origin_local_mtu,
            min_mtu: params.min_mtu,
            destination: params.destination,
            dest_init,
            hops: rev_hops,
        };
        Ok((state, wire))
    }
}

/// Authenticated cryptographic and MTU results produced by [`OriginSetupState::finish_setup_ok`].
#[allow(dead_code)]
pub struct OriginEstablished {
    pub session_keys: SessionKeys,
    pub terminal_hop_key: HopKey,
    pub hop_keys: Vec<HopKey>,
    pub dest_ttl: Duration,
    pub hop_ttls: Vec<Duration>,
    /// Authenticated per-leg wire MTUs `[origin_local_mtu, hop_0..hop_{N-1}, dest_local_mtu]`.
    pub legs: Vec<u16>,
    /// Authenticated minimum path MTU (`min(legs)`, ignoring cleartext `reverse_mtu`).
    pub path_mtu: u16,
    pub responder_cid: Cid,
}

/// Originator per-attempt setup cryptographic state awaiting `SETUP_OK`, `SETUP_ERR`, or `SETUP_COOKIE`.
#[allow(dead_code)]
pub struct OriginSetupState {
    plane: Plane,
    origin_local_mtu: u16,
    min_mtu: u16,
    destination: PublicKey,
    dest_init: Initiator,
    hops: Vec<HopInitSlot>,
}

#[allow(dead_code)]
impl OriginSetupState {
    #[must_use]
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// Decrypts and classifies a received `SETUP_ERR` frame (Spec §5.4).
    ///
    /// Returns `Ok(decoded_error)` if authentic (wrapping hop errors in `HopRejected`),
    /// or `Err(CoreError::Authentication | CoreError::Malformed)` if unauthentic or invalid.
    pub fn open_setup_err(&self, frame: &SetupErrFrame) -> Result<CoreError, CoreError> {
        let dist = usize::from(frame.distance);
        let n = self.hops.len();
        if dist > n {
            return Err(CoreError::Authentication);
        }
        let hop_key = if dist == n {
            self.dest_init.hop_key()
        } else {
            self.hops[dist].initiator.hop_key()
        };
        let (code, arg) = hop_key.open_setup_error(&frame.body)?;
        let err = decode_wire_error(code, arg)?;
        if dist == n {
            Ok(err)
        } else {
            Ok(CoreError::hop_rejected(frame.distance, err))
        }
    }

    /// Unseals a received `SETUP_COOKIE` challenge, returning `(node_index, cookie)` (Spec §4.8.4 & §5.5).
    pub fn unseal_setup_cookie(
        &self,
        frame: &SetupCookieFrame,
    ) -> Result<(usize, Zeroizing<[u8; COOKIE_LEN]>), CoreError> {
        let dist = usize::from(frame.distance);
        let n = self.hops.len();
        if dist > n {
            return Err(CoreError::Authentication);
        }
        let (target_pk, sent_mac1) = if dist == n {
            (self.destination, self.dest_init.sent_mac1())
        } else {
            (self.hops[dist].peer, self.hops[dist].initiator.sent_mac1())
        };
        let cookie = unseal_cookie_challenge(&target_pk, sent_mac1, &frame.challenge)?;
        Ok((dist, cookie))
    }

    /// Verifies `SETUP_OK`, decrypts Noise Message 2 + all reverse-ordered 26-byte hop trailers,
    /// validates every TTL (`1 ms..=24 h`), and computes authenticated `path_mtu` ignoring cleartext
    /// `reverse_mtu` (Spec §5.3).
    pub fn finish_setup_ok(self, wire: &[u8]) -> Result<OriginEstablished, CoreError> {
        let (hdr, reply, trailers) = SetupOkHeader::parse(wire)?;
        match self.plane {
            Plane::Stream => {
                if !hdr.target_cid.is_unbound()
                    || !hdr.responder_cid.is_unbound()
                    || wire.len() > STREAM_CHUNK
                {
                    return Err(CoreError::Malformed);
                }
            }
            Plane::Datagram => {
                if hdr.target_cid.is_unbound() || hdr.responder_cid.is_unbound() {
                    return Err(CoreError::Malformed);
                }
            }
        }

        let n = self.hops.len();
        if usize::from(hdr.hop_acks) != n {
            return Err(CoreError::Authentication);
        }

        let (dest_local_mtu, dest_ttl_ms, session_keys, terminal_hop_key) =
            self.dest_init.finish_message2(reply)?;
        let dest_ttl = validate_wire_ttl_ms(dest_ttl_ms)?;

        let mut legs = Vec::with_capacity(n + 2);
        legs.push(self.origin_local_mtu);

        let mut hop_keys = Vec::with_capacity(n);
        let mut hop_ttls = Vec::with_capacity(n);

        // Hop trailers were appended in reverse order (H_{N-1} first at offset 0, H_0 last).
        for (i, slot) in self.hops.into_iter().enumerate() {
            let offset = (n - 1 - i) * HOP_ACK_SIZE;
            let trailer: &[u8; HOP_ACK_SIZE] = trailers[offset..offset + HOP_ACK_SIZE]
                .try_into()
                .map_err(|_| CoreError::Malformed)?;
            let hop_key = slot.initiator.into_hop_key();
            let (hop_mtu, hop_ttl_ms) = hop_key.open_setup_hop_ack(trailer)?;
            let hop_ttl = validate_wire_ttl_ms(hop_ttl_ms)?;
            legs.push(hop_mtu);
            hop_ttls.push(hop_ttl);
            hop_keys.push(hop_key);
        }
        legs.push(dest_local_mtu);

        // Derive path MTU exclusively from authenticated per-leg values (NEVER cleartext reverse_mtu).
        let path_mtu = legs.iter().copied().min().unwrap_or(0);
        if path_mtu < self.min_mtu {
            return Err(CoreError::MtuTooSmall(path_mtu));
        }

        Ok(OriginEstablished {
            session_keys,
            terminal_hop_key,
            hop_keys,
            dest_ttl,
            hop_ttls,
            legs,
            path_mtu,
            responder_cid: hdr.responder_cid,
        })
    }
}

/// Parameters for [`HopSetupRewrite::rewrite_ok`].
#[allow(dead_code)]
pub struct HopOkRewriteParams<'a> {
    pub plane: Plane,
    pub expected_right_cid: Cid,
    pub inbound_upstream_cid: Cid,
    pub left_binding_cid: Cid,
    pub physical_mtu: u16,
    pub hop_lease_ttl_ms: u64,
    pub hop_key: &'a HopKey,
    pub max_wire_len: usize,
}

/// Pure transit-hop rewrite operations for `SETUP_FWD`, `SETUP_OK`, `SETUP_ERR`, and `SETUP_COOKIE`.
#[allow(dead_code)]
pub struct HopSetupRewrite;

#[allow(dead_code)]
impl HopSetupRewrite {
    /// Builds the downstream `SETUP_FWD` flight by prepending a clamped `ForwardHeader` onto `tail`.
    #[must_use]
    pub fn rewrite_forward(
        incoming_max_mtu: u16,
        inbound_mtu: u16,
        outbound_mtu: u16,
        outbound_cid: Cid,
        tail: &[u8],
    ) -> Vec<u8> {
        let max_mtu = incoming_max_mtu.min(inbound_mtu).min(outbound_mtu);
        let hdr = ForwardHeader {
            max_mtu,
            upstream: outbound_cid,
        };
        let mut out = Vec::with_capacity(FWD_HEADER + tail.len());
        out.extend_from_slice(&hdr.encode());
        out.extend_from_slice(tail);
        out
    }

    /// Mutates a downstream `SETUP_OK` in place: validates CIDs, increments `hop_acks`, clamps
    /// `reverse_mtu`, rewrites CIDs, checks `max_wire_len`, and appends the 26-byte authenticated
    /// hop ack trailer. Returns the downstream `next_cid` (Datagram) or `Cid::UNBOUND` (Stream).
    pub fn rewrite_ok(wire: &mut Vec<u8>, p: &HopOkRewriteParams<'_>) -> Result<Cid, CoreError> {
        let (hdr, _reply, _trailers) = SetupOkHeader::parse(wire)?;
        match p.plane {
            Plane::Stream => {
                if !hdr.target_cid.is_unbound() || !hdr.responder_cid.is_unbound() {
                    return Err(CoreError::Malformed);
                }
            }
            Plane::Datagram => {
                if hdr.target_cid != p.expected_right_cid || hdr.responder_cid.is_unbound() {
                    return Err(CoreError::Malformed);
                }
            }
        }

        let next_cid = hdr.responder_cid;
        let new_hop_acks = hdr.hop_acks.checked_add(1).ok_or(CoreError::Malformed)?;
        if wire.len() + HOP_ACK_SIZE > p.max_wire_len {
            return match p.plane {
                Plane::Datagram => Err(CoreError::MtuTooSmall(p.physical_mtu)),
                Plane::Stream => Err(CoreError::Malformed),
            };
        }

        let updated = SetupOkHeader {
            hop_acks: new_hop_acks,
            reverse_mtu: hdr.reverse_mtu.min(p.physical_mtu),
            target_cid: p.inbound_upstream_cid,
            responder_cid: p.left_binding_cid,
        };
        updated.write_into(wire)?;

        let trailer = p
            .hop_key
            .seal_setup_hop_ack(p.physical_mtu, p.hop_lease_ttl_ms);
        wire.extend_from_slice(&trailer);
        debug_assert_eq!(wire.len(), OK_SIZE + HOP_ACK_SIZE * usize::from(new_hop_acks));
        Ok(next_cid)
    }

    /// Increments `distance` and rewrites `target_cid` on an upstream-bound `SETUP_ERR` frame.
    pub fn rewrite_err(
        frame: &SetupErrFrame,
        new_target_cid: Cid,
    ) -> Result<[u8; ERR_SIZE], CoreError> {
        let distance = frame.distance.checked_add(1).ok_or(CoreError::Malformed)?;
        Ok(SetupErrFrame {
            distance,
            target_cid: new_target_cid,
            body: frame.body,
        }
        .encode())
    }

    /// Increments `distance` and rewrites `target_cid` on an upstream-bound `SETUP_COOKIE` frame.
    pub fn rewrite_cookie(
        frame: &SetupCookieFrame,
        new_target_cid: Cid,
    ) -> Result<[u8; COOKIE_SIZE], CoreError> {
        let distance = frame.distance.checked_add(1).ok_or(CoreError::Malformed)?;
        Ok(SetupCookieFrame {
            distance,
            target_cid: new_target_cid,
            challenge: frame.challenge,
        }
        .encode())
    }
}

/// Stack-only, zero-allocation datagram setup precheck (Spec §8.2.3 & §5.6).
///
/// Validates both unfragmented `SETUP_FWD` (`0x11`) and fragment 0 of `SETUP_FRAG` (`0x15`)
/// before delegating `(ScopeKid, encrypted_segment, has_mac2)` to `verify_scope`.
#[must_use]
pub fn precheck_datagram_setup_frame(
    wire: &[u8],
    verify_scope: impl FnOnce(ScopeKid, &[u8], bool) -> bool,
) -> bool {
    let Some(&op) = wire.first() else {
        return false;
    };
    match op {
        outer::SETUP_FWD => {
            let Ok(hdr) = ForwardHeader::parse(wire) else {
                return false;
            };
            if hdr.upstream.is_unbound() {
                return false;
            }
            let Ok(seg) = ParsedSegment::parse_full(&wire[FWD_HEADER..]) else {
                return false;
            };
            if seg.prefix.plane != Plane::Datagram || seg.encrypted.len() > MAX_SEGMENT {
                return false;
            }
            verify_scope(seg.scope_kid(), seg.encrypted, seg.prefix.has_mac2)
        }
        outer::SETUP_FRAG => {
            let Ok((frag, payload)) = SetupFragHeader::parse(wire) else {
                return false;
            };
            if frag.index != 0 {
                return false;
            }
            let Ok(hdr) = ForwardHeader::parse(payload) else {
                return false;
            };
            if hdr.upstream != frag.upstream_cid {
                return false;
            }
            let Ok(seg) = LeadingSegment::parse_leading(&payload[FWD_HEADER..]) else {
                return false;
            };
            if seg.prefix.plane != Plane::Datagram || seg.encrypted.len() > MAX_SEGMENT {
                return false;
            }
            let total = FWD_HEADER + seg.prefix.encoded_total_len();
            if total <= payload.len() + FRAG_HEADER
                || total.div_ceil(payload.len()) != usize::from(frag.count)
            {
                return false;
            }
            verify_scope(seg.scope_kid(), seg.encrypted, seg.prefix.has_mac2)
        }
        _ => false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::noise::Responder;
    use crate::crypto::replay::SetupReplay;
    use crate::runtime::MonotonicTime;

    #[test]
    fn multihop_setup_flight_ignores_spoofed_reverse_mtu_and_verifies_tail_aad() {
        let origin = ScopeKeypair::generate();
        let hop0 = ScopeKeypair::generate();
        let hop1 = ScopeKeypair::generate();
        let dest = ScopeKeypair::generate();
        let now_mono = MonotonicTime::ZERO;
        let now_wall = 1_700_000_000_000u64;

        let replay0 = SetupReplay::new(now_mono);
        let replay1 = SetupReplay::new(now_mono);
        let replay_d = SetupReplay::new(now_mono);

        let cid_a = Cid::from_parts(1, 1).unwrap();
        let cid_h0_r = Cid::from_parts(1, 2).unwrap();
        let cid_h0_l = Cid::from_parts(1, 3).unwrap();
        let cid_h1_r = Cid::from_parts(1, 4).unwrap();
        let cid_h1_l = Cid::from_parts(1, 5).unwrap();
        let cid_b = Cid::from_parts(1, 6).unwrap();

        let cookies = HashMap::new();
        let hops = [
            HopFlightInput {
                peer: hop0.public_key(),
                target: "to-h1",
                credential: b"c0",
            },
            HopFlightInput {
                peer: hop1.public_key(),
                target: "to-b",
                credential: b"c1",
            },
        ];

        let (origin_state, flight0) = SetupFlightBuilder::build(&SetupFlightParams {
            local: &origin,
            plane: Plane::Datagram,
            origin_local_mtu: 1400,
            min_mtu: 1152,
            upstream_cid: cid_a,
            destination: dest.public_key(),
            endpoint: "echo",
            dest_credential: b"cd",
            hops: &hops,
            cookies: &cookies,
            wall_time_ms: now_wall,
        })
        .unwrap();

        // Precheck accepts flight0 for hop0 and rejects for dest.
        assert!(precheck_datagram_setup_frame(&flight0, |kid, seg, mac2| {
            kid == hop0.scope_kid() && hop0.verify_segment_mac1(seg, mac2).is_ok()
        }));
        assert!(!precheck_datagram_setup_frame(&flight0, |kid, seg, mac2| {
            kid == dest.scope_kid() && dest.verify_segment_mac1(seg, mac2).is_ok()
        }));

        // Hop 0 authenticates and verifies tail_aad (flip 1 bit of tail -> fails!).
        let hdr0 = ForwardHeader::parse(&flight0).unwrap();
        let seg0 = ParsedSegment::parse_full(&flight0[FWD_HEADER..]).unwrap();
        let aad0 = compute_tail_aad(seg0.prefix_bytes, seg0.tail);
        let mut bad_tail = seg0.tail.to_vec();
        bad_tail[0] ^= 0x01;
        let bad_aad0 = compute_tail_aad(seg0.prefix_bytes, &bad_tail);
        assert!(matches!(
            Responder::authenticate(&hop0, &replay0, seg0.encrypted, &bad_aad0, now_mono, now_wall),
            Err(CoreError::Authentication)
        ));

        let (mut r0, pt0) =
            Responder::authenticate(&hop0, &replay0, seg0.encrypted, &aad0, now_mono, now_wall)
                .unwrap();
        assert_eq!(SetupPlaintext::parse(&pt0).unwrap(), (now_wall, "to-h1", &b"c0"[..]));
        r0.commit(&replay0, now_mono, now_wall).unwrap();
        let hk0 = r0.hop_key().clone();
        let flight1 = HopSetupRewrite::rewrite_forward(hdr0.max_mtu, 1300, 1250, cid_h0_r, seg0.tail);

        // Hop 1 authenticates and rewrites.
        let hdr1 = ForwardHeader::parse(&flight1).unwrap();
        assert_eq!(hdr1.max_mtu, 1250);
        let seg1 = ParsedSegment::parse_full(&flight1[FWD_HEADER..]).unwrap();
        let aad1 = compute_tail_aad(seg1.prefix_bytes, seg1.tail);
        let (mut r1, pt1) =
            Responder::authenticate(&hop1, &replay1, seg1.encrypted, &aad1, now_mono, now_wall)
                .unwrap();
        assert_eq!(SetupPlaintext::parse(&pt1).unwrap(), (now_wall, "to-b", &b"c1"[..]));
        r1.commit(&replay1, now_mono, now_wall).unwrap();
        let hk1 = r1.hop_key().clone();
        let flight2 = HopSetupRewrite::rewrite_forward(hdr1.max_mtu, 1250, 1200, cid_h1_r, seg1.tail);

        // Destination authenticates and emits SETUP_OK with dest_mtu = 1220.
        let hdr2 = ForwardHeader::parse(&flight2).unwrap();
        assert_eq!(hdr2.max_mtu, 1200);
        let seg2 = ParsedSegment::parse_full(&flight2[FWD_HEADER..]).unwrap();
        assert!(!seg2.prefix.is_hop);
        let aad2 = compute_tail_aad(seg2.prefix_bytes, seg2.tail);
        let (mut rd, ptd) =
            Responder::authenticate(&dest, &replay_d, seg2.encrypted, &aad2, now_mono, now_wall)
                .unwrap();
        assert_eq!(SetupPlaintext::parse(&ptd).unwrap(), (now_wall, "echo", &b"cd"[..]));
        rd.commit(&replay_d, now_mono, now_wall).unwrap();
        let (reply, dest_keys, _dest_hk) = rd.build_message2(1220, 90_000).unwrap();

        let mut ok_wire = SetupOkHeader {
            hop_acks: 0,
            reverse_mtu: 1220,
            target_cid: hdr2.upstream,
            responder_cid: cid_b,
        }
        .encode_base(&reply);

        // Hop 1 rewrites OK (physical_mtu = 1200, ttl = 45_000 ms).
        let next1 = HopSetupRewrite::rewrite_ok(
            &mut ok_wire,
            &HopOkRewriteParams {
                plane: Plane::Datagram,
                expected_right_cid: cid_h1_r,
                inbound_upstream_cid: hdr1.upstream,
                left_binding_cid: cid_h1_l,
                physical_mtu: 1200,
                hop_lease_ttl_ms: 45_000,
                hop_key: &hk1,
                max_wire_len: 1200,
            },
        )
        .unwrap();
        assert_eq!(next1, cid_b);

        // Hop 0 rewrites OK (physical_mtu = 1250, ttl = 30_000 ms).
        let next0 = HopSetupRewrite::rewrite_ok(
            &mut ok_wire,
            &HopOkRewriteParams {
                plane: Plane::Datagram,
                expected_right_cid: cid_h0_r,
                inbound_upstream_cid: hdr0.upstream,
                left_binding_cid: cid_h0_l,
                physical_mtu: 1250,
                hop_lease_ttl_ms: 30_000,
                hop_key: &hk0,
                max_wire_len: 1250,
            },
        )
        .unwrap();
        assert_eq!(next0, cid_h1_l);

        // Spoof cleartext reverse_mtu to 65000: Origin MUST ignore it and compute authenticated min = 1200!
        ok_wire[2..4].copy_from_slice(&65_000u16.to_be_bytes());

        let established = origin_state.finish_setup_ok(&ok_wire).unwrap();
        assert_eq!(established.legs, vec![1400, 1250, 1200, 1220]);
        assert_eq!(established.path_mtu, 1200);
        assert_eq!(established.dest_ttl, Duration::from_millis(90_000));
        assert_eq!(
            established.hop_ttls,
            vec![Duration::from_millis(30_000), Duration::from_millis(45_000)]
        );
        assert_eq!(established.session_keys.tx_key(), dest_keys.rx_key());
        assert_eq!(established.session_keys.rx_key(), dest_keys.tx_key());
    }
}
