//! Primitive, zero-allocation hot-path, and pure protocol state-machine conformance suite
//! covering Spec §10.1 and pure state machines from §10.2–10.4.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::alloc::{GlobalAlloc, Layout};
use core::cell::Cell;
use core::time::Duration;
use std::alloc::System;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
use rand_core::RngCore;

use confluence_core::__conformance::{
    AuthEpochTable, AuthGate, CookieDecision, CookieProtector, CredentialFetchOutcome, DatagramRx,
    DatagramTx, DestPathMtu, FeedOutcome, ForwardHeader, FragmentBurst, FragmentReassembler,
    FragmentReceipt, HopFlightInput, HopOkRewriteParams, HopSetupRewrite, Initiator, LeaseHandle,
    LoadTracker, MtuChange, MtuReporter, OpeningVerdict, OriginPathMtu, ParsedSegment,
    PreparedFlight, PublishRegistry, RenewalAction, RenewalDriver, RenewalVerifierState,
    ReplayWindow, Responder, RevocationIndex, RevocationKey, ScopeMetrics, SetupCookieFrame,
    SetupErrFrame, SetupFlightBuilder, SetupFlightParams, SetupFragAck, SetupOkHeader,
    SetupPlaintext, SetupReplay, SlabTable, StreamCipher, TrafficGateCache, TransitEpochTarget,
    TransitMtuEvent, TransitPathMtu, VerifierRenewalAction, advance_epoch, compute_mac1,
    compute_mac2, compute_tail_aad, decode_wire_error, decode_wire_error_bytes,
    derive_cookie_enc_key, derive_mac1_key, derive_scope_kid, e2e_dg, encode_wire_error,
    encode_wire_error_bytes, outer, precheck_datagram_setup_frame, prepend_dg_data_header,
    rewrite_dg_data_cid, route_cid, strip_dg_data_header, unseal_cookie_challenge,
};
use confluence_core::auth::{
    AuthDenied, AuthRequest, Authorizer, CredentialProvider, CredentialRequest, DatagramAction,
    EmptyCredentials, Lease, Revocation, StreamAction, revocation_channel,
};
use confluence_core::channel::{
    ChannelCaps, DatagramCarrier, DatagramLink, DatagramLinkExt, DatagramListener,
    IntoStreamHalves, LinkId, MtuWatch, StreamCarrier, StreamListener, StreamReadExt,
    StreamWriteExt,
};
use confluence_core::constants::{
    DATAGRAM_MIN_MTU, FRAG_MAX_ACTIVE, FRAG_MAX_COMPLETED, HEADROOM_BYTES, MAX_EPOCHS, MAX_SETUP,
    MTU_RETRY_DELAYS, TAILROOM_BYTES,
};
use confluence_core::handler::{
    DatagramEndpointHandler, DatagramTransitHandler, DynamicTransit, StaticTransit,
    StreamEndpointHandler, StreamTransitHandler,
};
use confluence_core::runtime::{BoxFuture, Clock, MonotonicTime, TaskSpawner, WallClock};
use confluence_core::testing::{
    MemoryDatagramPair, MemoryStreamPair, TestRuntime, VirtualClock, memory_datagram_channel,
    memory_stream_channel,
};
use confluence_core::{
    AuthLimits, Cid, CoreError, Credential, FailureClass, IntersectAuthorizer, PacketBuf, Plane,
    PublicKey, ScopeKeypair, TargetRef,
};

// ---------------------------------------------------------------------------
// Custom Counting Global Allocator (Per-Thread Const-Init ELF TLS, Zero Noise)
// ---------------------------------------------------------------------------

struct CountingAlloc;

thread_local! {
    static COUNT_THIS_THREAD: Cell<bool> = const { Cell::new(false) };
    static THREAD_ALLOCS: Cell<usize> = const { Cell::new(0) };
    static THREAD_DEALLOCS: Cell<usize> = const { Cell::new(0) };
}

#[allow(unsafe_code)]
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNT_THIS_THREAD.get() {
            THREAD_ALLOCS.set(THREAD_ALLOCS.get() + 1);
        }
        // SAFETY: Delegates directly to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if COUNT_THIS_THREAD.get() {
            THREAD_DEALLOCS.set(THREAD_DEALLOCS.get() + 1);
        }
        // SAFETY: Delegates directly to the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNT_THIS_THREAD.get() {
            THREAD_ALLOCS.set(THREAD_ALLOCS.get() + 1);
        }
        // SAFETY: Delegates directly to the system allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL_ALLOC: CountingAlloc = CountingAlloc;

/// Measures heap allocations and deallocations performed on the calling thread during `f`.
fn measure_allocs<R>(f: impl FnOnce() -> R) -> (usize, usize, R) {
    THREAD_ALLOCS.set(0);
    THREAD_DEALLOCS.set(0);
    COUNT_THIS_THREAD.set(true);
    let result = f();
    COUNT_THIS_THREAD.set(false);
    (THREAD_ALLOCS.get(), THREAD_DEALLOCS.get(), result)
}

struct DetRng(u64);
impl RngCore for DetRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() {
            *b = self.next_u64() as u8;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Section 10.1 — Zero-Allocation Hot Path & Invalid MAC1 Proofs
// ---------------------------------------------------------------------------

#[test]
fn counting_allocator_sanity_is_non_vacuous() {
    let (allocs, deallocs, ()) = measure_allocs(|| {
        let mut v = Vec::<u8>::with_capacity(128);
        v.push(42);
        std::hint::black_box(&v);
        drop(v);
    });
    assert!(allocs >= 1, "counting allocator must observe real allocations");
    assert!(deallocs >= 1, "counting allocator must observe real deallocations");
}

#[test]
fn zero_alloc_datagram_hot_path_all_sizes_and_stable_pointer() {
    let e2e_key = [0x33u8; 32];
    let outer_key = [0x99u8; 32];
    let outer_cipher = ChaCha20Poly1305::new((&outer_key).into());
    let mut tx = DatagramTx::new(&e2e_key);
    let mut rx = DatagramRx::new(&e2e_key);
    let cid_origin = Cid::from_parts(2, 100).unwrap();
    let cid_transit = Cid::from_parts(5, 200).unwrap();

    // Spec §10.1 normative size matrix.
    let sizes = [0usize, 1, 17, 128, 1202, 16_000, 65_505];
    for (idx, &size) in sizes.iter().enumerate() {
        let expected: Vec<u8> = (0..size).map(|i| (i.wrapping_mul(31) ^ idx) as u8).collect();
        let mut pkt = PacketBuf::from_payload(&expected);
        assert_eq!(pkt.headroom(), HEADROOM_BYTES);
        assert_eq!(pkt.tailroom(), TAILROOM_BYTES);
        let orig_ptr = pkt.payload().as_ptr();

        let mut outer_nonce_bytes = [0u8; 12];
        outer_nonce_bytes[4..12].copy_from_slice(&(idx as u64).to_be_bytes());
        let outer_nonce = Nonce::from_slice(&outer_nonce_bytes);

        let (allocs, deallocs, res) = measure_allocs(|| {
            // 1. E2E seal in place.
            let seq = tx.seal(e2e_dg::DG_DATA, &mut pkt).unwrap();
            // 2. Prepend 5-byte DG_DATA hop header in place.
            prepend_dg_data_header(&mut pkt, cid_origin).unwrap();
            // 3. Stacked outer link-AEAD wrap in place (12B nonce header + 16B tag).
            let outer_tag = outer_cipher
                .encrypt_in_place_detached(outer_nonce, b"link", pkt.payload_mut())
                .unwrap();
            pkt.prepend_header(&outer_nonce_bytes).unwrap();
            let outer_tag_arr: [u8; 16] = outer_tag.into();
            pkt.append_tag(&outer_tag_arr).unwrap();

            // 4. Stacked outer link-AEAD unwrap in place.
            let stripped_nonce = pkt.strip_header(12).unwrap();
            let mut rx_nonce = [0u8; 12];
            rx_nonce.copy_from_slice(stripped_nonce);
            let stripped_tag = pkt.strip_tail(16).unwrap();
            let mut rx_tag = [0u8; 16];
            rx_tag.copy_from_slice(stripped_tag);
            outer_cipher
                .decrypt_in_place_detached(
                    Nonce::from_slice(&rx_nonce),
                    b"link",
                    pkt.payload_mut(),
                    Tag::from_slice(&rx_tag),
                )
                .unwrap();

            // 5. Transit hop in-place CID rewrite.
            rewrite_dg_data_cid(&mut pkt, cid_transit).unwrap();
            // 6. Destination strip 5-byte hop header.
            let seen_cid = strip_dg_data_header(&mut pkt).unwrap();
            // 7. E2E open in place.
            let (rx_seq, opcode) = rx.open(&mut pkt).unwrap();
            (seq, seen_cid, rx_seq, opcode)
        });

        assert_eq!(
            (allocs, deallocs),
            (0, 0),
            "size {size} performed heap allocations ({allocs} allocs, {deallocs} deallocs)"
        );
        assert_eq!(res.0, idx as u64);
        assert_eq!(res.1, cid_transit);
        assert_eq!(res.2, idx as u64);
        assert_eq!(res.3, e2e_dg::DG_DATA);
        assert_eq!(pkt.payload(), expected.as_slice());
        assert_eq!(
            pkt.payload().as_ptr(),
            orig_ptr,
            "payload pointer shifted for size {size}"
        );
    }
}

#[test]
fn zero_alloc_datagram_renewal_open_and_in_place_wipe() {
    let key = [0x4Au8; 32];
    let mut tx = DatagramTx::new(&key);
    let mut rx = DatagramRx::new(&key);
    let mut body = Vec::with_capacity(8 + 64);
    body.extend_from_slice(&1u64.to_be_bytes());
    body.extend_from_slice(&[0x5A; 64]);
    let mut pkt = PacketBuf::from_payload(&body);
    let orig_ptr = pkt.payload().as_ptr();

    let (allocs, deallocs, (seq, op)) = measure_allocs(|| {
        tx.seal(e2e_dg::DG_RENEW, &mut pkt).unwrap();
        let opened = rx.open(&mut pkt).unwrap();
        pkt.zeroize_range(8..24);
        pkt.zeroize_payload();
        pkt.reset();
        opened
    });
    assert_eq!((allocs, deallocs), (0, 0));
    assert_eq!(seq, 0);
    assert_eq!(op, e2e_dg::DG_RENEW);
    assert_eq!(pkt.payload().as_ptr(), orig_ptr);
    assert!(pkt.is_empty());
}

#[test]
fn zero_alloc_invalid_mac1_and_unknown_scope_kid_rejection() {
    let origin = ScopeKeypair::generate();
    let dest = ScopeKeypair::generate();
    let other_scope = ScopeKeypair::generate();
    let t0 = MonotonicTime::ZERO;
    let wall = 1_700_000_000_000u64;
    let cid = Cid::from_parts(1, 12).unwrap();

    let cookies = HashMap::new();
    let (_st, flight) = SetupFlightBuilder::build(&SetupFlightParams {
        local: &origin,
        plane: Plane::Datagram,
        origin_local_mtu: 1232,
        min_mtu: 1152,
        upstream_cid: cid,
        destination: dest.public_key(),
        endpoint: "svc",
        dest_credential: b"cred",
        hops: &[],
        cookies: &cookies,
        wall_time_ms: wall,
    })
    .unwrap();

    // Corrupt final bit of mac1.
    let mut bad_mac1_flight = flight.clone();
    let last = bad_mac1_flight.len() - 1;
    bad_mac1_flight[last] ^= 0x01;

    // Also craft a fragmented flight to test frag-0 bad mac1 & unknown ScopeKid.
    let hops_kp: Vec<ScopeKeypair> = (0..5).map(|_| ScopeKeypair::generate()).collect();
    let hops: Vec<HopFlightInput<'_>> = hops_kp
        .iter()
        .map(|k| HopFlightInput {
            peer: k.public_key(),
            target: "hop-long-name-for-fragmentation",
            credential: &[0x77; 128],
        })
        .collect();
    let (_st2, large_flight) = SetupFlightBuilder::build(&SetupFlightParams {
        local: &origin,
        plane: Plane::Datagram,
        origin_local_mtu: 1200,
        min_mtu: 1152,
        upstream_cid: cid,
        destination: dest.public_key(),
        endpoint: "svc",
        dest_credential: &[0x88; 128],
        hops: &hops,
        cookies: &cookies,
        wall_time_ms: wall,
    })
    .unwrap();
    let frag0 = match FragmentBurst::prepare_with_id(&large_flight, 1200, cid, 777).unwrap() {
        PreparedFlight::Fragmented(b) => b.frames()[0].clone(),
        PreparedFlight::Single(_) => panic!("expected fragmented flight"),
    };
    let mut bad_frag0 = frag0.clone();
    // Flip a byte inside the leading encrypted segment's mac1 in frag0.
    bad_frag0.payload_mut()[16 + 8 + 8 + 100] ^= 0xFF;

    let seg_valid = ParsedSegment::parse_full(&flight[8..]).unwrap();
    let seg_bad_mac1 = ParsedSegment::parse_full(&bad_mac1_flight[8..]).unwrap();
    let aad = compute_tail_aad(seg_valid.prefix_bytes, seg_valid.tail);
    let replay = SetupReplay::new(t0);
    let protector = CookieProtector::new(dest.clone(), t0);
    let other_protector = CookieProtector::new(other_scope.clone(), t0);
    let hop0_protector = CookieProtector::new(hops_kp[0].clone(), t0);
    let mut reasm = FragmentReassembler::new();
    let src = [0xAB; 16];

    // All rejections MUST execute with 0 heap allocations and 0 deallocations!
    let (allocs, deallocs, ()) = measure_allocs(|| {
        // 1. Responder::authenticate on invalid mac1 -> BadMac.
        assert!(matches!(
            Responder::authenticate(&dest, &replay, seg_bad_mac1.encrypted, &aad, t0, wall),
            Err(CoreError::BadMac)
        ));
        // 2. Responder::authenticate on unknown ScopeKid -> BadMac.
        assert!(matches!(
            Responder::authenticate(&other_scope, &replay, seg_valid.encrypted, &aad, t0, wall),
            Err(CoreError::BadMac)
        ));
        // 3. CookieProtector::verify_segment (both !under_load and under_load) -> Drop.
        assert_eq!(
            protector.verify_segment(&src, seg_bad_mac1.encrypted, false, t0),
            CookieDecision::Drop
        );
        assert_eq!(
            other_protector.verify_segment(&src, seg_valid.encrypted, false, t0),
            CookieDecision::Drop
        );
        // 4. Stack-only precheck_datagram_setup_frame on SETUP_FWD & SETUP_FRAG frag 0.
        assert!(!precheck_datagram_setup_frame(&bad_mac1_flight, |kid, seg, has_mac2| {
            kid == dest.scope_kid() && protector.verify_mac1_only(seg, has_mac2)
        }));
        assert!(!precheck_datagram_setup_frame(&flight, |kid, seg, has_mac2| {
            kid == other_scope.scope_kid() && other_protector.verify_mac1_only(seg, has_mac2)
        }));
        assert!(!precheck_datagram_setup_frame(bad_frag0.payload(), |kid, seg, has_mac2| {
            kid == hops_kp[0].scope_kid() && hop0_protector.verify_mac1_only(seg, has_mac2)
        }));
        // 5. FragmentReassembler::feed rejects invalid mac1 frag 0 with 0 allocations.
        assert_eq!(
            reasm.feed(bad_frag0.payload(), t0, |_, _, _| OpeningVerdict::DropMac1),
            FeedOutcome::DropMac1
        );
    });

    assert_eq!((allocs, deallocs), (0, 0));
    assert_eq!(reasm.active_count(), 0);
    assert_eq!(reasm.allocated_bytes(), 0);
}

// ---------------------------------------------------------------------------
// Section 10.1 — Cryptographic Primitives & Normative Transcript Checks
// ---------------------------------------------------------------------------

#[test]
fn blake3_domain_strings_and_key_derivations() {
    let kp = ScopeKeypair::from_secret_bytes([0x19; 32]);
    let pk = kp.public_key();

    assert_eq!(
        derive_scope_kid(&pk).as_bytes(),
        &blake3::derive_key("confluence-v1-kid", pk.as_bytes())[0..8]
    );
    let m1k = derive_mac1_key(&pk);
    assert_eq!(m1k, blake3::derive_key("confluence-v1-mac1", pk.as_bytes()));
    assert_eq!(
        derive_cookie_enc_key(&pk),
        blake3::derive_key("confluence-v1-cookie", pk.as_bytes())
    );
    let data = b"normative v1 mac input";
    let expected_m1 = blake3::keyed_hash(&m1k, data);
    assert_eq!(&compute_mac1(&pk, data), &expected_m1.as_bytes()[0..16]);

    let cookie = [0xFE; 16];
    let m2k = blake3::derive_key("confluence-v1-mac2", &cookie);
    let expected_m2 = blake3::keyed_hash(&m2k, data);
    assert_eq!(&compute_mac2(&cookie, data), &expected_m2.as_bytes()[0..16]);
}

#[test]
fn noise_ik_asymmetry_all_zero_dh_and_prefix_tail_bit_flips() {
    let origin = ScopeKeypair::generate();
    let hop0 = ScopeKeypair::generate();
    let dest = ScopeKeypair::generate();
    let t0 = MonotonicTime::ZERO;
    let wall = 1_700_000_000_000u64;

    // Low-order all-zero X25519 public key MUST be rejected with Authentication.
    let zero_pk = PublicKey::from_bytes([0u8; 32]);
    let pt = SetupPlaintext::encode(wall, "ep", &[]).unwrap();
    assert!(matches!(
        Initiator::build_message1(&origin, zero_pk, &[0u8; 32], &pt, None),
        Err(CoreError::Authentication)
    ));

    // Build 1-hop flight and test flipping every bit in dispatch_prefix and sample bits in tail.
    let cookies = HashMap::new();
    let hops = [HopFlightInput {
        peer: hop0.public_key(),
        target: "next",
        credential: b"hop-cred",
    }];
    let (_st, flight) = SetupFlightBuilder::build(&SetupFlightParams {
        local: &origin,
        plane: Plane::Stream,
        origin_local_mtu: 16_384,
        min_mtu: 20,
        upstream_cid: Cid::UNBOUND,
        destination: dest.public_key(),
        endpoint: "echo",
        dest_credential: b"dest-cred",
        hops: &hops,
        cookies: &cookies,
        wall_time_ms: wall,
    })
    .unwrap();

    let seg = ParsedSegment::parse_full(&flight[8..]).unwrap();
    let replay = SetupReplay::new(t0);

    // Every single bit flip in the 8-byte dispatch prefix MUST fail authentication!
    for byte_idx in 0..seg.prefix_bytes.len() {
        for bit in 0..8u8 {
            let mut mutated_prefix = seg.prefix_bytes.to_vec();
            mutated_prefix[byte_idx] ^= 1u8 << bit;
            let bad_aad = compute_tail_aad(&mutated_prefix, seg.tail);
            assert!(matches!(
                Responder::authenticate(&hop0, &replay, seg.encrypted, &bad_aad, t0, wall),
                Err(CoreError::Authentication)
            ));
        }
    }

    // Flipping bits across tail (start, middle, end) MUST fail authentication!
    for &idx in &[0usize, seg.tail.len() / 2, seg.tail.len() - 1] {
        let mut mutated_tail = seg.tail.to_vec();
        mutated_tail[idx] ^= 0x01;
        let bad_aad = compute_tail_aad(seg.prefix_bytes, &mutated_tail);
        assert!(matches!(
            Responder::authenticate(&hop0, &replay, seg.encrypted, &bad_aad, t0, wall),
            Err(CoreError::Authentication)
        ));
    }

    // Genuine AAD succeeds and establishes asymmetric keys on Message 2.
    let aad = compute_tail_aad(seg.prefix_bytes, seg.tail);
    let (mut resp, _) =
        Responder::authenticate(&hop0, &replay, seg.encrypted, &aad, t0, wall).unwrap();
    resp.commit(&replay, t0, wall).unwrap();

    // Verify independent Message 1 + Message 2 on dest.
    let (init_d, seg_d) =
        Initiator::build_message1(&origin, dest.public_key(), &aad, &pt, None).unwrap();
    let replay_d = SetupReplay::new(t0);
    let (mut resp_d, _) =
        Responder::authenticate(&dest, &replay_d, &seg_d, &aad, t0, wall).unwrap();
    resp_d.commit(&replay_d, t0, wall).unwrap();
    let (reply, resp_keys, _) = resp_d.build_message2(16_384, 60_000).unwrap();
    let (_, _, init_keys, _) = init_d.finish_message2(&reply).unwrap();
    assert_eq!(init_keys.tx_key(), resp_keys.rx_key());
    assert_eq!(init_keys.rx_key(), resp_keys.tx_key());
    assert_ne!(init_keys.tx_key(), init_keys.rx_key());
}

#[test]
fn setup_replay_monotonic_wall_jump_two_phase_and_concurrent_race() {
    let rt = TestRuntime::new();
    let origin = ScopeKeypair::generate();
    let dest = ScopeKeypair::generate();
    let replay = Arc::new(SetupReplay::new(rt.clock.now()));

    let wall0 = rt.wall_clock.unix_millis();
    let pt = SetupPlaintext::encode(wall0, "ep", &[]).unwrap();
    let aad = [0x55u8; 32];
    let (_init, seg) =
        Initiator::build_message1(&origin, dest.public_key(), &aad, &pt, None).unwrap();

    // Authenticate without committing (simulating Authorizer denial): MUST NOT consume replay slot!
    let (_resp_aborted, _) =
        Responder::authenticate(&dest, &replay, &seg, &aad, rt.clock.now(), wall0).unwrap();
    drop(_resp_aborted);

    // Concurrent commit race across 8 OS threads for the EXACT same E_i: exactly 1 winner!
    let mut responders = Vec::new();
    for _ in 0..8 {
        let (r, _) =
            Responder::authenticate(&dest, &replay, &seg, &aad, rt.clock.now(), wall0).unwrap();
        responders.push(r);
    }

    let barrier = Arc::new(std::sync::Barrier::new(8));
    let winners = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for mut resp in responders {
        let r_ref = Arc::clone(&replay);
        let b_ref = Arc::clone(&barrier);
        let w_ref = Arc::clone(&winners);
        let mono = rt.clock.now();
        handles.push(thread::spawn(move || {
            b_ref.wait();
            if resp.commit(&r_ref, mono, wall0).is_ok() {
                w_ref.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(winners.load(Ordering::SeqCst), 1);

    // Backward wall-clock jump of 1 hour MUST NOT flush live replay entry!
    rt.wall_clock.step_back_ms(3_600_000);
    assert!(matches!(
        Responder::authenticate(&dest, &replay, &seg, &aad, rt.clock.now(), wall0),
        Err(CoreError::Replay)
    ));
}

#[test]
fn replay_window_and_hop_key_tamper_resistance() {
    let mut rw = ReplayWindow::new();
    assert!(rw.allows(0));
    rw.commit(0);
    assert!(!rw.allows(0));
    for seq in (1..64u64).rev() {
        assert!(rw.allows(seq));
        rw.commit(seq);
        assert!(!rw.allows(seq));
    }
    rw.commit(100);
    assert!(!rw.allows(36)); // 100 - 36 == 64 (outside window)
    assert!(!rw.allows(37)); // 37 was already committed above
    assert!(rw.allows(64));  // 100 - 64 == 36 < 64 and never committed
    assert!(rw.allows(99));
    rw.commit(64);
    assert!(!rw.allows(64));

    // HopKey tamper resistance across EVERY byte of setup_hop_ack (26 B) and setup_error (28 B).
    let origin = ScopeKeypair::generate();
    let dest = ScopeKeypair::generate();
    let wall = 1_700_000_000_000u64;
    let pt = SetupPlaintext::encode(wall, "svc", &[]).unwrap();
    let (init, seg) =
        Initiator::build_message1(&origin, dest.public_key(), &[0x11; 32], &pt, None).unwrap();
    let replay = SetupReplay::new(MonotonicTime::ZERO);
    let (resp, _) =
        Responder::authenticate(&dest, &replay, &seg, &[0x11; 32], MonotonicTime::ZERO, wall)
            .unwrap();

    let ack = resp.hop_key().seal_setup_hop_ack(1232, 45_000);
    assert_eq!(init.hop_key().open_setup_hop_ack(&ack), Ok((1232, 45_000)));
    for i in 0..ack.len() {
        let mut flipped = ack;
        flipped[i] ^= 0x01;
        assert_eq!(
            init.hop_key().open_setup_hop_ack(&flipped),
            Err(CoreError::Authentication),
            "hop ack bit flip at byte {i} was not rejected"
        );
    }

    let err1 = resp.hop_key().seal_setup_error(1, 1152);
    let err2 = resp.hop_key().seal_setup_error(1, 1152);
    assert_ne!(err1, err2, "setup_error must use fresh CSPRNG nonce per frame");
    assert_eq!(init.hop_key().open_setup_error(&err1), Ok((1, 1152)));
    for i in 0..err1.len() {
        let mut flipped = err1;
        flipped[i] ^= 0x01;
        assert_eq!(
            init.hop_key().open_setup_error(&flipped),
            Err(CoreError::Authentication),
            "setup error bit flip at byte {i} was not rejected"
        );
    }

    // ControlCipher directional isolation & opcode AAD binding.
    let mut c_origin = init.hop_key().control_cipher(true);
    let mut c_hop = resp.hop_key().control_cipher(false);
    let sealed = c_origin.seal(outer::DG_RENEW, b"cred-payload").unwrap();
    assert_eq!(c_hop.open(outer::DG_CLOSE, &sealed), Err(CoreError::Authentication));
    assert_eq!(&*c_hop.open(outer::DG_RENEW, &sealed).unwrap(), b"cred-payload");
    // StreamCipher reuse & bit-flip rejection.
    let mut st_tx = StreamCipher::new(&[0x44; 32]);
    let mut st_rx = StreamCipher::new(&[0x44; 32]);
    let mut scratch = Vec::new();
    st_tx.seal_into(0x10, b"stream-data", &mut scratch).unwrap();
    let mut bad = scratch.clone();
    bad[5] ^= 0x01;
    assert_eq!(st_rx.open_in_place(&mut bad), Err(CoreError::Authentication));
}

// ---------------------------------------------------------------------------
// Sections 10.2–10.4 — Pure State Machines Conformance
// ---------------------------------------------------------------------------

#[test]
fn cookie_protector_rotation_and_hysteresis_conformance() {
    let clock = VirtualClock::new();
    let origin = ScopeKeypair::generate();
    let dest = ScopeKeypair::generate();
    let protector = CookieProtector::new(dest.clone(), clock.now());

    // 75%/25%/5s hysteresis via VirtualClock.
    assert!(!protector.update_load(192, 256, clock.now())); // exactly 75% -> off
    assert!(protector.update_load(193, 256, clock.now()));  // > 75% -> ON
    clock.advance(Duration::from_secs(10));
    assert!(protector.update_load(100, 256, clock.now()));  // hysteresis band -> stays ON
    assert!(protector.update_load(64, 256, clock.now()));   // <= 25% -> starts 5s timer
    clock.advance(Duration::from_millis(4999));
    assert!(protector.update_load(0, 256, clock.now()));    // 4.999s -> still ON
    clock.advance(Duration::from_millis(1));
    assert!(!protector.update_load(0, 256, clock.now()));   // 5.000s -> OFF!

    // Challenge -> unseal -> accept across 1 rotation -> reject after 2 rotations.
    protector.set_under_load(Some(true));
    let pt = SetupPlaintext::encode(1_700_000_000_000, "ep", &[]).unwrap();
    let (init0, seg0) =
        Initiator::build_message1(&origin, dest.public_key(), &[0x22; 32], &pt, None).unwrap();
    let src = [0x12; 16];
    let challenge = match protector.verify_segment(&src, &seg0, false, clock.now()) {
        CookieDecision::Challenge(c) => c,
        other => panic!("expected challenge, got {other:?}"),
    };
    let cookie =
        unseal_cookie_challenge(&dest.public_key(), init0.sent_mac1(), &challenge).unwrap();
    let (_init1, seg1) =
        Initiator::build_message1(&origin, dest.public_key(), &[0x22; 32], &pt, Some(&cookie))
            .unwrap();
    assert!(matches!(
        protector.verify_segment(&src, &seg1, true, clock.now()),
        CookieDecision::Verified(_)
    ));

    // Advance 120s (1 rotation) -> grace period still accepts!
    clock.advance(Duration::from_secs(120));
    assert!(matches!(
        protector.verify_segment(&src, &seg1, true, clock.now()),
        CookieDecision::Verified(_)
    ));

    // Jump 240s (2 rotations at once) -> rejected with new challenge!
    clock.advance(Duration::from_secs(240));
    assert!(matches!(
        protector.verify_segment(&src, &seg1, true, clock.now()),
        CookieDecision::Challenge(_)
    ));

    // Also verify LoadTracker standalone override restoration.
    let mut lt = LoadTracker::new();
    lt.set_override(Some(true));
    assert!(lt.is_under_load());
    lt.set_override(None);
    assert!(!lt.is_under_load());
}

#[test]
fn fragment_reassembler_enforces_16_active_max_setup_and_32_completed_caps() {
    let origin = ScopeKeypair::generate();
    let dest = ScopeKeypair::generate();
    let hop_kps: Vec<ScopeKeypair> = (0..5).map(|_| ScopeKeypair::generate()).collect();
    let hops: Vec<HopFlightInput<'_>> = hop_kps
        .iter()
        .map(|k| HopFlightInput {
            peer: k.public_key(),
            target: "hop-target-padding-for-fragment-size",
            credential: &[0x55; 128],
        })
        .collect();
    let cookies = HashMap::new();
    let t0 = MonotonicTime::ZERO;
    let reasm = Arc::new(Mutex::new(FragmentReassembler::new()));

    // Fill 16 active assemblies; 17th MUST be ignored without exceeding FRAG_MAX_ACTIVE.
    for msg_id in 1..=(FRAG_MAX_ACTIVE as u64 + 1) {
        let cid = Cid::from_parts(1, msg_id as u32).unwrap();
        let (_st, wire) = SetupFlightBuilder::build(&SetupFlightParams {
            local: &origin,
            plane: Plane::Datagram,
            origin_local_mtu: 1200,
            min_mtu: 1152,
            upstream_cid: cid,
            destination: dest.public_key(),
            endpoint: "ep",
            dest_credential: &[0x66; 128],
            hops: &hops,
            cookies: &cookies,
            wall_time_ms: 1_700_000_000_000,
        })
        .unwrap();
        let burst = match FragmentBurst::prepare_with_id(&wire, 1200, cid, msg_id).unwrap() {
            PreparedFlight::Fragmented(b) => b,
            PreparedFlight::Single(_) => panic!("expected fragmented"),
        };
        let out = reasm
            .lock()
            .unwrap()
            .feed(burst.frames()[0].payload(), t0, |_, _, _| OpeningVerdict::Verified);
        if msg_id <= FRAG_MAX_ACTIVE as u64 {
            assert_eq!(out, FeedOutcome::NeedMore);
        } else {
            assert_eq!(out, FeedOutcome::Ignore);
        }
    }
    assert_eq!(reasm.lock().unwrap().active_count(), FRAG_MAX_ACTIVE);
    assert!(reasm.lock().unwrap().allocated_bytes() <= MAX_SETUP);

    // Expire active flights after 3 s.
    let t1 = t0.saturating_add(Duration::from_secs(3));
    reasm.lock().unwrap().expire(t1);
    assert_eq!(reasm.lock().unwrap().active_count(), 0);
    assert_eq!(reasm.lock().unwrap().allocated_bytes(), 0);

    // Push 35 completed receipts -> FIFO cap stays strictly at 32 (oldest 3 evicted).
    let cid = Cid::from_parts(1, 1).unwrap();
    let (_st, wire) = SetupFlightBuilder::build(&SetupFlightParams {
        local: &origin,
        plane: Plane::Datagram,
        origin_local_mtu: 1200,
        min_mtu: 1152,
        upstream_cid: cid,
        destination: dest.public_key(),
        endpoint: "ep",
        dest_credential: &[0x66; 128],
        hops: &hops,
        cookies: &cookies,
        wall_time_ms: 1_700_000_000_000,
    })
    .unwrap();
    for msg_id in 1..=35u64 {
        let burst = match FragmentBurst::prepare_with_id(&wire, 1200, cid, msg_id).unwrap() {
            PreparedFlight::Fragmented(b) => b,
            PreparedFlight::Single(_) => panic!("expected fragmented"),
        };
        let mut key = None;
        for f in burst.frames() {
            if let FeedOutcome::Complete { key: k, .. } =
                reasm.lock().unwrap().feed(f.payload(), t1, |_, _, _| OpeningVerdict::Verified)
            {
                key = Some(k);
            }
        }
        let receipt = FragmentReceipt::new(Arc::clone(&reasm), key.unwrap());
        let ack = receipt.acknowledge(t1).unwrap();
        assert_eq!(SetupFragAck::parse(&ack.encode()), Ok(ack));
    }
    assert_eq!(reasm.lock().unwrap().completed_count(), FRAG_MAX_COMPLETED);
}

#[test]
fn three_hop_setup_error_cookie_distance_and_wire_error_codes() {
    let origin = ScopeKeypair::generate();
    let hop0 = ScopeKeypair::generate();
    let hop1 = ScopeKeypair::generate();
    let hop2 = ScopeKeypair::generate();
    let dest = ScopeKeypair::generate();
    let wall = 1_700_000_000_000u64;
    let t0 = MonotonicTime::ZERO;

    let cid_a = Cid::from_parts(1, 1).unwrap();
    let cookies = HashMap::new();
    let hops = [
        HopFlightInput { peer: hop0.public_key(), target: "h0", credential: b"0" },
        HopFlightInput { peer: hop1.public_key(), target: "h1", credential: b"1" },
        HopFlightInput { peer: hop2.public_key(), target: "h2", credential: b"2" },
    ];

    let (origin_st, flight0) = SetupFlightBuilder::build(&SetupFlightParams {
        local: &origin,
        plane: Plane::Datagram,
        origin_local_mtu: 1500,
        min_mtu: DATAGRAM_MIN_MTU,
        upstream_cid: cid_a,
        destination: dest.public_key(),
        endpoint: "ep",
        dest_credential: b"d",
        hops: &hops,
        cookies: &cookies,
        wall_time_ms: wall,
    })
    .unwrap();

    // Walk forward through hop0 -> hop1 -> hop2 -> dest.
    let step_hop = |kp: &ScopeKeypair, flight: &[u8], out_cid: Cid| {
        let hdr = ForwardHeader::parse(flight).unwrap();
        let seg = ParsedSegment::parse_full(&flight[8..]).unwrap();
        let aad = compute_tail_aad(seg.prefix_bytes, seg.tail);
        let replay = SetupReplay::new(t0);
        let (resp, _) = Responder::authenticate(kp, &replay, seg.encrypted, &aad, t0, wall).unwrap();
        let next_flight = HopSetupRewrite::rewrite_forward(hdr.max_mtu, 1400, 1300, out_cid, seg.tail);
        (resp, next_flight, hdr.upstream)
    };

    let (r0, f1, _) = step_hop(&hop0, &flight0, Cid::from_parts(1, 2).unwrap());
    let (r1, f2, _) = step_hop(&hop1, &f1, Cid::from_parts(1, 3).unwrap());
    let (r2, f3, _) = step_hop(&hop2, &f2, Cid::from_parts(1, 4).unwrap());

    // Simulate hop1 emitting SETUP_ERR(Denied) at distance 0 -> hop0 increments to distance 1!
    let (code, arg) = encode_wire_error(&CoreError::Denied);
    let err_at_h1 = SetupErrFrame {
        distance: 0,
        target_cid: Cid::from_parts(1, 2).unwrap(),
        body: r1.hop_key().seal_setup_error(code, arg),
    };
    let forwarded_err_bytes = HopSetupRewrite::rewrite_err(&err_at_h1, cid_a).unwrap();
    assert_eq!(route_cid(&forwarded_err_bytes), Some(cid_a));
    let forwarded_err = SetupErrFrame::parse(&forwarded_err_bytes).unwrap();
    assert_eq!(forwarded_err.distance, 1);
    let opened = origin_st.open_setup_err(&forwarded_err).unwrap();
    assert_eq!(opened, CoreError::hop_rejected(1, CoreError::Denied));
    assert_eq!(opened.failure_class(), FailureClass::PathFailure);

    // Simulate dest emitting SETUP_COOKIE at distance 0 -> hop2 (1) -> hop1 (2) -> hop0 (3)!
    let seg_d = ParsedSegment::parse_full(&f3[8..]).unwrap();
    let dest_prot = CookieProtector::new(dest.clone(), t0);
    dest_prot.set_under_load(Some(true));
    let challenge = match dest_prot.verify_segment(&[0xEE; 16], seg_d.encrypted, false, t0) {
        CookieDecision::Challenge(c) => c,
        other => panic!("expected challenge, got {other:?}"),
    };
    let c0 = SetupCookieFrame { distance: 0, target_cid: Cid::from_parts(1, 4).unwrap(), challenge };
    let c1 = SetupCookieFrame::parse(&HopSetupRewrite::rewrite_cookie(&c0, Cid::from_parts(1, 3).unwrap()).unwrap()).unwrap();
    let c2 = SetupCookieFrame::parse(&HopSetupRewrite::rewrite_cookie(&c1, Cid::from_parts(1, 2).unwrap()).unwrap()).unwrap();
    let c3 = SetupCookieFrame::parse(&HopSetupRewrite::rewrite_cookie(&c2, cid_a).unwrap()).unwrap();
    assert_eq!(c3.distance, 3);
    let (node_idx, _cookie) = origin_st.unseal_setup_cookie(&c3).unwrap();
    assert_eq!(node_idx, 3);

    // Finish full 3-hop SETUP_OK with distinct MTUs and spoofed reverse_mtu.
    let aad_d = compute_tail_aad(seg_d.prefix_bytes, seg_d.tail);
    let replay_d = SetupReplay::new(t0);
    let (rd, _) = Responder::authenticate(&dest, &replay_d, seg_d.encrypted, &aad_d, t0, wall).unwrap();
    let (reply, _dk, _) = rd.build_message2(1240, 120_000).unwrap();
    let mut ok = SetupOkHeader {
        hop_acks: 0,
        reverse_mtu: 1240,
        target_cid: Cid::from_parts(1, 4).unwrap(),
        responder_cid: Cid::from_parts(1, 99).unwrap(),
    }
    .encode_base(&reply);

    HopSetupRewrite::rewrite_ok(&mut ok, &HopOkRewriteParams {
        plane: Plane::Datagram,
        expected_right_cid: Cid::from_parts(1, 4).unwrap(),
        inbound_upstream_cid: Cid::from_parts(1, 3).unwrap(),
        left_binding_cid: Cid::from_parts(1, 98).unwrap(),
        physical_mtu: 1190,
        hop_lease_ttl_ms: 80_000,
        hop_key: r2.hop_key(),
        max_wire_len: 1200,
    }).unwrap();
    HopSetupRewrite::rewrite_ok(&mut ok, &HopOkRewriteParams {
        plane: Plane::Datagram,
        expected_right_cid: Cid::from_parts(1, 3).unwrap(),
        inbound_upstream_cid: Cid::from_parts(1, 2).unwrap(),
        left_binding_cid: Cid::from_parts(1, 97).unwrap(),
        physical_mtu: 1280,
        hop_lease_ttl_ms: 70_000,
        hop_key: r1.hop_key(),
        max_wire_len: 1280,
    }).unwrap();
    HopSetupRewrite::rewrite_ok(&mut ok, &HopOkRewriteParams {
        plane: Plane::Datagram,
        expected_right_cid: Cid::from_parts(1, 2).unwrap(),
        inbound_upstream_cid: cid_a,
        left_binding_cid: Cid::from_parts(1, 96).unwrap(),
        physical_mtu: 1350,
        hop_lease_ttl_ms: 60_000,
        hop_key: r0.hop_key(),
        max_wire_len: 1350,
    }).unwrap();

    // Spoof cleartext reverse_mtu upward -> ignored!
    ok[2..4].copy_from_slice(&9000u16.to_be_bytes());
    let est = origin_st.finish_setup_ok(&ok).unwrap();
    assert_eq!(est.legs, vec![1500, 1350, 1280, 1190, 1240]);
    assert_eq!(est.path_mtu, 1190);

    // Wire error code 10 & non-zero arg on 2..=13 verification.
    assert_eq!(decode_wire_error(2, 0x1234), Ok(CoreError::Denied));
    let c10 = decode_wire_error_bytes(&encode_wire_error_bytes(&CoreError::Replay)).unwrap();
    assert!(matches!(c10, CoreError::Carrier(_)));
    assert!(!c10.is_retryable());
}

#[test]
fn slab_table_600_wrap_cycles_bounded_memory_and_zero_aliasing() {
    let clock = VirtualClock::new();
    let mut slab = SlabTable::<u64>::new();
    let mut active_set = HashSet::new();

    // Cycle 600 times across > 2 complete 255-generation wraps, advancing 60 s after each wrap.
    for round in 0..600u64 {
        let cid = slab.insert(round, clock.now()).unwrap();
        assert!(!cid.is_unbound());
        assert!(active_set.insert(cid) || round >= 255);
        assert_eq!(slab.get(cid), Some(&round));
        assert_eq!(slab.remove(cid, clock.now()), Some(round));
        if slab.quarantined_len() > 0 {
            clock.advance(Duration::from_secs(60));
        }
    }
    // Backing vector stayed tiny (1 slot reused after 60 s quarantine reclamation!).
    assert!(slab.slot_count() <= 2, "slot_count grew unboundedly: {}", slab.slot_count());
}

#[test]
fn mtu_reporter_renewal_driver_and_trust_enforcement_conformance() {
    let rt = TestRuntime::new();

    // MtuReporter + Origin/Dest/Transit PathMtu.
    assert!(advance_epoch(u32::MAX, 0));
    let mut rep = MtuReporter::with_initial(1232);
    assert_eq!(rep.publish(1200, rt.clock.now()), Some((1, 1200)));
    for delay in MTU_RETRY_DELAYS {
        rt.clock.advance(delay);
        assert_eq!(rep.poll_retry(rt.clock.now()), Some((1, 1200)));
    }
    let mut orig_mtu = OriginPathMtu::new(vec![1232, 1232], 1152);
    assert_eq!(orig_mtu.on_dest_mtu(1, 1180), MtuChange::Changed(1180));
    let mut dest_mtu = DestPathMtu::new(1232, 1232, 1152);
    assert_eq!(dest_mtu.on_origin_mtu(1, 1180), MtuChange::Changed(1180));
    assert_eq!(dest_mtu.on_origin_mtu(1, 1160), MtuChange::Unchanged);
    let mut tr_mtu = TransitPathMtu::new(1232, 1232, 1152);
    assert!(matches!(
        tr_mtu.clamp_leg(true, 1100, rt.clock.now()),
        TransitMtuEvent::FloorViolation { mtu: 1100, .. }
    ));

    // RenewalDriver + RenewalVerifierState.
    let mut rng = DetRng(12345);
    let mut drv = RenewalDriver::new(
        Plane::Stream,
        Duration::from_secs(10),
        Credential::empty(),
        vec![(Duration::from_secs(10), Credential::empty())],
        rt.clock.now(),
        &mut rng,
    );
    let dl = drv.next_deadline().unwrap();
    rt.clock.advance_to(dl);
    let acts = drv.poll_actions(rt.clock.now(), &mut rng);
    assert!(!acts.is_empty());
    let first_slot = match &acts[0] {
        RenewalAction::FetchCredential { slot, .. } => *slot,
        other => panic!("expected fetch, got {other:?}"),
    };
    let send = drv.on_credential_fetched(
        first_slot,
        Ok(Credential::from_slice(b"tok2").unwrap()),
        rt.clock.now(),
        &mut rng,
    );
    assert!(matches!(send, CredentialFetchOutcome::Send { renewal_id: 1, .. }));
    let mut verifier = RenewalVerifierState::new();
    assert_eq!(verifier.classify(1), VerifierRenewalAction::AuthorizeNew(1));
    verifier.complete(1, true);
    assert_eq!(verifier.classify(1), VerifierRenewalAction::ReplyIdempotent(1));
    assert_eq!(
        drv.on_ack(first_slot, 1, Duration::from_secs(10), rt.clock.now(), &mut rng),
        Ok(true)
    );

    // AuthGate + LeaseHandle + IntersectAuthorizer + PublishRegistry + AuthEpochTable overflow.
    let metrics = Arc::new(ScopeMetrics::new());
    let reg = Arc::new(PublishRegistry::new(Arc::clone(&metrics)));
    let peer = PublicKey::from_bytes([0xCC; 32]);

    struct StaticAuth(Duration, &'static str);
    impl Authorizer for StaticAuth {
        fn authorize<'a>(&'a self, _req: AuthRequest<'a>) -> BoxFuture<'a, Result<Lease, AuthDenied>> {
            Box::pin(async move { Ok(Lease::new(self.0).with_context(self.1.to_string())) })
        }
    }
    let combined = Arc::new(IntersectAuthorizer::new(
        Arc::new(StaticAuth(Duration::from_secs(30), "local")),
        Arc::new(StaticAuth(Duration::from_secs(90), "ext")),
    ));
    let gate = AuthGate::new(
        combined,
        AuthLimits::default(),
        rt.clock.clone(),
        Arc::clone(&reg),
        Arc::clone(&metrics),
    );
    let _pending = gate.acquire_pending(peer).unwrap();
    let lease = rt
        .spawner
        .try_block_on(gate.authorize(AuthRequest {
            peer,
            target: TargetRef::Endpoint {
                name: "ep",
                plane: Plane::Datagram,
            },
            credential: &[],
            is_renewal: false,
        }))
        .unwrap()
        .unwrap();
    assert_eq!(lease.ttl, Duration::from_secs(30));
    assert_eq!(
        lease.extensions.get::<String>().as_deref().map(String::as_str),
        Some("local")
    );

    let handle = LeaseHandle::new(peer, lease, Duration::from_secs(60), rt.clock.clone()).unwrap();
    let mut cache = TrafficGateCache::new();
    assert!(cache.get(&handle).is_none());

    let idx = RevocationIndex::new();
    idx.insert(RevocationKey::Peer(peer), &handle);
    assert_eq!(idx.revoke_key(&RevocationKey::Peer(peer), &CoreError::Revoked), 1);
    assert_eq!(handle.remaining(), Err(CoreError::Revoked));

    // AuthEpochTable overflow bound.
    let mut epochs = AuthEpochTable::new();
    for i in 0..=MAX_EPOCHS {
        epochs.bump_endpoint(&format!("e{i}"));
    }
    assert_eq!(epochs.global_epoch(), 1);
    assert_eq!(epochs.total_entries(), 0);

    // TransitEpochTarget TOCTOU check.
    struct DummyDgTr;
    impl DatagramTransitHandler for DummyDgTr {
        fn caps(&self) -> ChannelCaps { ChannelCaps::fixed(1232, false) }
        fn open<'a>(&'a self, _: &'a str, _: confluence_core::auth::SessionAuth) -> BoxFuture<'a, Result<Arc<dyn DatagramLink>, CoreError>> {
            Box::pin(async { Err(CoreError::Closed) })
        }
    }
    struct DummyStEp;
    impl StreamEndpointHandler for DummyStEp {
        fn open(&self, _: confluence_core::auth::SessionAuth) -> BoxFuture<'_, Result<confluence_core::channel::BoxedStream, CoreError>> {
            Box::pin(async { Err(CoreError::Closed) })
        }
    }
    struct DummyDgEp;
    impl DatagramEndpointHandler for DummyDgEp {
        fn open(&self, _: confluence_core::auth::SessionAuth) -> BoxFuture<'_, Result<Arc<dyn DatagramLink>, CoreError>> {
            Box::pin(async { Err(CoreError::Closed) })
        }
    }

    let _ep_st = reg.publish_stream_endpoint("st-ep", Arc::new(DummyStEp)).unwrap();
    let _ep_dg = reg.publish_datagram_endpoint("dg-ep", 1152, Arc::new(DummyDgEp)).unwrap();
    let g_tr = reg.publish_datagram_transit_prefix("p/", Arc::new(DummyDgTr)).unwrap();
    let res = reg.resolve_transit("p/sub", Plane::Datagram).unwrap();
    let target = TransitEpochTarget {
        peer,
        plane: Plane::Datagram,
        full_name: "p/sub",
        matched_prefix: Some("p/"),
        pub_id: res.pub_id,
        subtarget: "sub",
    };
    let snap = reg.epoch_for_transit(&target);
    g_tr.revoker().unwrap().revoke_target("sub").unwrap();
    let h2 = LeaseHandle::from_ttl(peer, Duration::from_secs(10), Duration::from_secs(60), rt.clock.clone()).unwrap();
    assert_eq!(reg.track_transit(&snap, &target, &res.active, &h2), Err(CoreError::Revoked));
}

#[test]
fn seam_ergonomics_rpitit_arc_link_ext_and_combinators() {
    let rt = TestRuntime::new();

    // Custom RPITIT vertical wrapper composing statically over MemoryDatagramCarrier.
    struct PrefixLink<L> {
        inner: L,
        id: LinkId,
    }
    impl<L: DatagramLink> DatagramLink for PrefixLink<L> {
        fn caps(&self) -> ChannelCaps {
            self.inner.caps().with_overhead(4)
        }
        fn poll_send_ready(&self, cx: &mut core::task::Context<'_>) -> core::task::Poll<Result<(), CoreError>> {
            self.inner.poll_send_ready(cx)
        }
        fn try_send(&self, mut packet: PacketBuf) -> Result<(), CoreError> {
            packet.prepend_header(&[0xDE, 0xAD, 0xBE, 0xEF])?;
            self.inner.try_send(packet)
        }
        fn poll_recv(&self, cx: &mut core::task::Context<'_>) -> core::task::Poll<Result<PacketBuf, CoreError>> {
            match self.inner.poll_recv(cx) {
                core::task::Poll::Ready(Ok(mut pkt)) => {
                    pkt.strip_header(4)?;
                    core::task::Poll::Ready(Ok(pkt))
                }
                other => other,
            }
        }
        fn link_id(&self) -> LinkId {
            self.id
        }
    }
    struct PrefixCarrier<C>(C);
    impl<C: DatagramCarrier> DatagramCarrier for PrefixCarrier<C> {
        type Link = PrefixLink<C::Link>;
        fn caps(&self) -> ChannelCaps {
            self.0.caps().with_overhead(4)
        }
        async fn open_link(&self, locator: &[u8]) -> Result<Self::Link, CoreError> {
            let inner = self.0.open_link(locator).await?;
            Ok(PrefixLink { inner, id: LinkId::allocate() })
        }
    }

    let (dg_carrier, dg_listener, _dg_mtu) = memory_datagram_channel(1232);
    let wrapped = Arc::new(PrefixCarrier(dg_carrier));
    assert_eq!(wrapped.caps().mtu(), 1228);

    // StaticTransit & DynamicTransit over RPITIT carriers + Arc<L> blanket DatagramLink.
    let static_dg = StaticTransit::new(Arc::clone(&wrapped), b"peer-a".to_vec());
    let dyn_dg = DynamicTransit::new(Arc::clone(&wrapped));
    assert_eq!(static_dg.caps().mtu(), 1228);
    assert_eq!(dyn_dg.caps().mtu(), 1228);

    let (st_carrier, st_listener, _st_mtu) = memory_stream_channel(16_384);
    let st_arc = Arc::new(st_carrier);
    let static_st = StaticTransit::new(Arc::clone(&st_arc), b"loc".to_vec());
    let dyn_st = DynamicTransit::new(Arc::clone(&st_arc));
    assert_eq!(static_st.caps().mtu(), 16_384);
    assert_eq!(dyn_st.caps().mtu(), 16_384);

    // StreamReadExt / StreamWriteExt & DatagramLinkExt zero-alloc async helpers.
    let st_pair = MemoryStreamPair::pair(4096);
    let (_ar, mut aw) = st_pair.a.into_halves();
    let (mut br, _bw) = st_pair.b.into_halves();
    rt.spawner.spawn(Box::pin(async move {
        aw.write_all(b"confluence").await.unwrap();
        aw.flush().await.unwrap();
        aw.shutdown().await.unwrap();
    }));
    let mut read_buf = [0u8; 10];
    assert_eq!(rt.spawner.try_block_on(br.read_exact(&mut read_buf)), Some(Ok(())));
    assert_eq!(&read_buf, b"confluence");

    let dg_pair = MemoryDatagramPair::pair(1232);
    assert_eq!(
        rt.spawner.try_block_on(dg_pair.a.send(PacketBuf::from_payload(b"ping"))),
        Some(Ok(()))
    );
    let got = rt.spawner.try_block_on(dg_pair.b.recv()).unwrap().unwrap();
    assert_eq!(got.payload(), b"ping");

    // EmptyCredentials & revocation_channel & MtuWatch basic smoke.
    let creds = EmptyCredentials;
    let c = rt
        .spawner
        .try_block_on(creds.credential(CredentialRequest {
            verifier: PublicKey::from_bytes([1; 32]),
            target: TargetRef::Endpoint { name: "ep", plane: Plane::Stream },
            destination: PublicKey::from_bytes([1; 32]),
            endpoint: "ep",
            path_id: 1,
            is_refresh: false,
            prior: &[],
        }))
        .unwrap()
        .unwrap();
    assert!(c.is_empty());

    let (rtx, mut rrx) = revocation_channel(2);
    rtx.send(Revocation::All);
    assert_eq!(rt.spawner.try_block_on(rrx.recv()), Some(Ok(Revocation::All)));

    let (_mtx, mw) = MtuWatch::channel(1500);
    assert_eq!(mw.with_overhead(28).with_cap(1232).current(), 1232);

    // Exercise RPITIT StreamCarrier/StreamListener and DatagramCarrier/DatagramListener end-to-end.
    let _dialed_st = rt.spawner.try_block_on(st_arc.dial_stream(b"loc")).unwrap().unwrap();
    let _accepted_st = rt.spawner.try_block_on(st_listener.accept()).unwrap().unwrap();
    let _opened_dg = rt.spawner.try_block_on(wrapped.open_link(b"peer")).unwrap().unwrap();
    let _accepted_dg = rt.spawner.try_block_on(dg_listener.accept_link()).unwrap().unwrap();

    let _ = (
        <StaticTransit<PrefixCarrier<_>> as DatagramTransitHandler>::caps(&static_dg),
        <DynamicTransit<_> as StreamTransitHandler>::caps(&dyn_st),
        MemoryStreamPair::pair(1200).a.caps().mtu(),
        DatagramAction::Allow,
        StreamAction::Allow,
    );
}

#[test]
fn independent_noise_ik_transcript_verifies_tail_aad_before_target_pk() {
    use x25519_dalek::{PublicKey as XPk, StaticSecret as XSec};

    let origin_secret = [0x11u8; 32];
    let dest_secret = [0x22u8; 32];
    let origin = ScopeKeypair::from_secret_bytes(origin_secret);
    let dest = ScopeKeypair::from_secret_bytes(dest_secret);
    let tail_aad = *blake3::hash(b"exact-dispatch-prefix-and-tail").as_bytes();
    let wall = 1_700_000_000_000u64;
    let pt = SetupPlaintext::encode(wall, "verify", b"secret").unwrap();

    let (_init, seg) =
        Initiator::build_message1(&origin, dest.public_key(), &tail_aad, &pt, None).unwrap();

    // Independently decrypt Message 1 directly from Section 4.4 formulas!
    let mix_hash = |h: &mut [u8; 32], data: &[u8]| {
        let mut hasher = blake3::Hasher::new();
        hasher.update(h);
        hasher.update(data);
        *h = *hasher.finalize().as_bytes();
    };
    let mix_key = |ck: &mut [u8; 32], k: &mut [u8; 32], dh: &[u8; 32]| {
        let prk = *blake3::keyed_hash(ck, dh).as_bytes();
        *ck = *blake3::keyed_hash(&prk, b"chaining key").as_bytes();
        *k = *blake3::keyed_hash(&prk, b"cipher key").as_bytes();
    };

    let init_hash = *blake3::hash(b"Noise_IK_25519_ChaChaPoly_BLAKE3+confluence-v1").as_bytes();
    let mut ck = init_hash;
    let mut h = init_hash;
    let mut k = [0u8; 32];

    // Spec §4.4.1: MUST mix `tail_aad` BEFORE `target_pk`.
    mix_hash(&mut h, &tail_aad);
    mix_hash(&mut h, dest.public_key().as_bytes());

    let e_i: [u8; 32] = seg[8..40].try_into().unwrap();
    mix_hash(&mut h, &e_i);

    let s_r = XSec::from(dest_secret);
    let dh_es = s_r.diffie_hellman(&XPk::from(e_i)).to_bytes();
    mix_key(&mut ck, &mut k, &dh_es);

    let mut dec_s = seg[40..72].to_vec();
    let tag_s = Tag::from_slice(&seg[72..88]);
    ChaCha20Poly1305::new((&k).into())
        .decrypt_in_place_detached(Nonce::from_slice(&[0u8; 12]), &h, &mut dec_s, tag_s)
        .expect("Message 1 static key decryption failed — check tail_aad ordering!");
    assert_eq!(dec_s.as_slice(), origin.public_key().as_bytes());

    let mut ct_s_with_tag = Vec::new();
    ct_s_with_tag.extend_from_slice(&seg[40..88]);
    mix_hash(&mut h, &ct_s_with_tag);

    let s_i: [u8; 32] = dec_s.try_into().unwrap();
    let dh_ss = s_r.diffie_hellman(&XPk::from(s_i)).to_bytes();
    mix_key(&mut ck, &mut k, &dh_ss);

    let ct_end = seg.len() - 32;
    let mut dec_pt = seg[88..ct_end].to_vec();
    let tag_p = Tag::from_slice(&seg[ct_end..ct_end + 16]);
    ChaCha20Poly1305::new((&k).into())
        .decrypt_in_place_detached(Nonce::from_slice(&[0u8; 12]), &h, &mut dec_pt, tag_p)
        .expect("Message 1 payload decryption failed!");
    assert_eq!(dec_pt.as_slice(), &*pt);
}
