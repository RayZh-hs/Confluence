use confluence_core::{
    CoreErr, PacketBuf, ScopeKeypair,
    cid::{Cid, SlabTable},
    crypto::{
        aead::{DatagramRx, DatagramTx},
        noise_ik::{self, Responder},
        replay::SetupReplay,
    },
    wire::{e2e, hop, setup},
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    time::{SystemTime, UNIX_EPOCH},
};

struct AllocationCounter;
thread_local! {
    static ALLOCS: Cell<Option<usize>> = const { Cell::new(None) };
}
fn record_allocation() {
    let _ = ALLOCS.try_with(|count| {
        if let Some(value) = count.get() {
            count.set(Some(value + 1));
        }
    });
}
unsafe impl GlobalAlloc for AllocationCounter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        unsafe { System.alloc(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_allocation();
        unsafe { System.realloc(ptr, layout, new_size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: AllocationCounter = AllocationCounter;

#[test]
fn invalid_mac_and_unknown_kid_allocate_nothing() {
    let a = ScopeKeypair::generate();
    let b = ScopeKeypair::generate();
    let now = now_ms();
    let aad = [0; 32];
    let replay = SetupReplay::default();
    let (mut segment, _) =
        noise_ik::initiate(&a, b.public_key(), &aad, &now.to_be_bytes()).unwrap();
    *segment.last_mut().unwrap() ^= 1;
    ALLOCS.with(|count| count.set(Some(0)));
    let bad_mac = Responder::accept(&b, &replay, &segment, &aad, now);
    segment[0] ^= 1;
    let bad_kid = Responder::accept(&b, &replay, &segment, &aad, now);
    let allocations = ALLOCS.with(|count| count.replace(None));
    assert!(matches!(bad_mac, Err(CoreErr::Authentication)));
    assert!(matches!(bad_kid, Err(CoreErr::Authentication)));
    assert_eq!(allocations, Some(0));
}

#[test]
fn datagram_aead_and_label_rewrite_keep_payload_in_place() {
    let mut tx = DatagramTx::new([9; 32]);
    let mut rx = DatagramRx::new([9; 32]);
    for size in [0, 1, 17, 128, 1202, 16000, 65_505] {
        let payload = vec![size as u8; size];
        let mut packet = PacketBuf::with_payload_cap(size);
        packet.spare_payload().copy_from_slice(&payload);
        assert!(packet.advance_payload(size));
        let addr = packet.as_slice().as_ptr();
        ALLOCS.with(|count| count.set(Some(0)));
        let mut packet = tx.seal(e2e::DG_DATA, packet).unwrap();
        assert!(packet.prepend_header(&hop::datagram_data(Cid::from_raw(42))));
        packet.as_mut_slice()[1..5].copy_from_slice(&77u32.to_be_bytes());
        assert!(packet.strip_header(5));
        let (kind, packet) = rx.open(packet).unwrap();
        let allocations = ALLOCS.with(|count| count.replace(None));
        assert_eq!(allocations, Some(0));
        assert_eq!(kind, e2e::DG_DATA);
        assert_eq!(packet.as_slice().as_ptr(), addr);
        assert_eq!(packet.as_slice(), &payload);
    }
}

#[test]
fn circuit_generations_never_alias_after_wrap_and_are_scoped_per_link() {
    let mut first = SlabTable::new(1);
    let mut second = SlabTable::new(1);
    let old = first.insert("first link").unwrap();
    let other = second.insert("second link").unwrap();
    assert_eq!(old, other);
    assert_ne!(first.get(old), second.get(old));
    assert_eq!(first.remove(old), Some("first link"));
    for _ in 0..700 {
        let live = first.insert("new").unwrap();
        assert_ne!(live, old);
        assert_eq!(first.get(old), None);
        first.remove(live).unwrap();
    }
    assert_eq!(second.get(other), Some(&"second link"));
    assert_eq!(first.get(Cid::UNBOUND), None);
}

#[test]
fn nested_tail_and_prefix_mutations_fail_authentication_and_flight_cannot_replay() {
    let a = ScopeKeypair::generate();
    let h = ScopeKeypair::generate();
    let b = ScopeKeypair::generate();
    let now = now_ms();
    let replay = SetupReplay::default();
    let prefix = [1, 1, 0, 0, 42];
    let tail = b"remaining hops plus B's terminal frame";
    let original = setup::tail_aad(&prefix, tail);
    let plain = noise_ik::hop_plaintext(now, b"credential", b"locator").unwrap();
    let (segment, initiate) = noise_ik::initiate(&a, h.public_key(), &original, &plain).unwrap();
    for offset in 0..tail.len() {
        let mut changed = tail.to_vec();
        changed[offset] ^= 1;
        assert!(matches!(
            Responder::accept(
                &h,
                &replay,
                &segment,
                &setup::tail_aad(&prefix, &changed),
                now
            ),
            Err(CoreErr::Authentication)
        ));
    }
    let opened = Responder::accept(&h, &replay, &segment, &original, now).unwrap();
    assert_eq!(opened.peer, a.public_key());
    assert_eq!(opened.plaintext, plain);
    assert!(Responder::accept(&h, &replay, &segment, &original, now).is_err());
    assert!(
        Responder::accept(
            &h,
            &SetupReplay::default(),
            &segment,
            &original,
            now + 31_000
        )
        .is_err()
    );

    let ack = [12; 18];
    let (reply, remote) = opened.reply(&ack).unwrap();
    let (clear, local) = initiate.finish(&a, &reply).unwrap();
    assert_eq!(clear, ack);
    assert_eq!(local.tx, remote.rx);
    assert_eq!(local.rx, remote.tx);
    assert_ne!(local.tx, local.rx);
    assert_ne!(b.kid(), h.kid());
    assert_ne!(b.public_key(), h.public_key());
}

#[test]
fn datagram_corruption_does_not_consume_a_sequence_or_advance_replay() {
    let mut tx = DatagramTx::new([3; 32]);
    let mut rx = DatagramRx::new([3; 32]);
    let sent = tx
        .seal(e2e::DG_DATA, PacketBuf::from_slice(b"reordered"))
        .unwrap();
    let mut corrupt = PacketBuf::from_slice(sent.as_slice());
    *corrupt.as_mut_slice().last_mut().unwrap() ^= 1;
    assert!(matches!(rx.open(corrupt), Err(CoreErr::Authentication)));
    assert_eq!(
        rx.open(PacketBuf::from_slice(sent.as_slice()))
            .unwrap()
            .1
            .as_slice(),
        b"reordered"
    );
    assert!(matches!(rx.open(sent), Err(CoreErr::Authentication)));
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
