# Document 1: Confluence Core v1 — Protocol & Behavioral Specification

## 1. Scope, Core Abstraction & Invariants

Confluence Core is a cleanroom A-to-B connectivity engine that connects an explicitly published endpoint on Originator `A` to an explicitly published endpoint on Destination `B` across an explicit, composable path. The Core strictly separates data movement, access verification, and local application attachment behind four narrow extension seams: **Channels**, **Route / Path Source**, **Access Control**, and **Edge Adapters**.

### 1.1 Architectural Non-Goals & Operational Boundaries

* **Opaque Payload Transport:** The Core transports only discrete datagrams and continuous byte streams without parsing or terminating application, L3, or L4 protocols.


* **Strict Two-Plane Separation:** The **Datagram Plane** and **Stream Plane** never implicitly convert into one another inside the Core. Crossing planes requires an explicit out-of-core adapter plugin (`Stream-over-Datagram` or `Datagram-over-Stream`) presenting the standard Channel contract.


* **Single-Path Execution Only:** The Core executes one explicit path supplied per dial attempt and reports failures honestly upward; peer discovery, candidate-path probing, racing, and failover remain outside the Core.


* **Verifier, Never Issuer:** The Core verifies cryptographic peer identity and queries the Access Control seam on control events only, enforcing the resulting time- and rate-bounded **Grant** on the data path while intersecting with local host veto rules.


* **Zero Default Network Endpoints:** A Confluence instance runs unprivileged by default, isolates state and keys per **Trust Scope**, exposes zero built-in network control endpoints, and makes only explicitly published named endpoints reachable. Circuit control travels strictly in-band, while host administration stays on local OS IPC.


* **1-to-1 Session Cardinality:** Each dial attempt (`A → B`) establishes exactly one bidirectional stream or one bidirectional datagram flow; destination `B` cannot spawn reverse sub-streams back toward `A`, and multiplexing (when desired) lives in composable Channel wrappers or Passive Relay plugins.



### 1.2 Threat & Link-Security Model

* **Untrusted Intermediaries:** Every intermediate node and transport carrier is treated as untrusted infrastructure relied upon solely for packet liveness and bandwidth. End-to-end payloads remain confidential, integrity-protected, and mutually authenticated between `A` and `B`.


* **No Transitive Multi-Hop Trust:** Each hop's targeted outbound channel authenticates Originator `A` directly (`channel ↔ originator`) in a single forward pass. Compromised upstream hops cannot read downstream credentials, impersonate `A`, or splice a valid hop header onto an altered downstream route tail.


* **Carrier Link Security Boundary:** Native carriers stay pure and delegate link-layer confidentiality or obfuscation to the node operator's chosen channel stack. Unencrypted raw carriers are intended strictly for trusted underlays (e.g., loopback, private LAN, or pre-encrypted links), whereas untrusted networks use encrypted or obfuscated channel plugins so on-path observers gain no visibility into outer Confluence headers. Even on raw links, circuit identifiers are scoped per inbound link handle so one neighbor cannot address circuits bound to another link.



---

## 2. Cryptographic Suite & Handshake Construction (v1)

Protocol v1 uses a single fixed cryptographic suite (**X25519 + ChaCha20-Poly1305 + BLAKE3**) with resumption tickets deferred to future versions.

* **Per-Scope Static Identity:** Each node holds an independent X25519 static keypair `(s_node, S_node)` per Trust Scope so participation in multiple scopes never links identities across scopes.


* **Unlinkable Key Identifier (`scope_kid`, 8 B):** Computed as `BLAKE3_derive_key("confluence-v1-kid", S_target)[0..8]`. Receivers resolve the targeted Trust Scope and static key in $O(1)$ without exposing static public keys in cleartext.


* **Pre-DH Volumetric Filter (`mac1`, 16 B):** Computed as `BLAKE3_keyed(BLAKE3_derive_key("confluence-v1-mac1", S_target), frame_bytes_before_mac1)[0..16]`. Invalid `scope_kid` or `mac1` values are silently discarded in constant time without heap allocation or X25519 scalar multiplication.


* **1-RTT `Noise_IK` Envelope:**
* **Forward Setup (`-> e, es, s, ss`):** Originator `A` generates an independent ephemeral X25519 keypair `(e_ai, E_ai)` for *each* intermediate hop `Hᵢ` and `(e_ab, E_ab)` for `B`, preventing colluding hops from correlating `A`'s ephemeral keys. `A`'s static key `S_a` is encrypted under `es = DH(e_ai, S_target)`, and inner setup parameters + credentials are sealed under `es + ss = DH(s_a, S_target)`.


* **Route Tail Binding (AEAD AAD):** When sealing hop `i`'s setup segment, `A` passes `BLAKE3(Dispatch_Prefix[i] || Remaining_Tail[i])` as Associated Data (AAD). Any upstream mutation of downstream hop frames or `B`'s terminal frame invalidates AEAD verification at hop `i`, causing silent discard.


* **Return Confirmation (`<- e, ee, se`):** Destination `B` generates fresh ephemeral `(e_b, E_b)` in `SETUP_OK`, completing mutual forward-secret authentication (`K_ab_tx`, `K_ab_rx`) and signing the clamped forward MTU. Each intermediate hop derives a symmetric hop control key `K_hop_i` from its `Noise_IK` handshake state (`es + ss`) to authenticate `SETUP_ERR`, `HOP_RENEW`, and `HOP_CLOSE` frames.





---

## 3. Wire Framing Specification

All multi-byte integers are unsigned big-endian. Byte `0` (`ver_type`) encodes protocol version (`0x1_`, `0x2_`, `0x3_`) and frame class for single-branch dispatch. Circuit identifiers (`Cid`) are 32-bit packed integers `[generation: 8 bits | slot_idx: 24 bits]` (`Cid(0)` reserved for unbound Hop-0 setup) scoped to `(inbound_link_id, cid)`.

### 3.1 Single-Pass Control Setup Frames (`0x11`–`0x13`)

On the Datagram Plane, setup frames travel as discrete datagrams; on the Stream Plane, they travel as the opening bytes on a newly dialed carrier stream prior to chunk splicing.

```text
SETUP_FWD (0x11) — Pipelined 1-RTT Forward Pass (shrinks at each hop)
+=============================================================================+
| Mutable Link Header (8 B — rewritten per hop by Path Engine)                |
|   ver_type=0x11 (1B) | flags (1B) | max_mtu (2B) | upstream_cid (4B)        |
+=============================================================================+
| Hop[i] Dispatch Prefix (16 B — cleartext, hashed into Hop[i] AEAD AAD)      |
|   mode=0x01 (1B) | plane (1B) | min_mtu (2B) | chan_tag (8B)                |
|   hop_seg_len (2B) | tail_len (2B)                                          |
+-----------------------------------------------------------------------------+
| Hop[i] Opaque Setup Segment (hop_seg_len B — dispatched to Channel Plugin)  |
|   scope_kid (8B) | E_ai (32B) | enc_S_a (48B) | enc_hop_params (var)        |
|   mac1 (16B)                                                                |
+-----------------------------------------------------------------------------+
| Remaining Tail (tail_len B — byte-for-byte immutable across upstream hops)  |
|   [ Hop[i+1] ... | DestFrame[B] ]                                           |
+=============================================================================+

DestFrame[B] — Innermost Terminal Frame
+-----------------------------------------------------------------------------+
| mode=0x02 (1B) | plane (1B) | min_mtu (2B) | e2e_seg_len (2B)               |
| scope_kid (8B) | E_ab (32B) | enc_S_a (48B) | enc_e2e_params (var)          |
| mac1 (16B)                                                                  |
+-----------------------------------------------------------------------------+

```

* **Encrypted Hop Plaintext (`enc_hop_params`):** `timestamp_ms (8B) | cred_len (2B) | cred (0..96B) | inner_len (2B) | inner_params (var)`. `inner_params` carries opaque next-hop dial locators, registered passive-relay presence IDs, or nested wrapper parameters.


* **Encrypted Destination Plaintext (`enc_e2e_params`):** `timestamp_ms (8B) | ep_len (1B) | endpoint_name (UTF-8) | cred_len (2B) | cred (0..96B)`.


* **Datagram Setup Byte Budget:** With a mandated **1232-byte** minimum Datagram Channel payload ceiling, `SETUP_FWD` requires `8 B` mutable header + `164–260 B` per intermediate hop (`0–96 B` credential) + `153–249 B` for `B`, fitting 3 full-credential hops (`~1,037 B`) or 5 allowlist hops (`~981 B`) in a single unfragmented datagram.


* **`SETUP_OK` (`0x12`, `78 B` total):**
* **Mutable Link Header (`12 B`):** `ver_type=0x12 (1B) | flags (1B) | rev_max_mtu (2B) | target_cid (4B) | responder_cid (4B)`.


* **E2E Reply Payload (`66 B`):** `E_b (32B) | enc_setup_ack (34B: clamped_fwd_mtu u16 + grant_ttl_ms u64 + rate_bps u64 + 16B tag)`.




* **`SETUP_ERR` (`0x13`, `36 B` total):**
* **Mutable Link Header (`8 B`):** `ver_type=0x13 (1B) | hop_dist (1B) | reserved (2B) | target_cid (4B)`.
* **Error Payload (`28 B`):** `nonce (8B) | enc_err (20B: err_code u16 + actual_mtu u16 + 16B tag under K_hop_i)`. Sent *only* after `A` passes cryptographic authentication at the rejecting node.





### 3.2 Steady-State Hop Layer & End-to-End (E2E) Layer

Steady-state forwarding separates untrusted hop headers from end-to-end AEAD records so intermediate hops switch labels or splice chunks with **zero per-packet cryptography**, while supporting in-band Grant renewal and authenticated teardown.

| Plane & Layer | `ver_type` / Record Type | Wire Header Layout | Behavioral Rule |
| --- | --- | --- | --- |
| **Datagram Hop Data** | `0x20` (`DG_DATA`) | `0x20 (1B) | cid (4B)` (**`5 B`**) | $O(1)$ `(in_link, cid) -> (out_link, out_cid)` rewrite after atomic Grant check.

 |
| **Datagram Hop Ctrl** | `0x21` `HOP_RENEW`<br>

<br>`0x22` `HOP_RENEW_OK`<br>

<br>`0x23` `HOP_CLOSE`<br>

<br>`0x24` `MTU_HINT` | `type (1B) | ttl (1B) | cid (4B)` (**`6 B`**) + body | Forwarded while `ttl > 0` (`ttl -= 1`); consumed at `ttl == 0` and verified under `K_hop_i` (except advisory `MTU_HINT`).

 |
| **Stream Hop Chunk** | `0x30` `ST_DATA`<br>

<br>`0x31` `HOP_RENEW`<br>

<br>`0x32` `HOP_RENEW_OK`<br>

<br>`0x33` `HOP_CLOSE` | `type (1B) | ttl (1B) | chunk_len (2B)` (**`4 B`**, max `16384 B`) | `0x30` splices cut-through with backpressure; `0x31`–`0x33` interleave between chunks and authenticate under `K_hop_i` at `ttl == 0`.

 |
| **Datagram E2E** *(inside `DG_DATA`)* | `0x01` `DATA`<br>

<br>`0x02` `E2E_RENEW`<br>

<br>`0x03` `E2E_RENEW_OK`<br>

<br>`0x04` `E2E_CLOSE`<br>

<br>`0x05` `MTU_PROBE`<br>

<br>`0x06` `MTU_PROBE_ACK` | `seq_no (8B) | enc(e2e_type 1B + payload) | tag (16B)` (**`25 B`** E2E; **`30 B`** total wire overhead) | ChaCha20-Poly1305 under `K_ab` with 64-packet sliding anti-replay bitmap; **invalid AEAD tags drop silently** without tearing down session. Preserves `1202 B` payload on `1232 B` carriers.

 |
| **Stream E2E** *(inside `ST_DATA`)* | `0x00` `OPEN_OK`<br>

<br>`0x01` `TARGET_REFUSED`<br>

<br>`0x02` `TARGET_UNREACHABLE`<br>

<br>`0x10` `DATA`<br>

<br>`0x11` `E2E_FIN`<br>

<br>`0x12` `E2E_RENEW`<br>

<br>`0x13` `E2E_RENEW_OK` | `len (2B, AAD, <= 16365) | enc(e2e_type 1B + body) | tag (16B)` (**`19 B`** E2E overhead) | Implicit monotonic `u64` nonce (`0, 1, ...`) per direction. `B`'s record `0` is the status preamble; `E2E_FIN` gives authenticated half-close (`EOF`), whereas carrier drop without `E2E_FIN` raises `UnexpectedEof`.

 |

---

## 4. Behavioral State Machines & Lifecycle Flows

### 4.1 Strict Pre-Authentication Gate Order

Every node receiving `SETUP_FWD` (at a forwardable Channel plugin or `B`'s E2E boundary) executes five checks strictly in order, **silently discarding** on any failure without allocating circuit slots:

1. **Scope Lookup:** Match `scope_kid` against active local Trust Scopes in $O(1)$.


2. **Constant-Time `mac1`:** Verify `mac1` on the raw packet buffer with zero heap allocation.


3. **Replay & Clock Skew Guard:** Check `(E_a, timestamp_ms)` against a ±30 s skew bound and lock-free sliding replay ring *before* running X25519.


4. **Noise `IK` Open & Tail AAD Check:** Compute X25519 `es` and `ss`, verify `BLAKE3(Dispatch_Prefix || Remaining_Tail)` AAD, and decrypt `S_a` and inner parameters.


5. **Bounded Policy Verification:** Check per-originator pending-setup quota, verify requested endpoint/channel publication and plane match, and invoke `AccessControl::verify` under a hard concurrency cap and timeout (failing closed on error or timeout), intersected with local host policy.



### 4.2 1-RTT Path Establishment & Deferred Destination Open (`t = 1.0 RTT`)

1. **Originator Pre-Dial (`A`):** `A` loads *only* its local Hop-0 channel plugin (never remote hop plugins or server configs), validates Hop-0's plane and `effective_mtu >= min_mtu`, allocates an inbound `Cid`, and transmits `SETUP_FWD` with `max_mtu = Hop0.effective_mtu`.


2. **Intermediate Hop (`Hᵢ`):** After passing Section 4.1 via the targeted outbound channel plugin (`channel ↔ originator`), `Hᵢ` prepares the outbound handle (dialing next hop for active transit, or selecting `B`'s registered presence with zero outbound dialing for a passive relay). If `outbound.effective_mtu < min_mtu` or `< tail_len + 8`, `Hᵢ` aborts downstream setup and returns `SETUP_ERR(MTU_TOO_SMALL, outbound.effective_mtu)`. Otherwise, `Hᵢ` clamps `max_mtu = min(max_mtu, outbound.effective_mtu)`, allocates a `HalfOpen` slot (`3 s` TTL) storing `(in_link, caller_cid, K_hop_i, Grant)`, writes its new `upstream_cid` into the mutable header, and forwards `Remaining_Tail`.


3. **Destination `B` Arrival (`t = 0.5 RTT`):** `B` authenticates `A`, verifies the published endpoint and `max_mtu >= endpoint.min_mtu`, and obtains the endpoint `Grant`. **`B` does not open the local destination service on `SETUP_FWD**`. Instead, `B` allocates an `AwaitingConfirm` session (`3 s` TTL) and sends `SETUP_OK` containing `E_b` and signed `clamped_fwd_mtu`.


4. **Return Binding & `t = 1.0 RTT` Service Open:** Each hop matches `target_cid` to its `HalfOpen` slot, binds `responder_cid` as its forward outbound `Cid`, clamps `rev_max_mtu`, and atomically transitions the slot to `Active`. Upon receiving `SETUP_OK` at `t = 1.0 RTT`, `A` learns `session_mtu = min(clamped_fwd_mtu, rev_max_mtu)` and immediately transmits E2E frame `0` under `ee`-derived keys. `B` opens the local destination service via its Edge Adapter *only* upon decrypting `A`'s first `ee`-protected frame (sending `OPEN_OK` or `TARGET_REFUSED` on streams), guaranteeing replay immunity and zero leaked sockets if `SETUP_OK` drops in transit.



### 4.3 Three-Stage MTU Clamping & Mid-Session Drift

* **Zero-Extra-RTT Happy Path:** Clamping during `SETUP_FWD` / `SETUP_OK` discovers declared channel framing ceilings across arbitrary vertical stacks in `0` extra RTTs, paying `< 1 RTT` only on explicit `MTU_TOO_SMALL` rejection.


* **Synchronous Local Guard:** Oversize datagram writes from an Edge Adapter return `MessageTooLarge(session_max_payload)` synchronously without closing the session or transmitting on the wire.


* **Mid-Session Shrink & Blackhole Detection:** UDP-based carriers set `DF=1` (`IP_PMTUDISC_DO` / `IPV6_DONTFRAG`). If an intermediate hop encounters `EMSGSIZE` mid-session, it updates its channel's `effective_mtu` upward: if the new limit falls below `min_mtu`, it tears down the circuit immediately via authenticated `HOP_CLOSE`; otherwise, it sends rate-limited `DG_MTU_HINT` backward. Because intermediaries are untrusted, `A` never trusts `MTU_HINT` blindly—it clamps temporarily to `min_mtu` and runs padded E2E `MTU_PROBE` / `MTU_PROBE_ACK` frames (`A ↔ B`) to verify the physical ceiling. Optional background E2E probing also resolves silent L3 middlebox blackholes without Core fragmentation.



### 4.4 Grant Enforcement, In-Band Renewal & Immediate Teardown

* **Data-Path Enforcement:** Every active E2E boundary and hop handle enforces Grant expiration and byte-rate limits per packet or stream chunk quantum; expired frames drop immediately and trigger teardown.


* **Live In-Band Renewal:** At `75% ± 5%` random jitter of each Grant's TTL, `A` sends `HOP_RENEW(ttl = hop_idx)` and `E2E_RENEW` carrying refreshed opaque credentials. Each verifier re-queries `AccessControl::verify` intersected with local host policy and updates the active Grant's expiry and rate atomics in place via `HOP_RENEW_OK` / `E2E_RENEW_OK` without pausing data frames.


* **Immediate Revocation & Honest Failure:** Unpublishing a local endpoint, removing peer trust, local host veto, carrier link failure, or an `AccessControl` revocation event immediately cancels all matching handles on that node, emits authenticated `HOP_CLOSE` / `E2E_CLOSE` frames along bound paths, and reports structured teardown reasons upward to `Route / Path Source` and `Edge Adapters`.



---

---

# Document 2: Concrete Implementation Plan & Rust Code Structure

## 1. Cargo Workspace Topology & Crate Boundaries

Confluence is structured as a multi-crate Rust workspace where `confluence-core` is a pure, embeddable library crate with `#![forbid(unsafe_code)]` and **zero OS networking or filesystem I/O** (`std::net` and `tokio::net` are prohibited in Core). Channels and Edge Adapters run in-process on the zero-copy hot path, whereas `AccessControl` and `PathSource` run strictly on control events and can bridge either in-process or over local Unix sockets (enabling polyglot policy/routing daemons if desired).

```text
confluence/
├── Cargo.toml                  # Workspace root, lint table, feature flags
├── crates/
│   ├── confluence-core/        # Cleanroom Core library (zero OS/socket I/O)
│   ├── confluence-plugins/     # Reusable AuthAclWrapper, StaticAcl, StaticPathSource, MemChannels
│   ├── confluence-net/         # Pure native OS carriers: TCP stream & UDP (DF=1) datagram plugins
│   ├── confluence-edge/        # Local TCP/UDP port forwarders (with 16-pkt staging ring) & IPC admin
│   └── confluence-Relay/       # Optional zero-dialing Passive Relay plugin (out-of-core mux)
└── fuzz/                       # cargo-fuzz targets for wire parsers & state machines

```

* **Allowed `confluence-core` Dependencies:** `bytes`, `x25519-dalek`, `chacha20poly1305`, `blake3`, `rand_core`, `subtle` (constant-time comparisons), `tokio` (`sync` and `time` features only), `futures-core`, and `thiserror`.


* **Explicit Out-of-Core Delegation:** Vertical channel stack sanity (e.g., avoiding `Stream-over-Datagram` stacked over `Datagram-over-Stream`) belongs to node operators configuring channel stacks, and concurrent stream multiplexing over a single presence link belongs inside out-of-core Passive Relay or Mux wrapper plugins.



---

## 2. `confluence-core` Internal Module Layout

```text
crates/confluence-core/src/
├── lib.rs              # #![forbid(unsafe_code)], public API surface & error types
├── buf.rs              # PacketBuf: BytesMut wrapper with 64B headroom & 16B tailroom invariants
├── cid.rs              # Cid(u32) [8-bit gen | 24-bit idx] + per-link generational SlabTable<T>
├── grant.rs            # #[repr(align(64))] GrantEnforcer + sharded RevocationIndex
├── crypto/
│   ├── mod.rs          # ScopeKeypair, PublicKey, ScopeKid, constant-time mac1 helpers
│   ├── replay.rs       # Lock-free striped ring/bloom filter for (E_a, timestamp_ms)
│   ├── noise_ik.rs     # 1-RTT Noise_IK initiator/responder + K_hop / K_e2e key derivation
│   └── aead.rs         # E2E Stream & Datagram ChaCha20-Poly1305 codecs + 64-bit replay bitmap
├── wire/
│   ├── setup.rs        # Zero-copy codecs for SETUP_FWD, SETUP_OK, SETUP_ERR + tail BLAKE3 AAD
│   ├── hop.rs          # 5B/6B Datagram hop headers & 4B Stream prefix chunk codecs
│   └── e2e.rs          # E2E record codecs (OPEN_OK/REFUSED preamble, DATA, E2E_FIN, RENEW, PROBE)
├── seams/
│   ├── channel.rs      # Ergonomic StreamChannel & DatagramChannel traits + Dyn* adapters
│   ├── acl.rs          # AccessControl trait + PolicyGate (timeout, semaphore, host-veto intersect)
│   ├── path_source.rs  # PathSource trait, ExplicitPath, HopSpec, PathOutcome
│   └── endpoint.rs     # StreamEndpointHandler & DatagramEndpointHandler traits
├── path/
│   ├── dialer.rs       # Originator 1-RTT multi-hop builder, Hop-0 validator & SETUP_OK unwrapper
│   ├── inbound.rs      # Pre-auth gate pipeline, blind hop dispatch & HalfOpen TTL wheel
│   ├── dg_switch.rs    # Per-link Datagram SlabTable switching loop & HOP_CTRL handler
│   └── st_splice.rs    # Cut-through 16 KiB Stream chunk splicer with backpressure & HOP_CTRL
├── e2e/
│   ├── stream.rs       # E2eStream (AsyncRead/AsyncWrite-like slice API, 1.0 RTT deferred open)
│   ├── datagram.rs     # E2eDatagram (atomic current_mtu, DPLPMTUD state machine, silent bad-AEAD drop)
│   └── renewal.rs      # Background jittered (75% ± 5% TTL) HOP_RENEW & E2E_RENEW task driver
└── scope.rs            # ScopeInstance: isolated keys, channel registry, published endpoints

```

---

## 3. Core Data Structures & Hot-Path Concurrency Design

### 3.1 Zero-Copy `PacketBuf` (`buf.rs`)

To guarantee zero reallocation during E2E sealing and multi-hop header rewrites, `PacketBuf` wraps `bytes::BytesMut` with single-owner Rust move semantics:

```rust
pub const HEADROOM_BYTES: usize = 64; // Fits outer carrier prefix + 5B/8B hop hdr + 8B E2E seq_no
pub const TAILROOM_BYTES: usize = 16; // Fits 16B Poly1305 AEAD tag in place

pub struct PacketBuf {
    buf: bytes::BytesMut,
    head: usize, // Initialized to HEADROOM_BYTES
    tail: usize, // Payload end; capacity >= tail + TAILROOM_BYTES
}

```

* Inbound carrier plugins allocate buffers via `PacketBuf::with_payload_cap(mtu)` and read wire bytes starting at `head`, allowing `prepend_header(&[u8])`, `strip_header(n)`, and `seal_in_place(&aead)` to adjust integer offsets without copying payload memory.



### 3.2 Generational `Cid(u32)` & Per-Link `SlabTable` (`cid.rs`)

Each `InboundLinkId` owns an isolated `SlabTable<Slot>` so circuit lookups execute as a single bounds-checked `Vec` index without hashing or cross-link spoofing:

```rust
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Cid(u32); // [bits 31..24: generation (u8) | bits 23..0: slot_idx (u24)]

impl Cid {
    pub const UNBOUND: Self = Self(0);
    #[inline] pub fn slot_idx(self) -> usize { (self.0 & 0x00FF_FFFF) as usize }
    #[inline] pub fn generation(self) -> u8 { (self.0 >> 24) as u8 }
}

pub enum DatagramSlot {
    Vacant { next_free: u32 },
    HalfOpen {
        deadline_ms: u64,
        upstream_link: InboundLinkId,
        upstream_cid: Cid,
        hop_key: [u8; 32],
        grant: Arc<GrantEnforcer>,
    },
    Active {
        outbound_link: Arc<dyn DynDatagramLink>,
        outbound_cid: Cid,
        hop_key: [u8; 32],
        grant: Arc<GrantEnforcer>,
    },
}

```

* Releasing a slot increments its `generation` (`wrapping_add(1)`, skipping `Cid(0)` on slot `0`) so delayed or reordered UDP packets from a closed circuit fail `entry.generation == cid.generation()` and drop cleanly.

### 3.3 Cache-Line-Aligned `GrantEnforcer` & `RevocationIndex` (`grant.rs`)

Data paths never acquire locks to check policy:

```rust
#[repr(align(64))]
pub struct GrantEnforcer {
    expires_at_ms: AtomicU64,
    rate_bps: AtomicU64,       // 0 = unlimited
    tokens_bytes: AtomicU64,   // Lock-free CAS token bucket
    last_refill_ms: AtomicU64,
    revoked: AtomicBool,
    cancel: tokio_util::sync::CancellationToken, // Or internal AtomicWaker list
}

```

* **Hot-Path Check:** `check_and_deduct(bytes: usize, now_ms: u64) -> bool` performs relaxed/acquire loads on `revoked` and `expires_at_ms` plus a single compare-exchange loop when `rate_bps > 0`.


* **Sharded Revocation Index:** Control-plane `RevocationIndex` maps `(ScopeId, PublicKey)` and `(ScopeId, EndpointName)` to `Vec<Weak<GrantEnforcer>>`. Unpublishing an endpoint, updating local host veto rules, or receiving an `AccessControl` revocation signal iterates matching weak pointers, sets `revoked = true`, and fires `cancel.cancel()` to wake stalled stream splicers and reap datagram slots in sub-millisecond time.



---

## 4. Public Extension Seam Contracts (`seams/*` & `scope.rs`)

Because native `async fn` in traits is not `dyn`-safe in Rust, `confluence-core` exposes ergonomic traits for plugin authors with blanket-implemented `DynStreamChannel` / `DynDatagramChannel` wrappers (`Pin<Box<dyn Future<Output T> + Send + '_>>`) internally. Stream and Datagram channels remain completely separate types so cross-plane wiring fails at compile time.

```rust
pub type BoxFut<'a, T> = core::pin::Pin<Box<dyn core::future::Future<Output = T> + Send + 'a>>;

#[derive(Clone, Debug)]
pub struct ChannelCaps {
    pub effective_mtu: u16, // >= 1232 for standard Datagram channels
    pub reliable_underlay: bool,
    pub mtu_watch: tokio::sync::watch::Receiver<u16>,
}

// --- SEAM 1A & 1B: CHANNELS ---
pub trait StreamChannel: Send + Sync + 'static {
    fn caps(&self) -> ChannelCaps;
    fn dial_stream<'a>(&'a self, locator: &'a [u8]) -> BoxFut<'a, Result<Box<dyn AsyncStream>, ChannelErr>>;
    fn accept_hop_stream<'a>(
        &'a self,
        hop_seg: &'a [u8],
        tail_aad: &'a [u8; 32],
        min_mtu: u16,
    ) -> BoxFut<'a, Result<(Box<dyn AsyncStream>, HopAuthCtx), HopReject>>;
}

pub trait DatagramChannel: Send + Sync + 'static {
    fn caps(&self) -> ChannelCaps;
    fn open_link<'a>(&'a self, locator: &'a [u8]) -> BoxFut<'a, Result<Arc<dyn DatagramLink>, ChannelErr>>;
    fn accept_hop_datagram<'a>(
        &'a self,
        hop_seg: &'a [u8],
        tail_aad: &'a [u8; 32],
        min_mtu: u16,
    ) -> BoxFut<'a, Result<(Arc<dyn DatagramLink>, HopAuthCtx), HopReject>>;
}

// --- SEAM 2: ROUTE / PATH SOURCE ---
pub trait PathSource: Send + Sync + 'static {
    fn resolve_path<'a>(
        &'a self,
        scope: ScopeId,
        peer: &'a PublicKey,
        endpoint: &'a str,
        plane: Plane,
    ) -> BoxFut<'a, Result<ExplicitPath, RouteErr>>;

    fn report_outcome(&self, path_id: u64, outcome: PathOutcome);
}

// --- SEAM 3: ACCESS CONTROL (Off-data-path; wrapped by Core PolicyGate) ---
pub trait AccessControl: Send + Sync + 'static {
    fn verify<'a>(
        &'a self,
        scope: ScopeId,
        peer: &'a PublicKey,
        action: ActionRef<'a>, // EndpointOpen { ep, plane } | HopForward { chan_tag, plane }
        credential: &'a [u8],
    ) -> BoxFut<'a, Result<GrantSpec, PolicyDenied>>;
}

// --- SEAM 4: EDGE ADAPTER FACING API ON ScopeInstance ---
impl ScopeInstance {
    pub async fn dial_stream(&self, peer: PublicKey, ep: &str, cred: &[u8]) -> Result<E2eStream, CoreErr>;
    pub async fn dial_datagram(&self, peer: PublicKey, ep: &str, min_mtu: u16, cred: &[u8]) -> Result<E2eDatagram, CoreErr>;
    pub fn publish_stream(&self, ep: &str, handler: Arc<dyn StreamEndpointHandler>) -> Result<PublishGuard, CoreErr>;
    pub fn publish_datagram(&self, ep: &str, min_mtu: u16, handler: Arc<dyn DatagramEndpointHandler>) -> Result<PublishGuard, CoreErr>;
    pub fn revoke_peer(&self, peer: &PublicKey); // Immediate local hard veto
}

```

* **`confluence-edge` Datagram Staging Rule:** Local UDP and TUN Edge Adapters maintain a per-flow staging ring buffer capped at `16` packets or `16 KiB` (tail-drop) while `dial_datagram` completes its 1-RTT setup, flushing immediately upon session establishment and reaping idle sessions after `60–120 s` of inactivity.



---

## 5. Phased Implementation & Verification Roadmap

| Phase | Target Modules & Crates | Key Deliverables & Invariant Verification Suite |
| --- | --- | --- |
| **M1: Zero-Copy Primitives & Crypto** | `buf.rs`, `cid.rs`, `crypto/*`, `wire/*` | Implement `PacketBuf`, `Cid(u32)` `8+24` `SlabTable`, `Noise_IK` + `mac1` + `replay.rs`, and all `wire/*` codecs.

<br>

<br>*Tests:* Zero-heap-allocation proof on invalid `mac1` packets; `PacketBuf` zero-realloc property tests; `Cid` generation wrap-around ABA tests; tail-AAD single-bit mutation rejection.

 |
| **M2: Policy Gate, Grants & Revocation** | `grant.rs`, `seams/acl.rs` | Implement `GrantEnforcer`, `PolicyGate` (500 ms hard timeout + semaphore + local host veto intersection), and `RevocationIndex`.

<br>

<br>*Tests:* Lock-free multi-thread token-bucket contention benchmark; fail-closed verification on mock ACL timeout/error; `< 1 ms` cancellation of active handles upon `PublishGuard` drop or `revoke_peer`.

 |
| **M3: Direct Two-Plane Engine (`A ↔ B`)** | `e2e/*`, `scope.rs`, `confluence-plugins` (mocks) | Implement `ScopeInstance`, `E2eStream`, `E2eDatagram`, in-band `E2E_RENEW`, and in-memory mock channels.

<br>

<br>*Tests:* Verify `B` never invokes `EndpointHandler` if `SETUP_OK` drops (`1.0 RTT` deferred open); verify `TARGET_REFUSED` vs. clean `E2E_FIN` vs. carrier `UnexpectedEof`; verify silent bad-AEAD drop on Datagram Plane; verify multi-scope key unlinkability.

 |
| **M4: 1-RTT Multi-Hop Path Engine** | `path/*`, `AuthAclWrapper` (`confluence-plugins`) | Implement `dialer.rs`, `inbound.rs`, `dg_switch.rs`, `st_splice.rs` (cut-through `16 KiB` chunks), and reusable `AuthAclWrapper`.

<br>

<br>*Tests:* 3-hop `A → H₁ → H₂ → H₃ → B` setup in 1 RTT on both planes; 0-RTT MTU clamping + `< 1 RTT` `SETUP_ERR(MTU_TOO_SMALL)` reporting to `PathSource`; live in-band `HOP_RENEW` (`ttl = 0..2`) without dropping traffic; cross-link `Cid` isolation test.

 |
| **M5: Native OS Carriers, Relays & Edge** | `confluence-net`, `confluence-edge`, `confluence-relay` | Implement TCP & UDP (`DF=1`) carriers, TCP/UDP port-forwarding Edge Adapters (16-pkt staging ring), local `0600` Unix admin IPC, and zero-dialing Passive Relay plugin.

<br>

<br>*Tests:* End-to-end TCP backpressure under stalled reader on `B` (bounded RSS across hops); live UDP `EMSGSIZE` shrink + `MTU_PROBE` recovery; verify Passive Relay makes zero outbound `connect()` calls.

 |
| **M6: Fuzzing & Chaos Hardening** | `fuzz/*`, deterministic chaos harness | Add `cargo-fuzz` harnesses for `SETUP_FWD`, `DG_CTRL`, `ST_DATA`, and E2E records; build loss/reorder/bit-flip in-memory channel harness.

<br>

<br>*Tests:* 1M-packet pre-auth flood verifying constant memory (`HalfOpen` cap + `3 s` TTL reaper) and zero policy-plugin starvation.

 |
