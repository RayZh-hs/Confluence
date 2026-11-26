# Confluence Core — Cleanroom Specification (v1)

> **Authoritative Single-Source Specification.** This document is self-contained and defines the complete architecture, cryptographic constructions, wire protocol, protocol state machines, security invariants, extension seam contracts, and verification criteria for **Confluence Core (`confluence-core`)**. Cleanroom implementation agents MUST rely solely on this specification and MUST NOT inspect any legacy source code.

---

## Table of Contents

1. [Scope, Cleanroom Contract & Conventions](#1-scope-cleanroom-contract--conventions)
2. [Architecture, Core Concepts & The 10 Invariants](#2-architecture-core-concepts--the-10-invariants)
3. [Normative Constants & Default Resource Envelopes](#3-normative-constants--default-resource-envelopes)
4. [Cryptographic Specification (v1)](#4-cryptographic-specification-v1)
5. [Wire Protocol Specification (v1)](#5-wire-protocol-specification-v1)
6. [Protocol State Machines & Behavioral Semantics](#6-protocol-state-machines--behavioral-semantics)
7. [Trust, Authorization, Leases & Revocation Model](#7-trust-authorization-leases--revocation-model)
8. [Multi-Scope Hosting (`Node`) & Runtime Integration](#8-multi-scope-hosting-node--runtime-integration)
9. [Extension Seam Contracts, Errors & Cleanroom API Freedom](#9-extension-seam-contracts-errors--cleanroom-api-freedom)
10. [Conformance & Verification Checklist](#10-conformance--verification-checklist)

---

## 1. Scope, Cleanroom Contract & Conventions

### 1.1 Scope

This specification defines **Confluence Core**: a runtime-independent, two-plane, A-to-B connectivity engine connecting an Originator `A` to an explicitly published named **Endpoint** on Destination `B` across zero or more explicitly named **Transits** (`H_0, ..., H_{N-1}`) over pure pluggable **Channels**.

Out-of-core components — concrete OS sockets (TCP/UDP), link-encryption wrappers, stream multiplexers, cross-plane adapters, passive relay presence protocols, QoS algorithms (token buckets, rate limiters, concurrency limiters), peer discovery, path racing/failover controllers, credential issuers (OIDC/SSO/CA), enterprise policy engines, and edge adapters — are explicitly **outside** Core and attach only through four narrow extension seams (Section 9).

### 1.2 Normative vs. Redesignable Boundary

A cleanroom implementation of Confluence Core:

* **MUST** be **byte-for-byte wire-compatible** with every frame layout, opcode, endianness rule, validation constraint, error code, cryptographic primitive, domain-separation string, key schedule, and handshake/control transcript specified in Sections 4 and 5.
* **MUST** preserve every behavioral invariant, state machine transition, timeout, retry schedule, hysteresis rule, resource bound, security property, and zero-allocation hot-path requirement specified in Sections 2, 3, 6, 7, and 8.
* **MAY** freely redesign the Rust public API (module layout, type/trait hierarchy, builder ergonomics, async/poll trait surfaces, internal concurrency structures, and error representation) to maximize code quality, clarity, maintainability, and type safety, provided every capability and semantic contract in Section 9 is cleanly expressible.

### 1.3 Requirement Keywords

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described in RFC 2119.

### 1.4 Safety, Portability & Dependency Constraints

* **Memory Safety:** Core **MUST** forbid unsafe code (`#![forbid(unsafe_code)]`).
* **Runtime Independence:** Core **MUST NOT** depend on a specific async executor or OS timer driver. All task spawning and monotonic time/timers **MUST** be supplied by the embedding host via injected runtime abstractions (`TaskSpawner` and `Clock`). Core **MAY** use runtime-independent synchronization primitives (e.g., channels, watches, semaphores, mutexes).
* **Wall-Clock Freshness vs. Monotonic Local Deadlines:** Cross-node setup freshness checks **MUST** use Unix epoch wall-clock milliseconds (`SystemTime`). All local deadlines, lease expirations, replay-cache aging, CID quarantine timers, flood-cookie rotation, retry backoffs, and hysteresis timers **MUST** use the injected monotonic `Clock` so wall-clock jumps cannot subvert security or liveness.
* **Secret Zeroization:** All secret key material (X25519 static/ephemeral secrets, MAC keys, rotating cookie secrets, Noise chaining/cipher keys, `HopKey`, `SessionKeys`), decrypted setup plaintexts, and caller credentials **MUST** be zeroized in memory upon drop.
* **Optional Serialization:** Core **SHOULD** gate serialization derives (`serde`) behind an opt-in feature flag (`serde`) disabled by default, supporting canonical lowercase-hex string serialization for `PublicKey` and structured snapshots for stats and `Plane`.

---

## 2. Architecture, Core Concepts & The 10 Invariants

### 2.1 Architectural Overview

```text
+-----------------------------------------------------------------------+
| Edge Adapters & App Middleware (Out of Core — Seam 4 Consumers)       |
|   TCP/UDP forwarders · Stream IO adapters · Virtual L3 · App RBAC     |
|   Reads live SessionAuth claims (updated automatically on renewal)    |
+-----------------------------------------------------------------------+
                     │                             │
      1:1 Stream     │  SessionAuth(peer, live)    │  1:1 Datagram Flow
                     ▼                             ▼
+=======================================================================+
|                          CONFLUENCE CORE                              |
|                                                                       |
|  +-----------------------------+   +-------------------------------+  |
|  |        Stream Plane         |   |         Datagram Plane        |  |
|  |  End-to-end protected byte  |   |  End-to-end protected discrete|  |
|  |  streams (explicit FIN/EOF) |   |  messages (no fragmentation)  |  |
|  +--------------+--------------+   +---------------+---------------+  |
|                 │                                  │                  |
|                 ▼                                  ▼                  |
|  +-----------------------------------------------------------------+  |
|  |          Unified Trust & Enforcement Boundary (Core)            |  |
|  |   Mutual Noise_IK · MAC1/MAC2 Flood Cookies · Replay Protection |  |
|  |   1.0 RTT Replay-Safe Open · Lease TTL & Instant Revocation     |  |
|  |   Caller credentials ◄──── [Seam 3A: CredentialProvider]        |  |
|  |   Verifier decisions ────► [Seam 3B: Authorizer / Intersect]    |  |
|  +-----------------------------------------------------------------+  |
|                                  │                                    |
|                                  ▼                                    |
|  +-----------------------------------------------------------------+  |
|  |                    Composable Path Engine                       |  |
|  |   Explicit single-path execution · End-to-end MTU agreement     |  |
|  |   Named Endpoints & Named Transits (SSRF-safe by construction)  |  |
|  |   Direct per-hop auth · Route integrity · Opaque forwarding     |  |
|  |   Receives chosen path ◄───────── [Seam 2: PathSource]          |  |
|  +-----------------------------------------------------------------+  |
+=======================================================================+
                                   │
                                   ▼
+-----------------------------------------------------------------------+
| Pure Composable Channels (Out of Core — Seam 1)                       |
|   Pure transports (zero Core crypto, auth, or policy logic):          |
|   Native TCP / UDP · Link-encrypted wrappers · Passive Relays         |
|   Explicit Stream<->Datagram cross-plane adapters                     |
+-----------------------------------------------------------------------+
```

### 2.2 Core Concepts

* **Trust Scope (`ScopeInstance`):** An isolated trust domain owning one independent X25519 static identity keypair (`ScopeKeypair`) and its unlinkable 8-byte key identifier (`ScopeKid`). Observers and intermediaries cannot correlate a host's presence across unrelated scopes.
* **Multi-Scope Container (`Node`):** A thin runtime container mounting multiple isolated `ScopeInstance`s onto shared Stream and Datagram listeners, demultiplexing inbound setups in $O(1)$ by `ScopeKid` while preserving per-link circuit isolation.
* **Strict Two-Plane Separation (`Plane::Datagram = 1`, `Plane::Stream = 2`):** Stream traffic only traverses Stream channels, transits, and endpoints; Datagram traffic only traverses Datagram channels, transits, and endpoints. Core never implicitly wraps one plane inside the other and never fragments/reassembles steady-state application datagrams.
* **Named Endpoints & Named Transits:**
  * **Endpoint (`TargetRef::Endpoint`):** A terminal service published on destination `B` under a UTF-8 name (`1..=255` bytes).
  * **Transit (`TargetRef::Transit`):** A forwarding exit published on an intermediate hop `H` under either an exact UTF-8 name (e.g., `"to-prod"`) or a prefix (e.g., `"relay/"` matching `"relay/bob"` with non-empty suffix `"bob"`).
  * **SSRF Prevention by Construction:** Originators name only logical transit targets (`HopSpec { peer, target }`) and never supply raw downstream IPs, ports, or internal channel types. Hop `H` privately owns how a transit reaches the next hop.
  * **Default-Deny Forwarding:** Registering an outbound first-hop carrier on a scope is exclusively for outbound dials and **MUST NEVER** expose the scope for inbound forwarding. Only explicitly published transits forward traffic.
* **Route-Integrity-Bound Single-Pass 1-RTT Setup:** Originator `A` builds a nested setup flight (`SETUP_FWD`) containing one Noise_IK segment per hop plus one for destination `B`. Each hop authenticates `A` directly (never trusting the preceding hop) and verifies route integrity via `BLAKE3(dispatch_prefix || remaining_tail)` as AEAD AAD so upstream hops cannot splice, alter, reorder, or truncate downstream legs.
* **1.0 RTT Replay-Safe Deferred Destination Open:** Destination `B` holds an `AwaitingConfirm` state after sending `SETUP_OK` and invokes its local `EndpointHandler::open` **ONLY** after decrypting `A`'s first `ee`-authenticated end-to-end record (confirmation). Staged dial APIs expose this boundary so out-of-core path racers can compare candidates before triggering destination side effects.
* **Symmetric Auth ("Verifier, Never Issuer"):** Originators fetch and refresh opaque credentials (`0..=128` bytes) per `(verifier, TargetRef)` via `CredentialProvider`; each verifier's credential is encrypted solely inside its own Noise_IK segment or hop/E2E renewal channel. Verifiers evaluate `Authorizer` strictly on control events (setup and in-band renewal, never per data packet), returning a time-bounded, revocable `Lease` carrying optional out-of-core `TrafficGate` hooks, session-scoped RAII `SessionGuard` permits, and live typed `AuthExtensions` surfaced via `SessionAuth`.

### 2.3 Non-Goals for Core

Core **MUST NOT** implement:
1. Application-layer or L3/L4 protocol parsing.
2. Concrete QoS/shaping/concurrency algorithms (Core enforces only the algorithm-agnostic `TrafficGate` and `SessionGuard` hooks on `Lease`).
3. Passive-relay presence/registration signaling protocols.
4. Implicit cross-plane conversion or steady-state datagram fragmentation.
5. In-core logical stream multiplexing (one dial = one 1:1 Stream or one 1:1 Datagram session).
6. Auto-routing, peer discovery, multi-path racing, or live path failover.
7. Built-in user/identity management, credential issuance, or default network control endpoints.
8. Root/privileged OS requirements or global topology assumptions.

### 2.4 The 10 Core Invariants

1. **Opaque Payloads & Revocable Leases Only:** Core knows no application, L3/L4, QoS, or passive-relay protocols — only opaque byte streams, opaque discrete datagrams, and revocable time-bounded leases.
2. **Strict Plane Separation & Zero Steady-State Datagram Fragmentation:** Datagram and Stream planes never mix inside Core, and application datagrams are never fragmented inside Core (link-local fragmentation applies solely to oversized `SETUP_FWD` flights).
3. **Pure, Composable, Locally Private Channels:** Channels move bytes without Core auth/policy logic; downstream stacks stay private behind named transits.
4. **Explicit Single-Path 1:1 Execution:** Core executes one explicit path per dial; discovery, probing, racing, failover, and multiplexing stay outside Core.
5. **Passive Relay vs. Active Transit Separation:** Passive relay lives outside Core and exposes presences strictly through named transit handlers.
6. **Direct Per-Hop Auth & Opaque Steady-State Forwarding:** Every transit hop authenticates `A` directly with route-integrity tail AAD during setup, then forwards opaque end-to-end ciphertext without per-hop payload decryption.
7. **Replay-Safe 1.0 RTT Admission & Explicit Lifecycle:** Destination handlers open only after 1.0 RTT `ee`-authenticated confirmation; Stream cleanly separates `OPEN_OK`, `TARGET_*`, `ST_FIN`, and `UnexpectedEof`.
8. **Symmetric Fail-Closed Auth & Host Sovereignty:** `CredentialProvider` is decoupled from routing; `Authorizer` runs only on control events, fails closed, cannot override local host veto (`IntersectAuthorizer`, `revoke_peer`, `PublishGuard` drop), enforces `TrafficGate` strictly on `DATA` frames (never control frames), and streams live `AuthExtensions` into `SessionAuth`.
9. **Honest Path & MTU Failure Surfacing:** Broken links and MTU floor violations tear down affected sessions cleanly and report structured `PathOutcome` events upward.
10. **Zero Default Endpoints & Unlinkable Rootless Scopes:** Nodes run unprivileged, isolate scopes with unlinkable `ScopeKid`s, keep connection control in-band and host administration strictly local, and expose only explicitly published Endpoints and Transits.

---

## 3. Normative Constants & Default Resource Envelopes

### 3.1 Wire & Protocol Constants (Normative — MUST NOT Change)

| Constant | Value | Meaning |
| --- | --- | --- |
| `DATAGRAM_MTU` | `1232` bytes | Baseline IPv6-safe UDP payload MTU discovery reference |
| `DATAGRAM_MIN_MTU` | `1152` bytes | Minimum effective wire MTU for Datagram Plane (`Plane::Datagram.minimum_mtu()`) |
| `STREAM_MIN_MTU` | `20` bytes | Minimum wire MTU for Stream Plane (`ST_OVERHEAD + 1 = 19 + 1`) |
| `STREAM_CHUNK` | `16384` bytes (`16 KiB`) | Maximum `ST_DATA` hop chunk payload size and max Stream setup/OK frame size |
| `DG_OVERHEAD` | `30` bytes | Total Datagram E2E wire overhead (`5` hop + `8` seq + `1` type + `16` tag) |
| `ST_OVERHEAD` | `19` bytes | Stream E2E record overhead (`2` len + `1` type + `16` tag) |
| `ST_MAX_BODY` | `16365` bytes | Maximum Stream E2E record body (`STREAM_CHUNK - ST_OVERHEAD`) |
| `CREDENTIAL_MAX` | `128` bytes | Maximum opaque credential length in setup and `RENEW` frames |
| `NAME_LEN_RANGE` | `1..=255` bytes | Valid UTF-8 byte length for endpoint, transit, prefix, and carrier names |
| `MAX_HOPS` | `255` | Maximum intermediate hops in an `ExplicitPath` (`u8` distance/TTL space) |
| `SEGMENT_OVERHEAD` | `120` bytes | Base Noise_IK segment overhead (`8` kid + `32` e + `48` enc_s + `16` pt_tag + `16` mac1) |
| `MAC_LEN` | `16` bytes | Length of `mac1` and `mac2` tags |
| `COOKIE_LEN` | `16` bytes | Length of a stateless flood cookie |
| `CHALLENGE_LEN` | `56` bytes | Length of encrypted cookie challenge (`24` XNonce + `16` cookie + `16` tag) |
| `REPLY_LEN` | `58` bytes | Noise_IK Message 2 reply length (`32` eph + `10` ack + `16` tag) |
| `FWD_HEADER` | `8` bytes | `SETUP_FWD` outer header size |
| `OK_SIZE` | `70` bytes | Base `SETUP_OK` size (`12` header + `58` Noise reply) |
| `HOP_ACK_SIZE` | `26` bytes | Encrypted hop trailer size appended to `SETUP_OK` (`2` MTU + `8` TTL + `16` tag) |
| `ERR_SIZE` | `36` bytes | `SETUP_ERR` total size (`8` header + `28` encrypted error body) |
| `COOKIE_SIZE` | `64` bytes | `SETUP_COOKIE` total size (`8` header + `56` challenge) |
| `FRAG_HEADER` | `16` bytes | `SETUP_FRAG` header size and exact `SETUP_FRAG_ACK` size |
| `MAX_FRAGS` | `8` | Maximum fragment count per fragmented datagram `SETUP_FWD` (`count in 2..=8`) |
| `MAX_SEGMENT` | `530` bytes | Maximum datagram leading encrypted segment (`120 + 11 + 255 + 128 + 16`) |
| `MAX_SETUP_SEGMENT` | `2048` bytes | Maximum stream leading encrypted segment accepted in stack precheck buffer |
| `MAX_SETUP` | `131086` bytes | Maximum reassembled datagram setup flight (`8 + 8 + 2 * 65535`) |
| `MAX_CONTROL` | `160` bytes | Maximum `ControlCipher` payload (`8` seq + `8` renewal_id + `128` cred + `16` tag); min `24` bytes |
| `MAX_WIRE_LEASE_TTL` | `86400 s` (`24 h`) | Hard wire ceiling for lease TTLs (min valid wire TTL is `1 ms`, `0` is malformed) |
| `SETUP_FRESHNESS_WINDOW` | `±30000 ms` | Accepted wall-clock timestamp skew `\|now_ms - ts_ms\| <= 30_000` |
| `REPLAY_WINDOW_PACKETS` | `64` packets | Sliding anti-replay bitmap width for `ControlCipher` and `DatagramRx` |
| `HEADROOM_BYTES` | `64` bytes | Packet buffer reserved headroom for in-place framing |
| `TAILROOM_BYTES` | `64` bytes | Packet buffer reserved tailroom (up to four stacked 16-byte AEAD tags) |

### 3.2 Timing, Retry & Resource Envelope Defaults (Behavioral)

| Parameter | Default / Value | Bounds / Notes |
| --- | --- | --- |
| `SETUP_TIMEOUT` | `3 s` | End-to-end setup, confirmation, handler open, fragment reassembly, and cookie-retry hold deadline |
| Best-effort close/error send timeout | `50 ms` | Timeout when transmitting terminal `SETUP_ERR`, `SETUP_COOKIE`, `TARGET_*`, `ST_CLOSE`, or `DG_CLOSE` |
| Stream frame write retry budget | `3 s` | Exponential backoff `10 ms -> 20 -> 40 -> 80 -> 160 -> 200 ms` (cap `200 ms`), resets to `10 ms` on any written byte |
| Flood cookie secret rotation | `120 s` | Minimum `1 s`; retains previous secret for 1 grace period |
| Auto `under_load` hysteresis | `> 75%` ON, `<= 25%` for `5 s` OFF | Specifically: activate when `used > max_pending - ceil(max_pending / 4)`; clear after `used <= max_pending / 4` continuously for `>= 5 s` |
| `SetupReplay` monotonic TTL | `61 s` (`4096` buckets × `4` ways) | Strictly covers the `±30 s` freshness window (`now - entry > 61 s` expires slot) |
| `SlabTable` CID quarantine cooldown | `60 s` | Applied when an entry's 8-bit generation wraps from `255` back to `1` |
| `SlabTable` per-link active limit | `4096` circuits | Per `DatagramPort` |
| Per-circuit datagram mailbox capacity | `32` packets | Drops packet on full (`queue_drops_total` + `datagram_mailbox_drops_total`) |
| Datagram fragment reassembly limits | `16` active flights, `MAX_SETUP` aggregate bytes, `32` completed cache | Per `DatagramPort`; incomplete and completed entries expire after `3 s` |
| Datagram fragment burst retry delays | `[150, 300, 600]` ms | Up to 3 retries within `SETUP_TIMEOUT` |
| MTU report retry delays | `[150, 300, 600, 1200, 2400]` ms | Up to 5 retries; `REASSERT_INTERVAL = 200 ms`; transit floor-violation drain `REPORT_TIMEOUT = 5 s` |
| Lease renewal trigger jitter | `70% ..= 80%` of granted TTL | Uniform integer percentage `70..=80` |
| Lease renewal retry backoff | Stream base `1000 ms`, Datagram base `100 ms` | `ceiling = min(base << min(retries, 6), 5000 ms)`, jitter `[ceiling/2, ceiling)`, clamped to `[10 ms, remaining/3]` |
| `AuthLimits::per_peer_pending` | `8` | Min `1` |
| `AuthLimits::auth_concurrency` | `32` | Min `1` |
| `AuthLimits::auth_timeout` | `500 ms` | Clamped `[10 ms, 5 s]` |
| `AuthLimits::max_lease_ttl` (`MAX_LEASE_TTL`) | `3600 s` (`1 h`) | Clamped `[1 s, 24 h]` |
| `ScopeLimits::max_pending` | `256` | Min `1` |
| `ScopeLimits::max_sessions` | `4096` | Min `1` |
| `ScopeLimits::max_datagram_ports` | `4096` | Min `1` |
| `Node` default `max_pending` / `max_datagram_ports` | `512` / `4096` | Each min `1` |
| Revocation epoch table bound (`MAX_EPOCHS`) | `16384` total entries | On overflow: increment `global_epoch` and clear all fine-grained epoch maps |

---

## 4. Cryptographic Specification (v1)

All multi-byte integers are unsigned **big-endian** (`be16`, `be32`, `be64`).

### 4.1 Primitives & Conventions

* **DH:** X25519 (RFC 7748) over Curve25519; 32-byte private scalars and 32-byte public keys.
* **AEAD (Session & Control):** ChaCha20-Poly1305 (RFC 8439) with 32-byte key, 12-byte nonce, and 16-byte Poly1305 authentication tag.
* **AEAD (Cookie Challenge):** XChaCha20-Poly1305 with 32-byte key, 24-byte random nonce, and 16-byte tag.
* **Hash / MAC / KDF:** BLAKE3 in three distinct modes:
  * `BLAKE3_hash(input)` -> 32 bytes (unkeyed hash).
  * `BLAKE3_keyed_hash(key_32B, input)` -> 32 bytes (keyed MAC/PRF).
  * `BLAKE3_derive_key(context_str, key_material)` -> 32 bytes (BLAKE3 KDF mode with UTF-8 context string).
* **Constant-Time Comparisons:** All MAC, `ScopeKid`, and all-zero DH output comparisons **MUST** execute in constant time.
* **Hex Representation:**
  * `PublicKey`: 32 bytes -> 64 lowercase hex characters (`Display`); parsing trims ASCII whitespace, accepts uppercase or lowercase hex, requires exact length 64.
  * `ScopeKid`: 8 bytes -> 16 lowercase hex characters (`Display`); parsing trims whitespace, requires exact length 16.
  * `ScopeKeypair` secret export: 64 lowercase hex characters (zeroizing intermediate buffers).

### 4.2 Identity & Pre-DH Key Derivations

Given a 32-byte X25519 static public key `pk`:

```text
scope_kid(pk)      = BLAKE3_derive_key("confluence-v1-kid",    pk)[0..8]   (8 bytes)
mac1_key(pk)       = BLAKE3_derive_key("confluence-v1-mac1",   pk)         (32 bytes)
mac1(pk, data)     = BLAKE3_keyed_hash(mac1_key(pk), data)[0..16]          (16 bytes)
cookie_enc_key(pk) = BLAKE3_derive_key("confluence-v1-cookie", pk)         (32 bytes)
```

Given a 16-byte stateless flood cookie `cookie`:

```text
mac2_key(cookie)      = BLAKE3_derive_key("confluence-v1-mac2", cookie)    (32 bytes)
mac2(cookie, data)    = BLAKE3_keyed_hash(mac2_key(cookie), data)[0..16]   (16 bytes)
```

### 4.3 ChaCha20-Poly1305 Nonce Encoding & Sequence Exhaustion

Every ChaCha20-Poly1305 operation using a 64-bit counter `seq: u64` constructs its 12-byte nonce as:

```text
nonce(seq) = [0x00, 0x00, 0x00, 0x00] || be64(seq)
```

For stateful directional ciphers (`ControlCipher`, `DatagramTx`, `StreamCipher`), `seq` initializes to `0` and advances via checked addition (`seq + 1`). If `seq == u64::MAX`, taking the next sequence **MUST** fail with `Closed` rather than wrapping or reusing a nonce.

### 4.4 Noise_IK Handshake Construction

Confluence uses Noise `IK` message token order (`<- s ... -> e, es, s, ss ... <- e, ee, se`) instantiated with a fixed BLAKE3-based symmetric state (note: `mix_key` uses BLAKE3 keyed hashing with explicit domain labels rather than HMAC-HKDF):

#### 4.4.1 Handshake State & Operations

State consists of `(ck: [u8; 32], h: [u8; 32], k: [u8; 32], n: u64)`.

1. **Initialize** for responder static public key `target_pk: [u8; 32]` and 32-byte route-integrity `aad: [u8; 32]`:
   ```text
   initial = BLAKE3_hash(b"Noise_IK_25519_ChaChaPoly_BLAKE3+confluence-v1")
   ck = initial
   h  = initial
   k  = [0; 32]
   n  = 0
   mix_hash(aad)        // MUST be mixed BEFORE target_pk
   mix_hash(target_pk)
   ```
2. **`mix_hash(data)`:**
   ```text
   h = BLAKE3_hash(h || data)
   ```
3. **`mix_ciphertext(ct, tag)`:**
   ```text
   h = BLAKE3_hash(h || ct || tag)
   ```
4. **`mix_key(dh_output: [u8; 32])`:**
   * Constant-time check: if `dh_output == [0u8; 32]`, **MUST** abort with `Authentication`.
   * Otherwise:
     ```text
     prk = BLAKE3_keyed_hash(ck, dh_output)
     ck  = BLAKE3_keyed_hash(prk, b"chaining key")
     k   = BLAKE3_keyed_hash(prk, b"cipher key")
     n   = 0
     ```
5. **`encrypt(pt)`:**
   ```text
   (ct, tag) = ChaCha20Poly1305_Seal(key=k, nonce=nonce(n), aad=h, pt=pt)
   n += 1
   mix_ciphertext(ct, tag)
   return (ct, tag)
   ```
6. **`decrypt(ct, tag)`:**
   ```text
   pt = ChaCha20Poly1305_Open(key=k, nonce=nonce(n), aad=h, ct=ct, tag=tag) // Authentication error on failure
   n += 1
   mix_ciphertext(ct, tag)
   return pt
   ```

#### 4.4.2 Message 1 (Initiator -> Target Segment)

Inputs: initiator keypair `(s_i, S_i)`, target public key `S_r`, 32-byte `tail_aad`, `plaintext` (length `P`).

1. Generate fresh random X25519 ephemeral keypair `(e_i, E_i)`.
2. `state = Initialize(S_r, tail_aad)`.
3. `mix_hash(E_i)`.
4. `mix_key(X25519(e_i, S_r))` (`es`).
5. `(enc_s, tag_s) = encrypt(S_i)` (`32 + 16 = 48` bytes).
6. `mix_key(X25519(s_i, S_r))` (`ss`).
7. `(enc_p, tag_p) = encrypt(plaintext)` (`P + 16` bytes).
8. Construct base segment body:
   ```text
   body = scope_kid(S_r)[8B] || E_i[32B] || enc_s[32B] || tag_s[16B] || enc_p[P B] || tag_p[16B]
   ```
   (Note: `scope_kid(S_r)` is NOT hashed into `h`.)
9. Append `mac1 = mac1(S_r, body)` (16 bytes).
10. Base segment length is `120 + P` bytes (`SEGMENT_OVERHEAD = 120`).
11. If a flood cookie `cookie` is attached (`MODE_MAC2` set in dispatch prefix), append `mac2 = mac2(cookie, body || mac1)` (16 bytes), giving total segment length `136 + P` bytes.

Responder processing (after `mac1`/`mac2` verification strips optional `mac2`, leaving `base_seg` of length `>= 120`):
1. Verify `mac1` and check replay eligibility (`insert = false`) on `E_i = base_seg[8..40]`.
2. `state = Initialize(S_r, tail_aad)`.
3. `mix_hash(E_i)`.
4. `mix_key(X25519(s_r, E_i))`.
5. `S_i = decrypt(base_seg[40..72], base_seg[72..88])`.
6. `mix_key(X25519(s_r, S_i))`.
7. `plaintext = decrypt(base_seg[88..len-32], base_seg[len-32..len-16])`.
8. Validate freshness of `plaintext` (Section 4.6).

#### 4.4.3 `HopKey` Derivation (Available Immediately After Message 1)

Both intermediate hops and the destination derive a 32-byte `HopKey` from the state immediately after Message 1 (before Message 2):

```text
transcript = BLAKE3_keyed_hash(ck, h)
HopKey     = BLAKE3_keyed_hash(transcript, b"confluence-v1 hop control")
```

#### 4.4.4 Message 2 (Destination Responder -> Initiator, 58 Bytes)

Used solely by the destination `B` (never by intermediate hops). Input: 10-byte `ack = [dest_local_mtu: u16 BE | dest_ttl_ms: u64 BE]`.

1. Generate fresh random X25519 ephemeral keypair `(e_r, E_r)`.
2. `mix_hash(E_r)`.
3. `mix_key(X25519(e_r, E_i))` (`ee`; initiator computes `X25519(e_i, E_r)`).
4. `mix_key(X25519(e_r, S_i))` (`se`; initiator computes `X25519(s_i, E_r)`).
5. `(enc_ack, tag) = encrypt(ack)` (`10 + 16 = 26` bytes).
6. Output 58-byte reply:
   ```text
   reply = E_r[32B] || enc_ack[10B] || tag[16B]
   ```

#### 4.4.5 End-to-End Session Key Split (After Message 2)

```text
root = BLAKE3_keyed_hash(ck, h)
fwd  = BLAKE3_keyed_hash(root, b"initiator to responder")   // Initiator TX, Responder RX
rev  = BLAKE3_keyed_hash(root, b"responder to initiator")   // Responder TX, Initiator RX
```

### 4.5 `HopKey`-Derived Constructions

1. **Setup Error Body (`28` bytes, inside `SETUP_ERR`):**
   * Plaintext: `pt = [code: u16 BE | arg: u16 BE]` (4 bytes).
   * Nonce counter: `r = random u64` (MUST be CSPRNG-random per error frame).
   * `(ct, tag) = ChaCha20Poly1305_Seal(key=HopKey, nonce=nonce(r), aad=b"confluence-v1 setup error", pt=pt)`.
   * Wire body: `[be64(r) | ct[4B] | tag[16B]]`.
2. **Setup Hop Ack Trailer (`26` bytes, appended to `SETUP_OK`):**
   * `ack_key = BLAKE3_keyed_hash(HopKey, b"hop setup ack")`.
   * Plaintext: `pt = [hop_mtu: u16 BE | lease_ttl_ms: u64 BE]` (10 bytes).
   * `(ct, tag) = ChaCha20Poly1305_Seal(key=ack_key, nonce=nonce(0), aad=b"confluence-v1 setup hop ack", pt=pt)`.
   * Wire trailer: `[ct[10B] | tag[16B]]`.
3. **Hop Bidirectional Control Cipher (`ControlCipher`):**
   * `fwd_key = BLAKE3_keyed_hash(HopKey, b"hop forward")` (Initiator TX, Hop/Dest RX).
   * `rev_key = BLAKE3_keyed_hash(HopKey, b"hop reverse")` (Hop/Dest TX, Initiator RX).
   * Seal for outer hop frame opcode `kind: u8` and `plaintext`:
     * Take monotonic `seq` starting at `0`.
     * `(ct, tag) = ChaCha20Poly1305_Seal(key=tx_key, nonce=nonce(seq), aad=&[kind], pt=plaintext)`.
     * Wire body: `[be64(seq) | ct | tag[16B]]`.
   * Open for outer hop frame opcode `kind: u8` and `wire`:
     * Reject (`Malformed`) if `!(24..=160).contains(&wire.len())`.
     * Extract `seq = be64(wire[0..8])`.
     * Check `replay_window.allows(seq)` BEFORE decryption (reject `Authentication` if disallowed).
     * Decrypt `wire[8..len-16]` with `tag = wire[len-16..]`, `nonce(seq)`, `aad = &[kind]`.
     * Commit `seq` to `replay_window` ONLY after AEAD authentication succeeds.

### 4.6 Setup Plaintext Payload & Freshness Window

Both Transit Hop segments and Destination Endpoint segments carry the identical plaintext schema inside Noise_IK Message 1:

```text
Offset  Size        Field
0       8           ts_ms        (u64 BE, originator Unix epoch milliseconds)
8       1           name_len     (u8, MUST be 1..=255)
9       name_len    name_utf8    (valid UTF-8 Endpoint name or Transit target name)
9+N     2           cred_len     (u16 BE, MUST be 0..=128)
11+N    cred_len    credential   (opaque bytes, zeroized after use)
```

* Exact decrypted payload length **MUST** equal `11 + name_len + cred_len` (total range `12..=394` bytes). Any mismatch, zero `name_len`, invalid UTF-8, or `cred_len > 128` **MUST** fail with `Malformed`.
* **Freshness Check:** `now_wall_ms.abs_diff(ts_ms) <= 30_000` (inclusive). If `plaintext.len() < 8` or skew exceeds `30_000 ms`, **MUST** fail with `ClockSkew`.

### 4.7 Replay Protection

#### 4.7.1 Setup Ephemeral Replay Cache (`SetupReplay`)

* Keyed on the 32-byte initiator ephemeral public key `E_i` (`segment[8..40]`).
* Uses a random per-instance 32-byte key (`BLAKE3_keyed_hash(key, E_i)`) to derive bucket index and fingerprint so attackers cannot craft deliberate hash collisions.
* Capacity: bounded set-associative table (reference: `4096` buckets × `4` ways; 32-bit non-zero fingerprint; 32-bit monotonic second timestamp relative to instance creation).
* Entry lifetime: `61` monotonic seconds (expired when `now_secs - entry_secs > 61`). Because it uses the monotonic `Clock`, backward wall-clock jumps **MUST NOT** flush replay entries.
* **Fail-Closed Saturation:** If all ways in a bucket contain unexpired non-matching entries, the check **MUST** return `false` (reject with `Replay`) rather than evicting live replay entries.
* **Two-Phase Commit (Anti-Poisoning):**
  1. `authenticate()` checks `replay` with `insert = false` (reads without consuming a slot).
  2. Policy evaluation (`Authorizer::authorize`) runs.
  3. `commit()` re-validates wall-clock freshness (`<= 30_000 ms`) AND atomically checks-and-inserts `E_i` (`insert = true`) ONLY after admission succeeds. Concurrent duplicate setups race safely: at most one succeeds and the other fails with `Replay`.

#### 4.7.2 Steady-State Sliding Window (`ReplayWindow`)

Used by `ControlCipher` and `DatagramRx`:

* Tracks `(max: u64, seen: u64)`, initialized to `(0, 0)`.
* `allows(seq)`: returns `true` iff `seq > max` OR (`max - seq < 64` AND `(seen & (1u64 << (max - seq))) == 0`).
* `commit(seq)`:
  * If `seq > max`: shift `seen` left by `seq - max` (or zero if shift `>= 64`), set `max = seq`.
  * If `max - seq < 64`: set bit `seen |= 1u64 << (max - seq)`.
* **Atomicity Rule:** `commit(seq)` **MUST NOT** be called if AEAD decryption fails; corrupted or spoofed packets **MUST NOT** advance `max` or consume a valid sequence number.

### 4.8 Stateless `MAC1` & Rotating `MAC2` Flood-Cookie Protection

1. **Zero-Allocation Pre-DH Verification:**
   * Given `(segment, has_mac2)`:
     * Require `segment.len() >= 120 + (16 if has_mac2 else 0)`.
     * Split `base = segment[..len - 16]` and `sent_mac2 = Some(&segment[len - 16..])` if `has_mac2`, else `(segment, None)`.
     * Constant-time compare `base[0..8] == self.scope_kid`.
     * Split `(body, sent_mac1) = base.split_at(base.len() - 16)`.
     * Constant-time compare `mac1(self.mac1_key, body) == sent_mac1`.
   * Any failure **MUST** drop immediately (`BadMac`) with **zero heap allocations** and **zero X25519 operations**.
2. **When `under_load == false`:** Return `Verified(base)` immediately (0-RTT; if caller unnecessarily sent `mac2`, it is stripped and ignored after `mac1` succeeds).
3. **When `under_load == true`:**
   * Maintain a rotating 32-byte CSPRNG secret `(current, previous: Option<[u8; 32]>, rotated_at: MonotonicTime)`.
   * Rotate lazily whenever `clock.now() - rotated_at >= rotation_interval` (default `120 s`, min `1 s`): zeroize old `previous`, move `current -> previous`, generate fresh random `current`, update `rotated_at`.
   * Derive per-source cookies from the carrier's 16-byte `source_tag`:
     ```text
     curr_cookie = BLAKE3_keyed_hash(secret.current, source_tag)[0..16]
     prev_cookie = secret.previous.map(|p| BLAKE3_keyed_hash(p, source_tag)[0..16])
     ```
   * If `sent_mac2` is `Some(m2)` and constant-time equals `mac2(curr_cookie, base)` or (if present) `mac2(prev_cookie, base)`: return `Verified(base)`.
   * Otherwise build a 56-byte stateless challenge:
     ```text
     xnonce     = random 24 bytes
     (ct, tag)  = XChaCha20Poly1305_Seal(key=cookie_enc_key(self.pk), nonce=xnonce, aad=sent_mac1, pt=curr_cookie)
     challenge  = xnonce[24B] || ct[16B] || tag[16B]
     ```
     Return `Challenge(challenge)` before executing any X25519 DH or replay-cache lookup.
4. **Originator Unsealing:**
   * Given `(target_pk, sent_mac1, challenge_56B)`: decrypt `challenge[24..40]` with `XChaCha20Poly1305_Open(key=cookie_enc_key(target_pk), nonce=challenge[0..24], aad=sent_mac1, tag=challenge[40..56])`. Any length mismatch or tag failure returns `Authentication`.
5. **Automatic `under_load` Hysteresis:**
   * Default mode is automatic (host MAY manually override via `set_under_load(bool)` and restore automatic mode).
   * Let `used = max_pending - available_pending_permits`.
   * Activate (`true`) immediately when `used > max_pending - ceil(max_pending / 4)` (strictly above 75% saturation) and clear any `below_since` timestamp.
   * When active and `used <= floor(max_pending / 4)` (at or below 25%), record `below_since = now` if unset; clear (`false`) once `now - below_since >= 5 s`.
   * If between 25% and 75%, clear `below_since` (hysteresis band keeps current state).

---

## 5. Wire Protocol Specification (v1)

All multi-byte integers are unsigned **big-endian**. Byte 0 of every outer frame is `ver_type` (opcode).

### 5.1 Outer Frame Type Registry (Byte 0)

| Opcode | Name | Direction | Plane | Framing Summary |
| --- | --- | --- | --- | --- |
| `0x11` | `SETUP_FWD` | Forward | Both | `8B` ForwardHeader + nested Segment chain (shrinks per hop) |
| `0x12` | `SETUP_OK` | Reverse | Both | `12B` OkHeader + `58B` Noise reply + `26B * hop_acks` trailers |
| `0x13` | `SETUP_ERR` | Reverse | Both | `8B` header + `28B` `HopKey`-sealed error (`36B` total) |
| `0x14` | `SETUP_COOKIE` | Reverse | Both | `8B` header + `56B` XChaCha20-Poly1305 challenge (`64B` total) |
| `0x15` | `SETUP_FRAG` | Forward | Datagram | `16B` fragment header + payload slice (link-local) |
| `0x16` | `SETUP_FRAG_ACK` | Reverse | Datagram | `16B` exact fragment receipt (link-local) |
| `0x20` | `DG_DATA` | Both | Datagram | `5B` hop header (`0x20 \| cid:4B`) + E2E datagram record |
| `0x23` | `DG_CLOSE` | Both | Datagram | `6B` hop control header + `24..=160B` `ControlCipher` body |
| `0x24` | `DG_MTU` | Reverse | Datagram | `6B` hop control header + `ControlCipher` `[epoch:4B \| mtu:2B]` |
| `0x25` | `DG_RENEW` | Forward | Datagram | `6B` hop control header + `ControlCipher` `[id:8B \| cred:0..=128B]` |
| `0x26` | `DG_RENEW_OK` | Reverse | Datagram | `6B` hop control header + `ControlCipher` `[id:8B \| ttl_ms:8B]` |
| `0x27` | `DG_MTU_ACK` | Forward | Datagram | `6B` hop control header + `ControlCipher` `[epoch:4B]` |
| `0x30` | `ST_DATA` | Both | Stream | `4B` chunk header (`0x30 \| 0x00 \| len:2B`) + `1..=16384B` E2E stream bytes |
| `0x33` | `ST_CLOSE` | Both | Stream | `4B` control header + `24..=160B` `ControlCipher` body |
| `0x34` | `ST_RENEW` | Forward | Stream | `4B` control header + `ControlCipher` `[id:8B \| cred:0..=128B]` |
| `0x35` | `ST_RENEW_OK` | Reverse | Stream | `4B` control header + `ControlCipher` `[id:8B \| ttl_ms:8B]` |

Opcodes `0x21`, `0x22`, `0x31`, `0x32` are reserved (MUST be rejected/ignored).

### 5.2 `SETUP_FWD` (`0x11`)

#### ForwardHeader (`8` bytes)

```text
 0      1        2..4          4..8
+------+--------+-------------+----------------+
| 0x11 | 0x00   | max_mtu:u16 | upstream_cid:u32|
+------+--------+-------------+----------------+
```

* Byte 1 **MUST** be `0x00` (else `Malformed`).
* On Stream Plane: `upstream_cid` **MUST** be `0` (`Cid::UNBOUND`).
* On Datagram Plane: `upstream_cid` **MUST NOT** be `0`.
* **Originator Initialization:** On each setup attempt, the Originator initializes `ForwardHeader.max_mtu` to its opened first-hop carrier's effective local MTU (`stream.caps().mtu()` on Stream; live `MtuWatch` effective MTU on Datagram, after verifying `>= min`), and writes the identical effective floor `min` (`max(path.min_mtu, 20)` on Stream; `max(path.min_mtu, caller_min_mtu, 1152)` on Datagram) into every segment's `DispatchPrefix.min_mtu`.

#### Nested Segment Chain

Immediately following `ForwardHeader` is one segment for the current receiver, recursively followed by downstream segments:

* **Transit Hop Dispatch Prefix (`8` bytes, `mode & 0x0f == 1`):**
  ```text
   0      1        2..4          4..6          6..8
  +------+--------+-------------+-------------+-------------+
  | mode | plane  | min_mtu:u16 | seg_len:u16 | tail_len:u16|
  +------+--------+-------------+-------------+-------------+
  ```
* **Destination Endpoint Dispatch Prefix (`6` bytes, `mode & 0x0f == 2`):**
  ```text
   0      1        2..4          4..6
  +------+--------+-------------+-------------+
  | mode | plane  | min_mtu:u16 | seg_len:u16 |
  +------+--------+-------------+-------------+
  ```

Validation rules:
* `mode`: `(mode & !0x13) == 0` AND `(mode & 0x0f) in {1, 2}` (else `Malformed`). Bit `0x10` (`MODE_MAC2`) indicates whether `encrypted` carries a trailing 16-byte `mac2`.
* `plane`: `1` = Datagram, `2` = Stream (else `Malformed`).
* `seg_len >= 120 + (16 if MODE_MAC2 else 0)`.
* For hop segments (`mode & 0x0f == 1`): `tail_len >= 6 + 120 = 126`.
* For destination segments (`mode & 0x0f == 2`): `tail_len = 0`; total segment buffer length MUST equal `6 + seg_len`.
* For hop segments: total remaining buffer length MUST equal `8 + seg_len + tail_len`.
* **Route Integrity (`tail_aad`):**
  ```text
  tail_aad = BLAKE3_hash(dispatch_prefix || tail)
  ```
  Note: `dispatch_prefix` includes the exact `mode` byte (with `MODE_MAC2` bit if set) and `seg_len` (including `mac2` length if set), and `tail` contains the exact raw bytes of all downstream prefixes and segments (empty for destination). Originator builds the chain **back-to-front** (destination first, then `H_{N-1}` down to `H_0`) using one shared `wall_time_ms()` timestamp across all segments in the flight.
* **Stream Framing Limits:** On Stream Plane, receiver **MUST** reject if `seg_len > 2048` (`MAX_SETUP_SEGMENT`) or `8 + prefix_len + seg_len + tail_len > 16384` (`STREAM_CHUNK`). Receiver **MUST** verify `ScopeKid` + `mac1` on a stack buffer before allocating memory for `tail`.
* **Per-Hop Forward Rewriting:** Transit strips `[ForwardHeader (8B) || prefix (8B) || encrypted (seg_len)]` leaving `tail`, and prepends a fresh `ForwardHeader`:
  * `max_mtu = min(incoming.max_mtu, inbound_mtu, outbound_mtu)`
  * `upstream_cid = 0` (Stream) or `outbound_binding.cid` (Datagram).

### 5.3 `SETUP_OK` (`0x12`)

```text
 0      1          2..4             4..8            8..12            12..70             70..70+26*K
+------+----------+----------------+---------------+----------------+------------------+--------------------+
| 0x12 | hop_acks | reverse_mtu:u16| target_cid:u32| responder_cid  | Noise_IK Reply   | Hop Trailers (26B*K)|
+------+----------+----------------+---------------+----------------+------------------+--------------------+
```

* Total length **MUST** equal `70 + 26 * hop_acks`.
* **Stream Plane:** `target_cid == 0`, `responder_cid == 0`, total length `<= 16384`.
* **Datagram Plane:** `target_cid != 0`, `responder_cid != 0`, total length MUST fit within a single datagram (`<= physical_mtu` at each hop; `SETUP_OK` is never fragmented).
* **Destination `B` emits:** `hop_acks = 0`, `reverse_mtu = dest_inbound_mtu`, `target_cid = incoming_upstream_cid`, `responder_cid = dest_binding_cid` (or `0` on Stream), plus 58-byte Noise Message 2 carrying `ack = [dest_inbound_mtu: u16 BE | dest_ttl_ms: u64 BE]`.
* **Each Transit Hop `H_i` mutates in reverse order (`H_{N-1}` -> ... -> `H_0`):**
  1. Verifies `target_cid == right.cid && responder_cid != 0` (Datagram) or both `0` (Stream).
  2. Records `next_cid = ok.responder` (Datagram).
  3. Increments `hop_acks = hop_acks.checked_add(1)` (else `Malformed`).
  4. Clamps `reverse_mtu = min(reverse_mtu, physical_mtu)` where `physical_mtu = min(inbound_mtu, outbound_mtu)`.
  5. Rewrites `target_cid = incoming_upstream_cid`, `responder_cid = left.cid` (Datagram).
  6. Appends 26-byte trailer `HopKey::setup_hop_ack(physical_mtu, hop_lease_ttl_ms)`. (On Datagram, if `len + 26 > physical_mtu`, fails with `MtuTooSmall(physical_mtu)`).
* **Originator `A` Verification:**
  1. Verifies `hop_acks == path.hops.len()` (else `Authentication`).
  2. Finishes destination Noise_IK on `reply[12..70]` -> `(dest_local_mtu, dest_ttl, SessionKeys)`. Validates `dest_ttl` in `1 ms ..= 24 h`.
  3. For each hop `i` in `0..N`: opens trailer at offset `70 + (N - 1 - i) * 26` using `hops[i]` -> `(hop_i_mtu, hop_i_ttl)`. Validates each `hop_i_ttl` in `1 ms ..= 24 h`.
  4. Computes authenticated leg vector `legs = [origin_local_mtu, hop_0_mtu, ..., hop_{N-1}_mtu, dest_local_mtu]`. `path_mtu = min(legs)`. (Cleartext `reverse_mtu` is informational only and MUST NOT determine the path MTU.) If `path_mtu < min_mtu`, fails with `MtuTooSmall(path_mtu)`.

### 5.4 `SETUP_ERR` (`0x13`, `36` bytes) & Wire Error Codes

```text
 0      1          2..4       4..8            8..36
+------+----------+----------+---------------+--------------------------+
| 0x13 | distance | 0x0000   | target_cid:u32| HopKey::setup_error (28B)|
+------+----------+----------+---------------+--------------------------+
```

* Bytes `2..4` **MUST** be `[0x00, 0x00]`.
* Emitter sets `distance = 0`, `target_cid = upstream_cid` (or `0` on Stream).
* Each upstream hop verifies `target_cid == right.cid` (Datagram), increments `distance` (`checked_add(1)`), rewrites `target_cid = upstream_cid`, and forwards.
* Originator decrypts with `destination.hop_key()` when `distance == N` (returning error directly) or `hops[distance]` when `distance < N` (returning `HopRejected { index: distance, reason }`).

#### Normative Wire Error Code Table (`[code: u16 BE | arg: u16 BE]`)

Used identically by `SETUP_ERR`, `ST_CLOSE`, `DG_CLOSE` (hop), and `e2e::DG_CLOSE`:

| `code` | `arg` | Semantic Error |
| --- | --- | --- |
| `1` | `mtu: u16` | `MtuTooSmall(mtu)` |
| `2` | `0` | `Denied` |
| `3` | `0` | `Unpublished` |
| `4` | `0` | `WrongPlane` |
| `5` | `0` | `Timeout` |
| `6` | `0` | `Busy` |
| `7` | `0` | `Revoked` |
| `8` | `0` | `Expired` |
| `9` | `0` | `Closed` |
| `10` | `0` | Remote/generic carrier failure (catch-all when encoding any unlisted `CoreErr`; decodes to permanent carrier failure: `FailureClass::PathFailure`, `is_retryable() == false`) |
| `11` | `0` | `TargetRefused` |
| `12` | `0` | `TargetUnreachable` |
| `13` | `0` | `UnexpectedEof` |
| Any other | — | `Malformed` (on decode) |

Encoders **MUST** write `arg = 0` for codes `2..=13`. Decoders **MUST** verify the decrypted payload is exactly `4` bytes, read `arg` exclusively for code `1` (`MtuTooSmall(arg)`), ignore `arg` on codes `2..=13`, and reject only unknown codes outside `1..=13` as `Malformed`.

### 5.5 `SETUP_COOKIE` (`0x14`, `64` bytes)

```text
 0      1          2..4       4..8            8..64
+------+----------+----------+---------------+---------------------------+
| 0x14 | distance | 0x0000   | target_cid:u32| Cookie Challenge (56B)    |
+------+----------+----------+---------------+---------------------------+
```

* Bytes `2..4` **MUST** be `[0x00, 0x00]`.
* Emitter sets `distance = 0`, `target_cid = upstream_cid` (or `0` on Stream).
* Each upstream hop increments `distance` (`checked_add(1)`), rewrites `target_cid = upstream_cid`, and forwards.

### 5.6 Datagram Link-Local Setup Fragmentation (`0x15` & `0x16`)

Applies **only** on the Datagram Plane when an adjacent hop's `SETUP_FWD` flight exceeds the adjacent link's current effective MTU (`wire.len() > link_mtu`). Each transit re-evaluates independently whether its stripped outbound flight requires fragmentation on its own outbound link.

#### `SETUP_FRAG` (`0x15`, `16 + payload` bytes)

```text
 0      1       2       3       4..8            8..16           16..
+------+-------+-------+-------+---------------+---------------+-------------+
| 0x15 | index | count | 0x00  | upstream_cid  | message_id:u64| payload...  |
+------+-------+-------+-------+---------------+---------------+-------------+
```

#### `SETUP_FRAG_ACK` (`0x16`, `16` bytes exact)

```text
 0      1..4            4..8            8..16
+------+---------------+---------------+---------------+
| 0x16 | 0x00 0x00 0x00| upstream_cid  | message_id:u64|
+------+---------------+---------------+---------------+
```

#### Sender Rules

1. If `wire.len() <= link_mtu`: send plain `SETUP_FWD` (no fragmentation).
2. Otherwise compute `stride = link_mtu.saturating_sub(16)`. If `stride == 0` or `wire.len() > stride * 8`, fail with `MtuTooSmall(link_mtu)`.
3. `count = ceil(wire.len() / stride)` (`2 <= count <= 8`). Generate CSPRNG `message_id: u64`.
4. Split `wire` into `chunks(stride)` and transmit all `count` fragments as a burst (`index = 0..count`). Ignore `WouldBlock` on individual fragment sends; fail immediately on fatal carrier errors.
5. Schedule up to 3 burst retransmissions at `[150 ms, 300 ms, 600 ms]` within the overall `SETUP_TIMEOUT`.
6. Stop retransmitting immediately upon receiving a `SETUP_FRAG_ACK` matching `(upstream_cid, message_id)` (or upon receiving a valid setup reply). Unmatched `SETUP_FRAG_ACK` frames are ignored.

#### Receiver Rules (Per `DatagramPort`)

1. Validate `SETUP_FRAG`: `wire.len() > 16`, `wire[3] == 0`, `2 <= count <= 8`, `index < count`, `upstream_cid != 0`.
2. Expire stale active and completed entries (`expiry <= now`, where lifetime is `SETUP_TIMEOUT = 3 s`) on fragment arrival. (Entries currently authenticating have their assembly buffer removed and are not expired mid-authentication.)
3. If `(upstream_cid, message_id)` is in the `completed` cache (FIFO capacity `32`, `3 s` TTL):
   * If `index == 0`: immediately re-transmit `SETUP_FRAG_ACK` without re-running setup.
   * Otherwise: ignore.
4. If `(upstream_cid, message_id)` matches an active assembly:
   * Ignore if `count != assembly.count` or bit `1 << index` is already set.
   * Compute `offset = stride * index`, `end = min(offset + stride, total)`. Ignore if `payload.len() != end - offset`.
   * Copy `payload` into `wire[offset..end]`, set bit `index`. When all `count` bits are set, detach assembly buffer (keeping slot reserved during authentication) and hand reassembled `SETUP_FWD` to setup admission with a `FragmentReceipt`.
5. If no active assembly matches:
   * Ignore any `index != 0` fragment.
   * For `index == 0`, validate opening BEFORE allocating any reassembly buffer:
     * `ForwardHeader::parse(payload)` succeeds and `hdr.upstream == fragment.upstream_cid`.
     * Leading `Segment::parse_leading(&payload[8..])` succeeds (fragment 0 MUST carry the entire `ForwardHeader + prefix + leading encrypted segment`, which is at most `8 + 8 + 530 = 546` bytes).
     * `segment.plane == Plane::Datagram`.
     * `segment.encrypted.len() <= MAX_SEGMENT (530)`.
     * Let `total = 8 + encoded_size(prefix)`. Require `total > payload.len() + 16` AND `ceil(total / payload.len()) == count`.
     * Look up target scope by `ScopeKid`, ensure scope is accepting (`!pending.is_closed()`), update load, and run `CookieProtector::verify_segment`:
       * `Drop` -> increment `mac1_drops_total`, discard.
       * `Challenge(c)` -> increment `mac2_challenges_total`, send `SETUP_COOKIE(0, upstream_cid, c)` immediately, discard without allocating.
       * `Verified` -> proceed if `active.len() < 16` and `total + allocated_bytes <= MAX_SETUP (131086)`. Allocate reassembly buffer of `total` bytes, copy fragment 0, set `stride = payload.len()`, `received_mask = 1`, `expires = now + 3 s`.
6. **Post-Authentication Acknowledgment & Mid-Reassembly Cookie Re-Evaluation:** Once reassembly completes, the setup task **MUST** re-evaluate `update_load()` and `CookieProtector::verify_segment` BEFORE `Responder::authenticate`. If `under_load` activated or the cookie secret rotated past its grace window mid-reassembly, the setup task sends `SETUP_COOKIE`, drops `FragmentReceipt` without acknowledging (removing the active slot without adding to `completed` and without sending `SETUP_FRAG_ACK`), and aborts with `CookieRequired`. `SETUP_FRAG_ACK` **MUST NOT** be sent until both `CookieProtector::verify_segment` and `Responder::authenticate` succeed (verifying `tail_aad` over the full reassembled flight and Noise_IK authentication). Upon success, remove the active slot, push `(id, now + 3 s)` to `completed` (evicting oldest if full), and transmit `SETUP_FRAG_ACK`. On authentication failure or drop before acknowledgment, remove the active slot without adding to `completed` and without sending `SETUP_FRAG_ACK`.

### 5.7 Steady-State Hop Framing

#### 5.7.1 Datagram Plane Hop Headers

* **`DG_DATA` (`0x20`, `5`-byte header):**
  ```text
   0      1..5         5..
  +------+------------+------------------------+
  | 0x20 | cid:u32 BE | E2E Datagram Record... |
  +------+------------+------------------------+
  ```
  Minimum packet length accepted for forwarding at a transit hop: `DG_OVERHEAD = 30` bytes.
* **Datagram Hop Control (`0x23..=0x27`, `6`-byte header):**
  ```text
   0      1            2..6         6..
  +------+------------+------------+----------------------------+
  | kind | ttl_or_dist| cid:u32 BE | ControlCipher Body (24..160)|
  +------+------------+------------+----------------------------+
  ```
  * Direction enforcement at intermediate transits: `DG_MTU (0x24)` MUST be dropped if received on the forward path (origin -> dest); `DG_MTU_ACK (0x27)` MUST be dropped if received on the reverse path (dest -> origin). `DG_RENEW (0x25)` and `DG_RENEW_OK (0x26)` are not direction-filtered by opcode at transits beyond cryptographic forward/reverse key separation and `ttl`/`distance` bounds (at `ttl == 0` on the forward path, unexpected opcodes such as `DG_RENEW_OK` are ignored).
  * Forward path (origin -> dest): if `ttl == 0`, addressed to this hop (open with `ControlCipher(aad=&[kind])`, silently drop on bad AEAD); if `ttl > 0`, rewrite `ttl = ttl - 1`, `cid = next_cid`, forward downstream.
  * Reverse path (dest -> origin): `distance = ttl.checked_add(1)` (drop on overflow), rewrite `ttl = distance`, `cid = caller_cid`, forward upstream.
  * Hop-originated control (`DG_CLOSE`, `DG_MTU`, `DG_RENEW_OK`): emitted toward origin with `ttl = 0`, `cid = caller_cid`. Origin sees `distance == hop_index` (`0..N-1`).
  * Origin-originated hop control (`DG_CLOSE`, `DG_RENEW`, `DG_MTU_ACK`) targeting hop `i`: emitted with `ttl = i as u8`, `cid = remote_cid`.
  * **Terminal Handling:** Datagram Destination silently ignores all non-`DG_DATA` packets (including all `0x23..=0x27`) in both `AwaitingConfirm` and steady state. Datagram Origin silently ignores `0x23..=0x27` packets with `len < 6`, `distance >= N`, failed `ControlCipher::open`, or opcodes other than `DG_CLOSE`, `DG_MTU`, and `DG_RENEW_OK` (an authenticated `DG_CLOSE` or `DG_RENEW_OK` with an invalid payload terminates with `Malformed`).
* **Inbound CID Dispatch (`route_cid`):**
  * `0x20`: `u32 BE` at offset `1`.
  * `0x23..=0x27`: `u32 BE` at offset `2`.
  * `0x12`, `0x13`, `0x14`, `0x16`: `u32 BE` at offset `4`.
  * `0x11`, `0x15`: returns `Cid::UNBOUND (0)` (dispatched to setup / fragment reassembly).
  * Any other byte 0 or truncated packet: silently ignored.

#### 5.7.2 Stream Plane Hop Headers

```text
 0      1            2..4        4..4+len
+------+------------+-----------+------------------+
| kind | ttl_or_dist| len:u16 BE| payload (len B)  |
+------+------------+-----------+------------------+
```

* `ST_DATA (0x30)`: **MUST** have `ttl == 0` AND `1 <= len <= 16384` (`STREAM_CHUNK`), else `Malformed`. Carries opaque bytes of the E2E record stream (an E2E record MAY span multiple `ST_DATA` chunks, and a single `ST_DATA` chunk MAY carry bytes of multiple E2E records; hop control frames MAY interleave between any two `ST_DATA` chunks).
* `ST_CLOSE (0x33)`, `ST_RENEW (0x34)`, `ST_RENEW_OK (0x35)`: **MUST** have `24 <= len <= 160` (`MAX_CONTROL`), else `Malformed`.
* Forward/reverse `ttl`/`distance` decrement/increment rules are identical to Datagram hop controls (transits do not apply per-opcode direction filters to `ST_RENEW`/`ST_RENEW_OK`; at `ttl == 0` on the forward path, only `ST_CLOSE` and `ST_RENEW` are handled and `ST_RENEW_OK` is ignored).
* **Terminal Hop Control:** Destination `B` also owns `terminal_key` (`HopKey` from destination's Noise_IK Message 1). When closing abnormally (`error != Closed`), `B` emits `ST_CLOSE` with `ttl = 0` sealed under `terminal_key.control(false)`; upstream hops increment `ttl` so Origin receives `distance == N`, decrypts with `terminal_key.control(true)`, and reports the decoded error directly (not wrapped in `HopRejected`). Destination also accepts `ST_CLOSE` with `ttl == 0` sealed under `terminal_key`.

### 5.8 End-to-End Record Framing

Encrypted E2E records use their own opcode space distinct from outer hop opcodes. Outer framing dispatch completes before E2E decryption.

#### 5.8.1 Datagram Plane E2E Records (Payload of `DG_DATA`)

```text
 0..8          8..9+B                        9+B..25+B
+-------------+-----------------------------+--------------+
| seq:u64 BE  | Enc(type:u8 || body[B B])   | tag: 16B     |
+-------------+-----------------------------+--------------+
```

* Minimum length after stripping 5-byte `DG_DATA` header: `25` bytes (`8 + 1 + 16`).
* Cipher: ChaCha20-Poly1305 with `key = session_tx / session_rx`, `nonce = nonce(seq)`, `aad = be64(seq)` (8 bytes).
* Receiver checks 64-packet `ReplayWindow` before decryption, decrypts, commits `seq` on success. Invalid length, replay rejection, or bad AEAD tag **MUST** be silently discarded without terminating the session.
* **Datagram E2E Opcodes (`type`):**
  * `0x01` `DG_DATA`: Application payload (`0..=max_payload`). Special case: `seq == 0 && body.is_empty()` from originator is the 1.0 RTT confirmation marker and **MUST** be suppressed at Destination in both `AwaitingConfirm` and steady state (no application delivery, no `TrafficGate` charging, and no ingress traffic accounting; Originator does not suppress empty `seq == 0` packets sent by Destination).
  * `0x04` `DG_CLOSE`: `[code: u16 BE | arg: u16 BE]` (4 bytes). Terminates session with decoded `CoreErr`.
  * `0x05` `DG_MTU`: `[epoch: u32 BE | mtu: u16 BE]` (6 bytes). Authenticated path/local MTU advertisement.
  * `0x06` `DG_MTU_ACK`: `[epoch: u32 BE]` (4 bytes). Acknowledgment for `DG_MTU`.
  * `0x07` `DG_RENEW`: `[renewal_id: u64 BE | credential: 0..=128 B]` (Origin -> Dest only; ignored/disallowed otherwise).
  * `0x08` `DG_RENEW_OK`: `[renewal_id: u64 BE | remaining_ttl_ms: u64 BE]` (16 bytes; Dest -> Origin only).
  * Opcodes `0x02` and `0x03` are reserved. Unknown E2E opcodes in authenticated datagram records are ignored.

#### 5.8.2 Stream Plane E2E Records (Byte Stream Inside `ST_DATA`)

```text
 0..2            2..3+B                        3+B..19+B
+---------------+-----------------------------+--------------+
| body_len:u16  | Enc(type:u8 || body[B B])   | tag: 16B     |
+---------------+-----------------------------+--------------+
```

* `body_len <= 16365` (`ST_MAX_BODY`), else `Malformed`.
* Total record wire length: `body_len + 19` (`ST_OVERHEAD = 19`).
* Cipher: ChaCha20-Poly1305 with `key = session_tx / session_rx`, implicit monotonic `seq` starting at `0` per direction (`nonce = nonce(seq)`), `aad = be16(body_len)` (2 bytes).
* Any framing violation, AEAD authentication failure, or unexpected E2E opcode **MUST** fail the stream session immediately (`Authentication` or `Malformed`).
* **Stream E2E Opcodes (`type`):**
  * `0x00` `OPEN_OK`: empty body (Dest -> Origin confirmation response).
  * `0x01` `TARGET_REFUSED`: empty body -> `TargetRefused`.
  * `0x02` `TARGET_UNREACHABLE`: empty body -> `TargetUnreachable`.
  * `0x03` `TARGET_BUSY`: empty body -> `Busy`.
  * `0x04` `TARGET_DENIED`: empty body -> `Denied`.
  * `0x10` `ST_DATA`: `0..=max_write_size` bytes. Origin sends empty `ST_DATA` (`seq = 0`) as 1.0 RTT confirmation; empty `ST_DATA` in steady state is ignored; `ST_DATA` after `ST_FIN` or exceeding `max_write_size` is `Malformed`.
  * `0x11` `ST_FIN`: empty body. Authenticated half-close; duplicate `ST_FIN` is `Malformed`.
  * `0x14` `ST_RENEW`: `[renewal_id: u64 BE | credential: 0..=128 B]` (Origin -> Dest only).
  * `0x15` `ST_RENEW_OK`: `[renewal_id: u64 BE | remaining_ttl_ms: u64 BE]` (16 bytes, Dest -> Origin only).
  * Opcodes `0x12` and `0x13` are reserved (MUST be rejected with `Malformed`).

---

## 6. Protocol State Machines & Behavioral Semantics

### 6.1 Originator Dial, Cookie Retry & Staged Confirmation

Originator supports four conceptual dial modes per plane:
* `dial_*` (resolve path via `PathSource`, stage, confirm)
* `dial_*_staged` (resolve path via `PathSource`, stop before 1.0 RTT confirmation)
* `dial_*_via` (use caller-supplied `ExplicitPath`, stage, confirm)
* `dial_*_staged_via` (use caller-supplied `ExplicitPath`, stop before 1.0 RTT confirmation)

#### Staging Flow

1. If scope is shutting down (`sessions` closed): if caller supplied a path, report `PathOutcome::Failed(Closed)` for `path.id`; return `Closed`.
2. Resolve `ExplicitPath` (if not caller-supplied).
3. Reject with `Revoked` immediately if destination `peer` is locally vetoed (`is_vetoed`).
4. Capture outbound revocation epoch (`epoch_for_endpoint(peer, None)`), acquire a `Scope` session permit (`Role::Origin`), compute effective MTU floor:
   * Stream: `min = max(path.min_mtu, 20)`.
   * Datagram: `min = max(path.min_mtu, caller_min_mtu, 1152)`.
5. Look up registered local outbound carrier `path.first_channel` (`Unpublished` if absent); verify `carrier.caps().mtu() >= min` (`MtuTooSmall` otherwise).
6. Fetch initial credentials sequentially via `CredentialProvider::credential` (each bounded by `auth_timeout`, `is_refresh: false`, `previous: &[]`): first for `TargetRef::Endpoint { name: ep, plane }` (verifier `peer`), then for each hop `TargetRef::Transit { name: hop.target, plane }` (verifier `hop.peer`). Wrap fetch errors or length `> 128 B` (`InvalidParameter`) in `CoreErr::Credential(...)`.
7. Execute the **Cookie-Retry Handshake Loop** within a single `SETUP_TIMEOUT` (3 s) deadline, up to `max_attempts = path.hops.len() + 2` iterations:
   * **Stream:** Dial a fresh outbound stream on `first_channel` each attempt, verify `stream.caps().mtu() >= min`, build fresh `SETUP_FWD` with current `cookies` map, write `SETUP_FWD` (`upstream_cid = 0`), read reply:
     * `SETUP_ERR`: decrypt and return error (wrapped in `HopRejected` if hop index `< N`).
     * `SETUP_COOKIE`: unseal cookie for `idx`; if `cookies.insert(idx, cookie)` replaces an existing entry (re-challenged for same node), fail with `CookieRequired`; else loop and retry.
     * `SETUP_OK`: validate header + Noise reply + hop trailers + authenticated `path_mtu >= min`. Break with established state.
   * **Datagram:** Open `first_channel` link ONCE before the loop, attach to `DatagramPort`, allocate one `Binding` (`cid`) reused across retries. Each iteration: verify `binding.mtu() >= min`, build fresh `SETUP_FWD` with `upstream = binding.cid`, transmit via `SetupReplies` (auto-fragmenting if `> binding.mtu()`), receive loop:
     * Ignore malformed, CID-mismatched, or unauthentic replies (on Datagram, spoofed/stray packets MUST NOT abort an in-progress handshake — only authentic `SETUP_ERR`, authentic `SETUP_COOKIE`, or authentic `SETUP_OK` advance state; note `MtuTooSmall` / `Denied` / `Malformed` on an authentic `SETUP_OK` DO fail setup).
     * On authentic `SETUP_COOKIE`: insert into `cookies` (failing with `CookieRequired` on duplicate challenge for same `idx`) and retry on the same `Binding`.
     * On authentic `SETUP_OK`: verify `target == binding.cid && responder != 0`, verify Noise reply + trailers + `path_mtu >= min`. Break.
   * Exhausting `max_attempts` returns `CookieRequired`.
8. Construct originator's endpoint `LeaseHandle` from `dest_ttl` (ceiling `MAX_WIRE_LEASE_TTL`), register with `track_endpoint(epoch, peer, None, &lease)`, initialize `Renewals` with initial `dest_ttl` and `hop_ttls`, and return `StagedStream` / `StagedDatagram`.
9. If staging fails at any step after path resolution, report `PathOutcome::Failed(error)` for `path.id`.

#### Confirmation & Staged Abort

* **Confirm (`StagedStream::confirm`):**
  * If scope is shutting down, report `PathOutcome::Failed(Closed)` and return `Closed`.
  * Transmit empty `e2e::ST_DATA` (`seq = 0`) and await status preamble within `SETUP_TIMEOUT`, racing against `lease.cancelled()`:
    * `OPEN_OK` (empty) -> spawn worker, report `PathOutcome::Established { mtu }`, return `E2eStream`.
    * `TARGET_REFUSED` / `TARGET_UNREACHABLE` / `TARGET_BUSY` / `TARGET_DENIED` (empty) -> fail with corresponding `CoreErr`.
    * `hop::ST_CLOSE` -> authenticate with `hops[index]` (if `< N`) or `terminal` (if `== N`) and return decoded error (wrapping hop errors in `HopRejected`).
    * Any other record -> `Malformed`.
  * On failure, report `PathOutcome::Failed(error)`.
* **Confirm (`StagedDatagram::confirm`):**
  * If scope is shutting down, report `PathOutcome::Failed(Closed)` and return `Closed`.
  * Transmit empty `e2e::DG_DATA` (`seq = 0`) once within `SETUP_TIMEOUT` without retransmission (failing reports `PathOutcome::Failed(error)`; any subsequent application `DG_DATA` also confirms Destination if the empty marker is lost in flight).
  * Immediately spawn worker, report `PathOutcome::Established { mtu }`, and return `E2eDatagram` (zero extra RTT wait).
* **Drop Without Confirming (Abort):**
  * Report `PathOutcome::Closed` to `PathSource`.
  * Best-effort (50 ms timeout) cleanup task:
    * `StagedStream`: send `hop::ST_CLOSE(Closed)` to each intermediate hop in reverse order (`N-1` down to `0`) and shut down the carrier stream.
    * `StagedDatagram`: send `e2e::DG_CLOSE(Closed)` to destination (immediately releasing `AwaitingConfirm` without invoking `EndpointHandler`) followed by `hop::DG_CLOSE(Closed)` to each intermediate hop in reverse order (`N-1` down to `0`).

### 6.2 Inbound Setup Admission & Transit Forwarding

#### Stream Inbound Flow

1. Acquire pending permit (`Node` semaphore first if accepted via `Node`, then `Scope` semaphore after resolving scope).
2. Read `SETUP_FWD` within `SETUP_TIMEOUT`, performing stack-only `ScopeKid` + `mac1` verification before allocating the tail buffer. Reject `hdr.upstream != 0` with `Malformed`.
3. Update scope load state, run `CookieProtector::verify_segment(&source_tag, encrypted, has_mac2)`. On `Challenge`, send `SETUP_COOKIE(0, 0, challenge)` (50 ms best-effort) and abort with `CookieRequired`.
4. Run `Responder::authenticate` (`mac1`, replay check `insert = false`, Noise decrypt, `±30 s` freshness). Any failure inside `Responder::authenticate` (`BadMac`, `Replay`, `Authentication`, `ClockSkew`) **MUST** drop silently without emitting `SETUP_ERR`.
5. **If Hop (`is_hop == true`):**
   * Verify `segment.plane == Plane::Stream` (else send `SETUP_ERR(WrongPlane)`).
   * Parse `(target_name, credential)`, acquire per-peer `PendingSetup`, resolve Stream transit (`Unpublished` / `WrongPlane`), verify `handler.caps().mtu() >= floor` (`floor = max(seg.min_mtu, 20)`), capture `epoch_for_transit`, invoke `AuthGate::authorize(Transit, is_renewal=false)`, create `LeaseHandle`, call `track_transit(epoch, ...)`, call `responder.commit(wall_time_ms())` (rechecking freshness & inserting replay entry), invoke `handler.open(subtarget, session_auth)` racing against `lease.cancelled()` and `SETUP_TIMEOUT`, recheck `lease.remaining()`. On any post-`authenticate` error (including post-decrypt `Malformed` plaintext or `commit()` `ClockSkew`/`Replay`, which encode via catch-all wire code `(10, 0)`) -> send `SETUP_ERR` (50 ms best-effort).
   * Verify actual opened stream `outbound_mtu >= floor && inbound_mtu >= floor` (else send `SETUP_ERR(MtuTooSmall(min))`).
   * Forward `SETUP_FWD(max_mtu=min(hdr.max_mtu, inbound_mtu, outbound_mtu), upstream=0) || tail` downstream and read reply racing against `lease.cancelled()` and `SETUP_TIMEOUT` (on error/cancel -> send `SETUP_ERR`).
   * Handle downstream reply:
     * `SETUP_ERR` / `SETUP_COOKIE`: increment `distance`, forward upstream within deadline, return.
     * `SETUP_OK`: validate `target == 0 && responder == 0`, increment `hop_acks`, clamp `reverse_mtu`, append 26B trailer (`min(inbound_mtu, outbound_mtu), lease_ttl_ms`), ensure `len <= 16384`, acquire `Scope` session permit (`Role::Transit`), write `SETUP_OK` upstream, release `PendingPermit` and `PendingSetup`, enter `splice`.
6. **If Destination (`is_hop == false`):**
   * Verify `segment.plane == Plane::Stream` (else `SETUP_ERR(WrongPlane)`).
   * Parse `(ep_name, credential)`, acquire per-peer `PendingSetup`, capture `epoch_for_endpoint`, look up published endpoint (`Unpublished` / `WrongPlane`), check `forwarded_mtu = min(hdr.max_mtu, inbound_mtu) >= max(seg.min_mtu, 20)` (Stream endpoint publication takes no `min_mtu`; its floor is `0`), invoke `AuthGate::authorize(Endpoint, is_renewal=false)`, create `LeaseHandle`, verify the exact same endpoint publication instance is still registered + `track_endpoint(epoch, ...)`, call `responder.commit(wall_time_ms())`, acquire `Scope` session permit (`Role::Destination`). On any post-`authenticate` error (including `Malformed` plaintext or `commit()` `ClockSkew`/`Replay`, encoded via catch-all `(10, 0)`) -> send `SETUP_ERR`.
   * Generate Noise Message 2 reply carrying `[inbound_mtu: 2B | ttl_ms: 8B]`, create `AwaitingConfirm` holding both `PendingPermit` and `PendingSetup` with deadline `now + SETUP_TIMEOUT`, write `SETUP_OK(hop_acks=0, reverse_mtu=inbound_mtu, target=0, responder=0) || reply`, enter Stream `serve` (with `negotiated_mtu = forwarded_mtu`).

#### Datagram Inbound Flow

1. `DatagramPort` background pump reads packets from `DatagramLink`:
   * Non-`UNBOUND` `route_cid` -> O(1) `SlabTable` lookup -> `try_send` to circuit's 32-slot mailbox (on full: drop + increment `queue_drops_total` and `datagram_mailbox_drops_total`).
   * `Cid::UNBOUND` (`SETUP_FWD` or `SETUP_FRAG`):
     * If `SETUP_FRAG`, feed into `Reassembly` (Section 5.6); proceed only when reassembled (incomplete fragments keep admission `Idle`).
     * Track `AdmissionAttempt` on the `DatagramPort` exposed via `DatagramIngress::admission() -> DatagramAdmission` (`attach_datagram` returns `DatagramIngress` exposing async `closed()` and sync `admission()`): starts `Idle` (`in_flight = 0`), reports `Pending` while any opening attempt is in flight (unless already `Admitted`), becomes permanently `Admitted` once transit or destination admission + permit + CID binding succeeds, and reports `Rejected` once `in_flight == 0` after an attempt drops before `Admitted` (subsequent opening packets transition `Rejected -> Pending` and may still reach `Admitted`). Reaching `Rejected` takes **no** automatic action (it does not close or detach the `DatagramPort`), and Core enforces **no** idle timeout on `Idle`/`Rejected` links.
     * Resolve scope via `ScopeKid` + `mac1`, acquire `Scope::pending_permit`, spawn setup task.
2. Inside setup task: validate `hdr.upstream != 0`, `Segment::parse`, `update_load()`, `CookieProtector::verify_segment` (emitting `SETUP_COOKIE(0, hdr.upstream, challenge)` on challenge and dropping any `FragmentReceipt` without `SETUP_FRAG_ACK`), `Responder::authenticate` (any failure here—including `ClockSkew` or `Replay`—silently drops without `SETUP_ERR` and drops any `FragmentReceipt` without `SETUP_FRAG_ACK`).
3. If the flight was fragmented, acknowledge the `FragmentReceipt` (`SETUP_FRAG_ACK` + `completed` cache) **immediately after `Responder::authenticate` succeeds**. Post-`authenticate` failures (including plaintext `Malformed` and `commit()` `ClockSkew`/`Replay`) emit best-effort `SETUP_ERR` (using catch-all `(10, 0)` for unlisted errors).
4. **If Hop (`is_hop == true`):**
   * Same transit admission sequence as Stream (with `Plane::Datagram`, `floor = max(seg.min_mtu, 1152)`). On error -> send `SETUP_ERR(0, hdr.upstream)` via inbound link.
   * Mark inbound port `Admitted`.
   * Attach outbound `DatagramLink` to `DatagramPort`, allocate `left` binding on inbound port and `right` binding on outbound port, verify `physical = min(inbound_mtu, outbound_mtu) >= floor`.
   * Strip leading segment, prepend `ForwardHeader(max_mtu=min(hdr.max_mtu, physical), upstream=right.cid)`, send via `SetupReplies` (auto-fragmenting if needed), receive loop ignoring mismatched CIDs:
     * `SETUP_OK` (`target == right.cid && responder != 0`): capture `next = ok.responder`, increment `hop_acks`, clamp `reverse_mtu`, rewrite `target = hdr.upstream`, `responder = left.cid`, check `len + 26 <= physical` (else `MtuTooSmall(physical)`), append 26B trailer (`physical, lease_ttl_ms`). Acquire `Scope` session permit (`Role::Transit`; on failure send `SETUP_ERR`), transmit `SETUP_OK` upstream, drop `PendingPermit` and `PendingSetup`, enter `Transit::run`.
     * `SETUP_ERR` (`target == right.cid`): increment `distance`, rewrite `target = hdr.upstream`, forward upstream, exit.
     * `SETUP_COOKIE` (`target == right.cid`): increment `distance`, rewrite `target = hdr.upstream`, forward upstream, and **retain an `Arc` to the outbound `DatagramPort` for `SETUP_TIMEOUT` (3 s)** (`hold_for_cookie_retry`) so the outgoing link's `source_tag` remains stable while Origin retries!
5. **If Destination (`is_hop == false`):**
   * Same endpoint admission sequence as Stream (with `Plane::Datagram`, `floor = max(ep.min_mtu, seg.min_mtu, 1152)`), plus acquire `Scope` session permit (`Role::Destination`) and allocate `binding` CID on inbound port. On any error -> send `SETUP_ERR`.
   * Mark inbound port `Admitted`.
   * Generate Noise Message 2 reply carrying `[inbound_mtu: 2B | ttl_ms: 8B]`, create `AwaitingConfirm`, send `SETUP_OK(hop_acks=0, reverse_mtu=inbound_mtu, target=hdr.upstream, responder=binding.cid) || reply`, enter Datagram `serve`.

### 6.3 1.0 RTT Deferred Destination Open

* **Stream Destination (`serve`):**
  1. Wait (bounded by `AwaitingConfirm.deadline`, `lease.cancelled()`, and inbound `mtu < floor`) for the first E2E record. MUST be `e2e::ST_DATA` (any other record fails with `Authentication`), with `len <= min(negotiated_mtu, 16384) - 19` where `negotiated_mtu = forwarded_mtu = min(hdr.max_mtu, inbound_mtu)` (else `Malformed`).
  2. Re-check `lease.remaining()`, release `AwaitingConfirm` permits (`PendingPermit` + `PendingSetup`).
  3. If first `ST_DATA` carries non-empty 1.0 RTT data, charge `TrafficGate::charge_stream(Direction::Ingress, len)` (handling `Delay` while watching `lease.cancelled()` and `mtu < floor`, or `Close`).
  4. Invoke `EndpointHandler::open(session_auth)` bounded by `SETUP_TIMEOUT`, `lease.cancelled()`, and `mtu < floor`:
     * On `lease.cancelled()` or `mtu < floor`: send best-effort `TARGET_UNREACHABLE`, abort.
     * On handler error: map `TargetRefused -> TARGET_REFUSED`, `Busy -> TARGET_BUSY`, `Denied -> TARGET_DENIED`, all other errors (including timeout) -> `TARGET_UNREACHABLE`; send best-effort status record and abort.
  5. Send `OPEN_OK` (empty body, bounded by `SETUP_TIMEOUT`), start E2E stream worker (pre-seeding `first` if non-empty), and bridge the local `AsyncStream` bidirectionally with clean half-close propagation (`app EOF -> stream.shutdown()`, `stream EOF -> app.shutdown()`).
* **Datagram Destination (`serve`):**
  1. Loop (bounded by `AwaitingConfirm.deadline` and `lease.cancelled()`) reading from `binding`, silently ignoring undecryptable/non-`DG_DATA` packets:
     * Authenticated `e2e::DG_CLOSE` -> abort with `Closed` (never opening handler).
     * Authenticated `e2e::DG_DATA`:
       * If `seq == 0 && body.is_empty()` -> confirmed with `first = None`.
       * Otherwise, if `lease.is_active()` -> confirmed with `first = Some(body)`.
  2. Release `AwaitingConfirm` permits.
  3. If `first` is `Some(pkt)`, evaluate `TrafficGate::check_datagram(Direction::Ingress, pkt.len())`: `Drop` clears `first`; `Close(err)` sends best-effort `e2e::DG_CLOSE(err)` and aborts.
  4. Invoke `EndpointHandler::open(session_auth)` bounded by `SETUP_TIMEOUT` and `lease.cancelled()`. On any failure, send best-effort `e2e::DG_CLOSE(error)` and abort.
  5. Start E2E datagram worker (pre-seeding `first` if `Some`) and bridge the local `DatagramLink` bidirectionally. App-originated packets exceeding current `max_payload` (`MessageTooLarge`) are dropped without terminating the session.

### 6.4 Steady-State Stream Engine

* **E2E Record Chunking & Reassembly:**
  * Outgoing E2E records (`len = body.len() + 19`) are sliced into `ST_DATA` chunks of size `min(current_mtu, 16384)`. If `min(current_mtu, 16384) < floor`, fail with `MtuTooSmall`.
  * Incoming reader reassembles E2E records across `ST_DATA` chunk boundaries while immediately dispatching any interleaved `ST_CLOSE`, `ST_RENEW`, `ST_RENEW_OK` hop control frames.
* **Reliable Frame Writing (`write_frame`):**
  * When a carrier `StreamWrite::write` or `flush` returns a retryable error (`is_retryable() == true`), Core MUST retain the exact unwritten byte slice and retry with exponential backoff (`10 ms`, doubling up to `200 ms`) within a `3 s` budget from the first retryable error. Any forward progress (`n > 0` bytes written) resets the backoff to `10 ms` (the `3 s` budget stays anchored or completes on finish). Exceeding `3 s` fails with `Timeout`. Returning `Ok(0)` fails with `UnexpectedEof`.
* **Stream Transit Splicing (`st_splice`):**
  * Runs two directional loops (`left -> right` = `Ingress`, `right -> left` = `Egress`), live MTU floor monitors on both links (`below_floor`), lease cancellation, scope shutdown, and a renewal verifier task.
  * Reads `ST_DATA` in quanta of up to `min(remaining_chunk_len, outbound_mtu.max(1), 4096)` bytes. For each quantum: checks `lease.remaining()`, evaluates `TrafficGate::charge_stream(dir, quantum_len)` (sleeping on `Delay` and re-checking `lease.remaining()`), forwards as `ST_DATA`, updates traffic counters.
  * Control frames (`ST_CLOSE`, `ST_RENEW`, `ST_RENEW_OK`) bypass `TrafficGate`. `ST_CLOSE` addressed to this hop (`ttl == 0`, authentic) terminates splice cleanly (`Ok(())`).
  * On abnormal termination (`Err(e)`), including an unexpected EOF on the downstream (`right`) carrier before a `hop::ST_CLOSE` (`Err(UnexpectedEof)`), sends best-effort (50 ms) `hop::ST_CLOSE(e)` upstream (`ttl = 0`).
* **E2E Stream Lifecycle & Clean Half-Close (`ST_FIN`):**
  * `max_write_size = min(negotiated_mtu, 16384) - 19` (at most `16365`), fixed at setup from `negotiated_mtu` (on Destination, `forwarded_mtu = min(hdr.max_mtu, inbound_mtu)`). Subsequent live `MtuWatch` drops while `>= floor` shrink outgoing `ST_DATA` hop chunk sizes without changing `max_write_size`; dropping `< floor` terminates with `MtuTooSmall`.
  * `read()` returns `Ok(0)` **only** after an authenticated `ST_FIN` has been received. Carrier EOF before `ST_FIN` fails the session with `UnexpectedEof`.
  * Once `ST_FIN` is received (`RECEIVED_FIN`), carrier EOF (or hop `ST_CLOSE` with `Closed`/`UnexpectedEof`) does **not** abort the outbound half until local `ST_FIN` (`SENT_FIN`) is also sent.
  * Once BOTH `RECEIVED_FIN` and `SENT_FIN` have occurred, the session terminates cleanly (`Closed`, clean = true) even if an underlying hop or carrier closes concurrently.
  * On teardown:
    * Origin sends best-effort (50 ms) `hop::ST_CLOSE(error)` to hops `N-1` down to `0`, shuts down the carrier writer, and reports `PathOutcome::Closed` (if `error == Closed`) or `PathOutcome::Failed(error)`.
    * Destination sends best-effort `hop::ST_CLOSE(error)` (`ttl = 0`, sealed with `terminal_key`) and shuts down the carrier writer ONLY if `error != Closed`.

### 6.5 Steady-State Datagram Engine

* **Per-Link Generational Circuit Table (`SlabTable`):**
  * Every attached `DatagramLink` (deduplicated by `LinkId`) owns ONE `DatagramPort` with ONE `SlabTable` (limit `4096` active slots).
  * `Cid` (32 bits): `[generation: 8 bits (1..=255) | slot_idx: 24 bits (0..2^24-1)]`. `Cid::UNBOUND = 0` is never allocated.
  * On allocation: prefer free-list slot -> else expired quarantine head (`now - retired_at >= 60 s`) -> else append new slot with `generation = 1` (up to `2^24` slots).
  * On removal: if `generation < 255`, increment `generation += 1` and push onto free list; if `generation == 255`, reset `generation = 1` and push `(slot_idx, now)` onto FIFO quarantine queue for `60 s`.
* **Application Send/Recv Semantics (`E2eDatagram`):**
  * `max_payload = current_path_mtu.saturating_sub(30)`.
  * Oversized outbound datagram (`packet.len() > max_payload`) **MUST** fail synchronously with `CoreErr::MessageTooLarge(max_payload)` **without** sending anything on the wire and **without** closing the session.
  * Non-blocking `send` returns `CoreErr::WouldBlock` when the 16-packet outbound queue is full; `send_wait` awaits capacity and re-checks `max_payload` before enqueuing.
  * Inbound 16-packet queue drops excess authenticated packets (incrementing `queue_drops_total`) rather than stalling the session control loop.
* **Datagram Transit Switching (`Transit`):**
  * Forwards `DG_DATA` in place by rewriting bytes `1..5` to the next-hop `Cid` (zero payload copy, zero heap allocation).
  * Drops `DG_DATA` silently if `len < 30`, if `!lease.is_active()`, or if `len > outbound_limit` (triggering MTU reassertion).
  * Evaluates `TrafficGate::check_datagram(dir, packet.len())` strictly on `DG_DATA` (`Drop` increments `traffic_gate_drops_total`; `Close(err)` tears down circuit).
  * Retryable carrier send errors (`is_retryable()`) drop the packet and increment `queue_drops_total` without closing the circuit.
  * On termination with error, sends best-effort (50 ms) `hop::DG_CLOSE(error)` upstream (`ttl = 0`, `cid = caller_cid`).
* **E2E Datagram Session Teardown:**
  * Sends best-effort (50 ms) `e2e::DG_CLOSE(error)` to peer, plus (if Origin) `hop::DG_CLOSE(error)` to hops `N-1` down to `0`, and reports `PathOutcome::Closed` / `PathOutcome::Failed(error)`.

### 6.6 Live Datagram Path MTU Agreement Protocol

Core maintains one bidirectional path MTU across all legs without trusting cleartext headers:

* **State:**
  * **Each Transit Hop `i`:** tracks `[left_link_mtu, right_link_mtu]` from `MtuWatch`es and `EMSGSIZE` / `MtuTooSmall(bound)` send errors. Effective hop MTU is `min(left, right)`.
  * **Destination `B`:** tracks `origin_path_mtu` (initialized to forwarded `min(hdr.max_mtu, inbound_mtu)`) and `local_mtu` (live `MtuWatch`). Effective session MTU is `min(origin_path_mtu, local_mtu)`. Advertises `local_mtu` to Origin via E2E `DG_MTU`.
  * **Origin `A`:** tracks `legs[0..N+2] = [local_mtu, hop_0_mtu, ..., hop_{N-1}_mtu, dest_local_mtu]`, per-hop `hop_epochs[0..N]`, and `peer_epoch`. Effective session MTU is `min(legs)`. Advertises `min(legs)` to Destination via E2E `DG_MTU`.
* **Reliable Epoch-Based Reporting (`MtuReporter`):**
  * Every report carries `[epoch: u32 BE | mtu: u16 BE]` (6 bytes); every ACK carries `[epoch: u32 BE]` (4 bytes).
  * `epoch` starts at `0` and wraps via `wrapping_add(1)` on each new publication.
  * Serial-number freshness (`advance_epoch`): an incoming `epoch` is strictly newer than `seen` iff `1 <= epoch.wrapping_sub(seen) < 2^31`.
  * A receiver **MUST** always reply with an ACK (`hop::DG_MTU_ACK` or `e2e::DG_MTU_ACK`) echoing the received `epoch` (even for duplicates/older epochs), and **MUST** apply the reported `mtu` ONLY when `advance_epoch` returns `true`.
  * Sender transmits immediately upon update, then retries up to 5 times at `[150, 300, 600, 1200, 2400]` ms (using a fresh AEAD sequence number each retry while preserving the same `epoch`) until ACKed or superseded by a newer update.
  * **Reassertion:** When an oversize packet is dropped at a transit or a link send fails with `MtuTooSmall(bound)`, the node clamps its local limit and `MtuWatch` seen bound to `min(limit, bound)` and calls `reassert(now)` (which publishes a new epoch with the current advertised MTU if no report is pending and at least `200 ms` have elapsed since the previous send).
* **Updates & Floor Violations:**
  * Immediately upon worker startup (after confirmation), both Origin and Destination sample their live `MtuWatch`, re-evaluate the path MTU against `floor`, and flush any resulting MTU advertisement (catching link MTU shifts that occurred between `SETUP_OK` and confirmation).
  * Whenever Origin's `min(legs)` changes (and remains `>= floor`), Origin updates `max_payload`, increments `mtu_updates_total`, reports `PathOutcome::MtuChanged { mtu }` to `PathSource`, and advertises the new `min(legs)` to Destination.
  * At Origin or Destination: if effective path MTU drops `< floor`, immediately terminate the session with `MtuTooSmall(mtu)`.
  * **Transit Floor-Violation Drain:** When a Transit hop's `min(left, right)` drops `< min_mtu`, it **MUST NOT** immediately vanish silently: it enters a **drain window** of `REPORT_TIMEOUT = 5 s`, publishes the below-floor `mtu` upstream via `hop::DG_MTU`, and keeps forwarding control frames so Origin can observe the floor violation and deliver its authenticated `e2e::DG_CLOSE(MtuTooSmall)` to Destination. The transit exits with `MtuTooSmall(bound)` as soon as Origin sends `hop::DG_CLOSE` or the 5 s drain deadline expires.

### 6.7 Idempotent In-Band Lease Renewal Protocol

Both planes use the identical renewal payload format and idempotency state machine:
* **Request payload:** `[renewal_id: u64 BE | credential: 0..=128 B]` (`renewal_id == 0` is `Malformed`).
* **Ack payload (`16` bytes):** `[renewal_id: u64 BE | remaining_ttl_ms: u64 BE]` (`renewal_id == 0` or `ttl_ms == 0` is `Malformed`; `ttl_ms > 24 h` is `Denied`).
* **Carriers:**
  * Endpoint slot: `e2e::ST_RENEW` / `e2e::ST_RENEW_OK` (Stream) or `e2e::DG_RENEW` / `e2e::DG_RENEW_OK` (Datagram).
  * Hop `i` slot: `hop::ST_RENEW` / `hop::ST_RENEW_OK` (Stream) or `hop::DG_RENEW` / `hop::DG_RENEW_OK` (Datagram) sealed with `ControlCipher` (`ttl = i` forward, `distance = i` reverse).

#### Originator Driver (`Renewals`)

1. Manages `1 + N` independent slots (`Endpoint` + `Hop(0..N-1)`), each initialized from the TTLs authenticated in `SETUP_OK` (zero `t = 0` renewal burst).
2. Each slot independently tracks: `credential`, `refresh_at`, `expires_at`, `retries`, `acknowledged: u64` (starts `0`), `in_flight: Option<(id, credential)>`.
3. When `with_ttl(ttl, now)` runs: `retries = 0`, `expires_at = now + ttl`, `refresh_at = now + ttl * (70..=80)%` (uniform random integer percent `70..=80`).
4. If ANY slot reaches `expires_at`: increment `lease_renewal_failures_total` and terminate the session with `Expired` (Endpoint) or `HopRejected { index, reason: Expired }` (Hop).
5. When a slot reaches `refresh_at`:
   * If `retries > 0`, increment `lease_renewal_retries_total`.
   * If `in_flight` is already `Some`: re-enqueue the **exact same `(id, credential)`** without re-querying `CredentialProvider`.
   * If `in_flight` is `None`: asynchronously invoke `CredentialProvider::credential` with `is_refresh: true`, `previous: last_acknowledged_credential`, bounded by `min(auth_timeout, remaining_slot_lease / 2)`. Validate credential length `<= 128 B` (else wrap `InvalidParameter` in `CoreErr::Credential`).
     * On success: assign `id = acknowledged.checked_add(1)` (else `Closed`), store `in_flight = Some((id, cred))`, send request.
     * On error: if `!error.is_retryable()`, increment `lease_renewal_failures_total` and immediately fail the session with `error`. If retryable, schedule retry.
   * After every send/retryable-error attempt, schedule next `refresh_at = now + delay`:
     * `base = 1000 ms` (Stream) or `100 ms` (Datagram).
     * `ceiling = min(base << min(retries, 6), 5000 ms)`.
     * Random jitter in `[ceiling / 2, ceiling)`.
     * Clamp: `delay = max(min(delay, remaining_slot_lease / 3), 10 ms)`.
     * Increment `retries`.
6. On receiving `RenewalAck(slot, id, ttl)`:
   * Accept **ONLY** if `slot.in_flight` has `request.id == id`. Ignore stale or mismatched IDs (so a late ACK cannot complete a subsequent renewal!).
   * For `Endpoint` slot: update local `LeaseHandle` TTL (`MAX_WIRE_LEASE_TTL`).
   * Set `acknowledged = id`, `credential = request.credential`, call `with_ttl(ttl, now)`, increment `lease_renewals_total`.

#### Verifier (`RenewalVerifier`)

1. Tracks `applied: u64` (initialized to `0`) and evaluates at most one renewal at a time per session/circuit.
2. On receiving `(id, credential)`:
   * **`id == applied + 1`:** Invoke `AuthGate::authorize(..., is_renewal: true)` and `LeaseHandle::renew_lease_with_max_ttl(renewed_lease)` (which atomically updates TTL, swaps `TrafficGate`, updates live `AuthExtensions` / `SessionAuth`, and preserves initial `SessionGuard`s while appending any new ones).
     * On success: set `applied = id` and send `RENEW_OK(id, max(lease.remaining(), 1 ms))`.
     * On retryable error (`Timeout`, `Busy`): do NOT terminate and do NOT send `RENEW_OK` (origin will retry while lease remains valid).
     * On non-retryable error (`Denied`, `Revoked`, `Expired`): immediately terminate the session/circuit.
   * **`id == applied` (duplicate of latest applied renewal):** Do **NOT** re-invoke `Authorizer` and do **NOT** extend the lease. Check `lease.remaining()?` and send `RENEW_OK(id, max(remaining, 1 ms))`.
   * **Any other `id`:** Silently ignore.

### 6.8 Graceful Shutdown & Draining

* `begin_shutdown()` on a scope:
  1. Closes both `pending` and `sessions` semaphores so all new inbound setups, `accept_stream`, `attach_datagram`, and outbound dials fail immediately with `Closed`.
  2. Signals the scope shutdown watch (with no imposed drain timeout bound):
     * Active Stream sessions initiate an authenticated `ST_FIN` (once any delayed pending write completes) and remain open until peer `ST_FIN`, carrier EOF/error, `hop::ST_CLOSE`, lease expiry/revocation, MTU floor violation, or local handle drop.
     * Active Datagram sessions and Stream/Datagram transit circuits terminate cleanly with `Closed` (sending best-effort close frames).
* `is_drained()` returns `true` when all pending permits, session permits, and destination stream bridge tasks have finished and been released.
* `Node::close_admission()` closes the shared node ingress semaphore (`accept_stream` and `attach_datagram` return `Closed`).

---

## 7. Trust, Authorization, Leases & Revocation Model

### 7.1 `AuthGate` Fail-Closed Enforcement

Every `ScopeInstance` wraps its `Authorizer` in an `AuthGate` with clamped `AuthLimits`:
1. **Local Hard Veto Check:** Reject immediately with `Revoked` if `peer` is in the local `vetoed` set (checked BOTH before and after invoking `Authorizer`).
2. **Per-Peer Pending Quota:** Reserve a RAII `PendingSetup` slot for `peer` before authorization (capped by `per_peer_pending`, failing with `Busy` and incrementing `capacity_drops_total` when saturated). Held until setup confirms (Destination) or splice/switch activates (Transit).
3. **Bounded Concurrency & Hard Timeout:** Acquire one permit from `auth_concurrency` semaphore and run `Authorizer::authorize(req)` under a single monotonic `deadline = now + auth_timeout`. If the deadline elapses (including if `clock.now() >= deadline` right after completion), fail closed with `Timeout`.
4. **Lease TTL Validation:** Reject with `Denied` if `lease.ttl.as_millis() == 0` or `lease.ttl > limits.max_lease_ttl`.
5. **Default Policies:** Fail-closed defaults MUST be used unless configured: `DenyAllAuthorizer`, `NoRoutes`, `EmptyCredentials`.

### 7.2 Host Sovereignty & `IntersectAuthorizer`

`IntersectAuthorizer(local, external)` composes a local host policy with an external verifier:
1. **Evaluation Order:** Evaluates `local.authorize(req)` FIRST. If `local` returns `Err`, `external` is NOT called (local hard veto). If either denies, fails closed.
2. **Lease Intersection (`local.intersect(external)`):**
   * `ttl = min(local.ttl, external.ttl)`.
   * `gate`: if both present, wrap in `IntersectGate`:
     * `check_datagram(dir, bytes)`: call `local` first; only if `local` returns `Allow`, call `external`. Otherwise return `local`'s `Drop` or `Close`.
     * `charge_stream(dir, bytes)`: call `local` first; if `Close`, return immediately; else call `external`. If either returns `Close`, return `Close`; if both `Delay(a)` and `Delay(b)`, return `Delay(max(a, b))`; if one `Delay(d)` and one `Allow`, return `Delay(d)`; else `Allow`.
   * `guards`: concatenate `local.guards` + `external.guards` (both sets remain alive until session close).
   * `extensions`: type-keyed merge preserving `local`'s entry on same-type collision (external authorizers can never overwrite local host claims).
3. **Revocation Streams:** Collects both `local` and `external` revocation streams directly without spawning intermediate forwarding tasks.

### 7.3 `Lease`, `LeaseHandle`, `TrafficGate` & Live `SessionAuth`

* **Lock-Free Hot Path:** `LeaseHandle` stores `expires_at` (monotonic nanos) and `revoked` as atomics (cache-line aligned) so `is_active()` is lock-free with zero contention.
* **Lock-Free `TrafficGate` Caching:** `LeaseHandle` maintains an atomic `gate_gen` counter incremented whenever renewal swaps `gate`. Per-session tasks cache `(seen_gen, Option<Arc<dyn TrafficGate>>)` so hot-path checks cost a single atomic load between renewals.
* **Renewal In-Place Update Semantics:**
  * Rejects if new `ttl` is `0 ms` or `> max_ttl` (`Denied`), or if the lease is already expired/revoked.
  * Atomically swaps `gate` and bumps `gate_gen`.
  * **Preserves all existing `SessionGuard`s** (appending any additional guards returned on renewal); all guards drop only when the `LeaseHandle` drops on session/circuit termination.
  * Publishes the new `AuthExtensions` snapshot to the watch channel backing all live `SessionAuth` clones so `auth.context::<T>()` immediately reflects updated roles/claims and `auth.changed().await` wakes listeners.
  * Extends `expires_at = clock.now() + lease.ttl` and wakes expiration sleepers.
* **`TrafficGate` Enforcement Contract:**
  * Enforced **strictly on `DATA` frames/chunks** after per-circuit demultiplexing (NEVER on `SETUP*`, `RENEW*`, `CLOSE`, `MTU*`, or `FIN`).
  * Enforced on **verifiers only** (Destinations and Transits; never on Originator).
  * Direction relative to verifier: `Ingress` = Origin -> Destination, `Egress` = Destination -> Origin.
  * Byte argument:
    * Datagram Transit: full forwarded wire packet length (including 5B hop header).
    * Datagram Destination: decrypted E2E payload length.
    * Stream Transit: ciphertext quantum length read from `ST_DATA` (up to `4096` B).
    * Stream Destination: decrypted E2E `ST_DATA` payload length.

### 7.4 Publication Namespaces, Precedence & Scoped Revocation

* **Name Validation:** All carrier, endpoint, exact-transit, and prefix-transit names MUST be `1..=255` UTF-8 bytes (else `InvalidParameter`). Duplicate registration in the same table returns `AlreadyPublished`.
* **Endpoint Namespace:** Single table shared across Stream and Datagram planes. Publishing a Stream endpoint takes no `min_mtu` parameter (implicit floor `0`, clamped to `20` during setup); publishing a Datagram endpoint accepts `min_mtu` and rejects `min_mtu < 1152` at publish time (`MtuTooSmall`). Dialing an endpoint on the wrong plane returns `WrongPlane`.
* **Transit Namespace:** Four separate tables: `(Stream, exact)`, `(Datagram, exact)`, `(Stream, prefix)`, `(Datagram, prefix)`.
  * Exact and prefix publications for the same plane MAY coexist, and identical names on different planes MAY coexist.
  * **Resolution Precedence (for plane `P` and target `T`):**
    1. Exact match in `(P, exact)` -> `subtarget = T`.
    2. Longest prefix `p` in `(P, prefix)` such that `T.starts_with(p)` AND `T.len() > p.len()` (suffix MUST be non-empty) -> `subtarget = &T[p.len()..]`.
    3. If `T` matches any exact or prefix entry on the OTHER plane -> `WrongPlane`.
    4. Otherwise -> `Unpublished`.
  * **Authorization Target Name:** `Authorizer` ALWAYS evaluates the **full requested target name `T`**, whereas `TransitHandler::open` receives `subtarget` (suffix for prefix publications, full name for exact publications).
* **RAII `PublishGuard` & `TransitRevoker`:**
  * Each transit publication is assigned a unique monotonic `PublicationId`.
  * Dropping an endpoint `PublishGuard` removes the endpoint and revokes all its active sessions with `Unpublished`.
  * Dropping a transit `PublishGuard` marks `publication.active = false`, removes it from its table, and revokes all circuits admitted under that `PublicationId` with `Unpublished` (without disturbing overlapping exact/prefix publications or subsequent replacement publications).
  * `TransitRevoker` (derived from a transit `PublishGuard`) exposes `revoke_target(target)` scoped strictly to that `PublicationId` and plane (taking the suffix for prefix publications, validating `!target.is_empty() && target.len() <= 255 - prefix.len()`, or exact name for exact publications), revoking only matching circuits of that publication with `Revoked`.

### 7.5 TOCTOU-Free Revocation Epochs & Instant Cancellation

* **Sharded Weak Registry (`RevocationIndex`):** 16-way sharded map of `RevocationKey -> Vec<Weak<LeaseHandle>>` indexing active leases by:
  * `Peer(PublicKey)`
  * `Endpoint(String)`
  * `Transit(Plane, String)` (both full name and matched prefix if prefix-matched)
  * `Publication(PublicationId)`
  * `PublicationTarget(PublicationId, String)` (`subtarget`)
  Stale weak pointers are pruned lazily on insertion. Revocation removes the key and calls `lease.revoke(reason)` on every live `Arc`.
* **TOCTOU Prevention:** Before awaiting `Authorizer::authorize`, Core captures an `AuthEpoch` snapshot (`global`, `peer`, `endpoint` or `transit`, `transit_prefix`, `publication_target`). After authorization, under the host-state lock, Core verifies no relevant epoch changed, `peer` is not vetoed, and the publication is still active/identical before tracking the lease. If any raced revocation occurred, admission fails with `Revoked` (or `Unpublished`).
* **Epoch Table Bounding:** If total fine-grained epoch entries reach `16384`, increment `global_epoch` and clear all fine-grained epoch maps.
* **Revocation Event Semantics:**
  * Host `Scope::revoke_peer(pk)`: inserts `pk` into `vetoed` (blocking future inbound AND outbound dials) + revokes active sessions (`Revoked`). `unrevoke_peer(pk)` removes from `vetoed`.
  * Authorizer `Revocation::Peer(pk)`: revokes active sessions (`Revoked`) WITHOUT inserting into `vetoed` (future dials re-query `Authorizer`).
  * Authorizer `Revocation::Endpoint(name)`: revokes endpoint sessions (`Unpublished`).
  * Authorizer `Revocation::Transit(name)` / Host `Scope::revoke_transit(name)`: revokes transit circuits across **both** planes (`Revoked`).
  * Authorizer `Revocation::All`: increments `global_epoch` and revokes ALL active leases in the scope (`Revoked`).
  * **Broadcast Lag Fail-Closed:** If a scope's background revocation-stream listener receives `Lagged(n)`, it **MUST** increment `revocation_lag_invalidations_total` and immediately invalidate ALL active leases in the scope (`Revoked`).

---

## 8. Multi-Scope Hosting (`Node`) & Runtime Integration

### 8.1 Runtime Abstractions

* **`MonotonicTime`:** 64-bit nanosecond timestamp relative to a clock's origin (saturating addition with `Duration`, saturating duration subtraction). Timestamps are comparable only within the same `Clock` domain.
* **`Clock`:** `now() -> MonotonicTime` (non-blocking, non-decreasing) and `sleep_until(deadline) -> Future<Output = ()>` (past deadline immediately ready; dropping future cancels timer).
* **`TaskSpawner`:** `spawn(Future<Output = ()> + Send + 'static)` for scope/node-owned background tasks.

### 8.2 Multi-Scope `Node` Rules

1. **Shared Clock Domain:** `Node::add_scope(scope)` **MUST** verify the scope shares the exact same `Clock` instance as the `Node` (`InvalidParameter` otherwise).
2. **Uniqueness & Single Membership:** Mounting fails with `AlreadyPublished` if a scope with the same `PublicKey` or `ScopeKid` is already mounted, or if the scope is already mounted on a `Node`.
3. **$O(1)$ Multi-Scope Demultiplexing:**
   * Stream: reads up to the leading segment on a stack buffer, looks up `Scope` by `ScopeKid` (`segment[0..8]`), verifies `mac1`, then acquires the scope's pending permit and dispatches identically to single-scope ingress.
   * Datagram: `DatagramPort` attached via `Node::attach_datagram` marks `node_wide = true` and dispatches any `SETUP_FWD` / `SETUP_FRAG` whose `ScopeKid` matches any mounted scope (after `mac1` verification).
   * Front-door `precheck_datagram_setup(wire) -> bool` (available on both `ScopeInstance` and `Node`) provides stack-only `ScopeKid` + `mac1` filtering for shared UDP listeners. It **MUST** accept both unfragmented `SETUP_FWD` (`0x11`, validating `upstream_cid != 0` and `plane == Datagram`) and fragment 0 of `SETUP_FRAG` (`0x15`, passing `Fragment::opening()` validation) so fragmented setup flights are not dropped at the socket boundary. It **MUST** return `false` once the matching scope stops accepting (`pending.is_closed()`).
4. **Per-Link `DatagramPort` Deduplication & Adoption:**
   * Concurrent attachments of the same `DatagramLink` (same `LinkId`) across scopes mounted on the same `Node` **MUST** share ONE `DatagramPort` and ONE `SlabTable` (preventing duplicate `recv()` loops and preserving per-link CID isolation).
   * Mounting a scope that already has live attached `DatagramPort`s atomically validates capacity (`max_datagram_ports`, failing `Busy`), checks for conflicting `LinkId` ports (`AlreadyPublished`), and adopts those ports into the `Node` registry with `node_wide = false` (restricted to explicitly attached scopes unless also attached node-wide).
   * Unmounting a scope (`remove_scope`) removes its `ScopeKid` from the `Node` and from all explicit scope lists on its attached `DatagramPort`s.
5. **Listener Loops:** `serve_stream_listener` and `serve_datagram_listener` (on both `ScopeInstance` and `Node`) ignore per-connection admission errors (e.g., `Busy`) and terminate only when the underlying listener returns an accept error.

### 8.3 Zero-Copy Packet Buffer (`PacketBuf`) Contract

* Allocates `HEADROOM_BYTES (64) + payload_capacity + TAILROOM_BYTES (64)` with `head = 64`, `tail = 64`.
* Supports in-place `prepend_header`, `strip_header`, `strip_tail`, `extend_tail` / `append_tag`, `spare_payload`, and `advance_payload` without reallocation.
* **Zero-Allocation Hot-Path Requirement:** Sealing a datagram (`DatagramTx`), prepending/rewriting/stripping the 5-byte `DG_DATA` hop header, stacking outer AEAD wrappers, and opening a datagram (`DatagramRx`) **MUST** perform **zero heap allocations** and keep the payload pointer stable in place.

---

## 9. Extension Seam Contracts, Errors & Cleanroom API Freedom

Cleanroom agents MAY redesign exact Rust trait/struct names and signatures for ergonomics, provided the four extension seams preserve these exact semantic contracts.

### 9.1 The Four Extension Seams

1. **Seam 1 — Pure Composable Channels & Listeners:**
   * **Capabilities (`ChannelCaps`) & `MtuWatch`:** Exports `effective_mtu`, `base_mtu`, `reliable_underlay`, and a live `MtuWatch`. `MtuWatch` **MUST** support zero-task vertical composition via `with_overhead(extra)` (subtracting overhead saturatingly) and `with_cap(max)` (capping effective MTU), suppressing spurious notifications when transformed effective MTU did not change, and allowing local `clamp_seen(bound)` on `MtuTooSmall` send failures.
   * **Stream Plane:** `StreamChannel` (`caps`, `dial_stream(locator)`), `StreamListener` (`accept`), `AsyncStream` (`caps`, `split() -> (Read, Write)`, optional 16-byte `source_tag()` defaulting to `[0; 16]`). Read/Write halves SHOULD be poll-based and dyn-safe for zero-allocation hot-path I/O.
   * **Datagram Plane:** `DatagramChannel` (`caps`, `open_link(locator)`), `DatagramListener` (`accept_link`), `DatagramLink` (`caps`, `current_mtu`, `poll_send_ready`, `try_send(PacketBuf)`, `poll_recv`, optional 16-byte `source_tag()`, stable logical `LinkId`). `LinkId::allocate()` MUST guarantee unique logical IDs that never collide with pointer-derived fallback IDs (e.g., reserving bit 63 for allocated IDs).
   * Vertical wrappers MUST compose statically at compile time with single type erasure at the Core boundary.
2. **Seam 2 — Pure Route / Path Source (`PathSource`):**
   * `resolve_path(peer, endpoint, plane) -> Result<ExplicitPath, CoreErr>`
   * `report_outcome(path_id, PathOutcome)` where `PathOutcome` distinguishes `Established { mtu }`, `MtuChanged { mtu }`, `Failed(CoreErr)`, and `Closed`.
   * `ExplicitPath { id: u64, first_channel: String, first_locator: Vec<u8>, min_mtu: u16, hops: Vec<HopSpec> }` where `HopSpec { peer: PublicKey, target: String }` carries **zero credentials** and **zero raw downstream network addresses**.
3. **Seam 3 — Symmetric Auth (`CredentialProvider` ↔ `Authorizer`):**
   * `CredentialProvider::credential(CredentialRequest)` receives `{ verifier, target: TargetRef, destination, endpoint, path_id, is_refresh, previous }` and returns `0..=128` opaque bytes.
   * `Authorizer::authorize(AuthRequest)` receives `{ peer, target: TargetRef, credential, is_renewal }` and returns `Result<Lease, AuthDenied>` (`AuthDenied::Denied | AuthDenied::Busy`), plus optional live revocation stream(s) (`Revocation::{Peer, Endpoint, Transit, All}`).
   * Core provides `EmptyCredentials`, `DenyAllAuthorizer`, and `IntersectAuthorizer`.
4. **Seam 4 — Endpoints & Named Transits:**
   * `StreamEndpointHandler::open(auth: SessionAuth) -> Result<AsyncStream, CoreErr>`
   * `DatagramEndpointHandler::open(auth: SessionAuth) -> Result<DatagramLink, CoreErr>`
   * `StreamTransitHandler` (`caps()`, `open(target: &str, auth: SessionAuth) -> Result<AsyncStream, CoreErr>`)
   * `DatagramTransitHandler` (`caps()`, `open(target: &str, auth: SessionAuth) -> Result<DatagramLink, CoreErr>`) — designed for 1:N shared neighbor `DatagramLink`s multiplexed by Core's `DatagramPort`.
   * Core provides built-in `StaticTransit<C>` (binds channel + fixed locator, ignoring `target`) and `DynamicTransit<C>` (forwards `target.as_bytes()` as locator).

### 9.2 Structured Error Taxonomy, `FailureClass` & Retryability

Core **MUST** preserve these distinct error conditions, their `FailureClass` classification (for failover routers), and their retryability semantics:

| Error Condition | `FailureClass` | `is_retryable()` |
| --- | --- | --- |
| `Timeout` | `PathFailure` | `true` |
| `Busy` | `DestinationApp` | `true` |
| `WouldBlock` | `LocalInvalid` | `true` |
| `CarrierFailure { message, transient }` | `PathFailure` | `transient` |
| `Carrier(message)` | `PathFailure` | `false` (except when nested inside `Credential`: see below) |
| `TargetUnreachable` | `PathFailure` | `false` (except when nested inside `Credential`: see below) |
| `UnexpectedEof`, `MtuTooSmall(u16)`, `Authentication`, `CookieRequired`, `BadMac`, `Malformed`, `ClockSkew`, `Replay`, `HopRejected { index, reason }` | `PathFailure` | `false` |
| `Denied`, `Revoked`, `Expired`, `Unpublished` | `DestinationPolicy` | `false` |
| `TargetRefused`, `WrongPlane` | `DestinationApp` | `false` |
| `Credential(inner)` | `LocalAuth` | `true` iff `inner` is `TargetUnreachable`, `Carrier(_)`, or `inner.is_retryable()` |
| `InvalidParameter`, `AlreadyPublished`, `MessageTooLarge(usize)`, `Closed`, `NoPath` | `LocalInvalid` | `false` |

`is_path_failure()` is `true` iff `failure_class() == FailureClass::PathFailure`. Notice that `HopRejected { index, reason }` is ALWAYS `PathFailure` even if `reason` is `Denied` — an intermediate hop refusing transit means trying another path may succeed!

### 9.3 Observability & Safe Diagnostics

* Core **SHOULD** expose local atomic counter snapshots (`ScopeStats` and `NodeStats`) covering:
  * Pending setup gauge, `under_load`, `accepting` flags
  * Active sessions and setup attempts/established/failures (by `Plane × Role { Origin, Destination, Transit }` and by `FailureClass`)
  * Authorization decisions (`allowed`, `rejected`, `timed_out`, `busy`, `duration_ms`, `renewed`, `renewal_retries`, `renewal_failures`) split by Endpoint vs. Transit
  * Traffic counters (`bytes_received`, `bytes_sent`, `datagrams_received`, `datagrams_sent`) per plane
  * Security & resource counters: `capacity_drops_total`, `mac1_drops_total`, `mac2_challenges_total`, `replay_rejects_total`, `revocations_total` (by peer/endpoint/transit/scope/lag), `sessions_closed_total`, `session_duration_ms`, `queue_drops_total`, `datagram_mailbox_drops_total`, `traffic_gate_drops_total`, `mtu_updates_total`.
* **Safe Logging Invariant:** Tracing events **MUST NEVER** log raw credentials, secret keys, or arbitrary `Display` error strings returned by untrusted extension seams (emit fixed static error code identifiers instead).

### 9.4 Cleanroom Architecture & Code-Quality Guidance

Because the goal of this cleanroom rewrite is improved code quality while preserving 100% wire and behavioral compatibility, implementers are encouraged to:
* **Decompose Large Engines Cleanly:** Separate pure synchronous protocol state machines (wire codecs, Noise handshake, fragment reassembly, MTU reporter, renewal scheduler, `SlabTable`, `ReplayWindow`, `CookieProtector`) from async I/O orchestration so protocol logic is unit-testable with zero async boilerplate.
* **Eliminate Duplicated Admission & Publication Logic:** Unify shared Stream/Datagram transit admission pipelines and transit exact/prefix table management instead of duplicating parallel code paths.
* **Make Lock Hierarchy Explicit & Minimal:** Avoid wide lock scopes and hidden multi-mutex lock orders across `Node`, `Scope`, and `DatagramPort`; prefer clean ownership boundaries and weak-reference cycle avoidance.
* **Simplify Type Erasure & Seam Ergonomics:** Keep zero-cost compile-time channel composition without sprawling boilerplate across public traits wherever Rust 2024 features allow cleaner abstractions.

---

## 10. Conformance & Verification Checklist

A cleanroom implementation is complete ONLY when automated tests verify every item below:

### 10.1 Cryptography & Zero-Allocation Primitives
- [ ] `ScopeKid`, `mac1`, `mac2`, and `cookie_enc_key` match the exact BLAKE3 `derive_key` / `keyed_hash` domain strings.
- [ ] Invalid `mac1` and unknown `ScopeKid` fail with `BadMac` and **0 heap allocations** (verified with a custom counting global allocator).
- [ ] `Noise_IK` Message 1 + Message 2 establish matching asymmetric `tx`/`rx` keys (`origin.tx == dest.rx`, `origin.rx == dest.tx`, `tx != rx`), reject all-zero DH outputs, and reject any 1-bit flip in `dispatch_prefix` or `tail` (`tail_aad`).
- [ ] `SetupReplay` uses monotonic time (immune to wall-clock step), commits ONLY on `commit()` (pre-auth failures do not consume cache slots), resolves concurrent `commit()` races to exactly one winner, and fails closed on saturated buckets.
- [ ] `ReplayWindow` accepts `seq = 0`, handles out-of-order packets within 64 packets, rejects duplicates and packets `< max - 63`, and NEVER advances state on corrupted AEAD tags.
- [ ] `DatagramTx::seal` + hop `DG_DATA` prepend/CID-rewrite/strip + stacked outer AEAD wrap/unwrap + `DatagramRx::open` execute with **0 heap allocations** and preserve the in-place payload pointer across sizes `0, 1, 17, 128, 1202, 16000, 65505`.
- [ ] `HopKey::setup_hop_ack` and `HopKey::setup_error` authenticate and reject 1-bit tampering.

### 10.2 Flood Cookies & Datagram Setup Fragmentation
- [ ] `CookieProtector`: 0-RTT when `!under_load`; issues `56 B` XChaCha20-Poly1305 challenge bound to `sent_mac1` AAD when `under_load`; rejects mismatched `source_tag` or wrong `sent_mac1`; accepts previous secret for one rotation period and rejects after two rotations.
- [ ] Automatic `under_load` hysteresis activates strictly above 75% pending usage and clears only after remaining `<= 25%` for 5 monotonic seconds.
- [ ] Multi-hop `SETUP_COOKIE` increments `distance` upstream, retains datagram outbound `DatagramPort` for 3 s (`hold_for_cookie_retry`), and fails with `CookieRequired` if the same hop challenges twice.
- [ ] Oversized datagram `SETUP_FWD` fragments into `2..=8` `SETUP_FRAG` packets, retransmits at `[150, 300, 600]` ms until `SETUP_FRAG_ACK`, validates fragment 0 (`ScopeKid`, `mac1`, `mac2`, bounds) BEFORE allocating reassembly memory, enforces `16` active / `MAX_SETUP` byte / `32` completed caps, sends `SETUP_FRAG_ACK` ONLY after `Responder::authenticate`, and re-ACKs duplicate fragment 0 without re-running setup.

### 10.3 Setup, 1.0 RTT Deferred Open, Multi-Hop & Planes
- [ ] Direct (`A -> B`) and multi-hop (`A -> H_0 -> ... -> H_k -> B`) flows work end-to-end on both Stream and Datagram planes.
- [ ] `SETUP_OK` carries reverse-ordered 26B hop trailers; Origin derives path MTU solely from authenticated trailers and Noise reply (ignoring spoofed cleartext `reverse_mtu`).
- [ ] Cross-plane dials (Stream to Datagram endpoint/transit or vice versa) fail honestly with `WrongPlane`; unpublished names fail with `Unpublished`.
- [ ] Staged dials (`dial_*_staged`) complete 1-RTT handshake without invoking `EndpointHandler::open`; dropping staged handle tears down cleanly with zero handler invocations; `confirm()` invokes handler and reports `PathOutcome::Established`.
- [ ] Stream destination handler errors map accurately to `TARGET_REFUSED`, `TARGET_BUSY`, `TARGET_DENIED`, `TARGET_UNREACHABLE`; clean `ST_FIN` yields `Ok(0)` while abrupt carrier drop yields `UnexpectedEof`.
- [ ] Stream `write_frame` resumes partial writes across retryable errors with backoff up to 3 s and flushes once.
- [ ] Datagram `SlabTable` isolates CIDs per link, never aliases across 255+ wrap cycles, and reclaims quarantined slots after 60 monotonic seconds without unbounded memory growth.
- [ ] Oversized `E2eDatagram::send` returns `MessageTooLarge(max_payload)` without sending on wire or closing the session.

### 10.4 Live Path MTU, In-Band Renewal, Auth & Multi-Scope `Node`
- [ ] Live `MtuWatch` drops at Origin, Transit, or Destination propagate via authenticated `DG_MTU` / `DG_MTU_ACK`, trigger `PathOutcome::MtuChanged`, ignore stale epochs, and close on floor violations (with 5 s drain window at Transits so `e2e::DG_CLOSE` reaches `B`).
- [ ] In-band renewal refreshes Endpoint and every Hop independently at 70–80% TTL, retries retryable credential/network failures reusing the same `(renewal_id, credential)`, ignores late ACKs for old IDs, handles duplicate verifier deliveries idempotently without re-authorizing or extending the lease, and terminates on non-retryable denial or expiry.
- [ ] `IntersectAuthorizer` enforces local hard veto first, intersects TTL, composes `TrafficGate`s (strictly on `DATA`, immune to control frames), preserves all `SessionGuard`s across renewals until drop, and merges `AuthExtensions` with local precedence while streaming live updates to `SessionAuth`.
- [ ] TOCTOU revocation epochs block racing setups; `TransitRevoker` revokes only its `PublicationId` + plane + target without affecting overlapping or replacement publications; broadcast revocation lag invalidates all leases fail-closed.
- [ ] `Node` rejects mismatched clocks, demultiplexes multiple scopes in $O(1)$ by `ScopeKid`, deduplicates concurrent `DatagramLink` attachments into one `DatagramPort`/`SlabTable`, and safely adopts/unmounts scope ports.
- [ ] `begin_shutdown()` stops new admissions, cleanly winds down active sessions (`ST_FIN` on Stream, `CLOSE` on Datagram), and `is_drained()` becomes `true` once all work completes.
