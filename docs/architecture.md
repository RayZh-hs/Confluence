# Implementation Architecture

Confluence's implementation strictly mirrors the cleanroom boundaries defined in [DESIGN.md](../DESIGN.md) and the [Statement of Purpose](purpose.md). Every crate enforces `#![forbid(unsafe_code)]`, and dependency edges guarantee at compile time that `confluence-core` never depends on concrete sockets, passive relay logic, policy files, route tables, or local port-forwarding adapters.

---

## 1. Layered Crate Architecture

```text
                       +-----------------------------------+
                       |          confluence-cli           |
                       |   Declarative TOML Node Runner    |
                       +-----------------+-----------------+
                                         |
         +---------------+---------------+---------------+---------------+
         |               |               |               |               |
         v               v               v               v               v
+----------------+ +-----------+ +---------------+ +-----------+ +---------------+
|confluence-edge | |confluence-| |  confluence-  | |confluence-| |  confluence-  |
|TCP/UDP Forward | |  policy   | |   carriers    | |   relay   | |    routing    |
|   (Seam 4)     | | (Seam 3)  | |UDP/TCP + ACL  | |0-Dial Slot| |Explicit Routes|
+--------+-------+ +-----+-----+ +-------+-------+ +-----+-----+ +-------+-------+
         |               |               |               |               |
         +---------------+---------------+-------+-------+---------------+
                                                 |
                                                 v
                            +-----------------------------------------+
                            |             confluence-core             |
                            |  Two-Plane E2E Engine (Stream/Datagram) |
                            |  Blind 1-RTT Single-Pass Path Engine    |
                            |  Noise_IK · TAI64N · MAC2 · GrantEnforce|
                            |  4 Narrow Extension Seam Traits         |
                            +-----------------------------------------+
```

---

## 2. Core Engine Components (`confluence-core`)

### 2.1 `Node` & Isolated `TrustScope`s
A `Node` is a self-contained user-space runtime instance requiring zero root privileges or host-wide network namespace changes:
- Multiple `TrustScope`s can be mounted on the same `Node`, even sharing a single UDP/TCP listener port via 8-byte opaque `TargetTag = BLAKE2s256(static_pubkey)[..8]` demultiplexing.
- Each `TrustScope` owns an independent X25519 `StaticKeypair` (`PeerId`), its own `AccessControl` verifier, its own `CookieProtector`, its own `Tai64nReplayWindow`, and an isolated `EndpointRegistry`.
- Only endpoints explicitly published via `publish_stream_endpoint` or `publish_datagram_endpoint` are reachable; dropping or unpublishing an endpoint handle immediately revokes and tears down all active streams and datagram sessions bound to it.

### 2.2 Strict Two-Plane Engine
- **Datagram Plane (`ConfluenceDatagramSession`):** Preserves discrete, unordered message semantics end-to-end. One `Noise_IK` session per `(A, B, scope, endpoint)` carries a flat 4-byte `HopLabel` + 8-byte nonce + `ChaCha20Poly1305` AEAD payload (**29 bytes** constant wire overhead) and a 64-bit sliding anti-replay window that verifies AEAD tags *before* advancing window state (preventing unauthenticated window-poisoning DoS).
- **Stream Plane (`ConfluenceStream`):** Preserves ordered, reliable byte streams with end-to-end TCP-style backpressure over length-prefixed (`<= 16 KiB`) `ChaCha20Poly1305` records with implicit 64-bit monotonic nonces. Only an AEAD-authenticated `Close` record yields clean `EOF`; abrupt underlying link drops surface `ConnectionReset` honestly (preventing stream truncation attacks).

### 2.3 Blind Single-Pass Multi-Hop Path Engine
Core's Path Engine contains **zero hop cryptography, zero hop ACL policy, and zero passive relay logic**:
1. **Originator `A`** constructs a single forward burst `[Seg_1(tag_1) | ... | Seg_k(tag_k) | Final(tag_B)]`, where each segment is encrypted directly to that hop channel's or destination scope's static public key (`Noise_IK` + monotonic 12-byte TAI64N timestamp).
2. **Intermediate Hop `H_i`** pops only its leading `Seg_i(tag_i)` and dispatches `(source_addr, seg_payload)` blindly by `TargetTag` to the mounted `DatagramForwardChannel` or `StreamForwardChannel`.
   - **On the Stream Plane:** Once the channel plugin returns an authorized `BoxedAsyncStream`, Core immediately enters `tokio::io::copy_bidirectional` without writing any intermediate handshake bytes—so `Seg_{i+1} | ... | Final` streams straight through in **0 per-hop RTTs**!
   - **On the Datagram Plane:** Hop `H_i` records a bounded pending circuit entry and forwards the remaining packed tail via the channel plugin's `DatagramForwardHandle`. When `B`'s `ChainSetupResp` traverses back, `H_i` installs two flat `DashMap<u32, LabelSwitchEntry>` entries (`up_label -> downstream_label` and `down_label -> upstream_label`). Steady-state forwarding overwrites `pkt[0..4]` in place and sends through the Grant-enforced handle.

---

## 3. Vertical & Horizontal Channel Composition

Confluence separates **active outbound transit** from **passive rendezvous relaying** as distinct, composable Seam 1 plugins outside Core:

- **Native Carriers (`UdpDatagramChannel`, `TcpStreamChannel` in `confluence-carriers`):** Pure transport connectivity with `TCP_NODELAY` and explicit MTU enforcement.
- **Active Transit Middleware (`NoiseAclDatagramChannel<D>`, `NoiseAclStreamChannel<S>` in `confluence-carriers`):** Wraps *any* underlying carrier to authenticate the originator `A` directly (`Noise_IK`), enforce 0-RTT TAI64N anti-replay and optional `MAC2` flood cookies, evaluate `Action::ChannelForward` against `AccessControl`, and wrap the resulting forwarding handle/stream in `GrantEnforcer`.
- **Passive Relay Plugin (`RelayDatagramChannel`, `RelayStreamChannel` in `confluence-relay`):** Holds **zero** outbound `StreamChannel` reference (making outbound dialing from `R` impossible at compile time). Destination `B` dials/registers *inbound* to `R` (`RelayDatagramClient` / `RelayIngressStreamChannel`), parking authenticated slots/streams. Originator `A` (either directly `A -> R <- B` or behind transit hops `A -> H1 -> R <- B`) authenticates directly with `R` (`Action::ChannelCustom { kind: "relay_connect" }`) targeting `B`'s hex `PeerId` slot.

---

## 4. Security & Enforcement Model

- **Control-Events-Only Policy:** `AccessControl::evaluate` executes exclusively on session open, hop setup, relay registration, and explicit renewal—never per data packet.
- **Host Sovereignty (`IntersectAccessControl<L, E>`):** Intersects local host policy `L` with external policy `E`. Local denial is an immediate hard veto; external timeouts or errors fail closed; allowed grants take the strict minimum of `expires_at`, `max_bytes_per_sec`, `max_datagrams_per_sec`, and `max_concurrent_streams`.
- **Live Enforcement & Instant Revocation (`GrantEnforcer`):** Enforces atomic expiration, continuous nanosecond-refilled byte/datagram token buckets, atomic stream concurrency permits, seamless in-place `update_grant` during in-band renewal, and `watch`-driven sub-millisecond teardown of even completely idle streams/circuits upon `RevocationEvent`.

For wire frame layouts, see [Wire Protocol Specification](wire-protocol.md). For Rust traits and TOML configuration, see [API Reference](api.md) and [User Guide](user-guide.md).
