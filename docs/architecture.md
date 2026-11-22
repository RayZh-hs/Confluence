# Confluence Architecture

Confluence is a cleanroom **A-to-B connectivity core** that connects explicitly published named **Endpoints** on Destination `B` to Originator `A` across isolated **Trust Scopes**, pure **Channels**, named **Transits**, and **1-RTT single-pass multi-hop paths**.

For foundational invariants, see [DESIGN.md](../DESIGN.md).

---

## Crate Topology

Compile-time dependency edges enforce the cleanroom boundary: **`confluence-core` has `#![forbid(unsafe_code)]` and zero OS socket, filesystem, or runtime-executor dependencies.**

```text
confluence-cli (Declarative TOML config, keygen, node runner)
 ├── confluence-edge     (TCP/UDP port forwarders, E2eStreamIo AsyncRead/AsyncWrite, 0600 Unix admin)
 ├── confluence-relay    (Out-of-core PassiveRelay + single-port RelayService / RelayMux + PassiveStreamPool)
 ├── confluence-net      (Pure native TCP carrier + Linux DF=1 UDP carrier + UdpIngress::serve_custom)
 ├── confluence-plugins  (RateGate / ConcurrencyLimiter / QosAuthorizer, StaticPolicy, StaticCredentials, StaticPathSource, Mem channels)
 └── confluence-core     (Two-plane E2E engine, named Endpoints & Transits, Node, cookies, Leases, 4 seams)

confluence-testkit (Deterministic fault-injection hubs, wire-tap capture, AuditAuthorizer, enterprise RBAC tests)
 └── confluence-core, confluence-plugins, confluence-edge, confluence-relay

confluence-ext (Out-of-core plugin suite: Group tokens, link-encrypted TCP/UDP, UDP P2P, Striped-TCP, L3 mesh)
 └── confluence-core, confluence-net, confluence-plugins, confluence-relay, confluence-edge
```

---

## Key Engine Properties

1. **Strict Two-Plane Separation:** `StreamChannel` / `E2eStream` and `DatagramChannel` / `E2eDatagram` are distinct types with zero implicit conversion or datagram fragmentation inside Core.
2. **Pure Channels + Named Transits:** Channels are pure 2-method transports (`caps`, `dial_stream` / `open_link`). Intermediate hops publish explicit named transits (`publish_stream_route`, `publish_datagram_route`, or prefix handlers like `"relay/"`), while Core uniformly executes `Noise_IK`, `MAC2` cookies, replay checks, and `AuthGate`—preventing SSRF by construction and hiding private downstream stacks from callers.
3. **Route-Integrity-Bound Single-Pass Setup:** Originator `A` emits one pipelined 1-RTT `SETUP_FWD` flight. Every hop and destination binds `BLAKE3(Dispatch_Prefix || Remaining_Tail)` as AEAD AAD so compromised upstream hops cannot splice or alter downstream legs. `SETUP_OK` carries 24-byte encrypted per-hop lease trailers so every hop's lease TTL is known on the initial RTT with zero `t = 0` renewal burst.
4. **Per-Link Generational Circuit IDs (`Cid`):** Every inbound `DatagramLink` owns an isolated `SlabTable` indexed by `[8-bit gen | 24-bit idx]` with a 60-second wrap quarantine, preventing cross-link CID spoofing and delayed-packet aliasing.
5. **Multi-Scope Single-Listener Hosting (`Node`):** Multiple isolated `ScopeInstance`s (each with an unlinkable X25519 keypair and `ScopeKid`) share a single TCP/UDP listener via `Node` with $O(1)$ `ScopeKid` demultiplexing for both Endpoints and Transits while preserving per-link `SlabTable` isolation.
6. **1.0 RTT Replay-Safe Destination Open:** Destination `B` holds `AwaitingConfirm` on `SETUP_FWD` and invokes its `EndpointHandler::open(SessionAuth)` only after decrypting `A`'s first `ee`-authenticated E2E frame, cleanly separating `OPEN_OK`, `TARGET_REFUSED`, `TARGET_UNREACHABLE`, `TARGET_BUSY`, `TARGET_DENIED`, `E2E_FIN`, and `UnexpectedEof`.
7. **Symmetric Auth, Revocable Leases, `TrafficGate` QoS & Live App RBAC:** `CredentialProvider` decouples token acquisition and live in-band refresh from routing and dial calls. Verifiers run `Authorizer` (optionally intersected with local host veto via `IntersectAuthorizer`) strictly on control events, returning `Lease { ttl, gate, guards, extensions }`. Core enforces TTL expiry, instant revocation (`LeaseHandle` + sharded `RevocationIndex`), session-scoped RAII `guards`, and per-circuit `TrafficGate` checks strictly on `DATA` frames (never control frames, preserving shared 1:N `DatagramLink` isolation), while streaming live `AuthExtensions` into `SessionAuth` across renewals.
8. **Out-of-Core Zero-Dialing Single-Port Passive Relay:** `confluence-relay` implements NAT presence registration cleanly at the transport layer (`0x52` / `0x53` / `0x57` via `RelayService` / `RelayMux` and `UdpIngress::serve_custom`), keeping `confluence-core` completely free of passive-relay framing while performing structurally zero outbound dialing.
