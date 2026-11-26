# Confluence — Core Design

**Scope:** Core ideas, architectural insights, and system boundaries for the **Confluence Core**. Concrete wire protocols, cryptographic constructions, transports, passive relay signaling, QoS traffic shapers, cross-plane channel adapters, stream multiplexers, peer discovery, routing/failover controllers, credential issuers, and enterprise policy engines are intentionally out of scope—the Core is designed to remain small, auditable, and easy to explain while supporting business-grade access control and arbitrary network stacks outside Core.

> **Relationship to `docs/core-spec.md`:** This document captures architectural intent, boundaries, and the 10 Core invariants; type and method names used below are illustrative concepts. [docs/core-spec.md](docs/core-spec.md) is the authoritative normative specification for the v1 wire protocol, cryptography, state machines, limits, and behavioral semantics.

---

## 1. Purpose & Core Abstraction

Confluence is a fast, resilient, composable **A-to-B connectivity core**.

Existing connectivity tools tend to lock users into one rigid trade-off:

* **Centralized mesh networks** tightly couple machine, user, and network under one administrative hierarchy, forcing full-host exposure or network merging just to share a single service.
* **Single-server reverse proxies** scope exposure cleanly to a port, but force all traffic through a fixed central bottleneck.
* **Standalone firewall-traversal tunnels** solve hostile-network reachability, but lack composable peer routing, trust isolation, and clean application boundaries.

Confluence resolves this with a single foundational abstraction: **connecting an Originator `A` to an explicitly published named Endpoint on `B`** over an explicit path of **named Transits** and **pure transport Channels**, while cleanly separating *how data moves*, *who is permitted*, *how credentials are obtained*, and *how local applications enter the fabric*.

### Non-Goals for the Core

* **No application-protocol awareness:** The Core transports opaque byte streams and discrete datagrams; it never parses or terminates application or L3/L4 protocols.
* **No QoS, bandwidth shaping, or concurrency-cap logic in Core:** Core enforces cryptographically authenticated **Lease** lifetimes, instant revocation, and an algorithm-agnostic `TrafficGate` hook + RAII `SessionGuard` permits on `DATA` frames only. Token buckets, rate/PPS shapers, and concurrency counters stay completely outside Core, while composing cleanly under `IntersectAuthorizer` and updating live on renewal.
* **No passive-relay registration protocol in Core:** Passive relay presence signaling belongs at the transport/channel layer outside Core.
* **No implicit cross-plane conversion or datagram fragmentation:** The Core never silently wraps streams into datagrams, wraps datagrams into streams, or fragments/reassembles datagrams; crossing planes or handling fragmentation is always an explicit out-of-core choice.
* **No in-core multiplexing:** One connection from A to B establishes one bidirectional stream or one bidirectional datagram flow; multiplexing multiple logical flows over a single carrier or passive relay lives in composable channels.
* **No auto-routing, discovery, or multi-path switching:** The Core executes one explicitly specified path cleanly; peer discovery, candidate-path management, probing/racing, and live path failover stay outside the Core.
* **No built-in user management, credential issuance, or network control server:** The Core verifies access via pluggable authorizers rather than issuing credentials, and exposes zero default network control endpoints.
* **No assumed global topology or host-wide ownership:** There is no mandatory central coordinator, global network namespace, or host-wide privilege requirement.

---

## 2. Architectural Overview

```text
+-----------------------------------------------------------------------+
| Edge Adapters & App Middleware (Out of Core — [Seam 4])               |
|   TCP/UDP port forwarders · E2eStreamIo · Virtual L3 · App RBAC       |
|   Live SessionAuth claims (updated automatically on renewal)          |
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
|  | streams (explicit lifecycle)|   |  messages (no fragmentation)  |  |
|  +--------------+--------------+   +---------------+---------------+  |
|                 │                                  │                  |
|                 ▼                                  ▼                  |
|  +-----------------------------------------------------------------+  |
|  |          Unified Trust & Enforcement Boundary (Core)            |  |
|  |   Mutual Noise_IK · MAC2 Flood Cookies · Replay Protection      |  |
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
| Pure Composable Channels (Out of Core — [Seam 1])                     |
|   2-method pure transports (zero crypto, auth, or policy logic):      |
|   Native TCP / Linux DF=1 UDP · Link-encrypted wrappers               |
|   Out-of-core single-port Passive Relays · Cross-plane adapters       |
+-----------------------------------------------------------------------+
```

---

## 3. Core Concepts

### 3.1 Decoupled Identity, Scope, and Control Surfaces

Machine, user, identity, and network membership are independent dimensions:

* **Instance (`Node`):** A self-contained Confluence runtime (standalone or embedded), unprivileged by default, able to host multiple isolated `ScopeInstance`s on a single shared TCP/UDP listener via unlinkable `ScopeKid` demultiplexing.
* **Trust Scope (`ScopeInstance`):** An isolated trust domain owning one independent X25519 identity keypair so observers and intermediaries cannot correlate its presence across unrelated scopes.
* **Host Sovereignty:** Every instance retains sole authority over its own machine; external authorities or peers can never expose an unpublished endpoint/transit or bypass a node's local hard veto (`IntersectAuthorizer`, `revoke_peer`, `PublishGuard` drop).
* **Explicit Exposure & Three-Way Control Split:** A node exposes zero built-in network control endpoints; only explicitly published named **Endpoints** and named **Transits** are reachable. Control separates cleanly into:
  1. **Connection & Path Control (In-Core, In-Band):** Path setup, MTU agreement, lease renewal, and teardown travel in-band with the active connection.
  2. **Fabric Coordination (Out-of-Core, Opt-In Endpoints):** Optional discovery, route distribution, or revocation feeds run over ordinary named endpoints when configured.
  3. **Host Administration (Local Boundary Only):** Publishing endpoints/transits and enforcing local vetoes stay within the local host boundary (in-process API or owner-only `0600` Unix IPC).

---

### 3.2 Datagram & Stream Separation (Two-Plane Model)

Network traffic falls into two fundamentally distinct semantic classes:

1. **Datagrams:** Unreliable, discrete, message-oriented payloads prioritizing independence between messages and low latency over ordered delivery.
2. **Streams:** Reliable, ordered, continuous byte flows with end-to-end backpressure.

Confluence enforces a strict, symmetric separation:

* **Two Strictly Separate End-to-End Planes:** Inside Core, stream traffic only traverses Stream channels/transits and datagram traffic only traverses Datagram channels/transits, with zero hidden cross-plane conversion.
* **Explicit, Symmetric Cross-Plane Channel Adapters:** Traversing a mismatched underlay requires an explicit *Stream-over-Datagram* or *Datagram-over-Stream* adapter exposing the exact same pure channel contract, payload limits, and health signals as a native carrier.

---

### 3.3 Pure Channels & Named Transits

Confluence draws a sharp line between **moving bytes** and **deciding who can forward where**:

* **Pure Channels (Seam 1):** `StreamChannel` (`caps`, `dial_stream`) and `DatagramChannel` (`caps`, `open_link`) are pure 2-method transports. They never handle `Noise_IK`, `MAC2` cookies, credentials, or policy. Native carriers stay simple, and vertical wrappers (link encryption, multiplexing, cross-plane adapters) compose statically at compile time.
* **Named Endpoints & Named Transits:** Every inbound target on a node is a human-readable logical name:
  * **Endpoint** (`TargetRef::Endpoint { name, plane }`): a terminal service published on destination `B` (e.g., `"analytics-db"`).
  * **Transit** (`TargetRef::Transit { name, plane }`): a forwarding route published on hop `H` (exact name like `"to-prod"`, or prefix like `"relay/"` matching `"relay/bob"`).
* **Core Owns Hop Admission Uniformly:** Because every hop is a `ScopeInstance` publishing named transits, Core itself executes the exact same `Noise_IK` handshake, `MAC2` flood-cookie verification, replay check, `AuthGate` authorization, and in-band renewal pipeline for both Endpoints and Transits—eliminating duplicated auth wrappers.
* **SSRF Prevention & Local Stack Privacy by Construction:** An originator only names the logical transit target (e.g., `HopSpec { peer: bastion, target: "to-prod" }`). It never specifies raw downstream IPs, ports, or internal channel types. Hop `H` privately owns how `"to-prod"` is reached (plain TCP, link-encrypted UDP, passive presence pool, etc.), and cannot be tricked into dialing arbitrary internal addresses.

#### Setup vs. Steady-State Forwarding

* **Setup (Direct Hop Authorization & Route Integrity):** Originator `A` emits one pipelined 1-RTT `SETUP_FWD` flight. Each hop authorizes `A` directly (never trusting the preceding hop) and binds `BLAKE3(Dispatch_Prefix || Remaining_Tail)` as AEAD AAD so upstream hops cannot splice or alter downstream legs.
* **Forwarding (Opaque, Low-Overhead Data Plane):** Once established, intermediate hops forward opaque end-to-end ciphertext without per-hop payload decryption or re-encryption. Per-hop encrypted trailers returned on `SETUP_OK` authenticate each hop's local MTU and establish every hop's lease TTL in the initial 1-RTT flight with zero `t = 0` renewal burst.

---

### 3.4 Explicit Single-Path Execution & Honest Path Semantics

The Core's routing mission is minimal: **execute one explicitly specified path cleanly**.

* **End-to-End Capability & Payload-Limit Agreement:** Every hop must support the requested plane and satisfy the caller's minimum MTU floor across forward clamping, authenticated setup trailers, and live mid-session MTU updates (combining carrier `MtuWatch` signals, `MtuTooSmall`/`EMSGSIZE` clamping, and authenticated `DG_MTU`/`DG_MTU_ACK` propagation; link-local DPLPMTUD probing lives outside Core).
* **1.0 RTT Replay-Safe Destination Open & Explicit Lifecycle:** Destination `B` holds an `AwaitingConfirm` state on `SETUP_FWD` and opens its `EndpointHandler` only after decrypting `A`'s first `ee`-authenticated E2E frame. End-to-end signaling cleanly distinguishes `OPEN_OK`, `TARGET_REFUSED`, `TARGET_UNREACHABLE`, `TARGET_BUSY`, `TARGET_DENIED`, clean `E2E_FIN`, and abrupt `UnexpectedEof`.
* **Honest Failure Handling:** Broken links and payload-limit violations tear down affected sessions immediately and report structured `PathOutcome` events (with `CoreErr::failure_class()`) upward to `PathSource`.

---

### 3.5 Symmetric Auth, "Verifier, Not Issuer", and Fine-Grained Application RBAC

Every channel and intermediary is treated as untrusted transport relied upon solely for liveness and bandwidth—never for confidentiality, integrity, or authorization.

#### Symmetric Credential & Authorization Split (Seam 3)

Auth is cleanly decoupled from both routing (`PathSource`) and application dial calls:

1. **Originator Side (`CredentialProvider`):** Whenever Core builds a setup flight or refreshes a lease in-band, it asks `CredentialProvider::credential(CredentialRequest)` for an opaque credential (`0..=128` bytes) for each verifier `(verifier_pubkey, TargetRef, is_refresh)`. Credentials can be empty (public-key-only), static secrets, or short-lived signed capability tokens fetched from an external OIDC/SSO/Vault broker. Each verifier's credential is encrypted inside its own `Noise_IK` envelope so no other hop can read it.
2. **Verifier Side (`Authorizer`):** After cryptographic peer proof (`Noise_IK`), Core's fail-closed `AuthGate` invokes `Authorizer::authorize(AuthRequest)` on **control events only** (setup and in-band renewal, never per packet), with bounded timeouts, bounded concurrency, and local hard-veto intersection (`IntersectAuthorizer`).
3. **Revocable `Lease` + `TrafficGate` + Live `AuthExtensions` (`SessionAuth`):**
   * An `Authorizer` returns `Lease { ttl, gate, guards, extensions }`.
   * **Core stays algorithm-agnostic while enforcing uniformly:** lock-free `LeaseHandle` TTL expiry, seamless in-band renewal before expiry, O(1) instant teardown via `Revocation` events (`Peer`, `Endpoint`, `Transit`, `All`) or local `revoke_peer` / `PublishGuard` drop, per-circuit `TrafficGate` enforcement strictly on `DATA` frames (after CID demuxing, keeping `SETUP`/`RENEW`/`CLOSE`/`DG_MTU`/`DG_MTU_ACK`/`ST_FIN` immune), and session-scoped RAII `SessionGuard` permits held across renewals until session close.
   * **Host-sovereign composition & live updates:** `IntersectAuthorizer` composes both `TrafficGate`s, preserves both sets of RAII `guards`, and merges type-keyed `AuthExtensions` with local-host precedence. On in-band renewal (`is_renewal: true`), Core atomically swaps `ttl`, `gate`, and live `SessionAuth` claims while keeping initial session `guards` intact.
   * **Zero-double-auth fine-grained RBAC:** Core passes live `SessionAuth` into confirmed `EndpointHandler::open(auth)` and `TransitHandler::open(target, auth)`. Application handlers read rich verified claims (user ID, roles, tenant, scopes) directly from `SessionAuth::context::<MyClaims>()`—automatically observing role/claim updates on renewal without re-authenticating inside the app protocol.

---

## 4. Core Boundary & Extension Seams

Everything outside the foundational engine attaches through four narrow seams:

| Seam | Responsibility | Out-of-Core Examples |
| --- | --- | --- |
| **1. Channels** | Pure 2-method Stream or Datagram transport (`caps`, `dial_stream` / `open_link`), live MTU watch, and symmetric inbound listeners. | Native TCP/UDP, link-encrypted TCP/UDP, single-port Passive Relays, explicit `Stream↔Datagram` adapters. |
| **2. Path Source** | Pure routing: supplies one `ExplicitPath` per `(peer, endpoint, plane)` and receives `PathOutcome` feedback (zero credentials). | `StaticPathSource`, Blind Rendezvous discovery, active probing/racing (`dial_*_staged`), and failover controllers. |
| **3. Auth (`CredentialProvider` ↔ `Authorizer`)** | Caller acquires/refreshes opaque credentials; verifier evaluates `(peer, TargetRef, credential)` on control events into a revocable `Lease` (`ttl`, optional `TrafficGate`, RAII `SessionGuard`s, typed `AuthExtensions`), and emits `Revocation`s. | `StaticCredentials`, `StaticPolicy`, `IntersectAuthorizer`, `RateGate`, `ConcurrencyLimiter`, `QosAuthorizer`, OIDC/capability-token brokers, enterprise policy engines. |
| **4. Endpoints, Transits & Edge Adapters** | Projects confirmed 1:1 Stream/Datagram flows (with live `SessionAuth`) to local targets, named forwarding transits (1:1 streams or 1:N shared datagram links), or embedded apps. | `StaticTransit` / `DynamicTransit`, `TcpTarget` / `UdpTarget`, `serve_local_tcp` / `serve_local_udp`, `E2eStreamIo`, virtual L3 mesh, native RPC apps. |

---

## 5. Core Invariants Checklist

1. **Core knows no application, L3/L4, QoS, or passive-relay protocols** — only opaque byte streams, opaque discrete datagrams, and revocable time-bounded leases.
2. **Datagram and Stream planes never mix or fragment in Core** — crossing planes requires an explicit channel adapter, and datagrams are never fragmented inside Core.
3. **Channels are pure, composable, and locally private** — channels move bytes without policy/auth logic; vertical stacks stay private behind named transits so originators only need their own first-hop carrier.
4. **One explicit path and 1:1 session per connection** — discovery, probing, failover, and stream multiplexing stay outside Core.
5. **Passive Relay and Active Transit never blur** — Passive Relay lives out of Core, performs structurally zero outbound dialing, and exposes presences strictly as named transits.
6. **Direct hop authorization and opaque forwarding** — Core authenticates the originator directly at every named transit hop with route-integrity AAD and forwards opaque end-to-end ciphertext without per-hop payload decryption.
7. **Replay-safe admission and explicit end-to-end lifecycle** — destination handlers open only after 1.0 RTT confirmation, cleanly distinguishing `OPEN_OK`, refusal, busy, denied, unreachable, `E2E_FIN`, and `UnexpectedEof`.
8. **Symmetric auth & "verifier, never issuer"** — `CredentialProvider` is decoupled from routing and dials; `Authorizer` runs strictly on control events, fails closed, never overrides local host veto (`IntersectAuthorizer`), enforces out-of-core QoS via composable `Lease` `TrafficGate` / `SessionGuard` hooks strictly on `DATA` frames, and flows live `AuthExtensions` into `SessionAuth` for zero-double-auth app RBAC.
9. **Path and payload-limit failures surface honestly** — broken links and MTU violations tear down cleanly and report structured `PathOutcome` upward.
10. **Zero default endpoints and rootless isolation** — nodes run unprivileged by default, keep identities unlinkable across Trust Scopes, keep connection control in-band and host administration strictly local, and expose only explicitly published Endpoints and Transits.
