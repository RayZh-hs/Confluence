# Confluence — Core Design

**Scope:** Design philosophy, core abstractions, architectural boundaries, and system invariants for **Confluence Core**. Concrete wire formats, cryptographic suites, API signatures, transports, passive relay signaling, QoS traffic shapers, cross-plane channel adapters, stream multiplexers, peer discovery, routing/failover controllers, credential issuers, and enterprise policy engines are intentionally out of scope.

> For the normative v1 wire protocol, cryptographic specification, state machines, limits, and conformance criteria, see [docs/core-spec.md](docs/core-spec.md).

---

## 1. Purpose & Core Abstraction

Confluence is a fast, resilient, composable **A-to-B connectivity core**.

Existing connectivity tools tend to lock users into one rigid trade-off:

* **Centralized mesh networks** tightly couple machine, user, and network under one administrative hierarchy, forcing full-host exposure or network merging just to share a single service.
* **Single-server reverse proxies** scope exposure cleanly to a port, but force all traffic through a fixed central bottleneck.
* **Standalone firewall-traversal tunnels** solve hostile-network reachability, but lack composable peer routing, trust isolation, and clean application boundaries.

Confluence resolves this with a single foundational abstraction: **connecting an Originator `A` to an explicitly published named Endpoint on Destination `B`** over an explicit path of **named Transits** and **pure transport Channels**, while cleanly separating *how data moves*, *who is permitted*, *how credentials are obtained*, and *how local applications enter the fabric*.

### Non-Goals for the Core

* **No application-protocol awareness:** Core transports opaque byte streams and discrete datagrams; it never parses or terminates application or L3/L4 protocols.
* **No QoS, bandwidth shaping, or concurrency-cap algorithms in Core:** Core enforces time-bounded, revocable leases together with algorithm-agnostic data-plane traffic gates and session-scoped permits. Token buckets, rate/packet shapers, and concurrency counters stay completely outside Core, while composing cleanly under host-sovereign policy intersection and updating live on renewal.
* **No passive-relay presence protocol in Core:** Passive relay registration and presence signaling belong at the transport/channel layer outside Core.
* **No implicit cross-plane conversion or steady-state datagram fragmentation:** Core never silently wraps streams into datagrams, wraps datagrams into streams, or fragments/reassembles application datagrams; crossing planes or handling fragmentation is always an explicit out-of-core choice.
* **No in-core multiplexing:** One connection from `A` to `B` establishes one bidirectional byte stream or one bidirectional datagram flow; multiplexing multiple logical flows over a shared underlay lives in composable channels.
* **No auto-routing, discovery, or multi-path switching:** Core executes one explicitly specified path cleanly; peer discovery, candidate-path management, probing/racing, and live path failover stay outside Core.
* **No built-in user management, credential issuance, or network control server:** Core verifies access through pluggable authorizers rather than issuing credentials, and exposes zero default network control endpoints.
* **No assumed global topology or host-wide ownership:** There is no mandatory central coordinator, global network namespace, or host-wide privilege requirement.

---

## 2. Architectural Overview

```text
+-----------------------------------------------------------------------+
| Edge Adapters & Application Middleware (Out of Core — Seam 4)         |
|   Port forwarders · Local I/O bridges · Virtual L3 · App RBAC         |
|   Reads live verified session claims (updated automatically on renew) |
+-----------------------------------------------------------------------+
                     │                             │
      1:1 Stream     │   Authenticated Peer &      │  1:1 Datagram Flow
                     │   Live Verified Claims      │
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
|  |   Mutual Auth · DoS Flood Protection · Replay Protection        |  |
|  |   Replay-Safe Deferred Open · Revocable Leases & Live Renewal   |  |
|  |   Caller credentials ◄──── [Seam 3A: Credential Acquisition]    |  |
|  |   Verifier decisions ────► [Seam 3B: Authorization & Veto]      |  |
|  +-----------------------------------------------------------------+  |
|                                  │                                    |
|                                  ▼                                    |
|  +-----------------------------------------------------------------+  |
|  |                    Composable Path Engine                       |  |
|  |   Explicit single-path execution · End-to-end payload-limit     |  |
|  |   agreement · Named Endpoints & Transits (SSRF-safe)            |  |
|  |   Direct per-hop auth · Route integrity · Opaque forwarding     |  |
|  |   Receives chosen path ◄───────── [Seam 2: Path Selection]      |  |
|  +-----------------------------------------------------------------+  |
+=======================================================================+
                                   │
                                   ▼
+-----------------------------------------------------------------------+
| Pure Composable Channels (Out of Core — Seam 1)                       |
|   Pure transports (zero Core auth, credentials, or policy logic):     |
|   Native stream & datagram underlays · Link-encrypted wrappers        |
|   Passive relay carriers · Explicit cross-plane adapters              |
+-----------------------------------------------------------------------+
```

---

## 3. Core Design Principles

### 3.1 Decoupled Identity, Trust Scopes, and Control Surfaces

Machine, user, cryptographic identity, and network membership are independent dimensions:

* **Node:** A self-contained runtime (standalone or embedded), unprivileged by default, capable of hosting multiple isolated Trust Scopes behind shared network listeners by demultiplexing inbound traffic via unlinkable scope identifiers.
* **Trust Scope:** An isolated trust domain owning one independent identity keypair so observers and intermediaries cannot correlate a node's presence across unrelated scopes.
* **Host Sovereignty:** Every host retains sole authority over its own machine; external authorities or peers can never expose an unpublished endpoint or transit, nor weaken or bypass a host's local hard veto and local unpublish/revocation controls.
* **Explicit Exposure & Three-Way Control Split:** A node exposes zero built-in network control endpoints; only explicitly published named **Endpoints** and named **Transits** are reachable. Control separates cleanly into three planes:
  1. **Connection & Path Control (In-Core, In-Band):** Path setup, payload-limit agreement, lease renewal, and teardown travel in-band with the active connection.
  2. **Fabric Coordination (Out-of-Core, Opt-In Endpoints):** Optional peer discovery, route distribution, or revocation feeds run over ordinary published endpoints when configured.
  3. **Host Administration (Local Boundary Only):** Publishing endpoints or transits and enforcing local vetoes stay strictly inside the local host boundary.

---

### 3.2 Strict Two-Plane Separation

Network traffic falls into two fundamentally distinct semantic classes:

1. **Datagrams:** Unreliable, discrete, message-oriented payloads prioritizing message independence and low latency over ordered delivery.
2. **Streams:** Reliable, ordered, continuous byte flows with end-to-end backpressure.

Confluence enforces a strict, symmetric separation:

* **Two Separate End-to-End Planes:** Inside Core, stream traffic traverses only Stream channels and transits, and datagram traffic traverses only Datagram channels and transits, with zero hidden cross-plane conversion.
* **Explicit, Symmetric Cross-Plane Adapters:** Crossing a mismatched underlay requires an explicit *Stream-over-Datagram* or *Datagram-over-Stream* channel adapter outside Core that exposes the exact same pure channel contract, payload limits, and health signals as a native carrier.

---

### 3.3 Pure Channels & Named Transits

Confluence draws a sharp line between **moving bytes** and **deciding who may forward where**:

* **Pure Channels (Seam 1):** Transport channels move opaque byte streams or discrete datagrams and report live payload limits and link health. They never perform Core handshakes, flood challenges, credential handling, or access policy. This keeps native carriers simple and lets transport wrappers (link encryption, multiplexing, cross-plane adapters, passive relays) compose cleanly.
* **Named Endpoints & Named Transits:** Every inbound target on a node is addressed by a logical name:
  * **Endpoint:** A terminal service explicitly published on destination `B`.
  * **Transit:** A forwarding exit explicitly published on an intermediate hop `H` (matched either by exact name or by prefix).
* **Uniform Core Admission:** Because every hop is a Trust Scope publishing named transits, Core executes the exact same authentication, pre-auth DoS filtering, replay protection, authorization, and in-band renewal pipeline for both Endpoints and Transits—eliminating duplicated security logic.
* **SSRF Prevention & Local Stack Privacy by Construction:** An originator names only the logical transit target at each hop; it never supplies raw downstream network addresses, ports, or internal carrier types. Each hop privately owns how a named transit reaches the next hop and cannot be coerced into dialing arbitrary internal addresses. Registering an outbound first-hop carrier never enables inbound forwarding (default-deny forwarding).

#### Setup vs. Steady-State Forwarding

* **Setup (Direct Per-Hop Authorization & Route Integrity):** Originator `A` initiates a single pipelined multi-hop setup flight. Every hop authenticates `A` directly (never trusting the preceding hop), and every hop cryptographically binds the entire remaining downstream route so compromised upstream hops cannot splice, reorder, truncate, or alter downstream legs.
* **Forwarding (Opaque, Low-Overhead Data Plane):** Once established, intermediate hops forward opaque end-to-end ciphertext without per-hop payload decryption or re-encryption. Authenticated setup responses deliver every hop's payload limit and initial lease lifetime during the initial round trip with zero initial renewal burst.

---

### 3.4 Explicit Single-Path Execution & Honest Path Semantics

Core's routing responsibility is minimal: **execute one explicitly specified path cleanly**.

* **End-to-End Capability & Payload-Limit Agreement:** Every hop along the path must support the requested plane and satisfy the negotiated minimum payload-limit floor across initial setup and live mid-session path changes. Limits are authenticated end-to-end rather than trusted from mutable cleartext headers.
* **Replay-Safe Deferred Destination Open & Explicit Lifecycle:** Destination `B` holds an unconfirmed pending state upon receiving initial setup and invokes its local endpoint handler only after receiving an end-to-end authenticated confirmation from `A`. Exposing a staged pre-confirmation boundary lets out-of-core path racers compare candidate paths with zero destination side effects. End-to-end signaling cleanly distinguishes successful open, application refusal, capacity busy, policy denial, target unreachability, clean half-close, and abrupt transport drop.
* **Honest Failure Handling:** Broken links and payload-limit floor violations tear down affected sessions cleanly and report structured outcome classifications upward so out-of-core routers can distinguish path/hop failures from destination policy or application rejections.

---

### 3.5 Symmetric Auth, "Verifier, Not Issuer", and Zero-Double-Auth App RBAC

Every transport channel and intermediate hop is treated as untrusted infrastructure relied upon solely for liveness and bandwidth—never for confidentiality, integrity, or authorization.

#### Symmetric Credential & Authorization Split (Seam 3)

Authentication and authorization are cleanly decoupled from both routing and application dial calls:

1. **Originator Side (Credential Acquisition):** Whenever Core builds a setup flight or renews a lease in-band, it requests an opaque credential per verifier and logical target. Credentials may be empty (public-key-only), static secrets, or short-lived capability tokens acquired from an external identity broker. Each verifier's credential is encrypted solely for that verifier so no other hop can inspect it.
2. **Verifier Side (Fail-Closed Authorization):** After cryptographic peer proof, Core evaluates the pluggable authorizer strictly on **control events** (initial setup and in-band renewal, never per data packet), under bounded timeouts, bounded concurrency, and fail-closed semantics.
3. **Revocable Leases, Data-Plane Gates, Permits & Live Claims:**
   * An authorization decision yields a time-bounded **Lease** carrying: a lifetime, an optional algorithm-agnostic data-plane traffic gate, optional session-scoped resource permits, and typed verified application claims.
   * **Uniform, algorithm-agnostic enforcement:** Core enforces lease expiration, idempotent in-band renewal before expiry, and instant out-of-band revocation (by peer, endpoint, transit, publication, or full scope). Data-plane traffic gates run strictly on user data after per-circuit demultiplexing so control frames (setup, renewal, payload-limit updates, close) remain immune and circuits sharing a link remain isolated. Session-scoped permits stay alive across renewals until session close.
   * **Host-sovereign composition:** Local and external policies compose by intersection—local policy evaluates first as a hard veto, lifetimes take the shorter bound, traffic gates intersect fail-closed, both sets of permits are retained, and typed claims merge with local-host precedence.
   * **Live updates & zero-double-auth application RBAC:** On in-band renewal, Core atomically updates the lease lifetime, active traffic gate, and verified claims visible to endpoint and transit handlers. Applications read verified identity and live claims directly from Core's session context—automatically observing role or scope changes without re-authenticating inside the application protocol.

---

## 4. Core Boundary & Extension Seams

Everything outside the foundational engine attaches through four narrow, implementation-independent seams:

| Seam | Responsibility | Out-of-Core Examples |
| --- | --- | --- |
| **1. Channels** | Pure stream or datagram transport, live payload-limit reporting, and symmetric inbound listeners. | Native TCP/UDP underlays, link-encrypted wrappers, passive relay carriers, explicit stream↔datagram adapters, link multiplexers. |
| **2. Path Selection** | Pure routing: supplies one explicit single path for a destination, endpoint, and plane, and receives structured lifecycle and failure feedback (zero credentials). | Static routes, blind rendezvous discovery, staged path probing/racing, failover controllers. |
| **3. Symmetric Auth** | Originator acquires and refreshes opaque per-verifier credentials; verifier evaluates authenticated control-plane requests into revocable leases (lifetime, traffic gate, session permits, typed claims) and emits live revocations. | Public-key allowlists, capability-token brokers, OIDC/SSO verifiers, host-sovereign policy combinators, rate/PPS shapers, concurrency limiters. |
| **4. Endpoints, Transits & Edge Adapters** | Projects confirmed 1:1 streams or datagram flows (carrying verified peer identity and live claims) onto local services, named forwarding exits, or embedded applications. | Static/dynamic forwarding transits, local port forwarders, virtual L3 adapters, embedded RPC/application servers. |

---

## 5. Core Invariants Checklist

1. **Core knows no application, L3/L4, QoS, or passive-relay protocols** — only opaque byte streams, opaque discrete datagrams, and revocable time-bounded leases.
2. **Datagram and Stream planes never mix or fragment application data in Core** — crossing planes requires an explicit out-of-core channel adapter, and application datagrams are never fragmented inside Core.
3. **Channels are pure, composable, and locally private** — channels move bytes without Core auth or policy logic; downstream transport stacks stay private behind named transits so originators need only their own first-hop carrier.
4. **One explicit path and 1:1 session per connection** — discovery, probing, racing, failover, and logical stream multiplexing stay outside Core.
5. **Passive Relay and Active Transit never blur** — passive relay presence lives outside Core, performs structurally zero outbound dialing, and exposes presences strictly as named transits.
6. **Direct per-hop authorization and opaque steady-state forwarding** — Core authenticates the originator directly at every named transit hop with cryptographic route integrity during setup, and forwards opaque end-to-end ciphertext without per-hop payload decryption afterward.
7. **Replay-safe deferred admission and explicit end-to-end lifecycle** — destination handlers open only after end-to-end confirmation, cleanly distinguishing open success, refusal, busy, denial, unreachability, clean half-close, and abrupt transport failure.
8. **Symmetric fail-closed auth & "verifier, never issuer"** — credential acquisition is decoupled from routing and dials; authorization runs strictly on control events, fails closed, never overrides local host veto, enforces out-of-core traffic gates strictly on data traffic (immune to control frames), preserves session permits across renewals, and surfaces live verified claims to applications.
9. **Path and payload-limit failures surface honestly** — broken links and payload-limit floor violations tear down cleanly and report structured root-cause feedback upward.
10. **Zero default endpoints and rootless isolation** — nodes run unprivileged by default, keep identities unlinkable across Trust Scopes, keep connection control in-band and host administration strictly local, and expose only explicitly published Endpoints and Transits.
