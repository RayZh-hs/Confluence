# Confluence — Core Design

**Scope:** Core ideas, architectural insights, and system boundaries for the **Confluence Core**. Concrete wire protocols, cryptographic constructions, forwarding mechanics, transports, cross-plane channel adapters, stream multiplexers, peer discovery, routing or failover controllers, trust/policy backends, credential issuers, and application frontends are intentionally out of scope—the Core is designed to be realizable by completely different implementations while preserving the same abstractions and invariants.

---

## 1. Purpose & Core Abstraction

Confluence is a fast, resilient, composable **A-to-B connectivity core**.

Existing connectivity tools tend to lock users into one rigid trade-off:

* **Centralized mesh networks** tightly couple machine, user, and network under one administrative hierarchy, forcing full-host exposure or network merging just to share a single service.
* **Single-server reverse proxies** scope exposure cleanly to a port, but force all traffic through a fixed central bottleneck.
* **Standalone firewall-traversal tunnels** solve hostile-network reachability, but lack composable peer routing, trust isolation, and clean application boundaries.

Confluence resolves this with a single foundational abstraction: **connecting an explicitly published endpoint on A to an explicitly published endpoint on B** over an explicit, composable path and pluggable channels, while separating *how data moves*, *who is permitted*, and *how local applications enter the fabric*.

### Non-Goals for the Core

* **No application-protocol awareness:** The Core transports opaque byte streams and discrete datagrams; it never parses or terminates application or L3/L4 protocols.
* **No implicit cross-plane conversion or datagram fragmentation:** The Core never silently wraps streams into datagrams, wraps datagrams into streams, or fragments/reassembles datagrams; crossing planes or handling fragmentation is always an explicit out-of-core choice.
* **No in-core multiplexing:** One connection from A to B establishes one bidirectional stream or one bidirectional datagram flow; multiplexing multiple logical flows over a single carrier or passive relay lives in composable channels.
* **No auto-routing, discovery, or multi-path switching:** The Core executes one explicitly specified path cleanly; peer discovery, candidate-path management, probing/racing, and live path failover stay outside the Core.
* **No built-in user management, credential issuance, or network control server:** The Core verifies access rather than issuing credentials, and exposes zero default network control endpoints.
* **No assumed global topology or host-wide ownership:** There is no mandatory central coordinator, global network namespace, or host-wide privilege requirement.

---

## 2. Architectural Overview

```text
+-----------------------------------------------------------------------+
| Edge Adapters (Out of Core — [Seam: Edge Adapters])                   |
+-----------------------------------------------------------------------+
                     │                             │
      1:1 Stream     │                             │  1:1 Datagram Flow
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
|  |            End-to-End Trust & Enforcement Boundary              |  |
|  |   Mutual A↔B peer authentication · Replay-safe service open     |  |
|  |   Control/data-plane Grant split · Live renewal & revocation    |  |
|  |   Delegates endpoint policy ─────► [Seam: Access Control]       |  |
|  +-----------------------------------------------------------------+  |
|                                  │                                    |
|                                  ▼                                    |
|  +-----------------------------------------------------------------+  |
|  |                    Composable Path Engine                       |  |
|  |   Explicit single-path execution · End-to-end limit agreement   |  |
|  |   Direct per-hop authorization · Route integrity                |  |
|  |   Opaque payload forwarding · In-band hop lifecycle control     |  |
|  |   Delegates hop transport/admission ──► Target Channels         |  |
|  |   Receives chosen path ◄───────── [Seam: Route / Path Source]   |  |
|  +-----------------------------------------------------------------+  |
+=======================================================================+
                                   │
                                   ▼
+-----------------------------------------------------------------------+
| Composable Channels (Out of Core — [Seam: Channels])                  |
|   Native carriers (Stream or Datagram; raw or link-protected)         |
|   Passive relay channels (registered presence, zero outbound dialing) |
|   Composable Auth/ACL, rate-limit & multiplexing channel wrappers     |
|   Explicit cross-plane adapters (Stream↔Datagram over a carrier)      |
+-----------------------------------------------------------------------+
```

---

## 3. Core Concepts

### 3.1 Decoupled Identity, Scope, and Control Surfaces

Machine, user, identity, and network membership are independent dimensions:

* **Instance (Node):** A self-contained Confluence runtime (standalone or embedded), unprivileged by default, allowing multiple independent instances to coexist on one machine.
* **Trust Scope:** An isolated sharing or administrative domain. One instance can participate in multiple scopes simultaneously using independent, unlinkable per-scope identities so observers and intermediaries cannot correlate its presence across unrelated scopes.
* **Host Sovereignty:** Every instance retains sole authority over its own machine; external authorities or peers can never expose an unpublished resource or bypass a node's local hard veto.
* **Explicit Exposure & Three-Way Control Split:** A node exposes zero built-in network control endpoints; only explicitly published named endpoints within a Trust Scope are reachable. Control responsibilities separate cleanly into three layers:
  1. **Connection & Path Control (In-Core, In-Band):** Path setup, capability/limit agreement, authorization renewal, and teardown travel with the active connection itself rather than through a separate network control endpoint.
  2. **Fabric Coordination (Out-of-Core, Opt-In Endpoints):** Optional discovery, route distribution, or revocation feeds "dogfood" ordinary named endpoints inside a Trust Scope when configured.
  3. **Host Administration (Local Boundary Only):** Publishing endpoints, attaching extensions, and enforcing local vetoes stay strictly within the local host boundary (e.g., in-process API or local IPC) unless explicitly bridged by the operator.

---

### 3.2 Datagram & Stream Separation (Two-Plane Model)

Network traffic falls into two fundamentally distinct semantic classes:

1. **Datagrams:** Unreliable, discrete, message-oriented payloads prioritizing independence between messages and low latency over ordered delivery.
2. **Streams:** Reliable, ordered, continuous byte flows with end-to-end backpressure.

Forcing one class blindly onto a carrier built for the other causes structural failures such as nested-retransmission collapse or head-of-line blocking. Confluence enforces a strict, symmetric separation:

* **Two Strictly Separate End-to-End Planes:** Inside the Core, stream traffic only traverses Stream channels and datagram traffic only traverses Datagram channels, with zero hidden cross-plane conversion.
* **Explicit, Symmetric Cross-Plane Channel Adapters:** Traversing a mismatched underlay requires an explicit *Stream-over-Datagram* or *Datagram-over-Stream* adapter exposing the exact same channel contract, payload limits, and health signals as a native carrier.

---

### 3.3 Composable Connections & Routes

Connectivity is built from **composable channels** and **end-to-end route composition**:

#### Composable Channels & Local Stack Privacy

Every channel—native carrier, passive relay, Auth/ACL or mux wrapper, or cross-plane adapter—presents one uniform contract:

* Moves discrete messages (Datagram) and/or byte flows (Stream) while reporting liveness, failures, and live effective payload limits upward to the Core.
* For forwardable outbound channels, supports direct originator-to-channel admission (`originator ↔ channel`), allowing the channel to verify who is asking to traverse it and enforce access bounds and revocation independently of the Core.

Channels compose **vertically** within a node and **horizontally** across hops. Native carriers stay pure: link-layer confidentiality or obfuscation over untrusted networks belongs to the node operator's chosen channel stack rather than being assumed or duplicated by the Core. Because hop admission decouples the originator from remote channel internals, Originator A only ever needs the channel implementation for its own local first hop—each remote hop can privately customize its internal vertical channel stack without clients installing remote plugins or mirroring server configurations.

#### Composable Route Topologies

Any route from A to B explicitly composes one or more hop segments suited to each network boundary:

1. **Direct:** A single logical channel between A and B (native carrier, zero-dialing passive relay channel, or adapted channel).
2. **Multi-Hop Chain:** An explicit sequence `A → H₁ → … → Hₙ → B`, mixing active outbound transit channels and passive relay channels (where B holds an active registered presence and the relay performs zero outbound dialing).

#### Setup vs. Steady-State Forwarding

* **Setup (Direct Hop Authorization & Route Integrity):** During path setup, each hop authorizes Originator A directly (rather than blindly trusting the preceding hop) and ensures upstream intermediaries cannot silently hijack, splice, or rewrite the originator's intended downstream route. Heavyweight authentication, policy verification, and compatibility checks occur on setup and explicit control events—not on every packet.
* **Forwarding (Opaque, Low-Overhead Data Plane):** Once established, intermediate hops forward opaque end-to-end ciphertext without per-hop payload decryption or re-encryption (leaving link privacy, where needed, to the operator's channel stack). Hop-level lifecycle control—such as refreshing authorization or tearing down a leg—can still travel alongside the connection without exposing end-to-end payloads.

---

### 3.4 Explicit Single-Path Execution & Honest Path Semantics

The Core's routing mission is minimal: **execute one explicitly specified path cleanly**.

* **End-to-End Capability & Payload-Limit Agreement:** A path is constrained by its narrowest hop. Every hop along a route must support the requested semantic plane (Stream or Datagram), and the effective payload ceiling must respect the tightest live limit across the full path. If a path cannot satisfy the caller's minimum payload requirement—either at setup or after a mid-session change—the Core rejects or terminates the connection explicitly rather than silently fragmenting datagrams or dropping oversized payloads into a black hole.
* **Replay-Safe Admission & Explicit End-to-End Lifecycle:** Destination B never triggers local application side effects (such as opening a local target service) before Originator A is mutually authenticated and protected against replay. In addition, end-to-end lifecycle signaling cleanly distinguishes *clean completion*, *destination refusal*, and *unexpected path or carrier failure*—a premature link drop must never masquerade as normal end-of-stream.
* **Honest Failure Handling:** When a link fails or payload limits drop below a session's minimum floor, the Core tears down affected sessions immediately and reports structured failure reasons upward to the Route / Path Source rather than hiding failures behind in-core path switching.

---

### 3.5 End-to-End Security & "Verifier, Not Issuer"

Every channel and intermediary is treated as untrusted transport infrastructure relied upon solely for liveness and bandwidth—never for confidentiality, integrity, or authorization.

#### Fixed Security Invariants

* **End-to-End Protection:** Mutual cryptographic identity proof and authenticated encryption between A and B. Unauthenticated, corrupted, or injected traffic from off-path attackers or untrusted relays is safely ignored so it cannot disrupt or reset active sessions.
* **Pre-Authentication Resilience:** Unauthenticated traffic must be cheap to reject before invoking expensive cryptographic handshakes or policy queries, and unconfirmed pre-authentication state must remain strictly bounded to resist resource exhaustion.
* **No Transitive Multi-Hop Trust:** Authorizing hop `Hᵢ` to forward traffic never grants it authority over other hops or destination B. A compromised hop cannot read credentials meant for other hops or B, impersonate A, divert or splice the route, or correlate and interfere with unrelated sessions.

#### Policy Verification, Renewal & Revocation

Both Core endpoint admission (`A ↔ B`) and composable Auth/ACL channel wrappers share the **"verifier, never issuer"** model via the **Access Control** seam:

1. After cryptographic peer proof, the verifier queries **Access Control** on **control events only** (setup and credential renewal), failing closed on timeout or error and intersecting every result with local host policy.
2. Accepted actions yield a bounded **Grant** (time-limited and optionally rate-bounded) enforced locally on the data path without consulting external policy engines per packet.
3. Peers can refresh Grants seamlessly **in-band** prior to expiry without interrupting live traffic, while local unpublishing, trust removal, or revocation signals trigger immediate local teardown bounded globally by short Grant lifetimes.

---

## 4. Core Boundary & Extension Seams

Everything outside the foundational engine attaches through four narrow seams:

| Seam | Responsibility | Out-of-Core Examples |
| --- | --- | --- |
| **1. Channels** | Exposes strictly typed Datagram or Stream connectivity, live payload limits, health signals, and optional direct originator-to-channel forwarding admission. | Pure TCP/UDP carriers, encrypted/obfuscated links, zero-dialing passive relays, Auth/ACL & stream-mux wrappers, explicit `Stream↔Datagram` adapters. |
| **2. Route / Path Source** | Supplies one explicit path per connection attempt and receives structured outcome and payload-limit feedback. | Static route configs, rendezvous discovery, active path probing, racing, and failover controllers. |
| **3. Access Control** | Evaluates `(verified peer, opaque credential, action)` on control events into a bounded Grant or denial, and emits revocations. | Static allowlists, short-lived capability token verifiers, external IPC or sandboxed enterprise policy engines. |
| **4. Edge Adapters** | Projects the Core's 1:1 Stream and Datagram handles to local sockets, interfaces, or applications. | Local TCP/UDP port forwarders, virtual network interfaces (owning L3 fragmentation if needed), application SDKs. |

### What Belongs Strictly Inside the Core

1. **Two-Plane Engine:** Strictly separated 1:1 end-to-end Stream and Datagram planes with zero implicit conversion or datagram fragmentation.
2. **End-to-End Trust & Enforcement Boundary:** Mutual `A ↔ B` authentication and encryption, pre-authentication DoS resilience, replay-safe destination opening, unambiguous end-to-end lifecycle signaling, local data-path Grant enforcement, live renewal, and instant revocation teardown.
3. **Composable Path Engine:** Explicit single-path execution, end-to-end plane and payload-limit enforcement, direct per-hop authorization with route integrity, opaque payload forwarding, and in-band hop lifecycle control.
4. **Seam Contracts:** Narrow, transport- and runtime-agnostic interfaces for the four extension seams.

---

## 5. Core Invariants Checklist

1. **Core knows no application or L3/L4 protocols** — only opaque discrete datagrams and opaque continuous byte streams.
2. **Datagram and Stream planes never mix or fragment in Core** — crossing planes requires an explicit channel adapter, and datagrams are never fragmented inside the Core.
3. **Channels are composable, pure, and locally private** — native carriers own link transport without policy logic; vertical stacks remain private to each host so originators only need their own first-hop channel and never sync remote configs.
4. **One explicit path and 1:1 session per connection** — discovery, probing, failover, and stream multiplexing stay outside the Core.
5. **Passive Relay and Active Transit never blur** — Passive Relay channels perform zero outbound dialing and stay strictly separate from outbound-dialing transit channels.
6. **Direct hop authorization and opaque forwarding** — each hop authorizes the originator directly without transitive trust or route tampering, and steady-state hops forward opaque end-to-end ciphertext without per-hop payload decryption or re-encryption.
7. **Replay-safe admission and explicit end-to-end lifecycle** — destination services open only after mutual authentication and replay protection, and end-to-end signaling cleanly distinguishes clean completion, destination refusal, and unexpected transport failure.
8. **Verifier, never an issuer** — policy runs strictly off the packet path on control events, fails closed, and never overrides local host veto.
9. **Path and payload-limit failures surface honestly** — broken links and payload-limit drops below session requirements tear down cleanly and report upward.
10. **Zero default endpoints and rootless isolation** — nodes run unprivileged by default, keep identities unlinkable across Trust Scopes, keep connection control in-band and host administration strictly local, and expose only explicitly published endpoints.
