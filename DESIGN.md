# Confluence — Core Design

> **Scope:** Cleanroom architectural specification for the **Confluence Core** only.
> All concrete transports, cross-plane channel adapters, peer discovery, auto-routing or multi-path switching controllers, trust/policy backends, credential issuers, and application frontends are intentionally excluded and attach later through the Core's extension seams.

---

## 1. Purpose & Core Abstraction

Confluence is a fast, resilient, composable **A-to-B connectivity core**.

Existing connectivity tools tend to lock users into one rigid trade-off:
- **Centralized mesh networks** tightly couple machine, user, and network under one administrative hierarchy, forcing full-host exposure or network merging just to share a single service.
- **Single-server reverse proxies** scope exposure cleanly to a port, but force all traffic through a fixed central bottleneck.
- **Standalone firewall-traversal tunnels** solve hostile-network reachability, but lack composable peer routing, trust isolation, and clean application boundaries.

Confluence resolves this with a single foundational abstraction: **connecting an endpoint on A to an endpoint on B** over an explicit, composable path and pluggable channels, while separating *how data moves*, *who is permitted*, and *how local applications enter the fabric*.

### Non-Goals for the Core
- **No application-protocol awareness:** The Core transports opaque byte streams and datagrams; it never parses or terminates application protocols.
- **No implicit cross-plane conversion:** The Core never silently wraps streams into datagrams or datagrams into streams; crossing planes is always an explicit, pluggable channel choice.
- **No auto-routing, discovery, or multi-path switching:** The Core's mission is to execute one explicitly specified path cleanly; peer discovery, candidate-path management, probing/racing, and live switching between paths stay outside the Core.
- **No built-in user management or credential issuance:** The Core verifies and enforces access; it never issues identities, manages invites, or runs enrollment workflows.
- **No assumed global topology or host-wide ownership:** There is no mandatory central coordinator, global network namespace, or host-wide privilege requirement.

---

## 2. Architectural Overview

```text
+-----------------------------------------------------------------------+
| Edge Adapters (Out of Core — [Seam: Edge Adapters])                   |
+-----------------------------------------------------------------------+
                     │                             │
             Stream  │                             │  Datagram
                     ▼                             ▼
+=======================================================================+
|                          CONFLUENCE CORE                              |
|                                                                       |
|  +-----------------------------+   +-------------------------------+  |
|  |        Stream Plane         |   |         Datagram Plane        |  |
|  |  End-to-end protected byte  |   |  End-to-end protected discrete|  |
|  |  streams                    |   |  messages                     |  |
|  +--------------+--------------+   +---------------+---------------+  |
|                 │                                  │                  |
|                 ▼                                  ▼                  |
|  +-----------------------------------------------------------------+  |
|  |            End-to-End Trust & Enforcement Boundary              |  |
|  |   A↔B cryptographic peer proof · Endpoint grant & rate limits   |  |
|  |   Delegates endpoint policy ─────► [Seam: Access Control]       |  |
|  +-----------------------------------------------------------------+  |
|                                  │                                    |
|                                  ▼                                    |
|  +-----------------------------------------------------------------+  |
|  |                    Composable Path Engine                       |  |
|  |   Explicit single-path execution · Plane/capability matching    |  |
|  |   Direct · Single-Pass Multi-Hop Label-Switched / Spliced Path  |  |
|  |   Dispatches opaque hop setup ───► Target Channel Plugins       |  |
|  |   Receives chosen path ◄───────── [Seam: Route / Path Source]   |  |
|  +-----------------------------------------------------------------+  |
+=======================================================================+
                                   │
                                   ▼
+-----------------------------------------------------------------------+
| Composable Channels (Out of Core — [Seam: Transports / Channels])     |
|   Native carriers (Stream or Datagram)                                |
|   Passive relay channels (registered presence, zero outbound dialing) |
|   Composable Auth/ACL/rate-limit channel wrappers (via Access Control)|
|   Explicit cross-plane channel adapters (Stream↔Datagram over carrier)|
+-----------------------------------------------------------------------+
```

---

## 3. Core Concepts

### 3.1 Decoupled Identity, Machine, and Trust Scope

Machine, user, identity, and network membership are independent dimensions:

- **Instance (Node):** A self-contained Confluence process, unprivileged by default. Multiple independent instances can coexist on the same machine under different users or purposes.
- **Trust Scope:** An isolated sharing or administrative domain. One instance can participate in many scopes simultaneously without merging their peers, routes, or permissions, and without linking its identity across unrelated scopes.
- **Host Sovereignty:** Every instance retains sole authority over its own machine. External authorities or peers can never expose an unpublished local resource or bypass a node's local hard veto.
- **Explicit Endpoint Exposure:** A node only exposes explicitly published named endpoints (stream, datagram, or both) within a Trust Scope; everything else on the host remains unreachable by default.

---

### 3.2 Datagram & Stream Separation (Two-Plane Model)

Network traffic falls into two fundamentally distinct semantic classes:
1. **Datagrams:** Unreliable, discrete, message-oriented payloads where low latency and independence between messages matter more than ordered delivery.
2. **Streams:** Reliable, ordered, continuous byte flows with backpressure.

Forcing one class blindly onto a carrier built for the other produces structural failure modes—such as cascading retransmission collapse when reliable streams are nested inside reliable streams, or head-of-line stalls when independent datagrams share an ordered channel.

Confluence makes this separation a strict, symmetric invariant:

- **Two Strictly Separate End-to-End Planes:** The Core maintains a **Datagram Plane** and a **Stream Plane** end-to-end between A and B. Inside the Core, stream traffic only traverses Stream channels, and datagram traffic only traverses Datagram channels.
- **No Implicit Cross-Plane Bridging in Core:** The Core never embeds a hidden stream-over-datagram or datagram-over-stream converter.
- **Explicit, Symmetric Cross-Plane Channel Adapters:** Whenever a node wants streams to traverse a datagram underlay, *or* datagrams to traverse a stream underlay, the node explicitly exposes a channel via an **adapter plugin**—using the **exact same channel contract** as any native transport channel:
  - A *Stream-over-Datagram* adapter plugin layers over a datagram channel/path and exposes a first-class **Stream** channel.
  - A *Datagram-over-Stream* adapter plugin layers over a stream channel/path and exposes a first-class **Datagram** channel.
- **Uniform Visibility to Path Execution:** Because adapted channels present the same interface as native channels (declaring their exposed traffic class, underlying reliability characteristics, framing bounds, and health signals), the Core validates and composes them uniformly without special-case logic.

---

### 3.3 Composable Connections & Routes

Connectivity is built from **composable channels** and **end-to-end route composition**:

#### Composable Channels (Native Carriers, Relays, Auth/ACL Wrappers & Cross-Plane Adapters)
Every channel exposed to the Core—whether a native hop-by-hop carrier, a passive relay channel, an Auth/ACL-guarded wrapper, or a cross-plane adapter layered over another channel—presents one uniform contract:
- Moves messages (Datagram) and/or byte flows (Stream) with explicit semantic guarantees.
- Declares its capabilities (exposed plane, underlying reliability traits, payload bounds).
- Reports liveness, failure, and effective payload limits upward so the Core can enforce framing and surface path health.
- For forwardable outbound channels, optionally accepts an opaque per-hop setup payload directly from the originator (`channel ↔ originator`), deciding admission and enforcing channel-level rate limits, expiry, and revocation on the returned forwarding handle.

Channels compose both **vertically** (layering cross-plane adaptation, passive relaying, or reusable Auth/ACL/rate-limit middleware over any underlying carrier) and **horizontally** (the Core chaining channels across an explicit hop sequence). Native carriers stay pure: they never own path selection, end-to-end security, or authorization policy; hop-level admission and passive relay behavior attach cleanly as composable channel plugins rather than being hardcoded inside the Core.

#### Composable Route Topologies
A single route from A to B explicitly composes one or more channels. Any hop in a route may use a different channel suited to that network boundary (including native carriers, passive relay channels where B holds an active registered presence with zero outbound dialing from the relay, or cross-plane adapters):

1. **Direct:** A single channel between A and B (which may be a direct carrier, a passive relay channel, or an adapted channel).
2. **Multi-Hop Chain:** A sequence of intermediate hops (`A → H₁ → … → Hₙ → B`), where each segment targets an outbound channel on that hop (e.g., an ACL-guarded egress carrier or a passive relay channel) suited to its network boundary.


#### Control-Plane Setup vs. Flat Data-Plane Forwarding
Multi-hop routes separate single-pass path establishment from steady-state packet forwarding:
- **Setup (Single-Pass Control Plane, 1 RTT End-to-End):** The originator sends one pipelined forward pass containing an opaque setup segment per hop plus the end-to-end handshake for B—no per-hop round-trip is required. Each intermediate node's Path Engine blindly dispatches its hop's opaque setup segment to the targeted outbound channel plugin, which authenticates the originator directly (`channel ↔ originator`), enforces its own isolated admission policy and rate bounds, and forwards the remaining tail. On the return pass from B, each hop binds its incoming label/stream to the authorized outgoing handle.
- **Forwarding (Data Plane, Every Packet/Stream):** Once established, intermediate hops perform constant-overhead label switching or raw stream splicing on untouched end-to-end protected payloads—no per-packet nested cryptographic unwrapping, no growing per-hop overhead, and no visibility into end-to-end contents.
- **Plane-Preserving Forwarding:** Datagram routes switch discrete end-to-end protected frames hop-by-hop; stream routes splice end-to-end protected byte streams hop-by-hop with backpressure.

---

### 3.4 Explicit Single-Path Execution

The Core's routing responsibility is intentionally minimal: **get one explicitly specified path right**.

- **No Auto-Routing or Multi-Path Management in Core:** The Core does not discover peers, compute route graphs, probe/race candidate paths, or dynamically switch between paths. Maintaining a list of viable paths and deciding which single path to use belongs outside the Core (in static user configuration or an external Route/Path Source plugin).
- **Strict Plane & Capability Validation:** Before establishing a path, the Core verifies that every channel in the chosen path matches the required plane (Datagram or Stream) and declared capability bounds—failing explicitly rather than silently converting planes or substituting unrequested routes.
- **Clean, Side-Effect-Free Setup:** Path establishment and mutual cryptographic authentication complete before opening any destination service, so a failed path setup never leaves duplicate or half-open application state.
- **Honest Failure Handling:** When an active path fails, the Core tears down affected sessions/streams cleanly and reports the failure upward rather than hiding broken links behind in-core path switching or stream-resumption machinery. Any failover, probing, or re-selection logic operates outside the Core by supplying a new chosen path.

---

### 3.5 End-to-End Security & "Verifier, Not Issuer"

Every channel and intermediary is treated as untrusted transport infrastructure.

#### Fixed Security Invariants in Core
Regardless of which channels, relays, or routers move the traffic, the Core guarantees:
- **End-to-End Protection:** Confidentiality, integrity, and mutual cryptographic proof of peer identity between A and B. Intermediaries never see plaintext payloads.
- **Pre-Authentication Resilience:** Unauthenticated traffic cannot exhaust CPU, memory, or policy-plugin capacity; invalid traffic is discarded silently and pending state is strictly bounded.
- **No Transitive Trust in Multi-Hop:** Every intermediate hop's target channel verifies the originator directly (`channel ↔ originator`). A compromised upstream hop cannot see credentials intended for downstream channels or B, nor impersonate the originator to them.

#### Policy Enforcement vs. Policy Decision
End-to-end endpoint trust (`A ↔ B`, enforced in Core) and per-hop forwarding admission (enforced by composable Auth/ACL channel plugins) both follow the same **"verifier, never issuer"** model using the shared **Access Control** seam:
1. Cryptographic handshake proves *who* the remote peer/originator is (with replay protection and pre-auth resilience).
2. On **control events only** (endpoint open, credential refresh, or channel/relay forwarding setup)—never per data packet—the verifier asks the active **Access Control** plugin whether that peer (presenting an optional opaque, bounded credential) is allowed to perform the requested action.
3. The plugin returns a **Grant** carrying an expiration time and optional rate bounds, or a denial (failing closed on error or timeout).
4. Grants (expiry and rate limits) are enforced directly on the data path—by Core for E2E endpoints, and by the authorized channel handle for intermediate hops.
5. Local host policy can always be intersected with any external policy plugin so a compromised authority can never override local host restrictions.

#### Seamless Renewal & Honest Revocation
- **In-Band Renewal:** Active peers can refresh expiring credentials over an established link to extend their Grant in place without interrupting live traffic.
- **Immediate Local Teardown:** Removing local trust, unpublishing an endpoint, or receiving a revocation signal immediately terminates matching active sessions, streams, and circuits on that node.
- **Honest Distributed Bounds:** In distributed or partitioned networks without continuous global coordination, revocation across remote peers is bounded naturally by short Grant lifetimes (optionally accelerated by revocation feeds), rather than pretending instantaneous global revocation exists.

---

## 4. Core Boundary & Extension Seams

To keep the Core small, auditable, and cleanroom-friendly, everything outside the foundational engine attaches through four narrow seams.

| Seam | Responsibility | Examples Added Later *(Out of Core)* |
| :--- | :--- | :--- |
| **1. Channels (Transports, Relays, Auth/ACL Wrappers & Cross-Plane Adapters)** | Exposes datagram and/or stream connectivity with declared capabilities, health signals, and optional direct `channel ↔ originator` setup admission—covering native carriers, passive relay channels, Auth/ACL wrappers, and cross-plane adapters. | Direct peer-to-peer carriers, passive relay channel plugins (zero outbound dialing), reusable Auth/ACL/rate-limit channel middleware, obfuscated carriers, explicit stream-over-datagram and datagram-over-stream adapters. |
| **2. Route / Path Source** | Supplies the single explicit path (direct or hop chain) for a target peer. All peer discovery, viable-path list management, probing/racing, and failover/switching live behind this seam. | Static user-configured path lists, local/rendezvous peer discovery, active probing or failover controllers. |
| **3. Access Control** | Evaluates `(verified peer identity, opaque credential, requested action)` into a bounded `Grant` or denial, and pushes revocation signals. Used by Core's E2E boundary and reusable by Auth/ACL channel plugins. | Static peer allowlists, short-lived certificate verifiers, external enterprise/quota policy engines. |
| **4. Edge Adapters** | Projects the Core's Stream and Datagram planes to local applications, host interfaces, or external tools. | Local port publish/bind, optional virtual network interfaces, custom application integrations. |

### What Belongs Strictly Inside the Core
1. **Two-Plane Engine:** End-to-end Datagram Plane and end-to-end Stream Plane, kept strictly separate with zero built-in cross-plane conversion.
2. **End-to-End Cryptographic & Enforcement Boundary:** `A ↔ B` peer identity proof, payload confidentiality/integrity, pre-auth resource bounds, endpoint Grant and rate enforcement, and immediate teardown on revocation.
3. **Composable Path Engine:** Explicit single-path execution, plane/capability validation, blind single-pass hop-setup dispatch to targeted channel plugins, and flat label-switched / spliced multi-hop forwarding (no hardcoded passive-relay or hop-ACL policy logic).
4. **Seam Contracts:** Clean, narrow interfaces for the four extension seams.

---

## 5. Cleanroom Invariants Checklist

Any future Core implementation or plugin must uphold these non-negotiable invariants:

1. **Core knows no application protocols** — only opaque datagrams and opaque byte streams.
2. **Datagram and Stream planes stay strictly separate in Core** — no implicit cross-plane conversion in either direction; crossing planes always happens by explicitly exposing a channel through an adapter plugin with the exact same interface as any native transport channel.
3. **Channels are composable and pure** — native carriers handle connectivity without owning path selection or policy; vertical channel plugins compose cross-plane adaptation, passive relaying, and channel-level Auth/ACL/rate-limiting uniformly behind one channel contract.
4. **Core executes one explicit path; no auto-routing** — the Core validates and runs the single path supplied to it, completing path setup and mutual authentication before opening destination services; discovery, probing, racing, and multi-path switching stay out of Core.
5. **Passive Relay and Active Transit never blur** — Passive Relay lives outside Core as a composable channel plugin that performs zero outbound dialing, physically separated from outbound-dialing transit channels (which enforce egress authorization via composable channel ACL).
6. **Multi-hop forwarding is flat, blind, and single-pass** — per-hop `channel ↔ originator` authentication completes in a single forward pass without per-hop round-trips; data-plane hops switch labels or splice streams without unwrapping end-to-end payloads or sharing credentials across hops.
7. **Verifier, never an issuer** — credentials are opaque; policy runs only on control events; local host policy always retains final veto.
8. **Path failures surface honestly** — when an active path fails, the Core tears it down cleanly and reports failure upward rather than hiding broken links behind in-core path switching or stream-resumption machinery.
9. **Least exposure and rootless by default** — instances are unprivileged, scopes are isolated, and only explicitly published endpoints are reachable.
