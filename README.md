# Confluence

Confluence is a fast, modular, cleanroom **A-to-B connectivity engine** implemented in safe Rust (`#![forbid(unsafe_code)]`).

Instead of forcing machines into a single centralized mesh hierarchy or routing all traffic through a fixed proxy bottleneck, Confluence connects **explicitly published endpoints on Node A to endpoints on Node B** across isolated **Trust Scopes**, composable **Channels**, and **1-RTT single-pass multi-hop paths**.

---

## Key Properties & Cleanroom Invariants

1. **Application-Protocol Agnostic:** Transports opaque discrete datagrams and opaque byte streams without parsing or terminating application protocols.
2. **Strict Two-Plane Separation:** End-to-end **Datagram Plane** and **Stream Plane** stay strictly separate inside Core with zero implicit cross-plane conversion.
3. **Composable Channels:** Native UDP/TCP carriers stay pure; `NoiseAclChannel` adds vertical `channel <-> originator` auth/ACL/rate-limiting to any carrier, and `confluence-relay` provides passive rendezvous relaying with **structurally zero outbound dialing**.
4. **Explicit Single-Path Execution:** Core validates plane/MTU/health bounds and executes the single explicit path supplied by `PathSource`, completing mutual authentication before opening local services.
5. **Blind, Flat, 1-RTT Multi-Hop Forwarding:** Pipelined `ChainSetup` authenticates each hop directly against the originator in **0-RTT per hop (1 RTT total end-to-end)** with zero transitive trust. Steady-state forwarding switches a flat 4-byte `HopLabel` (**29 bytes** constant datagram overhead regardless of hop count) or splices raw stream bytes without unwrapping E2E payloads.
6. **Verifier, Never an Issuer:** Access control runs **only on control events** (never per data packet), enforces token-bucket rate/concurrency/expiry `Grant`s on the data path, supports live in-band renewal, and guarantees local host hard veto via `IntersectAccessControl`.
7. **Pre-Authentication & Truncation Resilience:** Stateless `MAC1` pre-DH filtering and rotating `MAC2` flood cookies protect against CPU/state exhaustion; AEAD-authenticated `Close` records prevent stream truncation attacks.
8. **Rootless & Least Exposure by Default:** Unprivileged user-space instances, isolated `TrustScope` keypairs, and immediate session/circuit teardown on revocation, endpoint unpublish, or link failure.

---

## Workspace Layout

`confluence-core` has **zero** compile-time dependencies on any concrete socket carrier, passive relay plugin, policy backend, routing table, edge adapter, or CLI crate:

| Crate | Role |
| :--- | :--- |
| [`crates/confluence-core`](crates/confluence-core) | Two-plane E2E engine (`Node`, `TrustScope`, `EndpointRegistry`), blind single-pass multi-hop Path Engine, the 4 Seam traits, and reusable `Noise_IK`, TAI64N replay, MAC1/MAC2 cookie, `IntersectAccessControl`, and `GrantEnforcer` primitives. |
| [`crates/confluence-carriers`](crates/confluence-carriers) | Native `UdpDatagramChannel` & `TcpStreamChannel` carriers plus composable `NoiseAclDatagramChannel` & `NoiseAclStreamChannel` vertical middleware (Seam 1). |
| [`crates/confluence-relay`](crates/confluence-relay) | Standalone Passive Relay channel plugin (`RelayDatagramChannel`, `RelayStreamChannel`) and inbound presence clients (`RelayDatagramClient`, `RelayIngressStreamChannel`) — zero outbound dialing on the relay. |
| [`crates/confluence-policy`](crates/confluence-policy) | Static TOML-driven allowlist, bounded `Grant` rules, and live local revocation backend (Seam 3). |
| [`crates/confluence-routing`](crates/confluence-routing) | Static TOML-driven `ExplicitPath` resolver (Seam 2). |
| [`crates/confluence-edge`](crates/confluence-edge) | Local TCP (`TcpInboundForwarder`, `TcpOutboundForwarder`) and UDP (`UdpInboundForwarder`, `UdpOutboundForwarder`) port-forward adapters (Seam 4). |
| [`crates/confluence-testkit`](crates/confluence-testkit) | Deterministic in-memory datagram & stream fabrics with MTU, drop, reorder, link-cut, wire-tap inspection, and the Cleanroom Invariant verification suite. |
| [`crates/confluence-cli`](crates/confluence-cli) | Declarative TOML node runner and key utility (`confluence` binary). |

---

## Quickstart

### 1. Build & Run the Verification Suite

```bash
cargo build --workspace
cargo test --workspace
```

### 2. Generate Keys

Every Trust Scope and forwardable channel (`NoiseAclChannel` or `confluence-relay`) uses an isolated X25519 static keypair:

```bash
cargo run -p confluence-cli -- keygen --toml
```

Output:
```toml
secret_key = "..."
public_key = "..." # 32-byte hex PeerId
target_tag = "..." # 8-byte BLAKE2s256(public_key)[..8] demux tag
```

### 3. Validate & Run Example Topologies

Ready-to-run declarative TOML configurations are provided under [`examples/`](examples):

- **Direct (`A -> B`):** [`examples/direct/`](examples/direct)
- **Passive Relay (`A -> R <- B`):** [`examples/passive-relay/`](examples/passive-relay)
- **Multi-Hop + Passive Relay (`A -> H1 -> R <- B`):** [`examples/multihop-relay/`](examples/multihop-relay)

Validate any configuration without binding sockets:

```bash
cargo run -p confluence-cli -- validate --config examples/multihop-relay/alice.toml
```

Run a multi-hop + passive relay topology across four terminals:

```bash
# Terminal 1: Start Passive Relay R (zero outbound dialing)
cargo run -p confluence-cli -- run --config examples/multihop-relay/relay.toml

# Terminal 2: Start Transit Hop H1 (NoiseAclChannel egress guard)
cargo run -p confluence-cli -- run --config examples/multihop-relay/hop1.toml

# Terminal 3: Start NATed Destination Bob (exposes local 127.0.0.1:8080 TCP & :8081 UDP)
cargo run -p confluence-cli -- run --config examples/multihop-relay/bob.toml

# Terminal 4: Start Originator Alice (binds remote endpoint to local 127.0.0.1:18080 TCP & :18081 UDP)
cargo run -p confluence-cli -- run --config examples/multihop-relay/alice.toml
```

---

## Documentation

- [Statement of Purpose](docs/purpose.md) — Motivation and real-world sharing scenarios.
- [Core Design Specification](DESIGN.md) — Architectural principles, non-goals, and the 9 Cleanroom Invariants.
- [Implementation Architecture](docs/architecture.md) — Rust workspace design, concurrency model, and composable channel layering.
- [Wire Protocol Specification](docs/wire-protocol.md) — Byte-level `Noise_IK` envelopes, 1-RTT single-pass setup, 29-byte flat datagram switching, and stream record framing.
- [Extension Seams & Rust API Reference](docs/api.md) — Trait contracts and programmatic Rust usage.
- [User & Configuration Guide](docs/user-guide.md) — CLI usage, TOML schema reference, and topology walkthroughs.
- [Milestone 1 Implementation Plan](implementation_plan.md) — Phased engineering roadmap and verification matrix.
