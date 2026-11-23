# Confluence

Confluence securely connects explicitly published named **Endpoints** over explicit, pluggable paths and named **Transits**. A dial establishes one bidirectional byte stream or datagram flow. Intermediate hops forward end-to-end ciphertext under route-integrity-bound 1-RTT single-pass setup, and the destination opens its local service only after authenticating the originator's 1.0 RTT confirmation.

* [Core Design](DESIGN.md) — architectural boundaries, symmetric auth model, and the 10 Core invariants
* [Architecture](docs/architecture.md) · [Wire Protocol](docs/wire-protocol.md) · [API Reference](docs/api.md) · [Deployment Guide](docs/user-guide.md)

## Rust workspace

| Crate | Responsibility |
| --- | --- |
| [confluence-core](crates/confluence-core) | `#![forbid(unsafe_code)]`, zero-OS-I/O engine: `ScopeInstance`, multi-scope `Node`, route-integrity 1-RTT setup over named Endpoints & Transits, rotating `MAC2` flood cookies, per-link generational CIDs, symmetric `CredentialProvider` ↔ `Authorizer` + `IntersectAuthorizer`, revocable `Lease` (`TrafficGate`, `SessionGuard`, live `AuthExtensions` / `SessionAuth`), and the two independent data planes |
| [confluence-plugins](crates/confluence-plugins) | Out-of-core QoS primitives (`QosLimits`, `RateBucket`, `RateGate`, `ConcurrencyLimiter`, `QosAuthorizer`), `StaticAuthorizer`, TOML `StaticPolicy`, `StaticCredentials`, `StaticPathSource`, in-memory channels, and `TokioSpawner` |
| [confluence-net](crates/confluence-net) | Pure native TCP (`TcpCarrier`, `TcpListenerSource`) and Linux `DF=1` UDP (`UdpCarrier`, `UdpIngress` + `serve_custom`) carriers supporting both `ScopeInstance` and multi-scope `Node` |
| [confluence-relay](crates/confluence-relay) | Out-of-core zero-dialing `PassiveRelay` and single-port transport-muxed `RelayService` / `RelayMux` + NAT-side `RelayClientDatagramLink` & `PassiveStreamPool` |
| [confluence-edge](crates/confluence-edge) | TCP/UDP port forwarding, `E2eStreamIo` (`tokio::io::AsyncRead + AsyncWrite`), target handlers, and owner-only `0600` Unix administration |
| [confluence-testkit](crates/confluence-testkit) | Deterministic fault-injection hubs (`MemDatagramHub`, `MemStreamHub`), wire-tap capture, outbound-dial auditing, `AuditAuthorizer`, and enterprise RBAC end-to-end tests |
| [confluence-runtime](crates/confluence-runtime) | Rust `NodePlan` for composing and validating deployments, managing Tokio services, and shutting down |
| [confluence-ext](crates/confluence-ext) | Out-of-core plugin evaluation suite: Group capability tokens, link-encrypted TCP/UDP, muxed passive TCP relay, Blind Rendezvous UDP P2P + NAT traversal, Striped-TCP & Stream-over-Datagram adapters, and virtual L3 mesh |
| [confluence-examples](examples) | Runnable direct, passive-relay, and multihop deployments in Rust, plus `confluence-keygen` |

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo bench -p confluence-core --bench lease_contention
```

## Deploy with Rust

```rust
let mut app = NodePlan::new();
app.scope("app", identity)?
    .authorizer(policy)
    .publish_stream("http", Arc::new(TcpTarget(backend)))?;
app.listen_tcp(ingress);

let prepared = app.prepare()?;
prepared.start().await?.run_until(tokio::signal::ctrl_c()).await?;
```

The deployment binary supplies the identity, policy, and socket addresses. Build and run Alice and Bob locally with the [deployment guide](docs/user-guide.md), or inspect the [direct](examples/src/direct.rs) and [relayed](examples/src/relayed.rs) wiring.

## Embedding an instance

1. Build one or more `ScopeInstance`s via `ScopeInstance::builder(identity, tasks)` attaching your `Authorizer` (or `IntersectAuthorizer` for host sovereignty), `PathSource` (pure routing), and `CredentialProvider` (token acquisition & live in-band refresh). Optionally mount multiple scopes on a single `Node` to share one TCP/UDP listener.
2. Register local first-hop outbound carriers (`register_stream_carrier` / `register_datagram_carrier`). At intermediate hops, publish explicit named transits (`publish_stream_route` / `publish_datagram_route`, or prefix handlers such as `RelayService` via `publish_stream_transit_prefix`) — Core handles `Noise_IK`, `MAC2` cookies, replay protection, and `AuthGate` automatically.
3. Publish endpoints via `publish_stream` / `publish_datagram` directly (QoS is enforced fail-closed via `Lease` `TrafficGate` / `SessionGuard` attached by your `Authorizer`). Handlers receive a live `SessionAuth` whose `context::<MyClaims>()` reflects in-band renewals automatically, enabling fine-grained application RBAC with zero double-authentication.
4. Serve ingress via `serve_tcp` / `serve_tcp_node`, `UdpIngress::serve` / `serve_node` (or `RelayMux::serve_tcp_node` / `serve_udp_node` for single-port passive relays), and dial cleanly with `dial_stream(peer, endpoint)` or `dial_datagram(peer, endpoint, min_mtu)` (or attach `serve_local_tcp` / `serve_local_udp` / `E2eStreamIo`).

The optional `AdminSocket::bind` creates an owner-only `0600` Unix socket accepting one newline-terminated command per connection (`publish-stream`, `publish-datagram`, `unpublish`, `revoke-peer`, `list`).
