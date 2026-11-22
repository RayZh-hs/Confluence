# Extension Seams & Rust API Reference

`confluence-core` exposes a narrow programmatic API centered on `ScopeInstance`, multi-scope `Node`, and four extension seams in `confluence_core::seams`.

---

## 1. Core Identity & Runtime Types (`confluence_core`)

* `ScopeKeypair`: Per-scope X25519 keypair (`generate`, `from_bytes`, `from_secret_hex`, `secret_hex`, `public_key`, `kid`).
* `PublicKey` / `ScopeKid`: Validated hex `Display` / `FromStr`, compact `Debug`, and optional `serde` (via feature `"serde"`).
* `ScopeInstance`: Isolated Trust Scope built via `ScopeInstance::builder(identity, tasks).authorizer(..).routes(..).credentials(..).under_load(..).build()`.
  * Outbound carriers (first-hop only; default-deny forwarding): `register_stream_carrier(name, carrier)`, `register_datagram_carrier(name, carrier)`.
  * Published endpoints: `publish_stream(name, handler)`, `publish_datagram(name, min_mtu, handler)` (return RAII `PublishGuard`).
  * Published named transits: `publish_stream_route(name, channel, locator)`, `publish_datagram_route(name, channel, locator)`, `publish_stream_transit(name, handler)`, `publish_datagram_transit(name, handler)`, `publish_stream_transit_prefix(prefix, handler)`, `publish_datagram_transit_prefix(prefix, handler)`.
  * Dialing: `dial_stream(peer, endpoint)`, `dial_datagram(peer, endpoint, min_mtu)`, plus zero-side-effect staged variants `dial_stream_staged` / `dial_datagram_staged` for out-of-core path racers.
  * Local control: `set_under_load(bool)`, `revoke_peer(&pk)`, `unrevoke_peer(&pk)`, `revoke_transit(name)`.
* `Node`: Thin multi-scope container (`add_scope`, `remove_scope`, `scope(&pk)`, `accept_stream`, `attach_datagram`, `serve_stream_listener`, `serve_datagram_listener`) demultiplexing shared TCP/UDP listeners across isolated scopes in $O(1)$ by `ScopeKid`.

---

## 2. The Four Extension Seams (`confluence_core::seams`)

### Seam 1: Pure Composable Channels (`seams::channel`)
* **Pure 2-Method Transports:** `StreamChannel` (`type Stream`, `caps`, `dial_stream`) and `DatagramChannel` (`type Link`, `caps`, `open_link`) carry zero auth, cookie, or policy logic.
* **Compile-Time Vertical Composition:** Wrappers compose statically via associated `Stream: AsyncStream` / `Link: DatagramLink` types, erasing once at the `ScopeInstance` / `Node` boundary.
* **Poll-Based Hot Path & Zero-Copy Framing:** `StreamRead`, `StreamWrite`, and `DatagramLink` (`poll_send_ready`, `try_send`, `poll_recv`, `link_id() -> LinkId`) are natively dyn-safe and allocation-free. `ChannelCaps::with_overhead` / `with_cap` propagate dynamic MTU changes via `MtuWatch` without background tasks, and `PacketBuf` reserves 64 B headroom + 64 B tailroom for in-place outer sealing.
* **Symmetric Inbound Listeners:** `StreamListener` and `DatagramListener` (with blanket `Arc<L>` impls).
* **Built-in Implementations:**
  * `confluence_net::{TcpCarrier, TcpListenerSource, UdpCarrier, UdpIngress, CustomUdpAttachment, serve_tcp, serve_tcp_node}`
  * `confluence_relay::{PassiveRelay, RelayService, RelayMux, RelayClientDatagramLink, PassiveStreamPool, register_datagram_presence}`

### Seam 2: Pure Route / Path Source (`seams::path_source`)
* `PathSource::resolve_path(&self, peer, endpoint, plane) -> BoxFut<Result<ExplicitPath, CoreErr>>`
* `PathSource::report_outcome(&self, path_id, PathOutcome)` (`Established`, `MtuChanged`, `Failed`, `Closed`)
* `ExplicitPath { id, first_channel: String, first_locator: Vec<u8>, min_mtu, hops: Vec<HopSpec> }` where `HopSpec { peer: PublicKey, target: String }` carries **zero credentials** and **zero raw downstream IPs**.
* Built-in implementation: `confluence_plugins::StaticPathSource`.

### Seam 3: Symmetric Auth (`seams::auth` & `lease`)
* **Originator — `CredentialProvider`:**
  * `credential(&self, req: CredentialRequest) -> BoxFut<Result<Vec<u8>, CoreErr>>`
  * `CredentialRequest` supplies `{ verifier, target: TargetRef, destination, endpoint, path_id, is_refresh, previous }`.
  * Built-ins: `EmptyCredentials`, `confluence_plugins::StaticCredentials`.
* **Verifier — `Authorizer`:**
  * `authorize(&self, req: AuthRequest) -> BoxFut<Result<Lease, AuthDenied>>` (`AuthDenied::Denied` / `AuthDenied::Busy`)
  * `AuthRequest` supplies `{ peer, target: TargetRef, credential, is_renewal }`, where `TargetRef` is either `Endpoint { name, plane }` or `Transit { name, plane }`.
  * `revocations(&self)` / `revocation_streams(&self)` emit `Revocation::{Peer, Endpoint, Transit, All}`.
  * `IntersectAuthorizer<L, E>`: Host-sovereignty combinator enforcing local hard veto, intersecting TTL, `TrafficGate`s, RAII `guards`, and `AuthExtensions` (with local precedence) via `Lease::intersect`, and collecting both revocation streams with zero background tasks.
  * Built-ins: `DenyAllAuthorizer`, `confluence_plugins::{StaticAuthorizer, StaticPolicy, QosAuthorizer}`.
* **Lease, `TrafficGate` & Live `SessionAuth` (`confluence_core::lease`):**
  * `Lease::new(ttl).with_gate(rate_gate).with_guard(slot).with_context(my_claims)`: attaches an algorithm-agnostic `TrafficGate` (invoked by Core strictly on `DATA` frames, swapped live on renewal), session-scoped RAII `SessionGuard`s (held across renewals until session close), and type-keyed `AuthExtensions`.
  * `SessionAuth`: carries `peer: PublicKey` plus a live watch over `AuthExtensions` (`auth.context::<T>()` always returns the latest claims after in-band renewal, and `auth.changed().await` wakes on claim updates).
* **Out-of-Core QoS Primitives (`confluence_plugins::qos`):** `QosLimits`, `RateBucket`, `RateGate` (implements `TrafficGate`, per-session or shared `Arc` per-peer), `ConcurrencyLimiter<K>` / `SessionSlot<K>`, and `QosAuthorizer<A, F>`.

### Seam 4: Endpoints, Transits & Edge Adapters (`seams::endpoint`, `confluence_edge`)
* **Endpoints:** `StreamEndpointHandler::open(&self, auth: SessionAuth)` and `DatagramEndpointHandler::open(&self, auth: SessionAuth)`.
* **Transits:** `StreamTransitHandler::open(&self, target: &str, auth: SessionAuth)` (1:1 next-hop stream) and `DatagramTransitHandler::open(&self, target: &str, auth: SessionAuth)` (1:N shared neighbor link resolver), plus helpers `StaticTransit<C>` and `DynamicTransit<C>`.
* **Edge Adapters (`confluence_edge`):** `TcpTarget`, `UdpTarget`, `serve_local_tcp`, `serve_local_udp` (`Destination { peer, endpoint }` — zero credentials!), `E2eStreamIo` (`tokio::io::AsyncRead + AsyncWrite`), and `AdminSocket` (`0600` Unix IPC).

---

## 3. Building Fine-Grained Application RBAC (Zero Double-Auth)

See [crates/confluence-testkit/tests/enterprise_acl.rs](../crates/confluence-testkit/tests/enterprise_acl.rs) for a complete runnable end-to-end example:

1. **Client (`CredentialProvider`):** Fetch short-lived signed capability tokens from your identity broker (OIDC/SSO/Vault) per `(verifier, TargetRef)` and rotate them automatically when `req.is_refresh == true`.
2. **Verifier (`Authorizer` + `QosAuthorizer` + `IntersectAuthorizer`):** Verify the token signature, peer binding, expiry, and target allowlist once on setup/renewal; return `Lease::new(ttl).with_context(UserClaims { user, role, tenant, qos })`. Wrap with `QosAuthorizer` (or attach `RateGate` + `ConcurrencyLimiter` directly) and `IntersectAuthorizer(local_host_policy, corp_authorizer)` so local host TTL, QoS caps, and claims always compose with host sovereignty.
3. **Application Handler (`StreamEndpointHandler::open`):** Publish your handler directly (zero QoS wrapper boilerplate). Read `auth.context::<UserClaims>()` directly inside `open()` or per request to enforce query-, row-, tenant-, or method-level permissions—with live role/claim updates on in-band renewal and instant teardown via `Revocation::Peer(pk)`.
