# Extension Seams & Rust API Reference

`confluence-core` exposes a narrow programmatic surface centered on `Node`, `TrustScope`, and four extension seam traits in `confluence_core::seams`.

---

## 1. Core Runtime API (`confluence_core`)

### `StaticKeypair`, `PeerId`, and `TargetTag`
- `StaticKeypair::generate() -> StaticKeypair` — Generates a random X25519 static keypair (zeroized on drop).
- `StaticKeypair::from_secret_hex(&str) -> Result<StaticKeypair>` — Loads a 32-byte hex secret key.
- `keypair.peer_id() -> PeerId` — 32-byte X25519 public key (`Display` / `FromStr` as 64-char hex).
- `keypair.target_tag() -> TargetTag` — 8-byte `BLAKE2s256(pubkey)[..8]` listener demux tag.

### `TrustScope` & `Node`
```rust
let router = StaticRouter::new();
let node = Node::new(router);

let scope_id = ScopeId::new("engineering")?;
let scope = TrustScope::new(scope_id.clone(), keypair, policy);
node.add_scope(scope)?;

// Attach Seam 1 carriers & composable forwardable channels
node.attach_datagram_channel(udp_carrier)?;
node.attach_stream_channel(tcp_carrier)?;
node.mount_datagram_forward_channel(acl_or_relay_dgram_channel)?;
node.mount_stream_forward_channel(acl_or_relay_stream_channel)?;

// Seam 4 Inbound: publish explicit endpoints
let mut stream_ep = node.publish_stream_endpoint(&scope_id, EndpointName::new("ssh")?)?;
let mut dgram_ep = node.publish_datagram_endpoint(&scope_id, EndpointName::new("game-udp")?)?;

// Seam 4 Outbound: open end-to-end encrypted stream or datagram session
let mut stream = node.open_stream(&scope_id, remote_peer_id, EndpointName::new("ssh")?).await?;
let dgram = node.open_datagram(&scope_id, remote_peer_id, EndpointName::new("game-udp")?).await?;
```

---

## 2. The Four Extension Seams (`confluence_core::seams`)

### Seam 1: Composable Channels (`seams::channel`)
Divided strictly by plane (`Plane::Datagram` vs `Plane::Stream`) and role:
- **Transport Carriers:**
  - `DatagramChannel`: `id()`, `caps()`, `send_to(addr, payload)`, `recv_from(buf)`, `health()`, `close()`
  - `StreamChannel`: `id()`, `caps()`, `open(addr) -> BoxedAsyncStream`, `accept() -> (BoxedAsyncStream, ChannelAddr)`, `health()`, `close()`
- **Forwardable Channel Plugins (mounted by `TargetTag`):**
  - `DatagramForwardChannel`: `target_tag()`, `caps()`, `handle_setup(source_addr, setup_payload) -> Result<SetupOutcome<BoxedDatagramForwardHandle>>`, `handle_control(...)`
  - `StreamForwardChannel`: `target_tag()`, `caps()`, `handle_setup(source_addr, setup_payload) -> Result<SetupOutcome<BoxedAsyncStream>>`, `handle_control_stream(...)`

Provided implementations:
- `confluence_carriers::{UdpDatagramChannel, TcpStreamChannel}` — Pure native socket carriers.
- `confluence_carriers::{NoiseAclDatagramChannel, NoiseAclStreamChannel}` — Vertical `channel <-> originator` auth + `AccessControl` + `GrantEnforcer` wrappers.
- `confluence_relay::{RelayDatagramChannel, RelayStreamChannel, RelayDatagramClient, RelayIngressStreamChannel}` — Zero-outbound-dial passive relay slots and client pool adapters.

### Seam 2: Route / Path Source (`seams::routing`)
- `PathSource::resolve(&self, scope: &ScopeId, target: &PeerId, plane: Plane) -> Result<ExplicitPath>`
- `ExplicitPath`: Specifies `plane`, `entry_channel`, `entry_addr`, `hops: Vec<PathHop>`, `target_scope_tag`, `target_pubkey`, and optional `target_credential`.
- Provided implementation: `confluence_routing::StaticRouter`.

### Seam 3: Access Control (`seams::access`)
- `AccessControl::evaluate(&self, req: AccessRequest) -> Result<Decision>`
  - Evaluated **only on control events** (`Action::OpenEndpoint`, `Action::ChannelForward`, `Action::ChannelCustom`, `Action::RenewGrant`).
  - Returns `Decision::Allow(Grant)` (`expires_at`, `max_bytes_per_sec`, `max_datagrams_per_sec`, `max_concurrent_streams`) or `Decision::Deny { reason }`.
- `AccessControl::revocations(&self) -> broadcast::Receiver<RevocationEvent>`
- `IntersectAccessControl<L, E>` (in `confluence_core`): Enforces local host hard veto, bounded evaluation timeouts (fail-closed), strict minimum `Grant` intersection, and merged revocation broadcasts.
- Provided implementation: `confluence_policy::StaticPolicy`.

### Seam 4: Edge Adapters (`seams::edge`)
- `DatagramSession` trait (implemented by `ConfluenceDatagramSession`): `send`, `recv`, `renew`, `close`.
- `ConfluenceStream`: Implements `tokio::io::AsyncRead + AsyncWrite + Unpin + Send` plus `renew` and AEAD-authenticated `close`.
- Provided implementations: `confluence_edge::{TcpInboundForwarder, TcpOutboundForwarder, UdpInboundForwarder, UdpOutboundForwarder}`.
