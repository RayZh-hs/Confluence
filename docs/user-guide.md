# User Guide (`confluence-cli`)

`confluence-cli` runs any Confluence node role—Originator, Destination, Named Transit Hop, Zero-Dial Passive Relay, or multi-scope hybrid—from a single declarative TOML file.

---

## 1. CLI Commands

```sh
# Generate a fresh X25519 identity keypair
cargo run -p confluence-cli -- keygen

# Validate a TOML config without opening any sockets
cargo run -p confluence-cli -- check examples/direct/bob.toml

# Run a node (set RUST_LOG=debug for verbose tracing)
RUST_LOG=info cargo run -p confluence-cli -- run examples/direct/bob.toml
```

---

## 2. TOML Schema Overview

* `[[scopes]]`: Isolated Trust Scopes (`name`, `secret_key`, optional `under_load = true` for `MAC2` flood cookies covering both endpoints and transits on that scope).
* `[policy]` & `[[policy.rules]]`: Fail-closed `Authorizer` rules matching `scope` (name), `peers` (hex public keys or `"*"`), `action` (`"endpoint"`, `"transit"`, or `"any"`), `plane`, `target` (endpoint or transit name, supporting `"*"` and `"prefix*"`), `required_credential`, `ttl_secs`, plus optional out-of-core QoS limits (`max_bytes_per_sec`, `max_datagrams_per_sec`, `max_concurrent_streams` enforced directly on `Lease` via `RateGate` & `ConcurrencyLimiter`).
* `[[credentials]]`: Originator-side `CredentialProvider` entries (`scope`, optional `verifier` pubkey, `action`, `plane`, `target`, `credential`)—completely decoupled from routes and port bindings.
* `[[tcp_listeners]]` / `[[udp_listeners]]`: Explicit shared listeners demultiplexed across all mounted scopes via `Node` (and automatically muxed with `RelayMux` whenever `[[relay_transits]]` are configured).
* `[[outbound_carriers]]`: Named local first-hop carriers (`scope`, `name`, `plane`, `mtu`) mounted on an originator scope (never enables inbound forwarding).
* `[[transits]]`: Named fixed forwarding transits (`scope`, `name`, `plane`, `target_addr`, `mtu`) hiding downstream IP/port topology behind a logical name.
* `[[relay_transits]]`: Out-of-core zero-dialing single-port Passive Relay prefix (`scope`, `prefix`, `stream_mtu`, `datagram_mtu`, `[[relay_transits.registration_rules]]`) accepting NAT registrations over the node's existing TCP/UDP listeners.
* `[[relay_registrations]]`: NAT-side datagram keepalive registrations (`RelayClientDatagramLink`) and auto-replenishing passive TCP stream pools (`PassiveStreamPool`, `pool_size`).
* `[[routes]]` & `[[routes.hops]]`: Pure explicit single-path routes (`first_channel`, `first_locator`, hops `{ peer, target }` — zero credentials and zero raw downstream IPs).
* `[[publish_endpoints]]` / `[[bind_endpoints]]`: Local TCP/UDP service exposure and client port-forwarding.
* `[admin_socket]`: Optional local-only `0600` Unix control socket (`scope`, `path`).

---

## 3. Ready-to-Run Topologies

All repository examples are validated in CI (`cargo test -p confluence-cli`):

1. **Direct (`A -> B`):** [examples/direct/bob.toml](../examples/direct/bob.toml) & [examples/direct/alice.toml](../examples/direct/alice.toml)
2. **Passive Relay (`A -> R <- B`, single-port NAT registration):** [examples/passive-relay/relay.toml](../examples/passive-relay/relay.toml), [bob.toml](../examples/passive-relay/bob.toml), [alice.toml](../examples/passive-relay/alice.toml)
3. **Multi-Hop + Passive Relay (`A -> H1 -> R <- B`, named transit `"to-relay"`, `MAC2` cookies & QoS):** [examples/multihop-relay/relay.toml](../examples/multihop-relay/relay.toml), [hop1.toml](../examples/multihop-relay/hop1.toml), [bob.toml](../examples/multihop-relay/bob.toml), [alice.toml](../examples/multihop-relay/alice.toml)
