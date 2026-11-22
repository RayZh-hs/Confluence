# User & Configuration Guide

This guide walks through generating keys, writing declarative node TOML configurations, and running Confluence across Direct, Passive Relay, and Multi-Hop topologies using `confluence-cli`.

---

## 1. CLI Commands

Build the CLI binary:

```bash
cargo build --release -p confluence-cli
```

| Subcommand | Description |
| :--- | :--- |
| `confluence keygen [--toml]` | Generates a new X25519 static secret key, `PeerId` public key, and 8-byte `TargetTag`. |
| `confluence pubkey --secret <HEX>` | Prints the `PeerId` and `TargetTag` corresponding to an existing 64-char hex secret key. |
| `confluence validate --config <FILE.toml>` | Validates TOML syntax, keys, carrier references, scopes, and explicit routes offline. |
| `confluence run --config <FILE.toml>` | Starts the Confluence node and runs until `Ctrl+C`, shutting down all adapters cleanly. |

Set `RUST_LOG=info` or `RUST_LOG=debug` to control structured log verbosity.

---

## 2. Node TOML Configuration Reference

A single TOML file declaratively configures a Confluence node's local policy, Trust Scopes, carriers, transit/relay plugins, explicit routes, and local port-forwards.

### 2.1 `[policy]` and `[[policy.rules]]` (Seam 3)
Fails closed (`default_allow = false` recommended). Evaluates only on control events:

```toml
[policy]
default_allow = false
default_ttl_secs = 300

[[policy.rules]]
scope = "lab"                          # Scope ID or "*"
peers = ["<64-char-hex-peer-id>"]      # Allowed PeerIds or ["*"]
action = "open_endpoint"               # "open_endpoint" | "channel_forward" | "channel_custom" | "any"
plane = "stream"                       # Optional: "stream" | "datagram"
target = "demo-app"                    # Optional: endpoint name, forward addr, or custom kind ("relay_register" / "relay_connect")
required_credential = "secret-token"   # Optional opaque UTF-8 credential
ttl_secs = 300                         # Optional per-rule Grant TTL
max_bytes_per_sec = 52428800           # Optional throughput cap (bytes/sec)
max_datagrams_per_sec = 5000           # Optional packet rate cap (datagrams/sec)
max_concurrent_streams = 32            # Optional stream concurrency cap
```

### 2.2 `[[scopes]]`
Mounts isolated Trust Scopes on the node. Use distinct keypairs across unrelated scopes to prevent identity correlation:

```toml
[[scopes]]
id = "lab"
secret_key = "<64-char-hex-secret-key>"
under_load = false                     # Set true to enforce stateless MAC2 flood cookies
```

### 2.3 `[[udp_carriers]]` and `[[tcp_carriers]]` (Seam 1 Raw Carriers)

```toml
[[udp_carriers]]
id = "udp0"
bind_addr = "127.0.0.1:14100"          # Use ":0" for ephemeral outbound port
mtu = 1400

[[tcp_carriers]]
id = "tcp0"
listen_addr = "127.0.0.1:14101"        # Omit `listen_addr` for outbound-only client/NAT nodes!
```

### 2.4 `[[acl_forward_channels]]` (Active Transit Hop Middleware)
Mounts a `NoiseAclChannel` wrapper over an existing carrier on intermediate transit hops:

```toml
[[acl_forward_channels]]
plane = "stream"                       # "stream" or "datagram"
carrier_id = "tcp0"
scope = "transit-edge"
secret_key = "<64-char-hex-channel-secret-key>"
```

### 2.5 `[[relay_channels]]` and `[[relay_registrations]]` (Zero-Dial Passive Relay)
On the **Relay Node (`R`)**:

```toml
[[relay_channels]]
plane = "stream"                       # Mount both "stream" and "datagram" as needed
scope = "relay-domain"
secret_key = "<64-char-hex-relay-secret-key>"
```

On the **NATed Destination Node (`B`)**:

```toml
[[relay_registrations]]
plane = "datagram"
scope = "lab"
carrier_id = "udp_nat"
relay_addr = "127.0.0.1:15100"
relay_pubkey = "<relay-datagram-pubkey>"
keepalive_secs = 30

[[relay_registrations]]
plane = "stream"
scope = "lab"
carrier_id = "tcp_nat"
ingress_id = "relay_stream_in"
relay_addr = "127.0.0.1:15101"
relay_pubkey = "<relay-stream-pubkey>"
pool_size = 4
```

### 2.6 `[[routes]]` and `[[routes.hops]]` (Seam 2 Explicit Single-Path Routing)

```toml
[[routes]]
scope = "lab"
target_pubkey = "<bob-scope-pubkey>"
plane = "stream"
entry_channel = "tcp0"
entry_addr = "127.0.0.1:16101"         # First hop (or Bob directly when hops = [])
target_credential = "bob-e2e-token"

[[routes.hops]]
channel_pubkey = "<hop1-stream-pubkey>"
next_addr = "127.0.0.1:16201"          # Next hop address (or Bob's PeerId when targeting a Passive Relay!)
credential = "hop1-transit-token"
```

### 2.7 `[[publish_endpoints]]` and `[[bind_endpoints]]` (Seam 4 Local Port Forwards)

On the **Publishing Node (`B`)**:
```toml
[[publish_endpoints]]
scope = "lab"
endpoint = "demo-app"
plane = "stream"
local_target = "127.0.0.1:8080"
```

On the **Client Node (`A`)**:
```toml
[[bind_endpoints]]
scope = "lab"
target_pubkey = "<bob-scope-pubkey>"
endpoint = "demo-app"
plane = "stream"
listen_addr = "127.0.0.1:18080"
```

---

## 3. Walkthrough Topologies

Complete working configurations for all three topologies are ready to run in [`examples/`](../examples):

1. **Direct (`A -> B`):** [`examples/direct/bob.toml`](../examples/direct/bob.toml) and [`examples/direct/alice.toml`](../examples/direct/alice.toml)
2. **Passive Relay (`A -> R <- B`):** [`examples/passive-relay/relay.toml`](../examples/passive-relay/relay.toml), [`bob.toml`](../examples/passive-relay/bob.toml), and [`alice.toml`](../examples/passive-relay/alice.toml)
3. **Composed Multi-Hop + Passive Relay (`A -> H1 -> R <- B`):** [`examples/multihop-relay/hop1.toml`](../examples/multihop-relay/hop1.toml), [`relay.toml`](../examples/multihop-relay/relay.toml), [`bob.toml`](../examples/multihop-relay/bob.toml), and [`alice.toml`](../examples/multihop-relay/alice.toml)
