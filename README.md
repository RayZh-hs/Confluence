# Confluence

Confluence securely connects named endpoints over explicit, pluggable paths. A dial establishes one bidirectional byte stream or datagram flow. Intermediate hops forward end-to-end ciphertext, and the destination opens its local service after authenticating the originator’s confirmation.

The [design](DESIGN.md) describes the architecture. The [protocol and implementation plan](SPEC%26IMPL.md) specifies the wire format and milestones.

## Rust workspace

| Crate | Responsibility |
| --- | --- |
| [confluence-core](crates/confluence-core) | Scope identities, authenticated setup, explicit paths, grants, and the two independent data planes |
| [confluence-plugins](crates/confluence-plugins) | Static routes and ACLs, the transit authorization wrapper, and in-memory channels |
| [confluence-net](crates/confluence-net) | TCP and Linux DF UDP carriers on explicitly bound sockets |
| [confluence-edge](crates/confluence-edge) | TCP and UDP port forwarding, target handlers, and local Unix administration |
| [confluence-relay](crates/confluence-relay) | Passive selection of pre-established stream and datagram presence links |

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo bench -p confluence-core --bench grant_contention
```

## Embedding an instance

1. Create a `ScopeInstance` with its own `ScopeKeypair`, an `AccessControl` implementation, a `PathSource`, and a task spawner. The included plugins provide `StaticAcl`, `StaticPathSource`, and `TokioSpawner`.
2. Register the local first-hop carrier on the originator. At each intermediate scope, register its private carrier stack under the channel tag in the path. Use `AuthAclWrapper` to add transit admission to a native or passive carrier.
3. Bind and serve ingress on the scopes that should receive traffic. Publish the destination by name and retain the returned `PublishGuard` for as long as it should stay reachable.
4. Dial using `dial_stream` or `dial_datagram`, or bind a local socket and give it to an edge forwarder.

The [integration tests](crates/confluence-edge/tests/native.rs) show this wiring with native sockets, a three-hop path, and passive presence. For a passive stream relay, supply one already-connected stream per circuit. A registered datagram presence link can serve concurrent circuits.

The optional `AdminSocket::bind` creates an owner-only `0600` Unix socket at the supplied path. Send one newline-terminated command per connection. Commands include `publish-stream NAME ADDR`, `publish-datagram NAME MIN_MTU ADDR`, `unpublish NAME`, `revoke-peer HEX_PUBLIC_KEY`, and `list`. Replies begin with `OK` or `ERR`.

## Protocol decisions

- The receiver checks the scope identifier, MAC, and recently authenticated ephemerals before X25519. It checks clock skew after decrypting the timestamp in the documented v1 envelope.
- The hop and destination handshakes use Noise IK token order with a Confluence-specific BLAKE3 transcript and key schedule. The first end-to-end frame sent by the originator is an empty DATA confirmation.
- `SETUP_OK` carries the destination’s grant. The originator sends an initial in-band renewal to learn each intermediate hop’s lease. Forward hop controls count down to their target. Reverse controls carry the sender’s distance and count up.
- Datagram slot identifiers are retired on a link before their 8-bit generation would repeat. This prevents delayed packets from aliasing a reused label. Rate fields represent bytes per second.
