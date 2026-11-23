# Deploy Confluence with Rust

A deployment binary constructs a `NodePlan` with its scopes, authorizers, credentials, carriers, explicit routes, and endpoint handlers. Each example reads identity and token files at runtime and accepts socket addresses and peer public keys through environment variables.

## Direct Alice and Bob

The [direct topology](../examples/src/direct.rs) publishes two endpoints on Bob and forwards a local TCP port and UDP port on Alice. Here is the TCP portion of Bob's wiring, with a deployment-provided `Authorizer`.

```rust
let mut app = NodePlan::new();
app.scope("app", identity)?
    .authorizer(policy)
    .publish_stream("demo-tcp", Arc::new(TcpTarget(backend)))?;
app.listen_tcp(ingress);

let prepared = app.prepare()?;
prepared.start().await?.run_until(tokio::signal::ctrl_c()).await?;
```

`prepare()` validates scope identities, local static route references, and forwarding declarations without starting network services. The example binaries expose this step as `--check`. At startup, the runtime binds sockets, installs endpoints and transits, and starts managed tasks. A failed start closes the resources the runtime acquired. An application can supply any existing `Authorizer`, `CredentialProvider`, or `PathSource`. Static paths declared with `route()` receive preflight validation against the plan's carriers. A custom path source resolves paths at dial time.

From the workspace root, build the binaries and create a pair of identities and a shared endpoint token for the demo.

```sh
cargo build -p confluence-examples --bins
keys=$(mktemp -d)
export ALICE_PUB=$(target/debug/confluence-keygen "$keys/alice.key")
export BOB_PUB=$(target/debug/confluence-keygen "$keys/bob.key")
export ENDPOINT_TOKEN_FILE="$keys/endpoint.token"
(umask 077; openssl rand -hex 32 > "$ENDPOINT_TOKEN_FILE")
```

`confluence-keygen` writes the secret to a new file with mode `0600` on Unix and prints the public key to stdout.

Start an HTTP backend, then Bob, then Alice in the same shell. Wait for Bob to print its ingress addresses before starting Alice, and wait for Alice to print its forward addresses before calling the backend.

```sh
python3 -m http.server 8080 --bind 127.0.0.1 --directory examples &
backend_pid=$!

IDENTITY_FILE="$keys/bob.key" target/debug/direct-bob --check
IDENTITY_FILE="$keys/bob.key" target/debug/direct-bob &
bob_pid=$!

IDENTITY_FILE="$keys/alice.key" target/debug/direct-alice &
alice_pid=$!

curl --fail http://127.0.0.1:18080/
```

The UDP forward at `127.0.0.1:18081` reaches a UDP service on Bob at `127.0.0.1:8081`. Run a UDP backend there to exercise that plane.

Stop the direct deployment before reusing Alice's local forward ports for a relayed deployment.

```sh
kill -INT "$alice_pid" "$bob_pid"
wait "$alice_pid" "$bob_pid"
```

## Passive relay and multihop

The [relayed topology](../examples/src/relayed.rs) uses separate credentials for Alice's transit requests and Bob's presence registration. Bob connects out to the relay on both planes. In the multihop example, Alice first goes through a named transit with QoS limits and then through the same relay.

With the direct example's identities, endpoint token, and HTTP backend in place, create the relay and hop identities and their tokens.

```sh
export RELAY_PUB=$(target/debug/confluence-keygen "$keys/relay.key")
export HOP_PUB=$(target/debug/confluence-keygen "$keys/hop.key")
export RELAY_ACCESS_TOKEN_FILE="$keys/relay-access.token"
export RELAY_REG_TOKEN_FILE="$keys/relay-registration.token"
export HOP_TOKEN_FILE="$keys/hop.token"
(umask 077
 openssl rand -hex 32 > "$RELAY_ACCESS_TOKEN_FILE"
 openssl rand -hex 32 > "$RELAY_REG_TOKEN_FILE"
 openssl rand -hex 32 > "$HOP_TOKEN_FILE")
```

Start the relay and wait for it to print its ingress addresses. Start Bob and wait for it to print `Node started`, then start Alice. Use the same HTTP URL once Alice prints its forward address.

```sh
IDENTITY_FILE="$keys/relay.key" target/debug/passive-relay &
relay_pid=$!

IDENTITY_FILE="$keys/bob.key" target/debug/relay-bob &
bob_pid=$!

IDENTITY_FILE="$keys/alice.key" target/debug/relay-alice &
alice_pid=$!

curl --fail http://127.0.0.1:18080/
```

To insert the named hop, stop Alice, start the hop and wait for its ingress addresses, then start `multihop-alice`.

```sh
kill -INT "$alice_pid"
wait "$alice_pid"

IDENTITY_FILE="$keys/hop.key" target/debug/relay-hop &
hop_pid=$!

IDENTITY_FILE="$keys/alice.key" target/debug/multihop-alice &
alice_pid=$!

curl --fail http://127.0.0.1:18080/
```

Stop the remaining local processes when finished.

```sh
kill -INT "$alice_pid" "$hop_pid" "$bob_pid" "$relay_pid"
wait "$alice_pid" "$hop_pid" "$bob_pid" "$relay_pid"
kill "$backend_pid"
```

### Socket inputs

The binaries use loopback by default. Set the corresponding variable to an address including its port. Bind inputs and peer addresses are read by the process named in the table.

| Environment variables | Default TCP / UDP ports | Processes |
| --- | --- | --- |
| `BACKEND_TCP` / `BACKEND_UDP` | 8080 / 8081 | `direct-bob`, `relay-bob` |
| `BOB_TCP` / `BOB_UDP` | 14101 / 14100 | `direct-bob`, `direct-alice` |
| `RELAY_TCP` / `RELAY_UDP` | 16201 / 16200 | `passive-relay`, `relay-alice`, `relay-bob`, `relay-hop` |
| `HOP_TCP` / `HOP_UDP` | 16101 / 16100 | `relay-hop`, `multihop-alice` |
| `FORWARD_TCP` / `FORWARD_UDP` | 18080 / 18081 | `direct-alice`, `relay-alice`, `multihop-alice` |

Set `RUST_LOG=debug` for verbose tracing. Applications can also opt into a local owner-only Unix admin socket with `scope.admin_socket(path)`.

## Moving a TOML deployment to Rust

| Former topology entries | Rust wiring |
| --- | --- |
| Scopes, policy, credentials | `scope()`, `authorizer()`, `credentials()` |
| First-hop carriers and paths | `stream_carrier()`, `datagram_carrier()`, `route()` or `path_source()` |
| Shared TCP and UDP listeners | `listen_tcp()`, `listen_udp()` |
| Named transits and passive relay | `publish_stream_transit()`, `publish_datagram_transit()`, `publish_relay()` |
| NAT-side relay registration | `register_relay_tcp()`, `register_relay_udp()` |
| Endpoints and local port bindings | `publish_stream()`, `publish_datagram()`, `forward_tcp()`, `forward_udp()` |

Compile the deployment with Cargo. Use `prepare()` for preflight checks, `start().await` to bind and start, and `run_until()` or `shutdown().await` to own the service lifetime.
