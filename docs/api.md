# API Reference

Confluence exposes a local control API (accessible via CLI or Unix socket/loopback HTTP) for managing the user-space Node instance, alongside federated wire protocols for Rendezvous signaling and peer-to-peer data transport.

## Local Daemon Control

Each Confluence instance runs independently under a user account and is controlled via its local socket.

### Instance & Identity

- `POST /v1/node/init` — Generate a new `NodeKey` keypair and initialize local instance state.
- `GET /v1/node/status` — Return Node identity (`PublicKey`, registered `node@server` addresses), active TUN state, and connected Rendezvous/Relay servers.
- `PUT /v1/node/rendezvous` — Configure or update the list of federated Rendezvous servers used for discovery and NAT traversal.
- `PUT /v1/node/tun` — Enable or disable the optional virtual L3 TUN interface for transparent subnet routing.

## Group Management

Groups define isolated sharing scopes. Membership and permissions are enforced via cryptographic certificates signed by the Group creator(s).

- `POST /v1/groups` — Create a new Group and generate its genesis parameters.
  - **Body:** `{ "name": "string", "enable_peer_relay": true }`
- `POST /v1/groups/{group_id}/invites` — Issue a signed invite token with scoped capabilities.
  - **Parameters:** `ttl` (expiration), `allowed_ports` (publish/bind restrictions), `can_relay` (permission to use or act as a Group relay).
- `POST /v1/groups/join` — Join an existing Group using an invite token.
  - **Body:** `{ "token": "conf_inv_..." }`
- `GET /v1/groups` — List all joined Groups, active peers, and discovered routes.
- `DELETE /v1/groups/{group_id}` — Leave a Group and tear down all associated peer sessions and bindings.
- `DELETE /v1/groups/{group_id}/peers/{peer_id}` — Revoke a peer's membership certificate (creator only) and immediately terminate its active sessions.

## Endpoint Publishing & Binding

Instead of exposing an entire host, Nodes selectively publish local `addrport` targets to a Group and bind remote services locally.

### Publishing Local Services

- `POST /v1/groups/{group_id}/publish` — Expose a local `addrport` to members of the Group.
  - **Body:**
    ```json
    {
      "name": "minecraft",
      "protocol": "tcp+udp",
      "local_addr": "127.0.0.1:25565",
      "allowed_peers": ["*"]
    }
    ```
- `DELETE /v1/groups/{group_id}/publish/{name}` — Unpublish a service and close active peer streams to that endpoint.

### Binding Remote Services

- `POST /v1/groups/{group_id}/bind` — Map a remote peer's published endpoint to a local loopback `addrport`.
  - **Body:**
    ```json
    {
      "peer": "alice@rv.example.org",
      "service": "minecraft",
      "listen_addr": "127.0.0.1:25565"
    }
    ```
- `GET /v1/groups/{group_id}/routes` — Inspect active path selection (direct LAN, STUN/ICE hole-punched UDP, or Relay fallback) and round-trip latency per peer.
- `DELETE /v1/groups/{group_id}/bind/{binding_id}` — Remove a local port binding.

## Wire Specifications

### Identity & Invite Tokens

- **Node Identifier:** `<base58(NodePublicKey)>@<rendezvous_domain>` (or human-readable alias resolved via the Rendezvous server).
- **Invite Token (`conf_inv_*`):** Base64url-encoded CBOR structure containing:
  - `group_id`: 32-byte Group public identifier.
  - `rendezvous`: Bootstrap Rendezvous server endpoint(s).
  - `capabilities`: Bitmask of permissions (`PUBLISH`, `BIND`, `RELAY`, `ADMIN`).
  - `exp`: Unix timestamp expiration.
  - `sig`: Ed25519 signature by the Group authority key.

### Rendezvous & Relay Protocol

1. **Registration:** Nodes establish a persistent TLS/WebSocket or QUIC control stream to their Rendezvous server and authenticate possession of `NodeKey`.
2. **Signaling:** To connect across a Group, Nodes exchange encrypted candidate endpoints (LAN IPs, STUN-reflexive `addrport`s, and Relay descriptors) accompanied by their Group membership certificate.
3. **Path Probing & Data Plane:** Peers perform parallel UDP hole-punching and latency probes inside WireGuard/Noise (`Noise_IK`) handshakes. Traffic dynamically migrates to the lowest-latency verified path, falling back to end-to-end encrypted Relay forwarding when direct UDP is blocked.
