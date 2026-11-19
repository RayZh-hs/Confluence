# Architecture

To fulfill the goals outlined in the [Statement of Purpose](purpose.md), Confluence decouples identity, machine, and network membership. Instead of binding an entire host to a single centralized Tailnet, Confluence operates around lightweight, user-level **Instances**, federated **Signaling**, and capability-based **Groups**.

## Core Concepts

- **Node (Instance):** A Confluence process running in user space (or optionally as a system service). Multiple instances can run on the same physical machine under different users, each holding its own cryptographic keypair (`NodeKey`).
- **Group:** A virtual overlay network or sharing scope. A Node can join multiple Groups simultaneously without merging its broader network state or surrendering administrative control to a central owner.
- **Endpoint (`addrport`):** The unit of exposure within a Group. Rather than exposing an entire machine by default, a Node publishes specific local `addrport` targets (or an optional virtual TUN subnet) to a Group, and binds remote peers' shared endpoints to local loopback ports or virtual addresses.
- **Rendezvous & Relay (DERP-like):** Lightweight, federated coordination servers that handle peer discovery, NAT traversal signaling, and encrypted fallback relaying when direct connections fail.

## Decoupled Control Plane

Traditional mesh VPNs rely on a single coordination server that owns the network topology and enforces global ACLs. Confluence splits this into two layers:

1. **Federated Discovery:** Nodes register their public key and reachable endpoints with one or more Rendezvous servers (identified as `node@server`). Organizations or individuals can self-host Rendezvous servers or use public ones, similar to email or Matrix federation.
2. **Peer-Owned Groups:** A Group is defined by a cryptographic genesis token and managed by its creator(s) or via distributed membership certificates. Joining a Group grants a Node visibility into the peer list and the specific `addrport` services published to that Group—nothing more. Each participant retains sole authority over its own Node and what it chooses to expose.

## Data Plane & Routing

Confluence prioritizes lowest-latency paths between peers while working entirely in user space by default:

- **End-to-End Encryption:** All peer-to-peer traffic is authenticated and encrypted using WireGuard/Noise-based sessions keyed by each Node's `NodeKey`. Relay nodes only forward ciphertext.
- **Multi-Path Route Selection:** When connecting to a peer's shared `addrport`, Confluence probes available paths in parallel—direct LAN, STUN/ICE UDP hole-punching, and known Relay nodes (including peer-contributed relays within the Group)—and dynamically routes packets over the shortest-delaying path.
- **User-Space Proxying & TUN Modes:** By default, Confluence operates without root privileges by mapping remote Group endpoints to local ports (similar to `ssh -L` or FRP, but backed by a P2P mesh). When full L3 transparency is desired, an instance can optionally attach a virtual TUN interface.

## Lifecycle of a Group Session

1. **Creation:** A user creates a Group on their local instance, generating a signed invite token scoped with permissions (e.g., allowed ports, expiration, relay rights).
2. **Joining:** Peers import the invite token. Their instances contact the creator's Rendezvous server, verify membership signatures, and exchange endpoint metadata.
3. **Publishing & Binding:** The host publishes a local service (e.g., `127.0.0.1:25565` as `minecraft`), and peers bind it locally or access it via its Group address.
4. **Revocation:** The Group creator or the publishing Node can revoke a member's certificate or unpublish an `addrport` at any time, immediately terminating the corresponding WireGuard/Noise session.

For practical setup and workflows, refer to the [User Guide](user-guide.md). For daemon control, Group management, and wire specifications, refer to the [API Reference](api.md).
