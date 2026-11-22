# Wire Protocol Specification

This document specifies the Milestone 1 wire framing and cryptographic handshakes implemented in `confluence-core`.

---

## 1. Cryptographic Primitives & Constants

| Parameter | Specification |
| :--- | :--- |
| **Handshake Pattern** | `Noise_IK_25519_ChaChaPoly_BLAKE2s` (Noise Rev 34) |
| **Prologue** | `b"confluence-v1"` |
| **Static Identity (`PeerId`)** | 32-byte X25519 public key (low-order all-zero DH outputs rejected in constant time) |
| **Demux Tag (`TargetTag`)** | `BLAKE2s256(static_pubkey)[0..8]` (8 bytes) |
| **0-RTT Anti-Replay** | 12-byte big-endian `TAI64N` timestamp (`[secs: 8B BE][nanos: 4B BE]`) inside encrypted `Noise_IK` Message 1 |
| **Pre-Auth Fast Filter (`MAC1`)** | `HMAC-BLAKE2s256(key = BLAKE2s256("conf-mac1----" \|\| responder_pk), msg)[0..16]` |
| **Flood Cookie (`MAC2`)** | `HMAC-BLAKE2s256(key = cookie(source_addr), msg \|\| mac1)[0..16]` |
| **Cookie Challenge** | `[xnonce: 24B][XChaCha20Poly1305(key = BLAKE2s256("conf-cookie--" \|\| responder_pk), aad = mac1, pt = cookie_16B)]` (56 bytes) |

---

## 2. Sealed Handshake Envelope

Every `Noise_IK` Message 1 (both per-hop `HopHandshakeReq` and final `E2eHandshakeReq`) is wrapped in a pre-authentication envelope:

```text
+-------------------+------------------------+------------+------------+
| inner_len (2B BE) | noise_ik_msg1 (N B)    | mac1 (16B) | mac2 (16B) |
+-------------------+------------------------+------------+------------+
```

1. **Pre-DH `MAC1` Check:** Verifiers check `mac1` in constant time *before* performing any X25519 scalar multiplication. Packets with invalid `mac1` are silently dropped.
2. **Stateless `MAC2` Flood Mode:** When `under_load == true`, verifiers require a valid `mac2` computed over `source_addr` using a rotating 120-second secret before performing X25519 DH, issuing a stateless 56-byte `CookieChallenge` if absent.
3. **`Noise_IK` Message 1 (`96 + payload_len` bytes):**
   `[ ephemeral_pub: 32B ][ encrypted_initiator_static: 48B ][ encrypted_inner_payload: len + 16B ]`
   Initiator static `PeerId`, `TAI64N` timestamp, target endpoint/address, and optional `OpaqueCredential` (`<= 256B`) are all encrypted against passive observers.

### Inner Handshake Payloads

- **`E2eHandshakeReq` (`A -> B`):**
  ```text
  [ tai64n: 12B ][ plane: 1B ][ ep_len: 1B ][ endpoint_utf8 ][ has_cred: 1B ][ cred_len: 2B BE? ][ cred? ]
  ```
- **`HopHandshakeReq` (`A -> Hop / Relay`):**
  ```text
  [ tai64n: 12B ][ plane: 1B ][ addr_len: 2B BE ][ next_addr_utf8 ][ has_cred: 1B ][ cred_len: 2B BE? ][ cred? ]
  ```
- **`E2eHandshakeResp` (`B -> A` inside `Noise_IK` Message 2):**
  ```text
  [ granted_ttl_millis: u64 BE (8B) ]
  ```

---

## 3. Datagram Plane Wire Protocol

Every Confluence datagram begins with a 4-byte big-endian `HopLabel`:

- `HopLabel == 0` (`0x00000000`): Control-plane packet.
- `HopLabel != 0` (`1..=u32::MAX`): Steady-state data-plane packet.

### 3.1 Single-Pass Datagram `ChainSetup` (`HopLabel(0)`)

```text
+-------------------+--------------------+-------------------+----------------------------+
| hop_label = 0 (4B)| ctrl_type=0x10 (1B)| circuit_id (16B)  | sender_return_label (4B BE)|
+-------------------+--------------------+-------------------+----------------------------+
| target_tag (8B)   | seg_len (2B BE)    | seg_payload (...) | remaining_tail (...)       |
+-------------------+--------------------+-------------------+----------------------------+
```

- `remaining_tail` is a packed sequence of `[ target_tag: 8B ][ seg_len: 2B BE ][ seg_payload ]` segments.
- If `remaining_tail` is non-empty, `target_tag` dispatches to a mounted `DatagramForwardChannel` on the intermediate hop, which authenticates `A` in 0-RTT and forwards the remaining tail downstream.
- If `remaining_tail` is empty, `target_tag` dispatches to the destination `TrustScope` on `B`, which returns `ChainSetupResp (0x11)` carrying `[ circuit_id: 16B ][ responder_label: 4B BE ][ msg2_len: 2B BE ][ e2e_noise_msg2 ]`.
- Other `HopLabel(0)` control types:
  - `0x12`: `ChainSetupChallenge` (propagates `CookieChallenge` back to `A`)
  - `0x13`: `ChainSetupReject` (propagates explicit setup denial back to `A`)
  - `0x20` / `0x21`: `ChannelControl` / `ChannelControlResp` (blindly dispatched by `target_tag`, used e.g. for passive relay slot registration/keepalive)
  - `0x30` / `0x31`: `CircuitRenew` / `CircuitRenewResp` (renews an intermediate hop's `DatagramForwardHandle` in place)

### 3.2 Flat Steady-State Datagram Data Frame (**29 Bytes** Constant Overhead)

```text
+-------------------+-------------------+-----------------------------------------+----------------+
| hop_label (4B BE) | nonce (8B BE)     | ChaCha20(msg_type: 1B || payload)       | poly1305 (16B) |
+-------------------+-------------------+-----------------------------------------+----------------+
```

- Total wire overhead: `4 + 8 + 1 + 16 = 29 bytes` regardless of whether the path is Direct, 1-hop Relay, or N-hop Transit.
- Intermediate hops overwrite only `hop_label (4B)` using their flat `DashMap<u32, LabelSwitchEntry>` table; ciphertext `[4..]` is never unwrapped or re-encrypted.

---

## 4. Stream Plane Wire Protocol

### 4.1 Single-Pass Pipelined Stream Setup

Originator `A` writes all hop segments plus the final E2E segment in a single burst onto the opened stream:

```text
[ Seg_1 (mode=0x02 ForwardHop, tag_1, len, env_1) ]
[ Seg_2 (mode=0x02 ForwardHop, tag_2, len, env_2) ]
...
[ Final (mode=0x01 FinalE2e,   tag_B, len, env_B) ]
```

1. Each intermediate hop reads **only** its leading 11-byte header + `seg_payload`, authenticates `A` via its `StreamForwardChannel`, and immediately splices remaining bytes bidirectionally (`copy_bidirectional`) with **zero** intermediate response bytes on success.
2. Destination `B` reads `FinalE2e`, authenticates `A` and evaluates `OpenEndpoint`, and writes `StreamSetupReply`:
   `[ status: 1B (0x01 Accept | 0x02 Challenge | 0x03 Reject) ][ target_tag: 8B ][ len: 2B BE ][ payload ]`
   which flows untouched back through all intermediate splices to `A` in **1 RTT total**.
3. `mode = 0x03 ChannelControl` dispatches control streams (such as passive relay idle stream parking) directly to `StreamForwardChannel::handle_control_stream`.

### 4.2 Steady-State E2E Stream Record Framing (`A <-> B` Only)

```text
+--------------------+------------------------------------------+----------------+
| cipher_len (2B BE) | ChaCha20(msg_type: 1B || chunk <= 16KiB) | poly1305 (16B) |
+--------------------+------------------------------------------+----------------+
```

- Uses implicit sequential 64-bit nonces (`0, 1, 2, ...`) in each direction.
- Inner `msg_type` values (shared across both planes):
  - `0x01 = Data`: Application payload bytes.
  - `0x02 = InBandRenewReq`: Live credential refresh request (`[req_id: 8B][cred?]`).
  - `0x03 = InBandRenewResp`: Live grant extension response (`[req_id: 8B][status: 1B][ttl_or_reason]`).
  - `0x04 = Close`: AEAD-authenticated graceful EOF (distinguishing clean stream close from unauthenticated link truncation).
