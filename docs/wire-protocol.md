# Wire Protocol Reference (v1)

All multi-byte integers are unsigned big-endian. Cryptographic suite: **X25519 + ChaCha20-Poly1305 / XChaCha20-Poly1305 + BLAKE3**.

---

## 1. Core Frame Type Registry (`ver_type`, Byte 0)

| Byte | Name | Direction / Plane | Purpose |
| --- | --- | --- | --- |
| `0x11` | `SETUP_FWD` | Forward (both planes) | Single-pass pipelined 1-RTT chain setup (shrinks per hop) |
| `0x12` | `SETUP_OK` | Reverse (both planes) | `70 B` base E2E reply (`12 B` header + `58 B` Noise reply) + `24 B` encrypted lease trailer per intermediate hop |
| `0x13` | `SETUP_ERR` | Reverse (both planes) | `36 B` authenticated rejection encrypted under `K_hop_i` |
| `0x14` | `SETUP_COOKIE` | Reverse (both planes) | `64 B` stateless rotating `MAC2` flood-cookie challenge (`hop_dist`, `target_cid`, `56 B` XChaCha20-Poly1305 cookie bound to `mac1` AAD) |
| `0x20` | `DG_DATA` | Both (Datagram) | `5 B` hop header (`0x20 \| cid:4B`) + `25 B` E2E AEAD overhead (**30 B** total) |
| `0x21`–`0x24` | `DG_RENEW`, `DG_RENEW_OK`, `DG_CLOSE`, `DG_MTU_HINT` | Both (Datagram) | `6 B` hop control header (`kind \| ttl \| cid:4B`) |
| `0x30` | `ST_DATA` | Both (Stream) | `4 B` hop chunk header (`0x30 \| 0 \| len:2B`, max `16384 B`) |
| `0x31`–`0x33` | `ST_RENEW`, `ST_RENEW_OK`, `ST_CLOSE` | Both (Stream) | `4 B` interleaved hop control header (`kind \| ttl \| len:2B`) |

---

## 2. Single-Pass Setup, Named Targets & `MAC2` Flood Cookies

Each segment prefix byte `mode` encodes:
* Low nibble (`mode & 0x0f`): `1` = Named Transit Hop (`8 B` prefix: `mode | plane | min_mtu:2B | seg_len:2B | tail_len:2B`), `2` = Named Destination Endpoint (`6 B` prefix: `mode | plane | min_mtu:2B | seg_len:2B`).
* Bit `0x10` (`MODE_MAC2`): when set, the segment carries an extra `16 B` `mac2` tag appended immediately after `mac1`.

Inside each hop or destination `Noise_IK` encrypted payload (starting with `ScopeKid(8B)` so multi-scope `Node`s route in $O(1)$ without trial decryption):
```text
[ ts_ms: 8B | target_len: 1B | target_utf8 (1..=255B) | cred_len: 2B | credential (0..=512B) ]
```
The target is a UTF-8 **Endpoint** name (`mode = 2`) or **Transit** name (`mode = 1`). No raw downstream IPs or channel tags appear on the wire.

### Per-Hop `SETUP_OK` Lease Trailers
* Destination `B` emits `70 B` `SETUP_OK` (`12 B` `OkHeader` + `58 B` `Noise_IK` reply containing `mtu:2B | ttl_ms:8B`).
* Each intermediate hop `H_i` increments `hop_acks`, clamps `reverse_mtu`, and appends a `24 B` ChaCha20-Poly1305 trailer (`8 B ttl_ms + 16 B tag`, encrypted under `K_hop_i`) so Originator `A` learns every hop's exact lease TTL in the initial 1-RTT flight with zero `t = 0` renewal burst.

### Rotating `MAC2` Flood Cookies (`under_load`)
When `under_load == false`, `MODE_MAC2` is unset (`0` extra wire bytes). When `under_load == true`, the responder verifies `scope_kid` + `mac1` stack-only, checks `mac2` against a rotating per-source cookie (`BLAKE3_keyed(secret, source_tag)[..16]`), and if absent/stale returns `SETUP_COOKIE (0x14)` without invoking X25519. Intermediate hops propagate `SETUP_COOKIE` upstream incrementing `hop_dist`; Originator `A` unseals the challenge using `sent_mac1` as AAD and retries automatically.

### Route Integrity (Tail AAD)
Every hop and destination `Noise_IK` handshake hashes `BLAKE3(Dispatch_Prefix || Remaining_Tail)` as Associated Data (AAD). Any upstream modification to downstream hops or destination framing fails AEAD verification immediately.

### Credential Budget
Opaque credentials up to **`512 B`** (`CREDENTIAL_MAX`) are permitted in setup and live `RENEW` frames (subject to carrier MTU on the Datagram Plane).

---

## 3. End-to-End Records & Lease Renewal

* **Lease payload (both `ST_RENEW_OK` and `DG_RENEW_OK`):** `8 B` (`ttl_ms: u64`).
* **Datagram E2E** (inside `DG_DATA`): `seq_no (8B) | enc(type:1B || payload) | tag (16B)` with 64-packet sliding anti-replay window. Types: `0x01 DATA`, `0x02 DG_RENEW`, `0x03 DG_RENEW_OK`, `0x04 DG_CLOSE`, `0x05 MTU_PROBE`, `0x06 MTU_PROBE_ACK`. Bad AEAD tags drop silently.
* **Stream E2E** (inside `ST_DATA`): `len (2B, AAD) | enc(type:1B || body) | tag (16B)` with implicit monotonic `u64` nonce per direction. Types:
  * `0x00 OPEN_OK`, `0x01 TARGET_REFUSED`, `0x02 TARGET_UNREACHABLE`, `0x03 TARGET_BUSY`, `0x04 TARGET_DENIED`
  * `0x10 ST_DATA`, `0x11 ST_FIN`, `0x12 ST_RENEW`, `0x13 ST_RENEW_OK`

---

## 4. Out-of-Core Transport Mux (`confluence-relay`, non-Core)

Passive relay presence registration lives completely outside `confluence-core` using disjoint leading magic bytes on shared TCP/UDP listeners (`RelayMux` / `UdpIngress::serve_custom`):

* `0x52` (`RELAY_REG_REQ`): `[ 0x52 | 0x00 | payload_len:2B | req_id:4B | noise_ik_segment ]`
* `0x53` (`RELAY_REG_RESP`): `[ 0x53 | status:1B | payload_len:2B | req_id:4B | noise_ik_reply(58B) ]`
* `0x57` (`RELAY_WAKE_BYTE`): single wake byte written onto a parked TCP presence stream when an authorized originator attaches.
