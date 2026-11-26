//! Normative Confluence v1 wire constants and default behavioral envelopes.
//!
//! Wire and framing constants in this module are normative and MUST NOT change
//! within protocol version 1.

use core::time::Duration;

// ---------------------------------------------------------------------------
// Normative Wire & Protocol Constants (Spec §3.1)
// ---------------------------------------------------------------------------

/// Baseline IPv6-safe UDP payload MTU discovery reference.
pub const DATAGRAM_MTU: u16 = 1232;

/// Minimum effective wire MTU for the Datagram Plane (`Plane::Datagram.minimum_mtu()`).
pub const DATAGRAM_MIN_MTU: u16 = 1152;

/// Minimum wire MTU for the Stream Plane (`ST_OVERHEAD + 1`).
pub const STREAM_MIN_MTU: u16 = 20;

/// Maximum `ST_DATA` hop chunk payload size and maximum Stream `SETUP_FWD`/`SETUP_OK` frame size.
pub const STREAM_CHUNK: usize = 16_384;

/// Total Datagram end-to-end wire overhead (`5` hop + `8` seq + `1` type + `16` tag).
pub const DG_OVERHEAD: usize = 30;

/// Stream end-to-end record overhead (`2` len + `1` type + `16` tag).
pub const ST_OVERHEAD: usize = 19;

/// Maximum Stream end-to-end record body (`STREAM_CHUNK - ST_OVERHEAD`).
pub const ST_MAX_BODY: usize = STREAM_CHUNK - ST_OVERHEAD;

/// Maximum opaque credential length in setup and `RENEW` frames.
pub const CREDENTIAL_MAX: usize = 128;

/// Minimum UTF-8 byte length for endpoint, transit, prefix, and carrier names.
pub const NAME_MIN_LEN: usize = 1;

/// Maximum UTF-8 byte length for endpoint, transit, prefix, and carrier names.
pub const NAME_MAX_LEN: usize = 255;

/// Maximum number of intermediate hops in an [`crate::path::ExplicitPath`].
pub const MAX_HOPS: usize = 255;

/// Base Noise_IK segment overhead (`8` kid + `32` e + `48` enc_s + `16` pt_tag + `16` mac1).
pub const SEGMENT_OVERHEAD: usize = 120;

/// Length of `mac1` and `mac2` authentication tags in bytes.
pub const MAC_LEN: usize = 16;

/// Length of a stateless flood cookie in bytes.
pub const COOKIE_LEN: usize = 16;

/// Length of an encrypted flood-cookie challenge (`24` XNonce + `16` cookie + `16` tag).
pub const CHALLENGE_LEN: usize = 56;

/// Length of a Noise_IK Message 2 reply (`32` eph + `10` ack + `16` tag).
pub const REPLY_LEN: usize = 58;

/// `SETUP_FWD` outer header size in bytes.
pub const FWD_HEADER: usize = 8;

/// Base `SETUP_OK` frame size (`12` header + `58` Noise reply).
pub const OK_SIZE: usize = 70;

/// Encrypted hop trailer size appended to `SETUP_OK` (`2` MTU + `8` TTL + `16` tag).
pub const HOP_ACK_SIZE: usize = 26;

/// `SETUP_ERR` total frame size (`8` header + `28` encrypted error body).
pub const ERR_SIZE: usize = 36;

/// `SETUP_ERR` encrypted body size (`8` nonce + `4` pt + `16` tag).
pub const ERR_BODY_SIZE: usize = 28;

/// `SETUP_COOKIE` total frame size (`8` header + `56` challenge).
pub const COOKIE_SIZE: usize = 64;

/// `SETUP_FRAG` header size and exact `SETUP_FRAG_ACK` size in bytes.
pub const FRAG_HEADER: usize = 16;

/// Minimum fragment count for a fragmented datagram `SETUP_FWD`.
pub const MIN_FRAGS: usize = 2;

/// Maximum fragment count for a fragmented datagram `SETUP_FWD`.
pub const MAX_FRAGS: usize = 8;

/// Maximum datagram leading encrypted segment (`120 + 11 + 255 + 128 + 16`).
pub const MAX_SEGMENT: usize = 530;

/// Maximum stream leading encrypted segment accepted in the stack precheck buffer.
pub const MAX_SETUP_SEGMENT: usize = 2048;

/// Maximum reassembled datagram setup flight (`8 + 8 + 2 * 65535`).
pub const MAX_SETUP: usize = 131_086;

/// Minimum `ControlCipher` wire body length (`8` seq + `0` pt + `16` tag).
pub const MIN_CONTROL: usize = 24;

/// Maximum `ControlCipher` wire body length (`8` seq + `8` renewal_id + `128` cred + `16` tag).
pub const MAX_CONTROL: usize = 160;

/// Minimum valid wire lease TTL in milliseconds (`0` is malformed).
pub const MIN_WIRE_LEASE_TTL_MS: u64 = 1;

/// Hard wire ceiling for lease TTLs (`24 h` in milliseconds).
pub const MAX_WIRE_LEASE_TTL_MS: u64 = 86_400_000;

/// Hard wire ceiling for lease TTLs (`24 h`).
pub const MAX_WIRE_LEASE_TTL: Duration = Duration::from_secs(86_400);

/// Accepted wall-clock setup timestamp skew (`±30_000 ms`, inclusive).
pub const SETUP_FRESHNESS_WINDOW_MS: u64 = 30_000;

/// Sliding anti-replay bitmap width for `ControlCipher` and `DatagramRx`.
pub const REPLAY_WINDOW_PACKETS: u64 = 64;

/// Reserved headroom in [`crate::PacketBuf`] for zero-copy in-place framing.
pub const HEADROOM_BYTES: usize = 64;

/// Reserved tailroom in [`crate::PacketBuf`] (fits up to four stacked 16-byte AEAD tags).
pub const TAILROOM_BYTES: usize = 64;

/// Datagram hop `DG_DATA` outer header size (`1` opcode + `4` CID).
pub const DG_HOP_DATA_HEADER: usize = 5;

/// Datagram hop control outer header size (`1` opcode + `1` ttl/dist + `4` CID).
pub const DG_HOP_CTRL_HEADER: usize = 6;

/// Stream hop outer header size (`1` opcode + `1` ttl/dist + `2` len).
pub const ST_HOP_HEADER: usize = 4;

/// Minimum Datagram E2E record length after stripping the 5-byte hop header (`8` seq + `1` type + `16` tag).
pub const DG_E2E_MIN_LEN: usize = 25;

/// Minimum decrypted setup plaintext length (`8` ts + `1` name_len + `1` name + `2` cred_len).
pub const SETUP_PLAINTEXT_MIN: usize = 12;

/// Maximum decrypted setup plaintext length (`8` ts + `1` name_len + `255` name + `2` cred_len + `128` cred).
pub const SETUP_PLAINTEXT_MAX: usize = 394;

// ---------------------------------------------------------------------------
// Behavioral Timing, Retry & Resource Envelope Defaults (Spec §3.2)
// ---------------------------------------------------------------------------

/// End-to-end setup, confirmation, handler open, fragment reassembly, and cookie-retry hold deadline.
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(3);

/// Best-effort timeout for transmitting terminal close/error/cookie frames.
pub const CLOSE_SEND_TIMEOUT: Duration = Duration::from_millis(50);

/// Stream frame write retry budget on retryable carrier errors.
pub const STREAM_WRITE_RETRY_BUDGET: Duration = Duration::from_secs(3);

/// Initial backoff on retryable stream writes.
pub const STREAM_WRITE_BACKOFF_INITIAL: Duration = Duration::from_millis(10);

/// Maximum backoff on retryable stream writes.
pub const STREAM_WRITE_BACKOFF_CAP: Duration = Duration::from_millis(200);

/// Default flood-cookie secret rotation period.
pub const COOKIE_ROTATION_INTERVAL: Duration = Duration::from_secs(120);

/// Minimum allowed flood-cookie secret rotation period.
pub const COOKIE_ROTATION_MIN: Duration = Duration::from_secs(1);

/// Continuous low-load duration required before clearing automatic `under_load`.
pub const LOAD_HYSTERESIS_DURATION: Duration = Duration::from_secs(5);

/// Monotonic lifetime for `SetupReplay` entries in seconds (strictly covers `±30 s`).
pub const SETUP_REPLAY_TTL_SECS: u64 = 61;

/// Number of hash buckets in `SetupReplay` (must be a power of two).
pub const SETUP_REPLAY_BUCKETS: usize = 4096;

/// Set-associativity (ways per bucket) in `SetupReplay`.
pub const SETUP_REPLAY_WAYS: usize = 4;

/// CID quarantine duration when an 8-bit slot generation wraps from `255` back to `1`.
pub const SLAB_QUARANTINE_DURATION: Duration = Duration::from_secs(60);

/// Per-link active circuit limit in `SlabTable`.
pub const SLAB_MAX_ACTIVE: usize = 4096;

/// Per-circuit datagram mailbox capacity in packets.
pub const DATAGRAM_MAILBOX_CAP: usize = 32;

/// Per-session datagram application TX/RX queue capacity in packets.
pub const DATAGRAM_SESSION_QUEUE_CAP: usize = 16;

/// Maximum concurrent incomplete fragmented setups per `DatagramPort`.
pub const FRAG_MAX_ACTIVE: usize = 16;

/// Maximum cached completed fragmented setup receipts per `DatagramPort`.
pub const FRAG_MAX_COMPLETED: usize = 32;

/// Datagram fragment burst retransmission delays.
pub const FRAG_RETRY_DELAYS: [Duration; 3] = [
    Duration::from_millis(150),
    Duration::from_millis(300),
    Duration::from_millis(600),
];

/// Reliable MTU report retry schedule.
pub const MTU_RETRY_DELAYS: [Duration; 5] = [
    Duration::from_millis(150),
    Duration::from_millis(300),
    Duration::from_millis(600),
    Duration::from_millis(1200),
    Duration::from_millis(2400),
];

/// Minimum interval between unsolicited MTU reassertions.
pub const MTU_REASSERT_INTERVAL: Duration = Duration::from_millis(200);

/// Transit floor-violation drain window so Origin can deliver `e2e::DG_CLOSE`.
pub const MTU_REPORT_TIMEOUT: Duration = Duration::from_secs(5);

/// Lower inclusive percentage of lease TTL for renewal jitter.
pub const RENEWAL_JITTER_MIN_PCT: u64 = 70;

/// Upper inclusive percentage of lease TTL for renewal jitter.
pub const RENEWAL_JITTER_MAX_PCT: u64 = 80;

/// Base backoff for Stream lease renewal retries.
pub const RENEWAL_STREAM_BACKOFF_BASE: Duration = Duration::from_millis(1000);

/// Base backoff for Datagram lease renewal retries.
pub const RENEWAL_DATAGRAM_BACKOFF_BASE: Duration = Duration::from_millis(100);

/// Ceiling for lease renewal retry backoff.
pub const RENEWAL_BACKOFF_CAP: Duration = Duration::from_millis(5000);

/// Minimum delay between lease renewal retries.
pub const RENEWAL_BACKOFF_MIN: Duration = Duration::from_millis(10);

/// Default maximum concurrent pending setups per remote peer.
pub const DEFAULT_PER_PEER_PENDING: usize = 8;

/// Default maximum concurrent `Authorizer::authorize` evaluations.
pub const DEFAULT_AUTH_CONCURRENCY: usize = 32;

/// Default hard timeout for authorization and credential calls.
pub const DEFAULT_AUTH_TIMEOUT: Duration = Duration::from_millis(500);

/// Minimum configurable `auth_timeout`.
pub const MIN_AUTH_TIMEOUT: Duration = Duration::from_millis(10);

/// Maximum configurable `auth_timeout`.
pub const MAX_AUTH_TIMEOUT: Duration = Duration::from_secs(5);

/// Default maximum accepted lease TTL (`1 h`).
pub const DEFAULT_MAX_LEASE_TTL: Duration = Duration::from_secs(3600);

/// Minimum configurable `max_lease_ttl`.
pub const MIN_MAX_LEASE_TTL: Duration = Duration::from_secs(1);

/// Default maximum concurrent pending setups per scope.
pub const DEFAULT_SCOPE_MAX_PENDING: usize = 256;

/// Default maximum concurrent active sessions/circuits per scope.
pub const DEFAULT_SCOPE_MAX_SESSIONS: usize = 4096;

/// Default maximum attached datagram ports per scope or node.
pub const DEFAULT_MAX_DATAGRAM_PORTS: usize = 4096;

/// Default maximum concurrent pending setups per `Node`.
pub const DEFAULT_NODE_MAX_PENDING: usize = 512;

/// Hard cap on fine-grained revocation epoch entries before global-epoch fallback.
pub const MAX_EPOCHS: usize = 16_384;

/// Maximum ciphertext quantum per `TrafficGate` charge in Stream transit splicing.
pub const STREAM_SPLICE_QUANTUM: usize = 4096;
