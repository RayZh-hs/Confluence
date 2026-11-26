//! Lock-free atomic telemetry counters and immutable snapshot structs (Spec §9.3).

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::error::FailureClass;
use crate::types::{Plane, Role};

/// Power-of-two warning throttle helper.
///
/// Returns `true` on occurrences `1, 2, 4, 8, 16, ...` so repeated saturation or timeout
/// conditions surface immediately while keeping warning logs bounded.
#[inline]
#[must_use]
pub const fn should_warn_pow2(count: u64) -> bool {
    count > 0 && count.is_power_of_two()
}

/// Snapshot of session and setup counters for a single `(Plane, Role)` pair.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RoleStats {
    /// Currently active sessions or circuits in this role.
    pub active_sessions: usize,
    /// Total setup attempts started in this role.
    pub setup_attempts: u64,
    /// Total setups that reached established state in this role.
    pub setup_established: u64,
    /// Total setup failures in this role.
    pub setup_failures: u64,
}

/// Snapshot of plane-specific session and data-plane traffic counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PlaneStats {
    /// Originator-role session stats.
    pub origin: RoleStats,
    /// Destination-role session stats.
    pub destination: RoleStats,
    /// Intermediate transit-role circuit stats.
    pub transit: RoleStats,
    /// Total application/forwarded payload bytes received.
    pub bytes_received: u64,
    /// Total application/forwarded payload bytes sent.
    pub bytes_sent: u64,
    /// Total datagrams received (0 on Stream plane).
    pub datagrams_received: u64,
    /// Total datagrams sent (0 on Stream plane).
    pub datagrams_sent: u64,
}

/// Snapshot of authorization and renewal counters for either Endpoints or Transits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuthStats {
    /// Authorization decisions returning `Ok(Lease)`.
    pub allowed: u64,
    /// Authorization decisions returning `Denied` or invalid TTL.
    pub rejected: u64,
    /// Authorization evaluations failing with `Timeout`.
    pub timed_out: u64,
    /// Authorization evaluations failing with `Busy`.
    pub busy: u64,
    /// Cumulative authorization evaluation duration in milliseconds.
    pub duration_ms_total: u64,
    /// Successful in-band lease renewals completed.
    pub renewed: u64,
    /// Lease renewal retries triggered.
    pub renewal_retries: u64,
    /// Lease renewal failures or expirations.
    pub renewal_failures: u64,
}

/// Snapshot of setup failures grouped by [`FailureClass`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FailureClassStats {
    /// Failures classified as [`FailureClass::PathFailure`].
    pub path_failure: u64,
    /// Failures classified as [`FailureClass::DestinationPolicy`].
    pub destination_policy: u64,
    /// Failures classified as [`FailureClass::DestinationApp`].
    pub destination_app: u64,
    /// Failures classified as [`FailureClass::LocalAuth`].
    pub local_auth: u64,
    /// Failures classified as [`FailureClass::LocalInvalid`].
    pub local_invalid: u64,
}

/// Immutable atomic telemetry snapshot for a single `ScopeInstance`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ScopeStats {
    /// Currently held pending setup permits.
    pub pending_setups: usize,
    /// Whether flood-cookie protection (`under_load`) is currently active.
    pub under_load: bool,
    /// Whether the scope is still accepting new inbound/outbound sessions.
    pub accepting: bool,
    /// Number of currently attached `DatagramPort` links.
    pub active_datagram_ports: usize,
    /// Stream plane counters.
    pub stream: PlaneStats,
    /// Datagram plane counters.
    pub datagram: PlaneStats,
    /// Setup failures broken down by [`FailureClass`].
    pub setup_failures_by_class: FailureClassStats,
    /// Authorization and renewal counters for Endpoints.
    pub auth_endpoint: AuthStats,
    /// Authorization and renewal counters for Transits.
    pub auth_transit: AuthStats,
    /// Rejections caused by pending/session/per-peer capacity saturation.
    pub capacity_drops_total: u64,
    /// Packets silently dropped due to unknown `ScopeKid` or invalid `mac1`.
    pub mac1_drops_total: u64,
    /// Stateless flood-cookie challenges emitted under load.
    pub mac2_challenges_total: u64,
    /// Setups rejected by `SetupReplay`.
    pub replay_rejects_total: u64,
    /// Peer-scoped revocations triggered.
    pub revocations_peer_total: u64,
    /// Endpoint-scoped revocations triggered.
    pub revocations_endpoint_total: u64,
    /// Transit-scoped revocations triggered.
    pub revocations_transit_total: u64,
    /// Scope-wide (`Revocation::All`) revocations triggered.
    pub revocations_scope_total: u64,
    /// Fail-closed scope invalidations triggered by revocation broadcast lag.
    pub revocation_lag_invalidations_total: u64,
    /// Total sessions and circuits closed.
    pub sessions_closed_total: u64,
    /// Cumulative active lifetime of closed sessions in milliseconds.
    pub session_duration_ms_total: u64,
    /// Packets dropped due to full datagram session/carrier queues or transient send errors.
    pub queue_drops_total: u64,
    /// Packets dropped due to a full 32-slot per-circuit datagram mailbox.
    pub datagram_mailbox_drops_total: u64,
    /// Data-plane packets dropped by a `TrafficGate`.
    pub traffic_gate_drops_total: u64,
    /// Live path MTU changes applied mid-session.
    pub mtu_updates_total: u64,
}

/// Immutable atomic telemetry snapshot for a multi-scope `Node`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NodeStats {
    /// Number of mounted scopes.
    pub mounted_scopes: usize,
    /// Currently held node-level pending setup permits.
    pub pending_setups: usize,
    /// Whether the node is still accepting new inbound streams/links.
    pub accepting: bool,
    /// Number of active deduplicated `DatagramPort`s registered on the node.
    pub active_datagram_ports: usize,
    /// Node-level pending/port capacity rejections.
    pub capacity_drops_total: u64,
    /// Pre-DH `mac1` drops at node ingress.
    pub mac1_drops_total: u64,
    /// Inbound setups dropped because no mounted scope matched `ScopeKid`.
    pub unknown_scope_drops_total: u64,
}

#[derive(Default)]
struct AtomicRoleMetrics {
    active_sessions: AtomicUsize,
    setup_attempts: AtomicU64,
    setup_established: AtomicU64,
    setup_failures: AtomicU64,
}

impl AtomicRoleMetrics {
    fn snapshot(&self) -> RoleStats {
        RoleStats {
            active_sessions: self.active_sessions.load(Ordering::Relaxed),
            setup_attempts: self.setup_attempts.load(Ordering::Relaxed),
            setup_established: self.setup_established.load(Ordering::Relaxed),
            setup_failures: self.setup_failures.load(Ordering::Relaxed),
        }
    }
}

#[derive(Default)]
struct AtomicPlaneMetrics {
    origin: AtomicRoleMetrics,
    destination: AtomicRoleMetrics,
    transit: AtomicRoleMetrics,
    bytes_received: AtomicU64,
    bytes_sent: AtomicU64,
    datagrams_received: AtomicU64,
    datagrams_sent: AtomicU64,
}

impl AtomicPlaneMetrics {
    fn role(&self, role: Role) -> &AtomicRoleMetrics {
        match role {
            Role::Origin => &self.origin,
            Role::Destination => &self.destination,
            Role::Transit => &self.transit,
        }
    }

    fn snapshot(&self) -> PlaneStats {
        PlaneStats {
            origin: self.origin.snapshot(),
            destination: self.destination.snapshot(),
            transit: self.transit.snapshot(),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            datagrams_received: self.datagrams_received.load(Ordering::Relaxed),
            datagrams_sent: self.datagrams_sent.load(Ordering::Relaxed),
        }
    }
}

#[derive(Default)]
pub(crate) struct AtomicAuthMetrics {
    pub allowed: AtomicU64,
    pub rejected: AtomicU64,
    pub timed_out: AtomicU64,
    pub busy: AtomicU64,
    pub duration_ms_total: AtomicU64,
    pub renewed: AtomicU64,
    pub renewal_retries: AtomicU64,
    pub renewal_failures: AtomicU64,
}

impl AtomicAuthMetrics {
    fn snapshot(&self) -> AuthStats {
        AuthStats {
            allowed: self.allowed.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            timed_out: self.timed_out.load(Ordering::Relaxed),
            busy: self.busy.load(Ordering::Relaxed),
            duration_ms_total: self.duration_ms_total.load(Ordering::Relaxed),
            renewed: self.renewed.load(Ordering::Relaxed),
            renewal_retries: self.renewal_retries.load(Ordering::Relaxed),
            renewal_failures: self.renewal_failures.load(Ordering::Relaxed),
        }
    }
}

#[derive(Default)]
struct AtomicFailureClassMetrics {
    path_failure: AtomicU64,
    destination_policy: AtomicU64,
    destination_app: AtomicU64,
    local_auth: AtomicU64,
    local_invalid: AtomicU64,
}

impl AtomicFailureClassMetrics {
    fn record(&self, class: FailureClass) {
        let counter = match class {
            FailureClass::PathFailure => &self.path_failure,
            FailureClass::DestinationPolicy => &self.destination_policy,
            FailureClass::DestinationApp => &self.destination_app,
            FailureClass::LocalAuth => &self.local_auth,
            FailureClass::LocalInvalid => &self.local_invalid,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> FailureClassStats {
        FailureClassStats {
            path_failure: self.path_failure.load(Ordering::Relaxed),
            destination_policy: self.destination_policy.load(Ordering::Relaxed),
            destination_app: self.destination_app.load(Ordering::Relaxed),
            local_auth: self.local_auth.load(Ordering::Relaxed),
            local_invalid: self.local_invalid.load(Ordering::Relaxed),
        }
    }
}

#[allow(dead_code)]
#[cfg_attr(feature = "test-support", allow(missing_docs))]
pub(crate) mod internal {
    use super::*;

    /// Internal lock-free atomic metrics container owned by a scope.
    pub struct ScopeMetrics {
        pub pending_setups: AtomicUsize,
        pub under_load: AtomicBool,
        pub accepting: AtomicBool,
        pub active_datagram_ports: AtomicUsize,
        stream: AtomicPlaneMetrics,
        datagram: AtomicPlaneMetrics,
        setup_failures_by_class: AtomicFailureClassMetrics,
        pub(crate) auth_endpoint: AtomicAuthMetrics,
        pub(crate) auth_transit: AtomicAuthMetrics,
        pub capacity_drops_total: AtomicU64,
        pub mac1_drops_total: AtomicU64,
        pub mac2_challenges_total: AtomicU64,
        pub replay_rejects_total: AtomicU64,
        pub revocations_peer_total: AtomicU64,
        pub revocations_endpoint_total: AtomicU64,
        pub revocations_transit_total: AtomicU64,
        pub revocations_scope_total: AtomicU64,
        pub revocation_lag_invalidations_total: AtomicU64,
        pub sessions_closed_total: AtomicU64,
        pub session_duration_ms_total: AtomicU64,
        pub queue_drops_total: AtomicU64,
        pub datagram_mailbox_drops_total: AtomicU64,
        pub traffic_gate_drops_total: AtomicU64,
        pub mtu_updates_total: AtomicU64,
    }

    impl Default for ScopeMetrics {
        fn default() -> Self {
            Self {
                pending_setups: AtomicUsize::new(0),
                under_load: AtomicBool::new(false),
                accepting: AtomicBool::new(true),
                active_datagram_ports: AtomicUsize::new(0),
                stream: AtomicPlaneMetrics::default(),
                datagram: AtomicPlaneMetrics::default(),
                setup_failures_by_class: AtomicFailureClassMetrics::default(),
                auth_endpoint: AtomicAuthMetrics::default(),
                auth_transit: AtomicAuthMetrics::default(),
                capacity_drops_total: AtomicU64::new(0),
                mac1_drops_total: AtomicU64::new(0),
                mac2_challenges_total: AtomicU64::new(0),
                replay_rejects_total: AtomicU64::new(0),
                revocations_peer_total: AtomicU64::new(0),
                revocations_endpoint_total: AtomicU64::new(0),
                revocations_transit_total: AtomicU64::new(0),
                revocations_scope_total: AtomicU64::new(0),
                revocation_lag_invalidations_total: AtomicU64::new(0),
                sessions_closed_total: AtomicU64::new(0),
                session_duration_ms_total: AtomicU64::new(0),
                queue_drops_total: AtomicU64::new(0),
                datagram_mailbox_drops_total: AtomicU64::new(0),
                traffic_gate_drops_total: AtomicU64::new(0),
                mtu_updates_total: AtomicU64::new(0),
            }
        }
    }

    impl ScopeMetrics {
        pub fn new() -> Self {
            Self::default()
        }

        fn plane(&self, plane: Plane) -> &AtomicPlaneMetrics {
            match plane {
                Plane::Stream => &self.stream,
                Plane::Datagram => &self.datagram,
            }
        }

        pub(crate) fn auth(&self, is_transit: bool) -> &AtomicAuthMetrics {
            if is_transit {
                &self.auth_transit
            } else {
                &self.auth_endpoint
            }
        }

        pub fn record_setup_attempt(&self, plane: Plane, role: Role) {
            self.plane(plane)
                .role(role)
                .setup_attempts
                .fetch_add(1, Ordering::Relaxed);
        }

        pub fn record_setup_established(&self, plane: Plane, role: Role) {
            self.plane(plane)
                .role(role)
                .setup_established
                .fetch_add(1, Ordering::Relaxed);
        }

        pub fn record_setup_failure(&self, plane: Plane, role: Role, class: FailureClass) {
            self.plane(plane)
                .role(role)
                .setup_failures
                .fetch_add(1, Ordering::Relaxed);
            self.setup_failures_by_class.record(class);
        }

        pub fn inc_active_session(&self, plane: Plane, role: Role) {
            self.plane(plane)
                .role(role)
                .active_sessions
                .fetch_add(1, Ordering::Relaxed);
        }

        pub fn dec_active_session(&self, plane: Plane, role: Role, duration_ms: u64) {
            self.plane(plane)
                .role(role)
                .active_sessions
                .fetch_sub(1, Ordering::Relaxed);
            self.sessions_closed_total.fetch_add(1, Ordering::Relaxed);
            self.session_duration_ms_total
                .fetch_add(duration_ms, Ordering::Relaxed);
        }

        pub fn record_rx(&self, plane: Plane, bytes: u64, is_datagram: bool) {
            let p = self.plane(plane);
            p.bytes_received.fetch_add(bytes, Ordering::Relaxed);
            if is_datagram {
                p.datagrams_received.fetch_add(1, Ordering::Relaxed);
            }
        }

        pub fn record_tx(&self, plane: Plane, bytes: u64, is_datagram: bool) {
            let p = self.plane(plane);
            p.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
            if is_datagram {
                p.datagrams_sent.fetch_add(1, Ordering::Relaxed);
            }
        }

        pub fn record_capacity_drop(&self) -> u64 {
            self.capacity_drops_total
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1)
        }

        pub fn record_auth_timeout(&self, is_transit: bool) -> u64 {
            self.auth(is_transit)
                .timed_out
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1)
        }

        pub fn snapshot(&self) -> ScopeStats {
            ScopeStats {
                pending_setups: self.pending_setups.load(Ordering::Relaxed),
                under_load: self.under_load.load(Ordering::Acquire),
                accepting: self.accepting.load(Ordering::Acquire),
                active_datagram_ports: self.active_datagram_ports.load(Ordering::Relaxed),
                stream: self.stream.snapshot(),
                datagram: self.datagram.snapshot(),
                setup_failures_by_class: self.setup_failures_by_class.snapshot(),
                auth_endpoint: self.auth_endpoint.snapshot(),
                auth_transit: self.auth_transit.snapshot(),
                capacity_drops_total: self.capacity_drops_total.load(Ordering::Relaxed),
                mac1_drops_total: self.mac1_drops_total.load(Ordering::Relaxed),
                mac2_challenges_total: self.mac2_challenges_total.load(Ordering::Relaxed),
                replay_rejects_total: self.replay_rejects_total.load(Ordering::Relaxed),
                revocations_peer_total: self.revocations_peer_total.load(Ordering::Relaxed),
                revocations_endpoint_total: self.revocations_endpoint_total.load(Ordering::Relaxed),
                revocations_transit_total: self.revocations_transit_total.load(Ordering::Relaxed),
                revocations_scope_total: self.revocations_scope_total.load(Ordering::Relaxed),
                revocation_lag_invalidations_total: self
                    .revocation_lag_invalidations_total
                    .load(Ordering::Relaxed),
                sessions_closed_total: self.sessions_closed_total.load(Ordering::Relaxed),
                session_duration_ms_total: self.session_duration_ms_total.load(Ordering::Relaxed),
                queue_drops_total: self.queue_drops_total.load(Ordering::Relaxed),
                datagram_mailbox_drops_total: self
                    .datagram_mailbox_drops_total
                    .load(Ordering::Relaxed),
                traffic_gate_drops_total: self.traffic_gate_drops_total.load(Ordering::Relaxed),
                mtu_updates_total: self.mtu_updates_total.load(Ordering::Relaxed),
            }
        }
    }

    /// Internal lock-free atomic metrics container owned by a multi-scope `Node`.
    pub struct NodeMetrics {
        pub mounted_scopes: AtomicUsize,
        pub pending_setups: AtomicUsize,
        pub accepting: AtomicBool,
        pub active_datagram_ports: AtomicUsize,
        pub capacity_drops_total: AtomicU64,
        pub mac1_drops_total: AtomicU64,
        pub unknown_scope_drops_total: AtomicU64,
    }

    impl Default for NodeMetrics {
        fn default() -> Self {
            Self {
                mounted_scopes: AtomicUsize::new(0),
                pending_setups: AtomicUsize::new(0),
                accepting: AtomicBool::new(true),
                active_datagram_ports: AtomicUsize::new(0),
                capacity_drops_total: AtomicU64::new(0),
                mac1_drops_total: AtomicU64::new(0),
                unknown_scope_drops_total: AtomicU64::new(0),
            }
        }
    }

    impl NodeMetrics {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn snapshot(&self) -> NodeStats {
            NodeStats {
                mounted_scopes: self.mounted_scopes.load(Ordering::Relaxed),
                pending_setups: self.pending_setups.load(Ordering::Relaxed),
                accepting: self.accepting.load(Ordering::Acquire),
                active_datagram_ports: self.active_datagram_ports.load(Ordering::Relaxed),
                capacity_drops_total: self.capacity_drops_total.load(Ordering::Relaxed),
                mac1_drops_total: self.mac1_drops_total.load(Ordering::Relaxed),
                unknown_scope_drops_total: self.unknown_scope_drops_total.load(Ordering::Relaxed),
            }
        }
    }
}

#[allow(unused_imports)]
pub(crate) use internal::{NodeMetrics, ScopeMetrics};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pow2_warning_throttle_pattern() {
        assert!(!should_warn_pow2(0));
        assert!(should_warn_pow2(1));
        assert!(should_warn_pow2(2));
        assert!(!should_warn_pow2(3));
        assert!(should_warn_pow2(4));
        assert!(!should_warn_pow2(5));
        assert!(should_warn_pow2(1024));
        assert!(!should_warn_pow2(1025));
    }

    #[test]
    fn scope_metrics_snapshot_reflects_updates() {
        let m = ScopeMetrics::new();
        m.record_setup_attempt(Plane::Datagram, Role::Transit);
        m.record_setup_failure(Plane::Datagram, Role::Transit, FailureClass::PathFailure);
        m.record_rx(Plane::Datagram, 1200, true);
        let snap = m.snapshot();
        assert!(snap.accepting);
        assert_eq!(snap.datagram.transit.setup_attempts, 1);
        assert_eq!(snap.datagram.transit.setup_failures, 1);
        assert_eq!(snap.setup_failures_by_class.path_failure, 1);
        assert_eq!(snap.datagram.bytes_received, 1200);
        assert_eq!(snap.datagram.datagrams_received, 1);
    }
}
