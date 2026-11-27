//! Unified Endpoint, 4-table Transit, Carrier, and TOCTOU-free Revocation Registry (Spec §7.4–7.5).

use core::fmt;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use crate::constants::{DATAGRAM_MIN_MTU, NAME_MAX_LEN};
use crate::error::CoreError;
use crate::seam::channel::{
    DatagramCarrier, ErasedDatagramCarrier, ErasedStreamCarrier, StreamCarrier,
};
use crate::seam::handler::{
    DatagramEndpointHandler, DatagramTransitHandler, StreamEndpointHandler, StreamTransitHandler,
};
use crate::stats::ScopeMetrics;
use crate::trust::lease::LeaseHandle;
use crate::trust::revocation::{
    AuthEpochSnapshot, AuthEpochTable, RevocationIndex, RevocationKey, TransitEpochTarget,
};
use crate::types::{Plane, PublicationId, PublicKey, ValidatedName};

#[allow(dead_code)]
#[derive(Clone)]
pub enum EndpointHandlerKind {
    Stream(Arc<dyn StreamEndpointHandler>),
    Datagram {
        min_mtu: u16,
        handler: Arc<dyn DatagramEndpointHandler>,
    },
}

#[derive(Clone)]
struct EndpointEntry {
    pub_id: PublicationId,
    active: Arc<AtomicBool>,
    kind: EndpointHandlerKind,
}

#[derive(Clone)]
struct TransitEntry<H> {
    pub_id: PublicationId,
    active: Arc<AtomicBool>,
    handler: H,
}

#[allow(dead_code)]
pub struct ResolvedEndpoint {
    pub pub_id: PublicationId,
    pub active: Arc<AtomicBool>,
    pub kind: EndpointHandlerKind,
}

#[allow(dead_code)]
#[derive(Clone)]
pub enum ResolvedTransitHandler {
    Stream(Arc<dyn StreamTransitHandler>),
    Datagram(Arc<dyn DatagramTransitHandler>),
}

#[allow(dead_code)]
pub struct ResolvedTransit {
    pub pub_id: PublicationId,
    pub active: Arc<AtomicBool>,
    pub subtarget: String,
    pub matched_prefix: Option<String>,
    pub handler: ResolvedTransitHandler,
}

#[derive(Default)]
struct TrustState {
    endpoints: HashMap<String, EndpointEntry>,
    stream_exact: HashMap<String, TransitEntry<Arc<dyn StreamTransitHandler>>>,
    datagram_exact: HashMap<String, TransitEntry<Arc<dyn DatagramTransitHandler>>>,
    stream_prefix: HashMap<String, TransitEntry<Arc<dyn StreamTransitHandler>>>,
    datagram_prefix: HashMap<String, TransitEntry<Arc<dyn DatagramTransitHandler>>>,
    stream_carriers: HashMap<String, Arc<dyn ErasedStreamCarrier>>,
    datagram_carriers: HashMap<String, Arc<dyn ErasedDatagramCarrier>>,
    vetoed: HashSet<PublicKey>,
    epochs: AuthEpochTable,
}

impl TrustState {
    fn matches_plane_transit(&self, plane: Plane, target: &str) -> bool {
        match plane {
            Plane::Stream => {
                self.stream_exact.contains_key(target)
                    || self
                        .stream_prefix
                        .keys()
                        .any(|p| target.starts_with(p.as_str()) && target.len() > p.len())
            }
            Plane::Datagram => {
                self.datagram_exact.contains_key(target)
                    || self
                        .datagram_prefix
                        .keys()
                        .any(|p| target.starts_with(p.as_str()) && target.len() > p.len())
            }
        }
    }
}

/// Unified publication, carrier, local veto, epoch, and revocation registry owned by a scope.
///
/// Enforces lock ordering `Level 3 (TrustState) -> Level 4 (RevocationIndex)` so TOCTOU checks
/// and lease registration are atomic and deadlock-free.
pub struct PublishRegistry {
    state: RwLock<TrustState>,
    revocations: RevocationIndex,
    metrics: Arc<ScopeMetrics>,
}

#[allow(dead_code)]
impl PublishRegistry {
    #[must_use]
    pub fn new(metrics: Arc<ScopeMetrics>) -> Self {
        Self {
            state: RwLock::new(TrustState::default()),
            revocations: RevocationIndex::new(),
            metrics,
        }
    }

    // -----------------------------------------------------------------------
    // Outbound Carriers (Default-Deny Forwarding: Never Queried for Inbound Transits)
    // -----------------------------------------------------------------------

    pub fn register_stream_carrier<C: StreamCarrier>(
        &self,
        name: &str,
        carrier: C,
    ) -> Result<(), CoreError> {
        let valid = ValidatedName::validate_str(name)?;
        let mut st = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if st.stream_carriers.contains_key(valid) {
            return Err(CoreError::AlreadyPublished);
        }
        st.stream_carriers.insert(valid.to_owned(), Arc::new(carrier));
        Ok(())
    }

    pub fn register_datagram_carrier<C: DatagramCarrier>(
        &self,
        name: &str,
        carrier: C,
    ) -> Result<(), CoreError> {
        let valid = ValidatedName::validate_str(name)?;
        let mut st = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if st.datagram_carriers.contains_key(valid) {
            return Err(CoreError::AlreadyPublished);
        }
        st.datagram_carriers
            .insert(valid.to_owned(), Arc::new(carrier));
        Ok(())
    }

    pub(crate) fn get_stream_carrier(
        &self,
        name: &str,
    ) -> Result<Arc<dyn ErasedStreamCarrier>, CoreError> {
        let st = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        st.stream_carriers
            .get(name)
            .cloned()
            .ok_or(CoreError::Unpublished)
    }

    pub(crate) fn get_datagram_carrier(
        &self,
        name: &str,
    ) -> Result<Arc<dyn ErasedDatagramCarrier>, CoreError> {
        let st = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        st.datagram_carriers
            .get(name)
            .cloned()
            .ok_or(CoreError::Unpublished)
    }

    // -----------------------------------------------------------------------
    // Endpoints (Single Shared Namespace Across Stream & Datagram)
    // -----------------------------------------------------------------------

    /// Publishes a Stream endpoint (takes no `min_mtu`; implicit floor `0`, clamped to `20` on setup).
    pub fn publish_stream_endpoint(
        self: &Arc<Self>,
        name: &str,
        handler: Arc<dyn StreamEndpointHandler>,
    ) -> Result<PublishGuard, CoreError> {
        let valid = ValidatedName::validate_str(name)?;
        let pub_id = PublicationId::next();
        let active = Arc::new(AtomicBool::new(true));
        let mut st = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if st.endpoints.contains_key(valid) {
            return Err(CoreError::AlreadyPublished);
        }
        st.endpoints.insert(
            valid.to_owned(),
            EndpointEntry {
                pub_id,
                active: Arc::clone(&active),
                kind: EndpointHandlerKind::Stream(handler),
            },
        );
        Ok(PublishGuard {
            registry: Arc::clone(self),
            pub_id,
            active,
            kind: GuardKind::Endpoint(valid.to_owned()),
        })
    }

    /// Publishes a Datagram endpoint, rejecting `min_mtu < 1152` immediately with [`CoreError::MtuTooSmall`].
    pub fn publish_datagram_endpoint(
        self: &Arc<Self>,
        name: &str,
        min_mtu: u16,
        handler: Arc<dyn DatagramEndpointHandler>,
    ) -> Result<PublishGuard, CoreError> {
        let valid = ValidatedName::validate_str(name)?;
        if min_mtu < DATAGRAM_MIN_MTU {
            return Err(CoreError::MtuTooSmall(min_mtu));
        }
        let pub_id = PublicationId::next();
        let active = Arc::new(AtomicBool::new(true));
        let mut st = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if st.endpoints.contains_key(valid) {
            return Err(CoreError::AlreadyPublished);
        }
        st.endpoints.insert(
            valid.to_owned(),
            EndpointEntry {
                pub_id,
                active: Arc::clone(&active),
                kind: EndpointHandlerKind::Datagram { min_mtu, handler },
            },
        );
        Ok(PublishGuard {
            registry: Arc::clone(self),
            pub_id,
            active,
            kind: GuardKind::Endpoint(valid.to_owned()),
        })
    }

    pub fn resolve_endpoint(&self, name: &str, plane: Plane) -> Result<ResolvedEndpoint, CoreError> {
        let st = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(entry) = st.endpoints.get(name) else {
            return Err(CoreError::Unpublished);
        };
        let matches_plane = matches!(
            (&entry.kind, plane),
            (EndpointHandlerKind::Stream(_), Plane::Stream)
                | (EndpointHandlerKind::Datagram { .. }, Plane::Datagram)
        );
        if !matches_plane {
            return Err(CoreError::WrongPlane);
        }
        Ok(ResolvedEndpoint {
            pub_id: entry.pub_id,
            active: Arc::clone(&entry.active),
            kind: entry.kind.clone(),
        })
    }

    // -----------------------------------------------------------------------
    // Named Transits (4 Tables: Stream/Datagram × Exact/Prefix)
    // -----------------------------------------------------------------------

    pub fn publish_stream_transit(
        self: &Arc<Self>,
        name: &str,
        handler: Arc<dyn StreamTransitHandler>,
    ) -> Result<PublishGuard, CoreError> {
        let valid = ValidatedName::validate_str(name)?;
        let pub_id = PublicationId::next();
        let active = Arc::new(AtomicBool::new(true));
        let mut st = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if st.stream_exact.contains_key(valid) {
            return Err(CoreError::AlreadyPublished);
        }
        st.stream_exact.insert(
            valid.to_owned(),
            TransitEntry {
                pub_id,
                active: Arc::clone(&active),
                handler,
            },
        );
        Ok(PublishGuard {
            registry: Arc::clone(self),
            pub_id,
            active,
            kind: GuardKind::Transit {
                plane: Plane::Stream,
                is_prefix: false,
                key: valid.to_owned(),
            },
        })
    }

    pub fn publish_stream_transit_prefix(
        self: &Arc<Self>,
        prefix: &str,
        handler: Arc<dyn StreamTransitHandler>,
    ) -> Result<PublishGuard, CoreError> {
        let valid = ValidatedName::validate_str(prefix)?;
        let pub_id = PublicationId::next();
        let active = Arc::new(AtomicBool::new(true));
        let mut st = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if st.stream_prefix.contains_key(valid) {
            return Err(CoreError::AlreadyPublished);
        }
        st.stream_prefix.insert(
            valid.to_owned(),
            TransitEntry {
                pub_id,
                active: Arc::clone(&active),
                handler,
            },
        );
        Ok(PublishGuard {
            registry: Arc::clone(self),
            pub_id,
            active,
            kind: GuardKind::Transit {
                plane: Plane::Stream,
                is_prefix: true,
                key: valid.to_owned(),
            },
        })
    }

    pub fn publish_datagram_transit(
        self: &Arc<Self>,
        name: &str,
        handler: Arc<dyn DatagramTransitHandler>,
    ) -> Result<PublishGuard, CoreError> {
        let valid = ValidatedName::validate_str(name)?;
        let pub_id = PublicationId::next();
        let active = Arc::new(AtomicBool::new(true));
        let mut st = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if st.datagram_exact.contains_key(valid) {
            return Err(CoreError::AlreadyPublished);
        }
        st.datagram_exact.insert(
            valid.to_owned(),
            TransitEntry {
                pub_id,
                active: Arc::clone(&active),
                handler,
            },
        );
        Ok(PublishGuard {
            registry: Arc::clone(self),
            pub_id,
            active,
            kind: GuardKind::Transit {
                plane: Plane::Datagram,
                is_prefix: false,
                key: valid.to_owned(),
            },
        })
    }

    pub fn publish_datagram_transit_prefix(
        self: &Arc<Self>,
        prefix: &str,
        handler: Arc<dyn DatagramTransitHandler>,
    ) -> Result<PublishGuard, CoreError> {
        let valid = ValidatedName::validate_str(prefix)?;
        let pub_id = PublicationId::next();
        let active = Arc::new(AtomicBool::new(true));
        let mut st = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if st.datagram_prefix.contains_key(valid) {
            return Err(CoreError::AlreadyPublished);
        }
        st.datagram_prefix.insert(
            valid.to_owned(),
            TransitEntry {
                pub_id,
                active: Arc::clone(&active),
                handler,
            },
        );
        Ok(PublishGuard {
            registry: Arc::clone(self),
            pub_id,
            active,
            kind: GuardKind::Transit {
                plane: Plane::Datagram,
                is_prefix: true,
                key: valid.to_owned(),
            },
        })
    }

    /// Resolves a transit target with exact Spec §7.4 precedence:
    /// 1. Exact match on `plane` -> `subtarget = target`.
    /// 2. Longest prefix `p` on `plane` with `target.starts_with(p) && target.len() > p.len()` -> `subtarget = &target[p.len()..]`.
    /// 3. Match on opposite plane -> `WrongPlane`.
    /// 4. Else -> `Unpublished`.
    pub fn resolve_transit(&self, target: &str, plane: Plane) -> Result<ResolvedTransit, CoreError> {
        let st = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        match plane {
            Plane::Stream => {
                if let Some(entry) = st.stream_exact.get(target) {
                    return Ok(ResolvedTransit {
                        pub_id: entry.pub_id,
                        active: Arc::clone(&entry.active),
                        subtarget: target.to_owned(),
                        matched_prefix: None,
                        handler: ResolvedTransitHandler::Stream(Arc::clone(&entry.handler)),
                    });
                }
                if let Some((prefix, entry)) = st
                    .stream_prefix
                    .iter()
                    .filter(|(p, _)| target.starts_with(p.as_str()) && target.len() > p.len())
                    .max_by_key(|(p, _)| p.len())
                {
                    return Ok(ResolvedTransit {
                        pub_id: entry.pub_id,
                        active: Arc::clone(&entry.active),
                        subtarget: target[prefix.len()..].to_owned(),
                        matched_prefix: Some(prefix.clone()),
                        handler: ResolvedTransitHandler::Stream(Arc::clone(&entry.handler)),
                    });
                }
                if st.matches_plane_transit(Plane::Datagram, target) {
                    return Err(CoreError::WrongPlane);
                }
            }
            Plane::Datagram => {
                if let Some(entry) = st.datagram_exact.get(target) {
                    return Ok(ResolvedTransit {
                        pub_id: entry.pub_id,
                        active: Arc::clone(&entry.active),
                        subtarget: target.to_owned(),
                        matched_prefix: None,
                        handler: ResolvedTransitHandler::Datagram(Arc::clone(&entry.handler)),
                    });
                }
                if let Some((prefix, entry)) = st
                    .datagram_prefix
                    .iter()
                    .filter(|(p, _)| target.starts_with(p.as_str()) && target.len() > p.len())
                    .max_by_key(|(p, _)| p.len())
                {
                    return Ok(ResolvedTransit {
                        pub_id: entry.pub_id,
                        active: Arc::clone(&entry.active),
                        subtarget: target[prefix.len()..].to_owned(),
                        matched_prefix: Some(prefix.clone()),
                        handler: ResolvedTransitHandler::Datagram(Arc::clone(&entry.handler)),
                    });
                }
                if st.matches_plane_transit(Plane::Stream, target) {
                    return Err(CoreError::WrongPlane);
                }
            }
        }
        Err(CoreError::Unpublished)
    }

    // -----------------------------------------------------------------------
    // Local Hard Veto, TOCTOU Snapshots, Atomic Lease Tracking & Revocation
    // -----------------------------------------------------------------------

    #[must_use]
    pub fn is_vetoed(&self, peer: PublicKey) -> bool {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .vetoed
            .contains(&peer)
    }

    /// Host-sovereign `ScopeInstance::revoke_peer`: adds `peer` to local permanent veto set,
    /// bumps peer epoch, detaches indexed leases atomically under the write lock, and notifies
    /// all detached leases with `Revoked` strictly after releasing all locks.
    pub fn veto_peer(&self, peer: PublicKey) {
        let detached = {
            let mut st = self
                .state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            st.vetoed.insert(peer);
            st.epochs.bump_peer(peer);
            self.revocations.detach_key(&RevocationKey::Peer(peer))
        };
        self.metrics
            .revocations_peer_total
            .fetch_add(1, Ordering::Relaxed);
        RevocationIndex::notify_revoked(detached, &CoreError::Revoked);
    }

    /// Removes `peer` from the local hard veto set.
    pub fn unveto_peer(&self, peer: PublicKey) {
        self.state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .vetoed
            .remove(&peer);
    }

    /// Authorizer `Revocation::Peer`: revokes active sessions (`Revoked`) WITHOUT adding to local `vetoed`.
    pub fn revoke_peer_sessions_only(&self, peer: PublicKey) {
        let detached = {
            let mut st = self
                .state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            st.epochs.bump_peer(peer);
            self.revocations.detach_key(&RevocationKey::Peer(peer))
        };
        self.metrics
            .revocations_peer_total
            .fetch_add(1, Ordering::Relaxed);
        RevocationIndex::notify_revoked(detached, &CoreError::Revoked);
    }

    /// Authorizer `Revocation::Endpoint`: bumps endpoint epoch and revokes sessions with `Unpublished`.
    pub fn revoke_endpoint(&self, name: &str) {
        let detached = {
            let mut st = self
                .state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            st.epochs.bump_endpoint(name);
            self.revocations
                .detach_key(&RevocationKey::Endpoint(name.to_owned()))
        };
        self.metrics
            .revocations_endpoint_total
            .fetch_add(1, Ordering::Relaxed);
        RevocationIndex::notify_revoked(detached, &CoreError::Unpublished);
    }

    /// Host `Scope::revoke_transit` / Authorizer `Revocation::Transit`: revokes across BOTH planes (`Revoked`).
    pub fn revoke_transit(&self, name: &str) {
        let (detached_st, detached_dg) = {
            let mut st = self
                .state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            st.epochs.bump_transit_both_planes(name);
            let st_weaks = self
                .revocations
                .detach_key(&RevocationKey::Transit(Plane::Stream, name.to_owned()));
            let dg_weaks = self
                .revocations
                .detach_key(&RevocationKey::Transit(Plane::Datagram, name.to_owned()));
            (st_weaks, dg_weaks)
        };
        self.metrics
            .revocations_transit_total
            .fetch_add(1, Ordering::Relaxed);
        RevocationIndex::notify_revoked(detached_st, &CoreError::Revoked);
        RevocationIndex::notify_revoked(detached_dg, &CoreError::Revoked);
    }

    /// Authorizer `Revocation::All` or fail-closed broadcast lag invalidation.
    ///
    /// Establishes a single atomic admission cutoff by bumping `global_epoch` and detaching all
    /// indexed leases inside the same `TrustState` write lock (Level 3 -> Level 4), then
    /// notifying detached leases strictly after releasing all locks.
    pub fn revoke_all(&self, is_lag: bool) {
        let detached = {
            let mut st = self
                .state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            st.epochs.bump_all();
            self.revocations.detach_all()
        };
        if is_lag {
            self.metrics
                .revocation_lag_invalidations_total
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.metrics
                .revocations_scope_total
                .fetch_add(1, Ordering::Relaxed);
        }
        RevocationIndex::notify_revoked(detached, &CoreError::Revoked);
    }

    #[must_use]
    pub fn epoch_for_endpoint(&self, peer: PublicKey, endpoint: Option<&str>) -> AuthEpochSnapshot {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .epochs
            .snapshot_endpoint(peer, endpoint)
    }

    #[must_use]
    pub fn epoch_for_transit(&self, target: &TransitEpochTarget<'_>) -> AuthEpochSnapshot {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .epochs
            .snapshot_transit(target)
    }

    /// Atomically verifies TOCTOU epoch, local veto, and (for Destination) exact endpoint publication
    /// identity before inserting `lease` into [`RevocationIndex`] (Level 3 -> Level 4).
    pub fn track_endpoint(
        &self,
        snapshot: &AuthEpochSnapshot,
        peer: PublicKey,
        endpoint: Option<(&str, PublicationId)>,
        lease: &Arc<LeaseHandle>,
    ) -> Result<(), CoreError> {
        let st = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if st.vetoed.contains(&peer) {
            return Err(CoreError::Revoked);
        }
        if let Some((ep_name, expected_pub_id)) = endpoint {
            let Some(current) = st.endpoints.get(ep_name) else {
                return Err(CoreError::Unpublished);
            };
            if current.pub_id != expected_pub_id || !current.active.load(Ordering::Acquire) {
                return Err(CoreError::Unpublished);
            }
            if !st.epochs.matches_endpoint(snapshot, peer, Some(ep_name)) {
                return Err(CoreError::Revoked);
            }
            // Insert while still holding Level 3 read lock -> mathematically TOCTOU-free!
            self.revocations.insert(RevocationKey::Peer(peer), lease);
            self.revocations
                .insert(RevocationKey::Endpoint(ep_name.to_owned()), lease);
            self.revocations
                .insert(RevocationKey::Publication(expected_pub_id), lease);
        } else {
            if !st.epochs.matches_endpoint(snapshot, peer, None) {
                return Err(CoreError::Revoked);
            }
            self.revocations.insert(RevocationKey::Peer(peer), lease);
        }
        Ok(())
    }

    /// Atomically verifies TOCTOU epoch, local veto, and exact transit publication activity before
    /// indexing `lease` under Peer, Transit (full + prefix), Publication, and PublicationTarget.
    pub fn track_transit(
        &self,
        snapshot: &AuthEpochSnapshot,
        target: &TransitEpochTarget<'_>,
        active: &AtomicBool,
        lease: &Arc<LeaseHandle>,
    ) -> Result<(), CoreError> {
        let st = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if st.vetoed.contains(&target.peer) {
            return Err(CoreError::Revoked);
        }
        if !active.load(Ordering::Acquire) {
            return Err(CoreError::Unpublished);
        }
        if !st.epochs.matches_transit(snapshot, target) {
            return Err(CoreError::Revoked);
        }
        self.revocations
            .insert(RevocationKey::Peer(target.peer), lease);
        self.revocations.insert(
            RevocationKey::Transit(target.plane, target.full_name.to_owned()),
            lease,
        );
        if let Some(prefix) = target.matched_prefix {
            self.revocations
                .insert(RevocationKey::Transit(target.plane, prefix.to_owned()), lease);
        }
        self.revocations
            .insert(RevocationKey::Publication(target.pub_id), lease);
        self.revocations.insert(
            RevocationKey::PublicationTarget(target.pub_id, target.subtarget.to_owned()),
            lease,
        );
        Ok(())
    }

    fn unpublish_guard(&self, pub_id: PublicationId, active: &AtomicBool, kind: &GuardKind) {
        #[allow(dead_code)]
        enum RetiredEntry {
            Endpoint(EndpointEntry),
            StreamTransit(TransitEntry<Arc<dyn StreamTransitHandler>>),
            DatagramTransit(TransitEntry<Arc<dyn DatagramTransitHandler>>),
        }

        let (retired, detached) = {
            let mut st = self
                .state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            active.store(false, Ordering::Release);
            let retired = match kind {
                GuardKind::Endpoint(name) => {
                    let removed = if st.endpoints.get(name).is_some_and(|e| e.pub_id == pub_id) {
                        st.endpoints.remove(name).map(RetiredEntry::Endpoint)
                    } else {
                        None
                    };
                    st.epochs.bump_endpoint(name);
                    removed
                }
                GuardKind::Transit {
                    plane,
                    is_prefix,
                    key,
                } => {
                    // Spec §7.4: Guard drop is strictly scoped to its `PublicationId` (`active`
                    // flag + `RevocationKey::Publication(pub_id)`). Do NOT bump the name-wide
                    // `(plane, key)` transit epoch, which would falsely abort overlapping exact
                    // or prefix setups sharing the same key string.
                    match (plane, is_prefix) {
                        (Plane::Stream, false) => {
                            if st.stream_exact.get(key).is_some_and(|e| e.pub_id == pub_id) {
                                st.stream_exact.remove(key).map(RetiredEntry::StreamTransit)
                            } else {
                                None
                            }
                        }
                        (Plane::Stream, true) => {
                            if st.stream_prefix.get(key).is_some_and(|e| e.pub_id == pub_id) {
                                st.stream_prefix
                                    .remove(key)
                                    .map(RetiredEntry::StreamTransit)
                            } else {
                                None
                            }
                        }
                        (Plane::Datagram, false) => {
                            if st
                                .datagram_exact
                                .get(key)
                                .is_some_and(|e| e.pub_id == pub_id)
                            {
                                st.datagram_exact
                                    .remove(key)
                                    .map(RetiredEntry::DatagramTransit)
                            } else {
                                None
                            }
                        }
                        (Plane::Datagram, true) => {
                            if st
                                .datagram_prefix
                                .get(key)
                                .is_some_and(|e| e.pub_id == pub_id)
                            {
                                st.datagram_prefix
                                    .remove(key)
                                    .map(RetiredEntry::DatagramTransit)
                            } else {
                                None
                            }
                        }
                    }
                }
            };
            // Detach strictly by PublicationId inside the same write transaction so overlapping
            // and replacement publications are unaffected.
            let detached = self
                .revocations
                .detach_key(&RevocationKey::Publication(pub_id));
            (retired, detached)
        };
        match kind {
            GuardKind::Endpoint(_) => {
                self.metrics
                    .revocations_endpoint_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            GuardKind::Transit { .. } => {
                self.metrics
                    .revocations_transit_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        RevocationIndex::notify_revoked(detached, &CoreError::Unpublished);
        // Drop the retired handler strictly AFTER releasing all registry locks and completing
        // scoped revocation so a handler owning another `PublishGuard` in this scope cannot deadlock.
        drop(retired);
    }

    fn revoke_publication_target(&self, pub_id: PublicationId, subtarget: &str) {
        let detached = {
            let mut st = self
                .state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            st.epochs.bump_publication_target(pub_id, subtarget);
            self.revocations
                .detach_key(&RevocationKey::PublicationTarget(
                    pub_id,
                    subtarget.to_owned(),
                ))
        };
        self.metrics
            .revocations_transit_total
            .fetch_add(1, Ordering::Relaxed);
        RevocationIndex::notify_revoked(detached, &CoreError::Revoked);
    }
}

enum GuardKind {
    Endpoint(String),
    Transit {
        plane: Plane,
        is_prefix: bool,
        key: String,
    },
}

/// RAII handle keeping an Endpoint or Transit published.
///
/// Dropping a `PublishGuard` atomically removes the publication and immediately revokes all
/// active sessions/circuits admitted under its [`PublicationId`] with [`CoreError::Unpublished`].
pub struct PublishGuard {
    registry: Arc<PublishRegistry>,
    pub_id: PublicationId,
    active: Arc<AtomicBool>,
    kind: GuardKind,
}

impl PublishGuard {
    /// Returns the unique [`PublicationId`] of this published endpoint or transit.
    #[must_use]
    pub const fn publication_id(&self) -> PublicationId {
        self.pub_id
    }

    /// Returns a scoped [`TransitRevoker`] handle for transit publications (or `None` for endpoints).
    #[must_use]
    pub fn revoker(&self) -> Option<TransitRevoker> {
        match &self.kind {
            GuardKind::Endpoint(_) => None,
            GuardKind::Transit {
                plane,
                is_prefix,
                key,
            } => Some(TransitRevoker {
                registry: Arc::clone(&self.registry),
                pub_id: self.pub_id,
                plane: *plane,
                prefix_len: if *is_prefix { key.len() } else { 0 },
            }),
        }
    }
}

impl Drop for PublishGuard {
    fn drop(&mut self) {
        self.registry
            .unpublish_guard(self.pub_id, &self.active, &self.kind);
    }
}

impl fmt::Debug for PublishGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublishGuard")
            .field("pub_id", &self.pub_id)
            .finish()
    }
}

/// Publication-scoped revoker derived from a transit [`PublishGuard`] (Spec §7.4).
///
/// Revokes ONLY circuits admitted under its specific `(PublicationId, Plane, target)` without
/// disturbing overlapping exact/prefix publications or subsequent replacement publications.
#[derive(Clone)]
pub struct TransitRevoker {
    registry: Arc<PublishRegistry>,
    pub_id: PublicationId,
    plane: Plane,
    prefix_len: usize,
}

impl TransitRevoker {
    /// Returns the [`PublicationId`] this revoker is bound to.
    #[must_use]
    pub const fn publication_id(&self) -> PublicationId {
        self.pub_id
    }

    /// Returns the [`Plane`] this revoker is bound to.
    #[must_use]
    pub const fn plane(&self) -> Plane {
        self.plane
    }

    /// Revokes active circuits matching `target` (suffix for prefix publications, exact name for
    /// exact publications) strictly within this `(PublicationId, Plane)` with [`CoreError::Revoked`].
    pub fn revoke_target(&self, target: &str) -> Result<(), CoreError> {
        let max_len = NAME_MAX_LEN.saturating_sub(self.prefix_len);
        if target.is_empty() || target.len() > max_len {
            return Err(CoreError::InvalidParameter);
        }
        self.registry.revoke_publication_target(self.pub_id, target);
        Ok(())
    }
}

impl fmt::Debug for TransitRevoker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransitRevoker")
            .field("pub_id", &self.pub_id)
            .field("plane", &self.plane)
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use core::time::Duration;

    use super::*;
    use crate::runtime::BoxFuture;
    use crate::seam::auth::{Lease, SessionAuth};
    use crate::seam::channel::{BoxedStream, ChannelCaps, DatagramLink};
    use crate::testing::VirtualClock;

    struct DummyStEp;
    impl StreamEndpointHandler for DummyStEp {
        fn open(&self, _auth: SessionAuth) -> BoxFuture<'_, Result<BoxedStream, CoreError>> {
            Box::pin(async { Err(CoreError::Closed) })
        }
    }

    struct DummyDgEp;
    impl DatagramEndpointHandler for DummyDgEp {
        fn open(&self, _auth: SessionAuth) -> BoxFuture<'_, Result<Arc<dyn DatagramLink>, CoreError>> {
            Box::pin(async { Err(CoreError::Closed) })
        }
    }

    struct DummyStTr;
    impl StreamTransitHandler for DummyStTr {
        fn caps(&self) -> ChannelCaps {
            ChannelCaps::fixed(16_384, true)
        }
        fn open<'a>(&'a self, _t: &'a str, _a: SessionAuth) -> BoxFuture<'a, Result<BoxedStream, CoreError>> {
            Box::pin(async { Err(CoreError::Closed) })
        }
    }

    struct DummyDgTr;
    impl DatagramTransitHandler for DummyDgTr {
        fn caps(&self) -> ChannelCaps {
            ChannelCaps::fixed(1232, false)
        }
        fn open<'a>(&'a self, _t: &'a str, _a: SessionAuth) -> BoxFuture<'a, Result<Arc<dyn DatagramLink>, CoreError>> {
            Box::pin(async { Err(CoreError::Closed) })
        }
    }

    #[test]
    fn endpoint_plane_rules_and_transit_longest_prefix_precedence() {
        let metrics = Arc::new(ScopeMetrics::new());
        let reg = Arc::new(PublishRegistry::new(metrics));

        // Datagram endpoint rejects < 1152 at publish time.
        assert_eq!(
            reg.publish_datagram_endpoint("dg", 1151, Arc::new(DummyDgEp)).unwrap_err(),
            CoreError::MtuTooSmall(1151)
        );
        let _dg_ep = reg.publish_datagram_endpoint("dg", 1152, Arc::new(DummyDgEp)).unwrap();
        // Single shared endpoint namespace rejects duplicate across planes!
        assert_eq!(
            reg.publish_stream_endpoint("dg", Arc::new(DummyStEp)).unwrap_err(),
            CoreError::AlreadyPublished
        );
        assert!(matches!(
            reg.resolve_endpoint("dg", Plane::Stream),
            Err(CoreError::WrongPlane)
        ));
        assert!(matches!(
            reg.resolve_endpoint("missing", Plane::Stream),
            Err(CoreError::Unpublished)
        ));

        // Transit precedence: exact > longest prefix (non-empty suffix) > opposite plane WrongPlane > Unpublished.
        let _g_short = reg.publish_stream_transit_prefix("relay/", Arc::new(DummyStTr)).unwrap();
        let _g_long = reg.publish_stream_transit_prefix("relay/eu/", Arc::new(DummyStTr)).unwrap();
        let _g_exact = reg.publish_stream_transit("relay/eu/bob", Arc::new(DummyStTr)).unwrap();
        let _g_dg_same = reg.publish_datagram_transit("relay/eu/bob", Arc::new(DummyDgTr)).unwrap();

        let r_exact = reg.resolve_transit("relay/eu/bob", Plane::Stream).unwrap();
        assert_eq!(r_exact.subtarget, "relay/eu/bob");
        assert_eq!(r_exact.matched_prefix, None);

        let r_long = reg.resolve_transit("relay/eu/alice", Plane::Stream).unwrap();
        assert_eq!(r_long.subtarget, "alice");
        assert_eq!(r_long.matched_prefix.as_deref(), Some("relay/eu/"));

        let r_short = reg.resolve_transit("relay/us", Plane::Stream).unwrap();
        assert_eq!(r_short.subtarget, "us");
        assert_eq!(r_short.matched_prefix.as_deref(), Some("relay/"));

        // Exact match on prefix string itself ("relay/") has EMPTY suffix -> must NOT match prefix!
        assert!(matches!(
            reg.resolve_transit("relay/", Plane::Stream),
            Err(CoreError::Unpublished)
        ));

        // Target published only on Stream returns WrongPlane on Datagram.
        assert!(matches!(
            reg.resolve_transit("relay/us", Plane::Datagram),
            Err(CoreError::WrongPlane)
        ));
    }

    #[test]
    fn transit_revoker_and_guard_drop_stay_isolated_per_publication_id() {
        let clock = VirtualClock::new();
        let metrics = Arc::new(ScopeMetrics::new());
        let reg = Arc::new(PublishRegistry::new(metrics));
        let peer = PublicKey::from_bytes([5u8; 32]);

        let g_st = reg.publish_stream_transit_prefix("r/", Arc::new(DummyStTr)).unwrap();
        let g_dg = reg.publish_datagram_transit_prefix("r/", Arc::new(DummyDgTr)).unwrap();
        let rev_st = g_st.revoker().unwrap();

        // Validate suffix bounds: empty or > 255 - 2 fails InvalidParameter.
        assert_eq!(rev_st.revoke_target(""), Err(CoreError::InvalidParameter));
        assert_eq!(
            rev_st.revoke_target(&"a".repeat(254)),
            Err(CoreError::InvalidParameter)
        );

        let res_st_a = reg.resolve_transit("r/alice", Plane::Stream).unwrap();
        let res_st_b = reg.resolve_transit("r/bob", Plane::Stream).unwrap();
        let res_dg_a = reg.resolve_transit("r/alice", Plane::Datagram).unwrap();

        let lease_st_a = LeaseHandle::new(peer, Lease::new(Duration::from_secs(60)), Duration::from_secs(60), clock.clone()).unwrap();
        let lease_st_b = LeaseHandle::new(peer, Lease::new(Duration::from_secs(60)), Duration::from_secs(60), clock.clone()).unwrap();
        let lease_dg_a = LeaseHandle::new(peer, Lease::new(Duration::from_secs(60)), Duration::from_secs(60), clock.clone()).unwrap();

        let t_st_a = TransitEpochTarget {
            peer,
            plane: Plane::Stream,
            full_name: "r/alice",
            matched_prefix: Some("r/"),
            pub_id: res_st_a.pub_id,
            subtarget: "alice",
        };
        let t_st_b = TransitEpochTarget {
            peer,
            plane: Plane::Stream,
            full_name: "r/bob",
            matched_prefix: Some("r/"),
            pub_id: res_st_b.pub_id,
            subtarget: "bob",
        };
        let t_dg_a = TransitEpochTarget {
            peer,
            plane: Plane::Datagram,
            full_name: "r/alice",
            matched_prefix: Some("r/"),
            pub_id: res_dg_a.pub_id,
            subtarget: "alice",
        };

        let snap_st_a = reg.epoch_for_transit(&t_st_a);
        let snap_st_b = reg.epoch_for_transit(&t_st_b);
        let snap_dg_a = reg.epoch_for_transit(&t_dg_a);

        reg.track_transit(&snap_st_a, &t_st_a, &res_st_a.active, &lease_st_a).unwrap();
        reg.track_transit(&snap_st_b, &t_st_b, &res_st_b.active, &lease_st_b).unwrap();
        reg.track_transit(&snap_dg_a, &t_dg_a, &res_dg_a.active, &lease_dg_a).unwrap();

        // Scoped revoke_target("alice") on Stream prefix revokes ONLY lease_st_a!
        rev_st.revoke_target("alice").unwrap();
        assert_eq!(lease_st_a.remaining(), Err(CoreError::Revoked));
        assert!(lease_st_b.is_active());
        assert!(lease_dg_a.is_active());

        // Dropping g_st revokes lease_st_b with Unpublished, leaving Datagram lease_dg_a untouched!
        drop(g_st);
        assert_eq!(lease_st_b.remaining(), Err(CoreError::Unpublished));
        assert!(lease_dg_a.is_active());

        // Re-publishing "r/" on Stream gets a fresh PublicationId; dropping old guard already happened
        // and does not affect new publication; dropping g_dg revokes lease_dg_a.
        let _g_st2 = reg.publish_stream_transit_prefix("r/", Arc::new(DummyStTr)).unwrap();
        drop(g_dg);
        assert_eq!(lease_dg_a.remaining(), Err(CoreError::Unpublished));
    }

    #[test]
    fn toctou_revocation_blocks_racing_admission() {
        let clock = VirtualClock::new();
        let metrics = Arc::new(ScopeMetrics::new());
        let reg = Arc::new(PublishRegistry::new(metrics));
        let peer = PublicKey::from_bytes([8u8; 32]);

        let g_ep = reg.publish_stream_endpoint("api", Arc::new(DummyStEp)).unwrap();
        let snap = reg.epoch_for_endpoint(peer, Some("api"));

        // Authorizer Revocation::Peer fires while admission is in flight (does NOT add to vetoed).
        reg.revoke_peer_sessions_only(peer);
        assert!(!reg.is_vetoed(peer));

        let lease = LeaseHandle::new(peer, Lease::new(Duration::from_secs(30)), Duration::from_secs(60), clock).unwrap();
        assert_eq!(
            reg.track_endpoint(&snap, peer, Some(("api", g_ep.publication_id())), &lease),
            Err(CoreError::Revoked)
        );
    }

    #[test]
    fn unpublish_guard_reentrant_handler_drop_does_not_deadlock() {
        use std::sync::Mutex as StdMutex;

        struct ChainedEndpoint {
            _inner_guard: StdMutex<Option<PublishGuard>>,
        }
        impl StreamEndpointHandler for ChainedEndpoint {
            fn open(&self, _auth: SessionAuth) -> BoxFuture<'_, Result<BoxedStream, CoreError>> {
                Box::pin(async { Err(CoreError::Closed) })
            }
        }
        struct ChainedTransit {
            _inner_guard: StdMutex<Option<PublishGuard>>,
        }
        impl StreamTransitHandler for ChainedTransit {
            fn caps(&self) -> ChannelCaps {
                ChannelCaps::fixed(16_384, true)
            }
            fn open<'a>(
                &'a self,
                _t: &'a str,
                _a: SessionAuth,
            ) -> BoxFuture<'a, Result<BoxedStream, CoreError>> {
                Box::pin(async { Err(CoreError::Closed) })
            }
        }

        let metrics = Arc::new(ScopeMetrics::new());
        let reg = Arc::new(PublishRegistry::new(metrics));

        // Registry holds the sole Arc to outer handlers whose Drop drops an inner PublishGuard
        // in the exact same registry -> MUST NOT deadlock!
        let inner_ep = reg.publish_stream_endpoint("inner-ep", Arc::new(DummyStEp)).unwrap();
        let outer_ep = reg
            .publish_stream_endpoint(
                "outer-ep",
                Arc::new(ChainedEndpoint {
                    _inner_guard: StdMutex::new(Some(inner_ep)),
                }),
            )
            .unwrap();
        drop(outer_ep);
        assert!(matches!(
            reg.resolve_endpoint("outer-ep", Plane::Stream),
            Err(CoreError::Unpublished)
        ));
        assert!(matches!(
            reg.resolve_endpoint("inner-ep", Plane::Stream),
            Err(CoreError::Unpublished)
        ));

        let inner_tr = reg
            .publish_stream_transit_prefix("inner/", Arc::new(DummyStTr))
            .unwrap();
        let outer_tr = reg
            .publish_stream_transit(
                "outer-tr",
                Arc::new(ChainedTransit {
                    _inner_guard: StdMutex::new(Some(inner_tr)),
                }),
            )
            .unwrap();
        drop(outer_tr);
        assert!(matches!(
            reg.resolve_transit("outer-tr", Plane::Stream),
            Err(CoreError::Unpublished)
        ));
        assert!(matches!(
            reg.resolve_transit("inner/x", Plane::Stream),
            Err(CoreError::Unpublished)
        ));
    }

    #[test]
    fn transit_guard_drop_does_not_abort_overlapping_exact_or_prefix_setup() {
        let clock = VirtualClock::new();
        let metrics = Arc::new(ScopeMetrics::new());
        let reg = Arc::new(PublishRegistry::new(metrics));
        let peer = PublicKey::from_bytes([0x42; 32]);

        // Publish BOTH an exact Stream transit "relay/" AND a prefix Stream transit "relay/".
        let g_exact = reg.publish_stream_transit("relay/", Arc::new(DummyStTr)).unwrap();
        let g_prefix = reg
            .publish_stream_transit_prefix("relay/", Arc::new(DummyStTr))
            .unwrap();

        // Setup for "relay/alice" resolves through the prefix and captures its epoch snapshot.
        let res_prefix = reg.resolve_transit("relay/alice", Plane::Stream).unwrap();
        assert_eq!(res_prefix.pub_id, g_prefix.publication_id());
        assert_eq!(res_prefix.matched_prefix.as_deref(), Some("relay/"));
        let target_prefix = TransitEpochTarget {
            peer,
            plane: Plane::Stream,
            full_name: "relay/alice",
            matched_prefix: res_prefix.matched_prefix.as_deref(),
            pub_id: res_prefix.pub_id,
            subtarget: &res_prefix.subtarget,
        };
        let snap_prefix = reg.epoch_for_transit(&target_prefix);

        // Concurrently, an exact setup for "relay/" also starts in flight.
        let res_exact = reg.resolve_transit("relay/", Plane::Stream).unwrap();
        assert_eq!(res_exact.pub_id, g_exact.publication_id());
        let target_exact = TransitEpochTarget {
            peer,
            plane: Plane::Stream,
            full_name: "relay/",
            matched_prefix: None,
            pub_id: res_exact.pub_id,
            subtarget: &res_exact.subtarget,
        };
        let snap_exact = reg.epoch_for_transit(&target_exact);

        // Drop the EXACT guard while BOTH setups are awaiting authorization!
        drop(g_exact);

        let lease_exact =
            LeaseHandle::from_ttl(peer, Duration::from_secs(30), Duration::from_secs(60), clock.clone())
                .unwrap();
        let lease_prefix =
            LeaseHandle::from_ttl(peer, Duration::from_secs(30), Duration::from_secs(60), clock.clone())
                .unwrap();

        // The dropped exact setup MUST fail with Unpublished (via `active == false`).
        assert_eq!(
            reg.track_transit(&snap_exact, &target_exact, &res_exact.active, &lease_exact),
            Err(CoreError::Unpublished)
        );
        // The overlapping prefix setup MUST SUCCEED because its own publication is still active!
        assert_eq!(
            reg.track_transit(&snap_prefix, &target_prefix, &res_prefix.active, &lease_prefix),
            Ok(())
        );
        assert!(lease_prefix.is_active());

        // Symmetric check: re-publish exact "relay/", start exact setup, drop prefix guard.
        let g_exact2 = reg.publish_stream_transit("relay/", Arc::new(DummyStTr)).unwrap();
        let res_exact2 = reg.resolve_transit("relay/", Plane::Stream).unwrap();
        let target_exact2 = TransitEpochTarget {
            peer,
            plane: Plane::Stream,
            full_name: "relay/",
            matched_prefix: None,
            pub_id: res_exact2.pub_id,
            subtarget: &res_exact2.subtarget,
        };
        let snap_exact2 = reg.epoch_for_transit(&target_exact2);

        drop(g_prefix);
        assert_eq!(lease_prefix.remaining(), Err(CoreError::Unpublished));

        let lease_exact2 =
            LeaseHandle::from_ttl(peer, Duration::from_secs(30), Duration::from_secs(60), clock.clone())
                .unwrap();
        assert_eq!(
            reg.track_transit(&snap_exact2, &target_exact2, &res_exact2.active, &lease_exact2),
            Ok(())
        );
        assert!(lease_exact2.is_active());

        // Explicit name-wide revoke_transit("relay/") MUST still bump epoch & abort in-flight setups.
        let snap_before_revoke = reg.epoch_for_transit(&target_exact2);
        reg.revoke_transit("relay/");
        assert_eq!(lease_exact2.remaining(), Err(CoreError::Revoked));
        let lease_exact3 =
            LeaseHandle::from_ttl(peer, Duration::from_secs(30), Duration::from_secs(60), clock)
                .unwrap();
        assert_eq!(
            reg.track_transit(&snap_before_revoke, &target_exact2, &res_exact2.active, &lease_exact3),
            Err(CoreError::Revoked)
        );
        drop(g_exact2);
    }

    #[test]
    fn revoke_all_establishes_consistent_admission_cutoff_across_shards() {
        use std::sync::Barrier;
        use std::thread;

        let clock = VirtualClock::new();
        let metrics = Arc::new(ScopeMetrics::new());
        let reg = Arc::new(PublishRegistry::new(metrics));

        // Stress 40 rounds with 6 concurrent admitter threads spanning distinct peers across all 16
        // shards racing against one `revoke_all` per round. Every post-cutoff admission (epoch ==
        // round + 1) MUST survive regardless of shard index, and every pre-cutoff admission
        // (epoch == round) MUST either fail `track_endpoint` with `Revoked` or be revoked.
        for round in 0..40u64 {
            let expected_after = round + 1;
            let barrier = Arc::new(Barrier::new(7));
            let mut handles = Vec::with_capacity(6);

            for tid in 0..6u64 {
                let reg_c = Arc::clone(&reg);
                let clock_c = clock.clone();
                let bar_c = Arc::clone(&barrier);
                handles.push(thread::spawn(move || {
                    let mut results = Vec::with_capacity(64);
                    bar_c.wait();
                    for i in 0..64u64 {
                        let mut pk = [0u8; 32];
                        pk[0..8].copy_from_slice(&round.to_be_bytes());
                        pk[8..16].copy_from_slice(&tid.to_be_bytes());
                        pk[16..24].copy_from_slice(&i.to_be_bytes());
                        let peer = PublicKey::from_bytes(pk);
                        let snap = reg_c.epoch_for_endpoint(peer, None);
                        let lease = LeaseHandle::from_ttl(
                            peer,
                            Duration::from_secs(60),
                            Duration::from_secs(60),
                            clock_c.clone(),
                        )
                        .unwrap();
                        let tracked = reg_c.track_endpoint(&snap, peer, None, &lease);
                        results.push((snap.global, tracked, lease));
                    }
                    results
                }));
            }

            let reg_r = Arc::clone(&reg);
            let bar_r = Arc::clone(&barrier);
            let revoker = thread::spawn(move || {
                bar_r.wait();
                thread::yield_now();
                reg_r.revoke_all(false);
            });

            revoker.join().unwrap();
            for h in handles {
                for (snap_epoch, tracked, lease) in h.join().unwrap() {
                    if snap_epoch == expected_after {
                        assert_eq!(
                            tracked,
                            Ok(()),
                            "post-cutoff admission must succeed"
                        );
                        assert!(
                            lease.is_active(),
                            "post-cutoff admission must NOT be revoked by earlier revoke_all"
                        );
                    } else {
                        assert!(
                            tracked == Err(CoreError::Revoked)
                                || lease.remaining() == Err(CoreError::Revoked),
                            "pre-cutoff admission must fail track or be revoked"
                        );
                    }
                }
            }
        }
    }
}
