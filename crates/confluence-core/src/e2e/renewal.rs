use rand_core::{OsRng, RngCore};
use std::{sync::Arc, time::Duration};
use tokio::{sync::mpsc, time::Instant};

use crate::{
    CoreErr, CredentialProvider, CredentialRequest, ExplicitPath, PathOutcome, PathSource, Plane,
    PublicKey, TargetRef,
    crypto::noise_ik::HopKey,
    lease::{LeaseHandle, MAX_WIRE_LEASE_TTL},
    wire::e2e::credential,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LeaseSlot {
    Endpoint,
    Hop(u8),
}

struct ActiveLease {
    slot: LeaseSlot,
    credential: Vec<u8>,
    refresh_at: Option<Instant>,
    expires_at: Option<Instant>,
}

impl ActiveLease {
    fn with_ttl(&mut self, ttl: Duration) {
        let now = Instant::now();
        let percent = 70 + (OsRng.next_u32() % 11);
        self.refresh_at = Some(now + ttl.mul_f64(f64::from(percent) / 100.0));
        self.expires_at = Some(now + ttl);
    }

    fn next_deadline(&self) -> Option<Instant> {
        match (self.refresh_at, self.expires_at) {
            (Some(refresh), Some(expiry)) => Some(refresh.min(expiry)),
            (Some(refresh), None) => Some(refresh),
            (None, Some(expiry)) => Some(expiry),
            (None, None) => None,
        }
    }
}

pub(crate) struct Renewals {
    pub peer: PublicKey,
    pub endpoint: String,
    pub plane: Plane,
    pub path_id: u64,
    pub source: Arc<dyn PathSource>,
    credentials: Arc<dyn CredentialProvider>,
    timeout: Duration,
    pub hops: Vec<HopKey>,
    hop_meta: Vec<(PublicKey, String)>,
    pub terminal: HopKey,
    reliable: bool,
    leases: Vec<ActiveLease>,
}

pub(crate) type Request = (LeaseSlot, Vec<u8>);
pub(crate) type Ack = (LeaseSlot, Duration);

impl Renewals {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        peer: PublicKey,
        endpoint: String,
        source: Arc<dyn PathSource>,
        credentials: Arc<dyn CredentialProvider>,
        timeout: Duration,
        path: &ExplicitPath,
        plane: Plane,
        dest_cred: Vec<u8>,
        hop_creds: Vec<Vec<u8>>,
        hops: Vec<HopKey>,
        hop_ttls: Vec<Duration>,
        terminal: HopKey,
        dest_ttl: Duration,
    ) -> Self {
        let now = Instant::now();
        let mut endpoint_lease = ActiveLease {
            slot: LeaseSlot::Endpoint,
            credential: dest_cred,
            refresh_at: Some(now),
            expires_at: None,
        };
        endpoint_lease.with_ttl(dest_ttl);
        let mut leases = vec![endpoint_lease];
        let hop_meta: Vec<_> = path
            .hops
            .iter()
            .map(|h| (h.peer, h.target.clone()))
            .collect();
        leases.extend(hop_creds.into_iter().enumerate().map(|(idx, cred)| {
            let mut lease = ActiveLease {
                slot: LeaseSlot::Hop(idx as u8),
                credential: cred,
                refresh_at: None,
                expires_at: None,
            };
            if let Some(&hop_ttl) = hop_ttls.get(idx) {
                lease.with_ttl(hop_ttl);
            } else {
                lease.refresh_at = Some(now);
            }
            lease
        }));
        Self {
            peer,
            endpoint,
            plane,
            path_id: path.id,
            source,
            credentials,
            timeout,
            hops,
            hop_meta,
            reliable: plane == Plane::Stream,
            leases,
            terminal,
        }
    }

    pub fn report(&self, outcome: PathOutcome) {
        self.source.report_outcome(self.path_id, outcome);
    }

    pub async fn drive(
        &mut self,
        requests: mpsc::Sender<Request>,
        mut replies: mpsc::Receiver<Ack>,
        lease_handle: &LeaseHandle,
    ) -> Result<(), CoreErr> {
        loop {
            let now = Instant::now();
            if self
                .leases
                .iter()
                .filter_map(ActiveLease::next_deadline)
                .min()
                .is_some_and(|deadline| deadline <= now)
            {
                for lease in &mut self.leases {
                    if lease.expires_at.is_some_and(|expiry| expiry <= now) {
                        return Err(match lease.slot {
                            LeaseSlot::Endpoint => CoreErr::Expired,
                            LeaseSlot::Hop(index) => CoreErr::HopRejected {
                                index,
                                reason: Box::new(CoreErr::Expired),
                            },
                        });
                    }
                    if lease.refresh_at.is_none_or(|refresh| refresh > now) {
                        continue;
                    }
                    let (verifier, target) = match lease.slot {
                        LeaseSlot::Endpoint => (
                            self.peer,
                            TargetRef::Endpoint {
                                name: &self.endpoint,
                                plane: self.plane,
                            },
                        ),
                        LeaseSlot::Hop(index) => {
                            let (hop_peer, hop_target) = self
                                .hop_meta
                                .get(usize::from(index))
                                .ok_or(CoreErr::Malformed)?;
                            (
                                *hop_peer,
                                TargetRef::Transit {
                                    name: hop_target,
                                    plane: self.plane,
                                },
                            )
                        }
                    };
                    let req = CredentialRequest {
                        verifier,
                        target,
                        destination: self.peer,
                        endpoint: &self.endpoint,
                        path_id: self.path_id,
                        is_refresh: true,
                        previous: &lease.credential,
                    };
                    let fresh =
                        tokio::time::timeout(self.timeout, self.credentials.credential(req))
                            .await
                            .map_err(|_| CoreErr::Timeout)??;
                    credential(&fresh)?;
                    requests
                        .send((lease.slot, fresh.clone()))
                        .await
                        .map_err(|_| CoreErr::Closed)?;
                    lease.credential = fresh;
                    lease.refresh_at = if self.reliable {
                        None
                    } else {
                        Some(Instant::now() + Duration::from_millis(100))
                    };
                }
            }
            let next = self
                .leases
                .iter()
                .filter_map(ActiveLease::next_deadline)
                .min();
            tokio::select! {
                reply = replies.recv() => {
                    let (slot, ttl) = reply.ok_or(CoreErr::Closed)?;
                    if let Some(lease) = self.leases.iter_mut().find(|l| l.slot == slot) {
                        if slot == LeaseSlot::Endpoint {
                            lease_handle.renew_with_max_ttl(ttl, MAX_WIRE_LEASE_TTL)?;
                        }
                        lease.with_ttl(ttl);
                    }
                }
                _ = async {
                    match next {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending().await,
                    }
                } => {}
            }
        }
    }
}
