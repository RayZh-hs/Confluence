use rand_core::{OsRng, RngCore};
use std::{sync::Arc, time::Duration};
use tokio::{sync::mpsc, time::Instant};

use crate::{
    CoreErr, CredentialTarget, Either, ExplicitPath, PathOutcome, PathSource, Plane,
    crypto::noise_ik::HopKey,
    grant::{GrantEnforcer, GrantSpec},
    race,
    wire::e2e::credential,
};

struct Lease {
    target: CredentialTarget,
    credential: Vec<u8>,
    refresh_at: Option<Instant>,
    expires_at: Option<Instant>,
}
impl Lease {
    fn with_grant(&mut self, spec: GrantSpec) {
        let now = Instant::now();
        let percent = 70 + (OsRng.next_u32() % 11);
        self.refresh_at = Some(now + spec.ttl.mul_f64(f64::from(percent) / 100.0));
        self.expires_at = Some(now + spec.ttl);
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
    pub path_id: u64,
    pub source: Arc<dyn PathSource>,
    pub hops: Vec<HopKey>,
    pub terminal: HopKey,
    reliable: bool,
    leases: Vec<Lease>,
}
pub(crate) type Request = (CredentialTarget, Vec<u8>);
pub(crate) type Ack = (CredentialTarget, GrantSpec);

impl Renewals {
    pub fn new(
        source: Arc<dyn PathSource>,
        path: &ExplicitPath,
        plane: Plane,
        cred: &[u8],
        hops: Vec<HopKey>,
        terminal: HopKey,
        spec: GrantSpec,
    ) -> Self {
        let now = Instant::now();
        let mut endpoint = Lease {
            target: CredentialTarget::Endpoint,
            credential: cred.to_vec(),
            refresh_at: Some(now),
            expires_at: None,
        };
        endpoint.with_grant(spec);
        let mut leases = vec![endpoint];
        leases.extend(path.hops.iter().enumerate().map(|(idx, hop)| Lease {
            target: CredentialTarget::Hop(idx as u8),
            credential: hop.credential.clone(),
            // SETUP_OK carries only the destination grant. Query each hop
            // immediately to learn its own TTL and start its refresh schedule.
            // Each hop enforces its own real GrantEnforcer expiry independently,
            // so we do not impose a synthetic 3s client-side expiry before learning it.
            refresh_at: Some(now),
            expires_at: None,
        }));
        Self {
            source,
            path_id: path.id,
            hops,
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
        grant: &GrantEnforcer,
    ) -> Result<(), CoreErr> {
        loop {
            let now = Instant::now();
            if self
                .leases
                .iter()
                .filter_map(Lease::next_deadline)
                .min()
                .is_some_and(|deadline| deadline <= now)
            {
                for lease in &mut self.leases {
                    if lease.expires_at.is_some_and(|expiry| expiry <= now) {
                        return Err(match lease.target {
                            CredentialTarget::Endpoint => CoreErr::Expired,
                            CredentialTarget::Hop(index) => CoreErr::HopRejected {
                                index,
                                reason: Box::new(CoreErr::Expired),
                            },
                        });
                    }
                    if lease.refresh_at.is_none_or(|refresh| refresh > now) {
                        continue;
                    }
                    let fresh = tokio::time::timeout(
                        Duration::from_millis(500),
                        self.source.refresh_credential(
                            self.path_id,
                            lease.target,
                            &lease.credential,
                        ),
                    )
                    .await
                    .map_err(|_| CoreErr::Timeout)??;
                    credential(&fresh)?;
                    requests
                        .send((lease.target, fresh.clone()))
                        .await
                        .map_err(|_| CoreErr::Closed)?;
                    lease.credential = fresh;
                    // On unreliable datagrams, retry with a fresh nonce until an
                    // authenticated reply arrives. On reliable streams, wait for
                    // the in-flight renewal instead of flooding a backpressured pipe.
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
                .filter_map(Lease::next_deadline)
                .min();
            let sleep = async {
                match next {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending().await,
                }
            };
            if let Either::Left(reply) = race(replies.recv(), sleep).await {
                let (target, spec) = reply.ok_or(CoreErr::Closed)?;
                if let Some(lease) = self.leases.iter_mut().find(|lease| lease.target == target) {
                    if target == CredentialTarget::Endpoint {
                        grant.renew(spec)?;
                    }
                    lease.with_grant(spec);
                }
            }
        }
    }
}
