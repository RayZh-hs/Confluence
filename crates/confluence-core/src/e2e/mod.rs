pub mod datagram;
pub(crate) mod renewal;
pub mod stream;

use std::sync::Arc;
use tokio::{
    sync::{OwnedSemaphorePermit, watch},
    time::Instant,
};

use crate::{
    AuthRequest, BoxFut, CoreErr, Lease, LeaseHandle, PendingSetup, Plane, PublicKey, SessionAuth,
    TargetRef, crypto::noise_ik::HopKey, scope::Scope,
};

pub(crate) struct AwaitingConfirm {
    pub deadline: Instant,
    _node: OwnedSemaphorePermit,
    _peer: PendingSetup,
}
impl AwaitingConfirm {
    pub fn new(node: OwnedSemaphorePermit, peer: PendingSetup) -> Self {
        Self {
            deadline: crate::path::setup_deadline(),
            _node: node,
            _peer: peer,
        }
    }
}

pub(crate) struct EndpointAuth {
    pub scope: Arc<Scope>,
    pub name: String,
    pub peer: PublicKey,
    pub plane: Plane,
    pub lease: Arc<LeaseHandle>,
    pub terminal_key: HopKey,
}
impl EndpointAuth {
    pub fn session_auth(&self) -> SessionAuth {
        self.lease.session_auth(self.peer)
    }

    pub fn renewal(&self, credential: Vec<u8>) -> BoxFut<'static, Result<[u8; 8], CoreErr>> {
        let (scope, name, peer, plane, lease) = (
            self.scope.clone(),
            self.name.clone(),
            self.peer,
            self.plane,
            self.lease.clone(),
        );
        Box::pin(async move {
            let renewed = scope
                .auth
                .authorize(AuthRequest {
                    peer,
                    target: TargetRef::Endpoint { name: &name, plane },
                    credential: &credential,
                    is_renewal: true,
                })
                .await?;
            let wire_ttl = Lease::wire_ttl_bytes(renewed.ttl);
            scope.auth.renew_lease_from(&lease, renewed)?;
            Ok(wire_ttl)
        })
    }
}

pub(crate) struct Lifetime(pub watch::Sender<Option<CoreErr>>);
impl Drop for Lifetime {
    fn drop(&mut self) {
        self.0.send_if_modified(|state| {
            if state.is_some() {
                return false;
            }
            *state = Some(CoreErr::Closed);
            true
        });
    }
}
pub(crate) async fn cancellation(signal: &watch::Sender<Option<CoreErr>>) -> CoreErr {
    let mut rx = signal.subscribe();
    loop {
        if let Some(error) = rx.borrow_and_update().clone() {
            return error;
        }
        if rx.changed().await.is_err() {
            return CoreErr::Closed;
        }
    }
}
pub(crate) fn record_error(error: &CoreErr) -> [u8; 4] {
    let (code, value) = crate::wire::setup::error_code(error);
    let mut body = [0; 4];
    body[..2].copy_from_slice(&code.to_be_bytes());
    body[2..].copy_from_slice(&value.to_be_bytes());
    body
}
