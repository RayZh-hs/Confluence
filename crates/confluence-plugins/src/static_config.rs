use confluence_core::{
    AccessControl, ActionRef, BoxFut, CoreErr, ExplicitPath, PathOutcome, PathSource, Plane,
    PolicyDenied, PublicKey, Revocation, ScopeId, grant::GrantSpec,
};
use std::{collections::HashMap, sync::RwLock};
use tokio::sync::broadcast;

#[derive(Default)]
pub struct StaticAcl {
    grants: RwLock<HashMap<(ScopeId, PublicKey), GrantSpec>>,
    events: RwLock<HashMap<ScopeId, broadcast::Sender<Revocation>>>,
}
impl StaticAcl {
    pub fn allow(&self, scope: ScopeId, peer: PublicKey, grant: GrantSpec) {
        self.grants.write().unwrap().insert((scope, peer), grant);
    }
    pub fn revoke(&self, scope: ScopeId, peer: PublicKey) {
        self.grants.write().unwrap().remove(&(scope, peer));
        if let Some(events) = self.events.read().unwrap().get(&scope) {
            let _ = events.send(Revocation::Peer(peer));
        }
    }
}
impl AccessControl for StaticAcl {
    fn verify<'a>(
        &'a self,
        scope: ScopeId,
        peer: &'a PublicKey,
        _action: ActionRef<'a>,
        _credential: &'a [u8],
    ) -> BoxFut<'a, Result<GrantSpec, PolicyDenied>> {
        Box::pin(async move {
            self.grants
                .read()
                .unwrap()
                .get(&(scope, *peer))
                .copied()
                .ok_or(PolicyDenied)
        })
    }
    fn revocations(&self, scope: ScopeId) -> Option<broadcast::Receiver<Revocation>> {
        Some(
            self.events
                .write()
                .unwrap()
                .entry(scope)
                .or_insert_with(|| broadcast::channel(128).0)
                .subscribe(),
        )
    }
}

type RouteKey = (ScopeId, PublicKey, String, Plane);
pub struct StaticPathSource {
    routes: RwLock<HashMap<RouteKey, ExplicitPath>>,
    outcomes: broadcast::Sender<(u64, PathOutcome)>,
}
impl Default for StaticPathSource {
    fn default() -> Self {
        Self {
            routes: Default::default(),
            outcomes: broadcast::channel(128).0,
        }
    }
}
impl StaticPathSource {
    pub fn set(
        &self,
        scope: ScopeId,
        peer: PublicKey,
        endpoint: impl Into<String>,
        plane: Plane,
        path: ExplicitPath,
    ) {
        self.routes
            .write()
            .unwrap()
            .insert((scope, peer, endpoint.into(), plane), path);
    }
    pub fn outcomes(&self) -> broadcast::Receiver<(u64, PathOutcome)> {
        self.outcomes.subscribe()
    }
}
impl PathSource for StaticPathSource {
    fn resolve_path<'a>(
        &'a self,
        scope: ScopeId,
        peer: &'a PublicKey,
        endpoint: &'a str,
        plane: Plane,
    ) -> BoxFut<'a, Result<ExplicitPath, CoreErr>> {
        Box::pin(async move {
            self.routes
                .read()
                .unwrap()
                .get(&(scope, *peer, endpoint.into(), plane))
                .cloned()
                .ok_or(CoreErr::NoPath)
        })
    }
    fn report_outcome(&self, path_id: u64, outcome: PathOutcome) {
        let _ = self.outcomes.send((path_id, outcome));
    }
}
