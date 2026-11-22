use crate::{BoxFut, CoreErr, Plane, PublicKey, ScopeId};

pub type RouteErr = CoreErr;

#[derive(Clone, Debug)]
pub struct HopSpec {
    pub peer: PublicKey,
    pub channel: u64,
    pub locator: Vec<u8>,
    pub credential: Vec<u8>,
}
#[derive(Clone, Debug)]
pub struct ExplicitPath {
    pub id: u64,
    pub first_channel: u64,
    pub first_locator: Vec<u8>,
    pub min_mtu: u16,
    pub hops: Vec<HopSpec>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathOutcome {
    Established { mtu: u16 },
    MtuChanged { mtu: u16 },
    Failed(CoreErr),
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialTarget {
    Endpoint,
    Hop(u8),
}

pub trait PathSource: Send + Sync + 'static {
    fn resolve_path<'a>(
        &'a self,
        scope: ScopeId,
        peer: &'a PublicKey,
        endpoint: &'a str,
        plane: Plane,
    ) -> BoxFut<'a, Result<ExplicitPath, RouteErr>>;
    fn report_outcome(&self, path_id: u64, outcome: PathOutcome);
    fn refresh_credential<'a>(
        &'a self,
        _path_id: u64,
        _target: CredentialTarget,
        previous: &'a [u8],
    ) -> BoxFut<'a, Result<Vec<u8>, CoreErr>> {
        Box::pin(async { Ok(previous.to_vec()) })
    }
}
