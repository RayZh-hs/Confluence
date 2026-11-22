pub(crate) mod dg_switch;
pub(crate) mod dialer;
pub(crate) mod inbound;
pub(crate) mod st_splice;

use crate::{CoreErr, SETUP_TIMEOUT};
use std::{future::Future, time::Duration};

pub(crate) fn setup_deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + SETUP_TIMEOUT
}

pub(crate) async fn timed<T>(
    future: impl Future<Output = Result<T, CoreErr>>,
) -> Result<T, CoreErr> {
    before(setup_deadline(), future).await
}

pub(crate) async fn before<T>(
    deadline: tokio::time::Instant,
    future: impl Future<Output = Result<T, CoreErr>>,
) -> Result<T, CoreErr> {
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| CoreErr::Timeout)?
}

pub(crate) async fn best_effort(future: impl Future<Output = Result<(), CoreErr>>) {
    let _ = tokio::time::timeout(Duration::from_millis(50), future).await;
}

pub(crate) async fn below_floor(mut mtu: crate::MtuWatch, floor: u16) -> CoreErr {
    loop {
        let limit = mtu.mtu_and_update();
        if limit < floor {
            return CoreErr::MtuTooSmall(limit);
        }
        if mtu.changed().await.is_err() {
            return std::future::pending().await;
        }
    }
}
