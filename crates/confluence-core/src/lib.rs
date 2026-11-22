#![forbid(unsafe_code)]

pub mod buf;
pub mod cid;
pub mod crypto;
pub mod e2e;
pub mod grant;
mod path;
pub mod scope;
pub mod seams;
pub mod wire;

use std::{
    future::Future,
    pin::{Pin, pin},
    task::Poll,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub use buf::PacketBuf;
pub use crypto::{PublicKey, ScopeKeypair};
pub use e2e::{datagram::E2eDatagram, stream::E2eStream};
pub use scope::{PublishGuard, ScopeInstance};
pub use seams::*;

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub const DATAGRAM_MTU: u16 = 1232;
pub const STREAM_CHUNK: usize = 16384;
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Plane {
    Datagram = 1,
    Stream = 2,
}
impl Plane {
    pub const fn minimum_mtu(self) -> u16 {
        match self {
            Self::Datagram => DATAGRAM_MTU,
            Self::Stream => (wire::e2e::ST_OVERHEAD + 1) as u16,
        }
    }
}

impl TryFrom<u8> for Plane {
    type Error = CoreErr;
    fn try_from(value: u8) -> Result<Self, CoreErr> {
        match value {
            1 => Ok(Self::Datagram),
            2 => Ok(Self::Stream),
            _ => Err(CoreErr::Malformed),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CoreErr {
    #[error("invalid frame or parameter")]
    Malformed,
    #[error("authentication failed")]
    Authentication,
    #[error("setup timed out")]
    Timeout,
    #[error("pending setup limit reached")]
    Busy,
    #[error("access denied")]
    Denied,
    #[error("grant expired")]
    Expired,
    #[error("access revoked")]
    Revoked,
    #[error("endpoint or channel is unpublished")]
    Unpublished,
    #[error("a publication already exists with this name")]
    AlreadyPublished,
    #[error("wrong transport plane")]
    WrongPlane,
    #[error("MTU too small ({0} bytes)")]
    MtuTooSmall(u16),
    #[error("message too large (maximum {0} bytes)")]
    MessageTooLarge(usize),
    #[error("target refused the connection")]
    TargetRefused,
    #[error("target unreachable")]
    TargetUnreachable,
    #[error("carrier closed before authenticated FIN")]
    UnexpectedEof,
    #[error("session closed")]
    Closed,
    #[error("session send queue is full")]
    WouldBlock,
    #[error("no explicit path")]
    NoPath,
    #[error("hop {index} rejected setup: {reason}")]
    HopRejected { index: u8, reason: Box<CoreErr> },
    #[error("carrier error: {0}")]
    Carrier(String),
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub(crate) enum Either<A, B> {
    Left(A),
    Right(B),
}
pub(crate) async fn race<A: Future, B: Future>(a: A, b: B) -> Either<A::Output, B::Output> {
    let mut a = pin!(a);
    let mut b = pin!(b);
    std::future::poll_fn(|cx| {
        if let Poll::Ready(value) = a.as_mut().poll(cx) {
            return Poll::Ready(Either::Left(value));
        }
        b.as_mut().poll(cx).map(Either::Right)
    })
    .await
}
