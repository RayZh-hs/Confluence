//! Reusable cryptographic, anti-replay, DoS cookie, and Grant enforcement building blocks
//! shared by `confluence-core`'s E2E Trust Boundary and composable channel plugins.

pub mod cookie;
pub mod grant;
pub mod noise;
pub mod replay;
