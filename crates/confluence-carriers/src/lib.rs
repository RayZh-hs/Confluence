#![forbid(unsafe_code)]
//! Transport carriers and composable vertical channel middleware (`NoiseAclDatagramChannel` &
//! `NoiseAclStreamChannel`) implementing Confluence Seam 1.

pub mod noise_acl;

pub use noise_acl::{NoiseAclDatagramChannel, NoiseAclStreamChannel};
