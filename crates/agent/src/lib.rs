//! Endpoint Manager Windows Agent。

pub mod agent;
pub mod backoff;
pub mod client;
pub mod collector;
pub mod config;
pub mod sanitize;
pub mod schedule;
pub mod serde_util;
pub mod software;
pub mod state;
#[cfg(windows)]
pub mod windows;
