//! Endpoint Manager Windows Agent。

pub mod agent;
pub mod backoff;
pub mod client;
pub mod collector;
pub mod commands;
pub mod config;
pub mod deploy;
#[cfg(target_os = "linux")]
pub mod linux;
pub mod linux_parse;
pub mod regvalue;
pub mod sanitize;
pub mod schedule;
pub mod serde_util;
pub mod software;
pub mod state;
pub mod updates;
#[cfg(windows)]
pub mod windows;
