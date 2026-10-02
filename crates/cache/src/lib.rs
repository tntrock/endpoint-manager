//! 分點快取程式：就近提供派送套件給據點的端點。

pub mod auth;
pub mod central;
pub mod config;
pub mod fetch;
pub mod identity;
pub mod logfile;
pub mod run;
pub mod server;
#[cfg(windows)]
pub mod service;
pub mod store;
