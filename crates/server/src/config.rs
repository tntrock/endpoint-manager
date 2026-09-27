//! 由環境變數讀取設定。

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub database_url: String,
    pub ca_dir: PathBuf,
    pub agent_listen: SocketAddr,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Config> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<Config> {
        Ok(Config {
            database_url: get("DATABASE_URL").context("DATABASE_URL is required")?,
            ca_dir: get("EM_CA_DIR").unwrap_or_else(|| "./pki".into()).into(),
            agent_listen: get("EM_AGENT_LISTEN")
                .unwrap_or_else(|| "0.0.0.0:8443".into())
                .parse()
                .context("EM_AGENT_LISTEN")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_required() {
        let c =
            Config::from_lookup(|k| (k == "DATABASE_URL").then(|| "postgres://x".into())).unwrap();
        assert_eq!(c.agent_listen.port(), 8443);
        assert_eq!(c.ca_dir, PathBuf::from("./pki"));
        assert!(Config::from_lookup(|_| None).is_err());
    }
}
