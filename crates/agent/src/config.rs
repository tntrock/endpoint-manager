//! config.json：安裝時寫入（伺服器網址、註冊金鑰），註冊成功後移除金鑰。

use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::state::write_atomic;

pub const FILE: &str = "config.json";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentConfig {
    pub server_url: String,
    pub enroll_token: Option<String>,
}

impl AgentConfig {
    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        let path = dir.join(FILE);
        let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, dir: &Path) -> anyhow::Result<()> {
        write_atomic(&dir.join(FILE), &serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_clear_error_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let err = AgentConfig::load(dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("config.json"), "{err:#}");

        let c = AgentConfig {
            server_url: "https://em.corp.local:8443".into(),
            enroll_token: Some("tok".into()),
        };
        c.save(dir.path()).unwrap();
        assert_eq!(
            AgentConfig::load(dir.path())
                .unwrap()
                .enroll_token
                .as_deref(),
            Some("tok")
        );
    }
}
