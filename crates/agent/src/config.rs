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

/// 安裝／升級時合併設定：命令列值優先，否則沿用既有值；已註冊就不再保留註冊金鑰。
pub fn merge_config(
    existing: Option<AgentConfig>,
    enrolled: bool,
    server_url: Option<&str>,
    token: Option<&str>,
) -> anyhow::Result<AgentConfig> {
    let server_url = server_url
        .map(String::from)
        .or_else(|| existing.as_ref().map(|c| c.server_url.clone()))
        .context("SERVER_URL is required on first install")?;
    anyhow::ensure!(
        server_url.starts_with("https://"),
        "SERVER_URL must start with https://"
    );
    let enroll_token = if enrolled {
        None
    } else {
        token
            .map(String::from)
            .or_else(|| existing.and_then(|c| c.enroll_token))
    };
    Ok(AgentConfig {
        server_url,
        enroll_token,
    })
}

/// 安裝時寫入 root.pem（有提供才寫，否則沿用）與合併後的 config.json。資料目錄須已強化。
pub fn apply_install_config(
    data: &Path,
    server_url: Option<&str>,
    token: Option<&str>,
    root_ca: Option<&str>,
) -> anyhow::Result<()> {
    let root_path = data.join("root.pem");
    match root_ca {
        Some(b64) => write_atomic(&root_path, root_pem_from_b64(b64)?.as_bytes())?,
        None => anyhow::ensure!(root_path.exists(), "ROOT_CA is required on first install"),
    }
    let existing = AgentConfig::load(data).ok();
    let enrolled = crate::state::AgentState::load(data)?.is_enrolled();
    merge_config(existing, enrolled, server_url, token)?.save(data)
}

/// MSI 的 ROOT_CA 屬性（單行 base64 DER）→ PEM；不是一張可解析的 X.509 憑證就拒絕。
pub fn root_pem_from_b64(b64: &str) -> anyhow::Result<String> {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let b64: String = b64.split_whitespace().collect();
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk)?);
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    let der =
        CertificateDer::from_pem_slice(pem.as_bytes()).context("ROOT_CA is not valid base64")?;
    x509_parser::parse_x509_certificate(&der).context("ROOT_CA is not an X.509 certificate")?;
    Ok(pem)
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

    fn cfg(url: &str, tok: Option<&str>) -> AgentConfig {
        AgentConfig {
            server_url: url.into(),
            enroll_token: tok.map(String::from),
        }
    }

    #[test]
    fn merge_fresh_install_needs_url() {
        assert!(merge_config(None, false, None, Some("t")).is_err());
        assert!(merge_config(None, false, Some("http://x"), None).is_err());
        assert_eq!(
            merge_config(None, false, Some("https://a:8443"), Some("t")).unwrap(),
            cfg("https://a:8443", Some("t"))
        );
    }

    #[test]
    fn merge_upgrade_keeps_existing_values() {
        let old = cfg("https://a:8443", Some("t"));
        assert_eq!(
            merge_config(Some(old.clone()), false, None, None).unwrap(),
            old
        );
        assert_eq!(
            merge_config(Some(old), false, Some("https://b:8443"), Some("u")).unwrap(),
            cfg("https://b:8443", Some("u"))
        );
    }

    #[test]
    fn merge_enrolled_never_writes_token_back() {
        let old = cfg("https://a:8443", None);
        assert_eq!(
            merge_config(Some(old.clone()), true, None, Some("t")).unwrap(),
            old
        );
        assert_eq!(
            merge_config(Some(cfg("https://a:8443", Some("stale"))), true, None, None)
                .unwrap()
                .enroll_token,
            None
        );
    }

    /// 狀態檔只有 device_id（沒有憑證或私鑰）無法報到，還需要金鑰重新註冊。
    #[test]
    fn partial_state_keeps_token() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("root.pem"), "x").unwrap();
        crate::state::AgentState {
            device_id: Some(uuid::Uuid::new_v4()),
            ..Default::default()
        }
        .save(dir.path())
        .unwrap();
        apply_install_config(dir.path(), Some("https://a:8443"), Some("tok"), None).unwrap();
        assert_eq!(
            AgentConfig::load(dir.path())
                .unwrap()
                .enroll_token
                .as_deref(),
            Some("tok")
        );
    }

    #[test]
    fn root_pem_roundtrip_and_rejects_garbage() {
        let key = rcgen::KeyPair::generate().unwrap();
        let pem = rcgen::CertificateParams::default()
            .self_signed(&key)
            .unwrap()
            .pem();
        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let back = root_pem_from_b64(&b64).unwrap();
        assert_eq!(
            back.replace(['\r', '\n'], ""),
            pem.replace(['\r', '\n'], "")
        );
        assert!(back.lines().all(|l| l.len() <= 64));
        assert!(root_pem_from_b64("bm90IGEgY2VydA==").is_err());
        assert!(root_pem_from_b64("***").is_err());
    }
}
