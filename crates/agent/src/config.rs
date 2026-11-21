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
    /// 信任的簽章公鑰（Base64）。非空時只執行有效簽章的腳本與套件。只能在本機設定
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signing_keys: Vec<String>,
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
/// `signing_keys` 有值（逗號或空白分隔）就取代信任的公鑰清單，格式錯誤則失敗。
pub fn merge_config(
    existing: Option<AgentConfig>,
    enrolled: bool,
    server_url: Option<&str>,
    token: Option<&str>,
    signing_keys: Option<&str>,
) -> anyhow::Result<AgentConfig> {
    let server_url = server_url
        .map(String::from)
        .or_else(|| existing.as_ref().map(|c| c.server_url.clone()))
        .context("SERVER_URL is required on first install")?;
    anyhow::ensure!(
        server_url.starts_with("https://"),
        "SERVER_URL must start with https://"
    );
    let given = signing_keys
        .map(|list| {
            protocol::signing::parse_public_keys(
                list.split(|c: char| c == ',' || c.is_whitespace()),
            )
            .context("SIGNING_KEYS")
        })
        .transpose()?;
    // 沒給或只有分隔符號：沿用（不會因為漏填而默默關掉強制簽章）
    let signing_keys = match given {
        Some(keys) if !keys.is_empty() => keys,
        _ => existing
            .as_ref()
            .map(|c| c.signing_keys.clone())
            .unwrap_or_default(),
    };
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
        signing_keys,
    })
}

/// 安裝時寫入 root.pem（有提供才寫，否則沿用）與合併後的 config.json。資料目錄須已可信。
/// 先全部驗證再寫檔，失敗時不留下只改了一半的設定。
pub fn apply_install_config(
    data: &Path,
    server_url: Option<&str>,
    token: Option<&str>,
    root_ca: Option<&str>,
    signing_keys: Option<&str>,
) -> anyhow::Result<()> {
    let root_path = data.join("root.pem");
    let root_pem = root_ca.map(root_pem_from_b64).transpose()?;
    anyhow::ensure!(
        root_pem.is_some() || root_path.exists(),
        "ROOT_CA is required on first install"
    );
    let existing = AgentConfig::load(data).ok();
    let enrolled = crate::state::AgentState::load(data)?.is_enrolled();
    let config = merge_config(existing, enrolled, server_url, token, signing_keys)?;
    if let Some(pem) = root_pem {
        write_atomic(&root_path, pem.as_bytes())?;
    }
    config.save(data)
}

/// `--name value`；空字串視為未提供（MSI 未設屬性時傳 ""）。
pub fn flag(args: &[std::ffi::OsString], name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    let v = args.get(i + 1)?.to_string_lossy().trim().to_string();
    (!v.is_empty()).then_some(v)
}

/// `--signing-key K`（可重複）與 `--signing-keys K1,K2`（MSI 的 SIGNING_KEYS）合併；都沒有就是 None。
pub fn signing_keys_arg(args: &[std::ffi::OsString]) -> Option<String> {
    let mut out = vec![];
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if (a == "--signing-key" || a == "--signing-keys")
            && let Some(v) = it.next()
        {
            out.push(v.to_string_lossy().trim().to_string());
        }
    }
    out.retain(|v| !v.is_empty());
    (!out.is_empty()).then(|| out.join(","))
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
            signing_keys: vec![],
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
            signing_keys: vec![],
        }
    }

    #[test]
    fn merge_fresh_install_needs_url() {
        assert!(merge_config(None, false, None, Some("t"), None).is_err());
        assert!(merge_config(None, false, Some("http://x"), None, None).is_err());
        assert_eq!(
            merge_config(None, false, Some("https://a:8443"), Some("t"), None).unwrap(),
            cfg("https://a:8443", Some("t"))
        );
    }

    #[test]
    fn merge_upgrade_keeps_existing_values() {
        let old = cfg("https://a:8443", Some("t"));
        assert_eq!(
            merge_config(Some(old.clone()), false, None, None, None).unwrap(),
            old
        );
        assert_eq!(
            merge_config(Some(old), false, Some("https://b:8443"), Some("u"), None).unwrap(),
            cfg("https://b:8443", Some("u"))
        );
    }

    #[test]
    fn merge_enrolled_never_writes_token_back() {
        let old = cfg("https://a:8443", None);
        assert_eq!(
            merge_config(Some(old.clone()), true, None, Some("t"), None).unwrap(),
            old
        );
        assert_eq!(
            merge_config(
                Some(cfg("https://a:8443", Some("stale"))),
                true,
                None,
                None,
                None
            )
            .unwrap()
            .enroll_token,
            None
        );
    }

    #[test]
    fn merge_signing_keys() {
        let k1 = protocol::signing::encode_public_key(&[1u8; 32]);
        let k2 = protocol::signing::encode_public_key(&[2u8; 32]);
        let fresh = merge_config(
            None,
            false,
            Some("https://a:8443"),
            Some("t"),
            Some(&format!(" {k1} , {k2} ")),
        )
        .unwrap();
        assert_eq!(fresh.signing_keys, vec![k1.clone(), k2.clone()]);
        // 沒給、只有分隔符號：沿用
        for keep in [None, Some(" , ")] {
            assert_eq!(
                merge_config(Some(fresh.clone()), true, None, None, keep)
                    .unwrap()
                    .signing_keys,
                vec![k1.clone(), k2.clone()]
            );
        }
        // 有值就取代
        assert_eq!(
            merge_config(Some(fresh.clone()), true, None, None, Some(&k2))
                .unwrap()
                .signing_keys,
            vec![k2.clone()]
        );
        // 格式錯誤：失敗，不會變成不強制
        let err = merge_config(Some(fresh), true, None, None, Some("not-a-key")).unwrap_err();
        assert!(format!("{err:#}").contains("SIGNING_KEYS"), "{err:#}");
        // 沒有公鑰時不寫進 config.json（舊版 Agent 讀得懂）
        let plain = cfg("https://a:8443", None);
        assert!(
            !String::from_utf8(serde_json::to_vec(&plain).unwrap())
                .unwrap()
                .contains("signing_keys")
        );
    }

    /// 驗證全部通過才寫檔：失敗的安裝回復後，不能留下換過的 root.pem。
    #[test]
    fn invalid_config_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("root.pem"), "old").unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let pem = rcgen::CertificateParams::default()
            .self_signed(&key)
            .unwrap()
            .pem();
        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        assert!(
            apply_install_config(dir.path(), Some("http://a:8443"), None, Some(&b64), None)
                .is_err()
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("root.pem")).unwrap(),
            "old"
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
        apply_install_config(dir.path(), Some("https://a:8443"), Some("tok"), None, None).unwrap();
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
