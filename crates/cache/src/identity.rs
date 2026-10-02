//! 快取的身分：金鑰、憑證、註冊資訊（enroll.json）。都放在資料目錄。

use std::path::Path;

use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::write_atomic;

const ENROLL_FILE: &str = "enroll.json";
const KEY_FILE: &str = "key.pem";
const CERT_FILE: &str = "cert.pem";
const KEY_NEW: &str = "key.pem.new";
const CERT_NEW: &str = "cert.pem.new";
const PENDING_KEY: &str = "pending.key";
const ROOT_FILE: &str = "root.pem";

/// 註冊後中央給的 id 與輪詢密鑰（停用後重新啟用時也靠它取得新憑證）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrollment {
    pub cache_id: i64,
    pub poll_secret: String,
}

/// 成對的私鑰與憑證鏈（快取本身 + 中繼 CA）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub key_pem: String,
    pub chain_pem: String,
}

pub fn new_key_and_csr() -> anyhow::Result<(String, String)> {
    let key = rcgen::KeyPair::generate()?;
    let csr = rcgen::CertificateParams::default()
        .serialize_request(&key)?
        .pem()?;
    Ok((key.serialize_pem(), csr))
}

fn read_optional(path: &Path) -> anyhow::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::Error::from(e).context(format!("reading {}", path.display()))),
    }
}

pub fn load_root(dir: &Path) -> anyhow::Result<String> {
    read_optional(&dir.join(ROOT_FILE))?.context("root.pem is missing")
}

pub fn load_enrollment(dir: &Path) -> anyhow::Result<Option<Enrollment>> {
    read_optional(&dir.join(ENROLL_FILE))?
        .map(|s| serde_json::from_str(&s).context("parsing enroll.json"))
        .transpose()
}

pub fn save_enrollment(dir: &Path, e: &Enrollment) -> anyhow::Result<()> {
    write_atomic(&dir.join(ENROLL_FILE), &serde_json::to_vec_pretty(e)?)?;
    Ok(())
}

pub fn save_pending_key(dir: &Path, key_pem: &str) -> anyhow::Result<()> {
    write_atomic(&dir.join(PENDING_KEY), key_pem.as_bytes())?;
    Ok(())
}

pub fn load_pending_key(dir: &Path) -> anyhow::Result<Option<String>> {
    read_optional(&dir.join(PENDING_KEY))
}

pub fn remove_pending_key(dir: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(dir.join(PENDING_KEY)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

/// 順序：寫 key.pem.new → 寫 cert.pem.new → 改名金鑰 → 改名憑證。
/// 任何一步中斷，load_identity 都能從殘檔還原出成對的金鑰與憑證。
pub fn save_identity(dir: &Path, id: &Identity) -> anyhow::Result<()> {
    write_atomic(&dir.join(KEY_NEW), id.key_pem.as_bytes())?;
    write_atomic(&dir.join(CERT_NEW), id.chain_pem.as_bytes())?;
    std::fs::rename(dir.join(KEY_NEW), dir.join(KEY_FILE))?;
    std::fs::rename(dir.join(CERT_NEW), dir.join(CERT_FILE))?;
    Ok(())
}

pub fn load_identity(dir: &Path) -> anyhow::Result<Option<Identity>> {
    let key_new = dir.join(KEY_NEW).exists();
    let cert_new = dir.join(CERT_NEW).exists();
    match (key_new, cert_new) {
        // 新的一對已寫好，還沒改名
        (true, true) => {
            std::fs::rename(dir.join(KEY_NEW), dir.join(KEY_FILE))?;
            std::fs::rename(dir.join(CERT_NEW), dir.join(CERT_FILE))?;
        }
        // 金鑰已改名，憑證還沒
        (false, true) => std::fs::rename(dir.join(CERT_NEW), dir.join(CERT_FILE))?,
        // 憑證還沒寫完：新金鑰作廢，沿用舊的一對
        (true, false) => std::fs::remove_file(dir.join(KEY_NEW))?,
        (false, false) => {}
    }
    let key = read_optional(&dir.join(KEY_FILE))?;
    let cert = read_optional(&dir.join(CERT_FILE))?;
    Ok(key
        .zip(cert)
        .map(|(key_pem, chain_pem)| Identity { key_pem, chain_pem }))
}

/// 憑證鏈第一張（快取本身）的到期時間
pub fn cert_not_after(chain_pem: &str) -> anyhow::Result<DateTime<Utc>> {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let der = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
        .next()
        .context("empty certificate chain")??;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)?;
    DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0).context("bad not_after")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(tag: &str) -> Identity {
        Identity {
            key_pem: format!("KEY {tag}"),
            chain_pem: format!("CERT {tag}"),
        }
    }

    #[test]
    fn identity_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_identity(dir.path()).unwrap().is_none());
        save_identity(dir.path(), &pair("a")).unwrap();
        assert_eq!(load_identity(dir.path()).unwrap(), Some(pair("a")));
        save_identity(dir.path(), &pair("b")).unwrap();
        assert_eq!(load_identity(dir.path()).unwrap(), Some(pair("b")));
    }

    #[test]
    fn interrupted_saves_keep_a_matching_pair() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        save_identity(d, &pair("old")).unwrap();
        // 只寫了新金鑰：還沒寫完，沿用舊的一對
        std::fs::write(d.join("key.pem.new"), "KEY new").unwrap();
        assert_eq!(load_identity(d).unwrap(), Some(pair("old")));
        assert!(!d.join("key.pem.new").exists());
        save_identity(d, &pair("old")).unwrap();

        // 兩個新檔都寫好了，還沒改名：完成改名
        std::fs::write(d.join("key.pem.new"), "KEY new").unwrap();
        std::fs::write(d.join("cert.pem.new"), "CERT new").unwrap();
        assert_eq!(load_identity(d).unwrap(), Some(pair("new")));

        // 金鑰已改名、憑證還沒：完成憑證的改名
        std::fs::write(d.join("key.pem"), "KEY newer").unwrap();
        std::fs::write(d.join("cert.pem.new"), "CERT newer").unwrap();
        assert_eq!(load_identity(d).unwrap(), Some(pair("newer")));
        assert!(!d.join("cert.pem.new").exists());
    }

    #[test]
    fn enrollment_and_pending_key() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_enrollment(dir.path()).unwrap().is_none());
        let e = Enrollment {
            cache_id: 7,
            poll_secret: "s".into(),
        };
        save_enrollment(dir.path(), &e).unwrap();
        assert_eq!(load_enrollment(dir.path()).unwrap(), Some(e));
        assert!(load_pending_key(dir.path()).unwrap().is_none());
        let (key, csr) = new_key_and_csr().unwrap();
        assert!(csr.contains("CERTIFICATE REQUEST"));
        save_pending_key(dir.path(), &key).unwrap();
        assert_eq!(load_pending_key(dir.path()).unwrap(), Some(key));
    }
}
