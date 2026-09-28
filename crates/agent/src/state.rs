//! state.json：裝置身分（含私鑰）與被拒區段；以原子方式寫入。

use std::collections::BTreeMap;
use std::path::Path;

use protocol::Section;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const FILE: &str = "state.json";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentState {
    pub device_id: Option<Uuid>,
    pub chain_pem: Option<String>,
    pub key_pem: Option<String>,
    /// 被伺服器拒絕的區段 → 被拒時的 hash；hash 改變前不再重送
    #[serde(default)]
    pub rejected: BTreeMap<Section, String>,
}

/// 寫入暫存檔並 fsync 後再 rename：斷電時不會留下寫一半或內容為零的檔案。
/// 暫存檔一律重新建立（不沿用可能被他人預先建立、帶著其他擁有者的檔案）。
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("json.tmp");
    match std::fs::remove_file(&tmp) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

impl AgentState {
    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        let path = dir.join(FILE);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.into()),
        };
        match serde_json::from_slice(&bytes) {
            Ok(s) => Ok(s),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "state.json is corrupt; moved to state.json.corrupt, re-enrollment required"
                );
                std::fs::rename(&path, dir.join("state.json.corrupt"))?;
                Ok(Self::default())
            }
        }
    }

    pub fn save(&self, dir: &Path) -> anyhow::Result<()> {
        write_atomic(&dir.join(FILE), &serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub fn is_enrolled(&self) -> bool {
        self.device_id.is_some() && self.chain_pem.is_some() && self.key_pem.is_some()
    }

    pub fn identity_pem(&self) -> Option<String> {
        Some(format!(
            "{}{}",
            self.chain_pem.as_ref()?,
            self.key_pem.as_ref()?
        ))
    }
}

/// 建立目錄；Windows 上移除繼承權限，只留 SYSTEM 與 Administrators（以 SID 指定，不受語系影響）。
pub fn secure_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(windows)]
    {
        let status = std::process::Command::new("icacls")
            .arg(dir)
            .args([
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
            ])
            .stdout(std::process::Stdio::null())
            .status()?;
        anyhow::ensure!(status.success(), "icacls failed on {}", dir.display());
    }
    Ok(())
}

/// 服務模式用：先把目錄與其下所有檔案的擁有者改為 Administrators 並重設子項 ACL，
/// 再套用 secure_dir。防止一般使用者搶先建立目錄或暫存檔、以擁有者身分改回權限。
/// 需要系統管理員權限。
pub fn harden_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(windows)]
    for args in [
        &["/setowner", "*S-1-5-32-544", "/T", "/C", "/Q"][..],
        &["/reset", "/T", "/C", "/Q"][..],
    ] {
        let status = std::process::Command::new("icacls")
            .arg(dir)
            .args(args)
            .stdout(std::process::Stdio::null())
            .status()?;
        anyhow::ensure!(
            status.success(),
            "icacls {args:?} failed on {}",
            dir.display()
        );
    }
    secure_dir(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_state_is_default() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(AgentState::load(dir.path()).unwrap(), AgentState::default());
    }

    #[test]
    fn roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = AgentState {
            device_id: Some(Uuid::new_v4()),
            chain_pem: Some("CHAIN".into()),
            key_pem: Some("KEY".into()),
            ..Default::default()
        };
        s.rejected.insert(Section::Software, "abc".into());
        s.save(dir.path()).unwrap();
        let back = AgentState::load(dir.path()).unwrap();
        assert_eq!(back, s);
        assert!(back.is_enrolled());
        assert_eq!(back.identity_pem().as_deref(), Some("CHAINKEY"));
        assert!(!dir.path().join("state.json.tmp").exists());
    }

    #[test]
    fn corrupt_state_is_set_aside() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("state.json"), b"{\"device_id\": \"not-a-uu").unwrap();
        assert_eq!(AgentState::load(dir.path()).unwrap(), AgentState::default());
        assert!(dir.path().join("state.json.corrupt").exists());
        assert!(!dir.path().join("state.json").exists());
    }
}
