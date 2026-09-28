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

    /// 裝置憑證（chain 的第一張）的到期時間。
    pub fn cert_not_after(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        let der = CertificateDer::from_pem_slice(self.chain_pem.as_ref()?.as_bytes()).ok()?;
        let (_, cert) = x509_parser::parse_x509_certificate(&der).ok()?;
        chrono::DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
    }

    pub fn identity_pem(&self) -> Option<String> {
        Some(format!(
            "{}{}",
            self.chain_pem.as_ref()?,
            self.key_pem.as_ref()?
        ))
    }
}

const PROTECT: &[&str] = &[
    "/inheritance:r",
    "/grant:r",
    "*S-1-5-18:(OI)(CI)F",
    "*S-1-5-32-544:(OI)(CI)F",
];

#[cfg(windows)]
fn icacls(target: &Path, args: &[&str]) -> anyhow::Result<()> {
    let status = std::process::Command::new("icacls")
        .arg(target)
        .args(args)
        .stdout(std::process::Stdio::null())
        .status()?;
    anyhow::ensure!(
        status.success(),
        "icacls {args:?} failed on {}",
        target.display()
    );
    Ok(())
}

/// 建立目錄；Windows 上移除繼承權限，只留 SYSTEM 與 Administrators（以 SID 指定，不受語系影響）。
pub fn secure_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(windows)]
    icacls(dir, PROTECT)?;
    Ok(())
}

/// harden_dir 依序執行的 icacls（目標、參數）：
/// 1. 目錄與所有子項的擁有者改為 Administrators（原擁有者就不能再改回權限）；
/// 2. 目錄本身改為不繼承、只留 SYSTEM 與 Administrators；
/// 3. 子項重設為只繼承（此時目錄已受保護，繼承到的只有上一步的權限）。
///
/// 目錄本身絕不 /reset：那會暫時恢復繼承 ProgramData（Users 可讀）。
pub type Step = (std::path::PathBuf, &'static [&'static str]);

pub fn harden_steps(dir: &Path, has_children: bool) -> Vec<Step> {
    let mut steps: Vec<Step> = vec![
        (
            dir.to_path_buf(),
            &["/setowner", "*S-1-5-32-544", "/T", "/C", "/Q"],
        ),
        (dir.to_path_buf(), PROTECT),
    ];
    if has_children {
        steps.push((dir.join("*"), &["/reset", "/T", "/C", "/Q"]));
    }
    steps
}

/// 服務模式與安裝時用：防止一般使用者搶先建立目錄或暫存檔、以擁有者身分改回權限。
/// 需要系統管理員權限。
pub fn harden_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(windows)]
    {
        let has_children = std::fs::read_dir(dir)?.next().is_some();
        for (target, args) in harden_steps(dir, has_children) {
            icacls(&target, args)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 目錄本身不能被 /reset：那會暫時恢復繼承 ProgramData 的權限（Users 可讀），
    /// 讓一般使用者趁機開啟 state.json（含私鑰）並保留 handle。
    #[test]
    fn harden_never_resets_the_dir_itself() {
        let dir = Path::new(r"C:\ProgramData\EndpointManager");
        for has_children in [false, true] {
            let steps = harden_steps(dir, has_children);
            let pos = |f: &dyn Fn(&Step) -> bool| steps.iter().position(f);
            let owner = pos(&|(t, a)| t == dir && a.contains(&"/setowner")).expect("setowner");
            let protect =
                pos(&|(t, a)| t == dir && a.contains(&"/inheritance:r")).expect("protect");
            assert!(owner < protect, "先取得擁有權，擁有者才無法改回權限");
            assert!(
                !steps.iter().any(|(t, a)| t == dir && a.contains(&"/reset")),
                "{steps:?}"
            );
            match pos(&|(_, a)| a.contains(&"/reset")) {
                Some(reset) => {
                    assert!(has_children);
                    assert!(reset > protect, "子項要在目錄保護後才重設");
                    assert_eq!(steps[reset].0, dir.join("*"));
                }
                None => assert!(!has_children, "有子項時要重設子項的 ACL"),
            }
        }
    }

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
