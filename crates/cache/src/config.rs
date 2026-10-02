//! 資料目錄與 config.json（中央網址、監聽位址、儲存目錄、同時下載上限）。

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

pub const CONFIG_FILE: &str = "config.json";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub server_url: String,
    #[serde(default = "default_listen")]
    pub listen: String,
    /// None 表示 `<資料目錄>/packages`
    #[serde(default)]
    pub storage_dir: Option<PathBuf>,
    #[serde(default = "default_max_downloads")]
    pub max_downloads: usize,
}

fn default_listen() -> String {
    "0.0.0.0:8443".into()
}

fn default_max_downloads() -> usize {
    200
}

impl Config {
    pub fn load(dir: &Path) -> anyhow::Result<Config> {
        let path = dir.join(CONFIG_FILE);
        let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, dir: &Path) -> anyhow::Result<()> {
        write_atomic(&dir.join(CONFIG_FILE), &serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub fn storage(&self, dir: &Path) -> PathBuf {
        self.storage_dir
            .clone()
            .unwrap_or_else(|| dir.join("packages"))
    }
}

pub fn default_data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        let base = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
        PathBuf::from(base).join("EndpointManager").join("Cache")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/var/lib/endpoint-cache")
    }
}

/// 建立資料目錄並限制權限（私鑰放在這裡）。
/// Windows：只留 SYSTEM 與 Administrators（以 SID 設定，與語系無關）；Unix：0700。
pub fn secure_data_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(windows)]
    {
        let out = std::process::Command::new("icacls")
            .arg(dir)
            .args([
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
            ])
            .output()
            .context("running icacls")?;
        anyhow::ensure!(
            out.status.success(),
            "icacls failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// 先寫暫存檔再改名：中途失敗不會留下寫一半的檔案
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(CONFIG_FILE),
            r#"{"server_url":"https://em.corp:8443"}"#,
        )
        .unwrap();
        let c = Config::load(dir.path()).unwrap();
        assert_eq!(c.listen, "0.0.0.0:8443");
        assert_eq!(c.max_downloads, 200);
        assert_eq!(c.storage(dir.path()), dir.path().join("packages"));
        let c2 = Config {
            storage_dir: Some(dir.path().join("elsewhere")),
            ..c.clone()
        };
        c2.save(dir.path()).unwrap();
        assert_eq!(Config::load(dir.path()).unwrap(), c2);
        assert_eq!(c2.storage(dir.path()), dir.path().join("elsewhere"));
    }

    /// Windows 版會移除目前使用者的權限（測試環境沒有系統管理員權限），只在 Unix 測
    #[cfg(unix)]
    #[test]
    fn secure_data_dir_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("data");
        secure_data_dir(&d).unwrap();
        let mode = std::fs::metadata(&d).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }
}
