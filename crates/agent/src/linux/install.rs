//! 安裝腳本（root）呼叫：`configure` 於安裝／升級、`unconfigure` 於解除安裝。

use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::Path;

use super::exec::{CMD_TIMEOUT, is_not_found, run_capture};
use crate::config::apply_install_config;

/// 資料目錄不存在就建立（0700）；存在時擁有者必須是目前的使用者（避免用別人預先建好的目錄）。
fn prepare_data_dir(data: &Path) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(data) {
        Ok(m) => {
            // SAFETY: geteuid 沒有前置條件。
            let uid = unsafe { libc::geteuid() };
            anyhow::ensure!(
                m.is_dir() && m.uid() == uid,
                "資料目錄擁有者不正確：{}",
                data.display()
            );
            std::fs::set_permissions(data, std::fs::Permissions::from_mode(0o700))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(data)?;
            std::fs::set_permissions(data, std::fs::Permissions::from_mode(0o700))?;
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// 先確保資料目錄可信，之後才寫入 root.pem 與 config.json；成功後啟動服務。
pub fn configure(
    data: &Path,
    server_url: Option<&str>,
    token: Option<&str>,
    root_ca: Option<&str>,
) -> anyhow::Result<()> {
    prepare_data_dir(data)?;
    apply_install_config(data, server_url, token, root_ca)?;
    // 沒有 systemd（容器、WSL）或啟動失敗都不讓安裝失敗
    match run_capture("systemctl", &["start", "endpoint-agent"], CMD_TIMEOUT) {
        Ok(_) => {}
        Err(e) if is_not_found(&e) => eprintln!("警告：找不到 systemctl：{e}"),
        Err(e) => eprintln!("警告：systemctl start endpoint-agent 失敗：{e:#}"),
    }
    Ok(())
}

pub fn unconfigure(data: &Path) -> anyhow::Result<()> {
    match std::fs::remove_dir_all(data) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn configure_creates_private_dir() {
        // main 在啟動時設 umask 077；單元測試不經 main，所以在這裡先設
        // SAFETY: umask 沒有前置條件。
        unsafe { libc::umask(0o077) };
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        let key = rcgen::KeyPair::generate().unwrap();
        let pem = rcgen::CertificateParams::default()
            .self_signed(&key)
            .unwrap()
            .pem();
        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        configure(
            &data,
            Some("https://em.corp.local:8443"),
            Some("tok"),
            Some(&b64),
        )
        .unwrap();
        let mode = std::fs::metadata(&data).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        assert!(data.join("root.pem").exists() && data.join("config.json").exists());
        let mode = |f: &str| {
            std::fs::metadata(data.join(f))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode("config.json"), 0o600);
        assert_eq!(mode("root.pem"), 0o600);
        unconfigure(&data).unwrap();
        assert!(!data.exists());
        unconfigure(&data).unwrap();
    }
}
