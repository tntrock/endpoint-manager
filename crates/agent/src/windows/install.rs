//! MSI 的 custom action 呼叫（SYSTEM 身分）：`configure` 於安裝／升級、`unconfigure` 於解除安裝。

use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceFailureActions,
    ServiceFailureResetPeriod,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::secdir::prepare_data_dir;
use super::service::SERVICE_NAME;
use crate::config::apply_install_config;

/// 先確保資料目錄可信（不可信就重建），之後才寫入 root.pem 與 config.json。
pub fn configure(
    data: &Path,
    server_url: Option<&str>,
    token: Option<&str>,
    root_ca: Option<&str>,
) -> anyhow::Result<()> {
    prepare_data_dir(data)?;
    apply_install_config(data, server_url, token, root_ca)
}

/// 失敗後 60 秒重啟（3 次）、24 小時重置；非當機的失敗（結束代碼非 0）也套用。
pub fn set_recovery() -> anyhow::Result<()> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let svc = mgr
        .open_service(
            SERVICE_NAME,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
        )
        .context("open service")?;
    let actions = (0..3)
        .map(|_| ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(60),
        })
        .collect();
    svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 3600)),
        reboot_msg: None,
        command: None,
        actions: Some(actions),
    })?;
    svc.set_failure_actions_on_non_crash_failures(true)?;
    Ok(())
}

pub fn unconfigure(data: &Path) -> anyhow::Result<()> {
    match std::fs::remove_dir_all(data) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

/// `--name value`；空字串視為未提供（MSI 未設屬性時傳 ""）。
pub fn flag(args: &[OsString], name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    let v = args.get(i + 1)?.to_string_lossy().trim().to_string();
    (!v.is_empty()).then_some(v)
}
