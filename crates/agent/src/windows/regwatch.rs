//! RegNotifyChangeKeyValue：機碼（含子機碼）有變更時呼叫 on_change。

use protocol::Section;
use tokio::sync::mpsc;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_NOTIFY, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
    REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME, RegCloseKey, RegNotifyChangeKeyValue,
    RegOpenKeyExW,
};

use super::registry::UNINSTALL;

/// 可監聽的根機碼（用列舉而非裸 HKEY，避免呼叫端傳入無效指標）。
#[derive(Debug, Clone, Copy)]
pub enum Root {
    LocalMachine,
    CurrentUser,
}

impl Root {
    pub(crate) fn hkey(self) -> HKEY {
        match self {
            Root::LocalMachine => HKEY_LOCAL_MACHINE,
            Root::CurrentUser => HKEY_CURRENT_USER,
        }
    }
}

/// 監聽機碼與子機碼：新增／刪除機碼（NAME）與值的變更（LAST_SET）。
pub fn watch(
    root: Root,
    path: &str,
    wow64: u32,
    on_change: impl Fn() + Send + 'static,
) -> std::io::Result<()> {
    watch_filtered(
        root,
        path,
        wow64,
        REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
        on_change,
    )
}

fn watch_filtered(
    root: Root,
    path: &str,
    wow64: u32,
    filter: u32,
    on_change: impl Fn() + Send + 'static,
) -> std::io::Result<()> {
    let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let mut key: HKEY = std::ptr::null_mut();
    let rc = unsafe { RegOpenKeyExW(root.hkey(), wide.as_ptr(), 0, KEY_NOTIFY | wow64, &mut key) };
    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(rc as i32));
    }
    let key = key as usize; // HKEY 是裸指標，轉成 usize 才能移到執行緒
    std::thread::spawn(move || {
        loop {
            let rc =
                unsafe { RegNotifyChangeKeyValue(key as HKEY, 1, filter, std::ptr::null_mut(), 0) };
            if rc != 0 {
                unsafe { RegCloseKey(key as HKEY) };
                return;
            }
            on_change();
        }
    });
    Ok(())
}

/// 監聽 HKLM 64／32 位元 Uninstall 機碼；HKU 變動太頻繁，只靠每小時補收。
pub fn watch_software(tx: mpsc::Sender<Section>) {
    for wow in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
        let tx = tx.clone();
        if let Err(e) = watch(Root::LocalMachine, UNINSTALL, wow, move || {
            let _ = tx.try_send(Section::Software);
        }) {
            tracing::warn!(error = %e, "cannot watch Uninstall key");
        }
    }
}

/// 安裝更新（KB）時 CBS 會新增套件機碼：觸發重新收集 patches（Windows Update 完成時）。
pub const CBS_PACKAGES: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages";

/// 更新安裝期間 CBS 機碼會持續變動數十分鐘：只看新增套件機碼（NAME），且最多每 5 分鐘觸發一次，
/// 避免 Agent 不停提早報到，也避免塞滿觸發通道把軟體變更擠掉。
pub const PATCHES_MIN_GAP: std::time::Duration = std::time::Duration::from_secs(300);

pub fn watch_patches(tx: mpsc::Sender<Section>) {
    let throttle = crate::schedule::Throttle::new(PATCHES_MIN_GAP);
    let on_change = move || {
        if throttle.allow(std::time::Instant::now()) {
            let _ = tx.try_send(Section::Patches);
        }
    };
    if let Err(e) = watch_filtered(
        Root::LocalMachine,
        CBS_PACKAGES,
        KEY_WOW64_64KEY,
        REG_NOTIFY_CHANGE_NAME,
        on_change,
    ) {
        tracing::warn!(error = %e, "cannot watch Component Based Servicing key");
    }
}
