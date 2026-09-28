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
    fn hkey(self) -> HKEY {
        match self {
            Root::LocalMachine => HKEY_LOCAL_MACHINE,
            Root::CurrentUser => HKEY_CURRENT_USER,
        }
    }
}

pub fn watch(
    root: Root,
    path: &str,
    wow64: u32,
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
            let rc = unsafe {
                RegNotifyChangeKeyValue(
                    key as HKEY,
                    1,
                    REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                    std::ptr::null_mut(),
                    0,
                )
            };
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

pub fn watch_patches(tx: mpsc::Sender<Section>) {
    if let Err(e) = watch(
        Root::LocalMachine,
        CBS_PACKAGES,
        KEY_WOW64_64KEY,
        move || {
            let _ = tx.try_send(Section::Patches);
        },
    ) {
        tracing::warn!(error = %e, "cannot watch Component Based Servicing key");
    }
}
