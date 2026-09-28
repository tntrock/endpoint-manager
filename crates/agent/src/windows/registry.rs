//! 讀取 Uninstall 機碼：HKLM 64／32 位元與已載入的使用者設定檔（HKU）。

use protocol::{Arch, SoftwareItem};
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY};

use crate::software::{UninstallEntry, is_user_sid, to_items};

pub const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

fn read_entries(root: &RegKey, path: &str, flags: u32) -> Vec<UninstallEntry> {
    let Ok(key) = root.open_subkey_with_flags(path, KEY_READ | flags) else {
        return vec![];
    };
    key.enum_keys()
        .filter_map(Result::ok)
        .filter_map(|name| key.open_subkey_with_flags(&name, KEY_READ | flags).ok())
        .map(|k| UninstallEntry {
            display_name: k.get_value("DisplayName").ok(),
            display_version: k.get_value("DisplayVersion").ok(),
            publisher: k.get_value("Publisher").ok(),
            install_date: k.get_value("InstallDate").ok(),
            system_component: k.get_value::<u32, _>("SystemComponent").ok(),
            parent_key_name: k.get_value("ParentKeyName").ok(),
            release_type: k.get_value("ReleaseType").ok(),
        })
        .collect()
}

pub fn read_all_software() -> Vec<SoftwareItem> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut items = to_items(&read_entries(&hklm, UNINSTALL, KEY_WOW64_64KEY), Arch::X64);
    items.extend(to_items(
        &read_entries(&hklm, UNINSTALL, KEY_WOW64_32KEY),
        Arch::X86,
    ));
    let hku = RegKey::predef(HKEY_USERS);
    for sid in hku
        .enum_keys()
        .filter_map(Result::ok)
        .filter(|s| is_user_sid(s))
    {
        let path = format!(r"{sid}\{UNINSTALL}");
        items.extend(to_items(&read_entries(&hku, &path, 0), Arch::User));
    }
    items
}
