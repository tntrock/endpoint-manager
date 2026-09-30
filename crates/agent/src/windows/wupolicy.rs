//! WUfB 原則登錄檔（`HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`）的讀寫，
//! 以及待重開機偵測。

use std::io::{Error, ErrorKind};

use protocol::update::PolicyData;
use winreg::RegKey;
use winreg::enums::{
    HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_READ, KEY_SET_VALUE, KEY_WOW64_64KEY, RegType,
};

use super::regwatch::Root;
use crate::updates::host::WuHost;

pub const POLICY_PATH: &str = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";

/// 任一機碼存在即為待重開機
const REBOOT_KEYS: [&str; 2] = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
];

pub struct RegistryHost {
    root: Root,
    path: String,
}

impl RegistryHost {
    pub fn machine() -> Self {
        Self::at(Root::LocalMachine, POLICY_PATH)
    }

    /// 測試用：指定其他位置（例如 HKCU 底下的測試機碼）
    pub fn at(root: Root, path: &str) -> Self {
        RegistryHost {
            root,
            path: path.to_string(),
        }
    }
}

fn not_found(e: &Error) -> bool {
    e.kind() == ErrorKind::NotFound
}

impl WuHost for RegistryHost {
    fn read(&self, name: &str) -> std::io::Result<Option<PolicyData>> {
        let key = match RegKey::predef(self.root.hkey())
            .open_subkey_with_flags(&self.path, KEY_QUERY_VALUE | KEY_WOW64_64KEY)
        {
            Ok(k) => k,
            Err(e) if not_found(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        let raw = match key.get_raw_value(name) {
            Ok(v) => v,
            Err(e) if not_found(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        Ok(Some(match raw.vtype {
            RegType::REG_DWORD => key
                .get_value::<u32, _>(name)
                .map_or(PolicyData::Unknown, PolicyData::Dword),
            RegType::REG_SZ => key
                .get_value::<String, _>(name)
                .map_or(PolicyData::Unknown, PolicyData::String),
            _ => PolicyData::Unknown,
        }))
    }

    fn write(&self, name: &str, data: &PolicyData) -> std::io::Result<()> {
        let (key, _) = RegKey::predef(self.root.hkey())
            .create_subkey_with_flags(&self.path, KEY_SET_VALUE | KEY_WOW64_64KEY)?;
        match data {
            PolicyData::Dword(v) => key.set_value(name, v),
            PolicyData::String(s) => key.set_value(name, s),
            PolicyData::Unknown => Err(Error::new(
                ErrorKind::InvalidInput,
                "unsupported policy value type",
            )),
        }
    }

    fn delete(&self, name: &str) -> std::io::Result<()> {
        let key = match RegKey::predef(self.root.hkey())
            .open_subkey_with_flags(&self.path, KEY_SET_VALUE | KEY_WOW64_64KEY)
        {
            Ok(k) => k,
            Err(e) if not_found(&e) => return Ok(()),
            Err(e) => return Err(e),
        };
        match key.delete_value(name) {
            Err(e) if not_found(&e) => Ok(()),
            r => r,
        }
    }

    fn reboot_pending(&self) -> bool {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        REBOOT_KEYS.iter().any(|k| {
            hklm.open_subkey_with_flags(k, KEY_READ | KEY_WOW64_64KEY)
                .is_ok()
        })
    }
}
