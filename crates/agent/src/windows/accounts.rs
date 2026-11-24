//! Windows 本機帳號（錯誤設定規格 §6.2）：停用、密碼永不過期、不需要密碼、最後登入，
//! 以及自動登入有沒有存密碼（只查有沒有，不讀內容）。

use std::mem::MaybeUninit;

use protocol::{AccountsInfo, LocalUser};
use time::OffsetDateTime;
use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
use windows_sys::Win32::NetworkManagement::NetManagement::{
    FILTER_NORMAL_ACCOUNT, MAX_PREFERRED_LENGTH, NetApiBufferFree, NetUserEnum, UF_ACCOUNTDISABLE,
    UF_DONT_EXPIRE_PASSWD, UF_PASSWD_NOTREQD, USER_INFO_3,
};
use windows_sys::Win32::System::Registry::{HKEY, RegQueryValueExW};

use super::shares::{from_wide, wide};

const WINLOGON: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

/// `NetUserEnum` 的一筆轉成回報格式；`last_logon` 是 1970 年起的秒數，0 是沒登入過
pub fn user_from(name: String, rid: u32, flags: u32, last_logon: u32) -> LocalUser {
    LocalUser {
        name,
        uid: rid,
        disabled: flags & UF_ACCOUNTDISABLE != 0,
        password_never_expires: flags & UF_DONT_EXPIRE_PASSWD != 0,
        no_password: Some(flags & UF_PASSWD_NOTREQD != 0),
        last_logon: (last_logon != 0)
            .then(|| OffsetDateTime::from_unix_timestamp(i64::from(last_logon)).ok())
            .flatten(),
        ..Default::default()
    }
}

/// 本機的一般帳號
pub fn local_users() -> std::io::Result<Vec<LocalUser>> {
    let mut out = vec![];
    let mut resume = 0u32;
    loop {
        let mut buf = MaybeUninit::<*mut u8>::uninit();
        let (mut read, mut total) = (0u32, 0u32);
        // SAFETY: 層級 3 對應 USER_INFO_3；成功時 API 配置緩衝區並寫入 buf
        let rc = unsafe {
            NetUserEnum(
                std::ptr::null(),
                3,
                FILTER_NORMAL_ACCOUNT,
                buf.as_mut_ptr(),
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                &mut resume,
            )
        };
        if rc != 0 && rc != ERROR_MORE_DATA {
            return Err(std::io::Error::from_raw_os_error(rc as i32));
        }
        // SAFETY: 同上，內容是 read 個 USER_INFO_3
        unsafe {
            let p = buf.assume_init();
            if !p.is_null() {
                for u in std::slice::from_raw_parts(p as *const USER_INFO_3, read as usize) {
                    out.push(user_from(
                        from_wide(u.usri3_name),
                        u.usri3_user_id,
                        u.usri3_flags,
                        u.usri3_last_logon,
                    ));
                }
                NetApiBufferFree(p as *const _);
            }
        }
        if rc != ERROR_MORE_DATA {
            return Ok(out);
        }
    }
}

/// 登錄檔值的大小（位元組）；不存在是 None。只查大小，不讀內容
fn value_size(key: &winreg::RegKey, name: &str) -> std::io::Result<Option<u32>> {
    let name = wide(name);
    let mut size = 0u32;
    // SAFETY: key 是開啟中的機碼；資料緩衝區給 null，只取大小
    let rc = unsafe {
        RegQueryValueExW(
            key.raw_handle() as HKEY,
            name.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    match rc {
        0 => Ok(Some(size)),
        2 => Ok(None),
        e => Err(std::io::Error::from_raw_os_error(e as i32)),
    }
}

/// 自動登入存了密碼：Winlogon 底下有不是空字串的 `DefaultPassword`
pub fn autologon_password() -> std::io::Result<bool> {
    let key = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(WINLOGON, winreg::enums::KEY_QUERY_VALUE)?;
    // 空字串是一個 UTF-16 的 NUL（2 位元組）
    Ok(value_size(&key, "DefaultPassword")?.is_some_and(|n| n > 2))
}

pub fn collect() -> AccountsInfo {
    let mut info = AccountsInfo {
        flags: true,
        ..Default::default()
    };
    match local_users() {
        Ok(u) => info.users = u,
        Err(e) => info.errors.push(format!("無法讀取本機帳號：{e}")),
    }
    match autologon_password() {
        Ok(b) => info.autologon_password = Some(b),
        Err(e) => info.errors.push(format!("無法讀取自動登入設定：{e}")),
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_map_to_fields() {
        let u = user_from(
            "Guest".into(),
            501,
            UF_ACCOUNTDISABLE | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_NOTREQD,
            0,
        );
        assert_eq!(u.uid, 501);
        assert!(u.disabled && u.password_never_expires);
        assert_eq!(u.no_password, Some(true));
        assert_eq!(u.last_logon, None);
        let u = user_from("bob".into(), 1001, 0, 1_700_000_000);
        assert!(!u.disabled && !u.password_never_expires);
        assert_eq!(u.no_password, Some(false));
        assert_eq!(u.last_logon.unwrap().unix_timestamp(), 1_700_000_000);
    }

    #[test]
    fn collect_reads_builtin_accounts() {
        let a = collect();
        assert!(a.flags);
        assert!(a.errors.is_empty(), "{:?}", a.errors);
        // 內建 Administrator（RID 500）一定在，可能被改名
        assert!(a.users.iter().any(|u| u.uid == 500), "{:?}", a.users);
        assert!(a.autologon_password.is_some());
    }

    #[test]
    fn missing_value_has_no_size() {
        let key = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
            .open_subkey(WINLOGON)
            .unwrap();
        assert_eq!(value_size(&key, "NoSuchValue-em-test").unwrap(), None);
        assert!(value_size(&key, "Shell").unwrap().is_some_and(|n| n > 2));
    }
}
