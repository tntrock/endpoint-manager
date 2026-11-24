//! Windows SMB 共用（錯誤設定規格 §4.1）：列出共用、讀共用權限與資料夾的 NTFS 權限，
//! 轉成 SDDL 交給 [`crate::shares::judge_smb`] 判斷。只上傳結論。

use std::mem::MaybeUninit;

use protocol::{ShareItem, SharesInfo};
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, LocalFree};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    FILTER_NORMAL_ACCOUNT, MAX_PREFERRED_LENGTH, NetApiBufferFree, NetUserEnum, UF_ACCOUNTDISABLE,
    USER_INFO_20,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
use windows_sys::Win32::Storage::FileSystem::{
    NetShareEnum, SHARE_INFO_502, STYPE_DISKTREE, STYPE_MASK, STYPE_SPECIAL,
};

use crate::shares::judge_smb;

/// 內建 Guest 帳號的 RID
const GUEST_RID: u32 = 501;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// NUL 結尾的寬字串
unsafe fn from_wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: 呼叫端保證 p 指向 NUL 結尾的字串
    let len = (0..).take_while(|&i| unsafe { *p.add(i) } != 0).count();
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

/// 安全描述元的 DACL 轉成 SDDL
fn sddl_of(sd: PSECURITY_DESCRIPTOR) -> std::io::Result<String> {
    let mut text = MaybeUninit::<*mut u16>::uninit();
    // SAFETY: sd 是有效的安全描述元；成功時 API 配置字串並寫入 text
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            text.as_mut_ptr(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: 成功時 text 已寫入，字串由 LocalFree 釋放
    unsafe {
        let p = text.assume_init();
        let s = from_wide(p);
        LocalFree(p.cast());
        Ok(s)
    }
}

/// 資料夾的 NTFS 權限（SDDL）
pub fn ntfs_sddl(path: &str) -> std::io::Result<String> {
    let w = wide(path);
    let mut sd = MaybeUninit::<PSECURITY_DESCRIPTOR>::uninit();
    // SAFETY: 只要求安全描述元；成功時 API 配置並寫入 sd
    let err = unsafe {
        GetNamedSecurityInfoW(
            w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            sd.as_mut_ptr(),
        )
    };
    if err != 0 {
        return Err(std::io::Error::from_raw_os_error(err as i32));
    }
    // SAFETY: 成功時 sd 已寫入，由 LocalFree 釋放
    unsafe {
        let sd = sd.assume_init();
        let r = sddl_of(sd);
        LocalFree(sd);
        r
    }
}

/// 一個磁碟共用：名稱、路徑、共用權限（SDDL；沒有安全描述元時 None）
struct RawShare {
    name: String,
    path: String,
    sddl: Option<String>,
}

fn enum_shares() -> std::io::Result<Vec<RawShare>> {
    let mut out = vec![];
    let mut resume = 0u32;
    loop {
        let mut buf = MaybeUninit::<*mut u8>::uninit();
        let (mut read, mut total) = (0u32, 0u32);
        // SAFETY: 層級 502 對應 SHARE_INFO_502；成功時 API 配置緩衝區並寫入 buf
        let rc = unsafe {
            NetShareEnum(
                std::ptr::null(),
                502,
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
        // SAFETY: rc 是 0 或 ERROR_MORE_DATA 時 buf 已寫入（可能是空指標），內容是 read 個 SHARE_INFO_502
        unsafe {
            let p = buf.assume_init();
            if !p.is_null() {
                let items = std::slice::from_raw_parts(p as *const SHARE_INFO_502, read as usize);
                for i in items {
                    let ty = i.shi502_type;
                    if ty & STYPE_MASK != STYPE_DISKTREE || ty & STYPE_SPECIAL != 0 {
                        continue;
                    }
                    let sddl = if i.shi502_security_descriptor.is_null() {
                        None
                    } else {
                        sddl_of(i.shi502_security_descriptor).ok()
                    };
                    out.push(RawShare {
                        name: from_wide(i.shi502_netname),
                        path: from_wide(i.shi502_path),
                        sddl,
                    });
                }
                NetApiBufferFree(p as *const _);
            }
        }
        if rc != ERROR_MORE_DATA {
            return Ok(out);
        }
    }
}

/// 內建 Guest 帳號（RID 501，可能被改名）是否啟用
pub fn guest_enabled() -> std::io::Result<bool> {
    let mut resume = 0u32;
    loop {
        let mut buf = MaybeUninit::<*mut u8>::uninit();
        let (mut read, mut total) = (0u32, 0u32);
        // SAFETY: 層級 20 對應 USER_INFO_20；成功時 API 配置緩衝區並寫入 buf
        let rc = unsafe {
            NetUserEnum(
                std::ptr::null(),
                20,
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
        let mut found = None;
        // SAFETY: 同上，內容是 read 個 USER_INFO_20
        unsafe {
            let p = buf.assume_init();
            if !p.is_null() {
                let users = std::slice::from_raw_parts(p as *const USER_INFO_20, read as usize);
                found = users
                    .iter()
                    .find(|u| u.usri20_user_id == GUEST_RID)
                    .map(|u| u.usri20_flags & UF_ACCOUNTDISABLE == 0);
                NetApiBufferFree(p as *const _);
            }
        }
        if let Some(enabled) = found {
            return Ok(enabled);
        }
        if rc != ERROR_MORE_DATA {
            return Ok(false);
        }
    }
}

/// `EveryoneIncludesAnonymous`：開啟時匿名連線也算 Everyone
fn everyone_includes_anonymous() -> bool {
    winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(r"SYSTEM\CurrentControlSet\Control\Lsa")
        .and_then(|k| k.get_value::<u32, _>("EveryoneIncludesAnonymous"))
        .is_ok_and(|v| v == 1)
}

pub fn collect() -> SharesInfo {
    let mut info = SharesInfo::default();
    let guest = guest_enabled().unwrap_or_else(|e| {
        info.errors.push(format!("無法讀取 Guest 帳號：{e}"));
        false
    });
    let eia = everyone_includes_anonymous();
    match enum_shares() {
        Ok(shares) => {
            for s in shares.into_iter().take(protocol::MAX_SHARES) {
                let ntfs = match ntfs_sddl(&s.path) {
                    Ok(x) => Some(x),
                    Err(e) => {
                        info.errors.push(format!("無法讀取 {} 的權限：{e}", s.name));
                        None
                    }
                };
                let (anonymous, all_users) =
                    judge_smb(s.sddl.as_deref(), ntfs.as_deref(), guest, eia);
                info.shares.push(ShareItem {
                    kind: "smb".into(),
                    name: s.name,
                    path: s.path,
                    anonymous,
                    all_users,
                    no_root_squash: false,
                    clients: vec![],
                });
            }
        }
        Err(e) => info.errors.push(format!("無法列出共用：{e}")),
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::ShareAccess;

    /// 實際的資料夾權限：給 Everyone 修改權限後判斷為「所有使用者可寫入」
    #[test]
    fn ntfs_permissions_of_a_real_folder() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap().to_string();
        let before = ntfs_sddl(&path).unwrap();
        assert!(before.starts_with("D:"), "{before}");
        let (_, users) = judge_smb(Some("D:(A;;FA;;;WD)"), Some(&before), false, false);
        assert_ne!(
            users,
            ShareAccess::Write,
            "暫存資料夾一般不給所有人寫入：{before}"
        );
        let ok = std::process::Command::new("icacls")
            .arg(&path)
            .args(["/grant", "*S-1-1-0:(M)"])
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok);
        let after = ntfs_sddl(&path).unwrap();
        assert_eq!(
            judge_smb(Some("D:(A;;FA;;;WD)"), Some(&after), false, false),
            (ShareAccess::None, ShareAccess::Write),
            "{after}"
        );
        // 共用只能讀時取較小的
        assert_eq!(
            judge_smb(Some("D:(A;;0x1200a9;;;WD)"), Some(&after), false, false).1,
            ShareAccess::Read
        );
        assert!(ntfs_sddl(r"C:\no\such\path\for\test").is_err());
    }

    /// 實際列出共用（不一定有權限或有共用，只確認不會失敗得很難看）
    #[test]
    fn collect_runs() {
        let info = collect();
        assert!(info.shares.iter().all(|s| s.kind == "smb"));
        // 管理用共用不列出
        assert!(
            !info
                .shares
                .iter()
                .any(|s| ["C$", "ADMIN$", "IPC$"].contains(&s.name.as_str()))
        );
        let _ = guest_enabled();
    }
}
