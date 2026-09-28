//! 資料目錄（內含私鑰與註冊金鑰）：以完整的安全描述元建立，只檢查、不修補既有目錄。
//!
//! 一般使用者可以搶先建立 C:\ProgramData\EndpointManager（成為擁有者、自己加權限項目、
//! 放 junction 或預先開著 handle）。修補這種目錄（icacls /T）會跟著 junction 改到別處，
//! 也清不掉所有後門，所以不可信的目錄一律整個刪除後重建——裡面不可能有可信的身分。

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, bail};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, HANDLE, INVALID_HANDLE_VALUE,
    LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
    OPEN_EXISTING, READ_CONTROL,
};

use crate::state::{DATA_DIR_SDDL, sddl_is_trusted};

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

/// 目錄目前的擁有者與 DACL（SDDL）。不存在 → None；junction／符號連結／不是目錄 → Some("")（不可信）。
///
/// 屬性與安全描述元都從同一個 handle 讀取（開啟時不跟隨 reparse point），
/// 避免檢查「不是 junction」與讀取權限之間被換成 junction。
/// 判定可信之後才以路徑寫檔：可信目錄的擁有者是 SYSTEM／Administrators，一般使用者沒有
/// 該目錄的 DELETE，也沒有 ProgramData 的 DELETE_CHILD，無法再把它改名或換掉。
/// （EM_AGENT_DIR 指到其他位置時，這個前提取決於上層目錄的權限。）
pub fn current_sddl(dir: &Path) -> std::io::Result<Option<String>> {
    let path = wide(dir.as_os_str());
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let e = std::io::Error::last_os_error();
        return match e.raw_os_error().map(|c| c as u32) {
            Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) => Ok(None),
            _ => Err(e),
        };
    }
    let result = sddl_of_handle(handle);
    unsafe { CloseHandle(handle) };
    result.map(Some)
}

fn sddl_of_handle(handle: HANDLE) -> std::io::Result<String> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Ok(String::new());
    }
    let what = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let err = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            what,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if err != 0 {
        return Err(std::io::Error::from_raw_os_error(err as i32));
    }
    let mut text = std::ptr::null_mut();
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            what,
            &mut text,
            std::ptr::null_mut(),
        )
    };
    // 先取錯誤碼再釋放，LocalFree 可能覆蓋它
    let convert_err = (ok == 0).then(std::io::Error::last_os_error);
    unsafe { LocalFree(sd) };
    if let Some(e) = convert_err {
        return Err(e);
    }
    let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
    let sddl = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
    unsafe { LocalFree(text.cast()) };
    Ok(sddl)
}

/// Agent 只在資料目錄放一般檔案：出現子目錄或 junction／符號連結（例如 v0.1.0 時代被搶先建立、
/// 又被「強化」成可信權限的目錄裡殘留的）就不可信。可信目錄一般使用者無法新增項目，檢查結果不會被換掉。
fn only_plain_files(dir: &Path) -> std::io::Result<bool> {
    for entry in std::fs::read_dir(dir)? {
        let attrs = entry?.metadata()?.file_attributes();
        if attrs & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

/// 以 DATA_DIR_SDDL 建立目錄（建立的同時就套用，沒有空窗）。
fn create_secure(dir: &Path) -> std::io::Result<()> {
    let sddl = wide(OsStr::new(DATA_DIR_SDDL));
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let path = wide(dir.as_os_str());
    let ok = unsafe { CreateDirectoryW(path.as_ptr(), &attrs) };
    let result = if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    };
    unsafe { LocalFree(sd) };
    result
}

/// 刪除不可信的目錄：junction／符號連結只刪連結本身；一般目錄整個刪除
/// （std 的 remove_dir_all 不會跟著裡面的 junction 走）。
fn remove_untrusted(dir: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(dir)?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        std::fs::remove_dir(dir).or_else(|_| std::fs::remove_file(dir))
    } else if meta.is_dir() {
        std::fs::remove_dir_all(dir)
    } else {
        std::fs::remove_file(dir)
    }
}

/// 安裝時：確保資料目錄存在且可信；不可信就刪除重建。需要系統管理員權限。
pub fn prepare_data_dir(dir: &Path) -> anyhow::Result<()> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // 別人可能在我們刪除與建立之間又搶先建立，重試幾次
    for _ in 0..5 {
        match current_sddl(dir)? {
            None => match create_secure(dir) {
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                r => r.with_context(|| format!("creating {}", dir.display()))?,
            },
            Some(sddl) if sddl_is_trusted(&sddl) && only_plain_files(dir)? => return Ok(()),
            Some(sddl) => {
                tracing::warn!(dir = %dir.display(), %sddl, "untrusted data directory; recreating");
                remove_untrusted(dir)
                    .with_context(|| format!("removing untrusted {}", dir.display()))?;
            }
        }
    }
    bail!(
        "could not create a trusted data directory at {}",
        dir.display()
    )
}

/// 服務啟動時：只檢查、不修改。
pub fn verify_data_dir(dir: &Path) -> anyhow::Result<()> {
    match current_sddl(dir)? {
        Some(sddl) if sddl_is_trusted(&sddl) && only_plain_files(dir)? => Ok(()),
        Some(sddl) => bail!(
            "data directory {} has unexpected permissions ({sddl}); reinstall the agent",
            dir.display()
        ),
        None => bail!(
            "data directory {} is missing; reinstall the agent",
            dir.display()
        ),
    }
}
