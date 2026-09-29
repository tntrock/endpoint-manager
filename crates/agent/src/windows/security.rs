//! 安全設定收集：防火牆、BitLocker、Defender、密碼原則、本機管理員。每一項獨立，
//! 失敗時以 Probe::Error 回報，不影響其他項；錯誤依「同一錯誤只記一次」寫入事件記錄。

use protocol::{
    AccountInfo, DefenderInfo, FirewallInfo, PasswordPolicy, Probe, SecurityInfo, VolumeInfo,
};
use serde::Deserialize;
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};

pub fn collect() -> SecurityInfo {
    SecurityInfo {
        firewall: probe("firewall", firewall),
        bitlocker: probe("bitlocker", bitlocker),
        defender: probe("defender", defender),
        password: probe("password", password_policy),
        admins: probe("admins", local_admins),
    }
}

fn probe<T>(what: &'static str, f: impl FnOnce() -> anyhow::Result<T>) -> Probe<T> {
    match f() {
        Ok(v) => {
            super::collect::recovered(what);
            Probe::Ok(v)
        }
        Err(e) => {
            let e = format!("{e:#}");
            if super::collect::first_report(what, &e) {
                tracing::warn!(item = what, error = %e, "security probe failed");
            }
            Probe::Error(crate::sanitize::clean(&e))
        }
    }
}

fn dword(path: &str, name: &str) -> Option<u32> {
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(path, KEY_READ | KEY_WOW64_64KEY)
        .and_then(|k| k.get_value::<u32, _>(name))
        .ok()
}

/// 群組原則的設定優先，其次本機設定；都沒設定時 Windows 預設啟用防火牆。
pub fn firewall_effective(policy: Option<u32>, local: Option<u32>) -> bool {
    policy.or(local).unwrap_or(1) != 0
}

fn firewall() -> anyhow::Result<FirewallInfo> {
    const POLICY: &str = r"SOFTWARE\Policies\Microsoft\WindowsFirewall";
    const LOCAL: &str = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
    // 私人設定檔在本機設定叫 StandardProfile，在群組原則叫 PrivateProfile
    let profile = |policy_name: &str, local_name: &str| {
        firewall_effective(
            dword(&format!(r"{POLICY}\{policy_name}"), "EnableFirewall"),
            dword(&format!(r"{LOCAL}\{local_name}"), "EnableFirewall"),
        )
    };
    Ok(FirewallInfo {
        domain: profile("DomainProfile", "DomainProfile"),
        private: profile("PrivateProfile", "StandardProfile"),
        public: profile("PublicProfile", "PublicProfile"),
    })
}

#[derive(Deserialize)]
#[serde(rename = "Win32_EncryptableVolume", rename_all = "PascalCase")]
struct EncryptableVolume {
    drive_letter: Option<String>,
    protection_status: Option<u32>,
    volume_type: Option<u32>,
}

fn bitlocker() -> anyhow::Result<Vec<VolumeInfo>> {
    let con =
        wmi::WMIConnection::with_namespace_path(r"ROOT\CIMV2\Security\MicrosoftVolumeEncryption")?;
    let vols: Vec<EncryptableVolume> = con.query()?;
    Ok(vols
        .into_iter()
        // 0 = 作業系統磁碟、1 = 固定資料磁碟；卸除式不看
        .filter(|v| matches!(v.volume_type, Some(0 | 1)))
        .map(|v| VolumeInfo {
            drive: v.drive_letter.unwrap_or_default(),
            is_system: v.volume_type == Some(0),
            protected: v.protection_status == Some(1),
        })
        .collect())
}

#[derive(Deserialize)]
#[serde(rename = "MSFT_MpComputerStatus")]
struct MpStatus {
    #[serde(rename = "AMRunningMode")]
    am_running_mode: Option<String>,
    #[serde(rename = "AMServiceEnabled")]
    am_service_enabled: Option<bool>,
    #[serde(rename = "RealTimeProtectionEnabled")]
    real_time_protection_enabled: Option<bool>,
    #[serde(rename = "IsTamperProtected")]
    is_tamper_protected: Option<bool>,
    #[serde(rename = "AntivirusSignatureLastUpdated")]
    antivirus_signature_last_updated: Option<wmi::WMIDateTime>,
}

fn defender() -> anyhow::Result<DefenderInfo> {
    let con = wmi::WMIConnection::with_namespace_path(r"ROOT\Microsoft\Windows\Defender")?;
    let s: MpStatus = con
        .query::<MpStatus>()?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("MSFT_MpComputerStatus returned nothing"))?;
    // 舊版 Windows 沒有 AMRunningMode：以服務是否啟用判斷
    let active = match s.am_running_mode.as_deref() {
        Some(m) => m.eq_ignore_ascii_case("Normal"),
        None => s.am_service_enabled.unwrap_or(false),
    };
    Ok(DefenderInfo {
        active,
        realtime: s.real_time_protection_enabled.unwrap_or(false),
        tamper: s.is_tamper_protected.unwrap_or(false),
        signature_updated: s
            .antivirus_signature_last_updated
            .map(|t| t.0.with_timezone(&chrono::Utc)),
    })
}

/// NetUserModalsGet 的最長密碼使用期限（秒）轉成天；TIMEQ_FOREVER（u32::MAX）＝永不過期＝0。
pub fn days_from_seconds(max_passwd_age: u32) -> u32 {
    if max_passwd_age == u32::MAX {
        0
    } else {
        max_passwd_age / 86_400
    }
}

fn password_policy() -> anyhow::Result<PasswordPolicy> {
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        NetApiBufferFree, NetUserModalsGet, USER_MODALS_INFO_0, USER_MODALS_INFO_3,
    };
    // SAFETY: NetUserModalsGet 以 NetApiBuffer 配置緩衝區並寫入 buf；成功時讀取對應結構，
    // 讀完立刻以 NetApiBufferFree 釋放。失敗時 buf 未配置，不需釋放。
    unsafe {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let rc = NetUserModalsGet(std::ptr::null(), 0, &mut buf);
        anyhow::ensure!(
            rc == 0 && !buf.is_null(),
            "NetUserModalsGet(0) failed: {rc}"
        );
        let info0 = &*(buf as *const USER_MODALS_INFO_0);
        let (min_length, max_age) = (info0.usrmod0_min_passwd_len, info0.usrmod0_max_passwd_age);
        NetApiBufferFree(buf as *const _);

        let mut buf: *mut u8 = std::ptr::null_mut();
        let rc = NetUserModalsGet(std::ptr::null(), 3, &mut buf);
        anyhow::ensure!(
            rc == 0 && !buf.is_null(),
            "NetUserModalsGet(3) failed: {rc}"
        );
        let lockout_threshold = (*(buf as *const USER_MODALS_INFO_3)).usrmod3_lockout_threshold;
        NetApiBufferFree(buf as *const _);

        Ok(PasswordPolicy {
            min_length,
            max_age_days: days_from_seconds(max_age),
            lockout_threshold,
        })
    }
}

/// 以 null 結尾的 UTF-16 指標轉成 String。
///
/// SAFETY: 呼叫端保證 p 為 null 或指向有效、以 0 結尾的 UTF-16 字串。
unsafe fn wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0;
    // SAFETY: 見函式說明
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

fn local_admins() -> anyhow::Result<Vec<AccountInfo>> {
    use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, LocalFree};
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        LOCALGROUP_MEMBERS_INFO_2, MAX_PREFERRED_LENGTH, NetApiBufferFree, NetLocalGroupGetMembers,
    };
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, LookupAccountSidW, SID_NAME_USE, WinBuiltinAdministratorsSid,
    };

    // SAFETY: 所有緩衝區不是本函式的堆疊陣列（大小已傳給 API），就是由 API 配置並在
    // 使用後以對應函式（NetApiBufferFree／LocalFree）釋放。
    unsafe {
        // 以 SID 取得群組名稱：非英文版 Windows 的 Administrators 群組名稱不同
        let mut sid = [0u8; 68]; // SECURITY_MAX_SID_SIZE
        let mut sid_len = sid.len() as u32;
        anyhow::ensure!(
            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                std::ptr::null_mut(),
                sid.as_mut_ptr() as *mut _,
                &mut sid_len,
            ) != 0,
            "CreateWellKnownSid failed"
        );
        let mut name = [0u16; 256];
        let mut name_len = name.len() as u32;
        let mut domain = [0u16; 256];
        let mut domain_len = domain.len() as u32;
        let mut usage: SID_NAME_USE = 0;
        anyhow::ensure!(
            LookupAccountSidW(
                std::ptr::null(),
                sid.as_ptr() as *const _ as *mut _,
                name.as_mut_ptr(),
                &mut name_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut usage,
            ) != 0,
            "LookupAccountSidW failed"
        );

        let mut out = vec![];
        let mut resume: usize = 0;
        loop {
            let mut buf: *mut u8 = std::ptr::null_mut();
            let (mut read, mut total) = (0u32, 0u32);
            let rc = NetLocalGroupGetMembers(
                std::ptr::null(),
                name.as_ptr(),
                2,
                &mut buf,
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                &mut resume,
            );
            anyhow::ensure!(
                rc == 0 || rc == ERROR_MORE_DATA,
                "NetLocalGroupGetMembers failed: {rc}"
            );
            if !buf.is_null() {
                let items = std::slice::from_raw_parts(
                    buf as *const LOCALGROUP_MEMBERS_INFO_2,
                    read as usize,
                );
                for m in items {
                    let mut sid_str: *mut u16 = std::ptr::null_mut();
                    let sid_text = if ConvertSidToStringSidW(m.lgrmi2_sid, &mut sid_str) != 0 {
                        let s = wide(sid_str);
                        LocalFree(sid_str as *mut _);
                        s
                    } else {
                        String::new()
                    };
                    let mut name = wide(m.lgrmi2_domainandname);
                    // 帳號已刪除時沒有名稱：改用 SID 顯示
                    if name.is_empty() {
                        name = sid_text.clone();
                    }
                    out.push(AccountInfo {
                        name,
                        sid: sid_text,
                    });
                }
                NetApiBufferFree(buf as *const _);
            }
            if rc != ERROR_MORE_DATA {
                break;
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_policy_overrides_local_and_defaults_on() {
        assert!(firewall_effective(None, None), "都沒設定＝預設啟用");
        assert!(!firewall_effective(None, Some(0)));
        assert!(firewall_effective(Some(1), Some(0)), "GPO 優先");
        assert!(!firewall_effective(Some(0), Some(1)));
    }

    #[test]
    fn password_age_conversion() {
        assert_eq!(days_from_seconds(u32::MAX), 0, "永不過期");
        assert_eq!(days_from_seconds(42 * 86_400), 42);
        assert_eq!(days_from_seconds(0), 0);
    }
}
