//! 派送的純邏輯：偵測是否已安裝、決定下一步、結束碼對應、組出要執行的指令。

use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use protocol::SoftwareItem;
use protocol::deploy::{Assignment, DeployAction, DeployStatus, Detect, PackageKind, PackageSpec};
use protocol::matcher::{Glob, cmp_version};

use super::state::Entry;

/// 同一 revision 最多嘗試次數
pub const MAX_ATTEMPTS: i32 = 3;
/// 失敗後多久再試
pub const RETRY_AFTER_HOURS: i64 = 24;
/// 24 小時內安裝成功幾次後（又被移除）不再重裝
pub const MAX_REINSTALLS: usize = 3;

/// 名稱與發行者樣式相符，且版本 ≥ 最低版本（有設定時）
pub fn is_installed(d: &Detect, items: &[SoftwareItem]) -> bool {
    let name = Glob::new(&d.name);
    let publisher = d.publisher.as_deref().map(Glob::new);
    items.iter().any(|i| {
        name.is_match(&i.name)
            && publisher
                .as_ref()
                .is_none_or(|p| i.publisher.as_deref().is_some_and(|x| p.is_match(x)))
            && d.min_version.as_deref().is_none_or(|min| {
                i.version
                    .as_deref()
                    .is_some_and(|v| cmp_version(v, min) != std::cmp::Ordering::Less)
            })
    })
}

#[derive(Debug, Clone, PartialEq)]
pub enum Plan {
    Nothing,
    /// 已符合期望狀態、這個 revision 還沒回報過
    ReportCompliant,
    Execute,
    /// 上次失敗，等到這個時間再試
    Wait(DateTime<Utc>),
    /// 24 小時內已安裝 MAX_REINSTALLS 次又被移除：回報失敗一次，不再重裝
    Removed,
}

pub fn decide(a: &Assignment, installed: bool, e: &Entry, now: DateTime<Utc>) -> Plan {
    let satisfied = match a.action {
        DeployAction::Install => installed,
        DeployAction::Uninstall => !installed,
        DeployAction::Unknown => return Plan::Nothing,
    };
    if a.package.kind == PackageKind::Unknown {
        return Plan::Nothing;
    }
    let fresh = Entry::default();
    let e = if e.revision == a.revision { e } else { &fresh };
    if satisfied {
        let done = matches!(
            e.reported,
            Some(DeployStatus::Compliant | DeployStatus::Succeeded | DeployStatus::RebootRequired)
        );
        return if done {
            Plan::Nothing
        } else {
            Plan::ReportCompliant
        };
    }
    if a.action == DeployAction::Install
        && e.installs
            .iter()
            .filter(|t| **t > now - Duration::hours(RETRY_AFTER_HOURS))
            .count()
            >= MAX_REINSTALLS
    {
        return if e.reported == Some(DeployStatus::Failed) {
            Plan::Nothing
        } else {
            Plan::Removed
        };
    }
    if e.attempts >= MAX_ATTEMPTS {
        return Plan::Nothing;
    }
    if e.last_failed
        && let Some(t) = e.last_attempt
    {
        let next = t + Duration::hours(RETRY_AFTER_HOURS);
        if next > now {
            return Plan::Wait(next);
        }
    }
    Plan::Execute
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Outcome {
    Status(DeployStatus),
    /// 另一個 Windows Installer 安裝正在進行（1618）：不算嘗試，稍後再試
    Busy,
}

pub fn outcome(code: i32, spec: &PackageSpec) -> Outcome {
    match code {
        0 => Outcome::Status(DeployStatus::Succeeded),
        c if spec.success_codes.contains(&c) => Outcome::Status(DeployStatus::Succeeded),
        3010 | 1641 => Outcome::Status(DeployStatus::RebootRequired),
        1618 => Outcome::Busy,
        _ => Outcome::Status(DeployStatus::Failed),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Cmd {
    pub program: PathBuf,
    /// 原樣傳給程式的參數（Windows 以 raw_arg 傳入，不再跳脫）
    pub args: String,
}

/// 用完整路徑呼叫 msiexec，避免 PATH 劫持（系統目錄由 API 取得，不看可被改動的環境變數）
fn msiexec() -> PathBuf {
    system_dir().join("msiexec.exe")
}

#[cfg(windows)]
fn system_dir() -> PathBuf {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buf = [0u16; 260];
    // SAFETY: 緩衝區長度正確；回傳寫入的字元數（不含結尾 0），失敗或太長時為 0 或大於長度
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 || n >= buf.len() {
        return PathBuf::from(r"C:\Windows\System32");
    }
    PathBuf::from(std::ffi::OsString::from_wide(&buf[..n]))
}

#[cfg(not(windows))]
fn system_dir() -> PathBuf {
    PathBuf::from(r"C:\Windows\System32")
}

fn join(base: String, extra: &str) -> String {
    if extra.is_empty() {
        base
    } else {
        format!("{base} {extra}")
    }
}

pub fn install_cmd(spec: &PackageSpec, file: &Path, log: &Path) -> Option<Cmd> {
    match spec.kind {
        PackageKind::Msi => Some(Cmd {
            program: msiexec(),
            args: join(
                format!(
                    r#"/i "{}" /qn /norestart /L*v "{}""#,
                    file.display(),
                    log.display()
                ),
                &spec.install_args,
            ),
        }),
        PackageKind::Exe => Some(Cmd {
            program: file.to_path_buf(),
            args: spec.install_args.clone(),
        }),
        PackageKind::Unknown => None,
    }
}

fn is_guid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 38
        && b[0] == b'{'
        && b[37] == b'}'
        && b[1..37].iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// MSI 以 ProductCode 移除；EXE 以套件本身加移除參數執行，沒有參數就不執行
/// （不帶參數執行安裝程式可能跳出互動視窗，甚至反而安裝）
pub fn uninstall_cmd(spec: &PackageSpec, file: &Path) -> Option<Cmd> {
    match spec.kind {
        PackageKind::Msi => {
            let code = spec.msi_product_code.as_deref().filter(|c| is_guid(c))?;
            Some(Cmd {
                program: msiexec(),
                args: format!("/x {code} /qn /norestart"),
            })
        }
        PackageKind::Exe if !spec.uninstall_args.trim().is_empty() => Some(Cmd {
            program: file.to_path_buf(),
            args: spec.uninstall_args.clone(),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::state::Entry;
    use chrono::{Duration, TimeZone, Utc};
    use protocol::deploy::{
        Assignment, DeployAction, DeployStatus, Detect, PackageKind, PackageSpec,
    };
    use protocol::{Arch, SoftwareItem};
    use std::path::Path;

    fn item(name: &str, publisher: Option<&str>, version: Option<&str>) -> SoftwareItem {
        SoftwareItem {
            name: name.into(),
            version: version.map(Into::into),
            publisher: publisher.map(Into::into),
            install_date: None,
            arch: Arch::X64,
        }
    }

    fn spec(kind: PackageKind) -> PackageSpec {
        PackageSpec {
            id: 3,
            kind,
            sha256: "ab".repeat(32),
            size: 1,
            file_name: "x".into(),
            install_args: "ALLUSERS=1".into(),
            uninstall_args: "/uninstall /S".into(),
            msi_product_code: Some("{11111111-2222-3333-4444-555555555555}".into()),
            success_codes: vec![7],
            detect: Detect {
                name: "7-Zip*".into(),
                publisher: Some("Igor*".into()),
                min_version: Some("23.01".into()),
            },
        }
    }

    fn assignment(action: DeployAction, revision: i32) -> Assignment {
        Assignment {
            deployment_id: 1,
            revision,
            action,
            package: spec(PackageKind::Exe),
        }
    }

    #[test]
    fn detection_matches_name_publisher_and_version() {
        let d = spec(PackageKind::Exe).detect;
        assert!(is_installed(
            &d,
            &[item(
                "7-Zip 23.01 (x64)",
                Some("Igor Pavlov"),
                Some("23.01")
            )]
        ));
        assert!(is_installed(
            &d,
            &[item("7-zip 24", Some("igor pavlov"), Some("24.0"))]
        ));
        assert!(
            !is_installed(&d, &[item("7-Zip", Some("Igor Pavlov"), Some("22.0"))]),
            "版本太舊"
        );
        assert!(
            !is_installed(&d, &[item("7-Zip", None, Some("23.01"))]),
            "要求發行者"
        );
        assert!(
            !is_installed(&d, &[item("7-Zip", Some("Igor"), None)]),
            "要求版本"
        );
        assert!(!is_installed(
            &d,
            &[item("WinRAR", Some("Igor"), Some("99"))]
        ));
        let loose = Detect {
            name: "7-Zip*".into(),
            publisher: None,
            min_version: None,
        };
        assert!(is_installed(&loose, &[item("7-Zip", None, None)]));
    }

    #[test]
    fn decisions() {
        let now = Utc.with_ymd_and_hms(2026, 9, 30, 12, 0, 0).unwrap();
        let a = assignment(DeployAction::Install, 1);
        let fresh = Entry::default();
        assert_eq!(decide(&a, true, &fresh, now), Plan::ReportCompliant);
        assert_eq!(decide(&a, false, &fresh, now), Plan::Execute);
        let reported = Entry {
            revision: 1,
            reported: Some(DeployStatus::Succeeded),
            ..Entry::default()
        };
        assert_eq!(
            decide(&a, true, &reported, now),
            Plan::Nothing,
            "已回報不再回報"
        );
        let failed = Entry {
            revision: 1,
            attempts: 1,
            last_attempt: Some(now - Duration::hours(1)),
            last_failed: true,
            reported: Some(DeployStatus::Failed),
            ..Entry::default()
        };
        assert_eq!(
            decide(&a, false, &failed, now),
            Plan::Wait(now + Duration::hours(23))
        );
        let later = Entry {
            last_attempt: Some(now - Duration::hours(25)),
            ..failed.clone()
        };
        assert_eq!(decide(&a, false, &later, now), Plan::Execute);
        let exhausted = Entry {
            attempts: 3,
            ..later.clone()
        };
        assert_eq!(
            decide(&a, false, &exhausted, now),
            Plan::Nothing,
            "同一 revision 最多 3 次"
        );
        // 裝好後被使用者移除：之前成功過，重新安裝
        assert_eq!(decide(&a, false, &reported, now), Plan::Execute);
        let rm = assignment(DeployAction::Uninstall, 1);
        assert_eq!(decide(&rm, false, &fresh, now), Plan::ReportCompliant);
        assert_eq!(decide(&rm, true, &fresh, now), Plan::Execute);
        assert_eq!(
            decide(&assignment(DeployAction::Unknown, 1), false, &fresh, now),
            Plan::Nothing,
            "不認識的動作略過"
        );
    }

    #[test]
    fn reinstall_limit() {
        let now = Utc.with_ymd_and_hms(2026, 9, 30, 12, 0, 0).unwrap();
        let a = assignment(DeployAction::Install, 1);
        let removed = Entry {
            revision: 1,
            reported: Some(DeployStatus::Succeeded),
            installs: vec![now - Duration::hours(1); 3],
            ..Entry::default()
        };
        assert_eq!(decide(&a, false, &removed, now), Plan::Removed);
        let told = Entry {
            reported: Some(DeployStatus::Failed),
            ..removed.clone()
        };
        assert_eq!(decide(&a, false, &told, now), Plan::Nothing, "只回報一次");
        let old = Entry {
            installs: vec![now - Duration::hours(25); 3],
            ..removed.clone()
        };
        assert_eq!(decide(&a, false, &old, now), Plan::Execute, "24 小時後再試");
        assert_eq!(
            decide(&assignment(DeployAction::Install, 2), false, &removed, now),
            Plan::Execute,
            "重試失敗（新 revision）重新計算"
        );
    }

    #[test]
    fn exit_codes() {
        let s = spec(PackageKind::Exe);
        assert_eq!(outcome(0, &s), Outcome::Status(DeployStatus::Succeeded));
        assert_eq!(outcome(7, &s), Outcome::Status(DeployStatus::Succeeded));
        assert_eq!(
            outcome(3010, &s),
            Outcome::Status(DeployStatus::RebootRequired)
        );
        assert_eq!(
            outcome(1641, &s),
            Outcome::Status(DeployStatus::RebootRequired)
        );
        assert_eq!(outcome(1618, &s), Outcome::Busy);
        assert_eq!(outcome(1603, &s), Outcome::Status(DeployStatus::Failed));
    }

    #[test]
    fn commands() {
        let file = Path::new(r"C:\ProgramData\EndpointManager\packages\ab.msi");
        let log = Path::new(r"C:\ProgramData\EndpointManager\packages\ab.log");
        let c = install_cmd(&spec(PackageKind::Msi), file, log).unwrap();
        assert!(
            c.program
                .to_string_lossy()
                .to_ascii_lowercase()
                .ends_with(r"system32\msiexec.exe"),
            "{:?}",
            c.program
        );
        assert_eq!(
            c.args,
            format!(
                r#"/i "{}" /qn /norestart /L*v "{}" ALLUSERS=1"#,
                file.display(),
                log.display()
            )
        );
        let c = install_cmd(&spec(PackageKind::Exe), file, log).unwrap();
        assert_eq!((c.program.as_path(), c.args.as_str()), (file, "ALLUSERS=1"));
        let c = uninstall_cmd(&spec(PackageKind::Msi), file).unwrap();
        assert_eq!(
            c.args,
            "/x {11111111-2222-3333-4444-555555555555} /qn /norestart"
        );
        let c = uninstall_cmd(&spec(PackageKind::Exe), file).unwrap();
        assert_eq!(
            (c.program.as_path(), c.args.as_str()),
            (file, "/uninstall /S")
        );
        let no_args = PackageSpec {
            uninstall_args: String::new(),
            ..spec(PackageKind::Exe)
        };
        assert!(
            uninstall_cmd(&no_args, file).is_none(),
            "EXE 沒有移除參數不執行"
        );
        let no_code = PackageSpec {
            msi_product_code: None,
            ..spec(PackageKind::Msi)
        };
        assert!(uninstall_cmd(&no_code, file).is_none());
        let bad_code = PackageSpec {
            msi_product_code: Some("{x} & calc".into()),
            ..spec(PackageKind::Msi)
        };
        assert!(
            uninstall_cmd(&bad_code, file).is_none(),
            "ProductCode 必須是 GUID"
        );
        assert!(install_cmd(&spec(PackageKind::Unknown), file, log).is_none());
    }
}
