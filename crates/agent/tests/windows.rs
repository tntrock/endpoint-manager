//! Windows 實機冒煙測試。
#![cfg(windows)]

use std::process::Command;

use endpoint_agent::state::sddl_is_trusted;
use endpoint_agent::windows::secdir::{current_sddl, prepare_data_dir, verify_data_dir};

/// 需要系統管理員權限（CI 的 windows runner 有）；一般權限下略過。
fn elevated() -> bool {
    Command::new("net")
        .arg("session")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn sddl(p: &std::path::Path) -> String {
    current_sddl(p).unwrap().expect("exists")
}

/// 模擬一般使用者搶先建立的目錄：自己加了 Users 完全控制、放了假的 state.json。
fn squat(dir: &std::path::Path) {
    std::fs::create_dir_all(dir).unwrap();
    assert!(
        Command::new("icacls")
            .arg(dir)
            .args(["/grant", "*S-1-5-32-545:(OI)(CI)F"])
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    std::fs::write(dir.join("state.json"), b"{\"device_id\":null}").unwrap();
}

/// 不需系統管理員：一般的暫存目錄讀得到 SDDL，但不可信；不存在則為 None。
#[test]
fn current_sddl_of_ordinary_dir_is_untrusted() {
    let tmp = tempfile::tempdir().unwrap();
    let s = sddl(tmp.path());
    assert!(s.starts_with("O:") && s.contains("D:"), "{s}");
    assert!(!sddl_is_trusted(&s), "{s}");
    assert!(current_sddl(&tmp.path().join("missing")).unwrap().is_none());
    assert!(
        current_sddl(&tmp.path().join("missing").join("child"))
            .unwrap()
            .is_none()
    );
    assert!(verify_data_dir(tmp.path()).is_err());
}

#[test]
fn prepare_creates_trusted_dir() {
    if !elevated() {
        eprintln!("skipped: not elevated");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("em");
    prepare_data_dir(&dir).unwrap();
    assert!(sddl_is_trusted(&sddl(&dir)), "{}", sddl(&dir));
    verify_data_dir(&dir).unwrap();
    // 已可信的目錄：內容保留
    std::fs::write(dir.join("state.json"), b"keep").unwrap();
    prepare_data_dir(&dir).unwrap();
    assert_eq!(std::fs::read(dir.join("state.json")).unwrap(), b"keep");
}

#[test]
fn prepare_recreates_squatted_dir() {
    if !elevated() {
        eprintln!("skipped: not elevated");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("em");
    squat(&dir);
    assert!(verify_data_dir(&dir).is_err(), "搶先建立的目錄不可信");
    prepare_data_dir(&dir).unwrap();
    let s = sddl(&dir);
    assert!(
        sddl_is_trusted(&s) && !s.contains("S-1-5-32-545") && !s.contains(";;;BU)"),
        "{s}"
    );
    assert!(!dir.join("state.json").exists(), "搶先放的檔案要被清掉");
}

#[test]
fn prepare_does_not_follow_junctions() {
    if !elevated() {
        eprintln!("skipped: not elevated");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let victim = tmp.path().join("victim");
    std::fs::create_dir_all(&victim).unwrap();
    std::fs::write(victim.join("secret.txt"), b"x").unwrap();
    let before = sddl(&victim);
    let mklink = |link: &std::path::Path| {
        assert!(
            Command::new("cmd")
                .args(["/c", "mklink", "/J"])
                .arg(link)
                .arg(&victim)
                .stdout(std::process::Stdio::null())
                .status()
                .unwrap()
                .success()
        );
    };

    // 目錄裡放 junction 指向別處
    let dir = tmp.path().join("em");
    squat(&dir);
    mklink(&dir.join("sub"));
    prepare_data_dir(&dir).unwrap();
    assert!(
        victim.join("secret.txt").exists(),
        "不可刪到 junction 指向的目錄"
    );
    assert_eq!(sddl(&victim), before, "不可改到 junction 指向的目錄的權限");

    // 資料目錄本身就是 junction
    let dir2 = tmp.path().join("em2");
    mklink(&dir2);
    assert!(verify_data_dir(&dir2).is_err());
    prepare_data_dir(&dir2).unwrap();
    assert!(sddl_is_trusted(&sddl(&dir2)));
    assert!(victim.join("secret.txt").exists());
    assert_eq!(sddl(&victim), before);
}

/// 可信的目錄裡只該有一般檔案：v0.1.0 時代被搶先建立、又被「強化」成可信權限的目錄，
/// 可能還留著 junction。這種目錄服務要拒絕、安裝時要重建。
#[test]
fn trusted_dir_with_junction_child_is_recreated() {
    if !elevated() {
        eprintln!("skipped: not elevated");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let victim = tmp.path().join("victim");
    std::fs::create_dir_all(&victim).unwrap();
    std::fs::write(victim.join("secret.txt"), b"x").unwrap();
    let dir = tmp.path().join("em");
    prepare_data_dir(&dir).unwrap();
    assert!(
        Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(dir.join("sub"))
            .arg(&victim)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    assert!(verify_data_dir(&dir).is_err(), "有 junction 的目錄不可信");
    prepare_data_dir(&dir).unwrap();
    assert!(!dir.join("sub").exists());
    verify_data_dir(&dir).unwrap();
    assert!(victim.join("secret.txt").exists());
}

/// 不需系統管理員：Windows Update 的 CBS 套件機碼可以監聽。
#[test]
fn patches_key_can_be_watched() {
    endpoint_agent::windows::regwatch::watch(
        endpoint_agent::windows::regwatch::Root::LocalMachine,
        endpoint_agent::windows::regwatch::CBS_PACKAGES,
        windows_sys::Win32::System::Registry::KEY_WOW64_64KEY,
        || {},
    )
    .unwrap();
}

use endpoint_agent::collector::Collector;
use endpoint_agent::sanitize::sanitize;
use endpoint_agent::windows::collect::WindowsCollector;
use protocol::{InventoryPayload, Section};

#[test]
fn collector_reports_this_machine() {
    let c = WindowsCollector;
    let id = c.identity().unwrap();
    assert!(!id.hostname.is_empty());

    let hb = c.heartbeat().unwrap();
    assert!(hb.boot_time < chrono::Utc::now());

    // Registry 不經 collect（走 collect_registry）
    for s in Section::ALL.into_iter().filter(|s| *s != Section::Registry) {
        let mut p = c.collect(s).unwrap_or_else(|e| panic!("{s:?}: {e:#}"));
        sanitize(&mut p);
        assert_eq!(p.validate(), Ok(()), "{s:?}");
        match p {
            InventoryPayload::Basic(b) => {
                assert!(!b.os_caption.is_empty());
                assert!(
                    b.os_ubr.is_some_and(|u| u > 0),
                    "Windows 10/11 一定有 UBR: {b:?}"
                );
            }
            InventoryPayload::Hardware(h) => assert!(h.ram_mb > 0),
            InventoryPayload::Software(v) => assert!(!v.is_empty()),
            InventoryPayload::Services(v) => {
                assert!(v.iter().any(|s| s.name.eq_ignore_ascii_case("EventLog")))
            }
            InventoryPayload::Patches(_) => {}
            InventoryPayload::Security(sec) => {
                // CI 機器不一定有 BitLocker、Defender；防火牆、密碼原則、管理員一定要成功
                assert!(
                    matches!(sec.firewall, protocol::Probe::Ok(_)),
                    "{:?}",
                    sec.firewall
                );
                assert!(
                    matches!(sec.password, protocol::Probe::Ok(_)),
                    "{:?}",
                    sec.password
                );
                let protocol::Probe::Ok(admins) = &sec.admins else {
                    panic!("{:?}", sec.admins)
                };
                assert!(
                    !admins.is_empty() && admins.iter().all(|a| a.sid.starts_with("S-1-")),
                    "{admins:?}"
                );
            }
            InventoryPayload::Registry(_) => unreachable!("registry 不經 collect"),
        }
    }
}

use std::sync::mpsc;
use std::time::Duration;

use endpoint_agent::windows::{eventlog::EventLog, regwatch};
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER as WINREG_HKCU;

#[test]
fn registry_watch_fires_on_change() {
    let path = r"Software\EndpointManagerTest";
    let (key, _) = RegKey::predef(WINREG_HKCU).create_subkey(path).unwrap();
    let (tx, rx) = mpsc::channel();
    regwatch::watch(regwatch::Root::CurrentUser, path, 0, move || {
        let _ = tx.send(());
    })
    .unwrap();
    std::thread::sleep(Duration::from_millis(200));
    key.set_value("probe", &"1").unwrap();
    assert!(
        rx.recv_timeout(Duration::from_secs(5)).is_ok(),
        "no notification"
    );
    let _ = RegKey::predef(WINREG_HKCU).delete_subkey_all(path);
}

#[test]
fn eventlog_report_works() {
    let log = EventLog::open().unwrap();
    log.report(
        windows_sys::Win32::System::EventLog::EVENTLOG_INFORMATION_TYPE,
        "endpoint-agent test event",
    );
}

/// 需要系統管理員權限；一般權限下略過。
#[test]
fn configure_hardens_dir_and_writes_files() {
    if !elevated() {
        eprintln!("skipped: not elevated");
        return;
    }
    use endpoint_agent::config::AgentConfig;
    use endpoint_agent::windows::install::{configure, unconfigure};
    let key = rcgen::KeyPair::generate().unwrap();
    let pem = rcgen::CertificateParams::default()
        .self_signed(&key)
        .unwrap()
        .pem();
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");

    // 首次安裝缺根憑證 → 失敗
    assert!(
        configure(
            &data,
            Some("https://em.example.com:8443"),
            Some("tok"),
            None
        )
        .is_err()
    );

    configure(
        &data,
        Some("https://em.example.com:8443"),
        Some("tok"),
        Some(&b64),
    )
    .unwrap();
    assert!(
        std::fs::read_to_string(data.join("root.pem"))
            .unwrap()
            .contains("BEGIN CERTIFICATE")
    );
    let c = AgentConfig::load(&data).unwrap();
    assert_eq!(c.enroll_token.as_deref(), Some("tok"));

    // 重跑（升級）不帶參數：全部沿用
    configure(&data, None, None, None).unwrap();
    assert_eq!(AgentConfig::load(&data).unwrap(), c);

    unconfigure(&data).unwrap();
    assert!(!data.exists());
    unconfigure(&data).unwrap(); // 不存在也成功
}

#[test]
fn registry_values_are_read_and_guarded() {
    use protocol::{RegState, RegistryQuery};
    let q = |p: &str, n: &str| RegistryQuery {
        path: p.into(),
        name: n.into(),
    };
    let v = endpoint_agent::windows::registry::read_values(&[
        q(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "CurrentBuild",
        ),
        q(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "NoSuchValue-EM",
        ),
        q(r"HKLM\SAM\SAM", "C"),
        q("hklm/sam/SAM", "C"),
        q(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "DefaultPassword",
        ),
        // Windows API 讀到 NUL 就停：守衛必須擋下，不能讀到 ProductName
        q(
            &format!(
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion{}\x",
                '\u{0}'
            ),
            "ProductName",
        ),
        q(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "ProductName\u{0}junk",
        ),
    ]);
    assert_eq!(v.len(), 7);
    assert_eq!(v[0].state, RegState::Present, "{:?}", v[0]);
    assert!(v[0].data.parse::<u32>().is_ok(), "{:?}", v[0]);
    assert_eq!(v[1].state, RegState::Absent);
    assert!(v[2..].iter().all(|x| x.state == RegState::Denied), "{v:?}");
}

/// Agent 寫入的 WU 原則值名稱必須和 Windows 的 ADMX 一致（值名稱寫錯 Windows 會直接忽略）。
/// Windows Home 沒有 PolicyDefinitions：本機略過，CI 必須檢查到。
#[test]
fn admx_declares_every_policy_value() {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let path = format!(r"{root}\PolicyDefinitions\WindowsUpdate.admx");
    let Ok(admx) = std::fs::read_to_string(&path) else {
        assert!(std::env::var_os("CI").is_none(), "CI 必須有 {path}");
        eprintln!("略過：沒有 {path}");
        return;
    };
    // 值名稱所在元素的標籤（<text、<decimal、<boolean …；原則本身的 valueName 為 <policy）
    let tag = |name: &str| -> Option<String> {
        let at = admx.find(&format!("valueName=\"{name}\""))?;
        let start = admx[..at].rfind('<')?;
        Some(
            admx[start + 1..]
                .split(|c: char| c.is_whitespace())
                .next()?
                .to_string(),
        )
    };
    let missing: Vec<&str> = protocol::update::VALUE_NAMES
        .into_iter()
        .filter(|n| tag(n).is_none() && !protocol::update::LEGACY_VALUE_NAMES.contains(n))
        .collect();
    assert!(missing.is_empty(), "ADMX 沒有這些值：{missing:?}");
    assert_eq!(tag("PauseQualityUpdatesStartTime").as_deref(), Some("text"));
    assert_eq!(tag("PauseFeatureUpdatesStartTime").as_deref(), Some("text"));
    assert_eq!(
        tag("DeferQualityUpdatesPeriodInDays").as_deref(),
        Some("decimal")
    );
}

/// 不需系統管理員：在 HKCU 的測試機碼實際寫入、讀回、刪除
#[test]
fn registry_host_round_trip() {
    use endpoint_agent::updates::host::WuHost;
    use endpoint_agent::windows::wupolicy::RegistryHost;
    use protocol::update::PolicyData;
    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;

    let parent = r"Software\endpoint-manager-test";
    let path = format!(r"{parent}\{}", uuid::Uuid::new_v4());
    let h = RegistryHost::at(endpoint_agent::windows::regwatch::Root::CurrentUser, &path);
    assert_eq!(h.read("DeferQualityUpdates").unwrap(), None, "機碼不存在");
    h.write("DeferQualityUpdates", &PolicyData::Dword(1))
        .unwrap();
    h.write(
        "PauseQualityUpdatesStartTime",
        &PolicyData::String("2026-09-30".into()),
    )
    .unwrap();
    assert_eq!(
        h.read("DeferQualityUpdates").unwrap(),
        Some(PolicyData::Dword(1))
    );
    assert_eq!(
        h.read("PauseQualityUpdatesStartTime").unwrap(),
        Some(PolicyData::String("2026-09-30".into()))
    );
    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(&path, winreg::enums::KEY_ALL_ACCESS)
        .unwrap();
    assert_eq!(
        key.get_raw_value("PauseQualityUpdatesStartTime")
            .unwrap()
            .vtype,
        winreg::enums::RegType::REG_SZ
    );
    key.set_value("Other", &vec!["a".to_string()]).unwrap();
    assert_eq!(h.read("Other").unwrap(), Some(PolicyData::Unknown));
    h.delete("DeferQualityUpdates").unwrap();
    h.delete("DeferQualityUpdates").unwrap();
    assert_eq!(h.read("DeferQualityUpdates").unwrap(), None);
    let _ = h.reboot_pending();
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(parent, winreg::enums::KEY_ALL_ACCESS)
        .unwrap()
        .delete_subkey_all(path.rsplit('\\').next().unwrap())
        .unwrap();
}

/// 不需系統管理員：實際以 PowerShell 執行腳本，收回輸出與結束碼
#[tokio::test]
async fn windows_host_runs_powershell_script() {
    use endpoint_agent::commands::worker::CommandHost;
    use endpoint_agent::deploy::worker::RunResult;
    use endpoint_agent::windows::commands::WindowsHost;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.ps1");
    std::fs::write(
        &path,
        format!(
            "\u{feff}{}Write-Output '你好 hi'; exit 3",
            endpoint_agent::commands::logic::SCRIPT_PRELUDE
        ),
    )
    .unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(4);
    let host = WindowsHost {
        triggers: tx,
        nudges: vec![],
    };
    let out = host
        .run_script(&path, std::time::Duration::from_secs(120))
        .await
        .unwrap();
    assert_eq!(out.result, RunResult::Exited(3));
    assert!(out.output.contains("你好 hi"), "{}", out.output);
}
