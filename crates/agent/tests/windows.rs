//! Windows 實機冒煙測試。
#![cfg(windows)]

use std::process::Command;

use endpoint_agent::state::secure_dir;

/// 以 SDDL 檢查（不受系統語系影響）：只剩 SYSTEM (SY) 與 Administrators (BA)。
#[test]
fn secure_dir_leaves_only_system_and_admins() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("em");
    secure_dir(&target).unwrap();

    let save = dir.path().join("acl.txt");
    let ok = Command::new("icacls")
        .arg(&target)
        .arg("/save")
        .arg(&save)
        .status()
        .unwrap()
        .success();
    assert!(ok);
    let raw = std::fs::read(&save).unwrap();
    let utf16: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    let sddl = String::from_utf16_lossy(&utf16);
    assert!(sddl.contains(";;;SY)") && sddl.contains(";;;BA)"), "{sddl}");
    for other in [";;;BU)", ";;;AU)", ";;;WD)", ";;;CO)"] {
        assert!(!sddl.contains(other), "{other} in {sddl}");
    }

    // 還原，讓 tempdir 可以刪除（擁有者仍有 WRITE_DAC）
    Command::new("icacls")
        .arg(&target)
        .arg("/reset")
        .status()
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

    for s in Section::ALL {
        let mut p = c.collect(s).unwrap_or_else(|e| panic!("{s:?}: {e:#}"));
        sanitize(&mut p);
        assert_eq!(p.validate(), Ok(()), "{s:?}");
        match p {
            InventoryPayload::Basic(b) => assert!(!b.os_caption.is_empty()),
            InventoryPayload::Hardware(h) => assert!(h.ram_mb > 0),
            InventoryPayload::Software(v) => assert!(!v.is_empty()),
            InventoryPayload::Services(v) => {
                assert!(v.iter().any(|s| s.name.eq_ignore_ascii_case("EventLog")))
            }
            InventoryPayload::Patches(_) => {}
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

/// 需要系統管理員權限（CI 的 windows runner 有）；一般權限下略過。
#[test]
fn harden_dir_takes_ownership_from_squatter() {
    let elevated = Command::new("net")
        .arg("session")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !elevated {
        eprintln!("skipped: not elevated");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("em");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("state.json.tmp"), b"squatted").unwrap();
    endpoint_agent::state::harden_dir(&target).unwrap();

    // icacls /save 不含擁有者，改用 Get-Acl 取完整 SDDL（O: 擁有者、D: DACL）
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command"])
        .arg(format!(
            "(Get-Acl -LiteralPath '{}').Sddl",
            target.join("state.json.tmp").display()
        ))
        .output()
        .unwrap();
    let sddl = String::from_utf8_lossy(&out.stdout).to_string();
    let diag = format!(
        "sddl=[{sddl}] stderr=[{}]",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !sddl.contains(";;;BU)") && !sddl.contains(";;;AU)"),
        "{diag}"
    );
    assert!(sddl.contains("O:BA"), "{diag}");
    Command::new("icacls")
        .arg(&target)
        .args(["/reset", "/T", "/C", "/Q"])
        .status()
        .unwrap();
}
