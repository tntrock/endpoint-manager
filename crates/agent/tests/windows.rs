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
