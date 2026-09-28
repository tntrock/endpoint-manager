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
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
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
