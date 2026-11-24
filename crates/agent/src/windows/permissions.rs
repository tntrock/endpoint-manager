//! Windows 權限過寬（錯誤設定規格 §6.1）：服務執行檔與所在資料夾、以 SYSTEM 執行的排程工作，
//! 一般使用者可以改寫的。判斷在 [`crate::permissions`]。

use std::collections::HashMap;
use std::path::Path;

use protocol::{PermissionItem, PermissionsInfo};

use super::shares::ntfs_sddl;
use crate::permissions::{
    binary_of, decode_text, finish, parent_dir, system_task_commands, writable_by_users,
};

/// 服務類型：自己的程序或共用程序（排除驅動程式）
const SERVICE_WIN32: u32 = 0x30;
/// 排程工作定義檔最多讀幾個
const MAX_TASK_FILES: usize = 5000;

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok()
}

/// 檢查過的路徑（同一個執行檔可能有很多服務）
#[derive(Default)]
struct Checker {
    seen: HashMap<(String, bool), Vec<String>>,
    items: Vec<PermissionItem>,
    errors: Vec<String>,
}

impl Checker {
    fn check(&mut self, path: &str, dir: bool, kind: &str, name: &str) {
        let key = (path.to_lowercase(), dir);
        let who = match self.seen.get(&key) {
            Some(w) => w.clone(),
            None => {
                let w = match ntfs_sddl(path) {
                    Ok(sddl) => writable_by_users(&sddl, dir),
                    // 檔案不存在（解除安裝後留下的服務、路徑錯誤）：不算
                    Err(e) if matches!(e.raw_os_error(), Some(2 | 3)) => vec![],
                    Err(e) => {
                        if self.errors.len() < 20 {
                            self.errors.push(format!("無法讀取 {path} 的權限：{e}"));
                        }
                        vec![]
                    }
                };
                self.seen.insert(key, w.clone());
                w
            }
        };
        if !who.is_empty() {
            self.items.push(PermissionItem {
                kind: kind.into(),
                path: path.into(),
                name: Some(name.into()),
                granted_to: who,
            });
        }
    }

    fn services(&mut self) {
        let root = match winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
            .open_subkey(r"SYSTEM\CurrentControlSet\Services")
        {
            Ok(k) => k,
            Err(e) => {
                self.errors.push(format!("無法讀取服務清單：{e}"));
                return;
            }
        };
        for name in root.enum_keys().flatten() {
            let Ok(k) = root.open_subkey(&name) else {
                continue;
            };
            if k.get_value::<u32, _>("Type").unwrap_or(0) & SERVICE_WIN32 == 0 {
                continue;
            }
            let Ok(image) = k.get_value::<String, _>("ImagePath") else {
                continue;
            };
            let Some(bin) = binary_of(&image, &env) else {
                continue;
            };
            self.check(&bin, false, "service_binary", &name);
            if let Some(dir) = parent_dir(&bin) {
                self.check(dir, true, "service_dir", &name);
            }
        }
    }

    fn tasks(&mut self, dir: &Path) {
        let mut stack = vec![dir.to_path_buf()];
        let mut files = 0;
        while let Some(d) = stack.pop() {
            let entries = match std::fs::read_dir(&d) {
                Ok(e) => e,
                Err(e) => {
                    self.errors
                        .push(format!("無法讀取排程工作 {}：{e}", d.display()));
                    continue;
                }
            };
            for e in entries.flatten() {
                let p = e.path();
                let Ok(t) = e.file_type() else { continue };
                if t.is_dir() {
                    stack.push(p);
                    continue;
                }
                files += 1;
                if files > MAX_TASK_FILES {
                    return;
                }
                let Ok(bytes) = std::fs::read(&p) else {
                    continue;
                };
                let Some(cmds) = system_task_commands(&decode_text(&bytes)) else {
                    continue;
                };
                let name = p.strip_prefix(dir).map_or_else(
                    |_| p.display().to_string(),
                    |r| format!(r"\{}", r.display()),
                );
                for c in cmds {
                    if let Some(bin) = binary_of(&c, &env) {
                        self.check(&bin, false, "task_binary", &name);
                    }
                }
            }
        }
    }
}

pub fn collect() -> PermissionsInfo {
    let mut c = Checker::default();
    c.services();
    let root = env("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    c.tasks(&Path::new(&root).join(r"System32\Tasks"));
    finish(c.items, c.errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writable_folder_and_task_are_found() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("svc.exe");
        std::fs::write(&exe, b"x").unwrap();
        // 測試建立的資料夾：只給 SYSTEM、Administrators，再加上 Users 修改
        let p = dir.path().to_str().unwrap().to_string();
        let st = std::process::Command::new("icacls")
            .args([
                &p,
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
            ])
            .output()
            .unwrap();
        assert!(st.status.success(), "{st:?}");
        let mut c = Checker::default();
        c.check(exe.to_str().unwrap(), false, "service_binary", "a");
        c.check(&p, true, "service_dir", "a");
        assert!(c.items.is_empty(), "{:?}", c.items);
        let st = std::process::Command::new("icacls")
            .args([&p, "/grant", "*S-1-5-32-545:(OI)(CI)M"])
            .output()
            .unwrap();
        assert!(st.status.success(), "{st:?}");
        let mut c = Checker::default();
        c.check(exe.to_str().unwrap(), false, "service_binary", "a");
        c.check(exe.to_str().unwrap(), false, "service_binary", "b");
        c.check(&p, true, "service_dir", "a");
        c.check(r"C:\no\such\file.exe", false, "service_binary", "gone");
        let got: Vec<_> = c
            .items
            .iter()
            .map(|i| (i.kind.as_str(), i.name.as_deref(), i.granted_to.clone()))
            .collect();
        assert_eq!(
            got,
            [
                ("service_binary", Some("a"), vec!["Users".to_string()]),
                ("service_binary", Some("b"), vec!["Users".to_string()]),
                ("service_dir", Some("a"), vec!["Users".to_string()]),
            ]
        );
        assert!(c.errors.is_empty(), "{:?}", c.errors);

        // 排程工作：資料夾裡的 XML，以 SYSTEM 執行可改寫的程式
        let tasks = tempfile::tempdir().unwrap();
        std::fs::create_dir(tasks.path().join("Vendor")).unwrap();
        let xml = format!(
            "<Task><Principals><Principal><UserId>S-1-5-18</UserId></Principal></Principals>\
<Actions><Exec><Command>\"{}\"</Command></Exec></Actions></Task>",
            exe.display()
        );
        let mut b = vec![0xFF, 0xFE];
        b.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
        std::fs::write(tasks.path().join("Vendor").join("Update"), b).unwrap();
        let mut c = Checker::default();
        c.tasks(tasks.path());
        assert_eq!(c.items.len(), 1, "{:?}", c.items);
        assert_eq!(c.items[0].name.as_deref(), Some(r"\Vendor\Update"));
        assert_eq!(c.items[0].kind, "task_binary");
    }

    #[test]
    fn collect_runs() {
        let i = collect();
        // 一般的 CI 機器不應該有一般使用者可改寫的服務
        assert!(
            i.items
                .iter()
                .all(|x| !x.path.is_empty() && !x.granted_to.is_empty()),
            "{i:?}"
        );
    }
}
