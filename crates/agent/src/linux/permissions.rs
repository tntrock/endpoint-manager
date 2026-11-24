//! Linux 權限過寬（錯誤設定規格 §6.1）：`/etc` 底下所有人可寫入的檔案、
//! 一般使用者讀得到的 shadow、不屬於任何套件的 SUID／SGID 程式。

use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use protocol::{PermissionItem, PermissionsInfo};

use super::exec::{Run, is_not_found, real_run};
use crate::permissions::{alt_path, finish};

/// 檢查 SUID 的系統執行檔目錄（相對於根目錄）
const SUID_DIRS: [&str; 6] = [
    "usr/bin",
    "usr/sbin",
    "bin",
    "sbin",
    "usr/local/bin",
    "usr/local/sbin",
];
/// `/etc` 最多走幾層、看幾個項目
const MAX_DEPTH: usize = 16;
const MAX_ENTRIES: usize = 50_000;

const EVERYONE: &str = "所有人";

pub fn collect() -> PermissionsInfo {
    collect_with(&real_run, Path::new("/"))
}

/// 根目錄底下的路徑轉成 `/…` 顯示
fn display(root: &Path, p: &Path) -> String {
    match p.strip_prefix(root) {
        Ok(r) => format!("/{}", r.display()),
        Err(_) => p.display().to_string(),
    }
}

/// `/etc` 底下所有人可寫入的一般檔案：不跟隨符號連結、不跨檔案系統
fn world_writable(root: &Path, items: &mut Vec<PermissionItem>, errors: &mut Vec<String>) {
    let etc = root.join("etc");
    let dev = match std::fs::symlink_metadata(&etc) {
        Ok(m) => m.dev(),
        Err(e) => {
            errors.push(format!("無法讀取 /etc：{e}"));
            return;
        }
    };
    let mut stack = vec![(etc, 0usize)];
    let mut seen = 0;
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            seen += 1;
            if seen > MAX_ENTRIES {
                return;
            }
            let p = e.path();
            let Ok(m) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if m.is_dir() {
                if depth < MAX_DEPTH && m.dev() == dev {
                    stack.push((p, depth + 1));
                }
            } else if m.is_file() && m.mode() & 0o002 != 0 {
                items.push(PermissionItem {
                    kind: "etc_writable".into(),
                    path: display(root, &p),
                    name: None,
                    granted_to: vec![EVERYONE.into()],
                });
            }
        }
    }
}

/// `/etc/shadow`、`/etc/gshadow` 其他人可讀
fn shadow_readable(root: &Path, items: &mut Vec<PermissionItem>) {
    for f in ["shadow", "gshadow"] {
        let p = root.join("etc").join(f);
        if std::fs::symlink_metadata(&p).is_ok_and(|m| m.is_file() && m.mode() & 0o004 != 0) {
            items.push(PermissionItem {
                kind: "shadow_readable".into(),
                path: display(root, &p),
                name: None,
                granted_to: vec![EVERYONE.into()],
            });
        }
    }
}

/// 執行檔是否屬於某個套件：先問 dpkg（merged-usr 再試另一種路徑），沒有 dpkg 再問 rpm。
/// 兩個都沒有時回錯誤
fn packaged(run: Run, path: &str) -> anyhow::Result<bool> {
    match run("dpkg", &["-S", path]) {
        Ok(_) => return Ok(true),
        Err(e) if is_not_found(&e) => {}
        Err(_) => {
            return Ok(alt_path(path).is_some_and(|a| run("dpkg", &["-S", &a]).is_ok()));
        }
    }
    match run("rpm", &["-qf", path]) {
        Ok(_) => Ok(true),
        Err(e) if is_not_found(&e) => anyhow::bail!("沒有 dpkg 或 rpm"),
        Err(_) => Ok(false),
    }
}

/// 系統執行檔目錄裡的 SUID／SGID 程式：(實際路徑, 權限位元)
fn suid_files(root: &Path) -> Vec<(PathBuf, u32)> {
    let mut seen = BTreeSet::new();
    let mut out = vec![];
    for d in SUID_DIRS {
        let Ok(rd) = std::fs::read_dir(root.join(d)) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(m) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if !m.is_file() || m.mode() & 0o6000 == 0 {
                continue;
            }
            // /bin 是 /usr/bin 的連結時只算一次
            let real = std::fs::canonicalize(&p).unwrap_or(p);
            if seen.insert(real.clone()) {
                out.push((real, m.mode()));
            }
        }
    }
    out.sort();
    out
}

/// `root` 是根目錄（測試換成暫存目錄）
pub fn collect_with(run: Run, root: &Path) -> PermissionsInfo {
    let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let (mut items, mut errors) = (vec![], vec![]);
    world_writable(&root, &mut items, &mut errors);
    shadow_readable(&root, &mut items);
    for (p, mode) in suid_files(&root) {
        let shown = display(&root, &p);
        match packaged(run, &shown) {
            Ok(true) => {}
            Ok(false) => {
                let mut who = vec![];
                if mode & 0o4000 != 0 {
                    who.push("SUID".to_string());
                }
                if mode & 0o2000 != 0 {
                    who.push("SGID".to_string());
                }
                items.push(PermissionItem {
                    kind: "suid".into(),
                    path: shown,
                    name: None,
                    granted_to: who,
                });
            }
            Err(e) => {
                errors.push(format!("無法判斷 SUID 程式屬於哪個套件：{e}"));
                break;
            }
        }
    }
    finish(items, errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::exec::not_found;
    use std::os::unix::fs::PermissionsExt;

    fn chmod(p: &Path, mode: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn file(root: &Path, rel: &str, mode: u32) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"x").unwrap();
        chmod(&p, mode);
    }

    fn tree() -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        file(r, "etc/passwd", 0o644);
        file(r, "etc/cron.d/job", 0o666);
        file(r, "etc/deep/a/b/c.conf", 0o646);
        file(r, "etc/shadow", 0o644);
        file(r, "etc/gshadow", 0o640);
        file(r, "usr/bin/su", 0o4755);
        file(r, "usr/bin/ls", 0o755);
        file(r, "usr/local/bin/backdoor", 0o4755);
        file(r, "usr/sbin/wall", 0o2755);
        std::os::unix::fs::symlink(r.join("usr/bin"), r.join("bin")).unwrap();
        std::os::unix::fs::symlink("/tmp", r.join("etc/link")).unwrap();
        t
    }

    #[test]
    fn finds_weak_permissions() {
        let t = tree();
        let dpkg = |p: &str, a: &[&str]| -> anyhow::Result<String> {
            assert_eq!(p, "dpkg");
            match a[1] {
                "/usr/bin/su" => Ok("login: /usr/bin/su".into()),
                // merged-usr：套件登記的是 /sbin/wall
                "/sbin/wall" => Ok("util: /sbin/wall".into()),
                _ => anyhow::bail!("dpkg-query: no path found"),
            }
        };
        let i = collect_with(&dpkg, t.path());
        let got: Vec<_> = i
            .items
            .iter()
            .map(|x| (x.kind.as_str(), x.path.as_str(), x.granted_to.join(",")))
            .collect();
        assert_eq!(
            got,
            [
                ("etc_writable", "/etc/cron.d/job", "所有人".to_string()),
                ("etc_writable", "/etc/deep/a/b/c.conf", "所有人".to_string()),
                ("shadow_readable", "/etc/shadow", "所有人".to_string()),
                ("suid", "/usr/local/bin/backdoor", "SUID".to_string()),
            ]
        );
        assert!(i.errors.is_empty(), "{:?}", i.errors);
    }

    #[test]
    fn rpm_and_missing_managers() {
        let t = tree();
        let rpm = |p: &str, a: &[&str]| -> anyhow::Result<String> {
            match (p, a[1]) {
                ("dpkg", _) => Err(not_found("dpkg")),
                ("rpm", "/usr/bin/su" | "/usr/sbin/wall") => Ok("x".into()),
                _ => anyhow::bail!("file {} is not owned by any package", a[1]),
            }
        };
        let i = collect_with(&rpm, t.path());
        let suid: Vec<_> = i.items.iter().filter(|x| x.kind == "suid").collect();
        assert_eq!(suid.len(), 1);
        assert_eq!(suid[0].path, "/usr/local/bin/backdoor");

        let none = |p: &str, _: &[&str]| -> anyhow::Result<String> { Err(not_found(p)) };
        let i = collect_with(&none, t.path());
        assert!(i.items.iter().all(|x| x.kind != "suid"));
        assert_eq!(
            i.errors,
            ["無法判斷 SUID 程式屬於哪個套件：沒有 dpkg 或 rpm"]
        );
        // 沒有 /etc
        let empty = tempfile::tempdir().unwrap();
        let i = collect_with(&none, empty.path());
        assert!(i.errors[0].starts_with("無法讀取 /etc"), "{:?}", i.errors);
    }

    #[test]
    fn collect_works_unprivileged() {
        // 真的系統：不應該失敗，項目都有路徑
        let i = collect();
        assert!(i.items.iter().all(|x| x.path.starts_with('/')), "{i:?}");
    }
}
