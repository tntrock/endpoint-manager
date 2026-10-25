//! 帳號與管理權限：讀 /etc 檔案後交給 linux_parse::accounts。

use crate::linux_parse::accounts::{self as parse, Include, SudoersFile};
use protocol::{AccountsInfo, PrincipalKind, PrivilegeEntry};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// sudoers include 最多三層（sudoers 本身算第一層）
const MAX_DEPTH: usize = 3;

fn unreadable(path: &Path, e: &dyn std::fmt::Display) -> String {
    format!("無法讀取 {}：{e}", path.display())
}

/// 讀 sudoers 與它的 include：同一個實際路徑只讀一次，超過三層不再展開。
/// 回 (已讀入的檔案, 讀不到的說明行)。
fn read_sudoers_tree(entry: &Path) -> (Vec<SudoersFile>, Vec<String>) {
    let mut files = Vec::new();
    let mut errs = Vec::new();
    let mut seen = HashSet::new();
    read_file(entry, 1, &mut seen, &mut files, &mut errs);
    (files, errs)
}

fn read_file(
    path: &Path,
    depth: usize,
    seen: &mut HashSet<PathBuf>,
    files: &mut Vec<SudoersFile>,
    errs: &mut Vec<String>,
) {
    if depth > MAX_DEPTH {
        errs.push(format!(
            "略過 {}：include 超過 {MAX_DEPTH} 層",
            path.display()
        ));
        return;
    }
    let real = match fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) => return errs.push(unreadable(path, &e)),
    };
    if !seen.insert(real.clone()) {
        return;
    }
    let content = match fs::read_to_string(&real) {
        Ok(c) => c,
        Err(e) => return errs.push(unreadable(path, &e)),
    };
    let includes = parse::include_targets(&content);
    files.push(SudoersFile {
        name: path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        content,
    });
    for inc in includes {
        match inc {
            Include::File(p) => read_file(Path::new(&p), depth + 1, seen, files, errs),
            Include::Dir(d) => read_dir(Path::new(&d), depth + 1, seen, files, errs),
        }
    }
}

fn read_dir(
    dir: &Path,
    depth: usize,
    seen: &mut HashSet<PathBuf>,
    files: &mut Vec<SudoersFile>,
    errs: &mut Vec<String>,
) {
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => return errs.push(unreadable(dir, &e)),
    };
    let mut names: Vec<String> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.contains('.') && !n.ends_with('~'))
        .collect();
    names.sort();
    for n in names {
        let p = dir.join(n);
        if p.is_file() {
            read_file(&p, depth, seen, files, errs);
        }
    }
}

fn read_or_empty(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

pub fn collect() -> AccountsInfo {
    let passwd = read_or_empty("/etc/passwd");
    // 讀不到（沒有 root 權限）→ None；密碼欄位只在 parse 內部判斷後即丟棄
    let shadow = fs::read_to_string("/etc/shadow").ok();
    let min = parse::uid_min(&read_or_empty("/etc/login.defs"));
    let (users, system_user_count) = parse::users(&passwd, shadow.as_deref(), min);

    let mut privileged: Vec<PrivilegeEntry> = parse::uid_zero(&passwd)
        .into_iter()
        .map(|principal| PrivilegeEntry {
            principal,
            kind: PrincipalKind::User,
            source: "uid0".into(),
        })
        .collect();
    privileged.extend(
        parse::admin_group_members(&read_or_empty("/etc/group"))
            .into_iter()
            .map(|(principal, source)| PrivilegeEntry {
                principal,
                kind: PrincipalKind::User,
                source,
            }),
    );
    let (files, mut sudoers_unparsed) = read_sudoers_tree(Path::new("/etc/sudoers"));
    let (entries, unparsed) = parse::sudoers(&files);
    privileged.extend(entries);
    sudoers_unparsed.extend(unparsed);
    let sudoers_unparsed = parse::cap_unparsed(sudoers_unparsed);

    AccountsInfo {
        users,
        system_user_count,
        privileged,
        sudoers_unparsed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn include_loop_terminates() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (d.path().join("a"), d.path().join("b"));
        fs::write(
            &a,
            format!("root ALL=(ALL) ALL\n#include {}\n", b.display()),
        )
        .unwrap();
        fs::write(&b, format!("bob ALL=(ALL) ALL\n@include {}\n", a.display())).unwrap();
        let (files, errs) = read_sudoers_tree(&a);
        let names: Vec<_> = files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["a", "b"]);
        assert!(errs.is_empty());
    }

    #[test]
    fn include_depth_and_dir_rules() {
        let d = tempfile::tempdir().unwrap();
        let p = |n: &str| d.path().join(n);
        let sub = p("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(
            p("main"),
            format!(
                "#includedir {}\n#include {}\n",
                sub.display(),
                p("missing").display()
            ),
        )
        .unwrap();
        fs::write(sub.join("10-x"), "").unwrap();
        fs::write(sub.join("skip.bak"), "").unwrap();
        fs::write(sub.join("skip~"), "").unwrap();
        // 10-x -> l2 -> l3 -> l4（第四層）
        fs::write(
            sub.join("10-x"),
            format!("#include {}\n", p("l2").display()),
        )
        .unwrap();
        fs::write(p("l2"), format!("#include {}\n", p("l3").display())).unwrap();
        fs::write(p("l3"), "").unwrap();
        let (files, errs) = read_sudoers_tree(&p("main"));
        let names: Vec<_> = files.iter().map(|f| f.name.as_str()).collect();
        // main(1) -> 10-x(2) -> l2(3) -> l3(4) 被略過
        assert_eq!(names, ["main", "10-x", "l2"]);
        assert_eq!(errs.len(), 2);
        assert!(errs.iter().any(|e| e.starts_with("無法讀取 ")));
        assert!(errs.iter().any(|e| e.contains("超過")));
    }

    #[test]
    fn collect_works_unprivileged() {
        let info = collect();
        // SAFETY: getuid 無前置條件
        let uid = unsafe { libc::getuid() };
        if uid == 0 || uid >= 1000 {
            assert!(info.users.iter().any(|u| u.uid == uid));
        }
        assert!(info.privileged.iter().any(|p| p.source == "uid0"));
    }
}
