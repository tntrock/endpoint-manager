//! passwd / shadow / group / sudoers 的解析。
//! 安全：shadow 的密碼欄位只用來判斷是否鎖定，不會被存進任何結構、錯誤或訊息。

use chrono::NaiveDate;
use protocol::{LocalUser, PrincipalKind, PrivilegeEntry};
use std::collections::HashMap;

const UNPARSED_MAX_LINES: usize = 50;
const UNPARSED_MAX_CHARS: usize = 200;
const ADMIN_GROUPS: [&str; 3] = ["sudo", "wheel", "admin"];
const ALIAS_KEYWORDS: [&str; 4] = ["User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias"];
/// 1970-01-01 距西元 1 年 1 月 1 日的天數
const UNIX_EPOCH_DAYS_FROM_CE: i64 = 719_163;

/// `/etc/login.defs` 的 `UID_MIN`，沒有或無法解析 → 1000。
pub fn uid_min(login_defs: &str) -> u32 {
    login_defs
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            (it.next()? == "UID_MIN").then(|| it.next()?.parse().ok())?
        })
        .next_back()
        .unwrap_or(1000)
}

/// 只保留 (是否鎖定, 最後變更日)，密碼欄位在這裡就丟掉。
fn parse_shadow(shadow: &str) -> HashMap<&str, (bool, Option<NaiveDate>)> {
    shadow
        .lines()
        .filter_map(|l| {
            let mut f = l.split(':');
            let name = f.next()?;
            let pw = f.next()?;
            let locked = pw.starts_with('!') || pw.starts_with('*');
            let changed = f
                .next()
                .and_then(|d| d.trim().parse::<i64>().ok())
                .filter(|&n| n != 0)
                .and_then(|n| i32::try_from(n.checked_add(UNIX_EPOCH_DAYS_FROM_CE)?).ok())
                .and_then(NaiveDate::from_num_days_from_ce_opt);
            Some((name, (locked, changed)))
        })
        .collect()
}

/// 可登入帳號與系統帳號數。
pub fn users(passwd: &str, shadow: Option<&str>, uid_min: u32) -> (Vec<LocalUser>, u32) {
    let sh = shadow.map(parse_shadow);
    let mut out = Vec::new();
    let mut system = 0;
    for l in passwd.lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 7 {
            continue;
        }
        let Ok(uid) = f[2].parse::<u32>() else {
            continue;
        };
        let shell = f[6];
        let base = shell.rsplit('/').next().unwrap_or("");
        let hidden = matches!(base, "nologin" | "false" | "sync" | "halt" | "shutdown")
            || (uid < uid_min && f[0] != "root");
        if hidden {
            system += 1;
            continue;
        }
        let entry = sh.as_ref().and_then(|m| m.get(f[0]));
        out.push(LocalUser {
            name: f[0].to_string(),
            uid,
            shell: shell.to_string(),
            locked: entry.map(|e| e.0),
            password_changed: entry.and_then(|e| e.1),
        });
    }
    (out, system)
}

/// 所有 UID 0 的帳號名稱。
pub fn uid_zero(passwd: &str) -> Vec<String> {
    passwd
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() >= 3 && f[2] == "0").then(|| f[0].to_string())
        })
        .collect()
}

/// `sudo`、`wheel`、`admin` 群組的成員：`(成員, "group:<群組名>")`。
pub fn admin_group_members(group: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for l in group.lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 4 || !ADMIN_GROUPS.contains(&f[0]) {
            continue;
        }
        for m in f[3].split(',').map(str::trim).filter(|m| !m.is_empty()) {
            out.push((m.to_string(), format!("group:{}", f[0])));
        }
    }
    out
}

pub struct SudoersFile {
    pub name: String,
    pub content: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Include {
    File(String),
    Dir(String),
}

/// 行尾 `\` 接續下一行。
fn logical_lines(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for l in content.lines() {
        match l.strip_suffix('\\') {
            Some(head) => cur.push_str(head),
            None => {
                cur.push_str(l);
                out.push(std::mem::take(&mut cur));
            }
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn include_of(line: &str) -> Option<Include> {
    let mut it = line.trim().splitn(2, char::is_whitespace);
    let kind = it.next()?;
    let path = it.next()?.trim().trim_matches('"');
    if path.is_empty() {
        return None;
    }
    match kind {
        "#include" | "@include" => Some(Include::File(path.to_string())),
        "#includedir" | "@includedir" => Some(Include::Dir(path.to_string())),
        _ => None,
    }
}

/// 這個檔案裡的 include 指令。
pub fn include_targets(content: &str) -> Vec<Include> {
    logical_lines(content)
        .iter()
        .filter_map(|l| include_of(l))
        .collect()
}

/// 主體是別名（全大寫）或特殊寫法 → 不解析。
fn is_special(name: &str) -> bool {
    let n = name.strip_prefix('%').unwrap_or(name);
    n.is_empty()
        || n.starts_with(['+', '!', '#', ':'])
        || n.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// 只處理已讀入的檔案內容（include 由呼叫端展開）。回 (有效項目, 解析不了的原文行)。
pub fn sudoers(files: &[SudoersFile]) -> (Vec<PrivilegeEntry>, Vec<String>) {
    let mut entries = Vec::new();
    let mut unparsed = Vec::new();
    for f in files {
        for raw in logical_lines(&f.content) {
            let line = raw.trim();
            if line.is_empty()
                || (line.starts_with('#')
                    && !line.as_bytes().get(1).is_some_and(u8::is_ascii_digit))
                || line.starts_with('@')
                || line.starts_with("Defaults")
            {
                continue;
            }
            let first = line.split_whitespace().next().unwrap_or("");
            // 等號左邊最後一個空白分隔的詞是主機，前面整段是主體清單（逗號兩側可有空白）
            let names: Vec<&str> = line
                .split_once('=')
                .and_then(|(left, _)| left.trim_end().rsplit_once(char::is_whitespace))
                .map(|(subj, _)| {
                    subj.split(',')
                        .map(str::trim)
                        .filter(|n| !n.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            if ALIAS_KEYWORDS.contains(&first)
                || names.is_empty()
                || names
                    .iter()
                    .any(|n| n.contains(char::is_whitespace) || is_special(n))
            {
                unparsed.push(line.to_string());
                continue;
            }
            for n in names {
                let (principal, kind) = match n.strip_prefix('%') {
                    Some(g) => (g, PrincipalKind::Group),
                    None => (n, PrincipalKind::User),
                };
                entries.push(PrivilegeEntry {
                    principal: principal.to_string(),
                    kind,
                    source: format!("sudoers:{}", f.name),
                });
            }
        }
    }
    (entries, cap_unparsed(unparsed))
}

/// 最多 50 行、每行最多 200 字元。
pub fn cap_unparsed(lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .take(UNPARSED_MAX_LINES)
        .map(|l| l.chars().take(UNPARSED_MAX_CHARS).collect())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "root:x:0:0::/root:/bin/bash\n\
daemon:x:1:1::/:/usr/sbin/nologin\n\
alice:x:1000:1000::/home/alice:/bin/bash\n\
bob:x:1001:1001::/home/bob:/bin/zsh\n\
svc:x:999:999::/:/bin/bash\n";
    const SHADOW: &str = "root:*:19000:0:99999:7:::\n\
alice:$6$abc$hash:19500:0:99999:7:::\n\
bob:!$6$x:0:0:99999:7:::\n";

    fn d(y: i32, m: u32, day: u32) -> Option<NaiveDate> {
        NaiveDate::from_ymd_opt(y, m, day)
    }

    #[test]
    fn users_filters_and_reads_shadow() {
        let (u, sys) = users(PASSWD, Some(SHADOW), 1000);
        let got: Vec<_> = u
            .iter()
            .map(|x| (x.name.as_str(), x.locked, x.password_changed))
            .collect();
        assert_eq!(
            got,
            vec![
                ("root", Some(true), d(2022, 1, 8)),
                ("alice", Some(false), d(2023, 5, 23)),
                ("bob", Some(true), None),
            ]
        );
        assert_eq!(sys, 2);
        let (u, _) = users(PASSWD, None, 1000);
        assert!(
            u.iter()
                .all(|x| x.locked.is_none() && x.password_changed.is_none())
        );
    }

    #[test]
    fn shadow_secrets_never_leak() {
        let (u, _) = users(PASSWD, Some(SHADOW), 1000);
        let dbg = format!("{u:?}");
        let json = serde_json::to_string(&u).unwrap();
        for s in ["$6$", "abc", "hash"] {
            assert!(!dbg.contains(s) && !json.contains(s), "{s}");
        }
    }

    #[test]
    fn uid_min_parses() {
        assert_eq!(uid_min("UID_MIN\t\t500\n"), 500);
        assert_eq!(uid_min("# UID_MIN 5\n"), 1000);
        assert_eq!(uid_min("UID_MIN abc"), 1000);
    }

    #[test]
    fn uid_zero_lists_impostors() {
        let p = "root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/:/bin/sh\nbob:x:1001:1::/:/bin/sh\n";
        assert_eq!(uid_zero(p), ["root", "toor"]);
    }

    #[test]
    fn group_members() {
        let g = "sudo:x:27:alice,bob\nwheel:x:10:\nadm:x:4:carol\n";
        assert_eq!(
            admin_group_members(g),
            [
                ("alice".to_string(), "group:sudo".to_string()),
                ("bob".to_string(), "group:sudo".to_string())
            ]
        );
    }

    fn file(content: &str) -> Vec<SudoersFile> {
        vec![SudoersFile {
            name: "sudoers".into(),
            content: content.into(),
        }]
    }

    #[test]
    fn sudoers_parses_common_lines() {
        let c = "Defaults env_reset\n# comment\nroot ALL=(ALL:ALL) ALL\n%admin ALL=(ALL) ALL\n\
alice,bob ALL=(ALL) NOPASSWD: ALL\nUser_Alias ADMINS = carol, dave\nADMINS ALL=(ALL) ALL\n\
%sudo   ALL=(ALL:ALL) \\\n        ALL\n#includedir /etc/sudoers.d\n";
        let (p, un) = sudoers(&file(c));
        let got: Vec<_> = p.iter().map(|e| (e.principal.as_str(), e.kind)).collect();
        assert_eq!(
            got,
            [
                ("root", PrincipalKind::User),
                ("admin", PrincipalKind::Group),
                ("alice", PrincipalKind::User),
                ("bob", PrincipalKind::User),
                ("sudo", PrincipalKind::Group),
            ]
        );
        assert!(p.iter().all(|e| e.source == "sudoers:sudoers"));
        assert_eq!(
            un,
            ["User_Alias ADMINS = carol, dave", "ADMINS ALL=(ALL) ALL"]
        );
    }

    #[test]
    fn sudoers_special_principals_unparsed() {
        let c = "+netgrp ALL=(ALL) ALL\n#1000 ALL=(ALL) ALL\nx,#5 ALL=(ALL) ALL\n%#7 ALL=(ALL) ALL\n%:dom ALL=(ALL) ALL\nnoequals here\n";
        let (p, un) = sudoers(&file(c));
        // `#數字` 是 UID，不是註解
        assert!(p.is_empty());
        assert_eq!(un.len(), 6);
        assert!(un.iter().any(|l| l.starts_with("#1000")));
    }

    #[test]
    fn sudoers_comma_lists_tolerate_spaces() {
        for c in [
            "alice, bob ALL=(ALL) ALL",
            "alice ,bob ALL=(ALL) ALL",
            "alice , bob ALL=(ALL) ALL",
        ] {
            let (p, un) = sudoers(&file(c));
            let got: Vec<_> = p.iter().map(|e| e.principal.as_str()).collect();
            assert_eq!(got, ["alice", "bob"], "{c}");
            assert!(
                p.iter()
                    .all(|e| e.kind == PrincipalKind::User && e.source == "sudoers:sudoers")
            );
            assert!(un.is_empty());
        }
        // 逗號之外的空白不能默默吞掉名稱
        let (p, un) = sudoers(&file("alice bob ALL=(ALL) ALL"));
        assert!(p.is_empty());
        assert_eq!(un.len(), 1);
    }

    #[test]
    fn cap_unparsed_limits_lines_and_chars() {
        let v = cap_unparsed((0..60).map(|_| "x".repeat(300)).collect());
        assert_eq!(v.len(), 50);
        assert!(v.iter().all(|l| l.chars().count() == 200));
    }

    #[test]
    fn sudoers_unparsed_is_capped() {
        let many: String = (0..60)
            .map(|i| format!("Cmnd_Alias A{i} = /bin/x\n"))
            .collect();
        assert_eq!(sudoers(&file(&many)).1.len(), 50);
        let long = format!("Cmnd_Alias {}\n", "x".repeat(300));
        assert_eq!(sudoers(&file(&long)).1[0].chars().count(), 200);
    }

    #[test]
    fn include_targets_found() {
        let c = "#includedir /etc/sudoers.d\n@include /etc/sudoers.local\n# includes nothing\n";
        assert_eq!(
            include_targets(c),
            [
                Include::Dir("/etc/sudoers.d".into()),
                Include::File("/etc/sudoers.local".into())
            ]
        );
    }
}
