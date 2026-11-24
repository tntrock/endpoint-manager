//! 權限過寬（錯誤設定規格 §6.1）的判斷：純函式，各平台都能測試。
//! 平台各自收集：Windows 在 `windows::permissions`，Linux 在 `linux::permissions`。

use protocol::{MAX_PERMISSIONS, PermissionItem, PermissionsInfo};

use crate::shares::{Ace, dacl};

// ---------------------------------------------------------------------------
// Windows：服務執行檔、以 SYSTEM 執行的排程工作
// ---------------------------------------------------------------------------

const FILE_WRITE_DATA: u32 = 0x2;
const FILE_APPEND_DATA: u32 = 0x4;
const WRITE_DAC: u32 = 0x4_0000;
const WRITE_OWNER: u32 = 0x8_0000;

/// 一般使用者的身分：(SID, 顯示名稱)
const USER_SIDS: [(&str, &str); 4] = [
    ("S-1-1-0", "Everyone"),
    ("S-1-5-11", "Authenticated Users"),
    ("S-1-5-32-545", "Users"),
    ("S-1-5-4", "Interactive"),
];

/// 一般使用者裡有誰可以改寫：檔案是寫入或附加，資料夾是新增檔案；
/// 能改權限或擁有者（WRITE_DAC、WRITE_OWNER）也算。拒絕項目只扣同一個身分的
pub fn writable_by_users(sddl: &str, dir: bool) -> Vec<String> {
    let Some(aces) = dacl(sddl) else {
        // 沒有 DACL：所有人完全控制
        return vec!["Everyone".into()];
    };
    let write = if dir {
        FILE_WRITE_DATA | WRITE_DAC | WRITE_OWNER
    } else {
        FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | WRITE_OWNER
    };
    USER_SIDS
        .iter()
        .filter(|(sid, _)| effective(&aces, sid) & write != 0)
        .map(|(_, name)| name.to_string())
        .collect()
}

fn effective(aces: &[Ace], sid: &str) -> u32 {
    let (mut allowed, mut denied) = (0u32, 0u32);
    for a in aces.iter().filter(|a| !a.inherit_only && a.sid == sid) {
        let m = crate::shares::expand(a.mask);
        if a.allow {
            allowed |= m;
        } else {
            denied |= m;
        }
    }
    allowed & !denied
}

/// `%VAR%` 換成環境變數；找不到的保留原樣
pub fn expand_env(s: &str, env: &dyn Fn(&str) -> Option<String>) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        match after.find('%') {
            Some(j) if j > 0 => match env(&after[..j]) {
                Some(v) => {
                    out.push_str(&v);
                    rest = &after[j + 1..];
                }
                None => {
                    out.push('%');
                    rest = after;
                }
            },
            _ => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// 服務 ImagePath 或排程工作 Command 裡的執行檔路徑；不是絕對路徑時 None
pub fn binary_of(command: &str, env: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    let c = command.trim();
    let raw = if let Some(q) = c.strip_prefix('"') {
        q.split('"').next().unwrap_or("")
    } else {
        // 沒加引號：到 `.exe` 為止，否則到第一個空白
        let lower = c.to_ascii_lowercase();
        match lower.find(".exe") {
            Some(i) => &c[..i + 4],
            None => c.split_whitespace().next().unwrap_or(""),
        }
    };
    let mut p = expand_env(raw, env);
    if let Some(r) = p.strip_prefix(r"\??\") {
        p = r.to_string();
    }
    if p.len() >= 12 && p[..12].eq_ignore_ascii_case(r"\SystemRoot\") {
        p = format!("{}{}", env("SystemRoot")?, &p[11..]);
    }
    let b = p.as_bytes();
    (b.len() > 3 && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')).then_some(p)
}

/// 路徑所在的資料夾
pub fn parent_dir(path: &str) -> Option<&str> {
    let i = path.rfind(['\\', '/'])?;
    // `C:\x.exe` 的資料夾是 `C:\`
    Some(if i == 2 { &path[..3] } else { &path[..i] })
}

/// 所有 `<name>…</name>` 的內容
fn all_tags<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
    let (open, close) = (format!("<{name}"), format!("</{name}>"));
    let mut out = vec![];
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        let after = &rest[i + open.len()..];
        if !after.starts_with(['>', ' ']) {
            rest = after;
            continue;
        }
        let Some(gt) = after.find('>') else { break };
        let body = &after[gt + 1..];
        let Some(end) = body.find(&close) else { break };
        out.push(&body[..end]);
        rest = &body[end + close.len()..];
    }
    out
}

/// 排程工作的 XML：以 SYSTEM 執行時回傳要執行的指令；其他身分 None
pub fn system_task_commands(xml: &str) -> Option<Vec<String>> {
    let users = all_tags(xml, "UserId");
    let system = users.iter().any(|u| {
        let u = u.trim();
        u == "S-1-5-18"
            || u.eq_ignore_ascii_case("SYSTEM")
            || u.eq_ignore_ascii_case(r"NT AUTHORITY\SYSTEM")
            || u.eq_ignore_ascii_case("LocalSystem")
    });
    if !system {
        return None;
    }
    Some(
        all_tags(xml, "Exec")
            .into_iter()
            .filter_map(|e| {
                all_tags(e, "Command")
                    .first()
                    .map(|c| crate::oslog::unescape(c.trim()))
            })
            .filter(|c| !c.is_empty())
            .collect(),
    )
}

/// UTF-16（有 BOM）或 UTF-8 的檔案內容
pub fn decode_text(bytes: &[u8]) -> String {
    match bytes {
        [0xFF, 0xFE, rest @ ..] => {
            let units: Vec<u16> = rest
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect();
            String::from_utf16_lossy(&units)
        }
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

// ---------------------------------------------------------------------------
// Linux：SUID 程式屬於哪個套件
// ---------------------------------------------------------------------------

/// merged-usr 的另一種寫法：`/usr/bin/x` ↔ `/bin/x`
pub fn alt_path(path: &str) -> Option<String> {
    for d in ["/bin/", "/sbin/"] {
        if let Some(r) = path.strip_prefix(&format!("/usr{d}")) {
            return Some(format!("{d}{r}"));
        }
        if let Some(r) = path.strip_prefix(d) {
            return Some(format!("/usr{d}{r}"));
        }
    }
    None
}

/// 依種類、路徑排序並截斷
pub fn finish(mut items: Vec<PermissionItem>, errors: Vec<String>) -> PermissionsInfo {
    items.sort();
    items.dedup();
    let truncated = items.len() > MAX_PERMISSIONS;
    items.truncate(MAX_PERMISSIONS);
    PermissionsInfo {
        items,
        truncated,
        errors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(k: &str) -> Option<String> {
        match k {
            "SystemRoot" => Some(r"C:\Windows".into()),
            "ProgramFiles" => Some(r"C:\Program Files".into()),
            _ => None,
        }
    }

    #[test]
    fn user_write_detection() {
        // 系統預設：Users 只能讀與執行
        let sys = "O:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)";
        assert!(writable_by_users(sys, false).is_empty());
        assert!(writable_by_users(sys, true).is_empty());
        // Everyone 完全控制、Authenticated Users 修改
        let bad = "D:(A;;FA;;;WD)(A;;0x1301bf;;;AU)";
        assert_eq!(
            writable_by_users(bad, false),
            ["Everyone", "Authenticated Users"]
        );
        // 只能新增子資料夾（附加）：檔案算，資料夾不算
        let append = "D:(A;;0x4;;;BU)";
        assert_eq!(writable_by_users(append, false), ["Users"]);
        assert!(writable_by_users(append, true).is_empty());
        // 只繼承給子項目、被拒絕的不算；能改權限算
        assert!(writable_by_users("D:(A;OICIIO;FA;;;BU)", true).is_empty());
        assert!(writable_by_users("D:(A;;FA;;;IU)(D;;FA;;;IU)", false).is_empty());
        assert_eq!(writable_by_users("D:(A;;WD;;;IU)", false), ["Interactive"]);
        assert_eq!(writable_by_users("O:SY", false), ["Everyone"], "沒有 DACL");
    }

    #[test]
    fn binary_paths() {
        for (cmd, want) in [
            (
                r#""C:\Program Files\A\a.exe" -k x"#,
                Some(r"C:\Program Files\A\a.exe"),
            ),
            (
                r"C:\Program Files\A\a.exe -k x",
                Some(r"C:\Program Files\A\a.exe"),
            ),
            (
                r"%SystemRoot%\System32\svchost.exe -k netsvcs",
                Some(r"C:\Windows\System32\svchost.exe"),
            ),
            (
                r"\SystemRoot\System32\drivers\x.sys",
                Some(r"C:\Windows\System32\drivers\x.sys"),
            ),
            (r"\??\C:\Tools\t.exe", Some(r"C:\Tools\t.exe")),
            (r"C:\Tools\run.cmd arg", Some(r"C:\Tools\run.cmd")),
            ("cmd.exe /c x", None),
            ("system32\\drivers\\x.sys", None),
            (r"%Unknown%\x.exe", None),
            ("", None),
        ] {
            assert_eq!(binary_of(cmd, &env).as_deref(), want, "{cmd}");
        }
        assert_eq!(
            expand_env("100% %ProgramFiles%", &env),
            r"100% C:\Program Files"
        );
        assert_eq!(expand_env("%%", &env), "%%");
        assert_eq!(parent_dir(r"C:\A\b.exe"), Some(r"C:\A"));
        assert_eq!(parent_dir(r"C:\b.exe"), Some(r"C:\"));
        assert_eq!(parent_dir("b.exe"), None);
    }

    #[test]
    fn task_xml() {
        let xml = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task><Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
<Actions Context="Author"><Exec><Command>"C:\Tools\a.exe"</Command><Arguments>-x</Arguments></Exec>
<Exec><Command>%windir%\system32\b.exe</Command></Exec><ComHandler><ClassId>{x}</ClassId></ComHandler>
<Exec><Command>C:\x &amp; y\c.exe</Command></Exec></Actions></Task>"#;
        assert_eq!(
            system_task_commands(xml).unwrap(),
            [
                r#""C:\Tools\a.exe""#,
                r"%windir%\system32\b.exe",
                r"C:\x & y\c.exe"
            ]
        );
        let user = "<Task><Principals><Principal><UserId>CORP\\bob</UserId></Principal></Principals>\
<Actions><Exec><Command>x.exe</Command></Exec></Actions></Task>";
        assert_eq!(system_task_commands(user), None);
        let group = "<Task><Principals><Principal><GroupId>S-1-5-32-545</GroupId></Principal></Principals></Task>";
        assert_eq!(system_task_commands(group), None);
        assert_eq!(
            system_task_commands("<UserId>SYSTEM</UserId>"),
            Some(vec![])
        );
    }

    #[test]
    fn decode_utf16_and_utf8() {
        let mut b = vec![0xFF, 0xFE];
        b.extend("<Task>".encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(decode_text(&b), "<Task>");
        assert_eq!(decode_text(b"\xEF\xBB\xBFabc"), "abc");
        assert_eq!(decode_text(b"abc"), "abc");
    }

    #[test]
    fn package_ownership() {
        assert_eq!(alt_path("/usr/bin/su").as_deref(), Some("/bin/su"));
        assert_eq!(alt_path("/sbin/x").as_deref(), Some("/usr/sbin/x"));
        assert_eq!(alt_path("/usr/local/bin/x"), None);
    }

    #[test]
    fn finish_sorts_and_truncates() {
        let item = |p: &str| PermissionItem {
            kind: "suid".into(),
            path: p.into(),
            ..Default::default()
        };
        let i = finish(vec![item("/b"), item("/a"), item("/a")], vec![]);
        assert_eq!(i.items.len(), 2);
        assert_eq!(i.items[0].path, "/a");
        assert!(!i.truncated);
        let i = finish(
            (0..=MAX_PERMISSIONS)
                .map(|n| item(&n.to_string()))
                .collect(),
            vec![],
        );
        assert!(i.truncated && i.items.len() == MAX_PERMISSIONS);
    }
}
