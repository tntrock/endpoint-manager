//! 共用資料夾的權限判斷（錯誤設定規格 §4.1）。只有純函式，各平台都能測試；
//! 實際讀取在 `windows::shares`（SMB）與 `linux::shares`（Samba、NFS）。
//!
//! 每個共用只回報兩個結論：不登入（匿名）能做什麼、所有使用者能做什麼。不上傳 ACL。

use protocol::{ShareAccess, ShareItem};

// ---------------------------------------------------------------------------
// Windows：以 SDDL 字串判斷共用權限與 NTFS 權限
// ---------------------------------------------------------------------------

const FILE_READ_DATA: u32 = 0x1;
const FILE_WRITE_DATA: u32 = 0x2;
const FILE_APPEND_DATA: u32 = 0x4;
const WRITE_DAC: u32 = 0x4_0000;
const WRITE_OWNER: u32 = 0x8_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const FILE_ALL: u32 = 0x1F_01FF;
const FILE_GENERIC_READ: u32 = 0x12_0089;
const FILE_GENERIC_WRITE: u32 = 0x12_0116;
const FILE_GENERIC_EXECUTE: u32 = 0x12_00A0;

/// 一筆存取控制項目
#[derive(Debug, Clone, PartialEq)]
pub struct Ace {
    pub allow: bool,
    /// 只給子項目繼承，不套用在這個資料夾本身
    pub inherit_only: bool,
    pub mask: u32,
    /// 正規化的 SID：別名換成 `S-1-…`；網域相對的別名（`DU`、`DG`）保留
    pub sid: String,
}

fn right(token: &str) -> u32 {
    match token {
        "GA" => GENERIC_ALL,
        "GR" => GENERIC_READ,
        "GW" => GENERIC_WRITE,
        "GX" => GENERIC_EXECUTE,
        "FA" => FILE_ALL,
        "FR" => FILE_GENERIC_READ,
        "FW" => FILE_GENERIC_WRITE,
        "FX" => FILE_GENERIC_EXECUTE,
        "SD" => 0x1_0000,
        "RC" => 0x2_0000,
        "WD" => WRITE_DAC,
        "WO" => WRITE_OWNER,
        // 目錄服務的名稱，對檔案就是低 9 個位元
        "CC" => 0x1,
        "DC" => 0x2,
        "LC" => 0x4,
        "SW" => 0x8,
        "RP" => 0x10,
        "WP" => 0x20,
        "DT" => 0x40,
        "LO" => 0x80,
        "CR" => 0x100,
        _ => 0,
    }
}

fn rights(s: &str) -> u32 {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).unwrap_or(0);
    }
    if s.chars().all(|c| c.is_ascii_digit()) && !s.is_empty() {
        return s.parse().unwrap_or(0);
    }
    (0..s.len() / 2)
        .filter_map(|i| s.get(i * 2..i * 2 + 2))
        .map(right)
        .fold(0, |a, b| a | b)
}

fn sid(alias: &str) -> String {
    let s = alias.trim();
    match s {
        "WD" => "S-1-1-0",
        "AN" => "S-1-5-7",
        "AU" => "S-1-5-11",
        "NU" => "S-1-5-2",
        "IU" => "S-1-5-4",
        "SY" => "S-1-5-18",
        "BA" => "S-1-5-32-544",
        "BU" => "S-1-5-32-545",
        "BG" => "S-1-5-32-546",
        other => other,
    }
    .to_string()
}

/// SDDL 的 DACL 部分（`D:` 之後的項目）；沒有 DACL 時 None
pub fn dacl(sddl: &str) -> Option<Vec<Ace>> {
    let start = sddl.find("D:")? + 2;
    let mut rest = &sddl[start..];
    // DACL 旗標（P、AI、AR……）直到第一個 '('
    match rest.find('(') {
        Some(i) => rest = &rest[i..],
        None => return Some(vec![]),
    }
    let mut out = vec![];
    while let Some(body) = rest.strip_prefix('(') {
        let Some(end) = body.find(')') else {
            break;
        };
        let f: Vec<&str> = body[..end].split(';').collect();
        rest = &body[end + 1..];
        if f.len() < 6 {
            continue;
        }
        let allow = match f[0] {
            "A" => true,
            "D" => false,
            _ => continue,
        };
        out.push(Ace {
            allow,
            inherit_only: f[1].contains("IO"),
            mask: rights(f[2]),
            sid: sid(f[5]),
        });
    }
    Some(out)
}

pub(crate) fn expand(mask: u32) -> u32 {
    let mut m = mask & !(GENERIC_ALL | GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE);
    if mask & GENERIC_ALL != 0 {
        m |= FILE_ALL;
    }
    if mask & GENERIC_READ != 0 {
        m |= FILE_GENERIC_READ;
    }
    if mask & GENERIC_WRITE != 0 {
        m |= FILE_GENERIC_WRITE;
    }
    if mask & GENERIC_EXECUTE != 0 {
        m |= FILE_GENERIC_EXECUTE;
    }
    m
}

/// 符合 `who` 的 SID 加起來能做什麼：允許的權限扣掉拒絕的權限。
/// 能改權限或擁有者（WRITE_DAC、WRITE_OWNER）也算可寫入：可以自己加上寫入權限
pub fn access(aces: &[Ace], who: &dyn Fn(&str) -> bool) -> ShareAccess {
    let (mut allowed, mut denied) = (0u32, 0u32);
    for a in aces.iter().filter(|a| !a.inherit_only && who(&a.sid)) {
        if a.allow {
            allowed |= expand(a.mask);
        } else {
            denied |= expand(a.mask);
        }
    }
    let eff = allowed & !denied;
    if eff & (FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | WRITE_OWNER) != 0 {
        ShareAccess::Write
    } else if eff & FILE_READ_DATA != 0 {
        ShareAccess::Read
    } else {
        ShareAccess::None
    }
}

/// 網域相對的 SID：`S-1-5-21-…-<rid>`
fn domain_rid(sid: &str, rid: &str) -> bool {
    sid.starts_with("S-1-5-21-") && sid.rsplit('-').next() == Some(rid)
}

/// 所有使用者：Everyone、Authenticated Users、Users、Network、Domain Users
pub fn is_all_users(sid: &str) -> bool {
    matches!(
        sid,
        "S-1-1-0" | "S-1-5-11" | "S-1-5-32-545" | "S-1-5-2" | "DU"
    ) || domain_rid(sid, "513")
}

/// 不登入就能用的身分：Anonymous Logon；Guest 帳號啟用時加上 Guests、Domain Guests、Everyone；
/// `EveryoneIncludesAnonymous` 開啟時加上 Everyone
pub fn is_anonymous(sid: &str, guest_enabled: bool, everyone_includes_anonymous: bool) -> bool {
    sid == "S-1-5-7"
        || (guest_enabled
            && (matches!(sid, "S-1-5-32-546" | "DG" | "S-1-1-0") || domain_rid(sid, "514")))
        || (everyone_includes_anonymous && sid == "S-1-1-0")
}

/// SMB 共用的實際權限：共用權限與 NTFS 權限取較小的。
/// 沒有共用權限（安全描述元是空的）等於所有人完全控制；讀不到 NTFS 權限時只看共用權限
pub fn judge_smb(
    share_sddl: Option<&str>,
    ntfs_sddl: Option<&str>,
    guest_enabled: bool,
    everyone_includes_anonymous: bool,
) -> (ShareAccess, ShareAccess) {
    let share = share_sddl
        .and_then(dacl)
        .unwrap_or_else(|| dacl("D:(A;;FA;;;WD)").unwrap_or_default());
    let ntfs = ntfs_sddl.and_then(dacl);
    let anon = |s: &str| is_anonymous(s, guest_enabled, everyone_includes_anonymous);
    let both = |who: &dyn Fn(&str) -> bool| {
        let s = access(&share, who);
        match &ntfs {
            Some(n) => s.min(access(n, who)),
            None => s,
        }
    };
    (both(&anon), both(&is_all_users))
}

// ---------------------------------------------------------------------------
// Linux Samba：`testparm -s` 的輸出
// ---------------------------------------------------------------------------

fn yes(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "yes" | "true" | "1" | "on"
    )
}

/// 解析 `testparm -s`：每個共用（`[global]`、`[homes]`、`[printers]`、`print$` 與印表機共用除外）
pub fn parse_testparm(out: &str) -> Vec<ShareItem> {
    let mut sections: Vec<(String, Vec<(String, String)>)> = vec![];
    for line in out.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        if let Some(name) = l.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            sections.push((name.trim().to_string(), vec![]));
            continue;
        }
        if let (Some((k, v)), Some(cur)) = (l.split_once('='), sections.last_mut()) {
            let key = k
                .trim()
                .to_ascii_lowercase()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            cur.1.push((key, v.trim().to_string()));
        }
    }
    let global: Vec<(String, String)> = sections
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("global"))
        .map(|(_, kv)| kv.clone())
        .unwrap_or_default();
    let get = |kv: &[(String, String)], keys: &[&str]| -> Option<String> {
        kv.iter()
            .rev()
            .find(|(k, _)| keys.contains(&k.as_str()))
            .or_else(|| {
                global
                    .iter()
                    .rev()
                    .find(|(k, _)| keys.contains(&k.as_str()))
            })
            .map(|(_, v)| v.clone())
    };
    sections
        .iter()
        .filter(|(n, _)| {
            !["global", "homes", "printers", "print$"]
                .iter()
                .any(|s| n.eq_ignore_ascii_case(s))
        })
        .filter(|(_, kv)| !get(kv, &["printable", "print ok"]).is_some_and(|v| yes(&v)))
        .map(|(name, kv)| {
            // 預設唯讀；writeable、writable、write ok 是 read only 的反義
            let writable = match get(kv, &["read only"]) {
                Some(v) => !yes(&v),
                None => get(kv, &["writeable", "writable", "write ok"]).is_some_and(|v| yes(&v)),
            };
            let level = if writable {
                ShareAccess::Write
            } else {
                ShareAccess::Read
            };
            let guest = get(kv, &["guest ok", "public"]).is_some_and(|v| yes(&v));
            let anonymous = if guest { level } else { ShareAccess::None };
            let restricted = get(kv, &["valid users"]).is_some_and(|v| !v.trim().is_empty());
            let users = if restricted { ShareAccess::None } else { level };
            ShareItem {
                kind: "samba".into(),
                name: name.clone(),
                path: get(kv, &["path", "directory"]).unwrap_or_default(),
                anonymous,
                all_users: users.max(anonymous),
                no_root_squash: false,
                clients: vec![],
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Linux NFS：/etc/exports
// ---------------------------------------------------------------------------

/// 去掉註解、接上以 `\` 結尾的續行
fn logical_lines(text: &str) -> Vec<String> {
    let mut out = vec![];
    let mut cur = String::new();
    for raw in text.lines() {
        let line = match raw.find('#') {
            Some(i) => &raw[..i],
            None => raw,
        };
        if let Some(head) = line.trim_end().strip_suffix('\\') {
            cur.push_str(head);
            cur.push(' ');
            continue;
        }
        cur.push_str(line);
        if !cur.trim().is_empty() {
            out.push(cur.trim().to_string());
        }
        cur.clear();
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// 第一個欄位是路徑（可能有引號），其餘以空白分開
fn split_export(line: &str) -> (String, Vec<&str>) {
    if let Some(rest) = line.strip_prefix('"')
        && let Some(end) = rest.find('"')
    {
        return (
            rest[..end].to_string(),
            rest[end + 1..].split_whitespace().collect(),
        );
    }
    let mut it = line.split_whitespace();
    let path = it.next().unwrap_or_default().to_string();
    (path, it.collect())
}

/// 解析 exports 檔。來源是 `*` 或沒寫：匿名（NFS 預設不驗證使用者身分）；網段或主機：所有使用者
pub fn parse_exports(text: &str) -> Vec<ShareItem> {
    logical_lines(text)
        .iter()
        .filter_map(|line| {
            let (path, clients) = split_export(line);
            if path.is_empty() {
                return None;
            }
            // 沒有寫來源：所有人、預設選項（唯讀、root_squash）
            let specs: Vec<(&str, &str)> = if clients.is_empty() {
                vec![("*", "")]
            } else {
                clients
                    .iter()
                    .map(|c| match c.split_once('(') {
                        Some((host, opts)) => (host, opts.trim_end_matches(')')),
                        None => (*c, ""),
                    })
                    .collect()
            };
            let mut item = ShareItem {
                kind: "nfs".into(),
                name: path.clone(),
                path,
                anonymous: ShareAccess::None,
                all_users: ShareAccess::None,
                no_root_squash: false,
                clients: vec![],
            };
            for (host, opts) in specs {
                let host = if host.is_empty() { "*" } else { host };
                let mut rw = false;
                for o in opts.split(',').map(str::trim) {
                    match o {
                        "rw" => rw = true,
                        "ro" => rw = false,
                        "no_root_squash" => item.no_root_squash = true,
                        _ => {}
                    }
                }
                let level = if rw {
                    ShareAccess::Write
                } else {
                    ShareAccess::Read
                };
                if host == "*" {
                    item.anonymous = item.anonymous.max(level);
                }
                item.all_users = item.all_users.max(level);
                if !item.clients.iter().any(|c| c == host) {
                    item.clients.push(host.to_string());
                }
            }
            Some(item)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ShareAccess::{Read, Write};
    const NONE: ShareAccess = ShareAccess::None;

    #[test]
    fn sddl_parsing() {
        let a = dacl("O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICIIO;GA;;;CO)(D;;0x2;;;WD)(OA;;CR;x;;WD)(A;;CCDCLC;;;S-1-5-21-1-2-3-513)").unwrap();
        assert_eq!(a.len(), 4, "物件 ACE 略過：{a:?}");
        assert_eq!(
            a[0],
            Ace {
                allow: true,
                inherit_only: false,
                mask: FILE_ALL,
                sid: "S-1-5-18".into()
            }
        );
        assert!(a[1].inherit_only);
        assert!(!a[2].allow);
        assert_eq!(a[2].mask, 2);
        assert_eq!(a[3].mask, 0x7);
        assert_eq!(dacl("O:BA"), None);
        assert_eq!(dacl("D:P"), Some(vec![]));
        assert_eq!(dacl("D:(A;;FA;;;WD)(broken").unwrap().len(), 1);
        assert_eq!(dacl("D:(A;;FA)").unwrap().len(), 0);
        assert_eq!(rights("1179817"), 0x1200A9);
        assert_eq!(rights("0X10"), 0x10);
        assert_eq!(rights("zz"), 0);
    }

    #[test]
    fn access_with_allow_deny_and_generic() {
        let all = |s: &str| is_all_users(s);
        let a = dacl("D:(A;;0x1200a9;;;WD)").unwrap();
        assert_eq!(access(&a, &all), Read);
        let a = dacl("D:(A;;GW;;;AU)").unwrap();
        assert_eq!(access(&a, &all), Write);
        // 「變更」權限（沒有改權限）再拒絕寫入：只能讀
        let a = dacl("D:(A;;0x1301bf;;;BU)(D;;FW;;;BU)").unwrap();
        assert_eq!(access(&a, &all), Read, "拒絕寫入");
        // 完全控制只拒絕寫入：仍然可以改權限，算可寫入
        let a = dacl("D:(A;;FA;;;BU)(D;;FW;;;BU)").unwrap();
        assert_eq!(access(&a, &all), Write);
        let a = dacl("D:(A;;WD;;;DU)").unwrap();
        assert_eq!(access(&a, &all), Write, "可以改權限就算可寫入");
        let a = dacl("D:(A;OICIIO;FA;;;WD)(A;;FA;;;BA)").unwrap();
        assert_eq!(access(&a, &all), NONE, "只給子項目繼承、管理員不算");
        let a = dacl("D:(A;;GR;;;S-1-5-21-9-9-9-513)").unwrap();
        assert_eq!(access(&a, &all), Read);
        let a = dacl("D:(A;;FX;;;WD)").unwrap();
        assert_eq!(access(&a, &all), NONE, "只能執行");
    }

    #[test]
    fn anonymous_depends_on_guest() {
        assert!(is_anonymous("S-1-5-7", false, false));
        assert!(!is_anonymous("S-1-1-0", false, false));
        assert!(is_anonymous("S-1-1-0", true, false));
        assert!(is_anonymous("S-1-1-0", false, true));
        assert!(is_anonymous("S-1-5-32-546", true, false));
        assert!(!is_anonymous("S-1-5-32-546", false, false));
        assert!(is_anonymous("S-1-5-21-1-2-3-514", true, false));
        assert!(!is_anonymous("S-1-5-21-1-2-3-513", true, false));
        assert!(!is_all_users("S-1-5-32-544"));
        assert!(is_all_users("DU"));
    }

    #[test]
    fn smb_takes_the_smaller_of_share_and_ntfs() {
        // 共用：所有人完全控制；NTFS：Users 只能讀
        let (anon, users) = judge_smb(
            Some("D:(A;;FA;;;WD)"),
            Some("D:(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"),
            false,
            false,
        );
        assert_eq!((anon, users), (NONE, Read));
        // Guest 啟用時 Everyone 也算匿名
        let (anon, users) = judge_smb(
            Some("D:(A;;FA;;;WD)"),
            Some("D:(A;OICI;FA;;;WD)"),
            true,
            false,
        );
        assert_eq!((anon, users), (Write, Write));
        // 共用只給管理員：NTFS 再寬也沒用
        let (anon, users) = judge_smb(
            Some("D:(A;;FA;;;BA)"),
            Some("D:(A;OICI;FA;;;WD)"),
            true,
            true,
        );
        assert_eq!((anon, users), (NONE, NONE));
        // 沒有共用權限：所有人完全控制；讀不到 NTFS：只看共用
        assert_eq!(judge_smb(None, None, false, false), (NONE, Write));
        assert_eq!(
            judge_smb(Some("D:(A;;0x1200a9;;;AN)"), None, false, false),
            (Read, NONE)
        );
    }

    #[test]
    fn samba_shares() {
        let out = "\
# Global parameters
[global]
\tmap to guest = Bad User
\tserver role = standalone server

[homes]
\tbrowseable = No
\tread only = No

[printers]
\tpath = /var/spool/samba
\tprintable = Yes

[print$]
\tpath = /var/lib/samba/printers

[public]
\tguest ok = Yes
\tpath = /srv/public
\tread only = No

[docs]
\tpath = /srv/docs

[team]
\tpath = /srv/team
\tvalid users = @team
\twriteable = yes

[label]
\tpath = /srv/label
\tprintable = yes
";
        let v = parse_testparm(out);
        let names: Vec<&str> = v.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["public", "docs", "team"]);
        assert_eq!((v[0].anonymous, v[0].all_users), (Write, Write));
        assert_eq!(v[0].path, "/srv/public");
        assert_eq!(v[0].kind, "samba");
        assert_eq!((v[1].anonymous, v[1].all_users), (NONE, Read), "預設唯讀");
        assert_eq!((v[2].anonymous, v[2].all_users), (NONE, NONE), "限定使用者");
        // [global] 的設定是共用的預設值
        let v = parse_testparm("[global]\n\tguest ok = yes\n[x]\n\tpath = /x\n");
        assert_eq!(v[0].anonymous, Read);
        assert!(parse_testparm("").is_empty());
    }

    #[test]
    fn nfs_exports() {
        let text = r#"
# 註解
/srv/public *(rw,no_root_squash)   # 所有人
/srv/team 10.0.0.0/8(rw) host1(ro)
"/srv/with space" 192.168.1.0/24
/srv/world
/srv/multi \
    *(ro) 10.1.0.0/16(rw)
/srv/bare (rw)
"#;
        let v = parse_exports(text);
        assert_eq!(v.len(), 6, "{v:?}");
        assert_eq!((v[0].anonymous, v[0].all_users), (Write, Write));
        assert!(v[0].no_root_squash);
        assert_eq!(v[0].clients, ["*"]);
        assert_eq!((v[1].anonymous, v[1].all_users), (NONE, Write));
        assert_eq!(v[1].clients, ["10.0.0.0/8", "host1"]);
        assert!(!v[1].no_root_squash);
        assert_eq!(v[2].path, "/srv/with space");
        assert_eq!((v[2].anonymous, v[2].all_users), (NONE, Read));
        assert_eq!(
            (v[3].anonymous, v[3].all_users),
            (Read, Read),
            "沒寫來源：所有人唯讀"
        );
        assert_eq!((v[4].anonymous, v[4].all_users), (Read, Write));
        assert_eq!(
            (v[5].anonymous, v[5].clients.clone()),
            (Write, vec!["*".to_string()])
        );
        assert!(parse_exports("# only comments\n\n").is_empty());
    }
}
