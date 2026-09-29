//! 登錄檔路徑守衛：Agent 讀取前與伺服器建立規則時共用，確保兩端判斷一致。
//! 只允許 HKLM；拒絕 SAM、SECURITY 子樹與 Winlogon 的自動登入密碼。

use sha2::{Digest, Sha256};

use crate::RegistryQuery;

pub const DENIED_MESSAGE: &str =
    "不允許讀取這個位置（只能讀取 HKLM，且不能讀取 SAM、SECURITY 與自動登入密碼）";

const DENIED_SUBTREES: [&str; 2] = [r"HKLM\SAM", r"HKLM\SECURITY"];
/// 64 位元與 32 位元（WOW6432Node）檢視的 Winlogon：32 位元的自動登入工具會寫在後者
const WINLOGON: [&str; 2] = [
    r"HKLM\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON",
    r"HKLM\SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON",
];
const DENIED_WINLOGON_NAMES: [&str; 2] = ["DEFAULTPASSWORD", "ALTDEFAULTPASSWORD"];

/// 正規化成 `HKLM\子機碼\...`：接受 `HKEY_LOCAL_MACHINE` 別名、`/`、重複或結尾的 `\`、前後空白；
/// 不接受其他根機碼、沒有子機碼、含 `.`／`..` 段落，或含控制字元（包括 NUL）的路徑。
pub fn normalize(path: &str) -> Result<String, &'static str> {
    // Windows API 讀到 NUL 就停止：含 NUL 的路徑會開到和守衛看到的不同機碼
    if path.chars().any(char::is_control) {
        return Err("登錄檔路徑不能包含控制字元");
    }
    let path = path.trim().replace('/', "\\");
    let mut parts = path.split('\\').filter(|p| !p.is_empty());
    let root = parts.next().ok_or("登錄檔路徑必填")?;
    if !root.eq_ignore_ascii_case("HKLM") && !root.eq_ignore_ascii_case("HKEY_LOCAL_MACHINE") {
        return Err("登錄檔路徑必須以 HKLM\\ 開頭");
    }
    let rest: Vec<&str> = parts.collect();
    if rest.is_empty() {
        return Err("登錄檔路徑需要指定子機碼");
    }
    if rest.iter().any(|p| *p == "." || *p == "..") {
        return Err("登錄檔路徑不能包含 . 或 ..");
    }
    Ok(format!("HKLM\\{}", rest.join("\\")))
}

/// 正規化並套用拒絕清單，回傳正規化後的路徑。
pub fn check(path: &str, name: &str) -> Result<String, &'static str> {
    let p = normalize(path).map_err(|_| DENIED_MESSAGE)?;
    // 值名稱同樣不能含 NUL 等控制字元（API 會截斷，讀到守衛沒看到的值）
    if name.chars().any(char::is_control) {
        return Err(DENIED_MESSAGE);
    }
    let upper = p.to_uppercase();
    let denied_subtree = DENIED_SUBTREES
        .iter()
        .any(|d| upper == *d || upper.starts_with(&format!("{d}\\")));
    let denied_value = WINLOGON.contains(&upper.as_str())
        && DENIED_WINLOGON_NAMES.contains(&name.trim().to_uppercase().as_str());
    if denied_subtree || denied_value {
        return Err(DENIED_MESSAGE);
    }
    Ok(p)
}

/// 查詢清單的雜湊（不分順序、不分大小寫、重複只算一次）：Agent 用來判斷清單有沒有變。
pub fn queries_hash(q: &[RegistryQuery]) -> String {
    let mut keys: Vec<String> = q
        .iter()
        .map(|x| format!("{}\u{0}{}", x.path.to_uppercase(), x.name.to_uppercase()))
        .collect();
    keys.sort();
    keys.dedup();
    hex::encode(Sha256::digest(keys.join("\n").as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_aliases_and_separators() {
        let n = |p| normalize(p).unwrap();
        assert_eq!(n(r"HKLM\SOFTWARE\Foo"), r"HKLM\SOFTWARE\Foo");
        assert_eq!(n(r"hklm\SOFTWARE\Foo\"), r"HKLM\SOFTWARE\Foo");
        assert_eq!(n("HKEY_LOCAL_MACHINE/SOFTWARE//Foo"), r"HKLM\SOFTWARE\Foo");
        assert_eq!(n(r"  HKLM\SOFTWARE\Foo  "), r"HKLM\SOFTWARE\Foo");
        for bad in [
            r"HKCU\Software",
            r"HKU\S-1-5-18",
            r"SOFTWARE\Foo",
            "",
            r"HKLM",
            r"HKLM\..\SAM",
            r"HKLM\SOFTWARE\a\..\b",
        ] {
            assert!(normalize(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn deny_list_blocks_secrets_in_all_spellings() {
        for (p, name) in [
            (r"HKLM\SAM\SAM\Domains", "F"),
            (r"hklm\sam", ""),
            (r"HKEY_LOCAL_MACHINE/Security/Policy", "x"),
            (r"HKLM\SECURITY", "x"),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "DefaultPassword",
            ),
            (
                r"hklm\software\microsoft\windows nt\currentversion\winlogon",
                "defaultpassword",
            ),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                " AltDefaultPassword ",
            ),
        ] {
            assert!(check(p, name).is_err(), "{p} {name}");
        }
        assert!(check(r"HKLM\SAMPLE\Key", "x").is_ok(), "SAM 前綴但不同機碼");
        // 32 位元檢視的 Winlogon 也可能存自動登入密碼
        assert!(
            check(
                r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "DefaultPassword"
            )
            .is_err()
        );
        // Windows API 讀到 NUL 就停：含 NUL 或其他控制字元的路徑、名稱一律拒絕
        let winlogon = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        for (p, name) in [
            (format!("{winlogon}\u{0}"), "DefaultPassword".to_string()),
            (winlogon.to_string(), "DefaultPassword\u{0}x".to_string()),
            (format!(r"HKLM\SAM{}\x", '\u{0}'), "y".to_string()),
            (format!(r"HKLM\SOFTWARE{}", '\u{1}'), "y".to_string()),
            (r"HKLM\SOFTWARE".to_string(), "a\nb".to_string()),
        ] {
            assert!(check(&p, &name).is_err(), "{p:?} {name:?}");
        }
        assert!(
            check(
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "AutoAdminLogon"
            )
            .is_ok()
        );
    }

    #[test]
    fn queries_hash_is_order_independent() {
        let a = RegistryQuery {
            path: r"HKLM\A".into(),
            name: "x".into(),
        };
        let b = RegistryQuery {
            path: r"HKLM\B".into(),
            name: "y".into(),
        };
        assert_eq!(
            queries_hash(&[a.clone(), b.clone()]),
            queries_hash(&[b.clone(), a.clone()])
        );
        assert_ne!(queries_hash(std::slice::from_ref(&a)), queries_hash(&[b]));
        assert_eq!(queries_hash(&[]).len(), 64);
    }
}
