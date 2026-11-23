//! MAC 位址的廠商名稱（IEEE OUI）。
//!
//! 隨伺服器發佈一份精簡清單（`data/oui.tsv.gz`：前綴 TAB 名稱）；設定 `EM_OUI_FILE` 時改讀
//! IEEE 官網的 `oui.csv`（https://standards-oui.ieee.org/oui/oui.csv），方便換成新版。

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;

use anyhow::Context;

static BUILTIN: &[u8] = include_bytes!("../../data/oui.tsv.gz");
static TABLE: OnceLock<HashMap<u32, String>> = OnceLock::new();

fn prefix_of(hex: &str) -> Option<u32> {
    (hex.len() == 6)
        .then(|| u32::from_str_radix(hex, 16).ok())
        .flatten()
}

fn parse_tsv(text: &str) -> HashMap<u32, String> {
    text.lines()
        .filter_map(|l| {
            let (p, name) = l.split_once('\t')?;
            Some((prefix_of(p.trim())?, name.trim().to_string()))
        })
        .collect()
}

/// 一行 CSV 拆成欄位（支援雙引號與 "" 跳脫）
fn csv_fields(line: &str) -> Vec<String> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            ('"', _) => quoted = !quoted,
            (',', false) => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// IEEE 的 oui.csv：Registry,Assignment,Organization Name,…（只取 MA-L）
pub fn parse_ieee_csv(text: &str) -> HashMap<u32, String> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f = csv_fields(l);
            if f.first().map(String::as_str) != Some("MA-L") {
                return None;
            }
            let name = f.get(2)?.split_whitespace().collect::<Vec<_>>().join(" ");
            Some((prefix_of(f.get(1)?.trim())?, name)).filter(|(_, n)| !n.is_empty())
        })
        .collect()
}

fn builtin() -> HashMap<u32, String> {
    let mut text = String::new();
    flate2::read::GzDecoder::new(BUILTIN)
        .read_to_string(&mut text)
        .expect("embedded OUI list");
    parse_tsv(&text)
}

/// 啟動時呼叫：有 `EM_OUI_FILE` 就讀它，讀不到就停止啟動（設定錯誤要被發現）
pub fn init(file: Option<&Path>) -> anyhow::Result<usize> {
    let table = match file {
        Some(p) => {
            let text = std::fs::read_to_string(p)
                .with_context(|| format!("reading OUI file {}", p.display()))?;
            let t = parse_ieee_csv(&text);
            anyhow::ensure!(!t.is_empty(), "{} has no MA-L entries", p.display());
            t
        }
        None => builtin(),
    };
    let n = table.len();
    let _ = TABLE.set(table);
    Ok(n)
}

/// MAC 的廠商名稱；隨機產生的位址（本機管理位址）與查不到的回 None
pub fn vendor(mac: &str) -> Option<&'static str> {
    let hex: String = mac
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(6)
        .collect();
    let p = prefix_of(&hex)?;
    TABLE.get_or_init(builtin).get(&p).map(String::as_str)
}

/// 第一個位元組的「本機管理」位元：手機、筆電的隨機 MAC
pub fn is_random(mac: &str) -> bool {
    mac.get(0..2)
        .and_then(|b| u8::from_str_radix(b, 16).ok())
        .is_some_and(|b| b & 0x02 != 0)
}

/// MAC 的前 6 個十六進位字元（大寫），標記「同廠牌都算已知」時用
pub fn prefix_hex(mac: &str) -> Option<String> {
    let hex: String = mac
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(6)
        .collect();
    (hex.len() == 6).then(|| hex.to_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_list_loads() {
        let t = builtin();
        assert!(t.len() > 30_000, "{}", t.len());
        // Cisco 的經典前綴
        assert!(t.get(&0x00000C).is_some_and(|n| n.contains("Cisco")));
        assert!(vendor("00:00:0c:12:34:56").is_some_and(|n| n.contains("Cisco")));
        assert_eq!(vendor("zz"), None);
    }

    #[test]
    fn ieee_csv() {
        let csv = "Registry,Assignment,Organization Name,Organization Address\n\
                   MA-L,286FB9,\"Nokia Shanghai Bell Co., Ltd.\",\"No.388 Road\"\n\
                   MA-L,38E2CA,Katun  Corporation,Addr\n\
                   MA-M,38E2CA1,Other,Addr\n\
                   MA-L,ZZZZZZ,Bad,Addr\n\
                   MA-L,ABCDEF,\"Say \"\"Hi\"\"\",x\n";
        let t = parse_ieee_csv(csv);
        assert_eq!(t.len(), 3);
        assert_eq!(t[&0x286FB9], "Nokia Shanghai Bell Co., Ltd.");
        assert_eq!(t[&0x38E2CA], "Katun Corporation");
        assert_eq!(t[&0xABCDEF], "Say \"Hi\"");
        assert_eq!(csv_fields("a,\"b,c\",d"), vec!["a", "b,c", "d"]);
    }

    #[test]
    fn init_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("oui.csv");
        std::fs::write(&p, "Registry,Assignment,Organization Name\nMA-L,001122,X\n").unwrap();
        assert_eq!(init(Some(&p)).unwrap_or(1), 1);
        std::fs::write(&p, "header only\n").unwrap();
        assert!(init(Some(&p)).is_err());
        assert!(init(Some(&dir.path().join("missing"))).is_err());
    }

    #[test]
    fn random_and_prefix() {
        assert!(is_random("da:a1:19:00:00:01"));
        assert!(is_random("02:00:00:00:00:01"));
        assert!(!is_random("00:1b:2c:00:00:01"));
        assert!(!is_random(""));
        assert_eq!(prefix_hex("00:1b:2c:00:00:01").as_deref(), Some("001B2C"));
        assert_eq!(prefix_hex("00:1b"), None);
    }
}
