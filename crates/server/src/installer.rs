//! 由通用範本 MSI 產生「已包好伺服器網址、註冊金鑰、根憑證」的安裝檔：
//! 更新 Property 表的佔位列並換新 package code。全部在記憶體中完成。
//! 只能更新既有列：msi crate 新增列時會把整張表依字母重排，Windows Installer 會讀不到。

use std::collections::BTreeMap;
use std::io::Cursor;

use anyhow::Context;
use msi::{Column, Expr, Insert, Package, PackageType, Select, Update, Value};

/// 根憑證 PEM → 單行 base64（MSI 的 ROOT_CA 屬性）。
pub fn root_b64(root_pem: &str) -> String {
    root_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(str::trim)
        .collect()
}

pub fn build_msi(
    template: &[u8],
    server_url: &str,
    token: &str,
    root_pem: &str,
) -> anyhow::Result<Vec<u8>> {
    let existing = read_properties(template)?;
    let mut pkg = Package::open(Cursor::new(template.to_vec()))?;
    let root = root_b64(root_pem);
    for (k, v) in [
        ("SERVER_URL", server_url),
        ("ENROLL_TOKEN", token),
        ("ROOT_CA", root.as_str()),
    ] {
        anyhow::ensure!(
            existing.contains_key(k),
            "範本 MSI 缺少 {k} 屬性（請用 installer/agent.wxs 建置的範本）"
        );
        pkg.update_rows(
            Update::table("Property")
                .set("Value", Value::from(v))
                .with(Expr::col("Property").eq(Expr::string(k))),
        )
        .with_context(|| format!("updating {k}"))?;
    }
    pkg.summary_info_mut().set_uuid(uuid::Uuid::new_v4());
    Ok(pkg.into_inner()?.into_inner())
}

pub fn read_properties(msi: &[u8]) -> anyhow::Result<BTreeMap<String, String>> {
    let mut pkg = Package::open(Cursor::new(msi.to_vec()))?;
    let mut out = BTreeMap::new();
    for row in pkg.select_rows(Select::table("Property"))? {
        if let (Some(k), Some(v)) = (row[0].as_str(), row[1].as_str()) {
            out.insert(k.to_string(), v.to_string());
        }
    }
    Ok(out)
}

/// 只接受 `https://主機:埠`（結尾的 `/` 可有可無），主機名稱（或 IP）必須在伺服器憑證的 SAN 內，
/// 回傳正規化後的網址。這個值會放進 MSI 自訂動作的命令列，也會直接串接成 API 網址，
/// 所以路徑、查詢字串、userinfo、引號、反斜線、空白一律拒絕；埠必填，避免連到管理網頁的 443。
pub fn normalize_server_url(url: &str, names: &[String]) -> Result<String, String> {
    const FORMAT: &str = "伺服器網址格式須為 https://主機:埠（例：https://em.example.com:8443）";
    let rest = url.trim().strip_prefix("https://").ok_or(FORMAT)?;
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    let (host, port) = match authority.strip_prefix('[') {
        Some(v6) => {
            let (h, p) = v6.split_once("]:").ok_or(FORMAT)?;
            let ip: std::net::Ipv6Addr = h.parse().map_err(|_| FORMAT)?;
            (ip.to_string(), p)
        }
        None => {
            let (h, p) = authority.rsplit_once(':').ok_or(FORMAT)?;
            let valid = !h.is_empty()
                && h.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
            if !valid {
                return Err(FORMAT.into());
            }
            (h.to_ascii_lowercase(), p)
        }
    };
    let port: u16 = port
        .parse()
        .ok()
        .filter(|p| *p != 0)
        .ok_or("伺服器網址的埠須為 1～65535")?;
    if !names.iter().any(|n| san_matches(n, &host)) {
        return Err(format!(
            "「{host}」不在伺服器憑證的名稱內（{}），Agent 會無法連線",
            names.join("、")
        ));
    }
    Ok(url_of(&host, port))
}

/// 憑證名稱是否涵蓋主機：完全相同（不分大小寫），或 `*.網域` 涵蓋恰好多一層的名稱。
fn san_matches(name: &str, host: &str) -> bool {
    match name.strip_prefix("*.") {
        Some(domain) => host
            .split_once('.')
            .is_some_and(|(label, rest)| !label.is_empty() && rest.eq_ignore_ascii_case(domain)),
        None => name.eq_ignore_ascii_case(host),
    }
}

/// 未設定 EM_AGENT_PUBLIC_URL 時，表單預設填入伺服器憑證的第一個名稱與 Agent API 的埠。
pub fn default_public_url(names: &[String], agent_port: u16) -> String {
    names
        .iter()
        .find(|n| !n.starts_with("*."))
        .map(|h| url_of(h, agent_port))
        .unwrap_or_default()
}

fn url_of(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("https://[{host}]:{port}")
    } else {
        format!("https://{host}:{port}")
    }
}

/// 測試用：只有 Property 表的最小 MSI，含三個佔位屬性（與 installer/agent.wxs 相同）。
#[doc(hidden)]
pub fn sample_template() -> Vec<u8> {
    template_with(&[
        ("KEEP", "me"),
        ("SERVER_URL", " "),
        ("ENROLL_TOKEN", " "),
        ("ROOT_CA", " "),
    ])
}

fn template_with(props: &[(&str, &str)]) -> Vec<u8> {
    let mut pkg =
        Package::create(PackageType::Installer, Cursor::new(Vec::new())).expect("create package");
    pkg.create_table(
        "Property",
        vec![
            Column::build("Property").primary_key().id_string(72),
            Column::build("Value").formatted_string(0),
        ],
    )
    .expect("create Property table");
    for (k, v) in props {
        pkg.insert_rows(Insert::into("Property").row(vec![Value::from(*k), Value::from(*v)]))
            .expect("insert");
    }
    pkg.into_inner().expect("into_inner").into_inner()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "-----BEGIN CERTIFICATE-----\nQUJD\nREVG\n-----END CERTIFICATE-----\n";

    #[test]
    fn build_sets_properties_and_new_package_code() {
        let t = sample_template();
        let a = build_msi(&t, "https://em.example.com:8443", "tok-1", ROOT).unwrap();
        let p = read_properties(&a).unwrap();
        assert_eq!(p["SERVER_URL"], "https://em.example.com:8443");
        assert_eq!(p["ENROLL_TOKEN"], "tok-1");
        assert_eq!(p["ROOT_CA"], "QUJDREVG");
        assert_eq!(p["KEEP"], "me", "其他屬性不動");
        let b = build_msi(&t, "https://em.example.com:8443", "tok-2", ROOT).unwrap();
        assert_ne!(package_code(&a), package_code(&b));
        // 範本已有同名屬性時覆寫而不是重複
        let again = build_msi(&a, "https://other.example.com:8443", "tok-3", ROOT).unwrap();
        assert_eq!(
            read_properties(&again).unwrap()["SERVER_URL"],
            "https://other.example.com:8443"
        );
    }

    /// 只能更新範本既有的列：新增列會讓 msi crate 重排資料表，Windows Installer 讀不到。
    #[test]
    fn template_without_placeholders_is_rejected() {
        let t = template_with(&[("KEEP", "me")]);
        let e = build_msi(&t, "https://em.example.com:8443", "tok", ROOT).unwrap_err();
        assert!(format!("{e:#}").contains("SERVER_URL"), "{e:#}");
    }

    #[test]
    fn server_url_must_match_certificate() {
        let names = vec![
            "em.example.com".to_string(),
            "10.1.2.3".to_string(),
            "::1".to_string(),
        ];
        let ok = |u: &str| normalize_server_url(u, &names);
        assert_eq!(
            ok("https://em.example.com:8443").unwrap(),
            "https://em.example.com:8443"
        );
        assert_eq!(
            ok(" https://EM.example.com:8443/ ").unwrap(),
            "https://em.example.com:8443"
        );
        assert_eq!(
            ok("https://10.1.2.3:8443").unwrap(),
            "https://10.1.2.3:8443"
        );
        assert_eq!(ok("https://[::1]:8443").unwrap(), "https://[::1]:8443");
        assert!(ok("https://10.1.2.4:8443").is_err());
        assert!(ok("http://em.example.com:8443").is_err());
        assert!(ok("https://em.example.com.evil.test:8443").is_err());
        assert!(ok("https://").is_err());
    }

    /// 值會放進 MSI 自訂動作的命令列（"[SERVER_URL]"），也會直接串接成 API 網址：
    /// 只接受 https://主機:埠，其餘一律拒絕。
    #[test]
    fn server_url_rejects_anything_but_host_and_port() {
        let names = vec!["em.example.com".to_string()];
        for bad in [
            "https://em.example.com",         // 沒有埠：會連到管理網頁的 443
            "https://em.example.com:",        // 空的埠
            "https://em.example.com:abc",     // 非數字
            "https://em.example.com:0",       // 超出範圍
            "https://em.example.com:70000",   // 超出範圍
            "https://em.example.com:8443/\\", // 反斜線會吃掉命令列的結尾引號
            "https://em.example.com:8443/\" --root-ca \"x", // 注入其他參數
            "https://em.example.com:8443/api", // 路徑
            "https://em.example.com:8443?x=1", // 查詢字串
            "https://u@em.example.com:8443",  // userinfo
            "https://em.example.com:8443 x",  // 空白
        ] {
            assert!(
                normalize_server_url(bad, &names).is_err(),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn server_url_matches_wildcard_san_and_ipv6_variants() {
        let names = vec!["*.example.com".to_string(), "::1".to_string()];
        let ok = |u: &str| normalize_server_url(u, &names);
        assert_eq!(
            ok("https://em.example.com:8443").unwrap(),
            "https://em.example.com:8443"
        );
        // 萬用字元只涵蓋一層
        assert!(ok("https://a.b.example.com:8443").is_err());
        assert!(ok("https://example.com:8443").is_err());
        // IPv6 寫法不同但位址相同
        assert_eq!(ok("https://[0:0::1]:8443").unwrap(), "https://[::1]:8443");
    }

    #[test]
    fn default_public_url_uses_first_name_and_agent_port() {
        assert_eq!(
            default_public_url(&["em.example.com".into(), "10.1.2.3".into()], 8443),
            "https://em.example.com:8443"
        );
        assert_eq!(
            default_public_url(&["::1".into()], 8443),
            "https://[::1]:8443"
        );
        assert_eq!(default_public_url(&[], 8443), "");
        assert_eq!(
            default_public_url(&["*.example.com".into(), "em.example.com".into()], 8443),
            "https://em.example.com:8443"
        );
    }

    fn package_code(msi: &[u8]) -> uuid::Uuid {
        msi::Package::open(std::io::Cursor::new(msi.to_vec()))
            .unwrap()
            .summary_info()
            .uuid()
            .unwrap()
    }
}
