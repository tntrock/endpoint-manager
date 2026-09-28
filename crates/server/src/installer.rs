//! 由通用範本 MSI 產生「已包好伺服器網址、註冊金鑰、根憑證」的安裝檔：
//! 改寫 Property 表（先刪後插）並換新 package code。全部在記憶體中完成。

use std::collections::BTreeMap;
use std::io::Cursor;

use msi::{Column, Delete, Expr, Insert, Package, PackageType, Select, Value};

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
    let mut pkg = Package::open(Cursor::new(template.to_vec()))?;
    let root = root_b64(root_pem);
    for (k, v) in [
        ("SERVER_URL", server_url),
        ("ENROLL_TOKEN", token),
        ("ROOT_CA", root.as_str()),
    ] {
        pkg.delete_rows(Delete::from("Property").with(Expr::col("Property").eq(Expr::string(k))))?;
        pkg.insert_rows(Insert::into("Property").row(vec![Value::from(k), Value::from(v)]))?;
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

/// 網址必須是 https，且主機名稱（或 IP）在伺服器憑證的 SAN 內，否則 Agent 會連不上。
pub fn check_server_url(url: &str, names: &[String]) -> Result<(), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or("伺服器網址必須以 https:// 開頭")?;
    let authority = rest.split('/').next().unwrap_or_default();
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or_default(),
        None => authority.rsplit_once(':').map_or(authority, |(h, _)| h),
    };
    if host.is_empty() {
        return Err("伺服器網址缺少主機名稱".into());
    }
    if names.iter().any(|n| n.eq_ignore_ascii_case(host)) {
        Ok(())
    } else {
        Err(format!(
            "「{host}」不在伺服器憑證的名稱內（{}），Agent 會無法連線",
            names.join("、")
        ))
    }
}

/// 測試用：只有 Property 表的最小 MSI。
#[doc(hidden)]
pub fn sample_template() -> Vec<u8> {
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
    pkg.insert_rows(Insert::into("Property").row(vec![Value::from("KEEP"), Value::from("me")]))
        .expect("insert");
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

    #[test]
    fn server_url_must_match_certificate() {
        let names = vec!["em.example.com".to_string(), "10.1.2.3".to_string()];
        assert!(check_server_url("https://em.example.com:8443", &names).is_ok());
        assert!(check_server_url("https://EM.example.com:8443/", &names).is_ok());
        assert!(check_server_url("https://10.1.2.3:8443", &names).is_ok());
        assert!(check_server_url("https://10.1.2.4:8443", &names).is_err());
        assert!(check_server_url("http://em.example.com:8443", &names).is_err());
        assert!(check_server_url("https://em.example.com.evil.test:8443", &names).is_err());
        assert!(check_server_url("https://", &names).is_err());
    }

    fn package_code(msi: &[u8]) -> uuid::Uuid {
        msi::Package::open(std::io::Cursor::new(msi.to_vec()))
            .unwrap()
            .summary_info()
            .uuid()
            .unwrap()
    }
}
