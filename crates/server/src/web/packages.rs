//! 派送用的套件：清單、上傳（PUT 原始檔案串流）、編輯、刪除。只限平台管理員。

use askama::Template;
use axum::Json;
use axum::body::Body;
use axum::extract::{Path, RawForm, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Utc};
use serde_json::json;

use super::auth::{AdminSession, Nav, Session, check_csrf};
use super::devices::db_error;
use super::{fmt_time, forbidden, not_found, render};
use crate::AppState;
use crate::deploy::admin::{self, PackageInput};
use crate::deploy::store;

fn platform(s: &Session) -> Result<(), Response> {
    if s.all_devices() {
        Ok(())
    } else {
        Err(forbidden())
    }
}

/// 位元組數轉成易讀的大小
pub fn human_size(n: i64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

pub struct PackageRow {
    pub id: i64,
    pub name: String,
    pub version: String,
    pub kind: &'static str,
    pub file_name: String,
    pub size: String,
    pub used: i64,
    pub created: String,
}

#[derive(Template)]
#[template(path = "packages.html")]
struct ListPage {
    nav: Nav,
    rows: Vec<PackageRow>,
}

fn kind_label(k: &str) -> &'static str {
    if k == "msi" { "MSI" } else { "EXE" }
}

type ListRow = (i64, String, String, String, String, i64, i64, DateTime<Utc>);

pub async fn list(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
) -> Result<Response, Response> {
    platform(&s)?;
    let rows: Vec<ListRow> = sqlx::query_as(
        "SELECT p.id, p.name, p.version, p.kind, p.file_name, p.size, \
                (SELECT count(*) FROM deployments d WHERE d.package_id = p.id), p.created_at \
         FROM packages p ORDER BY lower(p.name), p.id DESC",
    )
    .fetch_all(&st.pool)
    .await
    .map_err(db_error)?;
    Ok(render(&ListPage {
        nav: Nav::from(&s),
        rows: rows
            .into_iter()
            .map(
                |(id, name, version, kind, file_name, size, used, at)| PackageRow {
                    id,
                    name,
                    version,
                    kind: kind_label(&kind),
                    file_name,
                    size: human_size(size),
                    used,
                    created: fmt_time(&st, Some(at)),
                },
            )
            .collect(),
    }))
}

#[derive(Template)]
#[template(path = "package_upload.html")]
struct UploadPage {
    nav: Nav,
}

pub async fn upload_page(AdminSession(s): AdminSession) -> Result<Response, Response> {
    platform(&s)?;
    Ok(render(&UploadPage { nav: Nav::from(&s) }))
}

fn bad(msg: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, msg.into()).into_response()
}

/// 上傳即建立套件（以 MSI 資訊或檔名預填），之後到編輯頁補參數。回 201 與 `{"id": …}`。
pub async fn upload(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let token = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if let Err(r) = check_csrf(&s, token) {
        return r;
    }
    if let Err(r) = platform(&s) {
        return r;
    }
    let raw = headers
        .get("x-file-name")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let name = form_urlencoded::parse(format!("n={raw}").as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default();
    let base = name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    let lower = base.to_lowercase();
    let kind = if lower.ends_with(".msi") {
        "msi"
    } else if lower.ends_with(".exe") {
        "exe"
    } else {
        return bad("只接受 .msi 或 .exe 檔案");
    };
    let stored = match store::save(&st.package_dir, Box::pin(body.into_data_stream())).await {
        Ok(v) => v,
        Err(e) if e.is::<store::TooLarge>() => {
            return (StatusCode::PAYLOAD_TOO_LARGE, e.to_string()).into_response();
        }
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), "package upload failed");
            return bad(format!("上傳失敗：{e:#}"));
        }
    };
    let discard = || async {
        if let Err(e) = admin::discard_file(&st.pool, &st.package_dir, &stored.sha256).await {
            tracing::error!(error = %format!("{e:#}"), "discarding rejected upload failed");
        }
    };
    let info = if kind == "msi" {
        let path = store::file_path(&st.package_dir, &stored.sha256);
        match tokio::task::spawn_blocking(move || store::msi_info(&path))
            .await
            .ok()
            .flatten()
        {
            Some(i) => Some(i),
            None => {
                discard().await;
                return bad("不是有效的 MSI 檔案（讀不到 ProductCode）");
            }
        }
    } else {
        None
    };
    let stem: String = base[..base.len() - 4]
        .chars()
        .take(admin::MAX_NAME_LEN)
        .collect();
    let display = info
        .as_ref()
        .map(|i| i.name.clone())
        .filter(|n| !n.trim().is_empty())
        .unwrap_or(stem);
    let display: String = display.chars().take(admin::MAX_NAME_LEN).collect();
    let input = PackageInput {
        name: display.clone(),
        version: info.as_ref().map(|i| i.version.clone()).unwrap_or_default(),
        kind: kind.into(),
        install_args: String::new(),
        uninstall_args: String::new(),
        success_codes: vec![],
        detect_name: format!("{display}*"),
        detect_publisher: info
            .as_ref()
            .map(|i| i.manufacturer.clone())
            .unwrap_or_default(),
        detect_min_version: info.as_ref().map(|i| i.version.clone()).unwrap_or_default(),
    };
    let product_code = info.as_ref().map(|i| i.product_code.as_str());
    match admin::create_package(
        &st.pool,
        &st.package_dir,
        &stored,
        &base,
        product_code,
        &input,
        &s.username,
    )
    .await
    {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id }))).into_response(),
        Err(e) => {
            discard().await;
            bad(format!("{e:#}"))
        }
    }
}

#[derive(Template)]
#[template(path = "package_form.html")]
struct FormPage {
    nav: Nav,
    id: i64,
    kind: String,
    file_name: String,
    size: String,
    sha256: String,
    product_code: String,
    used: i64,
    name: String,
    version: String,
    install_args: String,
    uninstall_args: String,
    success_codes: String,
    detect_name: String,
    detect_publisher: String,
    detect_min_version: String,
    error: Option<String>,
}

type PackageDbRow = (
    String,
    String,
    String,
    String,
    i64,
    String,
    Option<String>,
    String,
    String,
    Vec<i32>,
    String,
    Option<String>,
    Option<String>,
    i64,
);

async fn load_form(st: &AppState, s: &Session, id: i64) -> Result<Option<FormPage>, sqlx::Error> {
    let row: Option<PackageDbRow> = sqlx::query_as(
        "SELECT name, version, kind, file_name, size, sha256, msi_product_code, install_args, \
                uninstall_args, success_codes, detect_name, detect_publisher, detect_min_version, \
                (SELECT count(*) FROM deployments d WHERE d.package_id = p.id) \
         FROM packages p WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await?;
    Ok(row.map(|r| FormPage {
        nav: Nav::from(s),
        id,
        name: r.0,
        version: r.1,
        kind: r.2,
        file_name: r.3,
        size: human_size(r.4),
        sha256: r.5,
        product_code: r.6.unwrap_or_default(),
        install_args: r.7,
        uninstall_args: r.8,
        success_codes: r
            .9
            .iter()
            .map(i32::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        detect_name: r.10,
        detect_publisher: r.11.unwrap_or_default(),
        detect_min_version: r.12.unwrap_or_default(),
        used: r.13,
        error: None,
    }))
}

pub async fn edit_form(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
) -> Result<Response, Response> {
    platform(&s)?;
    let page = load_form(&st, &s, id).await.map_err(db_error)?;
    page.map(|p| render(&p)).ok_or_else(not_found)
}

/// 表單欄位（逗號或空白分隔的結束碼）
fn parse(raw: &[u8]) -> (String, PackageInput, Result<Vec<i32>, String>) {
    let mut csrf = String::new();
    let mut i = PackageInput {
        name: String::new(),
        version: String::new(),
        kind: String::new(),
        install_args: String::new(),
        uninstall_args: String::new(),
        success_codes: vec![],
        detect_name: String::new(),
        detect_publisher: String::new(),
        detect_min_version: String::new(),
    };
    let mut codes = String::new();
    for (k, v) in form_urlencoded::parse(raw) {
        let v = v.into_owned();
        match k.as_ref() {
            "csrf" => csrf = v,
            "name" => i.name = v,
            "version" => i.version = v,
            "install_args" => i.install_args = v,
            "uninstall_args" => i.uninstall_args = v,
            "success_codes" => codes = v,
            "detect_name" => i.detect_name = v,
            "detect_publisher" => i.detect_publisher = v,
            "detect_min_version" => i.detect_min_version = v,
            _ => {}
        }
    }
    let parsed = codes
        .split([',', ' ', '，'])
        .filter(|x| !x.trim().is_empty())
        .map(|x| {
            x.trim()
                .parse::<i32>()
                .map_err(|_| format!("成功結束碼必須是整數：{x}"))
        })
        .collect();
    (csrf, i, parsed)
}

pub async fn update(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let (csrf, mut input, codes) = parse(&raw);
    check_csrf(&s, &csrf)?;
    platform(&s)?;
    let mut page = load_form(&st, &s, id)
        .await
        .map_err(db_error)?
        .ok_or_else(not_found)?;
    input.kind = page.kind.clone();
    let result = match codes {
        Ok(c) => {
            input.success_codes = c;
            admin::update_package(&st.pool, id, &input, &s.username)
                .await
                .map_err(|e| format!("{e:#}"))
        }
        Err(e) => Err(e),
    };
    match result {
        Ok(()) => Ok(Redirect::to("/packages").into_response()),
        Err(e) => {
            // 保留使用者輸入，顯示錯誤
            page.name = input.name;
            page.version = input.version;
            page.install_args = input.install_args;
            page.uninstall_args = input.uninstall_args;
            page.detect_name = input.detect_name;
            page.detect_publisher = input.detect_publisher;
            page.detect_min_version = input.detect_min_version;
            page.error = Some(e);
            Ok((StatusCode::UNPROCESSABLE_ENTITY, render(&page)).into_response())
        }
    }
}

pub async fn delete(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let (csrf, _, _) = parse(&raw);
    check_csrf(&s, &csrf)?;
    platform(&s)?;
    admin::delete_package(&st.pool, &st.package_dir, id, &s.username)
        .await
        .map_err(super::devices::action_error)?;
    Ok(Redirect::to("/packages").into_response())
}
