//! 註冊金鑰：建立（明碼只顯示一次）、列表、作廢；群組管理員限自己的群組。

use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;

use super::auth::{AdminSession, Nav, Session, check_csrf};
use super::devices::{SelectOption, db_error, group_options};
use super::login::CsrfForm;
use super::{fmt_time, forbidden, not_found, render};
use crate::AppState;
use crate::tokens::{NewToken, create_token_in, revoke_token};

/// 內含於安裝檔的金鑰最長有效天數
const INSTALLER_MAX_DAYS: i64 = 90;

pub struct TokenRow {
    pub id: i64,
    pub name: String,
    pub group: String,
    pub used: i32,
    pub max: i32,
    pub expires: String,
    pub created_by: String,
    pub created_at: String,
    pub active: bool,
    pub state: &'static str,
}

#[derive(Template)]
#[template(path = "tokens.html")]
struct TokensPage {
    nav: Nav,
    new_token: Option<String>,
    groups: Vec<SelectOption>,
    rows: Vec<TokenRow>,
    installer: bool,
    public_url: String,
}

type Row = (
    i64,
    String,
    Option<String>,
    i32,
    i32,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    String,
    DateTime<Utc>,
);

async fn page_for(
    st: &AppState,
    s: &Session,
    new_token: Option<String>,
) -> Result<Response, Response> {
    if !s.can_manage() {
        return Err(forbidden());
    }
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT t.id, t.name, g.name, t.used_count, t.max_uses, t.expires_at, t.revoked_at, \
                t.created_by, t.created_at \
         FROM enroll_tokens t LEFT JOIN device_groups g ON g.id = t.group_id \
         WHERE t.kind = 'device' AND ($1::bool OR t.group_id = ANY($2::bigint[])) \
         ORDER BY t.id DESC",
    )
    .bind(s.all_devices())
    .bind(&s.groups)
    .fetch_all(&st.pool)
    .await
    .map_err(db_error)?;
    let now = Utc::now();
    let rows = rows
        .into_iter()
        .map(
            |(id, name, group, used, max, expires, revoked, created_by, created_at)| {
                let state = if revoked.is_some() {
                    "已作廢"
                } else if expires.is_some_and(|e| e <= now) {
                    "已過期"
                } else if used >= max {
                    "已用完"
                } else {
                    ""
                };
                TokenRow {
                    id,
                    name,
                    group: group.unwrap_or_else(|| "未分組".into()),
                    used,
                    max,
                    expires: expires
                        .map(|e| fmt_time(st, Some(e)))
                        .unwrap_or_else(|| "不限".into()),
                    created_by,
                    created_at: fmt_time(st, Some(created_at)),
                    active: state.is_empty(),
                    state,
                }
            },
        )
        .collect();
    Ok(render(&TokensPage {
        nav: Nav::from(s),
        new_token,
        groups: group_options(st, s, "", false).await.map_err(db_error)?,
        rows,
        // 檔案可能在伺服器啟動後才放進來，每次顯示時檢查
        installer: match &st.agent_msi {
            Some(p) => tokio::fs::metadata(p).await.is_ok_and(|m| m.is_file()),
            None => false,
        },
        public_url: st.agent_public_url.clone(),
    }))
}

pub async fn list(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
) -> Result<Response, Response> {
    page_for(&st, &s, None).await
}

#[derive(Deserialize)]
pub struct CreateForm {
    csrf: String,
    name: String,
    max_uses: String,
    #[serde(default)]
    group: String,
    #[serde(default)]
    valid_days: String,
    #[serde(default)]
    server_url: String,
    /// 非空：建立後直接下載安裝檔
    #[serde(default)]
    download: String,
}

pub async fn create(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Form(f): Form<CreateForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.can_manage() {
        return Err(forbidden());
    }
    let bad = |m: &str| (StatusCode::BAD_REQUEST, m.to_string()).into_response();
    let group: Option<i64> = match f.group.as_str() {
        "" | "none" => None,
        g => Some(g.parse().map_err(|_| bad("群組不正確"))?),
    };
    if !s.in_scope(group) {
        return Err(forbidden());
    }
    let name = f.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(bad("名稱必填，最多 100 字"));
    }
    let max_uses: i32 = f
        .max_uses
        .trim()
        .parse()
        .ok()
        .filter(|n| *n >= 1)
        .ok_or_else(|| bad("可使用次數需為正整數"))?;
    let valid_days: Option<i64> = match f.valid_days.trim() {
        "" => None,
        d => Some(
            d.parse()
                .ok()
                .filter(|n: &i64| (1..=3650).contains(n))
                .ok_or_else(|| bad("有效天數需為 1～3650"))?,
        ),
    };
    // 下載安裝檔：先檢查網址與範本，失敗時不留下多餘的金鑰
    let download = !f.download.is_empty();
    let installer = if download {
        let path = st.agent_msi.as_ref().ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "伺服器未設定安裝檔範本（EM_AGENT_MSI）",
            )
                .into_response()
        })?;
        // Windows 會把安裝檔快取在 C:\Windows\Installer（一般使用者可讀），金鑰必須有期限
        if !valid_days.is_some_and(|d| d <= INSTALLER_MAX_DAYS) {
            return Err(bad(&format!(
                "下載安裝檔時必須設定有效天數（1～{INSTALLER_MAX_DAYS}）"
            )));
        }
        let url = crate::installer::normalize_server_url(&f.server_url, &st.server_names)
            .map_err(|m| bad(&m))?;
        let template = tokio::fs::read(path).await.map_err(|e| {
            tracing::error!(error = %e, path = %path.display(), "cannot read agent MSI template");
            (StatusCode::SERVICE_UNAVAILABLE, "讀不到安裝檔範本").into_response()
        })?;
        crate::installer::check_template(&template).map_err(|e| {
            tracing::error!(error = %format!("{e:#}"), path = %path.display(), "bad agent MSI template");
            (StatusCode::SERVICE_UNAVAILABLE, "安裝檔範本不正確").into_response()
        })?;
        Some((url, template))
    } else {
        None
    };
    // 金鑰與稽核記錄同一個交易：不會有沒留下記錄的金鑰
    let mut tx = st.pool.begin().await.map_err(db_error)?;
    let (id, token) = create_token_in(
        &mut tx,
        &NewToken {
            name: name.into(),
            group_id: group,
            expires_at: valid_days.map(|d| Utc::now() + Duration::days(d)),
            max_uses,
            created_by: s.username.clone(),
            kind: crate::tokens::TokenKind::Device,
        },
    )
    .await
    .map_err(db_error)?;
    crate::audit::record(
        &mut tx,
        &s.username,
        "token_create",
        Some(&id.to_string()),
        serde_json::json!({
            "name": name, "max_uses": max_uses, "group_id": group, "valid_days": valid_days,
            "installer": download, "server_url": installer.as_ref().map(|(u, _)| u)
        }),
    )
    .await
    .map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    if let Some((url, template)) = installer {
        let root = st.ca.root_pem().to_string();
        let msi = tokio::task::spawn_blocking(move || {
            crate::installer::build_msi(&template, &url, &token, &root)
        })
        .await
        .map_err(anyhow::Error::from)
        .and_then(|r| r)
        .map_err(|e| {
            tracing::error!(error = %format!("{e:#}"), "building agent MSI failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "產生安裝檔失敗").into_response()
        })?;
        return Ok((
            [
                (header::CONTENT_TYPE, "application/x-msi"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"endpoint-agent.msi\"",
                ),
            ],
            msi,
        )
            .into_response());
    }
    page_for(&st, &s, Some(token)).await
}

pub async fn revoke(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.can_manage() {
        return Err(forbidden());
    }
    let group: Option<Option<i64>> =
        // 快取金鑰在 /caches 管理
        sqlx::query_scalar("SELECT group_id FROM enroll_tokens WHERE id = $1 AND kind = 'device'")
            .bind(id)
            .fetch_optional(&st.pool)
            .await
            .map_err(db_error)?;
    match group {
        Some(g) if s.in_scope(g) => {}
        _ => return Err(not_found()),
    }
    revoke_token(&st.pool, id, &s.username)
        .await
        .map_err(|e| (StatusCode::CONFLICT, format!("{e:#}")).into_response())?;
    Ok(Redirect::to("/tokens").into_response())
}
