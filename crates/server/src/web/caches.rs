//! 分點快取：清單、核准／拒絕、停用／啟用、指定據點、刪除，以及快取註冊金鑰。只限平台管理員。

use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;

use super::auth::{AdminSession, Nav, Session, check_csrf};
use super::devices::{action_error, db_error};
use super::login::CsrfForm;
use super::sites::cache_status_label;
use super::{fmt_time, forbidden, not_found, render};
use crate::AppState;
use crate::branch::caches;
use crate::tokens::{NewToken, TokenKind, create_token_in, revoke_token};

fn platform(s: &Session) -> Result<(), Response> {
    if s.all_devices() {
        Ok(())
    } else {
        Err(forbidden())
    }
}

pub struct CacheRow {
    pub id: i64,
    pub name: String,
    pub site: String,
    pub site_id: Option<i64>,
    pub url: String,
    pub status: String,
    pub status_label: &'static str,
    pub last_seen: String,
    pub version: String,
    pub disk: String,
    pub progress: String,
}

pub struct SiteOption {
    pub id: i64,
    pub name: String,
}

pub struct CacheTokenRow {
    pub id: i64,
    pub name: String,
    pub used: i32,
    pub max: i32,
    pub expires: String,
    pub created_by: String,
    pub state: &'static str,
}

#[derive(Template)]
#[template(path = "caches.html")]
struct CachesPage {
    nav: Nav,
    new_token: Option<String>,
    server_url: String,
    rows: Vec<CacheRow>,
    /// 還沒有快取的據點（核准、改據點時可選）
    free_sites: Vec<SiteOption>,
    tokens: Vec<CacheTokenRow>,
}

type Row = (
    i64,
    String,
    Option<String>,
    Option<i64>,
    String,
    String,
    Option<DateTime<Utc>>,
    Option<String>,
    Option<i64>,
    i64,
);

type TokenDbRow = (
    i64,
    String,
    i32,
    i32,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    String,
);

async fn page_for(
    st: &AppState,
    s: &Session,
    new_token: Option<String>,
) -> Result<Response, Response> {
    // 應有：未停止的派送用到的套件；已存：快取回報的套件中屬於應有清單的
    let expected: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT d.package_id) FROM deployments d WHERE d.stage <> 'stopped'",
    )
    .fetch_one(&st.pool)
    .await
    .map_err(db_error)?;
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT c.id, c.name, s.name, c.site_id, c.url, c.status, c.last_seen, c.version, \
                c.disk_used_bytes, \
                (SELECT count(*) FROM cache_packages cp WHERE cp.cache_id = c.id AND EXISTS \
                   (SELECT 1 FROM deployments d WHERE d.package_id = cp.package_id \
                    AND d.stage <> 'stopped')) \
         FROM caches c LEFT JOIN sites s ON s.id = c.site_id ORDER BY lower(c.name), c.id",
    )
    .fetch_all(&st.pool)
    .await
    .map_err(db_error)?;
    let rows = rows
        .into_iter()
        .map(
            |(id, name, site, site_id, url, status, last_seen, version, disk, stored)| CacheRow {
                id,
                name,
                site: site.unwrap_or_else(|| "—".into()),
                site_id,
                url,
                status_label: cache_status_label(&status),
                status,
                last_seen: fmt_time(st, last_seen),
                version: version.unwrap_or_else(|| "—".into()),
                disk: disk
                    .map(|b| format!("{:.1} GB", b as f64 / 1024f64.powi(3)))
                    .unwrap_or_else(|| "—".into()),
                progress: format!("已存 {stored}／應有 {expected}"),
            },
        )
        .collect();
    let free_sites: Vec<(i64, String)> = sqlx::query_as(
        "SELECT s.id, s.name FROM sites s \
         WHERE NOT EXISTS (SELECT 1 FROM caches c WHERE c.site_id = s.id) \
         ORDER BY lower(s.name), s.id",
    )
    .fetch_all(&st.pool)
    .await
    .map_err(db_error)?;
    let tokens: Vec<TokenDbRow> = sqlx::query_as(
        "SELECT id, name, used_count, max_uses, expires_at, revoked_at, created_by \
         FROM enroll_tokens WHERE kind = 'cache' ORDER BY id DESC",
    )
    .fetch_all(&st.pool)
    .await
    .map_err(db_error)?;
    let now = Utc::now();
    Ok(render(&CachesPage {
        nav: Nav::from(s),
        new_token,
        server_url: st.agent_public_url.clone(),
        rows,
        free_sites: free_sites
            .into_iter()
            .map(|(id, name)| SiteOption { id, name })
            .collect(),
        tokens: tokens
            .into_iter()
            .map(|(id, name, used, max, expires, revoked, created_by)| {
                let state = if revoked.is_some() {
                    "已作廢"
                } else if expires.is_some_and(|e| e <= now) {
                    "已過期"
                } else if used >= max {
                    "已用完"
                } else {
                    ""
                };
                CacheTokenRow {
                    id,
                    name,
                    used,
                    max,
                    expires: expires
                        .map(|e| fmt_time(st, Some(e)))
                        .unwrap_or_else(|| "不限".into()),
                    created_by,
                    state,
                }
            })
            .collect(),
    }))
}

pub async fn list(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
) -> Result<Response, Response> {
    platform(&s)?;
    page_for(&st, &s, None).await
}

#[derive(Deserialize)]
pub struct ActionForm {
    csrf: String,
    #[serde(default)]
    site: String,
}

pub async fn act(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path((id, action)): Path<(i64, String)>,
    Form(f): Form<ActionForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    let site: Option<i64> = match f.site.trim() {
        "" => None,
        v => Some(
            v.parse()
                .map_err(|_| (StatusCode::BAD_REQUEST, "據點不正確").into_response())?,
        ),
    };
    let user = s.username.as_str();
    let result = match action.as_str() {
        "approve" => match site {
            Some(site) => caches::approve(&st.pool, &st.ca, id, site, user).await,
            None => Err(anyhow::anyhow!("請選擇據點")),
        },
        "reject" => caches::reject(&st.pool, id, user).await,
        "disable" => caches::set_disabled(&st.pool, &st.ca, id, true, user).await,
        "enable" => caches::set_disabled(&st.pool, &st.ca, id, false, user).await,
        "site" => caches::assign_site(&st.pool, id, site, user).await,
        "delete" => caches::delete_cache(&st.pool, id, user).await,
        _ => return Err(not_found()),
    };
    match result {
        Ok(()) => Ok(Redirect::to("/caches").into_response()),
        Err(e) if format!("{e:#}") == "快取不存在" => Err(not_found()),
        Err(e) => Err(action_error(e)),
    }
}

#[derive(Deserialize)]
pub struct TokenForm {
    csrf: String,
    name: String,
    max_uses: String,
    #[serde(default)]
    valid_days: String,
}

pub async fn create_token(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Form(f): Form<TokenForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    let bad = |m: &str| (StatusCode::BAD_REQUEST, m.to_string()).into_response();
    let name = f.name.trim();
    if name.is_empty() || name.chars().count() > 100 || name.chars().any(char::is_control) {
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
    // 金鑰與稽核記錄同一個交易
    let mut tx = st.pool.begin().await.map_err(db_error)?;
    let (id, token) = create_token_in(
        &mut tx,
        &NewToken {
            name: name.into(),
            group_id: None,
            expires_at: valid_days.map(|d| Utc::now() + Duration::days(d)),
            max_uses,
            created_by: s.username.clone(),
            kind: TokenKind::Cache,
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
            "name": name, "max_uses": max_uses, "valid_days": valid_days, "kind": "cache"
        }),
    )
    .await
    .map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    page_for(&st, &s, Some(token)).await
}

pub async fn revoke_cache_token(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    let kind: Option<String> = sqlx::query_scalar("SELECT kind FROM enroll_tokens WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.pool)
        .await
        .map_err(db_error)?;
    if kind.as_deref() != Some("cache") {
        return Err(not_found());
    }
    revoke_token(&st.pool, id, &s.username)
        .await
        .map_err(|e| (StatusCode::CONFLICT, format!("{e:#}")).into_response())?;
    Ok(Redirect::to("/caches").into_response())
}
