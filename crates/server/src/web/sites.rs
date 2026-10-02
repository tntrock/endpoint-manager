//! 據點（分點快取）：清單、新增、編輯、刪除。只限平台管理員。

use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use super::auth::{AdminSession, Nav, Session, check_csrf};
use super::devices::db_error;
use super::login::CsrfForm;
use super::{forbidden, not_found, render};
use crate::AppState;
use crate::branch::sites::{self, SiteInput};

fn platform(s: &Session) -> Result<(), Response> {
    if s.all_devices() {
        Ok(())
    } else {
        Err(forbidden())
    }
}

/// 快取狀態的顯示文字
pub fn cache_status_label(status: &str) -> &'static str {
    match status {
        "active" => "使用中",
        "disabled" => "已停用",
        "pending" => "待核准",
        "rejected" => "已拒絕",
        _ => "未知",
    }
}

pub struct SiteRow {
    pub id: i64,
    pub name: String,
    pub cidrs: Vec<String>,
    pub cache: String,
    pub fallback: bool,
    pub bandwidth: String,
    pub disk_gb: i32,
    pub devices: i64,
}

#[derive(Template)]
#[template(path = "sites.html")]
struct SitesPage {
    nav: Nav,
    rows: Vec<SiteRow>,
}

type Row = (
    i64,
    String,
    Vec<String>,
    bool,
    Option<i32>,
    i32,
    Option<String>,
    Option<String>,
    i64,
);

pub async fn list(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
) -> Result<Response, Response> {
    platform(&s)?;
    // 每台裝置只解析一次 IP（try_inet 有例外處理，不要對每個據點各算一次）
    let rows: Vec<Row> = sqlx::query_as(
        "WITH d AS (SELECT try_inet(last_ip) AS ip FROM devices \
                    WHERE status = 'active' AND last_ip IS NOT NULL) \
         SELECT s.id, s.name, s.cidrs::text[], s.fallback_to_central, s.bandwidth_limit_mbps, \
                s.disk_limit_gb, c.name, c.status, \
                (SELECT count(*) FROM d WHERE d.ip <<= ANY(s.cidrs)) \
         FROM sites s LEFT JOIN caches c ON c.site_id = s.id \
         ORDER BY lower(s.name), s.id",
    )
    .fetch_all(&st.pool)
    .await
    .map_err(db_error)?;
    let rows = rows
        .into_iter()
        .map(
            |(id, name, cidrs, fallback, bw, disk_gb, cache, status, devices)| SiteRow {
                id,
                name,
                cidrs,
                cache: match (cache, status) {
                    (Some(c), Some(st)) => format!("{c}（{}）", cache_status_label(&st)),
                    _ => "—".into(),
                },
                fallback,
                bandwidth: bw
                    .map(|b| format!("{b} Mbps"))
                    .unwrap_or_else(|| "不限".into()),
                disk_gb,
                devices,
            },
        )
        .collect();
    Ok(render(&SitesPage {
        nav: Nav::from(&s),
        rows,
    }))
}

#[derive(Deserialize, Default)]
pub struct SiteForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub cidrs: String,
    #[serde(default)]
    pub fallback: Option<String>,
    #[serde(default)]
    pub bandwidth: String,
    #[serde(default)]
    pub disk_gb: String,
}

/// 表單重新顯示用的欄位
pub struct Fields {
    pub name: String,
    pub cidrs: String,
    pub fallback: bool,
    pub bandwidth: String,
    pub disk_gb: String,
}

impl SiteForm {
    fn fields(&self) -> Fields {
        Fields {
            name: self.name.clone(),
            cidrs: self.cidrs.clone(),
            fallback: self.fallback.is_some(),
            bandwidth: self.bandwidth.clone(),
            disk_gb: self.disk_gb.clone(),
        }
    }

    fn to_input(&self) -> Result<SiteInput, String> {
        let bandwidth_limit_mbps = match self.bandwidth.trim() {
            "" => None,
            b => Some(
                b.parse()
                    .map_err(|_| "頻寬上限要是整數（Mbps）".to_string())?,
            ),
        };
        let disk_limit_gb = self
            .disk_gb
            .trim()
            .parse()
            .map_err(|_| "磁碟上限要是整數（GB）".to_string())?;
        Ok(SiteInput {
            name: self.name.clone(),
            cidrs: self
                .cidrs
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect(),
            fallback_to_central: self.fallback.is_some(),
            bandwidth_limit_mbps,
            disk_limit_gb,
        })
    }
}

#[derive(Template)]
#[template(path = "site_form.html")]
struct FormPage {
    nav: Nav,
    /// None：新增
    id: Option<i64>,
    f: Fields,
    error: Option<String>,
}

fn form(s: &Session, id: Option<i64>, f: Fields, error: Option<String>) -> Response {
    let page = render(&FormPage {
        nav: Nav::from(s),
        id,
        f,
        error: error.clone(),
    });
    if error.is_some() {
        (StatusCode::UNPROCESSABLE_ENTITY, page).into_response()
    } else {
        page
    }
}

pub async fn new_form(AdminSession(s): AdminSession) -> Result<Response, Response> {
    platform(&s)?;
    Ok(form(
        &s,
        None,
        Fields {
            name: String::new(),
            cidrs: String::new(),
            fallback: true,
            bandwidth: String::new(),
            disk_gb: "100".into(),
        },
        None,
    ))
}

pub async fn create(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Form(f): Form<SiteForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    let result = match f.to_input() {
        Ok(i) => sites::create_site(&st.pool, &i, &s.username)
            .await
            .map_err(|e| format!("{e:#}")),
        Err(e) => Err(e),
    };
    match result {
        Ok(_) => Ok(Redirect::to("/sites").into_response()),
        Err(e) => Ok(form(&s, None, f.fields(), Some(e))),
    }
}

/// (名稱, 網段, 改向中央, 頻寬上限, 磁碟上限)
type EditRow = (String, Vec<String>, bool, Option<i32>, i32);

pub async fn edit_form(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
) -> Result<Response, Response> {
    platform(&s)?;
    let row: Option<EditRow> = sqlx::query_as(
        "SELECT name, cidrs::text[], fallback_to_central, bandwidth_limit_mbps, disk_limit_gb \
         FROM sites WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await
    .map_err(db_error)?;
    let Some((name, cidrs, fallback, bw, disk)) = row else {
        return Err(not_found());
    };
    Ok(form(
        &s,
        Some(id),
        Fields {
            name,
            cidrs: cidrs.join("\n"),
            fallback,
            bandwidth: bw.map(|b| b.to_string()).unwrap_or_default(),
            disk_gb: disk.to_string(),
        },
        None,
    ))
}

pub async fn update(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Form(f): Form<SiteForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    let result = match f.to_input() {
        Ok(i) => sites::update_site(&st.pool, id, &i, &s.username)
            .await
            .map_err(|e| format!("{e:#}")),
        Err(e) => Err(e),
    };
    match result {
        Ok(()) => Ok(Redirect::to("/sites").into_response()),
        Err(e) if e == "據點不存在" => Err(not_found()),
        Err(e) => Ok(form(&s, Some(id), f.fields(), Some(e))),
    }
}

pub async fn delete(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    match sites::delete_site(&st.pool, id, &s.username).await {
        Ok(()) => Ok(Redirect::to("/sites").into_response()),
        Err(_) => Err(not_found()),
    }
}

/// 裝置頁：依最後回報的 IP 對應的據點與該據點的快取（名稱, 快取顯示文字）
pub async fn site_of(st: &AppState, ip: Option<&str>) -> Result<(String, String), sqlx::Error> {
    let Some(ip) = ip.filter(|i| !i.trim().is_empty()) else {
        return Ok(("—".into(), "—".into()));
    };
    let row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT s.name, c.name, c.status FROM sites s LEFT JOIN caches c ON c.site_id = s.id \
         WHERE try_inet($1) <<= ANY(s.cidrs) \
         ORDER BY (SELECT max(masklen(x)) FROM unnest(s.cidrs) x WHERE try_inet($1) <<= x) DESC, \
                  s.id \
         LIMIT 1",
    )
    .bind(ip)
    .fetch_optional(&st.pool)
    .await?;
    Ok(match row {
        None => ("—".into(), "—".into()),
        Some((site, Some(cache), Some(status))) => {
            (site, format!("{cache}（{}）", cache_status_label(&status)))
        }
        Some((site, _, _)) => (site, "無（向中央下載）".into()),
    })
}
