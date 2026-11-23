//! 未管理設備（網路上有、沒裝 Agent）與「已知」標記。只限平台管理員。

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use super::auth::{AdminSession, Nav, check_csrf, platform};
use super::commands::command_error;
use super::devices::db_error;
use super::login::CsrfForm;
use super::netdevices::SiteOption;
use super::{enc, fmt_time, render};
use crate::AppState;
use crate::netdev::view::{self, KnownMatch};

pub struct Row {
    pub mac: String,
    pub ip: String,
    pub vendor: String,
    pub random: bool,
    pub net_device_id: Option<i64>,
    pub where_: String,
    pub if_index: String,
    pub vlan: String,
    pub first_seen: String,
    pub last_seen: String,
    pub is_new: bool,
}

#[derive(Template)]
#[template(path = "unmanaged.html")]
struct Page {
    nav: Nav,
    rows: Vec<Row>,
    total: usize,
    sites: Vec<SiteOption>,
    site: Option<i64>,
    q: String,
    saved: bool,
    error: Option<String>,
}

impl Page {
    fn site_selected(&self, id: &i64) -> bool {
        self.site == Some(*id)
    }
}

#[derive(Deserialize, Default)]
pub struct ListQuery {
    #[serde(default)]
    site: Option<String>,
    #[serde(default)]
    q: String,
    #[serde(default)]
    saved: bool,
    #[serde(default)]
    error: Option<String>,
}

/// 搜尋字串比對 MAC（忽略分隔符號與大小寫）、IP、廠商
pub fn matches(u: &view::Unmanaged, q: &str) -> bool {
    let q = q.trim().to_ascii_lowercase();
    if q.is_empty() {
        return true;
    }
    let hex = |s: &str| -> String {
        s.chars()
            .filter(char::is_ascii_hexdigit)
            .collect::<String>()
            .to_ascii_lowercase()
    };
    let qh = hex(&q);
    // 有「.」就是 IP；只由十六進位字元與 : - 組成才當成 MAC 片段
    let mac_like = !q.contains('.')
        && !qh.is_empty()
        && qh.len() == q.chars().filter(|c| !":-".contains(*c)).count();
    (mac_like && hex(&u.mac).contains(&qh))
        || u.ip.as_deref().is_some_and(|ip| ip.contains(&q))
        || u.vendor
            .is_some_and(|v| v.to_ascii_lowercase().contains(&q))
}

pub async fn list(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<ListQuery>,
) -> Result<Response, Response> {
    platform(&s)?;
    let site: Option<i64> = q.site.as_deref().and_then(|v| v.parse().ok());
    let all = view::unmanaged(&st.pool, site).await.map_err(db_error)?;
    let since = time::OffsetDateTime::now_utc() - time::Duration::hours(24);
    let total = all.len();
    let rows = all
        .into_iter()
        .filter(|u| matches(u, &q.q))
        .map(|u| Row {
            where_: match (&u.net_device, &u.port) {
                (Some(d), Some(p)) => format!("{d} {p}"),
                (Some(d), None) => format!("{d}（只在 ARP 表）"),
                _ => "—".into(),
            },
            mac: u.mac,
            ip: u.ip.unwrap_or_else(|| "—".into()),
            vendor: u.vendor.unwrap_or("").to_string(),
            random: u.random,
            net_device_id: u.net_device_id,
            if_index: u.if_index.map(|i| i.to_string()).unwrap_or_default(),
            vlan: if u.vlan > 0 {
                u.vlan.to_string()
            } else {
                "—".into()
            },
            is_new: u.first_seen > since,
            first_seen: fmt_time(&st, Some(u.first_seen)),
            last_seen: fmt_time(&st, Some(u.last_seen)),
        })
        .collect();
    let sites: Vec<(i64, String)> =
        sqlx::query_as("SELECT id, name FROM sites ORDER BY lower(name), id")
            .fetch_all(&st.pool)
            .await
            .map_err(db_error)?;
    Ok(render(&Page {
        nav: Nav::new(&s, "netdevices"),
        rows,
        total,
        sites: sites
            .into_iter()
            .map(|(id, name)| SiteOption { id, name })
            .collect(),
        site,
        q: q.q,
        saved: q.saved,
        error: q.error,
    }))
}

#[derive(Deserialize, Default)]
pub struct KnownForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    mac: String,
    #[serde(default)]
    net_device_id: String,
    #[serde(default)]
    if_index: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    note: String,
}

pub async fn add_known(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Form(f): Form<KnownForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    let result = async {
        let m = KnownMatch::parse(&f.kind).ok_or_else(|| {
            anyhow::Error::from(crate::commands::CmdError::Invalid("請選擇標記範圍".into()))
        })?;
        let value = view::known_value(
            m,
            &f.mac,
            f.net_device_id.trim().parse().ok(),
            f.if_index.trim().parse().ok(),
        )?;
        view::add_known(&st.pool, m, &value, &f.note, &s.username).await
    }
    .await;
    match result {
        Ok(()) => Ok(Redirect::to("/netdevices/unmanaged?saved=true").into_response()),
        Err(e) => match super::commands::form_error(&e) {
            // 錯誤訊息帶回清單頁顯示（表單在清單的每一列上）
            Some((_, msg)) => Ok(Redirect::to(&format!(
                "/netdevices/unmanaged?error={}",
                enc(&msg)
            ))
            .into_response()),
            None => Err(command_error(e)),
        },
    }
}

pub struct KnownRow {
    pub id: i64,
    pub kind: &'static str,
    pub value: String,
    pub vendor: String,
    pub note: String,
    pub created_by: String,
    pub created_at: String,
}

#[derive(Template)]
#[template(path = "known_macs.html")]
struct KnownPage {
    nav: Nav,
    rows: Vec<KnownRow>,
}

/// 標記值的顯示：埠是「設備名稱 埠名稱」
async fn port_label(st: &AppState, value: &str) -> Result<String, sqlx::Error> {
    let Some((d, i)) = value
        .split_once(':')
        .and_then(|(d, i)| Some((d.parse::<i64>().ok()?, i.parse::<i64>().ok()?)))
    else {
        return Ok(value.to_string());
    };
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT d.name, i.name FROM net_devices d \
         LEFT JOIN net_interfaces i ON i.device_id = d.id AND i.if_index = $2 WHERE d.id = $1",
    )
    .bind(d)
    .bind(i)
    .fetch_optional(&st.pool)
    .await?;
    Ok(match row {
        Some((d, Some(p))) => format!("{d} {p}"),
        Some((d, None)) => format!("{d}（埠 {i}）"),
        None => format!("（已刪除的設備）埠 {i}"),
    })
}

pub async fn known(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
) -> Result<Response, Response> {
    platform(&s)?;
    let mut rows = vec![];
    for k in view::known(&st.pool).await.map_err(db_error)? {
        let (value, vendor) = match k.kind.as_str() {
            "port" => (
                port_label(&st, &k.value).await.map_err(db_error)?,
                String::new(),
            ),
            "oui" => (
                k.value.clone(),
                crate::netdev::oui::vendor(&k.value)
                    .unwrap_or("")
                    .to_string(),
            ),
            _ => (
                k.value.clone(),
                crate::netdev::oui::vendor(&k.value)
                    .unwrap_or("")
                    .to_string(),
            ),
        };
        rows.push(KnownRow {
            id: k.id,
            kind: KnownMatch::label(&k.kind),
            value,
            vendor,
            note: k.note,
            created_by: k.created_by,
            created_at: fmt_time(&st, Some(k.created_at)),
        });
    }
    Ok(render(&KnownPage {
        nav: Nav::new(&s, "netdevices"),
        rows,
    }))
}

pub async fn delete_known(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    view::delete_known(&st.pool, id, &s.username)
        .await
        .map_err(command_error)?;
    Ok(Redirect::to("/netdevices/known").into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(mac: &str, ip: Option<&str>, vendor: Option<&'static str>) -> view::Unmanaged {
        view::Unmanaged {
            mac: mac.into(),
            ip: ip.map(String::from),
            vendor,
            random: false,
            net_device_id: None,
            net_device: None,
            site: String::new(),
            port: None,
            if_index: None,
            vlan: 0,
            first_seen: time::OffsetDateTime::UNIX_EPOCH,
            last_seen: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn search() {
        let x = u(
            "00:1b:2c:aa:bb:cc",
            Some("10.0.0.5"),
            Some("Hewlett Packard"),
        );
        for q in ["", "AA:BB", "aabbcc", "001b2c-aabb", "10.0.0", "hewlett"] {
            assert!(matches(&x, q), "{q}");
        }
        for q in ["dd", "10.9", "cisco"] {
            assert!(!matches(&x, q), "{q}");
        }
        // 純數字也可能是 MAC 片段，但不能把 IP 的數字當 MAC 比
        assert!(!matches(&u("00:00:00:00:00:10", None, None), "10.0"));
    }
}
