//! 網路設備：清單、新增、編輯、刪除、詳情；SNMP 帳密；查詢間隔。只限平台管理員。

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use protocol::netdev::SnmpCredential;
use serde::Deserialize;

use super::auth::{AdminSession, Nav, Session, check_csrf, platform};
use super::commands::{command_error, form_error};
use super::devices::db_error;
use super::login::CsrfForm;
use super::{fmt_time, not_found, render};
use crate::AppState;
use crate::netdev::{self, CredentialInput, DeviceInput, UNREACHABLE_AFTER};
use crate::network::duration_label;
use uuid::Uuid;

/// 設備狀態：(色調, 文字)
pub fn device_state(
    enabled: bool,
    has_cache: bool,
    polled: bool,
    ever_ok: bool,
    failures: i32,
) -> (&'static str, String) {
    if !enabled {
        ("off", "已停用".into())
    } else if !has_cache {
        ("warn", "據點沒有快取".into())
    } else if !polled {
        ("off", "等待查詢".into())
    } else if failures >= UNREACHABLE_AFTER {
        (
            "bad",
            if ever_ok {
                "無法連線".into()
            } else {
                "從未成功".into()
            },
        )
    } else if failures > 0 {
        ("warn", format!("查詢失敗 {failures} 次"))
    } else {
        ("ok", "正常".into())
    }
}

pub fn speed_label(mbps: Option<i64>) -> String {
    match mbps {
        None | Some(0) => "—".into(),
        Some(m) if m >= 1000 && m % 1000 == 0 => format!("{} Gbps", m / 1000),
        Some(m) => format!("{m} Mbps"),
    }
}

fn uptime_label(secs: Option<i64>) -> String {
    secs.map(|s| duration_label(time::Duration::seconds(s)))
        .unwrap_or_else(|| "—".into())
}

pub struct DeviceRow {
    pub id: i64,
    pub name: String,
    pub site: String,
    pub address: String,
    pub model: String,
    pub firmware: String,
    pub uptime: String,
    pub tone: &'static str,
    pub state: String,
    pub last_polled: String,
    pub ports: String,
}

pub struct CredentialRow {
    pub id: i64,
    pub name: String,
    pub version: String,
    pub user: String,
    pub used: i64,
}

pub struct SiteOption {
    pub id: i64,
    pub name: String,
}

#[derive(Template)]
#[template(path = "netdevices.html")]
struct ListPage {
    nav: Nav,
    rows: Vec<DeviceRow>,
    credentials: Vec<CredentialRow>,
    sites: Vec<SiteOption>,
    site: Option<i64>,
    down_only: bool,
    secrets_ok: bool,
    system_min: u32,
    table_min: u32,
    error: Option<String>,
    saved: bool,
}

impl ListPage {
    fn site_selected(&self, id: &i64) -> bool {
        self.site == Some(*id)
    }
}

#[derive(Deserialize, Default)]
pub struct ListQuery {
    #[serde(default)]
    site: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    saved: bool,
}

type ListRow = (
    i64,
    String,
    String,
    String,
    i32,
    Option<String>,
    Option<String>,
    Option<i64>,
    bool,
    bool,
    Option<time::OffsetDateTime>,
    Option<time::OffsetDateTime>,
    i32,
    i64,
    i64,
);

async fn sites(st: &AppState) -> Result<Vec<SiteOption>, sqlx::Error> {
    let rows: Vec<(i64, String)> =
        sqlx::query_as("SELECT id, name FROM sites ORDER BY lower(name), id")
            .fetch_all(&st.pool)
            .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name)| SiteOption { id, name })
        .collect())
}

async fn credentials(st: &AppState) -> Result<Vec<CredentialRow>, sqlx::Error> {
    let rows: Vec<(i64, String, String, Option<String>, i64)> = sqlx::query_as(
        "SELECT c.id, c.name, c.version, c.username, \
                (SELECT count(*) FROM net_devices d WHERE d.credential_id = c.id) \
         FROM snmp_credentials c ORDER BY lower(c.name), c.id",
    )
    .fetch_all(&st.pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, version, user, used)| CredentialRow {
            id,
            name,
            version,
            user: user.unwrap_or_else(|| "—".into()),
            used,
        })
        .collect())
}

async fn list_page(
    st: &AppState,
    s: &Session,
    q: &ListQuery,
    error: Option<String>,
) -> Result<ListPage, sqlx::Error> {
    let site: Option<i64> = q.site.as_deref().and_then(|v| v.parse().ok());
    let down_only = q.status.as_deref() == Some("down");
    let rows: Vec<ListRow> = sqlx::query_as(
        "SELECT d.id, d.name, s.name, d.address, d.port, d.model, d.firmware, d.uptime_secs, \
                d.enabled, EXISTS (SELECT 1 FROM caches c WHERE c.site_id = d.site_id \
                                   AND c.status = 'active'), \
                d.last_polled_at, d.last_ok_at, d.consecutive_failures, \
                (SELECT count(*) FROM net_interfaces i WHERE i.device_id = d.id AND i.oper_up), \
                (SELECT count(*) FROM net_interfaces i WHERE i.device_id = d.id) \
         FROM net_devices d JOIN sites s ON s.id = d.site_id \
         WHERE ($1::bigint IS NULL OR d.site_id = $1) \
           AND (NOT $2 OR (d.enabled AND d.consecutive_failures >= $3)) \
         ORDER BY lower(s.name), lower(d.name), d.id",
    )
    .bind(site)
    .bind(down_only)
    .bind(UNREACHABLE_AFTER)
    .fetch_all(&st.pool)
    .await?;
    let rows = rows
        .into_iter()
        .map(
            |(
                id,
                name,
                site,
                address,
                port,
                model,
                firmware,
                uptime,
                enabled,
                has_cache,
                polled,
                ok,
                failures,
                up,
                total,
            )| {
                let (tone, state) =
                    device_state(enabled, has_cache, polled.is_some(), ok.is_some(), failures);
                DeviceRow {
                    id,
                    name,
                    site,
                    address: if port == 161 {
                        address
                    } else {
                        format!("{address}:{port}")
                    },
                    model: model.unwrap_or_else(|| "—".into()),
                    firmware: firmware.unwrap_or_else(|| "—".into()),
                    uptime: uptime_label(uptime),
                    tone,
                    state,
                    last_polled: fmt_time(st, polled),
                    ports: if total == 0 {
                        "—".into()
                    } else {
                        format!("{up} / {total}")
                    },
                }
            },
        )
        .collect();
    let (system, tables) = netdev::intervals(&st.pool).await?;
    Ok(ListPage {
        nav: Nav::new(s, "netdevices"),
        rows,
        credentials: credentials(st).await?,
        sites: sites(st).await?,
        site,
        down_only,
        secrets_ok: st.secrets.is_some(),
        system_min: system / 60,
        table_min: tables / 60,
        error,
        saved: q.saved,
    })
}

pub async fn list(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<ListQuery>,
) -> Result<Response, Response> {
    platform(&s)?;
    let page = list_page(&st, &s, &q, None).await.map_err(db_error)?;
    Ok(render(&page))
}

#[derive(Deserialize, Default)]
pub struct IntervalForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    system_min: String,
    #[serde(default)]
    table_min: String,
}

pub async fn save_intervals(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Form(f): Form<IntervalForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    let parse = |v: &str| v.trim().parse::<u32>().ok().map(|m| m.saturating_mul(60));
    let result = match (parse(&f.system_min), parse(&f.table_min)) {
        (Some(a), Some(b)) => netdev::save_intervals(&st.pool, a, b, &s.username).await,
        _ => Err(crate::commands::CmdError::Invalid("查詢間隔要是正整數（分鐘）".into()).into()),
    };
    match result {
        Ok(()) => Ok(Redirect::to("/netdevices?saved=true").into_response()),
        Err(e) => match form_error(&e) {
            Some((code, msg)) => {
                let page = list_page(&st, &s, &ListQuery::default(), Some(msg))
                    .await
                    .map_err(db_error)?;
                Ok((code, render(&page)).into_response())
            }
            None => Err(command_error(e)),
        },
    }
}

// ---------- 設備表單 ----------

#[derive(Deserialize, Default)]
pub struct DeviceForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub site_id: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub port: String,
    #[serde(default)]
    pub credential_id: String,
    #[serde(default)]
    pub enabled: Option<String>,
    #[serde(default)]
    pub cisco_vlan: String,
}

impl DeviceForm {
    fn input(&self) -> DeviceInput {
        DeviceInput {
            name: self.name.clone(),
            site_id: self.site_id.trim().parse().unwrap_or(0),
            address: self.address.clone(),
            port: self.port.clone(),
            credential_id: self.credential_id.trim().parse().unwrap_or(0),
            enabled: self.enabled.is_some(),
            cisco_vlan: self.cisco_vlan.clone(),
        }
    }
}

pub struct DeviceFields {
    pub name: String,
    pub site_id: i64,
    pub address: String,
    pub port: String,
    pub credential_id: i64,
    pub enabled: bool,
    pub cisco_vlan: String,
}

impl From<&DeviceInput> for DeviceFields {
    fn from(i: &DeviceInput) -> Self {
        DeviceFields {
            name: i.name.clone(),
            site_id: i.site_id,
            address: i.address.clone(),
            port: i.port.clone(),
            credential_id: i.credential_id,
            enabled: i.enabled,
            cisco_vlan: if i.cisco_vlan.is_empty() {
                "auto".into()
            } else {
                i.cisco_vlan.clone()
            },
        }
    }
}

#[derive(Template)]
#[template(path = "netdevice_form.html")]
struct DeviceFormPage {
    nav: Nav,
    id: Option<i64>,
    f: DeviceFields,
    sites: Vec<SiteOption>,
    credentials: Vec<CredentialRow>,
    error: Option<String>,
}

async fn device_form(
    st: &AppState,
    s: &Session,
    id: Option<i64>,
    f: DeviceFields,
    error: Option<(StatusCode, String)>,
) -> Result<Response, Response> {
    let page = DeviceFormPage {
        nav: Nav::new(s, "netdevices"),
        id,
        f,
        sites: sites(st).await.map_err(db_error)?,
        credentials: credentials(st).await.map_err(db_error)?,
        error: error.as_ref().map(|e| e.1.clone()),
    };
    Ok(match error {
        Some((code, _)) => (code, render(&page)).into_response(),
        None => render(&page),
    })
}

pub async fn new_device(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
) -> Result<Response, Response> {
    platform(&s)?;
    let f = DeviceFields {
        name: String::new(),
        site_id: 0,
        address: String::new(),
        port: "161".into(),
        credential_id: 0,
        enabled: true,
        cisco_vlan: "auto".into(),
    };
    device_form(&st, &s, None, f, None).await
}

pub async fn create_device(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Form(f): Form<DeviceForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    let i = f.input();
    match netdev::create_device(&st.pool, &i, &s.username).await {
        Ok(id) => Ok(Redirect::to(&format!("/netdevices/{id}")).into_response()),
        Err(e) => match form_error(&e) {
            Some(err) => device_form(&st, &s, None, (&i).into(), Some(err)).await,
            None => Err(command_error(e)),
        },
    }
}

type EditRow = (String, i64, String, i32, i64, bool, String);

pub async fn edit_device(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
) -> Result<Response, Response> {
    platform(&s)?;
    let row: Option<EditRow> = sqlx::query_as(
        "SELECT name, site_id, address, port, credential_id, enabled, cisco_vlan \
         FROM net_devices WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await
    .map_err(db_error)?;
    let Some((name, site_id, address, port, credential_id, enabled, cisco_vlan)) = row else {
        return Err(not_found());
    };
    let f = DeviceFields {
        name,
        site_id,
        address,
        port: port.to_string(),
        credential_id,
        enabled,
        cisco_vlan,
    };
    device_form(&st, &s, Some(id), f, None).await
}

pub async fn update_device(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Form(f): Form<DeviceForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    let i = f.input();
    match netdev::update_device(&st.pool, id, &i, &s.username).await {
        Ok(()) => Ok(Redirect::to(&format!("/netdevices/{id}")).into_response()),
        Err(e) => match form_error(&e) {
            Some((StatusCode::NOT_FOUND, _)) => Err(not_found()),
            Some(err) => device_form(&st, &s, Some(id), (&i).into(), Some(err)).await,
            None => Err(command_error(e)),
        },
    }
}

pub async fn delete_device(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    netdev::delete_device(&st.pool, id, &s.username)
        .await
        .map_err(command_error)?;
    Ok(Redirect::to("/netdevices").into_response())
}

pub async fn poll_device(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    netdev::request_poll(&st.pool, id)
        .await
        .map_err(command_error)?;
    Ok(Redirect::to(&format!("/netdevices/{id}?polling=true")).into_response())
}

// ---------- 設備詳情 ----------

pub struct PortRow {
    pub if_index: i64,
    pub name: String,
    pub alias: String,
    pub tone: &'static str,
    pub state: &'static str,
    pub speed: String,
    pub vlan: String,
    pub uplink: bool,
    /// "auto" | "edge" | "uplink"（表單的選項）
    pub role: &'static str,
    /// 為什麼是上行埠
    pub uplink_why: &'static str,
    pub neighbor: String,
    pub endpoints: Vec<(Uuid, String)>,
    pub mac_count: i32,
    pub last_change: String,
}

/// (表單的角色, 是否上行, 原因)
pub fn port_role(role: &str, mac_count: i32, uplink: bool) -> (&'static str, &'static str) {
    let form = match role {
        "edge" => "edge",
        "uplink" => "uplink",
        _ => "auto",
    };
    let why = match (uplink, role) {
        (false, _) => "",
        (true, "uplink") => "管理員指定",
        (true, "auto_uplink") => "依 LLDP 鄰居判斷",
        (true, _) if mac_count >= 10 => "同時有 10 個以上 MAC",
        (true, _) => "上行",
    };
    (form, why)
}

#[derive(Template)]
#[template(path = "netdevice.html")]
struct DetailPage {
    nav: Nav,
    id: i64,
    name: String,
    site: String,
    address: String,
    credential: String,
    tone: &'static str,
    state: String,
    info: Vec<(&'static str, String)>,
    last_error: Option<String>,
    ports: Vec<PortRow>,
    polling: bool,
    role_saved: bool,
}

#[derive(Deserialize, Default)]
pub struct DetailQuery {
    #[serde(default)]
    polling: bool,
    #[serde(default)]
    role_saved: bool,
}

/// 介面狀態：(色調, 文字)
pub fn port_state(admin_up: bool, oper_up: bool) -> (&'static str, &'static str) {
    match (admin_up, oper_up) {
        (false, _) => ("off", "停用"),
        (true, true) => ("ok", "連線"),
        (true, false) => ("off", "未連線"),
    }
}

/// LLDP 鄰居的顯示文字：「名稱 埠」，多個用「、」隔開
pub fn neighbor_label(lldp: &serde_json::Value) -> String {
    lldp.as_array()
        .map(|a| {
            a.iter()
                .map(|n| {
                    let s = |k: &str| n[k].as_str().unwrap_or("").to_string();
                    let name = [s("sys_name"), s("chassis_id")]
                        .into_iter()
                        .find(|v| !v.is_empty())
                        .unwrap_or_default();
                    let port = [s("port_descr"), s("port_id")]
                        .into_iter()
                        .find(|v| !v.is_empty())
                        .unwrap_or_default();
                    format!("{name} {port}").trim().to_string()
                })
                .filter(|v| !v.is_empty())
                .collect::<Vec<_>>()
                .join("、")
        })
        .unwrap_or_default()
}

#[derive(sqlx::FromRow)]
struct DetailRow {
    name: String,
    site: String,
    address: String,
    port: i32,
    cred: String,
    version: String,
    enabled: bool,
    has_cache: bool,
    polled: Option<time::OffsetDateTime>,
    ok: Option<time::OffsetDateTime>,
    failures: i32,
    last_error: Option<String>,
    sys_name: Option<String>,
    sys_descr: Option<String>,
    location: Option<String>,
    contact: Option<String>,
    object_id: Option<String>,
    uptime: Option<i64>,
    model: Option<String>,
    serial: Option<String>,
    firmware: Option<String>,
}

#[derive(sqlx::FromRow)]
struct PortDbRow {
    if_index: i64,
    name: String,
    alias: String,
    admin_up: bool,
    oper_up: bool,
    speed_mbps: Option<i64>,
    pvid: Option<i32>,
    role: String,
    mac_count: i32,
    uplink: bool,
    lldp: serde_json::Value,
    last_change_at: Option<time::OffsetDateTime>,
}

pub async fn detail(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Query(q): Query<DetailQuery>,
) -> Result<Response, Response> {
    platform(&s)?;
    let row: Option<DetailRow> = sqlx::query_as(
        "SELECT d.name, s.name AS site, d.address, d.port, c.name AS cred, c.version, \
                d.enabled, EXISTS (SELECT 1 FROM caches k WHERE k.site_id = d.site_id \
                                   AND k.status = 'active') AS has_cache, \
                d.last_polled_at AS polled, d.last_ok_at AS ok, \
                d.consecutive_failures AS failures, d.last_error, d.sys_name, d.sys_descr, \
                d.sys_location AS location, d.sys_contact AS contact, \
                d.sys_object_id AS object_id, d.uptime_secs AS uptime, \
                d.model, d.serial, d.firmware \
         FROM net_devices d JOIN sites s ON s.id = d.site_id \
         JOIN snmp_credentials c ON c.id = d.credential_id WHERE d.id = $1",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await
    .map_err(db_error)?;
    let Some(DetailRow {
        name,
        site,
        address,
        port,
        cred,
        version,
        enabled,
        has_cache,
        polled,
        ok,
        failures,
        last_error,
        sys_name,
        sys_descr,
        location,
        contact,
        object_id,
        uptime,
        model,
        serial,
        firmware,
    }) = row
    else {
        return Err(not_found());
    };
    let (tone, state) = device_state(enabled, has_cache, polled.is_some(), ok.is_some(), failures);
    let dash = |v: Option<String>| v.unwrap_or_else(|| "—".into());
    let info = vec![
        ("型號", dash(model)),
        ("序號", dash(serial)),
        ("韌體版本", dash(firmware)),
        ("系統名稱", dash(sys_name)),
        ("位置", dash(location)),
        ("聯絡人", dash(contact)),
        ("開機時間", uptime_label(uptime)),
        ("最後查詢", fmt_time(&st, polled)),
        ("最後成功", fmt_time(&st, ok)),
        ("sysObjectID", dash(object_id)),
        ("系統描述", dash(sys_descr)),
    ];
    let ports: Vec<PortDbRow> = sqlx::query_as(
        "SELECT if_index, name, alias, admin_up, oper_up, speed_mbps, pvid, role, mac_count, \
                net_port_is_uplink(role, mac_count) AS uplink, lldp, last_change_at \
         FROM net_interfaces WHERE device_id = $1 ORDER BY if_index",
    )
    .bind(id)
    .fetch_all(&st.pool)
    .await
    .map_err(db_error)?;
    let mut endpoints = netdev::view::port_endpoints(&st.pool, id)
        .await
        .map_err(db_error)?;
    let ports = ports
        .into_iter()
        .map(|p| {
            let (tone, state) = port_state(p.admin_up, p.oper_up);
            let (role, uplink_why) = port_role(&p.role, p.mac_count, p.uplink);
            PortRow {
                if_index: p.if_index,
                name: p.name,
                alias: p.alias,
                tone,
                state,
                speed: speed_label(p.speed_mbps),
                vlan: p.pvid.map(|v| v.to_string()).unwrap_or_else(|| "—".into()),
                uplink: p.uplink,
                role,
                uplink_why,
                neighbor: neighbor_label(&p.lldp),
                endpoints: endpoints.remove(&p.if_index).unwrap_or_default(),
                mac_count: p.mac_count,
                last_change: fmt_time(&st, p.last_change_at),
            }
        })
        .collect();
    Ok(render(&DetailPage {
        nav: Nav::new(&s, "netdevices"),
        id,
        name,
        site,
        address: if port == 161 {
            address
        } else {
            format!("{address}:{port}")
        },
        credential: format!("{cred}（{version}）"),
        tone,
        state,
        info,
        last_error,
        ports,
        polling: q.polling,
        role_saved: q.role_saved,
    }))
}

#[derive(Deserialize, Default)]
pub struct RoleForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    role: String,
}

pub async fn set_port_role(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path((id, if_index)): Path<(i64, i64)>,
    Form(f): Form<RoleForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    netdev::view::set_port_role(&st.pool, id, if_index, &f.role, &s.username)
        .await
        .map_err(command_error)?;
    Ok(Redirect::to(&format!("/netdevices/{id}?role_saved=true#port-{if_index}")).into_response())
}

// ---------- SNMP 帳密 ----------

#[derive(Deserialize, Default)]
pub struct CredentialForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub community: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub auth: String,
    #[serde(default)]
    pub auth_pass: String,
    #[serde(default)]
    pub privacy: String,
    #[serde(default)]
    pub priv_pass: String,
}

impl CredentialForm {
    fn input(&self) -> CredentialInput {
        CredentialInput {
            name: self.name.clone(),
            version: self.version.clone(),
            community: self.community.clone(),
            user: self.user.clone(),
            auth: self.auth.clone(),
            auth_pass: self.auth_pass.clone(),
            privacy: self.privacy.clone(),
            priv_pass: self.priv_pass.clone(),
        }
    }
}

/// 表單重新顯示用：機密欄位一律不回填
pub struct CredentialFields {
    pub name: String,
    pub version: String,
    pub user: String,
    pub auth: String,
    pub privacy: String,
}

impl From<&CredentialForm> for CredentialFields {
    fn from(f: &CredentialForm) -> Self {
        CredentialFields {
            name: f.name.clone(),
            version: f.version.clone(),
            user: f.user.clone(),
            auth: f.auth.clone(),
            privacy: f.privacy.clone(),
        }
    }
}

#[derive(Template)]
#[template(path = "snmp_credential_form.html")]
struct CredentialFormPage {
    nav: Nav,
    id: Option<i64>,
    f: CredentialFields,
    secrets_ok: bool,
    error: Option<String>,
}

fn credential_form(
    st: &AppState,
    s: &Session,
    id: Option<i64>,
    f: CredentialFields,
    error: Option<(StatusCode, String)>,
) -> Response {
    let page = CredentialFormPage {
        nav: Nav::new(s, "netdevices"),
        id,
        f,
        secrets_ok: st.secrets.is_some(),
        error: error.as_ref().map(|e| e.1.clone()),
    };
    match error {
        Some((code, _)) => (code, render(&page)).into_response(),
        None => render(&page),
    }
}

pub async fn new_credential(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
) -> Result<Response, Response> {
    platform(&s)?;
    Ok(credential_form(
        &st,
        &s,
        None,
        CredentialFields {
            name: String::new(),
            version: "v3".into(),
            user: String::new(),
            auth: "sha256".into(),
            privacy: "aes128".into(),
        },
        None,
    ))
}

pub async fn create_credential(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Form(f): Form<CredentialForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    match netdev::create_credential(&st.pool, st.secrets.as_deref(), &f.input(), &s.username).await
    {
        Ok(_) => Ok(Redirect::to("/netdevices#credentials").into_response()),
        Err(e) => match form_error(&e) {
            Some(err) => Ok(credential_form(&st, &s, None, (&f).into(), Some(err))),
            None => Err(command_error(e)),
        },
    }
}

pub async fn edit_credential(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
) -> Result<Response, Response> {
    platform(&s)?;
    let row: Option<(String, String, Option<Vec<u8>>)> =
        sqlx::query_as("SELECT name, version, secret_enc FROM snmp_credentials WHERE id = $1")
            .bind(id)
            .fetch_optional(&st.pool)
            .await
            .map_err(db_error)?;
    let Some((name, version, sealed)) = row else {
        return Err(not_found());
    };
    // 演算法與使用者名稱不是機密，解得開就回填；密碼一律不顯示
    let old = st
        .secrets
        .as_deref()
        .zip(sealed)
        .and_then(|(k, sealed)| netdev::open(k, &sealed).ok());
    let (user, auth, privacy) = match old {
        Some(SnmpCredential::V3 {
            user,
            auth,
            privacy,
            ..
        }) => (
            user,
            serde_json::to_value(auth)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
            serde_json::to_value(privacy)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
        ),
        _ => (String::new(), "sha256".into(), "aes128".into()),
    };
    Ok(credential_form(
        &st,
        &s,
        Some(id),
        CredentialFields {
            name,
            version,
            user,
            auth,
            privacy,
        },
        None,
    ))
}

pub async fn update_credential(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Form(f): Form<CredentialForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    match netdev::update_credential(&st.pool, st.secrets.as_deref(), id, &f.input(), &s.username)
        .await
    {
        Ok(()) => Ok(Redirect::to("/netdevices#credentials").into_response()),
        Err(e) => match form_error(&e) {
            Some((StatusCode::NOT_FOUND, _)) => Err(not_found()),
            Some(err) => Ok(credential_form(&st, &s, Some(id), (&f).into(), Some(err))),
            None => Err(command_error(e)),
        },
    }
}

pub async fn delete_credential(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    netdev::delete_credential(&st.pool, id, &s.username)
        .await
        .map_err(command_error)?;
    Ok(Redirect::to("/netdevices#credentials").into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states() {
        assert_eq!(device_state(false, true, true, true, 0).1, "已停用");
        assert_eq!(device_state(true, false, true, true, 0).1, "據點沒有快取");
        assert_eq!(device_state(true, true, false, false, 0).1, "等待查詢");
        assert_eq!(
            device_state(true, true, true, true, 0),
            ("ok", "正常".into())
        );
        assert_eq!(
            device_state(true, true, true, true, 2),
            ("warn", "查詢失敗 2 次".into())
        );
        assert_eq!(
            device_state(true, true, true, true, 3),
            ("bad", "無法連線".into())
        );
        assert_eq!(
            device_state(true, true, true, false, 5),
            ("bad", "從未成功".into())
        );
    }

    #[test]
    fn roles() {
        assert_eq!(port_role("auto_edge", 3, false), ("auto", ""));
        assert_eq!(
            port_role("auto_edge", 12, true),
            ("auto", "同時有 10 個以上 MAC")
        );
        assert_eq!(
            port_role("auto_uplink", 0, true),
            ("auto", "依 LLDP 鄰居判斷")
        );
        assert_eq!(port_role("uplink", 0, true), ("uplink", "管理員指定"));
        assert_eq!(port_role("edge", 50, false), ("edge", ""));
        assert_eq!(port_role("edge", 0, true), ("edge", "上行"));
    }

    #[test]
    fn labels() {
        assert_eq!(speed_label(None), "—");
        assert_eq!(speed_label(Some(0)), "—");
        assert_eq!(speed_label(Some(100)), "100 Mbps");
        assert_eq!(speed_label(Some(10_000)), "10 Gbps");
        assert_eq!(speed_label(Some(2500)), "2500 Mbps");
        assert_eq!(uptime_label(None), "—");
        assert_eq!(uptime_label(Some(90_000)), "1 天 1 小時");
        assert_eq!(port_state(false, true), ("off", "停用"));
        assert_eq!(port_state(true, true), ("ok", "連線"));
        assert_eq!(port_state(true, false), ("off", "未連線"));
        let l = serde_json::json!([
            {"sys_name": "core-sw", "port_id": "Gi1/0/48", "port_descr": "", "chassis_id": "x"},
            {"sys_name": "", "port_id": "p2", "port_descr": "uplink", "chassis_id": "aa:bb"},
            {"sys_name": "", "port_id": "", "port_descr": "", "chassis_id": ""}
        ]);
        assert_eq!(neighbor_label(&l), "core-sw Gi1/0/48、aa:bb uplink");
        assert_eq!(neighbor_label(&serde_json::json!(null)), "");
    }
}
