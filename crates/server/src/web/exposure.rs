//! 對外開放的服務（錯誤設定規格 §5.3）：裝置頁的卡片，與依「連接埠＋程式」彙整全部裝置的 `/exposure` 頁。

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Response;
use protocol::ExposureInfo;
use serde::Deserialize;
use uuid::Uuid;

use super::auth::{AdminSession, Nav};
use super::devices::{SelectOption, group_options};
use super::{enc, render};
use crate::AppState;
use crate::compliance::rules::SERVICE_PRESETS;
use crate::error::AppError;

/// 清單最多列幾列
const LIMIT: i64 = 500;
/// 明細最多列幾台
const DETAIL_LIMIT: i64 = 2000;

/// 內建的高風險服務名稱（沒有就是空字串）
pub fn service_of(port: u16) -> &'static str {
    SERVICE_PRESETS
        .iter()
        .find(|(_, _, ps)| ps.contains(&port))
        .map_or("", |(_, l, _)| l)
}

pub struct ListenRow {
    pub proto: String,
    pub port: u16,
    pub addr: String,
    pub process: String,
    /// 監聽在所有介面
    pub any: bool,
    /// 內建的高風險服務
    pub service: &'static str,
}

pub struct SshdRow {
    pub root: String,
    pub password: bool,
    pub empty: bool,
    pub ports: String,
}

pub struct ExposureCard {
    pub rows: Vec<ListenRow>,
    pub truncated: bool,
    pub firewall: Option<Vec<String>>,
    pub sshd: Option<SshdRow>,
    /// 遠端桌面：(開啟, 成員)
    pub rdp: Option<(bool, Vec<String>)>,
    pub errors: Vec<String>,
}

pub fn card(info: ExposureInfo) -> ExposureCard {
    let mut rows: Vec<ListenRow> = info
        .listening
        .into_iter()
        .map(|l| ListenRow {
            any: l.any_interface(),
            service: service_of(l.port),
            proto: l.proto,
            port: l.port,
            addr: l.addr,
            process: l.process.unwrap_or_default(),
        })
        .collect();
    // 高風險服務排前面，其餘依連接埠
    rows.sort_by(|a, b| {
        (a.service.is_empty(), a.port, &a.proto).cmp(&(b.service.is_empty(), b.port, &b.proto))
    });
    ExposureCard {
        rows,
        truncated: info.truncated,
        firewall: info.firewall_allow_all,
        sshd: info.sshd.map(|s| SshdRow {
            root: s.permit_root_login,
            password: s.password_authentication,
            empty: s.permit_empty_passwords,
            ports: s
                .ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join("、"),
        }),
        rdp: info
            .rdp
            .map(|r| (r.enabled, r.users.into_iter().map(|u| u.name).collect())),
        errors: info.errors,
    }
}

/// 讀取裝置的 exposure 區段；沒有資料或 jsonb 讀不回來時 None
pub async fn load(st: &AppState, id: Uuid) -> Result<Option<ExposureCard>, sqlx::Error> {
    let data: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT data FROM device_exposure WHERE device_id = $1")
            .bind(id)
            .fetch_optional(&st.pool)
            .await?;
    Ok(data
        .and_then(|d| serde_json::from_value::<ExposureInfo>(d).ok())
        .map(card))
}

/// 範圍內每個監聽一列。$1 全部裝置、$2 範圍內的群組、$3 群組篩選（NULL＝全部、-1＝未分組）
const ROWS: &str = "WITH l AS ( \
       SELECT d.id, d.hostname, x->>'proto' AS proto, (x->>'port')::int AS port, \
              coalesce(x->>'process', '') AS process, coalesce(x->>'addr', '') AS addr \
       FROM device_exposure de \
       JOIN devices d ON d.id = de.device_id AND d.status NOT IN ('retired', 'pending_approval') \
       CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(de.data->'listening') = 'array' \
                                                    THEN de.data->'listening' ELSE '[]' END) x \
       WHERE ($1::bool OR d.group_id = ANY($2::bigint[])) \
         AND ($3::bigint IS NULL OR d.group_id = $3 OR ($3 = -1 AND d.group_id IS NULL)))";

#[derive(Deserialize)]
pub struct ListQuery {
    /// 連接埠或程式名稱
    #[serde(default)]
    q: String,
    #[serde(default)]
    group: String,
    /// 只看內建的高風險服務
    #[serde(default)]
    risky: bool,
}

pub struct PortRow {
    pub proto: String,
    pub port: i32,
    pub process: String,
    pub service: &'static str,
    pub hosts: i64,
    /// 其中監聽在所有介面的主機數
    pub any_hosts: i64,
    pub url: String,
}

#[derive(Template)]
#[template(path = "exposure.html")]
struct ListPage {
    nav: Nav,
    q: String,
    risky: bool,
    groups: Vec<SelectOption>,
    rows: Vec<PortRow>,
    truncated: bool,
}

fn risky_ports() -> Vec<i32> {
    SERVICE_PRESETS
        .iter()
        .flat_map(|(_, _, ps)| ps.iter().map(|p| i32::from(*p)))
        .collect()
}

pub async fn list(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<ListQuery>,
) -> Result<Response, AppError> {
    let group: Option<i64> = if q.group == "none" {
        Some(-1)
    } else {
        q.group.parse().ok()
    };
    let text = q.q.trim();
    let port: Option<i32> = text.parse().ok();
    let mut rows: Vec<(String, i32, String, i64, i64)> =
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "{ROWS} \
         SELECT proto, port, process, count(DISTINCT id), \
                count(DISTINCT id) FILTER (WHERE addr IN ('0.0.0.0', '::')) \
         FROM l WHERE ($4 = '' OR port = $5 OR process ILIKE $6) \
           AND (NOT $7 OR port = ANY($8)) \
         GROUP BY proto, port, process ORDER BY count(DISTINCT id) DESC, port, proto LIMIT $9"
        )))
        .bind(s.all_devices())
        .bind(&s.groups)
        .bind(group)
        .bind(text)
        .bind(port)
        .bind(super::escape_like(text))
        .bind(q.risky)
        .bind(risky_ports())
        .bind(LIMIT + 1)
        .fetch_all(&st.pool)
        .await?;
    let truncated = rows.len() as i64 > LIMIT;
    rows.truncate(LIMIT as usize);
    Ok(render(&ListPage {
        nav: Nav::new(&s, "exposure"),
        groups: group_options(&st, &s, &q.group, true).await?,
        rows: rows
            .into_iter()
            .map(|(proto, port, process, hosts, any_hosts)| PortRow {
                url: format!(
                    "/exposure/port?proto={}&port={port}&process={}",
                    enc(&proto),
                    enc(&process)
                ),
                service: u16::try_from(port).map_or("", service_of),
                proto,
                port,
                process,
                hosts,
                any_hosts,
            })
            .collect(),
        q: q.q,
        risky: q.risky,
        truncated,
    }))
}

#[derive(Deserialize)]
pub struct DetailQuery {
    #[serde(default)]
    proto: String,
    #[serde(default)]
    port: i32,
    #[serde(default)]
    process: String,
}

pub struct HostRow {
    pub device: Uuid,
    pub hostname: String,
    pub addr: String,
}

#[derive(Template)]
#[template(path = "exposure_detail.html")]
struct DetailPage {
    nav: Nav,
    title: String,
    service: &'static str,
    rows: Vec<HostRow>,
    truncated: bool,
}

pub async fn detail(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<DetailQuery>,
) -> Result<Response, AppError> {
    let mut rows: Vec<(Uuid, String, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{ROWS} \
         SELECT id, hostname, string_agg(DISTINCT addr, '、' ORDER BY addr) FROM l \
         WHERE proto = $4 AND port = $5 AND process = $6 \
         GROUP BY id, hostname ORDER BY hostname LIMIT $7"
    )))
    .bind(s.all_devices())
    .bind(&s.groups)
    .bind(None::<i64>)
    .bind(&q.proto)
    .bind(q.port)
    .bind(&q.process)
    .bind(DETAIL_LIMIT + 1)
    .fetch_all(&st.pool)
    .await?;
    let truncated = rows.len() as i64 > DETAIL_LIMIT;
    rows.truncate(DETAIL_LIMIT as usize);
    let process = if q.process.is_empty() {
        "未知程式"
    } else {
        q.process.as_str()
    };
    Ok(render(&DetailPage {
        nav: Nav::new(&s, "exposure"),
        title: format!("{}/{}（{process}）", q.port, q.proto),
        service: u16::try_from(q.port).map_or("", service_of),
        rows: rows
            .into_iter()
            .map(|(device, hostname, addr)| HostRow {
                device,
                hostname,
                addr,
            })
            .collect(),
        truncated,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::{AccountInfo, ListenItem, RdpInfo, SshdInfo};

    #[test]
    fn card_rows() {
        let l = |port: u16, addr: &str, process: Option<&str>| ListenItem {
            proto: "tcp".into(),
            addr: addr.into(),
            port,
            process: process.map(Into::into),
        };
        let c = card(ExposureInfo {
            listening: vec![l(443, "0.0.0.0", Some("nginx")), l(3306, "10.0.0.5", None)],
            truncated: true,
            firewall_allow_all: Some(vec!["Open".into()]),
            sshd: Some(SshdInfo {
                permit_root_login: "yes".into(),
                password_authentication: true,
                permit_empty_passwords: false,
                ports: vec![22, 2222],
            }),
            rdp: Some(RdpInfo {
                enabled: true,
                users: vec![AccountInfo {
                    name: "CORP\\bob".into(),
                    sid: "S-1-5-21-1".into(),
                }],
            }),
            errors: vec!["e".into()],
        });
        assert_eq!(c.rows[0].port, 3306, "高風險服務排前面");
        assert_eq!((c.rows[0].service, c.rows[0].any), ("MySQL", false));
        assert_eq!(c.rows[0].process, "");
        assert!(c.rows[1].any);
        assert!(c.truncated);
        assert_eq!(c.sshd.as_ref().unwrap().ports, "22、2222");
        assert_eq!(c.rdp.as_ref().unwrap().1, ["CORP\\bob"]);
        assert_eq!(service_of(5901), "VNC");
        assert_eq!(service_of(443), "");
        assert!(risky_ports().contains(&23));
    }
}
