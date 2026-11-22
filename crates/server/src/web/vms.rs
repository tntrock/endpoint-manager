//! 虛擬機（容器規格 §5.5）：主機的「虛擬機」分頁、`/vms` 清單、客體裝置頁的「執行於」。
//!
//! 虛擬機與已註冊裝置的配對：`vm_guests` 存 BIOS UUID 的兩種寫法，
//! 與 `devices.smbios_uuid`（不分大小寫）比對。

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Response;
use protocol::VmsInfo;
use serde::Deserialize;
use uuid::Uuid;

use super::auth::{AdminSession, Nav, Session};
use super::devices::{SelectOption, group_options};
use super::{escape_like, render};
use crate::AppState;
use crate::error::AppError;

/// 清單最多列幾台
const LIMIT: i64 = 1000;

/// 對到的裝置：未除役、不是主機自己；多台時取最近回報的
pub const MATCH: &str = "LEFT JOIN LATERAL ( \
       SELECT x.id, x.hostname, x.group_id FROM devices x \
       WHERE x.status <> 'retired' AND x.id <> g.host_id AND x.smbios_uuid IS NOT NULL \
         AND lower(x.smbios_uuid) IN (g.bios_uuid, g.bios_uuid_swapped) \
       ORDER BY x.last_seen_at DESC NULLS LAST LIMIT 1) m ON g.bios_uuid IS NOT NULL";

pub fn platform_label(p: &str) -> &'static str {
    match p {
        "hyperv" => "Hyper-V",
        "libvirt" => "KVM／libvirt",
        "proxmox" => "Proxmox VE",
        "proxmox-lxc" => "Proxmox LXC",
        _ => "其他",
    }
}

pub fn state_label(s: &str) -> (&'static str, &'static str) {
    match s {
        "running" => ("執行中", "ok"),
        "stopped" => ("已關機", ""),
        "paused" => ("已暫停", "warn"),
        "saved" => ("已儲存狀態", ""),
        _ => ("其他", ""),
    }
}

/// 配對結果欄位
pub struct Guest {
    /// 對到且在管理範圍內：裝置頁連結
    pub href: String,
    pub label: String,
    pub tone: &'static str,
}

fn guest(
    s: &Session,
    platform: &str,
    has_uuid: bool,
    matched: Option<(Uuid, String, Option<i64>)>,
) -> Guest {
    match matched {
        Some((id, host, g)) if s.in_scope(g) => Guest {
            href: format!("/devices/{id}"),
            label: host,
            tone: "",
        },
        Some(_) => Guest {
            href: String::new(),
            label: "已安裝 Agent（不在管理範圍）".into(),
            tone: "",
        },
        // Proxmox 的 LXC 容器沒有 SMBIOS，無從配對
        None if !has_uuid || platform == "proxmox-lxc" => Guest {
            href: String::new(),
            label: "無法配對".into(),
            tone: "",
        },
        None => Guest {
            href: String::new(),
            label: "未安裝 Agent".into(),
            tone: "warn",
        },
    }
}

pub struct PlatformRow {
    pub kind: &'static str,
    pub version: String,
    pub error: String,
}

pub struct VmRow {
    pub name: String,
    pub platform: &'static str,
    pub state: &'static str,
    pub state_tone: &'static str,
    pub vcpus: String,
    pub memory: String,
    pub os: String,
    pub guest: Guest,
}

#[derive(Template)]
#[template(path = "vms_tab.html")]
struct VmsTab {
    loaded: bool,
    platforms: Vec<PlatformRow>,
    vms: Vec<VmRow>,
    truncated: bool,
}

/// 這台有偵測到虛擬化平台（才顯示「虛擬機」分頁）
pub async fn has_platforms(st: &AppState, id: Uuid) -> Result<bool, sqlx::Error> {
    let n: Option<i32> = sqlx::query_scalar(
        "SELECT jsonb_array_length(data->'platforms') FROM device_vms \
         WHERE device_id = $1 AND jsonb_typeof(data->'platforms') = 'array'",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await?;
    Ok(n.unwrap_or(0) > 0)
}

fn memory_label(mb: Option<u64>) -> String {
    match mb {
        Some(mb) if mb >= 1024 => format!("{:.1} GB", mb as f64 / 1024.0),
        Some(mb) => format!("{mb} MB"),
        None => String::new(),
    }
}

type MatchRow = (String, String, Option<Uuid>, Option<String>, Option<i64>);

pub async fn device_tab(st: &AppState, s: &Session, id: Uuid) -> Result<Response, AppError> {
    let data: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT data FROM device_vms WHERE device_id = $1")
            .bind(id)
            .fetch_optional(&st.pool)
            .await?;
    let Some(info) = data.and_then(|d| serde_json::from_value::<VmsInfo>(d).ok()) else {
        return Ok(render(&VmsTab {
            loaded: false,
            platforms: vec![],
            vms: vec![],
            truncated: false,
        }));
    };
    let matches: Vec<MatchRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT g.platform, g.vm_id, m.id, m.hostname, m.group_id FROM vm_guests g {MATCH} \
         WHERE g.host_id = $1"
    )))
    .bind(id)
    .fetch_all(&st.pool)
    .await?;
    let found = |platform: &str, vm: &str| {
        matches
            .iter()
            .find(|m| m.0 == platform && m.1 == vm)
            .and_then(|m| Some((m.2?, m.3.clone()?, m.4)))
    };
    let vms = info
        .vms
        .iter()
        .map(|v| {
            let (state, state_tone) = state_label(&v.state);
            VmRow {
                name: v.name.clone(),
                platform: platform_label(&v.platform),
                state,
                state_tone,
                vcpus: v.vcpus.map(|n| n.to_string()).unwrap_or_default(),
                memory: memory_label(v.memory_mb),
                os: v.os_hint.clone().unwrap_or_default(),
                guest: guest(
                    s,
                    &v.platform,
                    v.bios_uuid.is_some(),
                    found(&v.platform, &v.id),
                ),
            }
        })
        .collect();
    Ok(render(&VmsTab {
        loaded: true,
        platforms: info
            .platforms
            .into_iter()
            .map(|p| PlatformRow {
                kind: platform_label(&p.kind),
                version: p.version.unwrap_or_default(),
                error: p.error.unwrap_or_default(),
            })
            .collect(),
        vms,
        truncated: info.truncated,
    }))
}

/// 客體裝置頁的「執行於」：(主機連結（範圍外為空）、主機名稱、虛擬機名稱)
pub async fn host_of(
    st: &AppState,
    s: &Session,
    id: Uuid,
) -> Result<Option<(String, String, String)>, sqlx::Error> {
    let row: Option<(Uuid, String, Option<i64>, String)> = sqlx::query_as(
        "SELECT h.id, h.hostname, h.group_id, g.name FROM devices d \
         JOIN vm_guests g ON lower(d.smbios_uuid) IN (g.bios_uuid, g.bios_uuid_swapped) \
         JOIN devices h ON h.id = g.host_id AND h.status <> 'retired' \
         WHERE d.id = $1 AND g.host_id <> d.id \
         ORDER BY g.state = 'running' DESC, h.last_seen_at DESC NULLS LAST LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await?;
    Ok(row.map(|(host, name, group, vm)| {
        let href = if s.in_scope(group) {
            format!("/devices/{host}")
        } else {
            String::new()
        };
        (href, name, vm)
    }))
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    q: String,
    #[serde(default)]
    group: String,
    /// 只看執行中、沒有對到裝置的虛擬機
    #[serde(default)]
    unmanaged: bool,
}

pub struct ListRow {
    pub name: String,
    pub host: String,
    pub host_href: String,
    pub platform: &'static str,
    pub state: &'static str,
    pub state_tone: &'static str,
    pub guest: Guest,
}

#[derive(Template)]
#[template(path = "vms.html")]
struct VmsPage {
    nav: Nav,
    q: String,
    unmanaged: bool,
    groups: Vec<SelectOption>,
    rows: Vec<ListRow>,
    truncated: bool,
}

type ListDbRow = (
    String,
    String,
    String,
    bool,
    Uuid,
    String,
    Option<Uuid>,
    Option<String>,
    Option<i64>,
);

/// 執行中、有 BIOS UUID、卻沒有對到任何裝置的虛擬機（總覽「需要處理」用）。
/// `scoped` 是主機的範圍條件（別名 d）。
pub fn unmanaged_sql(scoped: &str) -> String {
    format!(
        "SELECT count(*) FROM vm_guests g JOIN devices d ON d.id = g.host_id {MATCH} \
         WHERE g.state = 'running' AND g.bios_uuid IS NOT NULL AND m.id IS NULL AND {scoped}"
    )
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
    let name = q.q.trim().to_string();
    let mut rows: Vec<ListDbRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT g.name, g.platform, g.state, g.bios_uuid IS NOT NULL, d.id, d.hostname, \
                m.id, m.hostname, m.group_id \
         FROM vm_guests g \
         JOIN devices d ON d.id = g.host_id AND d.status NOT IN ('retired', 'pending_approval') \
         {MATCH} \
         WHERE ($1::bool OR d.group_id = ANY($2::bigint[])) \
           AND ($3::bigint IS NULL OR d.group_id = $3 OR ($3 = -1 AND d.group_id IS NULL)) \
           AND ($4 = '' OR g.name ILIKE $5 OR d.hostname ILIKE $5) \
           AND (NOT $6 OR (g.state = 'running' AND g.bios_uuid IS NOT NULL AND m.id IS NULL)) \
         ORDER BY g.state = 'running' DESC, lower(g.name), d.hostname LIMIT $7"
    )))
    .bind(s.all_devices())
    .bind(&s.groups)
    .bind(group)
    .bind(&name)
    .bind(format!("%{}%", escape_like(&name)))
    .bind(q.unmanaged)
    .bind(LIMIT + 1)
    .fetch_all(&st.pool)
    .await?;
    let truncated = rows.len() as i64 > LIMIT;
    rows.truncate(LIMIT as usize);
    let rows = rows
        .into_iter()
        .map(
            |(name, platform, state, has_uuid, host, hostname, mid, mhost, mgroup)| {
                let (state, state_tone) = state_label(&state);
                ListRow {
                    name,
                    host: hostname,
                    host_href: format!("/devices/{host}"),
                    platform: platform_label(&platform),
                    state,
                    state_tone,
                    guest: guest(
                        &s,
                        &platform,
                        has_uuid,
                        mid.zip(mhost).map(|(i, h)| (i, h, mgroup)),
                    ),
                }
            },
        )
        .collect();
    Ok(render(&VmsPage {
        nav: Nav::new(&s, "vms"),
        groups: group_options(&st, &s, &q.group, true).await?,
        q: name,
        unmanaged: q.unmanaged,
        rows,
        truncated,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels() {
        for (k, want) in [
            ("hyperv", "Hyper-V"),
            ("libvirt", "KVM／libvirt"),
            ("proxmox", "Proxmox VE"),
            ("proxmox-lxc", "Proxmox LXC"),
            ("x", "其他"),
        ] {
            assert_eq!(platform_label(k), want);
        }
        for (k, want) in [
            ("running", "執行中"),
            ("stopped", "已關機"),
            ("paused", "已暫停"),
            ("saved", "已儲存狀態"),
            ("x", "其他"),
        ] {
            assert_eq!(state_label(k).0, want);
        }
        assert_eq!(memory_label(Some(2048)), "2.0 GB");
        assert_eq!(memory_label(Some(512)), "512 MB");
        assert_eq!(memory_label(None), "");
    }
}
