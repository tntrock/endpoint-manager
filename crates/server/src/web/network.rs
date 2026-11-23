//! 裝置頁的「網路」分頁：每張網卡，以及目前是否為多重連線。

use askama::Template;
use axum::response::Response;
use protocol::{NetInterface, NetworkInfo};
use uuid::Uuid;

use super::{fmt_time, render};
use crate::AppState;
use crate::error::AppError;
use crate::network::{SiteNets, dual_homed, load_sites, site_of};

pub struct AddrRow {
    pub addr: String,
    /// 位址所在的據點
    pub site: String,
}

pub struct NicRow {
    pub name: String,
    pub description: String,
    pub kind: &'static str,
    pub up: bool,
    /// 有預設閘道的實體網卡
    pub uplink: bool,
    /// 多重連線涉及的網卡
    pub involved: bool,
    pub mac: String,
    pub addresses: Vec<AddrRow>,
    pub gateways: Vec<String>,
    pub dns: Vec<String>,
    pub ssid: String,
}

pub struct PeriodRow {
    pub started: String,
    /// 空字串表示還在持續
    pub ended: String,
    pub duration: String,
    pub interfaces: String,
    pub detail: String,
    pub incomplete: bool,
}

/// 最多列出幾段多重連線紀錄
const PERIOD_LIMIT: i64 = 20;

pub use crate::network::duration_label;

type Period = (
    time::OffsetDateTime,
    Option<time::OffsetDateTime>,
    String,
    Vec<String>,
    bool,
);

async fn periods(st: &AppState, id: Uuid) -> Result<Vec<PeriodRow>, sqlx::Error> {
    let rows: Vec<Period> = sqlx::query_as(
        "SELECT started_at, ended_at, detail, interfaces, incomplete \
         FROM device_dual_homed_periods WHERE device_id = $1 \
         ORDER BY started_at DESC, id DESC LIMIT $2",
    )
    .bind(id)
    .bind(PERIOD_LIMIT)
    .fetch_all(&st.pool)
    .await?;
    let now = time::OffsetDateTime::now_utc();
    Ok(rows
        .into_iter()
        .map(|(start, end, detail, names, incomplete)| PeriodRow {
            started: fmt_time(st, Some(start)),
            ended: end.map(|e| fmt_time(st, Some(e))).unwrap_or_default(),
            duration: duration_label(end.unwrap_or(now) - start),
            interfaces: names.join("、"),
            detail,
            incomplete,
        })
        .collect())
}

#[derive(Template)]
#[template(path = "network_tab.html")]
struct NetworkTab {
    periods: Vec<PeriodRow>,
    loaded: bool,
    updated: String,
    /// 多重連線的說明；None 表示不是
    dual_homed: Option<String>,
    has_sites: bool,
    nics: Vec<NicRow>,
    /// 交換器上看到的位置
    locations: Vec<LocationRow>,
    history: Vec<LocationRow>,
    /// 平台管理員才連到網路設備頁
    links: bool,
}

pub struct LocationRow {
    pub net_device_id: Option<i64>,
    pub net_device: String,
    pub port: String,
    pub vlan: String,
    pub mac: String,
    pub since: String,
    pub until: String,
    pub last_seen: String,
    /// 只在上行埠看到（下游有未登錄的交換器或 AP）
    pub via_uplink: bool,
}

fn location_row(st: &AppState, l: crate::netdev::view::Location, via_uplink: bool) -> LocationRow {
    LocationRow {
        net_device_id: l.net_device_id,
        net_device: l.net_device,
        port: l.port,
        vlan: if l.vlan > 0 {
            l.vlan.to_string()
        } else {
            "—".into()
        },
        mac: l.mac,
        since: fmt_time(st, Some(l.since)),
        until: l.until.map(|u| fmt_time(st, Some(u))).unwrap_or_default(),
        last_seen: fmt_time(st, l.last_seen),
        via_uplink,
    }
}

async fn locations(
    st: &AppState,
    id: Uuid,
) -> Result<(Vec<LocationRow>, Vec<LocationRow>), sqlx::Error> {
    let v = crate::netdev::view::endpoint_location(&st.pool, id).await?;
    let mut current: Vec<LocationRow> = v
        .current
        .into_iter()
        .map(|l| location_row(st, l, false))
        .collect();
    current.extend(v.via_uplink.map(|l| location_row(st, l, true)));
    let history = v
        .history
        .into_iter()
        .map(|l| location_row(st, l, false))
        .collect();
    Ok((current, history))
}

pub fn kind_label(kind: &str) -> &'static str {
    match kind {
        NetInterface::ETHERNET => "有線",
        NetInterface::WIFI => "Wi-Fi",
        NetInterface::CELLULAR => "行動網路",
        NetInterface::VPN => "VPN",
        NetInterface::VIRTUAL => "虛擬",
        NetInterface::LOOPBACK => "本機迴路",
        _ => "其他",
    }
}

/// 沒有下一站的預設路由（0.0.0.0／::）是直接連線，例如 PPP 或部分 VPN
fn gateway_label(g: &str) -> String {
    if matches!(g, "0.0.0.0" | "::") {
        "直接連線".into()
    } else {
        g.to_string()
    }
}

fn row(i: NetInterface, sites: &[SiteNets], involved: &[&str]) -> NicRow {
    NicRow {
        uplink: i.is_uplink(),
        involved: involved.contains(&i.name.as_str()),
        kind: kind_label(&i.kind),
        up: i.up,
        description: i.description.unwrap_or_default(),
        mac: i.mac.unwrap_or_default(),
        addresses: i
            .addresses
            .into_iter()
            .map(|a| AddrRow {
                site: site_of(sites, &a).unwrap_or_default().to_string(),
                addr: a,
            })
            .collect(),
        gateways: i.gateways.iter().map(|g| gateway_label(g)).collect(),
        dns: i.dns,
        ssid: i.ssid.unwrap_or_default(),
        name: i.name,
    }
}

pub async fn device_tab(st: &AppState, links: bool, id: Uuid) -> Result<Response, AppError> {
    let (locations, history) = locations(st, id).await?;
    let data: Option<(serde_json::Value, time::OffsetDateTime)> =
        sqlx::query_as("SELECT data, updated_at FROM device_network WHERE device_id = $1")
            .bind(id)
            .fetch_optional(&st.pool)
            .await?;
    let Some((info, updated)) = data.and_then(|(d, t)| {
        serde_json::from_value::<NetworkInfo>(d)
            .ok()
            .map(|n| (n, t))
    }) else {
        return Ok(render(&NetworkTab {
            periods: periods(st, id).await?,
            loaded: false,
            updated: String::new(),
            dual_homed: None,
            has_sites: false,
            nics: vec![],
            locations,
            history,
            links,
        }));
    };
    let sites = load_sites(&st.pool).await?;
    let dh = dual_homed(&info.interfaces, &sites);
    let involved: Vec<&str> = dh.as_ref().map(|d| d.interfaces()).unwrap_or_default();
    let mut nics = info.interfaces;
    // 啟用中、有閘道的在前，其餘依名稱
    nics.sort_by(|a, b| {
        (!a.up, a.gateways.is_empty(), &a.name).cmp(&(!b.up, b.gateways.is_empty(), &b.name))
    });
    let rows = nics
        .into_iter()
        .map(|i| row(i, &sites, &involved))
        .collect();
    Ok(render(&NetworkTab {
        periods: periods(st, id).await?,
        loaded: true,
        updated: fmt_time(st, Some(updated)),
        dual_homed: dh.as_ref().map(|d| d.describe()),
        has_sites: !sites.is_empty(),
        nics: rows,
        locations,
        history,
        links,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels() {
        assert_eq!(kind_label("wifi"), "Wi-Fi");
        assert_eq!(kind_label("cellular"), "行動網路");
        assert_eq!(kind_label("ethernet"), "有線");
        assert_eq!(kind_label("vpn"), "VPN");
        assert_eq!(kind_label("virtual"), "虛擬");
        assert_eq!(kind_label("loopback"), "本機迴路");
        assert_eq!(kind_label("future"), "其他");
        assert_eq!(gateway_label("0.0.0.0"), "直接連線");
        assert_eq!(gateway_label("::"), "直接連線");
        assert_eq!(gateway_label("10.0.0.1"), "10.0.0.1");
        let d = time::Duration::seconds;
        assert_eq!(duration_label(d(-5)), "0 秒");
        assert_eq!(duration_label(d(42)), "42 秒");
        assert_eq!(duration_label(d(125)), "2 分鐘");
        assert_eq!(duration_label(d(3 * 3600 + 7 * 60)), "3 小時 7 分");
        assert_eq!(duration_label(d(2 * 86_400 + 5 * 3600)), "2 天 5 小時");
    }
}
