//! Agent 上傳的事件（網路規格 §4.4、§5.2）：存下、重播網卡狀態、維護多重連線期間。

use std::collections::BTreeMap;

use protocol::{AgentEvent, NetInterface, NetworkInfo};
use sqlx::PgConnection;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::network::{DualHomed, SiteNets, dual_homed};

/// 端點時間比收到時間晚超過這麼多，就改用收到時間
pub const MAX_CLOCK_AHEAD: Duration = Duration::minutes(5);

/// 事件的有效時間：端點時鐘跑太快時以收到時間為準
pub fn effective_at(at: OffsetDateTime, received: OffsetDateTime) -> OffsetDateTime {
    if at - received > MAX_CLOCK_AHEAD {
        received
    } else {
        at
    }
}

/// 依名稱的網卡狀態
pub type NetState = BTreeMap<String, NetInterface>;

/// 套用一筆事件到網卡狀態；回傳狀態是否可能改變
pub fn apply(state: &mut NetState, kind: &str, data: &serde_json::Value) -> bool {
    match kind {
        AgentEvent::NET_SNAPSHOT => {
            let Ok(n) = serde_json::from_value::<NetworkInfo>(data.clone()) else {
                return false;
            };
            *state = n
                .interfaces
                .into_iter()
                .map(|i| (i.name.clone(), i))
                .collect();
            true
        }
        AgentEvent::NET_UP | AgentEvent::NET_CHANGED => {
            let Ok(i) = serde_json::from_value::<NetInterface>(data.clone()) else {
                return false;
            };
            state.insert(i.name.clone(), i);
            true
        }
        AgentEvent::NET_DOWN => match data.get("name").and_then(|n| n.as_str()) {
            Some(name) => state.remove(name).is_some(),
            None => false,
        },
        _ => false,
    }
}

/// 目前狀態是否為多重連線
pub fn evaluate(state: &NetState, sites: &[SiteNets]) -> Option<DualHomed> {
    let nics: Vec<NetInterface> = state.values().cloned().collect();
    dual_homed(&nics, sites)
}

/// 一筆要存的事件
pub struct Incoming<'a> {
    pub seq: i64,
    pub at: OffsetDateTime,
    pub event: &'a AgentEvent,
}

/// 存下事件、重播並更新多重連線期間。回傳要確認給 Agent 的最大序號。
/// 呼叫端負責交易與筆數上限。
pub async fn ingest(
    conn: &mut PgConnection,
    device_id: Uuid,
    journal_id: Uuid,
    events: &[AgentEvent],
    received: OffsetDateTime,
    sites: &[SiteNets],
) -> Result<Option<u64>, sqlx::Error> {
    let mut list: Vec<Incoming> = events
        .iter()
        // 序號超過 i64 存不進資料庫：當成不合法的事件略過（仍確認，Agent 才不會一直重送）
        .filter_map(|e| {
            Some(Incoming {
                seq: i64::try_from(e.seq).ok()?,
                at: effective_at(e.at, received),
                event: e,
            })
        })
        .collect();
    list.sort_by_key(|e| e.seq);
    let ack = events.iter().map(|e| e.seq).max();
    if list.is_empty() {
        return Ok(ack);
    }
    let seqs: Vec<i64> = list.iter().map(|e| e.seq).collect();
    let ats: Vec<OffsetDateTime> = list.iter().map(|e| e.at).collect();
    let kinds: Vec<&str> = list.iter().map(|e| e.event.kind.as_str()).collect();
    let data: Vec<String> = list.iter().map(|e| e.event.data.to_string()).collect();
    // 重送的（已存過的序號）不回傳，也不再重播
    let inserted: Vec<i64> = sqlx::query_scalar(
        "INSERT INTO device_events (device_id, journal_id, seq, at, received_at, kind, data) \
         SELECT $1, $2, v.seq, v.at, $3, v.kind, v.data::jsonb \
         FROM UNNEST($4::bigint[], $5::timestamptz[], $6::text[], $7::text[]) \
              AS v(seq, at, kind, data) \
         ON CONFLICT DO NOTHING RETURNING seq",
    )
    .bind(device_id)
    .bind(journal_id)
    .bind(received)
    .bind(&seqs)
    .bind(&ats)
    .bind(&kinds)
    .bind(&data)
    .fetch_all(&mut *conn)
    .await?;
    if inserted.is_empty() {
        return Ok(ack);
    }

    sqlx::query("INSERT INTO device_net_state (device_id) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(device_id)
        .execute(&mut *conn)
        .await?;
    let (raw, mut gap): (serde_json::Value, bool) = sqlx::query_as(
        "SELECT interfaces, gap FROM device_net_state WHERE device_id = $1 FOR UPDATE",
    )
    .bind(device_id)
    .fetch_one(&mut *conn)
    .await?;
    let mut state: NetState = serde_json::from_value::<Vec<NetInterface>>(raw)
        .unwrap_or_default()
        .into_iter()
        .map(|i| (i.name.clone(), i))
        .collect();
    let mut open: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM device_dual_homed_periods WHERE device_id = $1 AND ended_at IS NULL",
    )
    .bind(device_id)
    .fetch_optional(&mut *conn)
    .await?;

    for e in list.iter().filter(|e| inserted.contains(&e.seq)) {
        if e.event.kind == AgentEvent::JOURNAL_DROPPED {
            gap = true;
            if let Some(id) = open {
                sqlx::query("UPDATE device_dual_homed_periods SET incomplete = true WHERE id = $1")
                    .bind(id)
                    .execute(&mut *conn)
                    .await?;
            }
            continue;
        }
        if !apply(&mut state, &e.event.kind, &e.event.data) {
            continue;
        }
        match (evaluate(&state, sites), open) {
            (Some(dh), None) => {
                let names: Vec<String> = dh.interfaces().iter().map(|s| s.to_string()).collect();
                open = Some(
                    sqlx::query_scalar(
                        "INSERT INTO device_dual_homed_periods \
                             (device_id, started_at, detail, interfaces, incomplete) \
                         VALUES ($1, $2, $3, $4, $5) RETURNING id",
                    )
                    .bind(device_id)
                    .bind(e.at)
                    .bind(dh.describe())
                    .bind(&names)
                    .bind(gap)
                    .fetch_one(&mut *conn)
                    .await?,
                );
                gap = false;
            }
            (None, Some(id)) => {
                // 結束時間不早於開始時間（端點時鐘可能被往回調）
                sqlx::query(
                    "UPDATE device_dual_homed_periods \
                     SET ended_at = greatest($2, started_at), incomplete = incomplete OR $3 \
                     WHERE id = $1",
                )
                .bind(id)
                .bind(e.at)
                .bind(gap)
                .execute(&mut *conn)
                .await?;
                open = None;
                gap = false;
            }
            _ => {}
        }
    }

    let interfaces: Vec<&NetInterface> = state.values().collect();
    sqlx::query(
        "UPDATE device_net_state SET interfaces = $2::jsonb, gap = $3 WHERE device_id = $1",
    )
    .bind(device_id)
    .bind(serde_json::to_string(&interfaces).expect("serializable"))
    .bind(gap)
    .execute(&mut *conn)
    .await?;
    Ok(ack)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn nic(name: &str, kind: &str, gw: bool) -> NetInterface {
        NetInterface {
            name: name.into(),
            description: None,
            kind: kind.into(),
            up: true,
            mac: None,
            addresses: vec!["10.0.0.2/24".into()],
            gateways: if gw { vec!["10.0.0.1".into()] } else { vec![] },
            dns: vec![],
            ssid: None,
        }
    }

    #[test]
    fn replay_and_evaluate() {
        let mut s = NetState::new();
        let snap = json!({"interfaces": [nic("eth", "ethernet", true)]});
        assert!(apply(&mut s, AgentEvent::NET_SNAPSHOT, &snap));
        assert!(evaluate(&s, &[]).is_none());
        let lte = serde_json::to_value(nic("lte", "cellular", true)).unwrap();
        assert!(apply(&mut s, AgentEvent::NET_UP, &lte));
        assert!(evaluate(&s, &[]).is_some());
        assert!(apply(&mut s, AgentEvent::NET_DOWN, &json!({"name": "lte"})));
        assert!(evaluate(&s, &[]).is_none());
        // 不存在的網卡停用、格式錯誤、不認得的事件：不改變狀態
        assert!(!apply(
            &mut s,
            AgentEvent::NET_DOWN,
            &json!({"name": "nope"})
        ));
        assert!(!apply(&mut s, AgentEvent::NET_DOWN, &json!({})));
        assert!(!apply(&mut s, AgentEvent::NET_UP, &json!(5)));
        assert!(!apply(&mut s, AgentEvent::NET_SNAPSHOT, &json!("x")));
        assert!(!apply(&mut s, "usb.inserted", &json!({})));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn clock_ahead_uses_received_time() {
        let now = time::macros::datetime!(2026-11-22 12:00 UTC);
        assert_eq!(
            effective_at(now + Duration::minutes(4), now),
            now + Duration::minutes(4)
        );
        assert_eq!(effective_at(now + Duration::minutes(6), now), now);
        assert_eq!(
            effective_at(now - Duration::days(3), now),
            now - Duration::days(3)
        );
    }
}
