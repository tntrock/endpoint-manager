mod common;

use std::collections::BTreeMap;

use common::{TestAgent, TestServer};
use protocol::{AgentEvent, CheckinRequest, CheckinResponse, NetInterface, SCHEMA_VERSION};
use serde_json::json;
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

fn nic(name: &str, kind: &str, addr: &str, gw: &str) -> NetInterface {
    NetInterface {
        name: name.into(),
        description: None,
        kind: kind.into(),
        up: true,
        mac: None,
        addresses: vec![addr.into()],
        gateways: vec![gw.into()],
        dns: vec![],
        ssid: None,
    }
}

fn ev(seq: u64, at: OffsetDateTime, kind: &str, data: serde_json::Value) -> AgentEvent {
    AgentEvent {
        seq,
        at,
        kind: kind.into(),
        data,
    }
}

async fn send(
    s: &TestServer,
    a: &TestAgent,
    journal: Option<Uuid>,
    events: Vec<AgentEvent>,
) -> (u16, Option<CheckinResponse>) {
    let r = s
        .client(Some(a))
        .post(s.url("/v1/checkin"))
        .json(&CheckinRequest {
            os_family: None,
            signing_keys: vec![],
            journal_id: journal,
            events,
            schema_version: SCHEMA_VERSION,
            agent_version: "0.12.0".into(),
            boot_time: OffsetDateTime::now_utc(),
            logged_on_user: None,
            ip_addresses: vec![],
            section_hashes: BTreeMap::new(),
            section_errors: BTreeMap::new(),
        })
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    (status, r.json().await.ok())
}

type PeriodRow = (OffsetDateTime, Option<OffsetDateTime>, bool, Vec<String>);

async fn periods(s: &TestServer, a: &TestAgent) -> Vec<PeriodRow> {
    sqlx::query_as(
        "SELECT started_at, ended_at, incomplete, interfaces FROM device_dual_homed_periods \
         WHERE device_id = $1 ORDER BY started_at, id",
    )
    .bind(a.device_id)
    .fetch_all(&s.pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = false)]
async fn events_are_stored_once_and_replayed_into_periods(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;

    let (_, r) = send(&s, &a, None, vec![]).await;
    let r = r.unwrap();
    assert!(r.supports_events && r.events_ack.is_none());

    let j = Uuid::new_v4();
    // 整秒：資料庫存到微秒，比較時才不會差一點
    let t0 = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap() - Duration::hours(1);
    let min = |m: i64| t0 + Duration::minutes(m);
    let eth = nic("eth", "ethernet", "10.1.2.3/24", "10.1.2.1");
    let lte = serde_json::to_value(nic("lte", "cellular", "100.64.0.9/10", "100.64.0.1")).unwrap();
    let batch = vec![
        ev(
            1,
            min(0),
            AgentEvent::NET_SNAPSHOT,
            json!({ "interfaces": [eth] }),
        ),
        ev(2, min(1), AgentEvent::NET_UP, lte.clone()),
        ev(
            3,
            min(3),
            AgentEvent::NET_DOWN,
            json!({"name": "lte", "kind": "cellular"}),
        ),
        ev(4, min(10), AgentEvent::NET_UP, lte.clone()),
    ];
    let (_, r) = send(&s, &a, Some(j), batch.clone()).await;
    assert_eq!(r.unwrap().events_ack, Some(4));
    let p = periods(&s, &a).await;
    assert_eq!(p.len(), 2, "{p:?}");
    assert_eq!((p[0].0, p[0].1), (min(1), Some(min(3))));
    assert_eq!((p[1].0, p[1].1), (min(10), None));
    assert_eq!(p[0].3, ["eth", "lte"]);

    // 報到失敗後重送（含已存過的）：不重複，新的那筆結束持續中的期間
    let mut again = batch.clone();
    again.push(ev(
        5,
        min(12),
        AgentEvent::NET_DOWN,
        json!({"name": "lte", "kind": "cellular"}),
    ));
    let (_, r) = send(&s, &a, Some(j), again).await;
    assert_eq!(r.unwrap().events_ack, Some(5));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM device_events WHERE device_id = $1")
        .bind(a.device_id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 5);
    let p = periods(&s, &a).await;
    assert_eq!(p.len(), 2);
    assert_eq!(p[1].1, Some(min(12)));

    // 日誌有缺漏後的下一段期間標記為可能不完整
    let (_, r) = send(
        &s,
        &a,
        Some(j),
        vec![
            ev(6, min(20), AgentEvent::JOURNAL_DROPPED, json!({"count": 9})),
            ev(7, min(21), AgentEvent::NET_UP, lte.clone()),
        ],
    )
    .await;
    assert_eq!(r.unwrap().events_ack, Some(7));
    let p = periods(&s, &a).await;
    assert_eq!(p.len(), 3);
    assert!(!p[0].2 && !p[1].2 && p[2].2, "{p:?}");

    // 重新安裝（新的 journal_id，序號從 1 開始）：不會被當成重送；端點時鐘超前時用收到時間
    let j2 = Uuid::new_v4();
    let future = OffsetDateTime::now_utc() + Duration::hours(3);
    let (_, r) = send(
        &s,
        &a,
        Some(j2),
        vec![ev(
            1,
            future,
            AgentEvent::NET_SNAPSHOT,
            json!({ "interfaces": [nic("eth", "ethernet", "10.1.2.3/24", "10.1.2.1")] }),
        )],
    )
    .await;
    assert_eq!(r.unwrap().events_ack, Some(1));
    let (at, received): (OffsetDateTime, OffsetDateTime) = sqlx::query_as(
        "SELECT at, received_at FROM device_events WHERE device_id = $1 AND journal_id = $2",
    )
    .bind(a.device_id)
    .bind(j2)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(at, received);
    let p = periods(&s, &a).await;
    assert!(p[2].1.is_some(), "快照只剩一張網卡：期間結束");

    // 網路分頁與時間軸
    let admin = s.admin_client().await;
    let dev = format!("/devices/{}", a.device_id);
    let (_, html) = s.page(&admin, &format!("{dev}/tab/network")).await;
    for want in [
        "多重連線紀錄",
        "2 分鐘",
        "可能不完整",
        "兩條對外路徑",
        "eth、lte",
    ] {
        assert!(html.contains(want), "{want}: {html}");
    }
    let (_, html) = s.page(&admin, &format!("{dev}/tab/timeline")).await;
    for want in [
        "開始多重連線",
        "多重連線結束",
        "網卡「lte」已連線",
        "網卡「lte」已中斷",
        "本機事件日誌已滿",
    ] {
        assert!(html.contains(want), "{want}: {html}");
    }
}

#[sqlx::test(migrations = false)]
async fn limits_and_ignored_events(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let j = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let too_many: Vec<AgentEvent> = (1..=protocol::MAX_EVENTS_PER_CHECKIN as u64 + 1)
        .map(|i| ev(i, now, "net.changed", json!({})))
        .collect();
    assert_eq!(send(&s, &a, Some(j), too_many).await.0, 400);

    // 沒有 journal_id 的事件不處理也不確認
    let (_, r) = send(&s, &a, None, vec![ev(1, now, "net.up", json!({}))]).await;
    assert_eq!(r.unwrap().events_ack, None);

    // 序號超過資料庫範圍、不認得的種類：仍確認（Agent 才不會一直重送），不產生期間
    let (_, r) = send(
        &s,
        &a,
        Some(j),
        vec![
            ev(u64::MAX, now, "net.up", json!({})),
            ev(3, now, "usb.inserted", json!({})),
        ],
    )
    .await;
    assert_eq!(r.unwrap().events_ack, Some(u64::MAX));
    let (_, r) = send(
        &s,
        &a,
        Some(j),
        vec![ev(u64::MAX, now, "net.up", json!({}))],
    )
    .await;
    assert_eq!(r.unwrap().events_ack, Some(u64::MAX));
    assert!(periods(&s, &a).await.is_empty());
}
