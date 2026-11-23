//! 竄改偵測第一期：事件立即上傳、序號缺口、日誌重建、發現的顯示與確認

mod common;

use std::collections::BTreeMap;

use common::{TestAgent, TestServer, csrf_from};
use endpoint_server::web::auth::Role;
use protocol::{
    AgentEvent, CheckinRequest, CheckinResponse, EventsAck, EventsUpload, SCHEMA_VERSION,
};
use serde_json::json;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

fn ev(seq: u64, kind: &str, data: serde_json::Value) -> AgentEvent {
    AgentEvent {
        seq,
        at: OffsetDateTime::now_utc(),
        kind: kind.into(),
        data,
    }
}

fn evs(seqs: &[u64]) -> Vec<AgentEvent> {
    seqs.iter().map(|s| ev(*s, "test", json!({}))).collect()
}

async fn push(s: &TestServer, a: &TestAgent, journal: Uuid, events: Vec<AgentEvent>) -> u16 {
    // 每台每秒最多 2 次：測試裡連續送時稍等一下
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    let r = s
        .client(Some(a))
        .post(s.url("/v1/events"))
        .json(&EventsUpload {
            journal_id: journal,
            events: events.clone(),
        })
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    if status == 200 {
        let ack: EventsAck = r.json().await.unwrap();
        assert_eq!(ack.events_ack, events.iter().map(|e| e.seq).max());
    }
    status
}

async fn checkin(
    s: &TestServer,
    a: &TestAgent,
    journal: Uuid,
    events: Vec<AgentEvent>,
) -> CheckinResponse {
    let r = s
        .client(Some(a))
        .post(s.url("/v1/checkin"))
        .json(&CheckinRequest {
            os_family: None,
            signing_keys: vec![],
            journal_id: Some(journal),
            events,
            schema_version: SCHEMA_VERSION,
            agent_version: "0.13.0".into(),
            boot_time: OffsetDateTime::now_utc(),
            logged_on_user: None,
            ip_addresses: vec![],
            section_hashes: BTreeMap::new(),
            section_errors: BTreeMap::new(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    r.json().await.unwrap()
}

/// (種類, 還沒說明的筆數, 是否已確認)
async fn findings(s: &TestServer, a: &TestAgent) -> Vec<(String, i64, bool)> {
    sqlx::query_as(
        "SELECT kind, coalesce((detail->>'unexplained')::bigint, 0), acknowledged_at IS NOT NULL \
         FROM device_findings WHERE device_id = $1 ORDER BY id",
    )
    .bind(a.device_id)
    .fetch_all(&s.pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = false)]
async fn gaps_explanations_and_acknowledgement(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("研發部", 2).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let c = s.admin_client().await;
    let j = Uuid::new_v4();

    // 報到宣告支援立即上傳；連續的序號沒有發現
    let r = checkin(&s, &a, j, evs(&[1, 2, 3])).await;
    assert!(r.supports_event_push);
    assert_eq!(r.events_ack, Some(3));
    assert_eq!(push(&s, &a, j, evs(&[4])).await, 200);
    assert!(findings(&s, &a).await.is_empty());
    let (_, html) = s.page(&c, &format!("/devices/{}", a.device_id)).await;
    assert!(!html.contains("/tab/integrity\""), "沒有發現時不顯示分頁");

    // 跳號：5、6 不見了
    assert_eq!(push(&s, &a, j, evs(&[7])).await, 200);
    assert_eq!(
        findings(&s, &a).await,
        vec![("journal_gap".into(), 2, false)]
    );
    let (_, html) = s.page(&c, &format!("/devices/{}", a.device_id)).await;
    assert!(html.contains("/tab/integrity\""), "{html}");
    assert!(html.contains("事件序號不連續"));
    let (_, tl) = s
        .page(&c, &format!("/devices/{}/tab/timeline", a.device_id))
        .await;
    assert!(tl.contains("缺 2 筆（序號 5–6）"), "{tl}");
    let (_, list) = s.page(&c, "/devices?status=integrity").await;
    assert!(list.contains(&a.device_id.to_string()), "{list}");
    let (_, home) = s.page(&c, "/").await;
    assert!(home.contains("完整性警示"), "{home}");

    // 之後才到的 journal.dropped 說明了這兩筆：發現消失（報到重送不重複計算）
    let dropped = ev(8, AgentEvent::JOURNAL_DROPPED, json!({"count": 2}));
    checkin(&s, &a, j, vec![ev(7, "test", json!({})), dropped]).await;
    assert!(findings(&s, &a).await.is_empty());

    // 再缺一段，只說明一部分
    let dropped = ev(12, AgentEvent::JOURNAL_DROPPED, json!({"count": 1}));
    assert_eq!(push(&s, &a, j, vec![dropped]).await, 200);
    assert_eq!(
        findings(&s, &a).await,
        vec![("journal_gap".into(), 2, false)]
    );
    // 補上其中一筆
    assert_eq!(push(&s, &a, j, evs(&[10])).await, 200);
    assert_eq!(
        findings(&s, &a).await,
        vec![("journal_gap".into(), 1, false)]
    );
    let id: i64 = sqlx::query_scalar("SELECT id FROM device_findings WHERE device_id = $1")
        .bind(a.device_id)
        .fetch_one(&s.pool)
        .await
        .unwrap();

    // 檢視者看得到、不能確認
    let viewer = s.login_as("viewer", Role::Viewer, &["研發部"]).await;
    let (_, tab) = s
        .page(&viewer, &format!("/devices/{}/tab/integrity", a.device_id))
        .await;
    assert!(
        tab.contains("事件序號不連續") && tab.contains("未確認"),
        "{tab}"
    );
    assert!(!tab.contains("/ack\""));
    let (_, page) = s.page(&viewer, "/").await;
    let r = viewer
        .post(s.web_url(&format!("/devices/{}/findings/{id}/ack", a.device_id)))
        .form(&[("csrf", csrf_from(&page).as_str()), ("note", "x")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    // 管理員確認（htmx）：回傳更新後的分頁，寫入稽核記錄，不再列在需要處理
    let (_, page) = s.page(&c, "/").await;
    let r = c
        .post(s.web_url(&format!("/devices/{}/findings/{id}/ack", a.device_id)))
        .header("hx-request", "true")
        .form(&[("csrf", csrf_from(&page).as_str()), ("note", "測試換網卡")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let tab = r.text().await.unwrap();
    assert!(tab.contains("由 admin 確認：測試換網卡"), "{tab}");
    assert_eq!(
        findings(&s, &a).await,
        vec![("journal_gap".into(), 1, true)]
    );
    let audit: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action = 'finding_ack' AND target = $1",
    )
    .bind(a.device_id.to_string())
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(audit, 1);
    let (_, list) = s.page(&c, "/devices?status=integrity").await;
    assert!(!list.contains(&a.device_id.to_string()));
    let (_, html) = s.page(&c, &format!("/devices/{}", a.device_id)).await;
    assert!(html.contains("/tab/integrity\""), "確認後分頁仍在");
    // 再確認一次：提示已確認過；沒有 JavaScript 時回到裝置頁
    let r = c
        .post(s.web_url(&format!("/devices/{}/findings/{id}/ack", a.device_id)))
        .header("hx-request", "true")
        .form(&[("csrf", csrf_from(&page).as_str()), ("note", "")])
        .send()
        .await
        .unwrap();
    assert!(r.text().await.unwrap().contains("已經確認過"));
    let r = c
        .post(s.web_url(&format!("/devices/{}/findings/{id}/ack", a.device_id)))
        .form(&[("csrf", csrf_from(&page).as_str()), ("note", "")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    // 說明太長
    let r = c
        .post(s.web_url(&format!("/devices/{}/findings/{id}/ack", a.device_id)))
        .header("hx-request", "true")
        .form(&[
            ("csrf", csrf_from(&page).as_str()),
            ("note", &"長".repeat(501)),
        ])
        .send()
        .await
        .unwrap();
    assert!(r.text().await.unwrap().contains("說明最多 500 個字"));
}

#[sqlx::test(migrations = false)]
async fn rebuilt_journals_reenrollment_and_limits(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(3).await;
    let a = s.enroll_ok(&tok, None, None).await;

    // 第一份不算重建；之後 3 份新的日誌才標示一次
    for i in 0..4 {
        assert_eq!(push(&s, &a, Uuid::new_v4(), evs(&[1])).await, 200);
        let n = findings(&s, &a).await.len();
        assert_eq!(n, usize::from(i == 3), "第 {i} 份");
    }
    assert_eq!(push(&s, &a, Uuid::new_v4(), evs(&[1])).await, 200);
    assert_eq!(
        findings(&s, &a).await,
        vec![("journal_rebuilt".into(), 0, false)]
    );

    // 重新註冊沿用同一份日誌：從原本那台的序號接續，不算缺口
    let j = Uuid::new_v4();
    assert_eq!(push(&s, &a, j, evs(&[1, 2, 3])).await, 200);
    let b = s.enroll_ok(&tok, None, None).await;
    assert_eq!(push(&s, &b, j, evs(&[4, 5])).await, 200);
    assert!(findings(&s, &b).await.is_empty());

    // 一秒內送太多次：429
    let up = EventsUpload {
        journal_id: j,
        events: evs(&[6]),
    };
    let mut statuses = vec![];
    for _ in 0..4 {
        let r = s
            .client(Some(&b))
            .post(s.url("/v1/events"))
            .json(&up)
            .send()
            .await
            .unwrap();
        statuses.push(r.status().as_u16());
    }
    assert!(statuses.contains(&429), "{statuses:?}");
    // 筆數上限、空的批次
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let r = s
        .client(Some(&b))
        .post(s.url("/v1/events"))
        .json(&EventsUpload {
            journal_id: j,
            events: (1..=201).map(|i| ev(i, "t", json!({}))).collect(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let r = s
        .client(Some(&b))
        .post(s.url("/v1/events"))
        .json(&EventsUpload {
            journal_id: j,
            events: vec![],
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    // 沒有裝置憑證
    let r = s
        .client(None)
        .post(s.url("/v1/events"))
        .json(&up)
        .send()
        .await
        .unwrap();
    assert!(r.status() == 401 || r.status() == 403, "{}", r.status());
}
