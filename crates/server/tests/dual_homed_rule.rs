mod common;

use std::collections::BTreeMap;

use common::{TestAgent, TestServer};
use endpoint_server::compliance::admin::{self, RuleInput};
use endpoint_server::compliance::worker;
use protocol::{
    AgentEvent, CheckinRequest, InventoryPayload, InventoryUpload, NetInterface, NetworkInfo,
    SCHEMA_VERSION,
};
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

async fn checkin(s: &TestServer, a: &TestAgent, journal: Uuid, events: Vec<AgentEvent>) {
    let r = s
        .client(Some(a))
        .post(s.url("/v1/checkin"))
        .json(&CheckinRequest {
            os_family: None,
            signing_keys: vec![],
            journal_id: Some(journal),
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
    assert_eq!(r.status(), 200);
}

fn rule(name: &str, params: serde_json::Value) -> RuleInput {
    RuleInput {
        name: name.into(),
        description: String::new(),
        kind: "dual_homed".into(),
        severity: "high".into(),
        enabled: true,
        params,
        include: vec![],
        exclude: vec![],
        template_key: None,
    }
}

async fn violations(s: &TestServer, a: &TestAgent) -> Vec<(i64, String, String)> {
    sqlx::query_as(
        "SELECT rule_id, status, detail::text FROM device_violations \
         WHERE device_id = $1 ORDER BY rule_id",
    )
    .bind(a.device_id)
    .fetch_all(&s.pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = false)]
async fn rule_filters_issues_and_expiry(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let j = Uuid::new_v4();
    checkin(&s, &a, j, vec![]).await;
    let eth = nic("eth", "ethernet", "10.1.2.3/24", "10.1.2.1");
    let up = s
        .client(Some(&a))
        .put(s.url("/v1/inventory/network"))
        .json(&InventoryUpload {
            schema_version: SCHEMA_VERSION,
            payload: InventoryPayload::Network(NetworkInfo {
                interfaces: vec![eth.clone()],
            }),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(up.status(), 204);

    let all = admin::create_rule(&s.pool, &rule("多重連線", json!({})), "admin")
        .await
        .unwrap();
    let except = admin::create_rule(
        &s.pool,
        &rule(
            "多重連線（排除行動網路）",
            json!({"exclude_interfaces": ["lte*"]}),
        ),
        "admin",
    )
    .await
    .unwrap();
    worker::recompute_all(&s.pool).await.unwrap();
    assert!(violations(&s, &a).await.is_empty(), "沒有期間：符合");

    // 兩小時前插上 4G，一小時前拔掉：事件進來就重算
    let now = OffsetDateTime::now_utc();
    let lte = serde_json::to_value(nic("lte0", "cellular", "100.64.0.9/10", "100.64.0.1")).unwrap();
    checkin(
        &s,
        &a,
        j,
        vec![
            ev(
                1,
                now - Duration::hours(3),
                AgentEvent::NET_SNAPSHOT,
                json!({"interfaces": [eth]}),
            ),
            ev(2, now - Duration::hours(2), AgentEvent::NET_UP, lte.clone()),
            ev(
                3,
                now - Duration::hours(1),
                AgentEvent::NET_DOWN,
                json!({"name": "lte0"}),
            ),
        ],
    )
    .await;
    let v = violations(&s, &a).await;
    assert_eq!(v.len(), 1, "{v:?}");
    assert_eq!((v[0].0, v[0].1.as_str()), (all, "violating"));
    assert!(v[0].2.contains("\"count\": 1"), "{}", v[0].2);

    // 裝置清單篩選與裝置頁的問題清單
    let admin = s.admin_client().await;
    let link = format!("/devices/{}", a.device_id);
    let (_, html) = s.page(&admin, "/devices?net=recent").await;
    assert!(html.contains(&link), "{html}");
    let (_, html) = s.page(&admin, "/devices?net=now").await;
    assert!(!html.contains(&link), "{html}");
    let (_, html) = s.page(&admin, &link).await;
    assert!(html.contains("7 天內曾多重連線 1 次"), "{html}");
    let (_, html) = s.page(&admin, "/compliance/violations").await;
    assert!(html.contains("7 天內多重連線 1 次"), "{html}");

    // 又插上：目前為多重連線
    checkin(&s, &a, j, vec![ev(4, now, AgentEvent::NET_UP, lte)]).await;
    let (_, html) = s.page(&admin, "/devices?net=now").await;
    assert!(html.contains(&link), "{html}");
    let (_, html) = s.page(&admin, &link).await;
    assert!(html.contains("目前為多重連線"), "{html}");

    // 據點網段改變時，有多重連線規則就重算全部裝置
    let g0: i64 = sqlx::query_scalar("SELECT generation FROM compliance_state")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    endpoint_server::branch::sites::create_site(
        &s.pool,
        &endpoint_server::branch::sites::SiteInput {
            name: "總部".into(),
            cidrs: vec!["10.1.0.0/16".into()],
            fallback_to_central: true,
            bandwidth_limit_mbps: None,
            disk_limit_gb: 10,
        },
        "admin",
    )
    .await
    .unwrap();
    let g1: i64 = sqlx::query_scalar("SELECT generation FROM compliance_state")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(g1, g0 + 1);

    // 期間都結束且超過回溯天數：定期重算後恢復符合
    sqlx::query(
        "UPDATE device_dual_homed_periods \
         SET started_at = now() - interval '10 days', ended_at = now() - interval '9 days' \
         WHERE device_id = $1",
    )
    .bind(a.device_id)
    .execute(&s.pool)
    .await
    .unwrap();
    assert_eq!(worker::refresh_dual_homed(&s.pool).await.unwrap(), 1);
    assert!(violations(&s, &a).await.is_empty());
    assert_eq!(worker::refresh_dual_homed(&s.pool).await.unwrap(), 0);
    let _ = except;
}
