mod common;

use common::{TestAgent, TestServer};
use endpoint_server::compliance::rules::{Params, Rule, Severity};
use protocol::{Arch, InventoryPayload, InventoryUpload, PatchItem, SCHEMA_VERSION, SoftwareItem};
use sqlx::PgPool;

async fn put(s: &TestServer, a: &TestAgent, p: InventoryPayload) {
    let section = p.section().as_str();
    let r = s
        .client(Some(a))
        .put(s.url(&format!("/v1/inventory/{section}")))
        .json(&InventoryUpload {
            schema_version: SCHEMA_VERSION,
            payload: p,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
}

fn sw(name: &str) -> SoftwareItem {
    SoftwareItem {
        name: name.into(),
        version: Some("1".into()),
        publisher: None,
        install_date: None,
        arch: Arch::X64,
    }
}

/// 在指定群組註冊一台裝置並上傳軟體與修補。
async fn device_in(s: &TestServer, group: &str, software: &[&str]) -> TestAgent {
    let tok = s.create_group_token(group, 1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    put(
        s,
        &a,
        InventoryPayload::Software(software.iter().map(|n| sw(n)).collect()),
    )
    .await;
    put(
        s,
        &a,
        InventoryPayload::Patches(vec![PatchItem {
            kb: "KB1".into(),
            installed_on: None,
        }]),
    )
    .await;
    a
}

#[sqlx::test(migrations = false)]
async fn preview_counts_matching_devices(pool: PgPool) {
    let s = TestServer::start(pool).await;
    device_in(&s, "台北", &["TeamViewer 15"]).await;
    device_in(&s, "高雄", &["TeamViewer 15"]).await;
    device_in(&s, "高雄", &["7-Zip"]).await;
    let rule = |include: Vec<i64>| Rule {
        id: 0,
        name: "p".into(),
        severity: Severity::High,
        include,
        exclude: vec![],
        check: Ok(Params::parse(
            "forbidden_software",
            &serde_json::json!({"name": "*TeamViewer*"}),
        )
        .unwrap()
        .compile()),
    };
    let c = endpoint_server::compliance::preview::preview(&s.pool, rule(vec![]))
        .await
        .unwrap();
    assert_eq!((c.violating, c.unknown, c.devices), (2, 0, 3));
    let g = s.group_id("高雄").await;
    let c = endpoint_server::compliance::preview::preview(&s.pool, rule(vec![g]))
        .await
        .unwrap();
    assert_eq!(c.violating, 1);
}
