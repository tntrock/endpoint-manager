mod common;

use std::collections::BTreeMap;

use common::{TestAgent, TestServer};
use endpoint_server::web::auth::Role;
use protocol::{
    CheckinRequest, CheckinResponse, ContainerItem, ContainersInfo, InventoryPayload,
    InventoryUpload, OsFamily, RuntimeInfo, SCHEMA_VERSION, Section,
};
use sqlx::PgPool;
use time::macros::datetime;

fn ctr(name: &str, image: &str, state: &str) -> ContainerItem {
    ContainerItem {
        runtime: "docker".into(),
        id: format!("{name:0<12}").chars().take(12).collect(),
        name: name.into(),
        image: image.into(),
        image_id: Some("sha256:abc".into()),
        state: state.into(),
        health: None,
        created_at: Some(datetime!(2026-11-20 00:00 UTC)),
        started_at: Some(datetime!(2026-11-20 00:00:01 UTC)),
        finished_at: (state == "exited").then_some(datetime!(2026-11-21 00:00 UTC)),
        restart_policy: Some("always".into()),
        privileged: Some(false),
        host_network: Some(false),
        ports: vec![],
        host_mounts: vec![],
        owner: None,
    }
}

fn info(containers: Vec<ContainerItem>) -> InventoryPayload {
    InventoryPayload::Containers(ContainersInfo {
        runtimes: vec![
            RuntimeInfo {
                kind: "docker".into(),
                version: Some("27.3.1".into()),
                error: None,
            },
            RuntimeInfo {
                kind: "podman".into(),
                version: None,
                error: Some("使用者 alice：cannot connect".into()),
            },
        ],
        containers,
        truncated: false,
    })
}

async fn put(s: &TestServer, a: &TestAgent, p: &InventoryPayload) -> u16 {
    s.client(Some(a))
        .put(s.url("/v1/inventory/containers"))
        .json(&InventoryUpload {
            schema_version: SCHEMA_VERSION,
            payload: p.clone(),
        })
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

async fn checkin(
    s: &TestServer,
    a: &TestAgent,
    hashes: BTreeMap<Section, String>,
) -> CheckinResponse {
    s.client(Some(a))
        .post(s.url("/v1/checkin"))
        .json(&CheckinRequest {
            os_family: Some(OsFamily::Linux),
            signing_keys: vec![],
            journal_id: None,
            events: vec![],
            schema_version: SCHEMA_VERSION,
            agent_version: "0.12.0".into(),
            boot_time: time::OffsetDateTime::now_utc(),
            logged_on_user: None,
            ip_addresses: vec![],
            section_hashes: hashes,
            section_errors: BTreeMap::new(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn changes(s: &TestServer, a: &TestAgent) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT change, item_key FROM inventory_changes \
         WHERE device_id = $1 AND section = 'containers' ORDER BY item_key, change",
    )
    .bind(a.device_id)
    .fetch_all(&s.pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = false)]
async fn upload_tab_and_changes(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("台北", 2).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let win = s.enroll_ok(&tok, None, None).await;

    // 伺服器宣告支援 containers，Agent 才會回報
    let resp = checkin(&s, &a, BTreeMap::new()).await;
    assert!(
        resp.supports(Section::Containers),
        "{:?}",
        resp.supported_sections
    );

    let admin = s.admin_client().await;
    let dev = format!("/devices/{}", a.device_id);
    let (_, html) = s.page(&admin, &dev).await;
    assert!(!html.contains("/tab/containers"), "還沒有資料時不顯示分頁");
    let (st, html) = s.page(&admin, &format!("{dev}/tab/containers")).await;
    assert_eq!(st, 200);
    assert!(html.contains("尚無容器資料"), "{html}");

    let mut web = ctr("web", "nginx:1.27", "running");
    web.privileged = Some(true);
    web.host_mounts = vec!["/".into(), "/var/run/docker.sock".into()];
    web.ports = vec!["0.0.0.0:8080->80/tcp".into()];
    web.health = Some("unhealthy".into());
    let mut job = ctr("nightly-job", "busybox", "exited");
    job.host_network = Some(true);
    let mut old_job = ctr("old-job", "busybox", "exited");
    old_job.finished_at = Some(datetime!(2026-11-19 00:00 UTC));
    let p = info(vec![
        web.clone(),
        old_job,
        job.clone(),
        ctr("api", "app:1.4", "running"),
    ]);
    assert_eq!(put(&s, &a, &p).await, 204);

    // 讀回的內容與上傳一致（hash 相同就不會一直要求重傳）
    let mut c = s.pool.acquire().await.unwrap();
    let back = endpoint_server::inventory::load_payload(&mut c, a.device_id, Section::Containers)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(back.canonical_hash(), p.canonical_hash());
    let resp = checkin(
        &s,
        &a,
        BTreeMap::from([(Section::Containers, p.canonical_hash())]),
    )
    .await;
    assert!(!resp.request_sections.contains(&Section::Containers));

    let (_, html) = s.page(&admin, &dev).await;
    assert!(
        html.contains(&format!("/devices/{}/tab/containers", a.device_id)),
        "{html}"
    );
    let (_, html) = s.page(&admin, &format!("{dev}/tab/containers")).await;
    for want in [
        "Docker",
        "27.3.1",
        "讀取失敗",
        "使用者 alice：cannot connect",
        "執行中（2）",
        "已停止（2，7 天內）",
        "nginx:1.27",
        "特權",
        "掛載 docker.sock",
        "掛載根目錄",
        "主機網路",
        "不健康",
        "0.0.0.0:8080-&#62;80/tcp",
    ] {
        assert!(html.contains(want), "{want}: {html}");
    }
    // 有警示的執行中容器排在前面
    assert!(
        html.find(">web").unwrap() < html.find(">api").unwrap(),
        "{html}"
    );
    // 已停止的：最近結束的在前
    assert!(
        html.find(">nightly-job").unwrap() < html.find(">old-job").unwrap(),
        "{html}"
    );

    // 變更歷史：映像改變、新增、移除會記；狀態改變不記
    let mut api = ctr("api", "app:1.5", "running");
    api.state = "running".into();
    let mut job2 = job.clone();
    job2.state = "running".into();
    job2.finished_at = None;
    let p2 = info(vec![web, job2, api, ctr("cache", "redis:7", "running")]);
    assert_eq!(put(&s, &a, &p2).await, 204);
    let ch = changes(&s, &a).await;
    let keys: Vec<(&str, &str)> = ch.iter().map(|(k, i)| (k.as_str(), i.as_str())).collect();
    assert!(keys.contains(&("updated", "api|docker|")), "{keys:?}");
    assert!(keys.contains(&("added", "cache|docker|")), "{keys:?}");
    assert!(
        !keys.iter().any(|(_, i)| i.starts_with("nightly-job")),
        "{keys:?}"
    );
    let p3 = info(vec![]);
    assert_eq!(put(&s, &a, &p3).await, 204);
    assert!(
        changes(&s, &a)
            .await
            .iter()
            .any(|(k, i)| k == "removed" && i == "web|docker|")
    );
    let (_, html) = s.page(&admin, &format!("{dev}/tab/timeline")).await;
    assert!(html.contains("容器"), "{html}");

    // 沒有執行環境：不顯示分頁；分頁本身說明沒有偵測到
    let none = InventoryPayload::Containers(ContainersInfo {
        runtimes: vec![],
        containers: vec![],
        truncated: false,
    });
    assert_eq!(put(&s, &a, &none).await, 204);
    let (_, html) = s.page(&admin, &dev).await;
    assert!(!html.contains("/tab/containers"));
    let (_, html) = s.page(&admin, &format!("{dev}/tab/containers")).await;
    assert!(html.contains("沒有偵測到 Docker 或 Podman"), "{html}");

    // Windows 裝置沒有這個分頁；範圍外的群組管理員看不到
    let (st, _) = s
        .page(
            &admin,
            &format!("/devices/{}/tab/containers", win.device_id),
        )
        .await;
    assert_eq!(st, 404);
    s.create_group_token("高雄", 1).await;
    let other = s.login_as("olga", Role::GroupAdmin, &["高雄"]).await;
    assert_eq!(
        s.page(&other, &format!("{dev}/tab/containers")).await.0,
        404
    );
}

#[sqlx::test(migrations = false)]
async fn truncated_and_rejects_too_many(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    checkin(&s, &a, BTreeMap::new()).await;
    let too_many = info(
        (0..=protocol::MAX_CONTAINERS)
            .map(|i| ctr(&format!("c{i}"), "x", "running"))
            .collect(),
    );
    assert_eq!(put(&s, &a, &too_many).await, 400);
    let InventoryPayload::Containers(mut ok) = info(vec![ctr("one", "x", "running")]) else {
        unreachable!()
    };
    ok.truncated = true;
    assert_eq!(put(&s, &a, &InventoryPayload::Containers(ok)).await, 204);
    let admin = s.admin_client().await;
    let (_, html) = s
        .page(&admin, &format!("/devices/{}/tab/containers", a.device_id))
        .await;
    assert!(html.contains("只列出前 500 個"), "{html}");

    // 手動改壞的 jsonb：當成沒有資料，不讓讀取失敗
    sqlx::query("UPDATE device_containers SET data = '{\"bad\": 1}'::jsonb WHERE device_id = $1")
        .bind(a.device_id)
        .execute(&s.pool)
        .await
        .unwrap();
    let mut c = s.pool.acquire().await.unwrap();
    let back = endpoint_server::inventory::load_payload(&mut c, a.device_id, Section::Containers)
        .await
        .unwrap();
    assert!(back.is_none());
    let (_, html) = s
        .page(&admin, &format!("/devices/{}/tab/containers", a.device_id))
        .await;
    assert!(html.contains("尚無容器資料"), "{html}");
}
