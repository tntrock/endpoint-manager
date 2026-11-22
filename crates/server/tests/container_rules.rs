mod common;

use std::collections::BTreeMap;

use common::{TestAgent, TestServer};
use endpoint_server::compliance::admin::{self, RuleInput};
use endpoint_server::compliance::rules::{Params, Rule, Severity};
use endpoint_server::compliance::{preview, worker};
use protocol::{
    CheckinRequest, ContainerItem, ContainersInfo, InventoryPayload, InventoryUpload, K8sRef,
    OsFamily, RuntimeInfo, SCHEMA_VERSION,
};
use serde_json::{Value, json};
use sqlx::PgPool;

fn ctr(name: &str, image: &str, state: &str) -> ContainerItem {
    ContainerItem {
        runtime: "docker".into(),
        id: format!("{name:0<12}").chars().take(12).collect(),
        name: name.into(),
        image: image.into(),
        image_id: None,
        state: state.into(),
        health: None,
        created_at: None,
        started_at: None,
        finished_at: None,
        restart_policy: None,
        privileged: Some(false),
        host_network: Some(false),
        ports: vec![],
        host_mounts: vec![],
        owner: None,
        k8s: None,
    }
}

fn info(containers: Vec<ContainerItem>, error: Option<&str>) -> InventoryPayload {
    InventoryPayload::Containers(ContainersInfo {
        runtimes: vec![RuntimeInfo {
            kind: "docker".into(),
            version: Some("27.3.1".into()),
            error: error.map(Into::into),
        }],
        containers,
        truncated: false,
    })
}

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

async fn checkin_linux(s: &TestServer, a: &TestAgent) {
    let r = s
        .client(Some(a))
        .post(s.url("/v1/checkin"))
        .json(&CheckinRequest {
            os_family: Some(OsFamily::Linux),
            signing_keys: vec![],
            journal_id: None,
            events: vec![],
            schema_version: SCHEMA_VERSION,
            agent_version: "0.13.0".into(),
            boot_time: time::OffsetDateTime::now_utc(),
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

fn input(name: &str, kind: &str, params: Value) -> RuleInput {
    RuleInput {
        name: name.into(),
        description: String::new(),
        kind: kind.into(),
        severity: "high".into(),
        enabled: true,
        params,
        include: vec![],
        exclude: vec![],
        template_key: None,
    }
}

async fn results(s: &TestServer, a: &TestAgent) -> Vec<(i64, String, Value)> {
    let rows: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT rule_id, status, detail::text FROM device_violations \
         WHERE device_id = $1 ORDER BY rule_id",
    )
    .bind(a.device_id)
    .fetch_all(&s.pool)
    .await
    .unwrap();
    rows.into_iter()
        .map(|(id, st, d)| (id, st, serde_json::from_str(&d).unwrap()))
        .collect()
}

#[sqlx::test(migrations = false)]
async fn container_rules_apply_only_to_linux(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(2).await;
    let lin = s.enroll_ok(&tok, None, None).await;
    let win = s.enroll_ok(&tok, None, None).await;
    checkin_linux(&s, &lin).await;
    put(&s, &win, InventoryPayload::Patches(vec![])).await;

    let kb = admin::create_rule(
        &s.pool,
        &input("KB", "required_kb", json!({"kb": "KB5031455"})),
        "admin",
    )
    .await
    .unwrap();
    let forbidden = admin::create_rule(
        &s.pool,
        &input("挖礦", "forbidden_image", json!({"image": "*xmrig*"})),
        "admin",
    )
    .await
    .unwrap();
    let privilege = admin::create_rule(
        &s.pool,
        &input(
            "權限",
            "container_privilege",
            json!({"privileged": true, "runtime_socket": true, "except_images": ["portainer/*"]}),
        ),
        "admin",
    )
    .await
    .unwrap();
    let unpinned = admin::create_rule(
        &s.pool,
        &input("版本", "unpinned_image", json!({})),
        "admin",
    )
    .await
    .unwrap();
    worker::recompute_all(&s.pool).await.unwrap();
    assert!(
        results(&s, &lin).await.is_empty(),
        "沒有回報容器：容器規則不適用，Windows 規則也不套用"
    );
    let w = results(&s, &win).await;
    assert_eq!(w.len(), 1, "Windows 裝置只有 KB 規則：{w:?}");
    assert_eq!((w[0].0, w[0].1.as_str()), (kb, "violating"));

    let mut miner = ctr("miner", "docker.io/library/xmrig:latest", "running");
    miner.privileged = Some(true);
    let mut portainer = ctr("portainer", "portainer/portainer-ce:2.21", "running");
    portainer.privileged = Some(true);
    portainer.host_mounts = vec!["/var/run/docker.sock".into()];
    let mut agent = ctr("agent", "ghcr.io/acme/agent:1.0", "running");
    agent.host_mounts = vec!["/run/containerd/containerd.sock".into()];
    let mut k8s = ctr("app", "registry.local:5000/app@sha256:abc", "running");
    k8s.privileged = None;
    k8s.k8s = Some(K8sRef {
        namespace: "shop".into(),
        pod: "app-1".into(),
    });
    let old = ctr("old", "xmrig:6", "exited");
    put(
        &s,
        &lin,
        info(vec![miner, portainer, agent, k8s, old], None),
    )
    .await;
    let r = results(&s, &lin).await;
    let ids: Vec<i64> = r.iter().map(|x| x.0).collect();
    assert_eq!(ids, vec![forbidden, privilege, unpinned], "{r:?}");
    assert!(r.iter().all(|x| x.1 == "violating"));
    assert_eq!(
        r[0].2,
        json!({"check": "forbidden", "total": 1,
               "containers": [{"name": "miner", "image": "docker.io/library/xmrig:latest"}]}),
        "停止的容器預設不算"
    );
    assert_eq!(
        r[1].2,
        json!({"check": "privilege", "total": 2, "undetermined": 1, "containers": [
            {"name": "miner", "image": "docker.io/library/xmrig:latest", "issues": ["特權"]},
            {"name": "agent", "image": "ghcr.io/acme/agent:1.0", "issues": ["掛載容器 socket"]},
        ]}),
        "portainer 在例外；Kubernetes 容器讀不到特權"
    );
    assert_eq!(r[2].2["total"], 1, "{:?}", r[2].2);

    // 網頁：Linux 裝置顯示合規分頁與摘要
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, &format!("/devices/{}", lin.device_id)).await;
    assert!(html.contains("/tab/compliance\""), "{html}");
    let (st, html) = s
        .page(&c, &format!("/devices/{}/tab/compliance", lin.device_id))
        .await;
    assert_eq!(st, 200);
    assert!(
        html.contains("使用禁止的映像：miner（docker.io/library/xmrig:latest）"),
        "{html}"
    );
    assert!(html.contains("另有 1 個容器無法判斷"), "{html}");

    // 執行環境讀取失敗、沒有符合的容器：未知
    put(&s, &lin, info(vec![], Some("cannot connect"))).await;
    let r = results(&s, &lin).await;
    assert_eq!(r.len(), 3, "{r:?}");
    for (_, st, d) in &r {
        assert_eq!(st, "unknown");
        assert_eq!(d["error"], "docker：cannot connect");
    }
    // 讀取正常而且沒有容器：全部符合
    put(&s, &lin, info(vec![], None)).await;
    assert!(results(&s, &lin).await.is_empty());
}

#[sqlx::test(migrations = false)]
async fn preview_counts_only_matching_os(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(3).await;
    let lin = s.enroll_ok(&tok, None, None).await;
    let _w1 = s.enroll_ok(&tok, None, None).await;
    let _w2 = s.enroll_ok(&tok, None, None).await;
    checkin_linux(&s, &lin).await;
    put(&s, &lin, info(vec![ctr("web", "nginx", "running")], None)).await;
    let rule = |kind: &str, p: Value| Rule {
        id: 0,
        name: "x".into(),
        severity: Severity::High,
        include: vec![],
        exclude: vec![],
        check: Ok(Params::parse(kind, &p).unwrap().compile()),
    };
    let c = preview::preview(&s.pool, rule("unpinned_image", json!({})))
        .await
        .unwrap();
    assert_eq!((c.devices, c.violating, c.unknown), (1, 1, 0));
    let c = preview::preview(&s.pool, rule("required_kb", json!({"kb": "KB5031455"})))
        .await
        .unwrap();
    assert_eq!((c.devices, c.violating, c.unknown), (2, 0, 2));
}
