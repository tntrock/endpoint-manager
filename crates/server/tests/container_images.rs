mod common;

use std::collections::BTreeMap;

use common::{TestAgent, TestServer};
use endpoint_server::web::auth::Role;
use protocol::{
    CheckinRequest, ContainerItem, ContainersInfo, InventoryPayload, InventoryUpload, K8sRef,
    OsFamily, RuntimeInfo, SCHEMA_VERSION,
};
use sqlx::PgPool;
use time::macros::datetime;

fn ctr(runtime: &str, name: &str, image: &str, state: &str, day: u8) -> ContainerItem {
    ContainerItem {
        runtime: runtime.into(),
        id: format!("{name:0<12}").chars().take(12).collect(),
        name: name.into(),
        image: image.into(),
        image_id: None,
        state: state.into(),
        health: None,
        created_at: Some(datetime!(2026-11-01 00:00 UTC)),
        started_at: Some(datetime!(2026-11-01 00:00 UTC) + time::Duration::days(i64::from(day))),
        finished_at: (state == "exited").then_some(datetime!(2026-11-21 00:00 UTC)),
        restart_policy: None,
        privileged: None,
        host_network: None,
        ports: vec![],
        host_mounts: vec![],
        owner: None,
        k8s: None,
    }
}

async fn upload(s: &TestServer, a: &TestAgent, containers: Vec<ContainerItem>) {
    let r = s
        .client(Some(a))
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
            section_hashes: BTreeMap::new(),
            section_errors: BTreeMap::new(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let r = s
        .client(Some(a))
        .put(s.url("/v1/inventory/containers"))
        .json(&InventoryUpload {
            schema_version: SCHEMA_VERSION,
            payload: InventoryPayload::Containers(ContainersInfo {
                runtimes: vec![RuntimeInfo {
                    kind: "docker".into(),
                    version: None,
                    error: None,
                }],
                containers,
                truncated: false,
            }),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
}

#[sqlx::test(migrations = false)]
async fn image_list_and_detail(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("台北", 2).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let b = s.enroll_ok(&tok, None, None).await;
    let mut api = ctr(
        "containerd",
        "api",
        "registry.example.com:5000/shop/api:2.1",
        "running",
        3,
    );
    api.k8s = Some(K8sRef {
        namespace: "shop".into(),
        pod: "api-7d9f".into(),
    });
    upload(
        &s,
        &a,
        vec![
            ctr("docker", "web", "nginx:1.27", "running", 5),
            ctr(
                "docker",
                "pinned",
                "registry.example.com:5000/shop/api@sha256:0123456789abcdef0123456789",
                "running",
                1,
            ),
            api,
        ],
    )
    .await;
    upload(
        &s,
        &b,
        vec![
            ctr("docker", "web-old", "nginx:1.26", "exited", 2),
            ctr("incus", "db", "Debian bookworm", "running", 4),
        ],
    )
    .await;

    let admin = s.admin_client().await;
    let (st, html) = s.page(&admin, "/containers").await;
    assert_eq!(st, 200);
    assert!(html.contains(r#"href="/containers""#), "側欄有連結");
    // nginx：兩台、一個執行中、兩個標籤；有 port 的倉庫名稱不會被當成標籤切掉
    let row = |html: &str, repo: &str| -> String {
        let start = html
            .find(&format!("<code>{repo}</code>"))
            .unwrap_or_else(|| panic!("{repo}: {html}"));
        html[start..start + html[start..].find("</tr>").unwrap()].to_string()
    };
    let nginx = row(&html, "nginx");
    assert!(nginx.contains("1.26") && nginx.contains("1.27"), "{nginx}");
    assert!(nginx.contains(r#"<td class="num">2</td>"#), "{nginx}");
    assert!(nginx.contains(r#"<td class="num">1</td>"#), "{nginx}");
    let api_row = row(&html, "registry.example.com:5000/shop/api");
    assert!(
        api_row.contains("2.1") && api_row.contains("@sha256:0123456789ab"),
        "{api_row}"
    );
    assert!(html.contains("Debian bookworm"), "{html}");

    // 篩選：只看執行中、執行環境、名稱、群組
    let (_, html) = s.page(&admin, "/containers?running=true").await;
    assert!(row(&html, "nginx").contains(r#"<td class="num">1</td>"#));
    let (_, html) = s.page(&admin, "/containers?runtime=incus").await;
    assert!(
        html.contains("Debian bookworm") && !html.contains("<code>nginx</code>"),
        "{html}"
    );
    let (_, html) = s.page(&admin, "/containers?q=ngin").await;
    assert!(
        html.contains("<code>nginx</code>") && !html.contains("Debian"),
        "{html}"
    );
    let (_, html) = s.page(&admin, "/containers?group=none").await;
    assert!(html.contains("沒有符合的容器"), "{html}");

    // 明細：依啟動時間由新到舊
    let (st, html) = s
        .page(&admin, "/containers/image?repo=nginx&sort=-started")
        .await;
    assert_eq!(st, 200);
    assert!(html.contains("2 台主機、2 個容器"), "{html}");
    assert!(
        html.find(">web<").unwrap() < html.find(">web-old<").unwrap(),
        "{html}"
    );
    assert!(html.contains("已停止"), "{html}");
    let (_, html) = s
        .page(
            &admin,
            "/containers/image?repo=registry.example.com:5000/shop/api",
        )
        .await;
    assert!(html.contains("Pod shop／api-7d9f"), "{html}");
    assert!(html.contains("containerd"), "{html}");

    // 範圍外的群組管理員看不到
    s.create_group_token("高雄", 1).await;
    let g = s.login_as("olga", Role::GroupAdmin, &["高雄"]).await;
    let (_, html) = s.page(&g, "/containers").await;
    assert!(!html.contains("<code>nginx</code>"), "{html}");
    let (_, html) = s.page(&g, "/containers/image?repo=nginx").await;
    assert!(html.contains("範圍內沒有使用這個映像的容器"), "{html}");
}
