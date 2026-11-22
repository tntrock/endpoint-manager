mod common;

use common::{TestAgent, TestServer};
use endpoint_server::web::auth::Role;
use protocol::{
    InventoryPayload, InventoryUpload, RuntimeInfo, SCHEMA_VERSION, Section, VmItem, VmsInfo,
};
use sqlx::PgPool;

fn vm(platform: &str, id: &str, name: &str, state: &str, uuid: Option<&str>) -> VmItem {
    VmItem {
        platform: platform.into(),
        id: id.into(),
        name: name.into(),
        state: state.into(),
        bios_uuid: uuid.map(Into::into),
        vcpus: Some(2),
        memory_mb: Some(4096),
        os_hint: None,
    }
}

fn info(vms: Vec<VmItem>) -> InventoryPayload {
    InventoryPayload::Vms(VmsInfo {
        platforms: vec![RuntimeInfo {
            kind: "proxmox".into(),
            version: Some("8.2.4".into()),
            error: None,
        }],
        vms,
        truncated: false,
    })
}

async fn put(s: &TestServer, a: &TestAgent, p: &InventoryPayload) -> u16 {
    s.client(Some(a))
        .put(s.url("/v1/inventory/vms"))
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

/// vm1 的 BIOS UUID；客體裡讀到的是前三段反轉的寫法（大寫）
const VM1: &str = "00112233-4455-6677-8899-aabbccddeeff";
const GUEST: &str = "33221100-5544-7766-8899-AABBCCDDEEFF";

#[sqlx::test(migrations = false)]
async fn host_tab_guest_link_and_unmanaged(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(3).await;
    let host = s.enroll_ok(&tok, None, None).await;
    let guest = s.enroll_ok(&tok, Some(GUEST), None).await;
    let c = s.admin_client().await;

    // 還沒上傳：沒有分頁
    let (_, html) = s.page(&c, &format!("/devices/{}", host.device_id)).await;
    assert!(!html.contains("/tab/vms\""));

    let p = info(vec![
        vm("proxmox", "100", "web", "running", Some(VM1)),
        vm(
            "proxmox",
            "101",
            "orphan",
            "running",
            Some("99999999-0000-0000-0000-000000000000"),
        ),
        vm(
            "proxmox",
            "102",
            "old",
            "stopped",
            Some("88888888-0000-0000-0000-000000000000"),
        ),
        vm("proxmox-lxc", "200", "ct", "running", None),
    ]);
    assert_eq!(put(&s, &host, &p).await, 204);

    // 主機：虛擬機分頁
    let (_, html) = s.page(&c, &format!("/devices/{}", host.device_id)).await;
    assert!(html.contains("/tab/vms\""), "{html}");
    let (st, tab) = s
        .page(&c, &format!("/devices/{}/tab/vms", host.device_id))
        .await;
    assert_eq!(st, 200);
    assert!(
        tab.contains(&format!("href=\"/devices/{}\"", guest.device_id)),
        "{tab}"
    );
    assert!(tab.contains("Proxmox VE") && tab.contains("8.2.4"), "{tab}");
    assert!(
        tab.contains("未安裝 Agent") && tab.contains("無法配對"),
        "{tab}"
    );
    assert!(tab.contains("4.0 GB"), "{tab}");

    // 客體：執行於主機
    let (_, html) = s.page(&c, &format!("/devices/{}", guest.device_id)).await;
    assert!(html.contains("執行於"), "{html}");
    assert!(html.contains(&format!("href=\"/devices/{}\"", host.device_id)));

    // 總覽：執行中、沒對到裝置的只有 orphan（停止的與 LXC 不算）
    let (_, html) = s.page(&c, "/").await;
    assert!(html.contains("虛擬機未安裝 Agent"), "{html}");
    let (st, html) = s.page(&c, "/vms?unmanaged=true").await;
    assert_eq!(st, 200);
    assert!(
        html.contains("orphan") && !html.contains(">web<") && !html.contains(">old<"),
        "{html}"
    );
    let (_, html) = s.page(&c, "/vms?q=WE").await;
    assert!(html.contains(">web<") && !html.contains("orphan"), "{html}");
    let (_, html) = s.page(&c, "/vms").await;
    for n in ["web", "orphan", "old", "ct"] {
        assert!(html.contains(&format!(">{n}<")), "{n}");
    }

    // 第一次上傳只當基準線，不記變更；區段雜湊可以由資料庫重建
    let mut conn = s.pool.acquire().await.unwrap();
    let back = endpoint_server::inventory::load_payload(&mut conn, host.device_id, Section::Vms)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(back.canonical_hash(), p.canonical_hash());

    // 漏裝的虛擬機刪掉後，總覽不再提示；重複的 ID 只留一筆
    let p = info(vec![
        vm("proxmox", "100", "web", "running", Some(VM1)),
        vm("proxmox", "100", "dup", "running", None),
    ]);
    assert_eq!(put(&s, &host, &p).await, 204);
    // 變更歷史：移除 orphan、old、ct，新增 dup（同 ID 但名稱不同，只記一筆）
    let changes: Vec<(String, String)> = sqlx::query_as(
        "SELECT change, item_key FROM inventory_changes          WHERE device_id = $1 AND section = 'vms' ORDER BY item_key",
    )
    .bind(host.device_id)
    .fetch_all(&s.pool)
    .await
    .unwrap();
    assert_eq!(changes.len(), 4, "{changes:?}");
    assert!(
        changes
            .iter()
            .any(|(c, k)| c == "added" && k.starts_with("dup|")),
        "{changes:?}"
    );
    let (_, html) = s.page(&c, "/").await;
    assert!(!html.contains("虛擬機未安裝 Agent"));
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM vm_guests WHERE host_id = $1")
        .bind(host.device_id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(rows, 1);
    // 主機除役後，客體不再顯示執行於
    sqlx::query("UPDATE devices SET status = 'retired' WHERE id = $1")
        .bind(host.device_id)
        .execute(&s.pool)
        .await
        .unwrap();
    let (_, html) = s.page(&c, &format!("/devices/{}", guest.device_id)).await;
    assert!(!html.contains("執行於"));
}

#[sqlx::test(migrations = false)]
async fn empty_and_errors(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(2).await;
    let host = s.enroll_ok(&tok, None, None).await;
    let c = s.admin_client().await;
    // 沒有虛擬化平台：不顯示分頁
    let none = InventoryPayload::Vms(VmsInfo {
        platforms: vec![],
        vms: vec![],
        truncated: false,
    });
    assert_eq!(put(&s, &host, &none).await, 204);
    let (_, html) = s.page(&c, &format!("/devices/{}", host.device_id)).await;
    assert!(!html.contains("/tab/vms\""));
    let (_, tab) = s
        .page(&c, &format!("/devices/{}/tab/vms", host.device_id))
        .await;
    assert!(tab.contains("沒有偵測到虛擬化平台"), "{tab}");
    // 平台讀取失敗、沒有虛擬機；沒有上傳過的裝置
    let p = InventoryPayload::Vms(VmsInfo {
        platforms: vec![RuntimeInfo {
            kind: "hyperv".into(),
            version: None,
            error: Some("access denied".into()),
        }],
        vms: vec![],
        truncated: true,
    });
    assert_eq!(put(&s, &host, &p).await, 204);
    let (_, tab) = s
        .page(&c, &format!("/devices/{}/tab/vms", host.device_id))
        .await;
    assert!(tab.contains("Hyper-V") && tab.contains("access denied") && tab.contains("沒有虛擬機"));
    assert!(tab.contains("只列出前 500 台"));
    let other = s.enroll_ok(&tok, None, None).await;
    let (_, tab) = s
        .page(&c, &format!("/devices/{}/tab/vms", other.device_id))
        .await;
    assert!(tab.contains("尚無虛擬機資料"), "{tab}");

    // 太多虛擬機被拒絕
    let many: Vec<VmItem> = (0..=protocol::MAX_VMS)
        .map(|i| vm("libvirt", &i.to_string(), "x", "stopped", None))
        .collect();
    assert_eq!(put(&s, &host, &info(many)).await, 400);
}

#[sqlx::test(migrations = false)]
async fn group_admin_sees_only_scope(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let ks = s.create_group_token("高雄", 2).await;
    let tok = s.create_token(2).await;
    // 主機在範圍內、客體不在；另一台客體在範圍內、主機不在
    let host = s.enroll_ok(&ks, None, None).await;
    let _outside_guest = s.enroll_ok(&tok, Some(VM1), None).await;
    let other_host = s.enroll_ok(&tok, None, None).await;
    let inside_guest = s
        .enroll_ok(&ks, Some("77777777-0000-0000-0000-000000000000"), None)
        .await;
    put(
        &s,
        &host,
        &info(vec![vm("proxmox", "100", "web", "running", Some(VM1))]),
    )
    .await;
    put(
        &s,
        &other_host,
        &info(vec![vm(
            "libvirt",
            "x",
            "db",
            "running",
            Some("77777777-0000-0000-0000-000000000000"),
        )]),
    )
    .await;
    let g = s.login_as("olga", Role::GroupAdmin, &["高雄"]).await;
    let (_, tab) = s
        .page(&g, &format!("/devices/{}/tab/vms", host.device_id))
        .await;
    assert!(tab.contains("已安裝 Agent（不在管理範圍）"), "{tab}");
    let (_, html) = s
        .page(&g, &format!("/devices/{}", inside_guest.device_id))
        .await;
    assert!(html.contains("執行於"), "{html}");
    assert!(!html.contains(&format!("href=\"/devices/{}\"", other_host.device_id)));
    // 清單只列範圍內主機的虛擬機
    let (_, html) = s.page(&g, "/vms").await;
    assert!(html.contains(">web<") && !html.contains(">db<"), "{html}");
    let gid = s.group_id("高雄").await;
    let (_, html) = s.page(&g, &format!("/vms?group={gid}")).await;
    assert!(html.contains(">web<"), "{html}");
    let (_, html) = s.page(&g, "/vms?group=none").await;
    assert!(!html.contains(">web<"), "{html}");
}
