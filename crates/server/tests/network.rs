mod common;

use std::collections::BTreeMap;

use common::{TestAgent, TestServer};
use endpoint_server::web::auth::Role;
use protocol::{
    CheckinRequest, CheckinResponse, InventoryPayload, InventoryUpload, NetInterface, NetworkInfo,
    SCHEMA_VERSION, Section,
};
use sqlx::PgPool;

fn nic(name: &str, kind: &str, addr: &str, gw: Option<&str>) -> NetInterface {
    NetInterface {
        name: name.into(),
        description: Some(format!("{name} adapter")),
        kind: kind.into(),
        up: true,
        mac: Some("00:11:22:33:44:55".into()),
        addresses: vec![addr.into()],
        gateways: gw.map(|g| vec![g.to_string()]).unwrap_or_default(),
        dns: vec!["10.1.0.53".into()],
        ssid: (kind == "wifi").then(|| "Phone-Hotspot".into()),
    }
}

fn info(nics: Vec<NetInterface>) -> InventoryPayload {
    InventoryPayload::Network(NetworkInfo { interfaces: nics })
}

async fn put(s: &TestServer, a: &TestAgent, p: &InventoryPayload) -> u16 {
    s.client(Some(a))
        .put(s.url("/v1/inventory/network"))
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
    ips: &[&str],
) -> CheckinResponse {
    s.client(Some(a))
        .post(s.url("/v1/checkin"))
        .json(&CheckinRequest {
            os_family: None,
            signing_keys: vec![],
            journal_id: None,
            events: vec![],
            schema_version: SCHEMA_VERSION,
            agent_version: "0.12.0".into(),
            boot_time: time::OffsetDateTime::now_utc(),
            logged_on_user: None,
            ip_addresses: ips.iter().map(|s| s.to_string()).collect(),
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

#[sqlx::test(migrations = false)]
async fn network_tab_dual_homed_and_changes(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("台北", 1).await;
    let a = s.enroll_ok(&tok, None, None).await;

    let resp = checkin(&s, &a, BTreeMap::new(), &[]).await;
    assert!(
        resp.supports(Section::Network),
        "{:?}",
        resp.supported_sections
    );

    let admin = s.admin_client().await;
    let dev = format!("/devices/{}", a.device_id);
    let (_, html) = s.page(&admin, &dev).await;
    assert!(html.contains(&format!("{dev}/tab/network")), "{html}");
    let (st, html) = s.page(&admin, &format!("{dev}/tab/network")).await;
    assert_eq!(st, 200);
    assert!(html.contains("尚無網路資料"), "{html}");

    // 公司有線網路（沒有預設閘道）＋手機熱點，另有 VPN 與虛擬網卡
    let p = info(vec![
        nic("乙太網路", "ethernet", "10.1.2.3/24", None),
        nic("Wi-Fi", "wifi", "192.168.43.5/24", Some("192.168.43.1")),
        nic("WireGuard", "vpn", "10.9.0.2/24", Some("0.0.0.0")),
        nic("vEthernet (WSL)", "virtual", "172.20.0.1/20", None),
    ]);
    assert_eq!(put(&s, &a, &p).await, 204);
    let mut c = s.pool.acquire().await.unwrap();
    let back = endpoint_server::inventory::load_payload(&mut c, a.device_id, Section::Network)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(back.canonical_hash(), p.canonical_hash());
    let resp = checkin(
        &s,
        &a,
        BTreeMap::from([(Section::Network, p.canonical_hash())]),
        &[],
    )
    .await;
    assert!(!resp.request_sections.contains(&Section::Network));

    // 沒有設定據點：只有一張對外網卡，不算多重連線
    let (_, html) = s.page(&admin, &format!("{dev}/tab/network")).await;
    for want in [
        "乙太網路",
        "Wi-Fi",
        "Phone-Hotspot",
        "VPN",
        "虛擬",
        "10.1.2.3/24",
        "192.168.43.1",
        "直接連線",
        "10.1.0.53",
        "對外",
        "尚未設定據點網段",
    ] {
        assert!(html.contains(want), "{want}: {html}");
    }
    assert!(!html.contains("多重連線</strong>"), "{html}");

    // 設定據點後：公司網段＋據點以外的閘道 → 多重連線
    sqlx::query("INSERT INTO sites (name, cidrs) VALUES ('總部', '{10.1.0.0/16}')")
        .execute(&s.pool)
        .await
        .unwrap();
    let (_, html) = s.page(&admin, &format!("{dev}/tab/network")).await;
    assert!(html.contains("多重連線</strong>"), "{html}");
    assert!(html.contains("據點以外"), "{html}");
    assert!(html.contains("總部"), "{html}");
    assert!(!html.contains("尚未設定據點網段"), "{html}");

    // 兩張都有預設閘道：條件 1
    let p2 = info(vec![
        nic("乙太網路", "ethernet", "10.1.2.3/24", Some("10.1.2.1")),
        nic("手機", "cellular", "100.64.0.9/10", Some("100.64.0.1")),
    ]);
    assert_eq!(put(&s, &a, &p2).await, 204);
    let (_, html) = s.page(&admin, &format!("{dev}/tab/network")).await;
    assert!(html.contains("兩條對外路徑"), "{html}");
    assert!(html.contains("行動網路"), "{html}");

    // 變更歷史記網卡的新增、移除
    let ch: Vec<(String, String)> = sqlx::query_as(
        "SELECT change, item_key FROM inventory_changes \
         WHERE device_id = $1 AND section = 'network' ORDER BY item_key, change",
    )
    .bind(a.device_id)
    .fetch_all(&s.pool)
    .await
    .unwrap();
    assert!(ch.contains(&("added".into(), "nic|手機".into())), "{ch:?}");
    assert!(
        ch.contains(&("removed".into(), "nic|Wi-Fi".into())),
        "{ch:?}"
    );
    assert!(
        ch.contains(&("updated".into(), "nic|乙太網路".into())),
        "{ch:?}"
    );
    let (_, html) = s.page(&admin, &format!("{dev}/tab/timeline")).await;
    assert!(html.contains("網路"), "{html}");

    // 範圍外的群組管理員看不到
    s.create_group_token("高雄", 1).await;
    let other = s.login_as("olga", Role::GroupAdmin, &["高雄"]).await;
    assert_eq!(s.page(&other, &format!("{dev}/tab/network")).await.0, 404);

    // 壞掉的 jsonb：分頁當成沒有資料
    sqlx::query("UPDATE device_network SET data = '{\"interfaces\": 5}' WHERE device_id = $1")
        .bind(a.device_id)
        .execute(&s.pool)
        .await
        .unwrap();
    let (_, html) = s.page(&admin, &format!("{dev}/tab/network")).await;
    assert!(html.contains("尚無網路資料"), "{html}");
}

#[sqlx::test(migrations = false)]
async fn every_address_is_searchable(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    checkin(&s, &a, BTreeMap::new(), &["10.1.2.3", "192.168.43.5"]).await;
    s.state.heartbeat.flush(&s.pool).await.unwrap();
    let admin = s.admin_client().await;
    let link = format!("/devices/{}", a.device_id);
    // 第二個位址也搜得到，清單滑過 IP 會顯示全部
    let (_, html) = s.page(&admin, "/devices?q=192.168.43").await;
    assert!(html.contains(&link), "{html}");
    assert!(html.contains("title=\"10.1.2.3, 192.168.43.5\""), "{html}");
    let (_, html) = s.page(&admin, "/devices?q=172.16.").await;
    assert!(!html.contains(&link), "{html}");
}

#[sqlx::test(migrations = false)]
async fn rejects_too_many_interfaces(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    checkin(&s, &a, BTreeMap::new(), &[]).await;
    let too_many = info(
        (0..=protocol::MAX_INTERFACES)
            .map(|i| nic(&format!("n{i}"), "ethernet", "10.0.0.1/24", None))
            .collect(),
    );
    assert_eq!(put(&s, &a, &too_many).await, 400);
}
