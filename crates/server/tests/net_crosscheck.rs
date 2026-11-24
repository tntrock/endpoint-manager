//! 竄改偵測第三期：網路端交叉比對（沒報到但在網路上、MAC 同時出現在兩個埠、IP 被別的 MAC 使用）。
mod common;

use common::TestServer;
use endpoint_server::netdev::{crosscheck, ingest};
use protocol::netdev::{ArpEntry, FdbEntry, NetData, NetPollKind};
use sqlx::PgPool;
use uuid::Uuid;

const PC: &str = "00:1b:2c:00:00:01";
const OTHER: &str = "00:1b:2c:00:00:99";

struct Env {
    s: TestServer,
    nd: i64,
    pc: Uuid,
}

/// 台北據點、一台交換器（埠 1、2 是端點埠，48 是上行）、一台電腦（MAC PC、IP 10.1.0.5）
async fn setup(pool: PgPool) -> Env {
    let s = TestServer::start(pool).await;
    let site: i64 = sqlx::query_scalar(
        "INSERT INTO sites (name, cidrs) VALUES ('台北', '{10.1.0.0/16}') RETURNING id",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap();
    let cred: i64 = sqlx::query_scalar(
        "INSERT INTO snmp_credentials (name, version, secret_enc) VALUES ('c', 'v2c', '\\x00') \
         RETURNING id",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap();
    let nd: i64 = sqlx::query_scalar(
        "INSERT INTO net_devices (name, site_id, address, credential_id) \
         VALUES ('3F 交換器', $1, '10.1.0.2', $2) RETURNING id",
    )
    .bind(site)
    .bind(cred)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO net_interfaces (device_id, if_index, name, if_type, admin_up, oper_up, role) \
         VALUES ($1, 1, 'Gi1/0/1', 6, true, true, 'auto_edge'), \
                ($1, 2, 'Gi1/0/2', 6, true, true, 'auto_edge'), \
                ($1, 48, 'Te1/1/1', 6, true, true, 'uplink')",
    )
    .bind(nd)
    .execute(&s.pool)
    .await
    .unwrap();
    let tok = s.create_group_token("研發", 1).await;
    let pc = s.enroll_ok(&tok, None, None).await.device_id;
    sqlx::query(
        "INSERT INTO device_network (device_id, data) VALUES ($1, \
         '{\"interfaces\":[{\"name\":\"eth0\",\"kind\":\"ethernet\",\"up\":true,\
           \"mac\":\"00:1b:2c:00:00:01\",\"addresses\":[\"10.1.0.5/24\"],\"gateways\":[],\
           \"dns\":[]}]}')",
    )
    .bind(pc)
    .execute(&s.pool)
    .await
    .unwrap();
    seen(&s, pc, 0).await;
    Env { s, nd, pc }
}

/// 電腦最後報到在幾分鐘前
async fn seen(s: &TestServer, pc: Uuid, minutes_ago: i32) {
    sqlx::query(
        "UPDATE devices SET last_seen_at = now() - make_interval(mins => $2), \
         ips = '{10.1.0.5}' WHERE id = $1",
    )
    .bind(pc)
    .bind(minutes_ago)
    .execute(&s.pool)
    .await
    .unwrap();
}

fn fdb(mac: &str, if_index: u32) -> FdbEntry {
    FdbEntry {
        mac: mac.into(),
        if_index,
        vlan: Some(10),
    }
}

fn arp(ip: &str, mac: &str) -> ArpEntry {
    ArpEntry {
        ip: ip.into(),
        mac: mac.into(),
        if_index: None,
    }
}

async fn poll(e: &Env, fdb: Vec<FdbEntry>, arp: Vec<ArpEntry>) {
    ingest::store(
        &e.s.pool,
        &NetData {
            device_id: e.nd,
            kind: NetPollKind::Tables,
            error: None,
            system: None,
            interfaces: vec![],
            fdb,
            arp,
        },
    )
    .await
    .unwrap();
}

/// (種類, 是否持續中)
async fn findings(e: &Env) -> Vec<(String, bool)> {
    sqlx::query_as(
        "SELECT kind, ended_at IS NULL FROM device_findings WHERE device_id = $1 ORDER BY id",
    )
    .bind(e.pc)
    .fetch_all(&e.s.pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = false)]
async fn silent_on_network(pool: PgPool) {
    let e = setup(pool).await;
    // 有報到：看得到也不算
    for _ in 0..3 {
        poll(&e, vec![fdb(PC, 1)], vec![]).await;
    }
    assert!(findings(&e).await.is_empty());

    // 一小時沒報到：連續 3 次看得到才標示；只在上行埠看得到的不算
    seen(&e.s, e.pc, 60).await;
    poll(&e, vec![fdb(PC, 48)], vec![]).await;
    poll(&e, vec![fdb(PC, 1)], vec![]).await;
    poll(&e, vec![fdb(PC, 1)], vec![]).await;
    assert!(findings(&e).await.is_empty());
    poll(&e, vec![fdb(PC, 1)], vec![]).await;
    assert_eq!(findings(&e).await, vec![("silent_on_network".into(), true)]);
    let sev: String = sqlx::query_scalar("SELECT severity FROM device_findings")
        .fetch_one(&e.s.pool)
        .await
        .unwrap();
    assert_eq!(sev, "high");
    let c = e.s.admin_client().await;
    let (_, tab) =
        e.s.page(&c, &format!("/devices/{}/tab/integrity", e.pc))
            .await;
    assert!(
        tab.contains(
            "Agent 沒有報到，但 3F 交換器 的 Gi1/0/1 一直看得到這台電腦（00:1b:2c:00:00:01）"
        ),
        "{tab}"
    );
    assert!(tab.contains("持續中"), "{tab}");

    // 交換器上看不到了：結束
    poll(&e, vec![], vec![]).await;
    assert_eq!(
        findings(&e).await,
        vec![("silent_on_network".into(), false)]
    );

    // 再一次，這次是 Agent 恢復報到而結束；之後再看到要重新累計
    for _ in 0..3 {
        poll(&e, vec![fdb(PC, 2)], vec![]).await;
    }
    assert_eq!(findings(&e).await.len(), 2);
    assert!(findings(&e).await[1].1);
    let mut conn = e.s.pool.acquire().await.unwrap();
    crosscheck::checked_in(&mut conn, &[e.pc]).await.unwrap();
    assert!(!findings(&e).await[1].1);
    poll(&e, vec![fdb(PC, 2)], vec![]).await;
    assert_eq!(findings(&e).await.len(), 2);
}

#[sqlx::test(migrations = false)]
async fn mac_on_two_ports(pool: PgPool) {
    let e = setup(pool).await;
    // 上行埠與端點埠：不算
    poll(&e, vec![fdb(PC, 1), fdb(PC, 48)], vec![]).await;
    poll(&e, vec![fdb(PC, 1), fdb(PC, 48)], vec![]).await;
    assert!(findings(&e).await.is_empty());
    // 換位置時短暫重疊一次：不算
    poll(&e, vec![fdb(PC, 1), fdb(PC, 2)], vec![]).await;
    poll(&e, vec![fdb(PC, 2)], vec![]).await;
    assert!(findings(&e).await.is_empty());
    // 連續兩次
    poll(&e, vec![fdb(PC, 1), fdb(PC, 2)], vec![]).await;
    poll(&e, vec![fdb(PC, 1), fdb(PC, 2)], vec![]).await;
    assert_eq!(findings(&e).await, vec![("mac_duplicate".into(), true)]);
    let c = e.s.admin_client().await;
    let (_, tab) =
        e.s.page(&c, &format!("/devices/{}/tab/integrity", e.pc))
            .await;
    assert!(
        tab.contains("MAC 00:1b:2c:00:00:01 同時出現在 3F 交換器 的 Gi1/0/1、Gi1/0/2"),
        "{tab}"
    );
    poll(&e, vec![fdb(PC, 2)], vec![]).await;
    assert_eq!(findings(&e).await, vec![("mac_duplicate".into(), false)]);

    // 多台裝置共用的 MAC（例如虛擬網卡）不比對
    let tok = e.s.create_group_token("其他", 1).await;
    let twin = e.s.enroll_ok(&tok, None, None).await.device_id;
    sqlx::query("INSERT INTO device_macs (device_id, mac) VALUES ($1, $2)")
        .bind(twin)
        .bind(PC)
        .execute(&e.s.pool)
        .await
        .unwrap();
    poll(&e, vec![fdb(PC, 1), fdb(PC, 2)], vec![]).await;
    poll(&e, vec![fdb(PC, 1), fdb(PC, 2)], vec![]).await;
    assert_eq!(findings(&e).await.len(), 1);
}

#[sqlx::test(migrations = false)]
async fn ip_used_by_another_mac(pool: PgPool) {
    let e = setup(pool).await;
    // 對到自己的 MAC、據點網段外的位址：不算
    for _ in 0..2 {
        poll(
            &e,
            vec![],
            vec![arp("10.1.0.5", PC), arp("192.168.0.5", OTHER)],
        )
        .await;
    }
    assert!(findings(&e).await.is_empty());
    // 只出現一次：不算
    poll(&e, vec![], vec![arp("10.1.0.5", OTHER)]).await;
    poll(&e, vec![], vec![arp("10.1.0.5", PC)]).await;
    assert!(findings(&e).await.is_empty());
    // 連續兩次
    poll(&e, vec![], vec![arp("10.1.0.5", OTHER)]).await;
    poll(&e, vec![], vec![arp("10.1.0.5", OTHER)]).await;
    assert_eq!(findings(&e).await, vec![("ip_conflict".into(), true)]);
    let c = e.s.admin_client().await;
    let (_, tab) =
        e.s.page(&c, &format!("/devices/{}/tab/integrity", e.pc))
            .await;
    assert!(
        tab.contains(
            "這台回報的 IP 10.1.0.5，在 3F 交換器 的 ARP 表對到別的 MAC 00:1b:2c:00:00:99"
        ),
        "{tab}"
    );
    // 很久沒報到的裝置不比對（回報的 IP 可能已經過時）：結束
    seen(&e.s, e.pc, 60).await;
    poll(&e, vec![], vec![arp("10.1.0.5", OTHER)]).await;
    assert_eq!(findings(&e).await, vec![("ip_conflict".into(), false)]);
}
