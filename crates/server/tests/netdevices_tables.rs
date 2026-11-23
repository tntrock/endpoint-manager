//! 網路設備第二期：MAC 位址表、電腦的網路位置、未管理設備、已知標記、埠的角色。
mod common;

use common::{TestServer, csrf_from};
use endpoint_server::netdev::ingest;
use endpoint_server::web::auth::Role;
use protocol::netdev::{ArpEntry, FdbEntry, NetData, NetPollKind};
use sqlx::PgPool;
use uuid::Uuid;

const PC: &str = "00:1b:2c:00:00:01";
/// 00:00:0c 是 Cisco
const PRINTER: &str = "00:00:0c:11:22:33";
/// 第一個位元組的第 2 個位元是 1：隨機 MAC
const PHONE: &str = "da:a1:19:00:00:07";

struct Env {
    s: TestServer,
    admin: reqwest::Client,
    t: String,
    nd: i64,
    pc: Uuid,
}

async fn post(
    s: &TestServer,
    c: &reqwest::Client,
    path: &str,
    form: &[(&str, &str)],
) -> (u16, String, String) {
    let r = c.post(s.web_url(path)).form(form).send().await.unwrap();
    let status = r.status().as_u16();
    let loc = r
        .headers()
        .get("location")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    (status, loc, r.text().await.unwrap())
}

/// 台北據點（有快取）、一台交換器（埠 1、2 是端點埠，48 是上行）、一台在群組「研發」的電腦
async fn setup(pool: PgPool) -> Env {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, "/netdevices").await;
    let t = csrf_from(&html);
    let site: i64 = sqlx::query_scalar(
        "INSERT INTO sites (name, cidrs) VALUES ('台北', '{10.1.0.0/16}') RETURNING id",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO caches (name, site_id, url, dns_names, csr_pem, poll_secret_hash, status) \
         VALUES ('tp', $1, 'https://c:8443', ARRAY['c'], 'csr', 'x', 'active')",
    )
    .bind(site)
    .execute(&s.pool)
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
        "INSERT INTO net_devices (name, site_id, address, credential_id, last_polled_at, \
                last_ok_at) VALUES ('3F 交換器', $1, '10.1.0.2', $2, now(), now()) RETURNING id",
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
                ($1, 48, 'Te1/1/1', 6, true, true, 'auto_uplink')",
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
           \"mac\":\"00:1B:2C:00:00:01\",\"addresses\":[\"10.1.0.5/24\"],\"gateways\":[],\
           \"dns\":[]},{\"name\":\"bad\",\"kind\":\"virtual\",\"up\":false,\"mac\":\"x\",\
           \"addresses\":[],\"gateways\":[],\"dns\":[]}]}')",
    )
    .bind(pc)
    .execute(&s.pool)
    .await
    .unwrap();
    Env {
        s,
        admin,
        t,
        nd,
        pc,
    }
}

fn fdb(mac: &str, if_index: u32, vlan: Option<u32>) -> FdbEntry {
    FdbEntry {
        mac: mac.into(),
        if_index,
        vlan,
    }
}

/// 一輪 MAC 表：電腦在 pc_port，印表機與手機在埠 2，上行埠有核心交換器學到的位址
async fn round(e: &Env, pc_port: u32) {
    let mut f = vec![
        fdb(&PC.to_uppercase(), pc_port, Some(10)),
        fdb(PRINTER, 2, Some(20)),
        fdb(PHONE, 2, None),
        fdb("not a mac", 2, None),
    ];
    f.extend((0..12).map(|i| fdb(&format!("00:50:56:00:01:{i:02x}"), 48, Some(1))));
    ingest::store(
        &e.s.pool,
        &NetData {
            device_id: e.nd,
            kind: NetPollKind::Tables,
            error: None,
            system: None,
            interfaces: vec![],
            fdb: f,
            arp: vec![
                ArpEntry {
                    ip: "10.1.0.5".into(),
                    mac: PC.into(),
                    if_index: None,
                },
                ArpEntry {
                    ip: "10.1.0.9".into(),
                    mac: PRINTER.into(),
                    if_index: Some(5),
                },
                // 據點網段外、只在 ARP 表：不算
                ArpEntry {
                    ip: "192.168.9.9".into(),
                    mac: "00:aa:bb:cc:dd:ee".into(),
                    if_index: None,
                },
                // 據點網段內、交換器 MAC 表沒有：只在 ARP 表
                ArpEntry {
                    ip: "10.1.7.7".into(),
                    mac: "00:aa:bb:00:00:77".into(),
                    if_index: None,
                },
                ArpEntry {
                    ip: "bad ip".into(),
                    mac: PC.into(),
                    if_index: None,
                },
            ],
        },
    )
    .await
    .unwrap();
}

#[sqlx::test(migrations = false)]
async fn locations_and_port_roles(pool: PgPool) {
    let e = setup(pool).await;
    let (s, admin) = (&e.s, &e.admin);
    // 觸發器同步了電腦的 MAC（格式不對的略過）
    let macs: Vec<String> = sqlx::query_scalar("SELECT mac FROM device_macs")
        .fetch_all(&s.pool)
        .await
        .unwrap();
    assert_eq!(macs, vec![PC.to_string()]);

    round(&e, 1).await;
    let counts: Vec<(i64, i32)> = sqlx::query_as(
        "SELECT if_index, mac_count FROM net_interfaces WHERE device_id = $1 ORDER BY if_index",
    )
    .bind(e.nd)
    .fetch_all(&s.pool)
    .await
    .unwrap();
    assert_eq!(counts, vec![(1, 1), (2, 2), (48, 12)]);

    // 電腦的網路分頁
    let tab = format!("/devices/{}/tab/network", e.pc);
    let (st, html) = s.page(admin, &tab).await;
    assert_eq!(st, 200);
    assert!(html.contains("網路位置"));
    assert!(html.contains(&format!("/netdevices/{}", e.nd)) && html.contains("3F 交換器"));
    assert!(html.contains("Gi1/0/1") && html.contains(PC));
    // 群組管理員看得到位置，但沒有連到網路設備頁
    let ga = s.login_as("ga", Role::GroupAdmin, &["研發"]).await;
    let (st, html) = s.page(&ga, &tab).await;
    assert_eq!(st, 200);
    assert!(html.contains("3F 交換器") && !html.contains("/netdevices/"));

    // 網路設備詳情：埠 1 接著這台電腦，埠 2 有 2 個 MAC
    let (_, html) = s.page(admin, &format!("/netdevices/{}", e.nd)).await;
    assert!(html.contains(&format!("/devices/{}", e.pc)) && html.contains("PC-001"));
    assert!(html.contains("2 個 MAC"));
    assert!(html.contains("依 LLDP 鄰居判斷"));

    // 搬到埠 2：結束舊的一段，時間軸與位置紀錄都看得到
    round(&e, 2).await;
    let rows: Vec<(String, bool)> =
        sqlx::query_as("SELECT port_name, ended_at IS NULL FROM endpoint_locations ORDER BY id")
            .fetch_all(&s.pool)
            .await
            .unwrap();
    assert_eq!(
        rows,
        vec![("Gi1/0/1".into(), false), ("Gi1/0/2".into(), true)]
    );
    // 同一個位置再看到一次不會多一段
    round(&e, 2).await;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM endpoint_locations")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 2);
    let (_, html) = s.page(admin, &tab).await;
    assert!(html.contains("位置紀錄"));
    let (_, html) = s.page(admin, &format!("/devices/{}", e.pc)).await;
    assert!(!html.is_empty());
    let (st, html) = s
        .page(admin, &format!("/devices/{}/tab/timeline", e.pc))
        .await;
    assert_eq!(st, 200);
    assert!(html.contains("網路位置：3F 交換器 Gi1/0/2"), "{html}");

    // 把埠 2 設成上行：電腦只在上行埠看到 → 顯示「經由上行埠」
    let role = format!("/netdevices/{}/ports/2/role", e.nd);
    let (st, loc, _) = post(s, admin, &role, &[("csrf", &e.t), ("role", "uplink")]).await;
    assert_eq!(
        (st, loc),
        (303, format!("/netdevices/{}?role_saved=true#port-2", e.nd))
    );
    let (_, html) = s
        .page(admin, &format!("/netdevices/{}?role_saved=true", e.nd))
        .await;
    assert!(html.contains("已儲存埠的角色") && html.contains("管理員指定"));
    assert!(html.contains(r#"<option value="uplink" selected>"#));
    sqlx::query("UPDATE endpoint_locations SET ended_at = now()")
        .execute(&s.pool)
        .await
        .unwrap();
    round(&e, 2).await;
    let open: i64 =
        sqlx::query_scalar("SELECT count(*) FROM endpoint_locations WHERE ended_at IS NULL")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(open, 0, "上行埠不算位置");
    let (_, html) = s.page(admin, &tab).await;
    assert!(html.contains("經由上行埠"));

    // 改回自動、改成端點
    for r in ["auto", "edge"] {
        let (st, _, _) = post(s, admin, &role, &[("csrf", &e.t), ("role", r)]).await;
        assert_eq!(st, 303);
    }
    let r: String =
        sqlx::query_scalar("SELECT role FROM net_interfaces WHERE device_id = $1 AND if_index = 2")
            .bind(e.nd)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(r, "edge");
    // LLDP 判斷的上行埠改回自動時保留
    let up = format!("/netdevices/{}/ports/48/role", e.nd);
    post(s, admin, &up, &[("csrf", &e.t), ("role", "auto")]).await;
    let r: String = sqlx::query_scalar(
        "SELECT role FROM net_interfaces WHERE device_id = $1 AND if_index = 48",
    )
    .bind(e.nd)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(r, "auto_uplink");
    let (st, _, _) = post(s, admin, &role, &[("csrf", &e.t), ("role", "core")]).await;
    assert_eq!(st, 422);
    let (st, _, _) = post(
        s,
        admin,
        &format!("/netdevices/{}/ports/99/role", e.nd),
        &[("csrf", &e.t), ("role", "edge")],
    )
    .await;
    assert_eq!(st, 404);
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'netdevice_port_role'")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(n, 4);

    // 群組管理員不能改
    let t = csrf_from(&s.page(&ga, "/").await.1);
    assert_eq!(
        post(s, &ga, &role, &[("csrf", &t), ("role", "edge")])
            .await
            .0,
        403
    );

    // 資料保留：30 天沒看到的 MAC 表刪除
    sqlx::query("UPDATE net_mac_sightings SET last_seen = now() - interval '31 days'")
        .execute(&s.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE net_arp SET last_seen = now() - interval '31 days'")
        .execute(&s.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE endpoint_locations SET ended_at = now() - interval '400 days'")
        .execute(&s.pool)
        .await
        .unwrap();
    endpoint_server::retention::purge(&s.pool).await.unwrap();
    let left: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM net_mac_sightings), (SELECT count(*) FROM net_arp), \
                (SELECT count(*) FROM endpoint_locations)",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(left, (0, 0, 0));
}

#[sqlx::test(migrations = false)]
async fn unmanaged_and_known(pool: PgPool) {
    let e = setup(pool).await;
    let (s, admin) = (&e.s, &e.admin);
    round(&e, 1).await;

    let (st, html) = s.page(admin, "/netdevices/unmanaged").await;
    assert_eq!(st, 200);
    // 印表機（Cisco、有 IP）、手機（隨機 MAC）、只在 ARP 表的一台；不含電腦、上行埠、網段外
    assert!(html.contains(PRINTER) && html.contains("Cisco") && html.contains("10.1.0.9"));
    assert!(html.contains(PHONE) && html.contains("隨機 MAC"));
    assert!(html.contains("00:aa:bb:00:00:77") && html.contains("只在 ARP 表"));
    assert!(!html.contains(PC) && !html.contains("00:50:56:00:01:00"));
    assert!(!html.contains("00:aa:bb:cc:dd:ee"));
    assert!(html.contains("共 3 台"));
    assert!(html.contains(">新<"));

    // 篩選
    let (_, html) = s.page(admin, "/netdevices/unmanaged?q=11:22").await;
    assert!(html.contains(PRINTER) && !html.contains(PHONE));
    assert!(html.contains("全部 3 台"));
    let (_, html) = s.page(admin, "/netdevices/unmanaged?q=10.1.7").await;
    assert!(html.contains("00:aa:bb:00:00:77") && !html.contains(PRINTER));
    let other: i64 = sqlx::query_scalar(
        "INSERT INTO sites (name, cidrs) VALUES ('台中', '{10.2.0.0/16}') RETURNING id",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap();
    let (_, html) = s
        .page(admin, &format!("/netdevices/unmanaged?site={other}"))
        .await;
    assert!(html.contains("沒有未管理設備"));

    // 總覽
    let (_, html) = s.page(admin, "/").await;
    assert!(html.contains("新出現的未管理設備"));

    let nd = e.nd.to_string();
    let mark =
        |mac: &'static str, kind: &'static str, if_index: &'static str, note: &'static str| {
            vec![
                ("csrf", e.t.clone()),
                ("mac", mac.to_string()),
                ("net_device_id", nd.clone()),
                ("if_index", if_index.to_string()),
                ("kind", kind.to_string()),
                ("note", note.to_string()),
            ]
        };
    let send = |f: Vec<(&'static str, String)>| {
        let c = admin.clone();
        let url = s.web_url("/netdevices/unmanaged/known");
        async move {
            let r = c.post(url).form(&f).send().await.unwrap();
            let loc = r
                .headers()
                .get("location")
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap_or_default();
            (r.status().as_u16(), loc)
        }
    };
    // 錯誤：沒填說明、範圍不對、只在 ARP 表的不能標記埠、MAC 格式
    for (f, msg) in [
        (mark(PRINTER, "mac", "2", " "), "請填寫說明"),
        (mark(PRINTER, "all", "2", "x"), "請選擇標記範圍"),
        (mark("00:aa:bb:00:00:77", "port", "", "x"), "沒有交換器的埠"),
        (mark("zz", "mac", "2", "x"), "MAC 位址格式不正確"),
    ] {
        let (st, loc) = send(f).await;
        assert_eq!(st, 303);
        assert!(loc.starts_with("/netdevices/unmanaged?error="), "{loc}");
        let (_, html) = s.page(admin, &loc).await;
        assert!(html.contains(msg), "{msg}");
    }

    // 同廠牌：印表機不再列出
    let (st, loc) = send(mark(PRINTER, "oui", "2", "全公司的印表機")).await;
    assert_eq!(
        (st, loc.as_str()),
        (303, "/netdevices/unmanaged?saved=true")
    );
    let (_, html) = s.page(admin, "/netdevices/unmanaged?saved=true").await;
    assert!(html.contains("已標記為已知") && !html.contains(PRINTER));
    // 這個埠：手機也不再列出
    send(mark(PHONE, "port", "2", "會議室")).await;
    // 這個 MAC
    send(mark("00:aa:bb:00:00:77", "mac", "", "門禁")).await;
    let (_, html) = s.page(admin, "/netdevices/unmanaged").await;
    assert!(html.contains("沒有未管理設備"), "{html}");

    // 已知清單
    let (st, html) = s.page(admin, "/netdevices/known").await;
    assert_eq!(st, 200);
    assert!(html.contains("同廠牌（前綴）"));
    assert!(html.contains("00000C") && html.contains("全公司的印表機"));
    assert!(html.contains("3F 交換器 Gi1/0/2") && html.contains("會議室"));
    assert!(html.contains("這個 MAC") && html.contains("門禁"));
    // 已刪除設備的埠
    sqlx::query(
        "INSERT INTO net_known_macs (match, value, note, created_by) \
         VALUES ('port', '9999:1', '舊', 'x'), ('port', 'junk', '壞', 'x')",
    )
    .execute(&s.pool)
    .await
    .unwrap();
    let (_, html) = s.page(admin, "/netdevices/known").await;
    assert!(html.contains("（已刪除的設備）埠 1") && html.contains("junk"));

    // 取消標記
    // 取消「這個埠」：手機回來，印表機仍被「同廠牌」排除
    let id: i64 = sqlx::query_scalar("SELECT id FROM net_known_macs WHERE match = 'port' AND value <> 'junk' AND value <> '9999:1'")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    let (st, loc, _) = post(
        s,
        admin,
        &format!("/netdevices/known/{id}/delete"),
        &[("csrf", &e.t)],
    )
    .await;
    assert_eq!((st, loc.as_str()), (303, "/netdevices/known"));
    let (_, html) = s.page(admin, "/netdevices/unmanaged").await;
    assert!(html.contains(PHONE) && !html.contains(PRINTER));
    assert_eq!(
        post(
            s,
            admin,
            "/netdevices/known/99999/delete",
            &[("csrf", &e.t)]
        )
        .await
        .0,
        404
    );
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action LIKE 'netdevice_known_%'")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(n, 4);

    // 電腦退役後也算未管理
    sqlx::query("UPDATE devices SET status = 'retired' WHERE id = $1")
        .bind(e.pc)
        .execute(&s.pool)
        .await
        .unwrap();
    let (_, html) = s.page(admin, "/netdevices/unmanaged").await;
    assert!(html.contains(PC));

    // 權限
    let ga = s.login_as("ga", Role::GroupAdmin, &["研發"]).await;
    for p in ["/netdevices/unmanaged", "/netdevices/known"] {
        assert_eq!(s.page(&ga, p).await.0, 403, "{p}");
    }
    let t = csrf_from(&s.page(&ga, "/").await.1);
    for p in ["/netdevices/unmanaged/known", "/netdevices/known/1/delete"] {
        assert_eq!(post(s, &ga, p, &[("csrf", &t)]).await.0, 403, "{p}");
    }
}
