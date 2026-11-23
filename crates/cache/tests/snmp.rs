//! 網路設備查詢：在同一個行程啟動假的 SNMP 交換器（v2c 與 v3），再加上真實中央的端對端測試。
mod common;

use std::collections::BTreeMap;
use std::ops::Bound;
use std::sync::Arc;
use std::time::Duration;

use async_snmp::handler::{
    BoxFuture, GetNextResult, GetResult, HandlerResult, MibHandler, RequestContext,
};
use async_snmp::v3::{AuthProtocol, AuthoritativeEngine, PrivProtocol, generate_engine_id};
use async_snmp::{Agent, Oid, Value, VarBind};
use bytes::Bytes;
use endpoint_cache::snmp::{self, collect, parse, tables};
use protocol::netdev::{
    CiscoVlanMode, NetPollKind, SnmpAuthProtocol, SnmpCredential, SnmpPrivProtocol, SnmpTarget,
};
use sqlx::PgPool;
use tokio::sync::watch;

struct MapHandler(BTreeMap<Oid, Value>);

impl MibHandler for MapHandler {
    fn get<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetResult>> {
        let r = match self.0.get(oid) {
            Some(v) => GetResult::Value(v.clone()),
            None => GetResult::NoSuchInstance,
        };
        Box::pin(async move { Ok(r) })
    }

    fn get_next<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
        let r = match self
            .0
            .range((Bound::Excluded(oid.clone()), Bound::Unbounded))
            .next()
        {
            Some((o, v)) => GetNextResult::Value(VarBind {
                oid: o.clone(),
                value: v.clone(),
            }),
            None => GetNextResult::EndOfMibView,
        };
        Box::pin(async move { Ok(r) })
    }
}

fn s(v: &str) -> Value {
    Value::OctetString(Bytes::from(v.as_bytes().to_vec()))
}

fn put(m: &mut BTreeMap<Oid, Value>, base: &[u32], tail: &[u32], v: Value) {
    let mut arcs = base.to_vec();
    arcs.extend_from_slice(tail);
    m.insert(Oid::from_slice(&arcs), v);
}

/// 一台 3 個埠的交換器：埠 3 往上接核心交換器（LLDP）
fn switch_mib() -> BTreeMap<Oid, Value> {
    let mut m = BTreeMap::new();
    put(&mut m, parse::SYS_DESCR, &[], s("Test Switch OS 1.2"));
    put(
        &mut m,
        parse::SYS_OBJECT_ID,
        &[],
        Value::ObjectIdentifier(Oid::from_slice(&[1, 3, 6, 1, 4, 1, 99999, 1])),
    );
    put(&mut m, parse::SYS_UPTIME, &[], Value::TimeTicks(8_640_000));
    put(&mut m, parse::SYS_CONTACT, &[], s("IT"));
    put(&mut m, parse::SYS_NAME, &[], s("sw-test"));
    put(&mut m, parse::SYS_LOCATION, &[], s("2F"));
    put(&mut m, parse::ENT_PHYSICAL, &[5, 1], Value::Integer(3));
    put(&mut m, parse::ENT_PHYSICAL, &[10, 1], s("1.2.3"));
    put(&mut m, parse::ENT_PHYSICAL, &[11, 1], s("SN0001"));
    put(&mut m, parse::ENT_PHYSICAL, &[13, 1], s("TS-24"));
    for i in 1..=3u32 {
        put(&mut m, parse::IF_ENTRY, &[2, i], s(&format!("port{i}")));
        put(&mut m, parse::IF_ENTRY, &[3, i], Value::Integer(6));
        put(
            &mut m,
            parse::IF_ENTRY,
            &[5, i],
            Value::Gauge32(1_000_000_000),
        );
        put(
            &mut m,
            parse::IF_ENTRY,
            &[6, i],
            Value::OctetString(Bytes::from(vec![2, 0, 0, 0, 0, i as u8])),
        );
        put(&mut m, parse::IF_ENTRY, &[7, i], Value::Integer(1));
        put(
            &mut m,
            parse::IF_ENTRY,
            &[8, i],
            Value::Integer(if i == 2 { 2 } else { 1 }),
        );
        put(&mut m, parse::IF_ENTRY, &[9, i], Value::TimeTicks(100));
        put(&mut m, parse::IFX_ENTRY, &[1, i], s(&format!("Gi0/{i}")));
        put(&mut m, parse::IFX_ENTRY, &[15, i], Value::Gauge32(1000));
        put(&mut m, parse::IFX_ENTRY, &[18, i], s(""));
        put(
            &mut m,
            parse::BASE_PORT_IFINDEX,
            &[i],
            Value::Integer(i as i32),
        );
        put(&mut m, parse::Q_PVID, &[i], Value::Gauge32(10 * i));
    }
    put(&mut m, parse::LLDP_LOC_PORT, &[3, 3], s("Gi0/3"));
    put(&mut m, parse::LLDP_LOC_PORT, &[4, 3], s("port3"));
    for (col, v) in [
        (4, Value::Integer(7)),
        (5, s("core")),
        (6, Value::Integer(5)),
        (7, s("Te1/0/1")),
        (8, s("to sw-test")),
        (9, s("core-sw")),
        (12, Value::OctetString(Bytes::from(vec![0x28u8, 0]))),
    ] {
        put(&mut m, parse::LLDP_REM, &[col, 0, 3, 1], v);
    }
    put(
        &mut m,
        parse::LLDP_REM_MAN_ADDR,
        &[0, 3, 1, 1, 4, 10, 9, 9, 1],
        Value::Integer(2),
    );
    // MAC 位址表（Q-BRIDGE）：埠 1 接電腦、埠 2 接印表機、埠 3（上行）學到 12 個 MAC
    put(&mut m, tables::Q_VLAN_FDB_ID, &[0, 10], Value::Gauge32(10));
    let mut fdb = |mac: [u32; 6], port: i32| {
        let mut idx = vec![10];
        idx.extend(mac);
        put(&mut m, tables::Q_FDB_PORT, &idx, Value::Integer(port));
    };
    fdb(PC, 1);
    fdb(PRINTER, 2);
    for i in 0..12 {
        fdb([0, 0x50, 0x56, 0, 1, i], 3);
    }
    // ARP 表
    let pc_mac = Value::OctetString(Bytes::from(PC.map(|b| b as u8).to_vec()));
    let printer_mac = Value::OctetString(Bytes::from(PRINTER.map(|b| b as u8).to_vec()));
    put(
        &mut m,
        tables::IP_NET_TO_PHYS,
        &[3, 1, 4, 10, 0, 0, 5],
        pc_mac,
    );
    put(
        &mut m,
        tables::IP_NET_TO_PHYS,
        &[3, 1, 4, 10, 0, 0, 9],
        printer_mac,
    );
    m
}

const PC: [u32; 6] = [0, 0x1b, 0x2c, 0, 0, 1];
/// 00:00:0c 是 Cisco 的 OUI
const PRINTER: [u32; 6] = [0, 0, 0x0c, 0x11, 0x22, 0x33];

/// Cisco 交換器：沒有 Q-BRIDGE，MAC 位址表要用 community@VLAN 逐個 VLAN 查
fn cisco_mib() -> BTreeMap<Oid, Value> {
    let mut m = BTreeMap::new();
    put(
        &mut m,
        parse::SYS_OBJECT_ID,
        &[],
        Value::ObjectIdentifier(Oid::from_slice(&[1, 3, 6, 1, 4, 1, 9, 1, 1208])),
    );
    put(
        &mut m,
        parse::BASE_PORT_IFINDEX,
        &[5],
        Value::Integer(10105),
    );
    for v in [10, 20, 1002] {
        put(&mut m, tables::CISCO_VLAN_STATE, &[1, v], Value::Integer(1));
    }
    let mut idx = PC.to_vec();
    put(&mut m, tables::D_FDB_PORT, &idx, Value::Integer(5));
    idx = vec![0, 0x1b, 0x2c, 0, 0, 2];
    put(&mut m, tables::D_FDB_PORT, &idx, Value::Integer(5));
    put(&mut m, tables::D_FDB_STATUS, &idx, Value::Integer(4));
    // 舊表的 ARP
    put(
        &mut m,
        tables::IP_NET_TO_MEDIA,
        &[1, 10, 0, 0, 5],
        Value::OctetString(Bytes::from(PC.map(|b| b as u8).to_vec())),
    );
    m
}

struct FakeSwitch {
    agent: Agent,
    port: u16,
}

impl Drop for FakeSwitch {
    fn drop(&mut self) {
        self.agent.cancel();
    }
}

async fn fake_switch() -> FakeSwitch {
    fake_switch_with(switch_mib(), &[]).await
}

async fn fake_switch_with(all: BTreeMap<Oid, Value>, communities: &[&str]) -> FakeSwitch {
    let lldp = Oid::from_slice(&[1, 0, 8802]);
    let (l, rest): (BTreeMap<_, _>, BTreeMap<_, _>) =
        all.into_iter().partition(|(o, _)| o.starts_with(&lldp));
    let engine = AuthoritativeEngine::install(generate_engine_id().unwrap(), |_| {
        Ok::<(), std::convert::Infallible>(())
    })
    .unwrap();
    let mut b = Agent::builder().bind("127.0.0.1:0").community(b"public");
    for c in communities {
        b = b.community(c.as_bytes().to_vec());
    }
    let agent = b
        .authoritative_engine(engine)
        .usm_user("mon-sha1", |u| {
            u.auth_priv(
                AuthProtocol::Sha1,
                b"authpass123",
                PrivProtocol::Aes256Blumenthal,
                b"privpass123",
            )
        })
        .unwrap()
        .usm_user("mon-sha256", |u| {
            u.auth_priv(
                AuthProtocol::Sha256,
                b"authpass123",
                PrivProtocol::Aes128,
                b"privpass123",
            )
        })
        .unwrap()
        .usm_user("mon-cisco", |u| {
            u.auth_priv(
                AuthProtocol::Sha256,
                b"authpass123",
                PrivProtocol::Aes256Reeder,
                b"privpass123",
            )
        })
        .unwrap()
        .handler(Oid::from_slice(&[1, 3, 6]), Arc::new(MapHandler(rest)))
        .handler(lldp, Arc::new(MapHandler(l)))
        .without_builtin_handlers()
        .allow_all_access()
        .build()
        .await
        .unwrap();
    let port = agent.local_addr().port();
    let a = agent.clone();
    tokio::spawn(async move {
        let _ = a.run().await;
    });
    FakeSwitch { agent, port }
}

fn fast() -> collect::Limits {
    collect::Limits {
        request_timeout: Duration::from_millis(300),
        retries: 0,
        deadline: Duration::from_secs(20),
        ..Default::default()
    }
}

fn target(id: i64, port: u16, credential: SnmpCredential) -> SnmpTarget {
    SnmpTarget {
        id,
        address: "127.0.0.1".into(),
        port,
        credential,
        cisco_vlan: CiscoVlanMode::Auto,
        poll_now: false,
    }
}

fn v3(user: &str, auth: SnmpAuthProtocol, privacy: SnmpPrivProtocol, pass: &str) -> SnmpCredential {
    SnmpCredential::V3 {
        user: user.into(),
        auth,
        auth_pass: pass.into(),
        privacy,
        priv_pass: "privpass123".into(),
    }
}

fn v2c(c: &str) -> SnmpCredential {
    SnmpCredential::V2c {
        community: c.into(),
    }
}

#[tokio::test]
async fn polls_v2c_and_v3() {
    let sw = fake_switch().await;
    for (n, cred) in [
        v2c("public"),
        v3(
            "mon-sha1",
            SnmpAuthProtocol::Sha1,
            SnmpPrivProtocol::Aes256,
            "authpass123",
        ),
        v3(
            "mon-sha256",
            SnmpAuthProtocol::Sha256,
            SnmpPrivProtocol::Aes128,
            "authpass123",
        ),
        v3(
            "mon-cisco",
            SnmpAuthProtocol::Sha256,
            SnmpPrivProtocol::Aes256Cisco,
            "authpass123",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let d = collect::poll_system(&target(n as i64 + 1, sw.port, cred), &fast()).await;
        assert_eq!(d.error, None, "{n}");
        assert_eq!(d.device_id, n as i64 + 1);
        let sys = d.system.unwrap();
        assert_eq!(sys.name, "sw-test");
        assert_eq!(sys.model, "TS-24");
        assert_eq!(sys.serial, "SN0001");
        assert_eq!(sys.firmware, "1.2.3");
        assert_eq!(sys.uptime_secs, 86_400);
        assert_eq!(sys.object_id, "1.3.6.1.4.1.99999.1");
        assert_eq!(d.interfaces.len(), 3);
        let p2 = &d.interfaces[1];
        assert_eq!(
            (p2.name.as_str(), p2.oper_up, p2.pvid),
            ("Gi0/2", false, Some(20))
        );
        let p3 = &d.interfaces[2];
        assert_eq!(p3.lldp.len(), 1);
        assert_eq!(p3.lldp[0].sys_name, "core-sw");
        assert_eq!(p3.lldp[0].mgmt_address.as_deref(), Some("10.9.9.1"));
        assert!(p3.lldp[0].is_switch_or_router);
    }
}

#[tokio::test]
async fn wrong_credentials_are_explained() {
    let sw = fake_switch().await;
    let d = collect::poll_system(&target(1, sw.port, v2c("wrong")), &fast()).await;
    let e = d.error.unwrap();
    assert!(e.starts_with("逾時"), "{e}");
    assert!(d.system.is_none());
    let d = collect::poll_system(
        &target(
            1,
            sw.port,
            v3(
                "mon-sha256",
                SnmpAuthProtocol::Sha256,
                SnmpPrivProtocol::Aes128,
                "wrongpass1",
            ),
        ),
        &fast(),
    )
    .await;
    assert!(d.error.is_some());
    let d = collect::poll_system(
        &target(
            1,
            sw.port,
            v3(
                "nobody",
                SnmpAuthProtocol::Sha256,
                SnmpPrivProtocol::Aes128,
                "authpass123",
            ),
        ),
        &fast(),
    )
    .await;
    let e = d.error.unwrap();
    assert!(e.contains("驗證失敗") || e.starts_with("逾時"), "{e}");
    // 密碼太短：USM 不接受
    let d = collect::poll_system(
        &target(
            1,
            sw.port,
            v3(
                "mon-sha256",
                SnmpAuthProtocol::Sha256,
                SnmpPrivProtocol::Aes128,
                "short",
            ),
        ),
        &fast(),
    )
    .await;
    assert!(d.error.is_some());
    // 整輪逾時
    let l = collect::Limits {
        deadline: Duration::from_millis(1),
        ..fast()
    };
    let d = collect::poll_system(&target(1, sw.port, v2c("public")), &l).await;
    assert!(d.error.unwrap().contains("已中止"));
}

#[tokio::test]
async fn polls_mac_and_arp_tables() {
    let sw = fake_switch().await;
    for cred in [
        v2c("public"),
        v3(
            "mon-sha256",
            SnmpAuthProtocol::Sha256,
            SnmpPrivProtocol::Aes128,
            "authpass123",
        ),
    ] {
        let d = collect::poll(&target(7, sw.port, cred), NetPollKind::Tables, &fast()).await;
        assert_eq!(d.error, None);
        assert_eq!((d.device_id, d.kind), (7, NetPollKind::Tables));
        assert!(d.system.is_none() && d.interfaces.is_empty());
        assert_eq!(d.fdb.len(), 14);
        let pc = d.fdb.iter().find(|e| e.mac == "00:1b:2c:00:00:01").unwrap();
        assert_eq!((pc.if_index, pc.vlan), (1, Some(10)));
        assert_eq!(d.fdb.iter().filter(|e| e.if_index == 3).count(), 12);
        assert_eq!(d.arp.len(), 2);
        assert!(
            d.arp
                .iter()
                .any(|a| a.ip == "10.0.0.9" && a.mac == "00:00:0c:11:22:33")
        );
    }
    // 連不到：錯誤說明
    let d = collect::poll(
        &target(7, sw.port, v2c("wrong")),
        NetPollKind::Tables,
        &fast(),
    )
    .await;
    assert!(d.error.unwrap().starts_with("逾時"));
}

#[tokio::test]
async fn cisco_per_vlan_mac_table() {
    let sw = fake_switch_with(cisco_mib(), &["public@10", "public@20"]).await;
    let mut t = target(9, sw.port, v2c("public"));
    let d = collect::poll(&t, NetPollKind::Tables, &fast()).await;
    assert_eq!(d.error, None);
    // 1002 是保留 VLAN 不查；status 4（設備自己）不算
    let mut got: Vec<(String, u32, Option<u32>)> = d
        .fdb
        .iter()
        .map(|e| (e.mac.clone(), e.if_index, e.vlan))
        .collect();
    got.sort();
    assert_eq!(
        got,
        vec![
            ("00:1b:2c:00:00:01".into(), 10105, Some(10)),
            ("00:1b:2c:00:00:01".into(), 10105, Some(20)),
        ]
    );
    assert_eq!(d.arp.len(), 1);
    assert_eq!(d.arp[0].ip, "10.0.0.5");
    // 關閉逐 VLAN 查詢：直接查 BRIDGE-MIB，不知道 VLAN
    t.cisco_vlan = CiscoVlanMode::Off;
    let d = collect::poll(&t, NetPollKind::Tables, &fast()).await;
    assert_eq!(d.fdb.len(), 1);
    assert_eq!(d.fdb[0].vlan, None);
}

async fn wait_for<F, Fut>(mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..200 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out");
}

/// 中央下發工作 → 快取查詢 → 上傳 → 中央存下；連不到的設備記錄失敗
#[sqlx::test(migrations = false)]
async fn cache_polls_devices_and_central_stores_results(pool: PgPool) {
    use endpoint_server::netdev::{self, CredentialInput, DeviceInput};
    let e = common::central(pool).await;
    let sw = fake_switch().await;
    let (dir, enrollment) = common::approved_cache(&e).await;
    let site: i64 = sqlx::query_scalar("SELECT site_id FROM caches WHERE id = $1")
        .bind(enrollment.cache_id)
        .fetch_one(&e.pool)
        .await
        .unwrap();
    let cred = netdev::create_credential(
        &e.pool,
        e.state.secrets.as_deref(),
        &CredentialInput {
            name: "唯讀".into(),
            version: "v3".into(),
            user: "mon-sha256".into(),
            auth: "sha256".into(),
            auth_pass: "authpass123".into(),
            privacy: "aes128".into(),
            priv_pass: "privpass123".into(),
            ..Default::default()
        },
        "admin",
    )
    .await
    .unwrap();
    let dev = |name: &str, port: u16| DeviceInput {
        name: name.into(),
        site_id: site,
        address: "127.0.0.1".into(),
        port: port.to_string(),
        credential_id: cred,
        enabled: true,
        cisco_vlan: "auto".into(),
    };
    let ok_id = netdev::create_device(&e.pool, &dev("sw-test", sw.port), "admin")
        .await
        .unwrap();
    // 沒有東西在聽的埠
    let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);
    let dead_id = netdev::create_device(&e.pool, &dev("dead", dead_port), "admin")
        .await
        .unwrap();

    // 一台裝了 Agent 的電腦，網卡 MAC 是 PC（Agent 回報大寫）
    common::device(&e).await;
    let endpoint: uuid::Uuid = sqlx::query_scalar("SELECT id FROM devices LIMIT 1")
        .fetch_one(&e.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO device_network (device_id, data) VALUES ($1, \
         '{\"interfaces\":[{\"name\":\"eth0\",\"kind\":\"ethernet\",\"up\":true,\
           \"mac\":\"00:1B:2C:00:00:01\",\"addresses\":[],\"gateways\":[],\"dns\":[]}]}')",
    )
    .bind(endpoint)
    .execute(&e.pool)
    .await
    .unwrap();

    let (_stop_tx, stop) = watch::channel(false);
    let cache = endpoint_cache::run::Cache::start(dir.path(), stop.clone())
        .await
        .unwrap()
        .unwrap();
    cache.checkin_once().await.unwrap();
    let jobs = cache.snmp_jobs();
    {
        let job = jobs.borrow();
        let job = job.as_ref().expect("job");
        assert_eq!(job.targets.len(), 2);
        assert!(job.targets.iter().all(|t| t.poll_now));
        assert_eq!(job.system_interval_secs, 900);
    }
    // 讀過就清掉「立即查詢」
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM net_devices WHERE poll_requested")
        .fetch_one(&e.pool)
        .await
        .unwrap();
    assert_eq!(pending, 0);

    let task = tokio::spawn(snmp::run(
        cache.state.central.clone(),
        jobs,
        fast(),
        stop.clone(),
    ));
    let pool = e.pool.clone();
    wait_for(|| {
        let pool = pool.clone();
        async move {
            let (n, locs): (i64, i64) = sqlx::query_as(
                "SELECT (SELECT count(*) FROM net_devices WHERE last_polled_at IS NOT NULL), \
                        (SELECT count(*) FROM endpoint_locations)",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            n == 2 && locs == 1
        }
    })
    .await;
    task.abort();

    let (name, model, fw, failures): (Option<String>, Option<String>, Option<String>, i32) =
        sqlx::query_as(
            "SELECT sys_name, model, firmware, consecutive_failures FROM net_devices WHERE id = $1",
        )
        .bind(ok_id)
        .fetch_one(&e.pool)
        .await
        .unwrap();
    assert_eq!(
        (name.as_deref(), model.as_deref(), fw.as_deref(), failures),
        (Some("sw-test"), Some("TS-24"), Some("1.2.3"), 0)
    );
    let ports: Vec<(i64, String, bool, Option<i32>, String)> = sqlx::query_as(
        "SELECT if_index, name, oper_up, pvid, role FROM net_interfaces WHERE device_id = $1 \
         ORDER BY if_index",
    )
    .bind(ok_id)
    .fetch_all(&e.pool)
    .await
    .unwrap();
    assert_eq!(ports.len(), 3);
    assert_eq!(
        ports[1],
        (2, "Gi0/2".into(), false, Some(20), "auto_edge".into())
    );
    assert_eq!(ports[2].4, "auto_uplink", "LLDP 鄰居是交換器");

    let (err, failures): (Option<String>, i32) =
        sqlx::query_as("SELECT last_error, consecutive_failures FROM net_devices WHERE id = $1")
            .bind(dead_id)
            .fetch_one(&e.pool)
            .await
            .unwrap();
    assert!(err.unwrap().starts_with("逾時"));
    assert_eq!(failures, 1);

    // 電腦的位置：埠 1、VLAN 10
    let (port, vlan, mac): (String, i32, String) = sqlx::query_as(
        "SELECT port_name, vlan, mac FROM endpoint_locations WHERE device_id = $1 \
         AND ended_at IS NULL",
    )
    .bind(endpoint)
    .fetch_one(&e.pool)
    .await
    .unwrap();
    assert_eq!(
        (port.as_str(), vlan, mac.as_str()),
        ("Gi0/1", 10, "00:1b:2c:00:00:01")
    );
    let up: (i32, bool) = sqlx::query_as(
        "SELECT mac_count, net_port_is_uplink(role, mac_count) FROM net_interfaces \
         WHERE device_id = $1 AND if_index = 3",
    )
    .bind(ok_id)
    .fetch_one(&e.pool)
    .await
    .unwrap();
    assert_eq!(up, (12, true));
    // 未管理設備：只有印表機（電腦有 Agent、上行埠的 MAC 不算）
    let u = netdev::view::unmanaged(&e.pool, None).await.unwrap();
    assert_eq!(u.len(), 1, "{u:?}");
    assert_eq!(u[0].mac, "00:00:0c:11:22:33");
    assert_eq!(u[0].ip.as_deref(), Some("10.0.0.9"));
    assert_eq!(u[0].port.as_deref(), Some("Gi0/2"));
    assert!(u[0].vendor.is_some_and(|v| v.contains("Cisco")));
    let loc = netdev::view::endpoint_location(&e.pool, endpoint)
        .await
        .unwrap();
    assert_eq!(loc.current.len(), 1);
    assert!(loc.current[0].last_seen.is_some());
    assert!(loc.via_uplink.is_none());

    // MAC 表那一輪失敗也算一次失敗
    cache
        .state
        .central
        .netdata(&protocol::netdev::NetData {
            device_id: ok_id,
            kind: NetPollKind::Tables,
            error: Some("x".into()),
            system: None,
            interfaces: vec![],
            fdb: vec![],
            arp: vec![],
        })
        .await
        .unwrap();
    let failures: i32 =
        sqlx::query_scalar("SELECT consecutive_failures FROM net_devices WHERE id = $1")
            .bind(ok_id)
            .fetch_one(&e.pool)
            .await
            .unwrap();
    assert_eq!(failures, 1);

    // 據點沒有這台設備的快取不能上傳
    let other_site = common::site(&e, "10.99.0.0/16").await;
    sqlx::query("UPDATE net_devices SET site_id = $2 WHERE id = $1")
        .bind(ok_id)
        .bind(other_site)
        .execute(&e.pool)
        .await
        .unwrap();
    let r = cache
        .state
        .central
        .netdata(&protocol::netdev::NetData {
            device_id: ok_id,
            kind: protocol::netdev::NetPollKind::System,
            error: Some("x".into()),
            system: None,
            interfaces: vec![],
            fdb: vec![],
            arp: vec![],
        })
        .await;
    assert!(matches!(
        r,
        Err(endpoint_cache::central::CentralError::NotFound)
    ));
    // 下一次報到：工作只剩這個據點的 dead
    cache.checkin_once().await.unwrap();
    let ids: Vec<i64> = cache
        .snmp_jobs()
        .borrow()
        .as_ref()
        .unwrap()
        .targets
        .iter()
        .map(|t| t.id)
        .collect();
    assert_eq!(ids, vec![dead_id]);
}
