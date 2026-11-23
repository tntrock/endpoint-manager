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
use endpoint_cache::snmp::{self, collect, parse};
use protocol::netdev::{
    CiscoVlanMode, SnmpAuthProtocol, SnmpCredential, SnmpPrivProtocol, SnmpTarget,
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
    let all = switch_mib();
    let lldp = Oid::from_slice(&[1, 0, 8802]);
    let (l, rest): (BTreeMap<_, _>, BTreeMap<_, _>) =
        all.into_iter().partition(|(o, _)| o.starts_with(&lldp));
    let engine = AuthoritativeEngine::install(generate_engine_id().unwrap(), |_| {
        Ok::<(), std::convert::Infallible>(())
    })
    .unwrap();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
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
            let n: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM net_devices WHERE last_polled_at IS NOT NULL",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            n == 2
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

    // MAC／ARP 表第一期還不處理：接受但不改資料
    cache
        .state
        .central
        .netdata(&protocol::netdev::NetData {
            device_id: ok_id,
            kind: protocol::netdev::NetPollKind::Tables,
            error: Some("x".into()),
            system: None,
            interfaces: vec![],
        })
        .await
        .unwrap();
    let failures: i32 =
        sqlx::query_scalar("SELECT consecutive_failures FROM net_devices WHERE id = $1")
            .bind(ok_id)
            .fetch_one(&e.pool)
            .await
            .unwrap();
    assert_eq!(failures, 0);

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
