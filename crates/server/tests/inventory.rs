mod common;

use std::io::Write;

use common::{TestAgent, TestServer};
use protocol::{Arch, InventoryPayload, InventoryUpload, SCHEMA_VERSION, SoftwareItem};
use sqlx::PgPool;

fn sw(name: &str, ver: &str) -> SoftwareItem {
    SoftwareItem {
        name: name.into(),
        version: Some(ver.into()),
        publisher: None,
        install_date: None,
        arch: Arch::X64,
    }
}

fn upload(p: InventoryPayload) -> InventoryUpload {
    InventoryUpload {
        schema_version: SCHEMA_VERSION,
        payload: p,
    }
}

async fn put(s: &TestServer, a: &TestAgent, section: &str, u: &InventoryUpload) -> u16 {
    s.client(Some(a))
        .put(s.url(&format!("/v1/inventory/{section}")))
        .json(u)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

async fn setup(pool: PgPool) -> (TestServer, TestAgent) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    (s, a)
}

async fn change_count(s: &TestServer, a: &TestAgent) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM inventory_changes WHERE device_id = $1")
        .bind(a.device_id)
        .fetch_one(&s.pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = false)]
async fn upload_stores_rows_and_hash(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let p = InventoryPayload::Software(vec![sw("A", "1"), sw("B", "2")]);
    assert_eq!(put(&s, &a, "software", &upload(p.clone())).await, 204);

    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM device_software WHERE device_id = $1")
        .bind(a.device_id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 2);
    let hash: String = sqlx::query_scalar(
        "SELECT hash FROM inventory_sections WHERE device_id = $1 AND section = 'software'",
    )
    .bind(a.device_id)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(hash, p.canonical_hash());
}

#[sqlx::test(migrations = false)]
async fn first_upload_is_baseline_second_records_changes(pool: PgPool) {
    let (s, a) = setup(pool).await;
    put(
        &s,
        &a,
        "software",
        &upload(InventoryPayload::Software(vec![sw("A", "1"), sw("B", "1")])),
    )
    .await;
    assert_eq!(change_count(&s, &a).await, 0);

    put(
        &s,
        &a,
        "software",
        &upload(InventoryPayload::Software(vec![sw("A", "2"), sw("C", "1")])),
    )
    .await;
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT change, item_key FROM inventory_changes WHERE device_id = $1 ORDER BY item_key",
    )
    .bind(a.device_id)
    .fetch_all(&s.pool)
    .await
    .unwrap();
    assert_eq!(
        rows,
        vec![
            ("updated".into(), "A|x64|".into()),
            ("removed".into(), "B|x64|".into()),
            ("added".into(), "C|x64|".into()),
        ]
    );
}

#[sqlx::test(migrations = false)]
async fn roundtrip_through_db_produces_no_spurious_changes(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let p = InventoryPayload::Software(vec![
        sw("Java", "8"),
        sw("Java", "17"),
        sw("中文軟體", "1.0"),
    ]);
    assert_eq!(put(&s, &a, "software", &upload(p.clone())).await, 204);
    assert_eq!(put(&s, &a, "software", &upload(p)).await, 204);
    assert_eq!(change_count(&s, &a).await, 0);
}

#[sqlx::test(migrations = false)]
async fn basic_section_updates_device_columns(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let p = InventoryPayload::Basic(protocol::BasicInfo {
        hostname: "PC-RENAMED".into(),
        domain: Some("corp.local".into()),
        is_domain_joined: true,
        os_caption: "Windows 11 Pro".into(),
        os_build: "26100".into(),
        os_ubr: None,
    });
    assert_eq!(put(&s, &a, "basic", &upload(p)).await, 204);
    let (h, joined): (String, bool) =
        sqlx::query_as("SELECT hostname, is_domain_joined FROM devices WHERE id = $1")
            .bind(a.device_id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!((h.as_str(), joined), ("PC-RENAMED", true));
}

#[sqlx::test(migrations = false)]
async fn gzip_body_accepted(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let json = serde_json::to_vec(&upload(InventoryPayload::Software(vec![sw("A", "1")]))).unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&json).unwrap();
    let r = s
        .client(Some(&a))
        .put(s.url("/v1/inventory/software"))
        .header("content-encoding", "gzip")
        .header("content-type", "application/json")
        .body(gz.finish().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
}

#[sqlx::test(migrations = false)]
async fn gzip_bomb_rejected(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    let zeros = vec![0u8; 1024 * 1024];
    for _ in 0..60 {
        gz.write_all(&zeros).unwrap(); // 解壓後 60MB，壓縮後約 60KB
    }
    let r = s
        .client(Some(&a))
        .put(s.url("/v1/inventory/software"))
        .header("content-encoding", "gzip")
        .body(gz.finish().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 413);
}

#[sqlx::test(migrations = false)]
async fn oversized_string_rejected(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let p = InventoryPayload::Software(vec![sw(&"x".repeat(10_000), "1")]);
    assert_eq!(put(&s, &a, "software", &upload(p)).await, 400);
}

#[sqlx::test(migrations = false)]
async fn section_path_mismatch_rejected(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let p = InventoryPayload::Software(vec![sw("A", "1")]);
    assert_eq!(put(&s, &a, "patches", &upload(p)).await, 400);
}

#[sqlx::test(migrations = false)]
async fn upload_without_cert_is_401(pool: PgPool) {
    let (s, _) = setup(pool).await;
    let r = s
        .client(None)
        .put(s.url("/v1/inventory/software"))
        .json(&upload(InventoryPayload::Software(vec![])))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}

#[sqlx::test(migrations = false)]
async fn nul_in_every_section_is_400(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let nul = "a\0b".to_string();
    let payloads = vec![
        InventoryPayload::Basic(protocol::BasicInfo {
            hostname: nul.clone(),
            domain: None,
            is_domain_joined: false,
            os_caption: "W".into(),
            os_build: "1".into(),
            os_ubr: None,
        }),
        InventoryPayload::Hardware(protocol::HardwareInfo {
            manufacturer: Some(nul.clone()),
            model: None,
            cpu: None,
            ram_mb: 1,
            disks: vec![],
        }),
        InventoryPayload::Software(vec![sw(&nul, "1")]),
        InventoryPayload::Patches(vec![protocol::PatchItem {
            kb: nul.clone(),
            installed_on: None,
        }]),
        InventoryPayload::Services(vec![protocol::ServiceItem {
            name: nul.clone(),
            display_name: None,
            start_mode: "Auto".into(),
            state: "Running".into(),
            binary_path: None,
        }]),
    ];
    for p in payloads {
        let section = p.section().as_str();
        assert_eq!(put(&s, &a, section, &upload(p)).await, 400, "{section}");
    }
}

#[sqlx::test(migrations = false)]
async fn duplicate_patches_roundtrip_without_spurious_changes(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let kb = |on: Option<&str>| protocol::PatchItem {
        kb: "KB500".into(),
        installed_on: on.map(Into::into),
    };
    let p = InventoryPayload::Patches(vec![kb(Some("1/1/2026")), kb(None)]);
    for _ in 0..3 {
        assert_eq!(put(&s, &a, "patches", &upload(p.clone())).await, 204);
    }
    assert_eq!(change_count(&s, &a).await, 0);
}

#[sqlx::test(migrations = false)]
async fn basic_ubr_roundtrip(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let p = InventoryPayload::Basic(protocol::BasicInfo {
        hostname: "PC1".into(),
        domain: None,
        is_domain_joined: false,
        os_caption: "Windows 11".into(),
        os_build: "22631".into(),
        os_ubr: Some(4317),
    });
    assert_eq!(put(&s, &a, "basic", &upload(p.clone())).await, 204);
    let ubr: Option<i32> = sqlx::query_scalar("SELECT os_ubr FROM devices WHERE id = $1")
        .bind(a.device_id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(ubr, Some(4317));
    let mut c = s.pool.acquire().await.unwrap();
    let back =
        endpoint_server::inventory::load_payload(&mut c, a.device_id, protocol::Section::Basic)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        back.canonical_hash(),
        p.canonical_hash(),
        "讀回的內容與上傳一致"
    );
}

fn sec(public: bool) -> InventoryPayload {
    InventoryPayload::Security(protocol::SecurityInfo {
        firewall: protocol::Probe::Ok(protocol::FirewallInfo {
            domain: true,
            private: true,
            public,
        }),
        bitlocker: protocol::Probe::Ok(vec![protocol::VolumeInfo {
            drive: "C:".into(),
            is_system: true,
            protected: true,
        }]),
        defender: protocol::Probe::Error("inactive".into()),
        password: protocol::Probe::Ok(protocol::PasswordPolicy {
            min_length: 12,
            max_age_days: 0,
            lockout_threshold: 5,
        }),
        admins: protocol::Probe::Ok(vec![protocol::AccountInfo {
            name: r"PC\Administrator".into(),
            sid: "S-1-5-21-1-500".into(),
        }]),
    })
}

#[sqlx::test(migrations = false)]
async fn security_and_registry_roundtrip_with_history(pool: PgPool) {
    let (s, a) = setup(pool).await;
    // 伺服器只保存規則需要的值：先建立會收集這個值的規則
    endpoint_server::compliance::admin::create_rule(
        &s.pool,
        &endpoint_server::compliance::admin::RuleInput {
            name: "x".into(),
            description: String::new(),
            kind: "registry_value".into(),
            severity: "low".into(),
            enabled: true,
            params: serde_json::json!({"path": r"HKLM\SOFTWARE\X", "name": "Y", "op": "exists"}),
            include: vec![],
            exclude: vec![],
            template_key: None,
        },
        "admin",
    )
    .await
    .unwrap();
    assert_eq!(put(&s, &a, "security", &upload(sec(true))).await, 204);
    assert_eq!(put(&s, &a, "security", &upload(sec(false))).await, 204);
    let mut c = s.pool.acquire().await.unwrap();
    let back =
        endpoint_server::inventory::load_payload(&mut c, a.device_id, protocol::Section::Security)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(back.canonical_hash(), sec(false).canonical_hash());
    let change: (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT item_key, old_value, new_value FROM inventory_changes \
         WHERE device_id = $1 AND section = 'security'",
    )
    .bind(a.device_id)
    // 測試連線池很小：用手上的連線，並在呼叫伺服器前歸還
    .fetch_one(&mut *c)
    .await
    .unwrap();

    drop(c);
    assert_eq!(
        change,
        (
            "firewall.public".into(),
            Some("true".into()),
            Some("false".into())
        )
    );

    let reg = InventoryPayload::Registry(vec![protocol::RegistryValue {
        path: r"HKLM\SOFTWARE\X".into(),
        name: "Y".into(),
        state: protocol::RegState::Present,
        kind: protocol::RegKind::Dword,
        data: "1".into(),
    }]);
    assert_eq!(put(&s, &a, "registry", &upload(reg.clone())).await, 204);
    let mut c = s.pool.acquire().await.unwrap();
    let back =
        endpoint_server::inventory::load_payload(&mut c, a.device_id, protocol::Section::Registry)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(back.canonical_hash(), reg.canonical_hash());
}
