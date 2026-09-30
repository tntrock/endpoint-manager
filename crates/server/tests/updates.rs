mod common;

use chrono::NaiveDate;
use common::TestServer;
use endpoint_server::updates::admin::{self, PauseKind, PolicyInput};
use endpoint_server::updates::policy::PolicySettings;
use sqlx::PgPool;

fn input(name: &str, groups: Vec<i64>) -> PolicyInput {
    PolicyInput {
        name: name.into(),
        settings: PolicySettings {
            quality_defer_days: Some(7),
            ..Default::default()
        },
        groups,
    }
}

async fn generation(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT generation FROM update_state")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn settings(pool: &PgPool, id: i64) -> (i32, PolicySettings) {
    let (rev, json): (i32, String) =
        sqlx::query_as("SELECT revision, settings::text FROM update_policies WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap();
    (rev, serde_json::from_str(&json).unwrap())
}

async fn audits(pool: &PgPool, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = $1")
        .bind(action)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn err(e: anyhow::Error) -> String {
    format!("{e:#}")
}

#[sqlx::test(migrations = false)]
async fn create_validates_and_audits(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.group_id("台北").await;
    let g0 = generation(&s.pool).await;
    let id = admin::create_policy(&s.pool, &input("一般", vec![tp]), "admin")
        .await
        .unwrap();
    assert_eq!(generation(&s.pool).await, g0 + 1);
    assert_eq!(audits(&s.pool, "update_policy_create").await, 1);
    assert_eq!(settings(&s.pool, id).await.0, 1);

    let bad = [
        input(" ", vec![tp]),
        input("a\tb", vec![tp]),
        input("沒有群組", vec![]),
        PolicyInput {
            settings: PolicySettings {
                quality_defer_days: Some(31),
                ..Default::default()
            },
            ..input("延後太久", vec![tp])
        },
        input("群組不存在", vec![9999]),
        input("一般", vec![s.group_id("高雄").await]),
    ];
    for b in bad {
        assert!(
            admin::create_policy(&s.pool, &b, "admin").await.is_err(),
            "{}",
            b.name
        );
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM update_policies")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
}

#[sqlx::test(migrations = false)]
async fn group_belongs_to_one_policy(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.group_id("台北").await;
    let ks = s.group_id("高雄").await;
    let a = admin::create_policy(&s.pool, &input("原則A", vec![tp]), "admin")
        .await
        .unwrap();
    let e = err(
        admin::create_policy(&s.pool, &input("原則B", vec![ks, tp]), "admin")
            .await
            .unwrap_err(),
    );
    assert!(e.contains("原則A") && e.contains("台北"), "{e}");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM update_policies")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 1, "B 完全沒有寫入");

    // 更新 A 改用高雄後，台北可以給別的原則
    admin::set_pause(
        &s.pool,
        a,
        PauseKind::Quality,
        Some(NaiveDate::from_ymd_opt(2026, 9, 30).unwrap()),
        "admin",
    )
    .await
    .unwrap();
    admin::update_policy(&s.pool, a, &input("原則A", vec![ks]), "admin")
        .await
        .unwrap();
    let (rev, set) = settings(&s.pool, a).await;
    assert_eq!(rev, 3);
    assert!(set.quality_pause_start.is_some(), "表單更新保留暫停日");
    admin::create_policy(&s.pool, &input("原則B", vec![tp]), "admin")
        .await
        .unwrap();
    // 自己原本的群組不算衝突
    admin::update_policy(&s.pool, a, &input("原則A2", vec![ks]), "admin")
        .await
        .unwrap();
}

#[sqlx::test(migrations = false)]
async fn pause_and_resume(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.group_id("台北").await;
    let id = admin::create_policy(&s.pool, &input("一般", vec![tp]), "admin")
        .await
        .unwrap();
    let day = NaiveDate::from_ymd_opt(2026, 9, 30).unwrap();
    admin::set_pause(&s.pool, id, PauseKind::Feature, Some(day), "admin")
        .await
        .unwrap();
    let (rev, set) = settings(&s.pool, id).await;
    assert_eq!((rev, set.feature_pause_start), (2, Some(day)));
    assert_eq!(set.quality_defer_days, Some(7), "其他設定不變");
    admin::set_pause(&s.pool, id, PauseKind::Feature, None, "admin")
        .await
        .unwrap();
    let (rev, set) = settings(&s.pool, id).await;
    assert_eq!((rev, set.feature_pause_start), (3, None));
    assert_eq!(audits(&s.pool, "update_policy_pause").await, 1);
    assert_eq!(audits(&s.pool, "update_policy_resume").await, 1);
}

#[sqlx::test(migrations = false)]
async fn delete_releases_groups(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.group_id("台北").await;
    let id = admin::create_policy(&s.pool, &input("一般", vec![tp]), "admin")
        .await
        .unwrap();
    let e = err(endpoint_server::groups::delete(&s.pool, tp, "admin")
        .await
        .unwrap_err());
    assert!(e.contains("更新原則"), "{e}");
    admin::delete_policy(&s.pool, id, "admin").await.unwrap();
    assert_eq!(audits(&s.pool, "update_policy_delete").await, 1);
    endpoint_server::groups::delete(&s.pool, tp, "admin")
        .await
        .unwrap();
    for e in [
        admin::delete_policy(&s.pool, id, "admin")
            .await
            .unwrap_err(),
        admin::update_policy(&s.pool, id, &input("x", vec![]), "admin")
            .await
            .unwrap_err(),
        admin::set_pause(&s.pool, id, PauseKind::Quality, None, "admin")
            .await
            .unwrap_err(),
    ] {
        assert!(err(e).contains("原則不存在"));
    }
}

async fn checkin(s: &TestServer, a: &common::TestAgent) -> protocol::CheckinResponse {
    // 報到用的快取最多每 5 秒確認一次 generation；測試直接讓快取過期
    s.state.updates.invalidate();
    s.client(Some(a))
        .post(s.url("/v1/checkin"))
        .json(&protocol::CheckinRequest {
            schema_version: protocol::SCHEMA_VERSION,
            agent_version: "0.5.0".into(),
            boot_time: chrono::Utc::now(),
            logged_on_user: None,
            ip_addresses: vec![],
            section_hashes: Default::default(),
            section_errors: Default::default(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[sqlx::test(migrations = false)]
async fn checkin_delivers_policy_by_group(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp_tok = s.create_group_token("台北", 1).await;
    let ks_tok = s.create_group_token("高雄", 1).await;
    let tp = s.enroll_ok(&tp_tok, None, None).await;
    let ks = s.enroll_ok(&ks_tok, None, None).await;
    let tp_g = s.group_id("台北").await;
    let i = input("一般", vec![tp_g]);
    let id = admin::create_policy(&s.pool, &i, "admin").await.unwrap();

    let r = checkin(&s, &tp).await;
    let p = r.update_policy.clone().expect("台北有原則");
    assert_eq!((p.id, p.revision), (id, 1));
    assert_eq!(p.values, i.settings.values());
    assert_eq!(
        r.update_policy_hash.as_deref(),
        Some(protocol::update::update_policy_hash(Some(&p)).as_str())
    );
    let r = checkin(&s, &ks).await;
    assert!(r.update_policy.is_none(), "高雄沒有原則");
    assert_eq!(
        r.update_policy_hash.as_deref(),
        Some(protocol::update::update_policy_hash(None).as_str())
    );

    let before = checkin(&s, &tp).await.update_policy_hash;
    admin::update_policy(
        &s.pool,
        id,
        &PolicyInput {
            settings: PolicySettings {
                quality_defer_days: Some(14),
                ..Default::default()
            },
            ..i.clone()
        },
        "admin",
    )
    .await
    .unwrap();
    let r = checkin(&s, &tp).await;
    assert_eq!(r.update_policy.as_ref().unwrap().revision, 2);
    assert_ne!(r.update_policy_hash, before);

    sqlx::query("UPDATE devices SET status = 'retired' WHERE id = $1")
        .bind(tp.device_id)
        .execute(&s.pool)
        .await
        .unwrap();
    assert!(
        checkin(&s, &tp).await.update_policy.is_none(),
        "非使用中不下發"
    );
    sqlx::query("UPDATE devices SET status = 'active' WHERE id = $1")
        .bind(tp.device_id)
        .execute(&s.pool)
        .await
        .unwrap();
    admin::delete_policy(&s.pool, id, "admin").await.unwrap();
    let r = checkin(&s, &tp).await;
    assert!(r.update_policy.is_none() && r.update_policy_hash.is_some());
}

fn status_body(state: &str) -> serde_json::Value {
    serde_json::json!({
        "policy_id": 7, "revision": 2, "state": state, "detail": "",
        "reboot_pending": true, "reboot_pending_since": "2026-09-29T01:00:00Z",
        "last_patch_date": "2026-09-10"
    })
}

async fn put_status(
    s: &TestServer,
    a: Option<&common::TestAgent>,
    body: &serde_json::Value,
) -> u16 {
    s.client(a)
        .put(s.url("/v1/update-status"))
        .json(body)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[sqlx::test(migrations = false)]
async fn status_is_stored_per_device(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(2).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let b = s.enroll_ok(&tok, None, None).await;
    assert_eq!(put_status(&s, Some(&a), &status_body("applied")).await, 204);
    let row: (
        Option<i64>,
        Option<i32>,
        String,
        bool,
        Option<chrono::NaiveDate>,
    ) = sqlx::query_as(
        "SELECT policy_id, revision, state, reboot_pending, last_patch_date \
         FROM update_policy_status WHERE device_id = $1",
    )
    .bind(a.device_id)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(
        row,
        (
            Some(7),
            Some(2),
            "applied".into(),
            true,
            NaiveDate::from_ymd_opt(2026, 9, 10)
        )
    );
    let mut c = status_body("conflict");
    c["detail"] = "DeferQualityUpdatesPeriodInDays\u{7}".into();
    assert_eq!(put_status(&s, Some(&a), &c).await, 204);
    let (state, detail): (String, String) =
        sqlx::query_as("SELECT state, detail FROM update_policy_status WHERE device_id = $1")
            .bind(a.device_id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(
        (state.as_str(), detail.as_str()),
        ("conflict", "DeferQualityUpdatesPeriodInDays"),
        "控制字元被移除"
    );
    assert_eq!(
        put_status(&s, Some(&b), &status_body("unmanaged")).await,
        204
    );
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM update_policy_status")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 2, "每台各一列");
}

#[sqlx::test(migrations = false)]
async fn invalid_status_is_rejected(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let future = (chrono::Utc::now() + chrono::Duration::days(3)).date_naive();
    let mut bad = vec![];
    let mut b = status_body("applied");
    b["last_patch_date"] = future.to_string().into();
    bad.push(b);
    let mut b = status_body("applied");
    b["detail"] = "x".repeat(501).into();
    bad.push(b);
    bad.push(status_body("weird"));
    for b in &bad {
        assert_eq!(put_status(&s, Some(&a), b).await, 400, "{b}");
    }
    assert_eq!(put_status(&s, None, &status_body("applied")).await, 401);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM update_policy_status")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}
