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
