mod common;

use common::TestServer;
use endpoint_server::commands::Actor;
use endpoint_server::commands::scripts::{self, ScriptInput};
use sqlx::PgPool;

fn platform(name: &str) -> Actor {
    Actor {
        username: name.into(),
        platform: true,
        groups: vec![],
    }
}

fn input(content: &str) -> ScriptInput {
    ScriptInput {
        name: "清暫存".into(),
        description: "刪除 Temp".into(),
        content: content.into(),
        timeout_minutes: 30,
    }
}

async fn script_row(pool: &PgPool, id: i64) -> (String, String, Option<String>) {
    sqlx::query_as("SELECT status, sha256, approved_by FROM scripts WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn sha(s: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}

fn err(e: anyhow::Error) -> String {
    format!("{e:#}")
}

#[sqlx::test(migrations = false)]
async fn script_validation_and_permissions(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let group_admin = Actor {
        username: "gary".into(),
        platform: false,
        groups: vec![1],
    };
    assert!(
        scripts::create_script(&s.pool, &input("dir"), &group_admin)
            .await
            .is_err()
    );
    let alice = platform("alice");
    for bad in [
        ScriptInput {
            name: " ".into(),
            ..input("dir")
        },
        input(""),
        input("a\0b"),
        input(&"a".repeat(65537)),
        ScriptInput {
            timeout_minutes: 0,
            ..input("dir")
        },
        ScriptInput {
            timeout_minutes: 121,
            ..input("dir")
        },
    ] {
        assert!(
            scripts::create_script(&s.pool, &bad, &alice).await.is_err(),
            "{:?}",
            bad.name
        );
    }
    assert!(
        scripts::create_script(&s.pool, &input(&"a".repeat(65536)), &alice)
            .await
            .is_ok()
    );
    let e = err(scripts::create_script(&s.pool, &input("dir"), &alice)
        .await
        .unwrap_err());
    assert!(e.contains("名稱已存在"), "{e}");
}

#[sqlx::test(migrations = false)]
async fn two_person_approval(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let (alice, bob) = (platform("alice"), platform("bob"));
    let id = scripts::create_script(&s.pool, &input("Remove-Item $env:TEMP\\* -Recurse"), &alice)
        .await
        .unwrap();
    let (status, hash, by) = script_row(&s.pool, id).await;
    assert_eq!(
        (status.as_str(), hash, by),
        ("pending", sha("Remove-Item $env:TEMP\\* -Recurse"), None)
    );
    let e = err(scripts::approve_script(&s.pool, id, &alice)
        .await
        .unwrap_err());
    assert!(e.contains("自己"), "{e}");
    scripts::approve_script(&s.pool, id, &bob).await.unwrap();
    assert_eq!(script_row(&s.pool, id).await.0, "approved");

    // 只改說明：不用重新核准
    scripts::update_script(
        &s.pool,
        id,
        &ScriptInput {
            description: "新的說明".into(),
            ..input("Remove-Item $env:TEMP\\* -Recurse")
        },
        &alice,
    )
    .await
    .unwrap();
    assert_eq!(script_row(&s.pool, id).await.0, "approved");
    // 改內容：回到待核准
    scripts::update_script(&s.pool, id, &input("dir"), &alice)
        .await
        .unwrap();
    let (status, hash, by) = script_row(&s.pool, id).await;
    assert_eq!((status.as_str(), hash, by), ("pending", sha("dir"), None));
    // bob 改內容後，alice 可以核准
    scripts::update_script(&s.pool, id, &input("dir /s"), &bob)
        .await
        .unwrap();
    assert!(scripts::approve_script(&s.pool, id, &bob).await.is_err());
    scripts::approve_script(&s.pool, id, &alice).await.unwrap();
    assert_eq!(script_row(&s.pool, id).await.2.as_deref(), Some("alice"));
    // 已核准的不能再核准
    assert!(scripts::approve_script(&s.pool, id, &bob).await.is_err());

    // 停用：不能改內容；啟用後回到待核准
    scripts::set_disabled(&s.pool, id, true, &alice)
        .await
        .unwrap();
    let e = err(scripts::update_script(&s.pool, id, &input("x"), &alice)
        .await
        .unwrap_err());
    assert!(e.contains("停用"), "{e}");
    scripts::set_disabled(&s.pool, id, false, &alice)
        .await
        .unwrap();
    assert_eq!(script_row(&s.pool, id).await.0, "pending");
    scripts::delete_script(&s.pool, id, &alice).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action LIKE 'script_%'")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert!(n >= 9, "{n}");
}

#[sqlx::test(migrations = false)]
async fn single_person_mode(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let carol = platform("carol");
    assert!(scripts::require_second_approver(&s.pool).await.unwrap());
    scripts::set_require_second_approver(&s.pool, false, &carol)
        .await
        .unwrap();
    assert!(!scripts::require_second_approver(&s.pool).await.unwrap());
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action = 'setting_scripts_second_approver'",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(n, 1);
    let id = scripts::create_script(&s.pool, &input("dir"), &carol)
        .await
        .unwrap();
    let (status, _, by) = script_row(&s.pool, id).await;
    assert_eq!(
        (status.as_str(), by.as_deref()),
        ("approved", Some("carol"))
    );
    // 設定被改壞：當成需要雙人核准
    sqlx::query(
        "UPDATE settings SET value = '\"x\"' WHERE key = 'scripts_require_second_approver'",
    )
    .execute(&s.pool)
    .await
    .unwrap();
    assert!(scripts::require_second_approver(&s.pool).await.unwrap());
}
