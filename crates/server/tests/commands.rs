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

use endpoint_server::commands::runs::{self, RunInput, Target};

fn run(action: &str, target: Target) -> RunInput {
    RunInput {
        action: action.into(),
        target,
        delay_minutes: None,
        script_id: None,
        expires_hours: 24,
    }
}

async fn targets(pool: &PgPool, run: i64) -> Vec<String> {
    sqlx::query_scalar("SELECT status FROM command_targets WHERE run_id = $1 ORDER BY id")
        .bind(run)
        .fetch_all(pool)
        .await
        .unwrap()
}

struct Fleet {
    tp: i64,
    ks: i64,
    tp_dev: Vec<common::TestAgent>,
    ks_dev: common::TestAgent,
}

async fn fleet(s: &TestServer) -> Fleet {
    let tok = s.create_group_token("台北", 3).await;
    let mut tp_dev = vec![];
    for _ in 0..3 {
        tp_dev.push(s.enroll_ok(&tok, None, None).await);
    }
    let ks_dev = s
        .enroll_ok(&s.create_group_token("高雄", 1).await, None, None)
        .await;
    Fleet {
        tp: s.group_id("台北").await,
        ks: s.group_id("高雄").await,
        tp_dev,
        ks_dev,
    }
}

#[sqlx::test(migrations = false)]
async fn create_runs_with_scope_and_validation(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let f = fleet(&s).await;
    let admin = platform("admin");
    let (id, n) = runs::create_run(&s.pool, &run("collect", Target::Group(f.tp)), &admin)
        .await
        .unwrap();
    assert_eq!(n, 3);
    assert_eq!(targets(&s.pool, id).await, vec!["pending"; 3]);
    let (id, n) = runs::create_run(
        &s.pool,
        &run("reboot", Target::Device(f.ks_dev.device_id)),
        &admin,
    )
    .await
    .unwrap();
    assert_eq!(n, 1);
    let (delay, label): (Option<i32>, String) =
        sqlx::query_as("SELECT delay_minutes, target_label FROM command_runs WHERE id = $1")
            .bind(id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(delay, Some(10));
    assert!(label.starts_with("裝置 "), "{label}");
    for bad in [
        RunInput {
            delay_minutes: Some(61),
            ..run("reboot", Target::Group(f.tp))
        },
        RunInput {
            expires_hours: 0,
            ..run("collect", Target::Group(f.tp))
        },
        RunInput {
            expires_hours: 721,
            ..run("collect", Target::Group(f.tp))
        },
        run("format", Target::Group(f.tp)),
        run("collect", Target::Device(uuid::Uuid::new_v4())),
    ] {
        assert!(runs::create_run(&s.pool, &bad, &admin).await.is_err());
    }
    // 群組內沒有使用中的裝置：不留下 run
    let empty = s.group_id("空的").await;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM command_runs")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    let e = err(
        runs::create_run(&s.pool, &run("collect", Target::Group(empty)), &admin)
            .await
            .unwrap_err(),
    );
    assert!(e.contains("沒有使用中的裝置"), "{e}");
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM command_runs")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(before, after);

    // 群組管理員（只管台北）
    let gary = Actor {
        username: "gary".into(),
        platform: false,
        groups: vec![f.tp],
    };
    for t in [Target::Group(f.ks), Target::Device(f.ks_dev.device_id)] {
        let e = err(runs::create_run(&s.pool, &run("collect", t), &gary)
            .await
            .unwrap_err());
        assert!(e.contains("管理範圍"), "{e}");
    }
    let sid = scripts::create_script(&s.pool, &input("dir"), &admin)
        .await
        .unwrap();
    let e = err(runs::create_run(
        &s.pool,
        &RunInput {
            script_id: Some(sid),
            ..run("script", Target::Group(f.tp))
        },
        &gary,
    )
    .await
    .unwrap_err());
    assert!(e.contains("平台管理員"), "{e}");
    runs::create_run(
        &s.pool,
        &run("collect", Target::Device(f.tp_dev[0].device_id)),
        &gary,
    )
    .await
    .unwrap();
}

#[sqlx::test(migrations = false)]
async fn script_runs_snapshot_content(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let f = fleet(&s).await;
    let (alice, bob) = (platform("alice"), platform("bob"));
    let sid = scripts::create_script(&s.pool, &input("Write-Output v1"), &alice)
        .await
        .unwrap();
    let script_run = |sid| RunInput {
        script_id: Some(sid),
        ..run("script", Target::Group(f.tp))
    };
    let e = err(runs::create_run(&s.pool, &script_run(sid), &alice)
        .await
        .unwrap_err());
    assert!(e.contains("核准"), "{e}");
    scripts::approve_script(&s.pool, sid, &bob).await.unwrap();
    let (id, _) = runs::create_run(&s.pool, &script_run(sid), &alice)
        .await
        .unwrap();
    scripts::update_script(&s.pool, sid, &input("Write-Output v2"), &alice)
        .await
        .unwrap();
    let (content, hash): (String, String) =
        sqlx::query_as("SELECT script_content, script_sha256 FROM command_runs WHERE id = $1")
            .bind(id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(
        (content.as_str(), hash),
        ("Write-Output v1", sha("Write-Output v1"))
    );
    let e = err(scripts::delete_script(&s.pool, sid, &alice)
        .await
        .unwrap_err());
    assert!(e.contains("只能停用"), "{e}");
}

#[sqlx::test(migrations = false)]
async fn cancel_rules(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let f = fleet(&s).await;
    let gary = Actor {
        username: "gary".into(),
        platform: false,
        groups: vec![f.tp],
    };
    let other = Actor {
        username: "olga".into(),
        platform: false,
        groups: vec![f.tp],
    };
    let (id, _) = runs::create_run(&s.pool, &run("collect", Target::Group(f.tp)), &gary)
        .await
        .unwrap();
    assert!(runs::cancel_run(&s.pool, id, &other).await.is_err());
    runs::cancel_run(&s.pool, id, &gary).await.unwrap();
    assert_eq!(targets(&s.pool, id).await, vec!["canceled"; 3]);
    let e = err(runs::cancel_run(&s.pool, id, &platform("admin"))
        .await
        .unwrap_err());
    assert!(e.contains("已取消"), "{e}");
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action IN ('command_create', 'command_cancel')",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(n, 2);
}
