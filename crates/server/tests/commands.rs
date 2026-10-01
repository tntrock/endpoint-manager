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
    let e = err(
        scripts::approve_script(&s.pool, id, &sha_of(&s.pool, id).await, &alice)
            .await
            .unwrap_err(),
    );
    assert!(e.contains("自己"), "{e}");
    scripts::approve_script(&s.pool, id, &sha_of(&s.pool, id).await, &bob)
        .await
        .unwrap();
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
    // bob 也改了內容：上次核准後的修改者（alice、bob）都不能核准，由 carol 核准
    scripts::update_script(&s.pool, id, &input("dir /s"), &bob)
        .await
        .unwrap();
    for who in [&bob, &alice] {
        assert!(
            scripts::approve_script(&s.pool, id, &sha_of(&s.pool, id).await, who)
                .await
                .is_err()
        );
    }
    let carol = platform("carol");
    scripts::approve_script(&s.pool, id, &sha_of(&s.pool, id).await, &carol)
        .await
        .unwrap();
    assert_eq!(script_row(&s.pool, id).await.2.as_deref(), Some("carol"));
    // 已核准的不能再核准
    assert!(
        scripts::approve_script(&s.pool, id, &sha_of(&s.pool, id).await, &bob)
            .await
            .is_err()
    );

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
    scripts::approve_script(&s.pool, sid, &sha_of(&s.pool, sid).await, &bob)
        .await
        .unwrap();
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

async fn checkin(s: &TestServer, a: &common::TestAgent) -> protocol::CheckinResponse {
    s.client(Some(a))
        .post(s.url("/v1/checkin"))
        .json(&protocol::CheckinRequest {
            schema_version: protocol::SCHEMA_VERSION,
            agent_version: "0.6.0".into(),
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

async fn report(s: &TestServer, a: &common::TestAgent, id: i64, body: serde_json::Value) -> u16 {
    s.client(Some(a))
        .post(s.url(&format!("/v1/commands/{id}/result")))
        .json(&body)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

async fn target_state(pool: &PgPool, id: i64) -> (String, Option<i32>, String) {
    sqlx::query_as("SELECT status, exit_code, output FROM command_targets WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = false)]
async fn checkin_delivers_and_resends(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let f = fleet(&s).await;
    let a = &f.tp_dev[0];
    let admin = platform("admin");
    assert!(checkin(&s, a).await.commands.is_empty());
    for _ in 0..12 {
        runs::create_run(
            &s.pool,
            &run("collect", Target::Device(a.device_id)),
            &admin,
        )
        .await
        .unwrap();
    }
    let r = checkin(&s, a).await;
    let ids: Vec<i64> = r.commands.iter().map(|c| c.id).collect();
    assert_eq!(ids.len(), 10);
    assert!(ids.windows(2).all(|w| w[0] < w[1]), "由舊到新");
    let sent: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM command_targets WHERE device_id = $1 AND status = 'sent'",
    )
    .bind(a.device_id)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(sent, 10);
    let again: Vec<i64> = checkin(&s, a).await.commands.iter().map(|c| c.id).collect();
    assert_eq!(again, ids, "收到結果前重送");

    // 腳本：下發建立當時的內容
    let bob = platform("bob");
    let sid = scripts::create_script(&s.pool, &input("Write-Output hi"), &admin)
        .await
        .unwrap();
    scripts::approve_script(&s.pool, sid, &sha_of(&s.pool, sid).await, &bob)
        .await
        .unwrap();
    let b = &f.tp_dev[1];
    runs::create_run(
        &s.pool,
        &RunInput {
            script_id: Some(sid),
            ..run("script", Target::Device(b.device_id))
        },
        &admin,
    )
    .await
    .unwrap();
    let c = &checkin(&s, b).await.commands[0];
    assert_eq!(c.action, protocol::command::CommandAction::Script);
    let spec = c.script.as_ref().unwrap();
    assert_eq!(
        (
            spec.content.as_str(),
            spec.sha256.clone(),
            spec.timeout_minutes
        ),
        ("Write-Output hi", sha("Write-Output hi"), 30)
    );

    // 取消、過期、停用的裝置
    let d = &f.tp_dev[2];
    let (canceled, _) =
        runs::create_run(&s.pool, &run("apply", Target::Device(d.device_id)), &admin)
            .await
            .unwrap();
    runs::cancel_run(&s.pool, canceled, &admin).await.unwrap();
    assert!(checkin(&s, d).await.commands.is_empty());
    let (old, _) = runs::create_run(&s.pool, &run("apply", Target::Device(d.device_id)), &admin)
        .await
        .unwrap();
    sqlx::query("UPDATE command_runs SET expires_at = now() - interval '1 minute' WHERE id = $1")
        .bind(old)
        .execute(&s.pool)
        .await
        .unwrap();
    assert!(checkin(&s, d).await.commands.is_empty());
    assert_eq!(
        endpoint_server::commands::worker::expire(&s.pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(targets(&s.pool, old).await, vec!["expired"]);
    runs::create_run(
        &s.pool,
        &run("apply", Target::Device(f.ks_dev.device_id)),
        &admin,
    )
    .await
    .unwrap();
    sqlx::query("UPDATE devices SET status = 'retired' WHERE id = $1")
        .bind(f.ks_dev.device_id)
        .execute(&s.pool)
        .await
        .unwrap();
    assert!(checkin(&s, &f.ks_dev).await.commands.is_empty());
}

#[sqlx::test(migrations = false)]
async fn results_are_recorded_once(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let f = fleet(&s).await;
    let (a, b) = (&f.tp_dev[0], &f.tp_dev[1]);
    let admin = platform("admin");
    runs::create_run(&s.pool, &run("collect", Target::Group(f.tp)), &admin)
        .await
        .unwrap();
    let id = checkin(&s, a).await.commands[0].id;
    let ok =
        serde_json::json!({"status": "succeeded", "exit_code": 0, "output": "line1\nbeep\u{7}"});
    assert_eq!(report(&s, a, id, ok).await, 204);
    assert_eq!(
        target_state(&s.pool, id).await,
        ("succeeded".into(), Some(0), "line1\nbeep".into())
    );
    let fail = serde_json::json!({"status": "failed", "exit_code": 1, "output": "x"});
    assert_eq!(report(&s, a, id, fail.clone()).await, 204);
    assert_eq!(target_state(&s.pool, id).await.0, "succeeded", "不覆寫");
    assert_eq!(report(&s, b, id, fail.clone()).await, 404, "別台的指令");
    let big = serde_json::json!({"status": "failed", "output": "a".repeat(65537)});
    let bid = checkin(&s, b).await.commands[0].id;
    assert_eq!(report(&s, b, bid, big).await, 400);
    // 取消後才回報：忽略
    let (run2, _) = runs::create_run(&s.pool, &run("apply", Target::Device(b.device_id)), &admin)
        .await
        .unwrap();
    let t2: i64 = sqlx::query_scalar("SELECT id FROM command_targets WHERE run_id = $1")
        .bind(run2)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    runs::cancel_run(&s.pool, run2, &admin).await.unwrap();
    assert_eq!(report(&s, b, t2, fail).await, 204);
    assert_eq!(target_state(&s.pool, t2).await.0, "canceled");
}

// ---- 審查修正 ----

async fn sha_of(pool: &PgPool, id: i64) -> String {
    sqlx::query_scalar("SELECT sha256 FROM scripts WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// 核准者看到的內容在核准前被改掉：不能核准沒看過的版本
#[sqlx::test(migrations = false)]
async fn approve_requires_the_reviewed_hash(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let (alice, bob) = (platform("alice"), platform("bob"));
    let id = scripts::create_script(&s.pool, &input("Write-Output ok"), &alice)
        .await
        .unwrap();
    let seen = sha_of(&s.pool, id).await;
    scripts::update_script(&s.pool, id, &input(r"Remove-Item C:\ -Recurse"), &alice)
        .await
        .unwrap();
    let e = err(scripts::approve_script(&s.pool, id, &seen, &bob)
        .await
        .unwrap_err());
    assert!(e.contains("內容已變更"), "{e}");
    assert_eq!(script_row(&s.pool, id).await.0, "pending");
    let now = sha_of(&s.pool, id).await;
    scripts::approve_script(&s.pool, id, &now, &bob)
        .await
        .unwrap();
}

/// 別人只改逾時（或改一點點內容）不能讓原作者自己核准
#[sqlx::test(migrations = false)]
async fn every_editor_since_approval_is_excluded(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let (alice, bob, carol) = (platform("alice"), platform("bob"), platform("carol"));
    let id = scripts::create_script(&s.pool, &input("evil"), &alice)
        .await
        .unwrap();
    scripts::update_script(
        &s.pool,
        id,
        &ScriptInput {
            timeout_minutes: 31,
            ..input("evil")
        },
        &bob,
    )
    .await
    .unwrap();
    let h = sha_of(&s.pool, id).await;
    for who in [&alice, &bob] {
        let e = err(scripts::approve_script(&s.pool, id, &h, who)
            .await
            .unwrap_err());
        assert!(e.contains("自己"), "{e}");
    }
    scripts::approve_script(&s.pool, id, &h, &carol)
        .await
        .unwrap();
    // 核准後重新計算：之後的修改者才被排除
    scripts::update_script(&s.pool, id, &input("fixed"), &carol)
        .await
        .unwrap();
    let h = sha_of(&s.pool, id).await;
    scripts::approve_script(&s.pool, id, &h, &alice)
        .await
        .unwrap();
}

/// 單人模式下自己核准的腳本，切回雙人模式後不能直接執行，要由另一位重新核准
#[sqlx::test(migrations = false)]
async fn self_approved_scripts_need_review_after_mode_switch(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let f = fleet(&s).await;
    let (alice, bob) = (platform("alice"), platform("bob"));
    scripts::set_require_second_approver(&s.pool, false, &alice)
        .await
        .unwrap();
    let id = scripts::create_script(&s.pool, &input("dir"), &alice)
        .await
        .unwrap();
    scripts::set_require_second_approver(&s.pool, true, &alice)
        .await
        .unwrap();
    let script_run = RunInput {
        script_id: Some(id),
        ..run("script", Target::Group(f.tp))
    };
    let e = err(runs::create_run(&s.pool, &script_run, &alice)
        .await
        .unwrap_err());
    assert!(e.contains("核准"), "{e}");
    let h = sha_of(&s.pool, id).await;
    assert!(
        scripts::approve_script(&s.pool, id, &h, &alice)
            .await
            .is_err()
    );
    scripts::approve_script(&s.pool, id, &h, &bob)
        .await
        .unwrap();
    runs::create_run(&s.pool, &script_run, &alice)
        .await
        .unwrap();
}

/// 取消與報到同時發生：取消先完成時，報到不能送出已取消的指令
#[sqlx::test(migrations = false)]
async fn canceled_while_checking_in_is_not_delivered(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let f = fleet(&s).await;
    let a = &f.tp_dev[0];
    let (run_id, _) = runs::create_run(
        &s.pool,
        &run("reboot", Target::Device(a.device_id)),
        &platform("admin"),
    )
    .await
    .unwrap();
    // 模擬取消的交易：已改好狀態但還沒 commit
    let mut tx = s.pool.begin().await.unwrap();
    sqlx::query("UPDATE command_targets SET status = 'canceled' WHERE run_id = $1")
        .bind(run_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE command_runs SET canceled_at = now() WHERE id = $1")
        .bind(run_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    let checkin = {
        let s = &s;
        async move { checkin(s, a).await }
    };
    let commit = async move {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        tx.commit().await.unwrap();
    };
    let (r, _) = tokio::join!(checkin, commit);
    assert!(r.commands.is_empty(), "{:?}", r.commands);
}
