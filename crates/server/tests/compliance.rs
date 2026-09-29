mod common;

use common::{TestAgent, TestServer};
use protocol::{Arch, InventoryPayload, InventoryUpload, PatchItem, SCHEMA_VERSION, SoftwareItem};
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

async fn put(s: &TestServer, a: &TestAgent, p: InventoryPayload) {
    let section = p.section().as_str();
    let r = s
        .client(Some(a))
        .put(s.url(&format!("/v1/inventory/{section}")))
        .json(&InventoryUpload {
            schema_version: SCHEMA_VERSION,
            payload: p,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
}

/// 直接寫入規則並 bump generation（不經 admin API）。
async fn add_rule(s: &TestServer, kind: &str, params: serde_json::Value) -> i64 {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO compliance_rules (name, kind, severity, params, created_by) \
         VALUES ($1, $2, 'high', $3::jsonb, 'test') RETURNING id",
    )
    .bind(format!("{kind} rule"))
    .bind(kind)
    .bind(params.to_string())
    .fetch_one(&s.pool)
    .await
    .unwrap();
    bump(s).await;
    id
}

async fn bump(s: &TestServer) {
    sqlx::query("UPDATE compliance_state SET generation = generation + 1")
        .execute(&s.pool)
        .await
        .unwrap();
}

async fn violations(s: &TestServer, a: &TestAgent) -> Vec<(i64, String)> {
    sqlx::query_as(
        "SELECT rule_id, status FROM device_violations WHERE device_id = $1 ORDER BY rule_id",
    )
    .bind(a.device_id)
    .fetch_all(&s.pool)
    .await
    .unwrap()
}

async fn events(s: &TestServer, a: &TestAgent) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT from_status, to_status FROM violation_events WHERE device_id = $1 ORDER BY id",
    )
    .bind(a.device_id)
    .fetch_all(&s.pool)
    .await
    .unwrap()
}

async fn setup(pool: PgPool) -> (TestServer, TestAgent) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    (s, a)
}

#[sqlx::test(migrations = false)]
async fn upload_triggers_evaluation_and_history(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let rule = add_rule(
        &s,
        "forbidden_software",
        serde_json::json!({"name": "*TeamViewer*"}),
    )
    .await;

    put(
        &s,
        &a,
        InventoryPayload::Software(vec![sw("TeamViewer 15", "15.1")]),
    )
    .await;
    assert_eq!(violations(&s, &a).await, vec![(rule, "violating".into())]);
    assert_eq!(
        events(&s, &a).await,
        vec![("none".into(), "violating".into())]
    );

    // 版本變了但仍違規：只更新細節，不寫歷程
    put(
        &s,
        &a,
        InventoryPayload::Software(vec![sw("TeamViewer 15", "15.2")]),
    )
    .await;
    let detail: String =
        sqlx::query_scalar("SELECT detail::text FROM device_violations WHERE device_id = $1")
            .bind(a.device_id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert!(detail.contains("15.2"), "{detail}");
    assert_eq!(events(&s, &a).await.len(), 1);

    put(
        &s,
        &a,
        InventoryPayload::Software(vec![sw("7-Zip", "23.01")]),
    )
    .await;
    assert!(violations(&s, &a).await.is_empty());
    assert_eq!(events(&s, &a).await[1], ("violating".into(), "none".into()));
}

#[sqlx::test(migrations = false)]
async fn broken_rule_does_not_fail_upload(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let broken = add_rule(&s, "required_kb", serde_json::json!({"oops": true})).await;
    let good = add_rule(&s, "required_kb", serde_json::json!({"kb": "KB5031455"})).await;
    put(
        &s,
        &a,
        InventoryPayload::Patches(vec![PatchItem {
            kb: "KB1".into(),
            installed_on: None,
        }]),
    )
    .await;
    assert_eq!(
        violations(&s, &a).await,
        vec![(broken, "unknown".into()), (good, "violating".into())]
    );
}

#[sqlx::test(migrations = false)]
async fn retire_clears_and_group_move_reevaluates(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let g = s.group_id("資訊亭").await;
    let rule = add_rule(&s, "required_kb", serde_json::json!({"kb": "KB5031455"})).await;
    sqlx::query(
        "INSERT INTO compliance_rule_groups (rule_id, group_id, mode) VALUES ($1, $2, 'exclude')",
    )
    .bind(rule)
    .bind(g)
    .execute(&s.pool)
    .await
    .unwrap();
    bump(&s).await;
    put(&s, &a, InventoryPayload::Patches(vec![])).await;
    assert_eq!(violations(&s, &a).await.len(), 1);

    endpoint_server::groups::move_device(&s.pool, a.device_id, Some(g), "t")
        .await
        .unwrap();
    assert!(
        violations(&s, &a).await.is_empty(),
        "移到排除群組後違規消失"
    );
    endpoint_server::groups::move_device(&s.pool, a.device_id, None, "t")
        .await
        .unwrap();
    assert_eq!(violations(&s, &a).await.len(), 1);

    endpoint_server::devices::retire(&s.pool, a.device_id, "t")
        .await
        .unwrap();
    assert!(violations(&s, &a).await.is_empty(), "除役後清除");
    assert_eq!(events(&s, &a).await.last().unwrap().1, "none");
}

use endpoint_server::compliance::admin::{self, RuleInput};

fn input(kind: &str, params: serde_json::Value) -> RuleInput {
    RuleInput {
        name: "禁止遠端桌面軟體".into(),
        description: String::new(),
        kind: kind.into(),
        severity: "high".into(),
        enabled: true,
        params,
        include: vec![],
        exclude: vec![],
    }
}

async fn generation(s: &TestServer) -> i64 {
    sqlx::query_scalar("SELECT generation FROM compliance_state")
        .fetch_one(&s.pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = false)]
async fn rule_crud_validates_and_audits(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let g = s.group_id("資訊亭").await;
    let kb = || serde_json::json!({"kb": "KB5034439"});
    let bad = RuleInput {
        include: vec![g],
        exclude: vec![g],
        ..input("required_kb", kb())
    };
    assert!(
        admin::create_rule(&s.pool, &bad, "admin").await.is_err(),
        "同一群組不能同時只套用又排除"
    );
    assert!(
        admin::create_rule(
            &s.pool,
            &input("required_kb", serde_json::json!({"kb": "x"})),
            "admin"
        )
        .await
        .is_err()
    );
    let blank = RuleInput {
        name: "  ".into(),
        ..input("required_kb", kb())
    };
    assert!(admin::create_rule(&s.pool, &blank, "admin").await.is_err());

    let before = generation(&s).await;
    let id = admin::create_rule(
        &s.pool,
        &input("required_kb", serde_json::json!({"kb": " kb5034439"})),
        "admin",
    )
    .await
    .unwrap();
    let params: String =
        sqlx::query_scalar("SELECT params::text FROM compliance_rules WHERE id = $1")
            .bind(id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(params, r#"{"kb": "KB5034439"}"#, "存正規化後的參數");
    let mut upd = input("required_kb", kb());
    upd.include = vec![g];
    admin::update_rule(&s.pool, id, &upd, "admin")
        .await
        .unwrap();
    let groups: Vec<(i64, String)> =
        sqlx::query_as("SELECT group_id, mode FROM compliance_rule_groups WHERE rule_id = $1")
            .bind(id)
            .fetch_all(&s.pool)
            .await
            .unwrap();
    assert_eq!(groups, vec![(g, "include".into())]);
    admin::delete_rule(&s.pool, id, "admin").await.unwrap();
    assert_eq!(generation(&s).await, before + 3);
    let actions: Vec<String> =
        sqlx::query_scalar("SELECT action FROM audit_log WHERE action LIKE 'rule_%' ORDER BY id")
            .fetch_all(&s.pool)
            .await
            .unwrap();
    assert_eq!(actions, ["rule_create", "rule_update", "rule_delete"]);
    assert!(
        admin::update_rule(&s.pool, id, &upd, "admin")
            .await
            .is_err(),
        "已刪除"
    );
}

#[sqlx::test(migrations = false)]
async fn exemption_marks_exempt_and_revoke_restores(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let rule = admin::create_rule(
        &s.pool,
        &input("required_kb", serde_json::json!({"kb": "KB5031455"})),
        "admin",
    )
    .await
    .unwrap();
    put(&s, &a, InventoryPayload::Patches(vec![])).await;
    assert_eq!(violations(&s, &a).await, vec![(rule, "violating".into())]);

    let now = chrono::Utc::now();
    let soon = now + chrono::Duration::days(30);
    for (reason, until) in [
        (" ", soon),
        ("ok", now + chrono::Duration::days(400)),
        ("ok", now - chrono::Duration::minutes(1)),
    ] {
        assert!(
            admin::create_exemption(&s.pool, a.device_id, rule, reason, until, "admin")
                .await
                .is_err(),
            "{reason:?} {until}"
        );
    }

    let ex = admin::create_exemption(&s.pool, a.device_id, rule, "舊系統相容性", soon, "admin")
        .await
        .unwrap();
    assert_eq!(violations(&s, &a).await, vec![(rule, "exempt".into())]);
    admin::revoke_exemption(&s.pool, ex, "admin").await.unwrap();
    assert_eq!(violations(&s, &a).await, vec![(rule, "violating".into())]);
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action LIKE 'exemption_%'")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(n, 2);
}

use endpoint_server::compliance::worker;

fn kb_rule(kb: &str) -> RuleInput {
    input("required_kb", serde_json::json!({ "kb": kb }))
}

#[sqlx::test(migrations = false)]
async fn recompute_applies_rule_changes_to_all_devices(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(3).await;
    let mut agents = vec![];
    for _ in 0..3 {
        let a = s.enroll_ok(&tok, None, None).await;
        put(&s, &a, InventoryPayload::Patches(vec![])).await;
        agents.push(a);
    }
    let id = admin::create_rule(&s.pool, &kb_rule("KB5031455"), "admin")
        .await
        .unwrap();
    for a in &agents {
        assert!(violations(&s, a).await.is_empty(), "還沒重算");
    }
    worker::recompute_all(&s.pool).await.unwrap();
    for a in &agents {
        assert_eq!(violations(&s, a).await, vec![(id, "violating".into())]);
    }
    assert!(!worker::progress(&s.pool).await.unwrap().running);

    // 停用 → 重算後清除並寫解除事件
    let mut off = kb_rule("KB5031455");
    off.enabled = false;
    admin::update_rule(&s.pool, id, &off, "admin")
        .await
        .unwrap();
    assert!(worker::progress(&s.pool).await.unwrap().running);
    worker::recompute_all(&s.pool).await.unwrap();
    for a in &agents {
        assert!(violations(&s, a).await.is_empty());
        assert_eq!(
            events(&s, a).await.last().unwrap(),
            &("violating".to_string(), "none".to_string())
        );
    }
}

#[sqlx::test(migrations = false)]
async fn recompute_restarts_when_rules_change_midway(pool: PgPool) {
    let (s, a) = setup(pool).await;
    put(&s, &a, InventoryPayload::Patches(vec![])).await;
    admin::create_rule(&s.pool, &kb_rule("KB5031455"), "admin")
        .await
        .unwrap();
    // 模擬跑到一半（cursor 已越過這台）時規則又改了
    sqlx::query(
        "UPDATE compliance_state SET run_generation = generation, \
         cursor = 'ffffffff-ffff-ffff-ffff-ffffffffffff'",
    )
    .execute(&s.pool)
    .await
    .unwrap();
    let second = admin::create_rule(&s.pool, &kb_rule("KB5031456"), "admin")
        .await
        .unwrap();
    worker::recompute_all(&s.pool).await.unwrap();
    let v = violations(&s, &a).await;
    assert_eq!(v.len(), 2, "從頭重算，兩條規則都套用：{v:?}");
    assert_eq!(v[1].0, second);
    let (g, done): (i64, i64) =
        sqlx::query_as("SELECT generation, done_generation FROM compliance_state")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(g, done);
}

#[sqlx::test(migrations = false)]
async fn expired_exemption_is_removed_and_reevaluated(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let rule = admin::create_rule(&s.pool, &kb_rule("KB5031455"), "admin")
        .await
        .unwrap();
    put(&s, &a, InventoryPayload::Patches(vec![])).await;
    admin::create_exemption(
        &s.pool,
        a.device_id,
        rule,
        "暫時",
        chrono::Utc::now() + chrono::Duration::days(1),
        "admin",
    )
    .await
    .unwrap();
    assert_eq!(violations(&s, &a).await, vec![(rule, "exempt".into())]);
    sqlx::query("UPDATE compliance_exemptions SET expires_at = now() - interval '1 second'")
        .execute(&s.pool)
        .await
        .unwrap();
    assert_eq!(worker::expire_exemptions(&s.pool).await.unwrap(), 1);
    assert_eq!(violations(&s, &a).await, vec![(rule, "violating".into())]);
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'exemption_expire'")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(n, 1);
}

#[sqlx::test(migrations = false)]
async fn daily_snapshot_and_history_cleanup(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let rule = admin::create_rule(&s.pool, &kb_rule("KB5031455"), "admin")
        .await
        .unwrap();
    put(&s, &a, InventoryPayload::Patches(vec![])).await;
    let today = chrono::Utc::now().date_naive();
    worker::snapshot_daily(&s.pool, today).await.unwrap();
    worker::snapshot_daily(&s.pool, today).await.unwrap();
    let row: (i32, i32, i32) = sqlx::query_as(
        "SELECT violating, unknown, exempt FROM compliance_daily WHERE day = $1 AND rule_id = $2",
    )
    .bind(today)
    .bind(rule)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(row, (1, 0, 0));

    sqlx::query("UPDATE violation_events SET at = now() - interval '400 days'")
        .execute(&s.pool)
        .await
        .unwrap();
    assert_eq!(worker::cleanup_history(&s.pool).await.unwrap(), 1);
}

/// 上傳評估拿到舊規則集（背景重算已先處理過這台）時，不能把已停用規則的違規寫回去
#[sqlx::test(migrations = false)]
async fn stale_ruleset_is_reloaded_under_lock(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let id = admin::create_rule(&s.pool, &kb_rule("KB5031455"), "admin")
        .await
        .unwrap();
    put(&s, &a, InventoryPayload::Patches(vec![])).await;
    let stale = {
        let mut c = s.pool.acquire().await.unwrap();
        endpoint_server::compliance::store::load_ruleset(&mut c)
            .await
            .unwrap()
    };
    let mut off = kb_rule("KB5031455");
    off.enabled = false;
    admin::update_rule(&s.pool, id, &off, "admin")
        .await
        .unwrap();
    worker::recompute_all(&s.pool).await.unwrap();
    assert!(violations(&s, &a).await.is_empty());
    endpoint_server::compliance::store::refresh_device(&s.pool, &stale, a.device_id)
        .await
        .unwrap();
    assert!(violations(&s, &a).await.is_empty(), "不能用舊規則寫回違規");
}

/// 刪除規則也要寫「→ none」事件，歷程與通知才知道違規已結束
#[sqlx::test(migrations = false)]
async fn deleting_rule_records_resolution(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let id = admin::create_rule(&s.pool, &kb_rule("KB5031455"), "admin")
        .await
        .unwrap();
    put(&s, &a, InventoryPayload::Patches(vec![])).await;
    admin::delete_rule(&s.pool, id, "admin").await.unwrap();
    assert_eq!(
        events(&s, &a).await.last().unwrap(),
        &("violating".to_string(), "none".to_string())
    );
}

/// 單台裝置評估失敗不能卡住整個重算
#[sqlx::test(migrations = false)]
async fn recompute_skips_failing_device(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(2).await;
    let bad = s.enroll_ok(&tok, None, None).await;
    let good = s.enroll_ok(&tok, None, None).await;
    for a in [&bad, &good] {
        put(&s, a, InventoryPayload::Patches(vec![])).await;
    }
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE FUNCTION fail_one() RETURNS trigger AS $$ BEGIN \
           IF NEW.device_id = '{}' THEN RAISE EXCEPTION 'boom'; END IF; RETURN NEW; \
         END $$ LANGUAGE plpgsql",
        bad.device_id
    )))
    .execute(&s.pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER fail_one BEFORE INSERT ON device_violations \
         FOR EACH ROW EXECUTE FUNCTION fail_one()",
    )
    .execute(&s.pool)
    .await
    .unwrap();
    let id = admin::create_rule(&s.pool, &kb_rule("KB5031455"), "admin")
        .await
        .unwrap();
    worker::recompute_all(&s.pool).await.unwrap();
    assert_eq!(violations(&s, &good).await, vec![(id, "violating".into())]);
    assert!(!worker::progress(&s.pool).await.unwrap().running);
}

/// 核准重新註冊時不能與「寫入違規時外鍵取得的 KEY SHARE 鎖」互等：
/// 舊裝置的 Agent 正在上傳評估（持有 KEY SHARE）時，核准不能被卡住
#[sqlx::test(migrations = false)]
async fn approve_is_not_blocked_by_key_share(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let t = s.create_token(2).await;
    let old = s.enroll_ok(&t, Some("UUID-K"), Some("SN-K")).await;
    let new = s.enroll_ok(&t, Some("UUID-K"), Some("SN-K")).await;
    let mut holder = s.pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM devices WHERE id = $1 FOR KEY SHARE")
        .bind(old.device_id)
        .execute(&mut *holder)
        .await
        .unwrap();
    // 用 lock_timeout 判斷「在等鎖」，不受機器快慢影響
    let mut tx = s.pool.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout = '2s'")
        .execute(&mut *tx)
        .await
        .unwrap();
    let r = endpoint_server::devices::approve_in(&mut tx, new.device_id, "admin").await;
    holder.rollback().await.unwrap();
    assert!(r.is_ok(), "核准被 KEY SHARE 鎖卡住：{:#}", r.unwrap_err());
    tx.commit().await.unwrap();
}

/// 每日快照要包含沒有違規的啟用規則（趨勢圖顯示 0 而不是缺一天）
#[sqlx::test(migrations = false)]
async fn daily_snapshot_includes_rules_without_violations(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let rule = admin::create_rule(&s.pool, &kb_rule("KB5031455"), "admin")
        .await
        .unwrap();
    let today = chrono::Utc::now().date_naive();
    worker::snapshot_daily(&s.pool, today).await.unwrap();
    let row: Option<(i32, i32, i32)> = sqlx::query_as(
        "SELECT violating, unknown, exempt FROM compliance_daily WHERE day = $1 AND rule_id = $2",
    )
    .bind(today)
    .bind(rule)
    .fetch_optional(&s.pool)
    .await
    .unwrap();
    assert_eq!(row, Some((0, 0, 0)));
}
