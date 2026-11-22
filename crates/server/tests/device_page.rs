mod common;

use common::TestServer;
use endpoint_server::web::auth::Role;
use sqlx::PgPool;
use uuid::Uuid;

async fn exec(s: &TestServer, sql: &str, id: Uuid) {
    sqlx::query(sqlx::AssertSqlSafe(sql.to_string()))
        .bind(id)
        .execute(&s.pool)
        .await
        .unwrap();
}

async fn rule(s: &TestServer, name: &str, severity: &str) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO compliance_rules (name, kind, severity, params, created_by) \
         VALUES ($1, 'forbidden_software', $2, '{\"name\":\"x\"}'::jsonb, 't') RETURNING id",
    )
    .bind(name)
    .bind(severity)
    .fetch_one(&s.pool)
    .await
    .unwrap()
}

async fn failed_deployment(s: &TestServer, id: Uuid) {
    sqlx::query(
        "INSERT INTO packages (name, version, kind, file_name, size, sha256, install_args, detect_name, created_by) \
         VALUES ('App', '1', 'exe', 'a.exe', 10, repeat('a', 64), '/S', 'App*', 'admin')",
    )
    .execute(&s.pool)
    .await
    .unwrap();
    exec(
        s,
        "WITH dep AS (INSERT INTO deployments (name, package_id, action, stage, max_failure_pct, min_samples, created_by) \
         SELECT '安裝 App', max(id), 'install', 'all', 10, 20, 'admin' FROM packages RETURNING id) \
         INSERT INTO deployment_status (deployment_id, device_id, status, revision, message) \
         SELECT dep.id, $1, 'failed', 1, '結束代碼 1603' FROM dep",
        id,
    )
    .await;
}

async fn command(s: &TestServer, id: Uuid, status: &str, ago: &str) {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "WITH r AS (INSERT INTO command_runs (action, target_label, created_by, expires_at) \
         VALUES ('reboot', 'x', 'admin', now() + interval '1 day') RETURNING id) \
         INSERT INTO command_targets (run_id, device_id, status, finished_at) \
         SELECT r.id, $1, $2, now() - interval '{ago}' FROM r"
    )))
    .bind(id)
    .bind(status)
    .execute(&s.pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = false)]
async fn windows_device_shows_cards_and_issues(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(2).await;
    let id = s.enroll_ok(&tok, None, None).await.device_id;
    exec(
        &s,
        "UPDATE devices SET last_seen_at = now(), section_errors = '{\"patches\":\"WMI timeout\"}' WHERE id = $1",
        id,
    )
    .await;
    let high = rule(&s, "禁用軟體X", "high").await;
    let medium = rule(&s, "舊版壓縮工具", "medium").await;
    for (r, status) in [(high, "violating"), (medium, "unknown")] {
        sqlx::query(
            "INSERT INTO device_violations (device_id, rule_id, status, detail) VALUES ($1, $2, $3, '{}'::jsonb)",
        )
        .bind(id)
        .bind(r)
        .bind(status)
        .execute(&s.pool)
        .await
        .unwrap();
    }
    exec(
        &s,
        "INSERT INTO update_policy_status (device_id, state, reboot_pending, reboot_pending_since, last_patch_date) \
         VALUES ($1, 'applied', true, now() - interval '10 days', '2026-11-01')",
        id,
    )
    .await;
    failed_deployment(&s, id).await;
    command(&s, id, "failed", "2 days").await;
    command(&s, id, "failed", "10 days").await;

    let admin = s.admin_client().await;
    let (status, html) = s.page(&admin, &format!("/devices/{id}")).await;
    assert_eq!(status, 200);
    // 狀態卡
    assert!(
        html.contains(
            r#"<div class="stat-value">違反 1 條</div><div class="stat-sub">其中高風險 1 條</div>"#
        ),
        "{html}"
    );
    assert!(html.contains(r#"<div class="stat-value">2026-11-01</div>"#));
    assert!(
        html.contains(
            r#"<div class="stat-value">0 / 1</div><div class="stat-sub">失敗 1 個</div>"#
        )
    );
    assert!(html.contains("最後回報 剛剛"));
    // 問題清單：高風險在前、收集錯誤在後；10 天前的失敗指令不列
    for needle in [
        "<span class=\"t\">禁用軟體X</span>",
        "無法判斷：舊版壓縮工具",
        "派送失敗：安裝 App",
        "結束代碼 1603",
        "<span class=\"t\">等待重新開機</span>",
        "收集錯誤：修補",
        "WMI timeout",
    ] {
        assert!(html.contains(needle), "{needle}: {html}");
    }
    assert_eq!(html.matches("遠端指令失敗：重新開機").count(), 1);
    let pos = |n: &str| html.find(n).unwrap();
    assert!(pos("派送失敗：安裝 App") < pos("收集錯誤：修補"));
    assert!(
        pos("等待重新開機</span>") < pos("無法判斷：舊版壓縮工具"),
        "超過 7 天是高"
    );
    // 預設分頁是時間軸；舊的收集錯誤卡片已併入問題清單
    assert!(html.contains(&format!(
        r#"hx-get="/devices/{id}/tab/timeline" hx-trigger="load""#
    )));
    assert!(!html.contains("<h2>收集錯誤</h2>"));
    assert!(!html.contains(" style="));
}

#[sqlx::test(migrations = false)]
async fn clean_and_linux_devices(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(2).await;
    let win = s.enroll_ok(&tok, None, None).await.device_id;
    let linux = s.enroll_ok(&tok, None, None).await.device_id;
    exec(
        &s,
        "UPDATE devices SET last_seen_at = now() WHERE id = $1",
        win,
    )
    .await;
    exec(
        &s,
        "UPDATE devices SET os_family = 'linux', last_seen_at = now() - interval '9 days' WHERE id = $1",
        linux,
    )
    .await;
    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, &format!("/devices/{win}")).await;
    assert!(html.contains("沒有發現問題"), "{html}");
    assert!(html.contains(r#"<div class="stat-value">合規</div>"#));

    let (_, html) = s.page(&admin, &format!("/devices/{linux}")).await;
    assert!(html.contains("Agent 版本") && html.contains("開機時間"));
    assert!(html.contains("離線超過 7 天") && html.contains("最後回報 9 天前"));
    assert!(html.contains(r#"class="card stat bad""#));
    for t in ["compliance", "updates", "deployments"] {
        assert!(!html.contains(&format!("/tab/{t}\"")), "{t}");
    }
    let (st, _) = s
        .page(&admin, &format!("/devices/{linux}/tab/timeline"))
        .await;
    assert_eq!(st, 200);
}

#[sqlx::test(migrations = false)]
async fn runs_in_label_tag_filter_and_hint(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(5).await;
    let mut ids = Vec::new();
    for (name, kind, detail) in [
        ("env-phys", Some("host"), Some("none")),
        ("env-vm", Some("host"), Some("microsoft")),
        ("env-ctr", Some("container"), Some("docker")),
        ("env-wsl", Some("wsl"), Some("2")),
        ("env-old", None, None),
    ] {
        let id = s.enroll_ok(&tok, None, None).await.device_id;
        sqlx::query(
            "UPDATE devices SET hostname = $2, runs_in = $3, runs_in_detail = $4 WHERE id = $1",
        )
        .bind(id)
        .bind(name)
        .bind(kind)
        .bind(detail)
        .execute(&s.pool)
        .await
        .unwrap();
        ids.push(id);
    }
    let admin = s.admin_client().await;

    // 清單：只標出容器與 WSL；篩選
    let (_, html) = s.page(&admin, "/devices").await;
    assert!(
        html.contains(r#">容器（docker）</span>"#)
            && html.contains(r#">WSL 2</span>"#)
            && !html.contains(r#"<span class="tag info">實體機</span>"#),
        "{html}"
    );
    assert!(html.contains(r#"<select name="env""#));
    // 標籤滑鼠移上去有白話說明
    assert!(html.contains(r#"<span class="tag info" title="WSL（Windows Subsystem for Linux）"#));
    assert!(html.contains("WSL（Windows 裡的 Linux）"), "篩選選項附說明");
    for (env, want) in [
        ("physical", "env-phys"),
        ("vm", "env-vm"),
        ("container", "env-ctr"),
        ("wsl", "env-wsl"),
    ] {
        let (_, html) = s.page(&admin, &format!("/devices?env={env}")).await;
        let table = &html[html.find("<table").unwrap()..];
        let shown: Vec<&str> = ["env-phys", "env-vm", "env-ctr", "env-wsl", "env-old"]
            .into_iter()
            .filter(|n| table.contains(&format!(">{n}<")))
            .collect();
        assert_eq!(shown, [want], "{env}");
        // 翻頁與排序連結保留篩選
        assert!(html.contains(&format!("env={env}")), "{env}");
    }
    let (_, html) = s.page(&admin, "/devices?env=bogus").await;
    assert!(html.contains(">env-old<"), "不認得的值當成全部");

    // 裝置頁：顯示執行環境；容器有提示，其他沒有
    let (_, html) = s.page(&admin, &format!("/devices/{}", ids[1])).await;
    assert!(html.contains("虛擬機（Hyper-V）") && !html.contains("Agent 在容器內執行"));
    let (_, html) = s.page(&admin, &format!("/devices/{}", ids[2])).await;
    assert!(html.contains("容器（docker）") && html.contains("Agent 在容器內執行"));
    let (_, html) = s.page(&admin, &format!("/devices/{}", ids[3])).await;
    assert!(html.contains("WSL 2") && html.contains("裝在 Windows 電腦裡的 Linux 環境"));
    let (_, html) = s.page(&admin, &format!("/devices/{}", ids[0])).await;
    assert!(html.contains("實體機") && !html.contains("裝在 Windows 電腦裡"));
    let (_, html) = s.page(&admin, &format!("/devices/{}", ids[4])).await;
    assert!(html.contains("Agent 尚未回報"));
}

#[sqlx::test(migrations = false)]
async fn timeline_merges_sources_newest_first(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let id = s.enroll_ok(&tok, None, None).await.device_id;
    exec(
        &s,
        "UPDATE devices SET enrolled_at = now() - interval '1 day' WHERE id = $1",
        id,
    )
    .await;
    exec(
        &s,
        "INSERT INTO violation_events (device_id, rule_name, severity, from_status, to_status, detail, at) VALUES \
         ($1, 'R', 'high', 'none', 'violating', '{}', now() - interval '3 hours'), \
         ($1, 'R', 'high', 'violating', 'none', '{}', now() - interval '1 hour')",
        id,
    )
    .await;
    exec(
        &s,
        "INSERT INTO inventory_changes (device_id, section, change, item_key, detected_at) VALUES \
         ($1, 'software', 'added', '7-Zip|x64|Igor', date_trunc('second', now()) - interval '2 hours'), \
         ($1, 'software', 'added', 'Chrome|x64|Google', date_trunc('second', now()) - interval '2 hours'), \
         ($1, 'software', 'removed', 'WinRAR|x86|', date_trunc('second', now()) - interval '2 hours')",
        id,
    )
    .await;
    command(&s, id, "succeeded", "30 minutes").await;
    failed_deployment(&s, id).await;
    exec(
        &s,
        "INSERT INTO audit_log (actor, action, target, at) VALUES ('admin', 'device_move', $1::text, now() - interval '4 hours')",
        id,
    )
    .await;

    let admin = s.admin_client().await;
    let (status, html) = s.page(&admin, &format!("/devices/{id}/tab/timeline")).await;
    assert_eq!(status, 200);
    let needles = [
        "派送「安裝 App」失敗",
        "指令「重新開機」成功",
        "「R」恢復合規",
        "軟體：新增 2、移除 1",
        "違反「R」",
        "移動裝置群組",
        "<div class=\"tl-title\">註冊</div>",
    ];
    let mut last = 0;
    for n in needles {
        let p = html.find(n).unwrap_or_else(|| panic!("{n}: {html}"));
        assert!(p >= last, "{n} 順序不對：{html}");
        last = p;
    }
    assert!(html.contains("7-Zip、Chrome、WinRAR"));
    assert!(html.contains("由 admin"));
    assert!(!html.contains("載入更早的事件"));
}

#[sqlx::test(migrations = false)]
async fn timeline_pages_without_gaps(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let id = s.enroll_ok(&tok, None, None).await.device_id;
    // 80 筆違規事件與 30 筆指令交錯
    exec(
        &s,
        "INSERT INTO violation_events (device_id, rule_name, severity, from_status, to_status, detail, at) \
         SELECT $1, 'P' || lpad(i::text, 2, '0'), 'low', 'none', 'violating', '{}', now() - i * interval '1 minute' \
         FROM generate_series(1, 80) i",
        id,
    )
    .await;
    for i in 0..30 {
        command(&s, id, "succeeded", &format!("{} minutes", 2 * i + 1)).await;
    }
    let admin = s.admin_client().await;
    let mut url = format!("/devices/{id}/tab/timeline");
    let mut all = String::new();
    for _ in 0..10 {
        let (status, html) = s.page(&admin, &url).await;
        assert_eq!(status, 200, "{url}");
        all.push_str(&html);
        let marker = "hx-get=\"/devices/";
        let Some(p) = html.find(&format!("{marker}{id}/timeline?before=")) else {
            break;
        };
        let rest = &html[p + "hx-get=\"".len()..];
        url = rest[..rest.find('"').unwrap()].replace("&#38;", "&");
    }
    for i in 1..=80 {
        assert_eq!(
            all.matches(&format!("違反「P{i:02}」")).count(),
            1,
            "P{i:02}"
        );
    }
    assert_eq!(all.matches("指令「重新開機」成功").count(), 30);
    assert_eq!(all.matches("<div class=\"tl-title\">註冊</div>").count(), 1);

    // 範圍外 404、before 格式錯誤 400
    let gary = s.login_as("gary", Role::GroupAdmin, &["別的群組"]).await;
    let (st, _) = s
        .page(
            &gary,
            &format!("/devices/{id}/timeline?before=2026-01-01T00:00:00Z"),
        )
        .await;
    assert_eq!(st, 404);
    let (st, _) = s
        .page(&admin, &format!("/devices/{id}/timeline?before=bad"))
        .await;
    assert_eq!(st, 400);
}

#[sqlx::test(migrations = false)]
async fn status_variants(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(3).await;
    let dup = s.enroll_ok(&tok, None, None).await.device_id;
    let linux = s.enroll_ok(&tok, None, None).await.device_id;
    exec(
        &s,
        "UPDATE devices SET status = 'duplicate_suspect', last_seen_at = now() WHERE id = $1",
        dup,
    )
    .await;
    exec(
        &s,
        "INSERT INTO update_policy_status (device_id, state, detail, reboot_pending) \
         VALUES ($1, 'conflict', '群組原則覆寫了設定', false)",
        dup,
    )
    .await;
    exec(
        &s,
        "INSERT INTO packages (name, version, kind, file_name, size, sha256, install_args, detect_name, created_by) \
         SELECT 'App', '1', 'exe', 'a.exe', 10, repeat('a', 64), '/S', 'App*', 'admin' WHERE $1::uuid IS NOT NULL",
        dup,
    )
    .await;
    exec(
        &s,
        "WITH dep AS (INSERT INTO deployments (name, package_id, action, stage, max_failure_pct, min_samples, created_by) \
         SELECT 'OK App', max(id), 'install', 'all', 10, 20, 'admin' FROM packages RETURNING id) \
         INSERT INTO deployment_status (deployment_id, device_id, status, revision) \
         SELECT dep.id, $1, 'succeeded', 1 FROM dep",
        dup,
    )
    .await;
    exec(
        &s,
        "UPDATE devices SET os_family = 'linux', agent_version = '0.10.0', last_seen_at = now() WHERE id = $1",
        linux,
    )
    .await;
    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, &format!("/devices/{dup}")).await;
    for needle in [
        "<span class=\"t\">疑似重複</span>",
        "更新原則衝突",
        "群組原則覆寫了設定",
        r#"<div class="stat-value">1 / 1</div><div class="stat-sub">全部成功</div>"#,
        "最後修補日期・原則衝突",
    ] {
        assert!(html.contains(needle), "{needle}: {html}");
    }
    let (_, html) = s.page(&admin, &format!("/devices/{linux}")).await;
    assert!(
        html.contains(r#"<div class="stat-value">0.10.0</div>"#),
        "{html}"
    );

    // 待核准的重新註冊
    let old = s
        .enroll_ok(&tok, Some("UUID-P"), Some("SN-P"))
        .await
        .device_id;
    let tok2 = s.create_token(1).await;
    let pending = s
        .enroll_ok(&tok2, Some("UUID-P"), Some("SN-P"))
        .await
        .device_id;
    assert_ne!(old, pending);
    let (_, html) = s.page(&admin, &format!("/devices/{pending}")).await;
    assert!(html.contains("待核准的重新註冊"), "{html}");
}
