//! Linux 裝置的後台畫面：裝置列表的作業系統篩選、裝置頁分頁、帳號與權限、軟體頁篩選。

mod common;

use common::TestServer;
use endpoint_server::web::auth::Role;
use protocol::{AccountsInfo, LocalUser, PrincipalKind, PrivilegeEntry};
use sqlx::PgPool;
use uuid::Uuid;

/// 一台 Windows（WIN-01）、一台 Linux（LNX-01），都在群組「混合」，各裝一個軟體
async fn mixed(s: &TestServer) -> (Uuid, Uuid) {
    let tok = s.create_group_token("混合", 2).await;
    let win = s.enroll_ok(&tok, None, None).await.device_id;
    let linux = s.enroll_ok(&tok, None, None).await.device_id;
    for (id, host, os, sw) in [
        (win, "WIN-01", "windows", "Google Chrome"),
        (linux, "LNX-01", "linux", "openssh-server"),
    ] {
        sqlx::query("UPDATE devices SET hostname = $2, os_family = $3 WHERE id = $1")
            .bind(id)
            .bind(host)
            .bind(os)
            .execute(&s.pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO device_software (device_id, name, version, arch) VALUES ($1, $2, '1.0', 'x64')",
        )
        .bind(id)
        .bind(sw)
        .execute(&s.pool)
        .await
        .unwrap();
    }
    // 兩台都有的軟體
    for id in [win, linux] {
        sqlx::query(
            "INSERT INTO device_software (device_id, name, version, arch) VALUES ($1, 'zlib', '1.3', 'x64')",
        )
        .bind(id)
        .execute(&s.pool)
        .await
        .unwrap();
    }
    (win, linux)
}

#[sqlx::test(migrations = false)]
async fn device_list_filters_by_os(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.admin_client().await;
    mixed(&s).await;

    let (_, html) = s.page(&c, "/devices").await;
    assert!(html.contains("WIN-01") && html.contains("LNX-01"), "{html}");
    assert!(html.contains(r#"<select name="os""#));
    // Linux 那一列有標籤，Windows 沒有
    assert_eq!(
        html.matches(r#"<span class="tag info">Linux</span>"#)
            .count(),
        1
    );

    let (_, html) = s.page(&c, "/devices?os=linux").await;
    assert!(
        !html.contains("WIN-01") && html.contains("LNX-01"),
        "{html}"
    );
    assert!(html.contains(r#"<option value="linux" selected>"#));
    let (_, html) = s.page(&c, "/devices?os=windows").await;
    assert!(html.contains("WIN-01") && !html.contains("LNX-01"));
    // 不認得的值當成全部
    let (st, html) = s.page(&c, "/devices?os=bogus").await;
    assert_eq!(st, 200);
    assert!(html.contains("WIN-01") && html.contains("LNX-01"));
}

#[sqlx::test(migrations = false)]
async fn linux_device_page_shows_only_linux_tabs(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.admin_client().await;
    let (win, linux) = mixed(&s).await;

    let (_, html) = s.page(&c, &format!("/devices/{linux}")).await;
    for t in ["commands", "software", "services", "accounts", "changes"] {
        assert!(html.contains(&format!("/tab/{t}\"")), "{t}: {html}");
    }
    // 合規分頁只在有容器執行環境時顯示（容器規則）
    assert!(!html.contains("/tab/compliance\""), "{html}");
    for t in ["security", "deployments", "updates", "patches"] {
        assert!(!html.contains(&format!("/tab/{t}\"")), "{t}: {html}");
        let (st, _) = s.page(&c, &format!("/devices/{linux}/tab/{t}")).await;
        assert_eq!(st, 404, "{t}");
    }

    let (_, html) = s.page(&c, &format!("/devices/{win}")).await;
    assert!(html.contains("/tab/patches\"") && !html.contains("/tab/accounts\""));
    let (st, _) = s.page(&c, &format!("/devices/{win}/tab/accounts")).await;
    assert_eq!(st, 404);
    let (st, _) = s.page(&c, &format!("/devices/{win}/tab/patches")).await;
    assert_eq!(st, 200);
}

fn accounts() -> AccountsInfo {
    AccountsInfo {
        users: vec![
            LocalUser {
                name: "alice".into(),
                uid: 1000,
                shell: "/bin/bash".into(),
                locked: Some(false),
                password_changed: protocol::timefmt::ymd(2026, 1, 2),
            },
            LocalUser {
                name: "bob".into(),
                uid: 1001,
                shell: "/bin/zsh".into(),
                locked: None,
                password_changed: None,
            },
        ],
        system_user_count: 27,
        privileged: vec![
            PrivilegeEntry {
                principal: "root".into(),
                kind: PrincipalKind::User,
                source: "uid0".into(),
            },
            PrivilegeEntry {
                principal: "toor".into(),
                kind: PrincipalKind::User,
                source: "uid0".into(),
            },
            PrivilegeEntry {
                principal: "alice".into(),
                kind: PrincipalKind::User,
                source: "group:sudo".into(),
            },
            PrivilegeEntry {
                principal: "admins".into(),
                kind: PrincipalKind::Group,
                source: "sudoers:/etc/sudoers.d/admins".into(),
            },
        ],
        sudoers_unparsed: vec!["Host_Alias SERVERS = db1, db2".into()],
    }
}

#[sqlx::test(migrations = false)]
async fn accounts_tab(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let (_, linux) = mixed(&s).await;
    let c = s.admin_client().await;
    let url = format!("/devices/{linux}/tab/accounts");

    let (st, html) = s.page(&c, &url).await;
    assert_eq!(st, 200);
    assert!(html.contains("尚無帳號資料"), "{html}");

    sqlx::query("INSERT INTO device_accounts (device_id, data) VALUES ($1, $2)")
        .bind(linux)
        .bind(serde_json::to_value(accounts()).unwrap())
        .execute(&s.pool)
        .await
        .unwrap();
    let (_, html) = s.page(&c, &url).await;
    // 只有非 root 的 UID 0 帳號有警示，而且排在最前面
    assert_eq!(
        html.matches(r#"<span class="tag bad">UID 0</span>"#)
            .count(),
        1
    );
    let toor = html.find("toor").unwrap();
    assert!(toor < html.find("<td>root</td>").unwrap(), "{html}");
    assert!(html.contains("<td>sudo 群組</td>"), "{html}");
    assert!(html.contains("<td>/etc/sudoers.d/admins</td>"), "{html}");
    assert!(html.contains("<td>群組</td>"));
    assert!(html.contains("<td>alice</td><td class=\"num\">1000</td><td>/bin/bash</td><td>否</td><td>2026-01-02</td>"), "{html}");
    assert!(
        html.contains(
            "<td>bob</td><td class=\"num\">1001</td><td>/bin/zsh</td><td>無法讀取</td><td></td>"
        ),
        "{html}"
    );
    assert!(html.contains("Host_Alias SERVERS = db1, db2"));
    assert!(html.contains("另有 27 個系統帳號未列出"));

    // 沒有無法解析的行時，不顯示那一段
    let mut a = accounts();
    a.sudoers_unparsed.clear();
    sqlx::query("UPDATE device_accounts SET data = $2 WHERE device_id = $1")
        .bind(linux)
        .bind(serde_json::to_value(a).unwrap())
        .execute(&s.pool)
        .await
        .unwrap();
    let (_, html) = s.page(&c, &url).await;
    assert!(!html.contains("無法解析的 sudoers 設定"));

    // 改壞的 jsonb 當成沒有資料
    sqlx::query("UPDATE device_accounts SET data = '{\"x\":1}' WHERE device_id = $1")
        .bind(linux)
        .execute(&s.pool)
        .await
        .unwrap();
    let (st, html) = s.page(&c, &url).await;
    assert_eq!(st, 200);
    assert!(html.contains("尚無帳號資料"));
}

#[sqlx::test(migrations = false)]
async fn accounts_tab_respects_scope(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let (_, linux) = mixed(&s).await;
    // 唯讀檢視者至少要有一個群組：給它另一個群組
    s.create_group_token("其他", 1).await;
    let other = s.login_as("carol", Role::Viewer, &["其他"]).await;
    let (st, _) = s
        .page(&other, &format!("/devices/{linux}/tab/accounts"))
        .await;
    assert_eq!(st, 404);
    let viewer = s.login_as("dave", Role::Viewer, &["混合"]).await;
    let (st, _) = s
        .page(&viewer, &format!("/devices/{linux}/tab/accounts"))
        .await;
    assert_eq!(st, 200);
}

#[sqlx::test(migrations = false)]
async fn software_search_defaults_to_windows(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.admin_client().await;
    mixed(&s).await;

    let (_, html) = s.page(&c, "/software?q=o").await;
    assert!(
        html.contains("Google Chrome") && !html.contains("openssh-server"),
        "{html}"
    );
    assert!(html.contains(r#"<option value="windows" selected>"#));
    // 兩台都有的軟體：預設只算 Windows
    let (_, html) = s.page(&c, "/software?q=zlib").await;
    assert!(
        html.contains(r#"href="/devices?software=zlib&#38;version=1.3&#38;os=windows">1</a>"#),
        "{html}"
    );

    let (_, html) = s.page(&c, "/software?q=o&os=linux").await;
    assert!(!html.contains("Google Chrome") && html.contains("openssh-server"));
    let (_, html) = s.page(&c, "/software?q=zlib&os=all").await;
    assert!(
        html.contains(r#"href="/devices?software=zlib&#38;version=1.3&#38;os=">2</a>"#),
        "{html}"
    );

    // 從軟體頁點進裝置列表：帶著作業系統篩選
    let (_, html) = s
        .page(&c, "/devices?software=zlib&version=1.3&os=linux")
        .await;
    assert!(
        html.contains("LNX-01") && !html.contains("WIN-01"),
        "{html}"
    );
}
