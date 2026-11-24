//! 錯誤設定偵測：服務路徑沒加引號（Windows）、多餘的 UID 0 帳號（Linux）、規則的適用平台（第一期），
//! 開放的共用（第二期），對外開放的服務與遠端登入（第三期），帳號設定（第四期）。
mod common;

use std::collections::BTreeMap;

use common::{TestAgent, TestServer};
use endpoint_server::compliance::admin::{self, RuleInput};
use endpoint_server::compliance::rules::{Params, Rule, Severity};
use endpoint_server::compliance::{preview, worker};
use protocol::{
    AccountInfo, AccountsInfo, CheckinRequest, ExposureInfo, InventoryPayload, InventoryUpload,
    ListenItem, LocalUser, OsFamily, PrincipalKind, PrivilegeEntry, RdpInfo, SCHEMA_VERSION,
    ServiceItem, ShareAccess, ShareItem, SharesInfo, SshdInfo,
};
use serde_json::{Value, json};
use sqlx::PgPool;

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

async fn checkin_linux(s: &TestServer, a: &TestAgent) {
    let r = s
        .client(Some(a))
        .post(s.url("/v1/checkin"))
        .json(&CheckinRequest {
            os_family: Some(OsFamily::Linux),
            signing_keys: vec![],
            journal_id: None,
            events: vec![],
            schema_version: SCHEMA_VERSION,
            agent_version: "0.14.0".into(),
            boot_time: time::OffsetDateTime::now_utc(),
            logged_on_user: None,
            ip_addresses: vec![],
            section_hashes: BTreeMap::new(),
            section_errors: BTreeMap::new(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

fn input(name: &str, kind: &str, params: Value) -> RuleInput {
    RuleInput {
        name: name.into(),
        description: String::new(),
        kind: kind.into(),
        severity: "high".into(),
        enabled: true,
        params,
        include: vec![],
        exclude: vec![],
        template_key: None,
    }
}

async fn results(s: &TestServer, a: &TestAgent) -> Vec<(i64, String, Value)> {
    let rows: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT rule_id, status, detail::text FROM device_violations \
         WHERE device_id = $1 ORDER BY rule_id",
    )
    .bind(a.device_id)
    .fetch_all(&s.pool)
    .await
    .unwrap();
    rows.into_iter()
        .map(|(id, st, d)| (id, st, serde_json::from_str(&d).unwrap()))
        .collect()
}

fn svc(name: &str, path: Option<&str>) -> ServiceItem {
    ServiceItem {
        name: name.into(),
        display_name: None,
        start_mode: "Auto".into(),
        state: "Running".into(),
        binary_path: path.map(Into::into),
    }
}

fn root(name: &str, source: &str) -> PrivilegeEntry {
    PrivilegeEntry {
        principal: name.into(),
        kind: PrincipalKind::User,
        source: source.into(),
        ..Default::default()
    }
}

#[sqlx::test(migrations = false)]
async fn misconfig_rules_by_platform(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(2).await;
    let lin = s.enroll_ok(&tok, None, None).await;
    let win = s.enroll_ok(&tok, None, None).await;
    checkin_linux(&s, &lin).await;

    let unquoted = admin::create_rule(
        &s.pool,
        &input(
            "引號",
            "unquoted_service_path",
            json!({"except_services": ["Legacy*"]}),
        ),
        "admin",
    )
    .await
    .unwrap();
    let uid0 = admin::create_rule(
        &s.pool,
        &input("UID 0", "extra_root_account", json!({})),
        "admin",
    )
    .await
    .unwrap();
    worker::recompute_all(&s.pool).await.unwrap();
    // 還沒有資料：各自只在適用的平台上是「未知」
    let w = results(&s, &win).await;
    assert_eq!(w.len(), 1, "{w:?}");
    assert_eq!((w[0].0, w[0].1.as_str()), (unquoted, "unknown"));
    let l = results(&s, &lin).await;
    assert_eq!(l.len(), 1, "{l:?}");
    assert_eq!((l[0].0, l[0].1.as_str()), (uid0, "unknown"));

    put(
        &s,
        &win,
        InventoryPayload::Services(vec![
            svc("Spooler", Some(r"C:\Windows\System32\spoolsv.exe")),
            svc(
                "VendorSvc",
                Some(r"C:\Program Files\Vendor App\svc.exe -service"),
            ),
            svc("LegacyAgent", Some(r"C:\Old Tools\agent.exe")),
            svc("Quoted", Some(r#""C:\Program Files\Q\q.exe""#)),
            svc("NoPath", None),
        ]),
    )
    .await;
    let w = results(&s, &win).await;
    assert_eq!(w.len(), 1, "{w:?}");
    assert_eq!(w[0].1, "violating");
    assert_eq!(
        w[0].2,
        json!({"total": 1, "unquoted": [
            {"service": "VendorSvc", "path": r"C:\Program Files\Vendor App\svc.exe -service"}
        ]})
    );

    put(
        &s,
        &lin,
        InventoryPayload::Accounts(AccountsInfo {
            users: vec![],
            system_user_count: 20,
            privileged: vec![
                root("root", "uid0"),
                root("toor", "uid0"),
                root("alice", "/etc/sudoers"),
            ],
            sudoers_unparsed: vec![],
            ..Default::default()
        }),
    )
    .await;
    let l = results(&s, &lin).await;
    assert_eq!(l.len(), 1, "{l:?}");
    assert_eq!(l[0].1, "violating");
    assert_eq!(l[0].2, json!({"total": 1, "root_accounts": ["toor"]}));

    // 網頁：違規摘要與規則表單的適用平台
    let c = s.admin_client().await;
    let (_, html) = s
        .page(&c, &format!("/devices/{}/tab/compliance", win.device_id))
        .await;
    assert!(
        html.contains(
            r"服務路徑沒加引號：VendorSvc（C:\Program Files\Vendor App\svc.exe -service）"
        ),
        "{html}"
    );
    let (_, html) = s
        .page(&c, &format!("/devices/{}/tab/compliance", lin.device_id))
        .await;
    assert!(html.contains("root 以外的 UID 0 帳號：toor"), "{html}");
    let (st, html) = s
        .page(&c, "/compliance/rules/new?kind=extra_root_account")
        .await;
    assert_eq!(st, 200);
    assert!(html.contains("適用於：Linux"), "{html}");
    assert!(html.contains("p_except_names"), "{html}");
    let (_, html) = s.page(&c, &format!("/compliance/rules/{unquoted}")).await;
    assert!(html.contains("適用於：Windows"), "{html}");
    assert!(html.contains("Legacy*"), "{html}");
    let (_, html) = s.page(&c, "/compliance/rules").await;
    assert!(
        html.contains("服務路徑沒加引號 <span class=\"faint\">Windows</span>"),
        "{html}"
    );

    // 修好之後恢復
    put(
        &s,
        &win,
        InventoryPayload::Services(vec![svc("NoPath", None)]),
    )
    .await;
    assert!(results(&s, &win).await.is_empty());

    // 預覽只算適用的平台
    let rule = |kind: &str| Rule {
        id: 0,
        name: "x".into(),
        severity: Severity::High,
        include: vec![],
        exclude: vec![],
        check: Ok(Params::parse(kind, &json!({})).unwrap().compile()),
    };
    let p = preview::preview(&s.pool, rule("extra_root_account"))
        .await
        .unwrap();
    assert_eq!((p.devices, p.violating), (1, 1));
    let p = preview::preview(&s.pool, rule("unquoted_service_path"))
        .await
        .unwrap();
    assert_eq!((p.devices, p.violating), (1, 0));
}

fn share(kind: &str, name: &str, anon: ShareAccess, users: ShareAccess) -> ShareItem {
    ShareItem {
        kind: kind.into(),
        name: name.into(),
        path: format!("/srv/{name}"),
        anonymous: anon,
        all_users: users,
        no_root_squash: false,
        clients: vec![],
    }
}

#[sqlx::test(migrations = false)]
async fn open_shares(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(2).await;
    let lin = s.enroll_ok(&tok, None, None).await;
    let win = s.enroll_ok(&tok, None, None).await;
    checkin_linux(&s, &lin).await;
    let rule = admin::create_rule(
        &s.pool,
        &input(
            "共用",
            "open_share",
            json!({"anonymous": true, "all_users": true, "no_root_squash": true,
                   "except_shares": ["dept*"]}),
        ),
        "admin",
    )
    .await
    .unwrap();
    worker::recompute_all(&s.pool).await.unwrap();
    // 兩邊都適用：還沒有資料時都是未知
    for a in [&lin, &win] {
        let r = results(&s, a).await;
        assert_eq!((r.len(), r[0].1.as_str()), (1, "unknown"), "{r:?}");
    }

    put(
        &s,
        &win,
        InventoryPayload::Shares(SharesInfo {
            shares: vec![
                share("smb", "public", ShareAccess::Read, ShareAccess::Write),
                share("smb", "dept-sales", ShareAccess::None, ShareAccess::Write),
                share("smb", "docs", ShareAccess::None, ShareAccess::Read),
            ],
            errors: vec![],
        }),
    )
    .await;
    let r = results(&s, &win).await;
    assert_eq!((r[0].0, r[0].1.as_str()), (rule, "violating"));
    assert_eq!(
        r[0].2,
        json!({"total": 1, "shares": [
            {"name": "public", "kind": "smb", "path": "/srv/public", "issues": ["所有使用者可寫入"]}
        ]}),
        "匿名只能讀不算（只算可寫入）；部門共用在例外"
    );

    let mut nfs = share("nfs", "/export", ShareAccess::None, ShareAccess::Read);
    nfs.no_root_squash = true;
    nfs.clients = vec!["10.0.0.0/8".into()];
    put(
        &s,
        &lin,
        InventoryPayload::Shares(SharesInfo {
            shares: vec![nfs],
            errors: vec!["無法讀取 Samba 設定：x".into()],
        }),
    )
    .await;
    let r = results(&s, &lin).await;
    assert_eq!(r[0].1, "violating");
    assert_eq!(r[0].2["shares"][0]["issues"], json!(["no_root_squash"]));

    // 裝置頁：Windows 在「安全」分頁、Linux 在「帳號與權限」分頁
    let c = s.admin_client().await;
    let (_, html) = s
        .page(&c, &format!("/devices/{}/tab/security", win.device_id))
        .await;
    assert!(
        html.contains("共用資料夾") && html.contains("id=\"shares\""),
        "{html}"
    );
    assert!(
        html.contains("<span class=\"tag bad\">開放</span> public"),
        "{html}"
    );
    let (_, html) = s
        .page(&c, &format!("/devices/{}/tab/accounts", lin.device_id))
        .await;
    assert!(html.contains("來源：10.0.0.0/8；no_root_squash"), "{html}");
    assert!(html.contains("讀取失敗：無法讀取 Samba 設定：x"), "{html}");
    let (_, html) = s
        .page(&c, &format!("/devices/{}/tab/compliance", lin.device_id))
        .await;
    assert!(
        html.contains("開放的共用：/export（no_root_squash）"),
        "{html}"
    );

    // 規則表單
    let (_, html) = s.page(&c, &format!("/compliance/rules/{rule}")).await;
    assert!(html.contains("適用於：Windows、Linux"), "{html}");
    assert!(html.contains("dept*"), "{html}");

    // 修好之後恢復；只剩讀取失敗：未知
    put(
        &s,
        &lin,
        InventoryPayload::Shares(SharesInfo {
            shares: vec![],
            errors: vec!["無法讀取 Samba 設定：x".into()],
        }),
    )
    .await;
    assert_eq!(results(&s, &lin).await[0].1, "unknown");
    put(&s, &win, InventoryPayload::Shares(SharesInfo::default())).await;
    assert!(results(&s, &win).await.is_empty());
}

fn listen(port: u16, addr: &str, process: &str) -> ListenItem {
    ListenItem {
        proto: "tcp".into(),
        addr: addr.into(),
        port,
        process: Some(process.into()),
    }
}

#[sqlx::test(migrations = false)]
async fn exposure_rules_and_pages(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("研發部", 2).await;
    let lin = s.enroll_ok(&tok, None, None).await;
    let win = s.enroll_ok(&tok, None, None).await;
    checkin_linux(&s, &lin).await;
    let svc = admin::create_rule(
        &s.pool,
        &input(
            "服務",
            "exposed_service",
            json!({"services": ["mysql", "redis"]}),
        ),
        "admin",
    )
    .await
    .unwrap();
    let fw = admin::create_rule(
        &s.pool,
        &input("防火牆", "firewall_allow_all", json!({})),
        "admin",
    )
    .await
    .unwrap();
    let ssh = admin::create_rule(
        &s.pool,
        &input(
            "ssh",
            "ssh_config",
            json!({"no_empty_passwords": true, "no_root_password": true}),
        ),
        "admin",
    )
    .await
    .unwrap();
    let rdp = admin::create_rule(
        &s.pool,
        &input("rdp", "rdp_users", json!({"allowed": [r"CORP\helpdesk"]})),
        "admin",
    )
    .await
    .unwrap();
    worker::recompute_all(&s.pool).await.unwrap();
    // 適用平台：Linux 兩條、Windows 三條，還沒有資料都是未知
    let ids = |r: Vec<(i64, String, Value)>| r.into_iter().map(|x| x.0).collect::<Vec<_>>();
    assert_eq!(ids(results(&s, &lin).await), [svc, ssh]);
    assert_eq!(ids(results(&s, &win).await), [svc, fw, rdp]);

    put(
        &s,
        &win,
        InventoryPayload::Exposure(ExposureInfo {
            listening: vec![
                listen(3389, "0.0.0.0", "svchost.exe"),
                listen(3306, "0.0.0.0", "mysqld.exe"),
            ],
            firewall_allow_all: Some(vec!["Open everything".into()]),
            rdp: Some(RdpInfo {
                enabled: true,
                users: vec![
                    AccountInfo {
                        name: r"CORP\helpdesk".into(),
                        sid: "S-1-5-21-9-1105".into(),
                    },
                    AccountInfo {
                        name: r"CORP\bob".into(),
                        sid: "S-1-5-21-9-1200".into(),
                    },
                ],
            }),
            ..Default::default()
        }),
    )
    .await;
    let w = results(&s, &win).await;
    assert!(w.iter().all(|x| x.1 == "violating"), "{w:?}");
    assert_eq!(w[0].2["services"][0]["port"], 3306);
    assert_eq!(w[1].2["firewall_rules"], json!(["Open everything"]));
    assert_eq!(w[2].2["rdp_users"], json!([r"CORP\bob"]));

    put(
        &s,
        &lin,
        InventoryPayload::Exposure(ExposureInfo {
            listening: vec![
                listen(22, "0.0.0.0", "sshd"),
                listen(6379, "0.0.0.0", "redis-server"),
            ],
            sshd: Some(SshdInfo {
                permit_root_login: "prohibit-password".into(),
                password_authentication: true,
                permit_empty_passwords: true,
                ports: vec![22],
            }),
            ..Default::default()
        }),
    )
    .await;
    let l = results(&s, &lin).await;
    assert_eq!(l.len(), 2, "{l:?}");
    assert_eq!(l[0].2["services"][0]["service"], "Redis");
    assert_eq!(l[1].2["ssh"], json!(["允許空密碼"]));

    // 裝置頁卡片
    let c = s.admin_client().await;
    let (_, html) = s
        .page(&c, &format!("/devices/{}/tab/security", win.device_id))
        .await;
    assert!(html.contains("id=\"listening\""), "{html}");
    assert!(
        html.contains("<span class=\"tag bad\">MySQL</span> mysqld.exe"),
        "{html}"
    );
    assert!(
        html.contains("防火牆全開規則：<span class=\"tag bad\">Open everything</span>"),
        "{html}"
    );
    assert!(
        html.contains(r"遠端桌面：開啟，Remote Desktop Users：CORP\helpdesk、CORP\bob"),
        "{html}"
    );
    let (_, html) = s
        .page(&c, &format!("/devices/{}/tab/accounts", lin.device_id))
        .await;
    assert!(
        html.contains("PermitRootLogin <code>prohibit-password</code>"),
        "{html}"
    );

    // 對外服務頁：依連接埠彙整，可以篩選
    let (st, html) = s.page(&c, "/exposure").await;
    assert_eq!(st, 200);
    for p in ["3389", "3306", "6379", "22"] {
        assert!(html.contains(&format!("port={p}&")), "{p}：{html}");
    }
    let (_, html) = s.page(&c, "/exposure?risky=true").await;
    assert!(
        html.contains("port=3306&") && !html.contains("port=22&"),
        "{html}"
    );
    let (_, html) = s.page(&c, "/exposure?q=redis").await;
    assert!(
        html.contains("port=6379&") && !html.contains("port=3306&"),
        "{html}"
    );
    let (_, html) = s.page(&c, "/exposure?q=22").await;
    assert!(
        html.contains("port=22&") && !html.contains("port=6379&"),
        "{html}"
    );
    let (st, html) = s
        .page(
            &c,
            "/exposure/port?proto=tcp&port=6379&process=redis-server",
        )
        .await;
    assert_eq!(st, 200);
    assert!(html.contains(&lin.device_id.to_string()), "{html}");
    assert!(html.contains("Redis"), "{html}");
    // 範圍外的群組看不到
    let other = s
        .login_as(
            "other",
            endpoint_server::web::auth::Role::Viewer,
            &["別的部門"],
        )
        .await;
    let (_, html) = s.page(&other, "/exposure").await;
    assert!(!html.contains("port=6379&"), "{html}");

    // 規則表單
    let (_, html) = s.page(&c, &format!("/compliance/rules/{svc}")).await;
    assert!(html.contains("適用於：Windows、Linux"), "{html}");
    assert!(html.contains("value=\"mysql\" checked"), "{html}");
    assert!(html.contains("value=\"telnet\" >"), "{html}");
    let (_, html) = s.page(&c, &format!("/compliance/rules/{ssh}")).await;
    assert!(html.contains("適用於：Linux"), "{html}");
}

fn local(name: &str, uid: u32) -> LocalUser {
    LocalUser {
        name: name.into(),
        uid,
        no_password: Some(false),
        ..Default::default()
    }
}

#[sqlx::test(migrations = false)]
async fn account_flags_rule(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(2).await;
    let lin = s.enroll_ok(&tok, None, None).await;
    let win = s.enroll_ok(&tok, None, None).await;
    checkin_linux(&s, &lin).await;
    let rule = admin::create_rule(
        &s.pool,
        &input(
            "帳號",
            "account_flags",
            json!({"no_password": true, "guest_disabled": true, "sudo_nopasswd": true,
                   "no_autologon_password": true, "except_accounts": ["%ops"]}),
        ),
        "admin",
    )
    .await
    .unwrap();
    worker::recompute_all(&s.pool).await.unwrap();
    for a in [&lin, &win] {
        let r = results(&s, a).await;
        assert_eq!((r.len(), r[0].1.as_str()), (1, "unknown"), "{r:?}");
    }

    let mut guest = local("Guest", 501);
    guest.no_password = Some(true);
    put(
        &s,
        &win,
        InventoryPayload::Accounts(AccountsInfo {
            users: vec![local("Administrator", 500), guest],
            flags: true,
            autologon_password: Some(true),
            ..Default::default()
        }),
    )
    .await;
    let r = results(&s, &win).await;
    assert_eq!((r[0].0, r[0].1.as_str()), (rule, "violating"));
    assert_eq!(
        r[0].2,
        json!({"total": 3, "account_issues": [
            "Guest 沒有密碼", "Guest 帳號（Guest）已啟用", "自動登入存了密碼"
        ]})
    );

    let mut alice = local("alice", 1000);
    alice.no_password = Some(true);
    let sudo = |p: &str, kind: PrincipalKind| PrivilegeEntry {
        principal: p.into(),
        kind,
        source: "sudoers:sudoers".into(),
        nopasswd_all: true,
    };
    put(
        &s,
        &lin,
        InventoryPayload::Accounts(AccountsInfo {
            users: vec![local("root", 0), alice],
            privileged: vec![
                sudo("deploy", PrincipalKind::User),
                sudo("ops", PrincipalKind::Group),
            ],
            flags: true,
            ..Default::default()
        }),
    )
    .await;
    let r = results(&s, &lin).await;
    assert_eq!(
        r[0].2["account_issues"],
        json!(["alice 沒有密碼", "deploy 可以免密碼 sudo 執行任何指令"])
    );

    // 裝置頁：Windows 在「安全設定」分頁，Linux 在「帳號與權限」分頁標示
    let c = s.admin_client().await;
    let (_, html) = s
        .page(&c, &format!("/devices/{}/tab/security", win.device_id))
        .await;
    assert!(
        html.contains("本機帳號") && html.contains("id=\"local-users\""),
        "{html}"
    );
    assert!(
        html.contains("<span class=\"tag bad\">存了密碼</span>"),
        "{html}"
    );
    assert!(
        html.contains("<span class=\"tag bad\">不需要密碼</span>"),
        "{html}"
    );
    let (_, html) = s
        .page(&c, &format!("/devices/{}/tab/accounts", lin.device_id))
        .await;
    assert!(
        html.contains("<span class=\"tag bad\">空密碼</span> alice"),
        "{html}"
    );
    assert!(html.contains("免密碼 ALL"), "{html}");
    let (_, html) = s
        .page(&c, &format!("/devices/{}/tab/compliance", win.device_id))
        .await;
    assert!(html.contains("帳號設定：Guest 沒有密碼"), "{html}");

    // 規則表單
    let (_, html) = s.page(&c, &format!("/compliance/rules/{rule}")).await;
    assert!(html.contains("適用於：Windows、Linux"), "{html}");
    assert!(html.contains("%ops"), "{html}");

    // 舊版 Agent（沒有旗標）：未知
    put(
        &s,
        &win,
        InventoryPayload::Accounts(AccountsInfo {
            users: vec![local("Administrator", 500)],
            ..Default::default()
        }),
    )
    .await;
    assert_eq!(results(&s, &win).await[0].1, "unknown");
    let (_, html) = s
        .page(&c, &format!("/devices/{}/tab/security", win.device_id))
        .await;
    assert!(html.contains("Agent 版本太舊"), "{html}");
}
