mod common;

use common::TestServer;
use endpoint_server::deploy::admin::{self, DeploymentInput, PackageInput, Transition};
use endpoint_server::deploy::store::{self, Stored};
use futures_util::StreamExt;
use sqlx::PgPool;

fn chunks(
    data: &[u8],
) -> impl futures_util::Stream<Item = Result<axum::body::Bytes, std::io::Error>> + Unpin {
    let v: Vec<Result<axum::body::Bytes, std::io::Error>> = data
        .chunks(7)
        .map(|c| Ok(axum::body::Bytes::copy_from_slice(c)))
        .collect();
    futures_util::stream::iter(v)
}

fn sha(data: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(data))
}

pub fn pkg_input(kind: &str) -> PackageInput {
    PackageInput {
        name: "7-Zip".into(),
        version: "23.01".into(),
        kind: kind.into(),
        install_args: if kind == "exe" {
            "/S".into()
        } else {
            String::new()
        },
        uninstall_args: String::new(),
        success_codes: vec![],
        detect_name: "7-Zip*".into(),
        detect_publisher: String::new(),
        detect_min_version: "23.01".into(),
    }
}

async fn package(s: &TestServer, dir: &std::path::Path, kind: &str, data: &[u8]) -> i64 {
    let st = store::save(dir, chunks(data)).await.unwrap();
    admin::create_package(&s.pool, dir, &st, "7z.exe", None, &pkg_input(kind), "admin")
        .await
        .unwrap()
}

pub fn dep_input(package_id: i64, pilot: Option<i64>) -> DeploymentInput {
    DeploymentInput {
        name: "7-Zip 全公司".into(),
        package_id,
        action: "install".into(),
        include: vec![],
        exclude: vec![],
        pilot_group_id: pilot,
        max_failure_pct: 10,
        min_samples: 20,
    }
}

#[tokio::test]
async fn store_hashes_dedups_and_enforces_limit() {
    let dir = tempfile::tempdir().unwrap();
    let data = b"hello package content".repeat(10);
    let a: Stored = store::save(dir.path(), chunks(&data)).await.unwrap();
    assert_eq!((a.sha256.clone(), a.size), (sha(&data), data.len() as u64));
    assert_eq!(
        std::fs::read(store::file_path(dir.path(), &a.sha256)).unwrap(),
        data
    );
    let b = store::save(dir.path(), chunks(&data)).await.unwrap();
    assert_eq!(a, b);
    let err = store::save_limited(dir.path(), chunks(&data), 10).await;
    assert!(err.is_err());
    let files: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert_eq!(files.len(), 1, "超過上限時不留暫存檔");
}

#[test]
fn msi_info_reads_properties() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.msi");
    std::fs::write(
        &p,
        endpoint_server::installer::template_with(&[
            ("ProductName", "Foo App"),
            ("ProductVersion", "1.2.3"),
            ("ProductCode", "{12345678-1234-1234-1234-123456789012}"),
            ("Manufacturer", "ACME"),
        ]),
    )
    .unwrap();
    let i = store::msi_info(&p).unwrap();
    assert_eq!(
        (
            i.name.as_str(),
            i.version.as_str(),
            i.product_code.as_str(),
            i.manufacturer.as_str()
        ),
        (
            "Foo App",
            "1.2.3",
            "{12345678-1234-1234-1234-123456789012}",
            "ACME"
        )
    );
    let q = dir.path().join("b.exe");
    std::fs::write(&q, b"MZ not an msi").unwrap();
    assert!(store::msi_info(&q).is_none());
}

#[sqlx::test(migrations = false)]
async fn package_validation_and_delete_rules(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let dir = tempfile::tempdir().unwrap();
    let st = store::save(dir.path(), chunks(b"exe bytes")).await.unwrap();
    for bad in [
        PackageInput {
            detect_name: " ".into(),
            ..pkg_input("exe")
        },
        PackageInput {
            kind: "zip".into(),
            ..pkg_input("exe")
        },
        PackageInput {
            name: "a\u{7}b".into(),
            ..pkg_input("exe")
        },
        PackageInput {
            install_args: "/S\n/X".into(),
            ..pkg_input("exe")
        },
        PackageInput {
            install_args: "x".repeat(1001),
            ..pkg_input("exe")
        },
        PackageInput {
            success_codes: (1..=21).collect(),
            ..pkg_input("exe")
        },
        PackageInput {
            name: String::new(),
            ..pkg_input("exe")
        },
    ] {
        assert!(
            admin::create_package(&s.pool, dir.path(), &st, "a.exe", None, &bad, "admin")
                .await
                .is_err(),
            "{bad:?}"
        );
    }
    let id = admin::create_package(
        &s.pool,
        dir.path(),
        &st,
        "a.exe",
        None,
        &pkg_input("exe"),
        "admin",
    )
    .await
    .unwrap();
    // 同一個檔案的第二個套件：刪掉其中一個時不能刪檔
    let id2 = admin::create_package(
        &s.pool,
        dir.path(),
        &st,
        "a.exe",
        None,
        &pkg_input("exe"),
        "admin",
    )
    .await
    .unwrap();
    admin::update_package(
        &s.pool,
        id,
        &PackageInput {
            version: "24.0".into(),
            ..pkg_input("exe")
        },
        "admin",
    )
    .await
    .unwrap();
    let dep = admin::create_deployment(&s.pool, &dep_input(id, None), "admin")
        .await
        .unwrap();
    let err = admin::delete_package(&s.pool, dir.path(), id, "admin")
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("派送"), "{err:#}");
    admin::delete_package(&s.pool, dir.path(), id2, "admin")
        .await
        .unwrap();
    assert!(
        store::file_path(dir.path(), &st.sha256).exists(),
        "另一個套件仍在使用"
    );
    admin::set_stage(&s.pool, dep, Transition::Stop, "admin")
        .await
        .unwrap();
    admin::delete_deployment(&s.pool, dep, "admin")
        .await
        .unwrap();
    admin::delete_package(&s.pool, dir.path(), id, "admin")
        .await
        .unwrap();
    assert!(
        !store::file_path(dir.path(), &st.sha256).exists(),
        "最後一個套件刪除時刪檔"
    );
    let audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action LIKE 'package_%' OR action LIKE 'deployment_%'",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(
        audits, 8,
        "3 package_create/update + 1 deployment_create + stop + delete + 2 package_delete"
    );
}

#[sqlx::test(migrations = false)]
async fn deployment_stage_transitions(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let dir = tempfile::tempdir().unwrap();
    let pkg = package(&s, dir.path(), "exe", b"x").await;
    let pilot = s.group_id("試點").await;
    let stage = |id: i64| {
        let pool = s.pool.clone();
        async move {
            let r: (String, i32) =
                sqlx::query_as("SELECT stage, revision FROM deployments WHERE id = $1")
                    .bind(id)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            r
        }
    };
    let d = admin::create_deployment(&s.pool, &dep_input(pkg, Some(pilot)), "admin")
        .await
        .unwrap();
    assert_eq!(stage(d).await.0, "pilot");
    assert!(
        admin::set_stage(&s.pool, d, Transition::Resume, "admin")
            .await
            .is_err()
    );
    admin::set_stage(&s.pool, d, Transition::Pause, "admin")
        .await
        .unwrap();
    assert_eq!(stage(d).await.0, "paused");
    assert!(
        admin::set_stage(&s.pool, d, Transition::Expand, "admin")
            .await
            .is_err()
    );
    admin::set_stage(&s.pool, d, Transition::Resume, "admin")
        .await
        .unwrap();
    assert_eq!(stage(d).await.0, "pilot", "繼續時回到暫停前的階段");
    admin::set_stage(&s.pool, d, Transition::Expand, "admin")
        .await
        .unwrap();
    assert_eq!(stage(d).await.0, "all");
    admin::retry_failed(&s.pool, d, "admin").await.unwrap();
    assert_eq!(stage(d).await.1, 2);
    assert!(
        admin::delete_deployment(&s.pool, d, "admin").await.is_err(),
        "只能刪除已停止的"
    );
    admin::set_stage(&s.pool, d, Transition::Stop, "admin")
        .await
        .unwrap();
    assert!(
        admin::set_stage(&s.pool, d, Transition::Resume, "admin")
            .await
            .is_err()
    );
    assert!(admin::retry_failed(&s.pool, d, "admin").await.is_err());

    let direct = admin::create_deployment(&s.pool, &dep_input(pkg, None), "admin")
        .await
        .unwrap();
    assert_eq!(stage(direct).await.0, "all", "沒有試點群組時直接全部");
    // 規則與派送變更都會讓報到快取過期
    let g: i64 = sqlx::query_scalar("SELECT generation FROM deploy_state")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert!(g >= 8, "{g}");
    for bad in [
        "UPDATE deployments SET stage = 'paused', paused_from = NULL WHERE id = $1",
        "UPDATE deployments SET stage = 'all', paused_from = 'pilot' WHERE id = $1",
    ] {
        assert!(
            sqlx::query(bad)
                .bind(direct)
                .execute(&s.pool)
                .await
                .is_err(),
            "paused_from 必須和 paused 階段一致：{bad}"
        );
    }
}

#[sqlx::test(migrations = false)]
async fn deployment_input_validation(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let dir = tempfile::tempdir().unwrap();
    let exe = package(&s, dir.path(), "exe", b"e").await;
    let uninstall = DeploymentInput {
        action: "uninstall".into(),
        ..dep_input(exe, None)
    };
    let err = admin::create_deployment(&s.pool, &uninstall, "admin")
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("移除"), "{err:#}");
    let g = s.group_id("台北").await;
    for bad in [
        DeploymentInput {
            name: " ".into(),
            ..dep_input(exe, None)
        },
        DeploymentInput {
            name: "a\tb".into(),
            ..dep_input(exe, None)
        },
        DeploymentInput {
            action: "reinstall".into(),
            ..dep_input(exe, None)
        },
        DeploymentInput {
            max_failure_pct: 0,
            ..dep_input(exe, None)
        },
        DeploymentInput {
            min_samples: 0,
            ..dep_input(exe, None)
        },
        DeploymentInput {
            include: vec![g],
            exclude: vec![g],
            ..dep_input(exe, None)
        },
        DeploymentInput {
            package_id: 9999,
            ..dep_input(exe, None)
        },
    ] {
        assert!(
            admin::create_deployment(&s.pool, &bad, "admin")
                .await
                .is_err(),
            "{:?}",
            bad.name
        );
    }
}

#[sqlx::test(migrations = false)]
async fn group_used_by_deployment_cannot_be_deleted(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let dir = tempfile::tempdir().unwrap();
    let pkg = package(&s, dir.path(), "exe", b"g").await;
    let pilot = s.group_id("試點").await;
    let inc = s.group_id("台北").await;
    admin::create_deployment(
        &s.pool,
        &DeploymentInput {
            include: vec![inc],
            ..dep_input(pkg, Some(pilot))
        },
        "admin",
    )
    .await
    .unwrap();
    for g in [pilot, inc] {
        let err = endpoint_server::groups::delete(&s.pool, g, "admin")
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("派送"), "{err:#}");
    }
}

async fn checkin(s: &TestServer, a: &common::TestAgent) -> protocol::CheckinResponse {
    s.client(Some(a))
        .post(s.url("/v1/checkin"))
        .json(&protocol::CheckinRequest {
            schema_version: protocol::SCHEMA_VERSION,
            agent_version: "0.4.0".into(),
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

/// 報到用的快取最多每 5 秒確認一次 generation；測試直接讓快取過期
async fn ids(s: &TestServer, a: &common::TestAgent) -> Vec<i64> {
    s.state.deploy.invalidate();
    checkin(s, a)
        .await
        .deployments
        .iter()
        .map(|d| d.deployment_id)
        .collect()
}

#[sqlx::test(migrations = false)]
async fn checkin_assigns_by_scope_and_stage(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let dir = tempfile::tempdir().unwrap();
    let pkg = package(&s, dir.path(), "exe", b"payload").await;
    let pilot_tok = s.create_group_token("試點", 1).await;
    let tp_tok = s.create_group_token("台北", 1).await;
    let ks_tok = s.create_group_token("高雄", 1).await;
    let pilot_dev = s.enroll_ok(&pilot_tok, None, None).await;
    let tp = s.enroll_ok(&tp_tok, None, None).await;
    let ks = s.enroll_ok(&ks_tok, None, None).await;
    let pilot = s.group_id("試點").await;
    let ks_g = s.group_id("高雄").await;

    let d = admin::create_deployment(
        &s.pool,
        &DeploymentInput {
            exclude: vec![ks_g],
            ..dep_input(pkg, Some(pilot))
        },
        "admin",
    )
    .await
    .unwrap();
    assert_eq!(ids(&s, &pilot_dev).await, vec![d], "試點階段只給試點群組");
    assert!(ids(&s, &tp).await.is_empty());
    let r = checkin(&s, &pilot_dev).await;
    assert_eq!(
        r.deployments_hash.as_deref(),
        Some(protocol::deploy::assignments_hash(&r.deployments).as_str())
    );
    let spec = &r.deployments[0].package;
    assert_eq!(
        (spec.id, spec.size, spec.detect.name.as_str()),
        (pkg, 7, "7-Zip*")
    );

    admin::set_stage(&s.pool, d, Transition::Expand, "admin")
        .await
        .unwrap();
    assert_eq!(ids(&s, &tp).await, vec![d]);
    assert!(ids(&s, &ks).await.is_empty(), "排除的群組");
    admin::set_stage(&s.pool, d, Transition::Pause, "admin")
        .await
        .unwrap();
    assert!(ids(&s, &tp).await.is_empty(), "暫停後不下發");
    let paused_hash = checkin(&s, &tp).await.deployments_hash;
    assert_eq!(
        paused_hash.as_deref(),
        Some(protocol::deploy::assignments_hash(&[]).as_str())
    );
    admin::set_stage(&s.pool, d, Transition::Resume, "admin")
        .await
        .unwrap();
    assert_eq!(ids(&s, &tp).await, vec![d]);
    // 停用的裝置不指派
    sqlx::query("UPDATE devices SET status = 'retired' WHERE id = $1")
        .bind(tp.device_id)
        .execute(&s.pool)
        .await
        .unwrap();
    assert!(ids(&s, &tp).await.is_empty());
}

/// 套件放在伺服器的套件目錄（下載 API 讀這裡）
async fn server_package(s: &TestServer, kind: &str, data: &[u8]) -> i64 {
    package(s, &s.state.package_dir, kind, data).await
}

async fn result(
    s: &TestServer,
    a: &common::TestAgent,
    dep: i64,
    status: protocol::deploy::DeployStatus,
    revision: i32,
) -> u16 {
    s.client(Some(a))
        .post(s.url(&format!("/v1/deployments/{dep}/result")))
        .json(&protocol::deploy::DeployResult {
            revision,
            status,
            exit_code: Some(1603),
            message: "boom".into(),
            attempts: 1,
            source: None,
        })
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[sqlx::test(migrations = false)]
async fn download_requires_assignment_and_is_limited(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let data = b"MZ fake installer".repeat(1000);
    let pkg = server_package(&s, "exe", &data).await;
    let other = server_package(&s, "exe", b"not assigned").await;
    let tp = s
        .enroll_ok(&s.create_group_token("台北", 1).await, None, None)
        .await;
    let ks = s
        .enroll_ok(&s.create_group_token("高雄", 1).await, None, None)
        .await;
    let ks_g = s.group_id("高雄").await;
    admin::create_deployment(
        &s.pool,
        &DeploymentInput {
            exclude: vec![ks_g],
            ..dep_input(pkg, None)
        },
        "admin",
    )
    .await
    .unwrap();
    s.state.deploy.invalidate();
    let get = |a: &common::TestAgent, id: i64| {
        let c = s.client(Some(a));
        let url = s.url(&format!("/v1/packages/{id}/content"));
        async move { c.get(url).send().await.unwrap() }
    };
    let r = get(&tp, pkg).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.bytes().await.unwrap().as_ref(), data.as_slice());
    assert_eq!(get(&ks, pkg).await.status(), 404, "被排除的裝置");
    assert_eq!(get(&tp, other).await.status(), 404, "沒被指派的套件");
    assert_eq!(get(&tp, 9999).await.status(), 404);
    // 同時下載數用完時回 503 與 Retry-After；歸還後恢復
    let held = s
        .state
        .downloads
        .clone()
        .acquire_many_owned(2)
        .await
        .unwrap();
    let r = get(&tp, pkg).await;
    assert_eq!(r.status(), 503);
    assert_eq!(r.headers()["retry-after"], "60");
    drop(held);
    let r = get(&tp, pkg).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.bytes().await.unwrap().len(), data.len());
    // 用戶端收完最後一個位元組時，伺服器端的串流可能還沒被釋放：等一下再確認
    let mut returned = false;
    for _ in 0..40 {
        if s.state.downloads.available_permits() == 2 {
            returned = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(returned, "串流結束後歸還許可");
    // 檔案被刪掉時回 404
    let sha: String = sqlx::query_scalar("SELECT sha256 FROM packages WHERE id = $1")
        .bind(pkg)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    std::fs::remove_file(store::file_path(&s.state.package_dir, &sha)).unwrap();
    assert_eq!(get(&tp, pkg).await.status(), 404);
}

#[sqlx::test(migrations = false)]
async fn results_are_recorded_and_failures_auto_pause(pool: PgPool) {
    use protocol::deploy::DeployStatus::*;
    let s = TestServer::start(pool).await;
    let pkg = server_package(&s, "exe", b"x").await;
    let tok = s.create_group_token("台北", 5).await;
    let mut devs = vec![];
    for _ in 0..4 {
        devs.push(s.enroll_ok(&tok, None, None).await);
    }
    let outsider = s
        .enroll_ok(&s.create_group_token("高雄", 1).await, None, None)
        .await;
    let tp = s.group_id("台北").await;
    let d = admin::create_deployment(
        &s.pool,
        &DeploymentInput {
            include: vec![tp],
            max_failure_pct: 40,
            min_samples: 3,
            ..dep_input(pkg, None)
        },
        "admin",
    )
    .await
    .unwrap();
    s.state.deploy.invalidate();
    assert_eq!(result(&s, &outsider, d, Failed, 1).await, 404, "範圍外");
    assert_eq!(result(&s, &devs[0], 9999, Failed, 1).await, 404);
    let bad = s
        .client(Some(&devs[0]))
        .post(s.url(&format!("/v1/deployments/{d}/result")))
        .json(&serde_json::json!({"revision": 1, "status": "failed", "message": "x".repeat(1001)}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400);

    let stage = || async {
        let v: String = sqlx::query_scalar("SELECT stage FROM deployments WHERE id = $1")
            .bind(d)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        v
    };
    // compliant 不算樣本；舊 revision 不算
    assert_eq!(result(&s, &devs[0], d, Compliant, 1).await, 204);
    assert_eq!(result(&s, &devs[1], d, Failed, 0).await, 204);
    assert_eq!(result(&s, &devs[2], d, Failed, 1).await, 204);
    assert_eq!(stage().await, "all", "樣本不足不暫停");
    assert_eq!(result(&s, &devs[3], d, Succeeded, 1).await, 204);
    assert_eq!(stage().await, "all", "1 失敗／2 樣本，還不夠 3 台");
    // 同一台再回報會覆寫（upsert）
    assert_eq!(result(&s, &devs[1], d, Failed, 1).await, 204);
    assert_eq!(stage().await, "paused", "2 失敗／3 樣本 > 40%");
    let (status, code, msg): (String, Option<i32>, String) = sqlx::query_as(
        "SELECT status, exit_code, message FROM deployment_status \
         WHERE deployment_id = $1 AND device_id = $2",
    )
    .bind(d)
    .bind(devs[1].device_id)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(
        (status.as_str(), code, msg.as_str()),
        ("failed", Some(1603), "boom")
    );
    let audit: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action = 'deployment_auto_pause' AND actor = 'system'",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(audit, 1);
    // 暫停中仍接受回報（已在執行的安裝）
    s.state.deploy.invalidate();
    assert_eq!(result(&s, &devs[0], d, Succeeded, 1).await, 204);
    // 停止後不接受
    admin::set_stage(&s.pool, d, Transition::Stop, "admin")
        .await
        .unwrap();
    s.state.deploy.invalidate();
    assert_eq!(result(&s, &devs[0], d, Succeeded, 1).await, 404);
}

/// 多台同時第一次回報失敗：外鍵的 KEY SHARE 鎖不能和自動暫停的鎖互鎖（死結 → 500）
#[sqlx::test(migrations = false)]
async fn concurrent_failure_reports_do_not_deadlock(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let pkg = server_package(&s, "exe", b"x").await;
    let tok = s.create_token(12).await;
    let mut devs = vec![];
    for _ in 0..12 {
        devs.push(s.enroll_ok(&tok, None, None).await);
    }
    let d = admin::create_deployment(
        &s.pool,
        &DeploymentInput {
            min_samples: 100,
            ..dep_input(pkg, None)
        },
        "admin",
    )
    .await
    .unwrap();
    s.state.deploy.invalidate();
    let codes = futures_util::future::join_all(
        devs.iter()
            .map(|a| result(&s, a, d, protocol::deploy::DeployStatus::Failed, 1)),
    )
    .await;
    assert!(codes.iter().all(|c| *c == 204), "{codes:?}");
}

#[sqlx::test(migrations = false)]
async fn stale_or_future_revision_results(pool: PgPool) {
    use protocol::deploy::DeployStatus::*;
    let s = TestServer::start(pool).await;
    let pkg = server_package(&s, "exe", b"x").await;
    let a = s.enroll_ok(&s.create_token(1).await, None, None).await;
    let d = admin::create_deployment(&s.pool, &dep_input(pkg, None), "admin")
        .await
        .unwrap();
    admin::retry_failed(&s.pool, d, "admin").await.unwrap();
    s.state.deploy.invalidate();
    assert_eq!(
        result(&s, &a, d, Succeeded, 3).await,
        400,
        "未來的 revision"
    );
    assert_eq!(result(&s, &a, d, Succeeded, 2).await, 204);
    assert_eq!(
        result(&s, &a, d, Failed, 1).await,
        204,
        "舊 revision 仍接受"
    );
    let status: String =
        sqlx::query_scalar("SELECT status FROM deployment_status WHERE deployment_id = $1")
            .bind(d)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(status, "succeeded", "但不覆寫較新的結果");
}

#[sqlx::test(migrations = false)]
async fn exe_uninstall_args_cannot_be_cleared_while_used(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let dir = tempfile::tempdir().unwrap();
    let st = store::save(dir.path(), chunks(b"u")).await.unwrap();
    let input = PackageInput {
        uninstall_args: "/uninstall /S".into(),
        ..pkg_input("exe")
    };
    let pkg = admin::create_package(&s.pool, dir.path(), &st, "a.exe", None, &input, "admin")
        .await
        .unwrap();
    admin::create_deployment(
        &s.pool,
        &DeploymentInput {
            action: "uninstall".into(),
            ..dep_input(pkg, None)
        },
        "admin",
    )
    .await
    .unwrap();
    let err = admin::update_package(&s.pool, pkg, &pkg_input("exe"), "admin")
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("移除"), "{err:#}");
}

/// 檔案已不在（例如和刪除同時發生）時不能建立套件
#[sqlx::test(migrations = false)]
async fn package_requires_file_present(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let dir = tempfile::tempdir().unwrap();
    let st = store::save(dir.path(), chunks(b"gone")).await.unwrap();
    std::fs::remove_file(store::file_path(dir.path(), &st.sha256)).unwrap();
    let err = admin::create_package(
        &s.pool,
        dir.path(),
        &st,
        "a.exe",
        None,
        &pkg_input("exe"),
        "admin",
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("重新上傳"), "{err:#}");
}

#[tokio::test]
async fn cancelled_upload_leaves_no_temp_file() {
    let dir = tempfile::tempdir().unwrap();
    let first: Result<axum::body::Bytes, std::io::Error> =
        Ok(axum::body::Bytes::from_static(b"part"));
    let body = futures_util::stream::iter(vec![first]).chain(futures_util::stream::pending());
    let r = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        store::save(dir.path(), Box::pin(body)),
    )
    .await;
    assert!(r.is_err(), "上傳卡住被取消");
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        0,
        "取消時刪除暫存檔"
    );
    std::fs::write(dir.path().join(".upload-leftover"), b"x").unwrap();
    std::fs::write(dir.path().join("keep"), b"x").unwrap();
    store::cleanup_temp(dir.path()).await;
    let left: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, vec!["keep".to_string()]);
}
