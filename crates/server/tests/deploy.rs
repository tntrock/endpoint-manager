mod common;

use common::TestServer;
use endpoint_server::deploy::admin::{self, DeploymentInput, PackageInput, Transition};
use endpoint_server::deploy::store::{self, Stored};
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
    admin::create_package(&s.pool, &st, "7z.exe", None, &pkg_input(kind), "admin")
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
            admin::create_package(&s.pool, &st, "a.exe", None, &bad, "admin")
                .await
                .is_err(),
            "{bad:?}"
        );
    }
    let id = admin::create_package(&s.pool, &st, "a.exe", None, &pkg_input("exe"), "admin")
        .await
        .unwrap();
    // 同一個檔案的第二個套件：刪掉其中一個時不能刪檔
    let id2 = admin::create_package(&s.pool, &st, "a.exe", None, &pkg_input("exe"), "admin")
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
