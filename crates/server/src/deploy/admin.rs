//! 套件與派送的管理（平台管理員）：驗證、CRUD、階段切換、稽核。

use std::path::Path;

use anyhow::{Context, bail, ensure};
use serde_json::json;
use sqlx::{PgConnection, PgPool};

use super::store::{Stored, file_path};
use crate::audit;
use protocol::deploy::MAX_ARGS_LEN;

pub const MAX_NAME_LEN: usize = 100;
pub const MAX_PATTERN_LEN: usize = 256;
pub const MAX_SUCCESS_CODES: usize = 20;

#[derive(Debug, Clone)]
pub struct PackageInput {
    pub name: String,
    pub version: String,
    /// `msi` 或 `exe`
    pub kind: String,
    pub install_args: String,
    pub uninstall_args: String,
    pub success_codes: Vec<i32>,
    pub detect_name: String,
    /// 空字串表示不限
    pub detect_publisher: String,
    pub detect_min_version: String,
}

struct ValidPackage {
    name: String,
    version: String,
    kind: &'static str,
    install_args: String,
    uninstall_args: String,
    success_codes: Vec<i32>,
    detect_name: String,
    detect_publisher: Option<String>,
    detect_min_version: Option<String>,
}

fn args(field: &str, v: &str) -> anyhow::Result<String> {
    let v = v.trim();
    ensure!(
        v.chars().count() <= MAX_ARGS_LEN,
        "{field}最多 {MAX_ARGS_LEN} 字"
    );
    ensure!(
        !v.chars().any(char::is_control),
        "{field}不能包含換行等控制字元"
    );
    Ok(v.to_string())
}

fn optional(field: &str, v: &str) -> anyhow::Result<Option<String>> {
    let v = v.trim();
    ensure!(
        v.chars().count() <= MAX_PATTERN_LEN,
        "{field}最多 {MAX_PATTERN_LEN} 字"
    );
    ensure!(!v.chars().any(char::is_control), "{field}不能包含控制字元");
    Ok((!v.is_empty()).then(|| v.to_string()))
}

fn validate_package(i: &PackageInput) -> anyhow::Result<ValidPackage> {
    let name = i.name.trim().to_string();
    ensure!(
        !name.is_empty() && name.chars().count() <= MAX_NAME_LEN,
        "套件名稱必填，最多 {MAX_NAME_LEN} 字"
    );
    ensure!(
        !name.chars().any(char::is_control),
        "套件名稱不能包含控制字元"
    );
    let version = optional("版本", &i.version)?.unwrap_or_default();
    let kind = match i.kind.as_str() {
        "msi" => "msi",
        "exe" => "exe",
        _ => bail!("套件類型必須是 MSI 或 EXE"),
    };
    let mut success_codes = i.success_codes.clone();
    success_codes.sort_unstable();
    success_codes.dedup();
    ensure!(
        success_codes.len() <= MAX_SUCCESS_CODES,
        "成功結束碼最多 {MAX_SUCCESS_CODES} 個"
    );
    let detect_name = optional("偵測名稱", &i.detect_name)?.context("偵測用的軟體名稱必填")?;
    Ok(ValidPackage {
        name,
        version,
        kind,
        install_args: args("安裝參數", &i.install_args)?,
        // MSI 以 ProductCode 移除，不使用移除參數
        uninstall_args: if kind == "exe" {
            args("移除參數", &i.uninstall_args)?
        } else {
            String::new()
        },
        success_codes,
        detect_name,
        detect_publisher: optional("偵測發行者", &i.detect_publisher)?,
        detect_min_version: optional("偵測最低版本", &i.detect_min_version)?,
    })
}

/// 任何派送或套件異動都讓報到端的快取過期
async fn bump(conn: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE deploy_state SET generation = generation + 1")
        .execute(conn)
        .await?;
    Ok(())
}

fn file_name(raw: &str) -> anyhow::Result<String> {
    // 只留檔名（瀏覽器可能帶路徑），只用於顯示與副檔名
    let base = raw.rsplit(['\\', '/']).next().unwrap_or("").trim();
    ensure!(
        !base.is_empty() && base.chars().count() <= 255 && !base.chars().any(char::is_control),
        "檔名無效"
    );
    Ok(base.to_string())
}

/// 同一個檔案（sha256）的建立與刪除依序進行：刪除時判斷「沒人用」並刪檔，
/// 不能和同時建立同內容的套件交錯，否則會留下沒有檔案的套件
async fn lock_file(conn: &mut PgConnection, sha256: &str) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('package:' || $1))")
        .bind(sha256)
        .execute(conn)
        .await?;
    Ok(())
}

/// 上傳後沒建立成套件（驗證失敗）：沒有其他套件使用這個檔案時刪除
pub async fn discard_file(pool: &PgPool, dir: &Path, sha256: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    lock_file(&mut tx, sha256).await?;
    let used: i64 = sqlx::query_scalar("SELECT count(*) FROM packages WHERE sha256 = $1")
        .bind(sha256)
        .fetch_one(&mut *tx)
        .await?;
    if used == 0 {
        match tokio::fs::remove_file(file_path(dir, sha256)).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    tx.commit().await?;
    Ok(())
}

pub async fn create_package(
    pool: &PgPool,
    dir: &Path,
    file: &Stored,
    original_name: &str,
    msi_product_code: Option<&str>,
    i: &PackageInput,
    actor: &str,
) -> anyhow::Result<i64> {
    let v = validate_package(i)?;
    let fname = file_name(original_name)?;
    let product_code = msi_product_code.filter(|_| v.kind == "msi");
    let mut tx = pool.begin().await?;
    lock_file(&mut tx, &file.sha256).await?;
    ensure!(
        tokio::fs::try_exists(file_path(dir, &file.sha256))
            .await
            .unwrap_or(false),
        "伺服器上找不到上傳的檔案，請重新上傳"
    );
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO packages (name, version, kind, file_name, size, sha256, msi_product_code, \
           install_args, uninstall_args, success_codes, detect_name, detect_publisher, \
           detect_min_version, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING id",
    )
    .bind(&v.name)
    .bind(&v.version)
    .bind(v.kind)
    .bind(&fname)
    .bind(file.size as i64)
    .bind(&file.sha256)
    .bind(product_code)
    .bind(&v.install_args)
    .bind(&v.uninstall_args)
    .bind(&v.success_codes)
    .bind(&v.detect_name)
    .bind(&v.detect_publisher)
    .bind(&v.detect_min_version)
    .bind(actor)
    .fetch_one(&mut *tx)
    .await?;
    bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        "package_create",
        Some(&v.name),
        json!({"id": id, "sha256": file.sha256, "size": file.size, "kind": v.kind}),
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn update_package(
    pool: &PgPool,
    id: i64,
    i: &PackageInput,
    actor: &str,
) -> anyhow::Result<()> {
    let v = validate_package(i)?;
    let mut tx = pool.begin().await?;
    if v.kind == "exe" && v.uninstall_args.is_empty() {
        let used: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM deployments WHERE package_id = $1 AND action = 'uninstall' \
             AND stage <> 'stopped'",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        ensure!(used == 0, "有移除派送正在使用這個套件，移除參數不能清空");
    }
    // 類型跟著檔案，不能改（MSI 的 ProductCode 也來自檔案）
    let n = sqlx::query(
        "UPDATE packages SET name = $2, version = $3, install_args = $4, uninstall_args = \
           CASE WHEN kind = 'exe' THEN $5 ELSE '' END, success_codes = $6, detect_name = $7, \
           detect_publisher = $8, detect_min_version = $9, updated_at = now() \
         WHERE id = $1 AND kind = $10",
    )
    .bind(id)
    .bind(&v.name)
    .bind(&v.version)
    .bind(&v.install_args)
    .bind(&v.uninstall_args)
    .bind(&v.success_codes)
    .bind(&v.detect_name)
    .bind(&v.detect_publisher)
    .bind(&v.detect_min_version)
    .bind(v.kind)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    ensure!(n == 1, "套件不存在，或套件類型不能變更");
    bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        "package_update",
        Some(&v.name),
        json!({"id": id}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// 被派送引用時不能刪除；沒有其他套件使用同一個檔案時一併刪檔。
pub async fn delete_package(pool: &PgPool, dir: &Path, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let sha: String = sqlx::query_scalar("SELECT sha256 FROM packages WHERE id = $1")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .context("套件不存在")?;
    lock_file(&mut tx, &sha).await?;
    let used: i64 = sqlx::query_scalar("SELECT count(*) FROM deployments WHERE package_id = $1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    ensure!(used == 0, "套件仍被 {used} 個派送使用，請先刪除相關派送");
    let (name, _): (String, String) =
        sqlx::query_as("DELETE FROM packages WHERE id = $1 RETURNING name, sha256")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .context("套件不存在")?;
    let others: i64 = sqlx::query_scalar("SELECT count(*) FROM packages WHERE sha256 = $1")
        .bind(&sha)
        .fetch_one(&mut *tx)
        .await?;
    bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        "package_delete",
        Some(&name),
        json!({"id": id, "sha256": sha}),
    )
    .await?;
    // 在檔案鎖內刪檔：同時建立同內容套件的交易會等到這裡結束，再發現檔案不在
    if others == 0 {
        match tokio::fs::remove_file(file_path(dir, &sha)).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(sha256 = %sha, error = %e, "package file not removed"),
        }
    }
    tx.commit().await?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct DeploymentInput {
    pub name: String,
    pub package_id: i64,
    /// `install` 或 `uninstall`
    pub action: String,
    pub include: Vec<i64>,
    pub exclude: Vec<i64>,
    /// 有設定時先只派送給這個群組
    pub pilot_group_id: Option<i64>,
    pub max_failure_pct: i32,
    pub min_samples: i32,
}

pub async fn create_deployment(
    pool: &PgPool,
    i: &DeploymentInput,
    actor: &str,
) -> anyhow::Result<i64> {
    let name = i.name.trim().to_string();
    ensure!(
        !name.is_empty() && name.chars().count() <= MAX_NAME_LEN,
        "派送名稱必填，最多 {MAX_NAME_LEN} 字"
    );
    ensure!(
        !name.chars().any(char::is_control),
        "派送名稱不能包含控制字元"
    );
    let action = match i.action.as_str() {
        "install" => "install",
        "uninstall" => "uninstall",
        _ => bail!("動作必須是安裝或移除"),
    };
    ensure!(
        (1..=100).contains(&i.max_failure_pct),
        "失敗率門檻必須是 1–100%"
    );
    ensure!(
        (1..=10_000).contains(&i.min_samples),
        "最少樣本數必須是 1–10000"
    );
    ensure!(
        !i.include.iter().any(|g| i.exclude.contains(g)),
        "同一個群組不能同時「只派送給」又「排除」"
    );
    let mut tx = pool.begin().await?;
    let pkg: Option<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT kind, msi_product_code, uninstall_args FROM packages WHERE id = $1 FOR SHARE",
    )
    .bind(i.package_id)
    .fetch_optional(&mut *tx)
    .await?;
    let (kind, product_code, uninstall_args) = pkg.context("套件不存在")?;
    if action == "uninstall" {
        let ok = match kind.as_str() {
            "msi" => product_code.is_some(),
            _ => !uninstall_args.is_empty(),
        };
        ensure!(
            ok,
            "這個套件不能用來移除：MSI 需要 ProductCode，EXE 需要設定移除參數"
        );
    }
    let stage = if i.pilot_group_id.is_some() {
        "pilot"
    } else {
        "all"
    };
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO deployments (name, package_id, action, stage, pilot_group_id, \
           max_failure_pct, min_samples, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(&name)
    .bind(i.package_id)
    .bind(action)
    .bind(stage)
    .bind(i.pilot_group_id)
    .bind(i.max_failure_pct)
    .bind(i.min_samples)
    .bind(actor)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(d) if d.is_foreign_key_violation() => {
            anyhow::anyhow!("試點群組不存在")
        }
        _ => e.into(),
    })?;
    for (groups, mode) in [(&i.include, "include"), (&i.exclude, "exclude")] {
        for g in groups {
            sqlx::query(
                "INSERT INTO deployment_groups (deployment_id, group_id, mode) VALUES ($1, $2, $3) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(id)
            .bind(g)
            .bind(mode)
            .execute(&mut *tx)
            .await
            .map_err(|_| anyhow::anyhow!("群組不存在：{g}"))?;
        }
    }
    bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        "deployment_create",
        Some(&name),
        json!({
            "id": id, "package_id": i.package_id, "action": action, "stage": stage,
            "include": i.include, "exclude": i.exclude, "pilot_group_id": i.pilot_group_id,
            "max_failure_pct": i.max_failure_pct, "min_samples": i.min_samples
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// 試點 → 全部
    Expand,
    Pause,
    /// 回到暫停前的階段
    Resume,
    /// 終態：之後只能刪除
    Stop,
}

impl Transition {
    fn action(self) -> &'static str {
        match self {
            Transition::Expand => "deployment_expand",
            Transition::Pause => "deployment_pause",
            Transition::Resume => "deployment_resume",
            Transition::Stop => "deployment_stop",
        }
    }
}

/// 回傳 (新階段, 新的 paused_from)；不合法的切換回 None
fn next_stage(
    stage: &str,
    paused_from: Option<&str>,
    t: Transition,
) -> Option<(&'static str, Option<&'static str>)> {
    let active = |s: &str| match s {
        "pilot" => Some("pilot"),
        "all" => Some("all"),
        _ => None,
    };
    match (t, stage) {
        (Transition::Expand, "pilot") => Some(("all", None)),
        (Transition::Pause, s) => active(s).map(|from| ("paused", Some(from))),
        (Transition::Resume, "paused") => Some((active(paused_from?)?, None)),
        (Transition::Stop, "pilot" | "all" | "paused") => Some(("stopped", None)),
        _ => None,
    }
}

async fn lock_deployment(
    conn: &mut PgConnection,
    id: i64,
) -> anyhow::Result<(String, String, Option<String>)> {
    sqlx::query_as("SELECT name, stage, paused_from FROM deployments WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_optional(conn)
        .await?
        .context("派送不存在")
}

pub async fn set_stage(pool: &PgPool, id: i64, t: Transition, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let (name, stage, paused_from) = lock_deployment(&mut tx, id).await?;
    let (new, from) =
        next_stage(&stage, paused_from.as_deref(), t).context("派送目前的狀態不能執行這個動作")?;
    sqlx::query(
        "UPDATE deployments SET stage = $2, paused_from = $3, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(new)
    .bind(from)
    .execute(&mut *tx)
    .await?;
    bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        t.action(),
        Some(&name),
        json!({"id": id, "from": stage, "to": new}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// revision 加一：Agent 重設嘗試次數，失敗的裝置會再試
pub async fn retry_failed(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let (name, stage, _) = lock_deployment(&mut tx, id).await?;
    ensure!(stage != "stopped", "已停止的派送不能重試");
    let revision: i32 = sqlx::query_scalar(
        "UPDATE deployments SET revision = revision + 1, updated_at = now() WHERE id = $1 \
         RETURNING revision",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        "deployment_retry",
        Some(&name),
        json!({"id": id, "revision": revision}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn delete_deployment(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let (name, stage, _) = lock_deployment(&mut tx, id).await?;
    ensure!(stage == "stopped", "只能刪除已停止的派送");
    sqlx::query("DELETE FROM deployments WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        "deployment_delete",
        Some(&name),
        json!({"id": id}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_table() {
        use Transition::*;
        assert_eq!(next_stage("pilot", None, Expand), Some(("all", None)));
        assert_eq!(next_stage("all", None, Expand), None);
        assert_eq!(
            next_stage("all", None, Pause),
            Some(("paused", Some("all")))
        );
        assert_eq!(
            next_stage("paused", Some("pilot"), Resume),
            Some(("pilot", None))
        );
        assert_eq!(next_stage("paused", None, Resume), None);
        assert_eq!(
            next_stage("paused", Some("all"), Stop),
            Some(("stopped", None))
        );
        assert_eq!(next_stage("stopped", None, Stop), None);
        assert_eq!(next_stage("stopped", None, Pause), None);
    }
}
