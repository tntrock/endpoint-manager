//! 建立與取消遠端指令：權限範圍、腳本快照、群組展開成每台一筆。

use anyhow::{Context, bail, ensure};
use chrono::{Duration, Utc};
use protocol::command::CommandAction;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use super::Actor;
use crate::audit;

pub const DEFAULT_DELAY_MINUTES: i32 = 10;
pub const DEFAULT_EXPIRES_HOURS: i64 = 24 * 7;
pub const MAX_EXPIRES_HOURS: i64 = 24 * 30;

#[derive(Debug, Clone, Copy)]
pub enum Target {
    Device(Uuid),
    Group(i64),
}

#[derive(Debug, Clone)]
pub struct RunInput {
    pub action: String,
    pub target: Target,
    pub delay_minutes: Option<i32>,
    pub script_id: Option<i64>,
    pub expires_hours: i64,
}

/// 腳本快照：(id, sha256, 內容, 逾時)
type ScriptSnapshot = (i64, String, String, i32);

/// 回傳 (run id, 台數)
pub async fn create_run(pool: &PgPool, i: &RunInput, actor: &Actor) -> anyhow::Result<(i64, i64)> {
    let action = CommandAction::parse(&i.action);
    ensure!(
        action != CommandAction::Unknown,
        "不支援的動作：{}",
        i.action
    );
    let delay = match action {
        CommandAction::Reboot | CommandAction::Shutdown => {
            let d = i.delay_minutes.unwrap_or(DEFAULT_DELAY_MINUTES);
            ensure!((0..=60).contains(&d), "延遲必須是 0–60 分鐘");
            Some(d)
        }
        _ => None,
    };
    ensure!(
        (1..=MAX_EXPIRES_HOURS).contains(&i.expires_hours),
        "過期時間必須是 1 小時到 30 天"
    );
    ensure!(
        action != CommandAction::Script || actor.platform,
        "只有平台管理員能執行腳本"
    );
    let mut tx = pool.begin().await?;

    let script: Option<ScriptSnapshot> = if action == CommandAction::Script {
        let id = i.script_id.context("請選擇腳本")?;
        let row: Option<(String, String, String, i32)> = sqlx::query_as(
            "SELECT status, sha256, content, timeout_minutes FROM scripts \
             WHERE id = $1 FOR SHARE",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let (status, sha, content, timeout) = row.context("腳本不存在")?;
        ensure!(status == "approved", "腳本尚未核准或已停用");
        Some((id, sha, content, timeout))
    } else {
        None
    };

    // 對象與範圍：非平台管理員只能選自己群組（未分組的裝置不在範圍內）
    let in_scope = |g: Option<i64>| actor.platform || g.is_some_and(|g| actor.groups.contains(&g));
    let label = match i.target {
        Target::Device(d) => {
            let row: Option<(String, Option<i64>)> = sqlx::query_as(
                "SELECT hostname, group_id FROM devices WHERE id = $1 AND status = 'active'",
            )
            .bind(d)
            .fetch_optional(&mut *tx)
            .await?;
            let (hostname, group) = row.context("裝置不存在或未啟用")?;
            ensure!(in_scope(group), "這台裝置不在你的管理範圍");
            format!("裝置 {hostname}")
        }
        Target::Group(g) => {
            let name: Option<String> =
                sqlx::query_scalar("SELECT name FROM device_groups WHERE id = $1")
                    .bind(g)
                    .fetch_optional(&mut *tx)
                    .await?;
            let name = name.context("群組不存在")?;
            ensure!(in_scope(Some(g)), "這個群組不在你的管理範圍");
            format!("群組 {name}")
        }
    };

    let expires_at = Utc::now() + Duration::hours(i.expires_hours);
    let run_id: i64 = sqlx::query_scalar(
        "INSERT INTO command_runs (action, delay_minutes, script_id, script_sha256, \
           script_content, script_timeout_minutes, target_label, created_by, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
    )
    .bind(action.as_str())
    .bind(delay)
    .bind(script.as_ref().map(|s| s.0))
    .bind(script.as_ref().map(|s| s.1.clone()))
    .bind(script.as_ref().map(|s| s.2.clone()))
    .bind(script.as_ref().map(|s| s.3))
    .bind(&label)
    .bind(&actor.username)
    .bind(expires_at)
    .fetch_one(&mut *tx)
    .await?;
    let count = match i.target {
        Target::Device(d) => {
            sqlx::query("INSERT INTO command_targets (run_id, device_id) VALUES ($1, $2)")
                .bind(run_id)
                .bind(d)
                .execute(&mut *tx)
                .await?
                .rows_affected()
        }
        Target::Group(g) => sqlx::query(
            "INSERT INTO command_targets (run_id, device_id) \
             SELECT $1, id FROM devices WHERE status = 'active' AND group_id = $2",
        )
        .bind(run_id)
        .bind(g)
        .execute(&mut *tx)
        .await?
        .rows_affected(),
    } as i64;
    if count == 0 {
        bail!("群組內沒有使用中的裝置");
    }
    audit::record(
        &mut tx,
        &actor.username,
        "command_create",
        Some(&label),
        json!({
            "id": run_id, "action": action.as_str(), "count": count,
            "script_id": script.as_ref().map(|s| s.0),
            "script_sha256": script.as_ref().map(|s| s.1.clone()),
            "delay_minutes": delay, "expires_at": expires_at,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok((run_id, count))
}

pub async fn cancel_run(pool: &PgPool, id: i64, actor: &Actor) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let row: Option<(String, String, bool)> = sqlx::query_as(
        "SELECT target_label, created_by, canceled_at IS NOT NULL FROM command_runs \
         WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let (label, created_by, canceled) = row.context("指令不存在")?;
    ensure!(
        actor.platform || created_by == actor.username,
        "只有建立者或平台管理員能取消"
    );
    ensure!(!canceled, "指令已取消");
    sqlx::query("UPDATE command_runs SET canceled_at = now(), canceled_by = $2 WHERE id = $1")
        .bind(id)
        .bind(&actor.username)
        .execute(&mut *tx)
        .await?;
    let n = sqlx::query(
        "UPDATE command_targets SET status = 'canceled', finished_at = now() \
         WHERE run_id = $1 AND status IN ('pending', 'sent')",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    audit::record(
        &mut tx,
        &actor.username,
        "command_cancel",
        Some(&label),
        json!({"id": id, "canceled": n}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
