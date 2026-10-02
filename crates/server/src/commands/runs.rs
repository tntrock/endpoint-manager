//! 建立與取消遠端指令：權限範圍、腳本快照、群組展開成每台一筆。

use chrono::{Duration, Utc};
use protocol::command::CommandAction;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use super::{Actor, CmdError, check};
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
    // 權限最先檢查：群組管理員送腳本一律 403，不因其他欄位得到不同的錯誤
    if action == CommandAction::Script && !actor.platform {
        return Err(CmdError::Forbidden("只有平台管理員能執行腳本".into()).into());
    }
    // 群組：範圍先於存在，群組管理員無法藉錯誤訊息得知群組是否存在
    if let Target::Group(g) = i.target
        && !actor.platform
        && !actor.groups.contains(&g)
    {
        return Err(CmdError::Forbidden("這個群組不在你的管理範圍".into()).into());
    }
    check!(
        action != CommandAction::Unknown,
        Invalid,
        "不支援的動作：{}",
        i.action
    );
    let delay = match action {
        CommandAction::Reboot | CommandAction::Shutdown => {
            let d = i.delay_minutes.unwrap_or(DEFAULT_DELAY_MINUTES);
            check!((0..=60).contains(&d), Invalid, "延遲必須是 0–60 分鐘");
            Some(d)
        }
        _ => None,
    };
    check!(
        (1..=MAX_EXPIRES_HOURS).contains(&i.expires_hours),
        Invalid,
        "過期時間必須是 1 小時到 30 天"
    );
    let second = super::scripts::require_second_approver(pool).await?;
    let mut tx = pool.begin().await?;

    let script: Option<ScriptSnapshot> = if action == CommandAction::Script {
        let id = i
            .script_id
            .ok_or_else(|| CmdError::Invalid("請選擇腳本".into()))?;
        type Row = (String, String, String, i32, Option<String>, Vec<String>);
        let row: Option<Row> = sqlx::query_as(
            "SELECT status, sha256, content, timeout_minutes, approved_by, editors FROM scripts \
             WHERE id = $1 FOR SHARE",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let (status, sha, content, timeout, approved_by, editors) =
            row.ok_or_else(|| CmdError::NotFound("腳本不存在".into()))?;
        check!(status == "approved", Conflict, "腳本尚未核准或已停用");
        // 雙人核准下，自己核准的（切換模式前）不能執行
        check!(
            !second || super::scripts::approval_is_independent(approved_by.as_deref(), &editors),
            Conflict,
            "腳本需要另一位平台管理員核准（已開啟雙人核准）"
        );
        Some((id, sha, content, timeout))
    } else {
        None
    };

    // 對象與範圍：非平台管理員只能選自己群組（未分組的裝置不在範圍內）
    let in_scope = |g: Option<i64>| actor.platform || g.is_some_and(|g| actor.groups.contains(&g));
    let label = match i.target {
        Target::Device(d) => {
            // FOR SHARE：檢查範圍到建立完成之間，裝置不會被移到別的群組
            let row: Option<(String, Option<i64>)> = sqlx::query_as(
                "SELECT hostname, group_id FROM devices WHERE id = $1 AND status = 'active' \
                 FOR SHARE",
            )
            .bind(d)
            .fetch_optional(&mut *tx)
            .await?;
            let forbidden = || CmdError::Forbidden("這台裝置不在你的管理範圍".into());
            // 群組管理員：不存在與範圍外是同一個錯誤
            let (hostname, group) = match row {
                Some(r) => r,
                None if actor.platform => {
                    return Err(CmdError::NotFound("裝置不存在或未啟用".into()).into());
                }
                None => return Err(forbidden().into()),
            };
            if !in_scope(group) {
                return Err(forbidden().into());
            }
            format!("裝置 {hostname}")
        }
        Target::Group(g) => {
            let name: Option<String> =
                sqlx::query_scalar("SELECT name FROM device_groups WHERE id = $1")
                    .bind(g)
                    .fetch_optional(&mut *tx)
                    .await?;
            // 範圍已在最前面檢查過，走到這裡的都是平台管理員或自己的群組
            let name = name.ok_or_else(|| CmdError::NotFound("群組不存在".into()))?;
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
    check!(count > 0, Conflict, "群組內沒有使用中的裝置");
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
    let (label, created_by, canceled) =
        row.ok_or_else(|| CmdError::NotFound("指令不存在".into()))?;
    if !actor.platform && created_by != actor.username {
        return Err(CmdError::Forbidden("只有建立者或平台管理員能取消".into()).into());
    }
    check!(!canceled, Conflict, "指令已取消");
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
    check!(n > 0, Conflict, "指令都已完成，沒有可取消的裝置");
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
