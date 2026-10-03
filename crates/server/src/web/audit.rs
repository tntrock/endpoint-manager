//! 稽核記錄頁（平台管理員）。

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Response;
use chrono::{DateTime, Utc};
use serde::Deserialize;

use super::auth::{AdminSession, Nav};
use super::{fmt_time, forbidden, render};
use crate::AppState;
use crate::error::AppError;

const PAGE_SIZE: i64 = 50;

fn label(action: &str) -> &str {
    match action {
        "login" => "登入成功",
        "login_failed" => "登入失敗",
        "logout" => "登出",
        "password_change" => "修改自己的密碼",
        "token_create" => "建立註冊金鑰",
        "token_revoke" => "作廢註冊金鑰",
        "device_retire" => "除役裝置",
        "device_approve" => "核准重新註冊",
        "device_reject" => "拒絕重新註冊",
        "device_move" => "移動裝置群組",
        "group_create" => "建立群組",
        "group_delete" => "刪除群組",
        "admin_create" => "建立帳號",
        "admin_update" => "變更帳號角色／群組",
        "admin_disable" => "停用帳號",
        "admin_enable" => "啟用帳號",
        "admin_password_reset" => "重設帳號密碼",
        "admin_unlock" => "解除帳號鎖定",
        "rule_create" => "建立合規規則",
        "rule_update" => "修改合規規則",
        "rule_delete" => "刪除合規規則",
        "exemption_create" => "新增豁免",
        "exemption_revoke" => "撤銷豁免",
        "exemption_expire" => "豁免到期",
        "compliance_export" => "匯出違規清單",
        "notify_settings" => "修改通知設定",
        other => other,
    }
}

#[derive(Deserialize)]
pub struct PageQuery {
    #[serde(default)]
    page: i64,
}

pub struct AuditRow {
    pub at: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
}

#[derive(Template)]
#[template(path = "audit.html")]
struct AuditPage {
    nav: Nav,
    rows: Vec<AuditRow>,
    page: i64,
    has_next: bool,
}

type Row = (DateTime<Utc>, String, String, Option<String>, String);

pub async fn page(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<PageQuery>,
) -> Result<Response, AppError> {
    if !s.all_devices() {
        return Ok(forbidden());
    }
    let page = q.page.clamp(0, super::devices::MAX_PAGE);
    let mut rows: Vec<Row> = sqlx::query_as(
        "SELECT at, actor, action, target, detail::text FROM audit_log \
         ORDER BY id DESC LIMIT $1 OFFSET $2",
    )
    .bind(PAGE_SIZE + 1)
    .bind(page * PAGE_SIZE)
    .fetch_all(&st.pool)
    .await?;
    let has_next = rows.len() as i64 > PAGE_SIZE;
    rows.truncate(PAGE_SIZE as usize);
    Ok(render(&AuditPage {
        nav: Nav::new(&s, "audit"),
        rows: rows
            .into_iter()
            .map(|(at, actor, action, target, detail)| AuditRow {
                at: fmt_time(&st, Some(at)),
                actor,
                action: label(&action).to_string(),
                target: target.unwrap_or_default(),
                detail: if detail == "{}" {
                    String::new()
                } else {
                    detail
                },
            })
            .collect(),
        page,
        has_next,
    }))
}
