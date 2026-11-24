//! Windows 本機帳號卡片（錯誤設定規格 §6.2）：放在裝置頁「安全設定」分頁。

use protocol::AccountsInfo;
use uuid::Uuid;

use crate::AppState;

/// Windows 內建 Guest 帳號的 RID
const GUEST_RID: u32 = 501;

pub struct UserRow {
    pub name: String,
    pub disabled: bool,
    pub never_expires: bool,
    pub no_password: bool,
    pub guest: bool,
    pub last_logon: String,
}

pub struct LocalUsersCard {
    /// Agent 有回報帳號旗標（0.15.0 以上）
    pub flags: bool,
    pub rows: Vec<UserRow>,
    /// 自動登入存了密碼；None＝讀不到
    pub autologon_password: Option<bool>,
    pub errors: Vec<String>,
}

pub fn card(st: &AppState, a: AccountsInfo) -> LocalUsersCard {
    let mut rows: Vec<UserRow> = a
        .users
        .into_iter()
        .map(|u| UserRow {
            disabled: u.disabled,
            never_expires: u.password_never_expires,
            no_password: u.no_password == Some(true),
            guest: u.uid == GUEST_RID,
            last_logon: super::fmt_time(st, u.last_logon),
            name: u.name,
        })
        .collect();
    // 啟用中的排前面
    rows.sort_by(|x, y| {
        (x.disabled, x.name.to_lowercase()).cmp(&(y.disabled, y.name.to_lowercase()))
    });
    LocalUsersCard {
        flags: a.flags,
        rows,
        autologon_password: a.autologon_password,
        errors: a.errors,
    }
}

/// 讀取裝置的 accounts 區段；沒有資料或 jsonb 讀不回來時 None
pub async fn load(st: &AppState, id: Uuid) -> Result<Option<LocalUsersCard>, sqlx::Error> {
    let data: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT data FROM device_accounts WHERE device_id = $1")
            .bind(id)
            .fetch_optional(&st.pool)
            .await?;
    Ok(data
        .and_then(|d| serde_json::from_value::<AccountsInfo>(d).ok())
        .map(|a| card(st, a)))
}
