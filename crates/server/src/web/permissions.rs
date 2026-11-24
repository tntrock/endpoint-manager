//! 權限過寬卡片（錯誤設定規格 §6.1）：Windows 在「安全設定」分頁，Linux 在「帳號與權限」分頁。

use protocol::PermissionsInfo;
use uuid::Uuid;

use crate::AppState;
use crate::compliance::evaluate::permission_label;

pub struct PermissionRow {
    pub label: &'static str,
    pub path: String,
    pub name: String,
    pub granted_to: String,
}

pub struct PermissionsCard {
    pub rows: Vec<PermissionRow>,
    pub truncated: bool,
    pub errors: Vec<String>,
}

pub fn card(info: PermissionsInfo) -> PermissionsCard {
    PermissionsCard {
        rows: info
            .items
            .into_iter()
            .map(|x| PermissionRow {
                label: permission_label(&x.kind),
                path: x.path,
                name: x.name.unwrap_or_default(),
                granted_to: x.granted_to.join("、"),
            })
            .collect(),
        truncated: info.truncated,
        errors: info.errors,
    }
}

/// 讀取裝置的 permissions 區段；沒有資料或 jsonb 讀不回來時 None
pub async fn load(st: &AppState, id: Uuid) -> Result<Option<PermissionsCard>, sqlx::Error> {
    let data: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT data FROM device_permissions WHERE device_id = $1")
            .bind(id)
            .fetch_optional(&st.pool)
            .await?;
    Ok(data
        .and_then(|d| serde_json::from_value::<PermissionsInfo>(d).ok())
        .map(card))
}
