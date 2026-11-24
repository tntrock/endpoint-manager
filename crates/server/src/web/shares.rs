//! 裝置頁的「共用」卡片（錯誤設定規格 §4.3）：Windows 在「安全」分頁、Linux 在「帳號與權限」分頁。

use protocol::{ShareAccess, SharesInfo};
use uuid::Uuid;

use crate::AppState;

pub struct ShareRow {
    pub kind: &'static str,
    pub name: String,
    pub path: String,
    pub anonymous: &'static str,
    pub all_users: &'static str,
    /// 匿名可讀寫、所有使用者可寫入，或 NFS 的 no_root_squash
    pub warn: bool,
    /// NFS：允許的來源與 no_root_squash
    pub note: String,
}

/// 還沒上傳共用區段時 None
pub struct SharesCard {
    pub rows: Vec<ShareRow>,
    pub errors: Vec<String>,
}

pub fn access_label(a: ShareAccess) -> &'static str {
    match a {
        ShareAccess::None => "—",
        ShareAccess::Read => "可讀取",
        ShareAccess::Write => "可寫入",
    }
}

fn kind_label(kind: &str) -> &'static str {
    match kind {
        "smb" => "SMB",
        "samba" => "Samba",
        "nfs" => "NFS",
        _ => "其他",
    }
}

pub fn card(info: SharesInfo) -> SharesCard {
    let mut rows: Vec<ShareRow> = info
        .shares
        .into_iter()
        .map(|s| {
            let mut note = vec![];
            if !s.clients.is_empty() {
                note.push(format!("來源：{}", s.clients.join("、")));
            }
            if s.no_root_squash {
                note.push("no_root_squash".to_string());
            }
            ShareRow {
                kind: kind_label(&s.kind),
                warn: s.anonymous != ShareAccess::None
                    || s.all_users == ShareAccess::Write
                    || s.no_root_squash,
                anonymous: access_label(s.anonymous),
                all_users: access_label(s.all_users),
                note: note.join("；"),
                name: s.name,
                path: s.path,
            }
        })
        .collect();
    rows.sort_by_key(|r| !r.warn);
    SharesCard {
        rows,
        errors: info.errors,
    }
}

/// 讀取裝置的共用區段；沒有資料或 jsonb 讀不回來時 None
pub async fn load(st: &AppState, id: Uuid) -> Result<Option<SharesCard>, sqlx::Error> {
    let data: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT data FROM device_shares WHERE device_id = $1")
            .bind(id)
            .fetch_optional(&st.pool)
            .await?;
    Ok(data
        .and_then(|d| serde_json::from_value::<SharesInfo>(d).ok())
        .map(card))
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::ShareItem;

    #[test]
    fn rows_and_warnings() {
        let item = |name: &str, kind: &str, anon, users| ShareItem {
            kind: kind.into(),
            name: name.into(),
            path: format!("/srv/{name}"),
            anonymous: anon,
            all_users: users,
            no_root_squash: false,
            clients: vec![],
        };
        let mut nfs = item("n", "nfs", ShareAccess::None, ShareAccess::Read);
        nfs.clients = vec!["10.0.0.0/8".into()];
        nfs.no_root_squash = true;
        let c = card(SharesInfo {
            shares: vec![
                item("ok", "smb", ShareAccess::None, ShareAccess::Read),
                item("pub", "samba", ShareAccess::Write, ShareAccess::Write),
                nfs,
                item("x", "zz", ShareAccess::None, ShareAccess::None),
            ],
            errors: vec!["e".into()],
        });
        let names: Vec<&str> = c.rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["pub", "n", "ok", "x"], "警示的排前面");
        assert_eq!(
            (c.rows[0].kind, c.rows[0].anonymous, c.rows[0].all_users),
            ("Samba", "可寫入", "可寫入")
        );
        assert_eq!(c.rows[1].note, "來源：10.0.0.0/8；no_root_squash");
        assert!(c.rows[1].warn);
        assert_eq!((c.rows[2].kind, c.rows[2].anonymous), ("SMB", "—"));
        assert!(!c.rows[2].warn);
        assert_eq!(c.rows[3].kind, "其他");
        assert_eq!(c.errors, ["e"]);
    }
}
