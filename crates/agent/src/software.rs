//! Uninstall 機碼項目轉成 SoftwareItem（純函式，讀登錄檔在 windows/registry.rs）。

use protocol::{Arch, SoftwareItem};

#[derive(Debug, Clone, Default)]
pub struct UninstallEntry {
    pub display_name: Option<String>,
    pub display_version: Option<String>,
    pub publisher: Option<String>,
    pub install_date: Option<String>,
    pub system_component: Option<u32>,
    pub parent_key_name: Option<String>,
    pub release_type: Option<String>,
}

const HIDDEN_RELEASE_TYPES: &[&str] = &["Update", "Hotfix", "Security Update"];

/// 只保留「程式和功能」看得到的項目，並去除完全相同的重複項。
pub fn to_items(entries: &[UninstallEntry], arch: Arch) -> Vec<SoftwareItem> {
    let mut items: Vec<SoftwareItem> = entries
        .iter()
        .filter(|e| e.system_component != Some(1))
        .filter(|e| e.parent_key_name.is_none())
        .filter(|e| {
            e.release_type
                .as_deref()
                .is_none_or(|t| !HIDDEN_RELEASE_TYPES.contains(&t))
        })
        .filter_map(|e| {
            let name = e.display_name.as_deref()?.trim();
            (!name.is_empty()).then(|| SoftwareItem {
                name: name.to_string(),
                version: e.display_version.clone(),
                publisher: e.publisher.clone(),
                install_date: e.install_date.clone(),
                arch,
            })
        })
        .collect();
    items.sort();
    items.dedup();
    items
}

/// HKEY_USERS 底下真正的使用者設定檔：AD／本機帳戶（S-1-5-21-）與 Entra ID 帳戶（S-1-12-1-），
/// 排除系統帳戶與 _Classes。
pub fn is_user_sid(name: &str) -> bool {
    (name.starts_with("S-1-5-21-") || name.starts_with("S-1-12-1-")) && !name.ends_with("_Classes")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(name: &str) -> UninstallEntry {
        UninstallEntry {
            display_name: Some(name.into()),
            display_version: Some("1.0".into()),
            ..Default::default()
        }
    }

    #[test]
    fn keeps_visible_programs_only() {
        let entries = vec![
            e("7-Zip"),
            UninstallEntry {
                system_component: Some(1),
                ..e("Hidden")
            },
            UninstallEntry {
                parent_key_name: Some("Office".into()),
                ..e("Office Update")
            },
            UninstallEntry {
                release_type: Some("Security Update".into()),
                ..e("KB123")
            },
            UninstallEntry {
                display_name: Some("   ".into()),
                ..Default::default()
            },
            UninstallEntry::default(),
        ];
        let items = to_items(&entries, Arch::X64);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "7-Zip");
        assert_eq!(items[0].version.as_deref(), Some("1.0"));
        assert_eq!(items[0].arch, Arch::X64);
    }

    #[test]
    fn identical_entries_deduplicated() {
        let items = to_items(&[e("A"), e("A"), e("B")], Arch::X86);
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn user_sid_detection() {
        assert!(is_user_sid("S-1-5-21-111-222-333-1001"));
        assert!(is_user_sid("S-1-12-1-111-222-333-444"), "Entra ID 使用者");
        assert!(!is_user_sid("S-1-12-1-111-222-333-444_Classes"));
        assert!(!is_user_sid("S-1-5-21-111-222-333-1001_Classes"));
        assert!(!is_user_sid("S-1-5-18"));
        assert!(!is_user_sid(".DEFAULT"));
    }
}
