//! 軟體派送：伺服器隨報到下發的指派（期望狀態），以及 Agent 回報的結果。

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 回報訊息長度上限（字元）
pub const MAX_RESULT_MESSAGE: usize = 1000;
/// 參數字串長度上限（字元）
pub const MAX_ARGS_LEN: usize = 1000;
/// 套件檔案大小上限
pub const MAX_PACKAGE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployAction {
    Install,
    Uninstall,
    /// 較新伺服器的新動作：舊 Agent 略過，不讓整個報到回應解析失敗
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageKind {
    Msi,
    Exe,
    /// 較新伺服器的新類型：舊 Agent 略過
    #[serde(other)]
    Unknown,
}

/// 「已安裝」的判斷：名稱與發行者樣式（`*` 萬用字元、不分大小寫），版本 ≥ min_version
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Detect {
    pub name: String,
    #[serde(default)]
    pub publisher: Option<String>,
    #[serde(default)]
    pub min_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PackageSpec {
    pub id: i64,
    pub kind: PackageKind,
    pub sha256: String,
    pub size: u64,
    pub file_name: String,
    #[serde(default)]
    pub install_args: String,
    #[serde(default)]
    pub uninstall_args: String,
    #[serde(default)]
    pub msi_product_code: Option<String>,
    /// 0 以外額外視為成功的結束碼（3010／1641 固定為「成功但需重開機」）
    #[serde(default)]
    pub success_codes: Vec<i32>,
    pub detect: Detect,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Assignment {
    pub deployment_id: i64,
    /// 管理員「重試失敗」時加一，Agent 看到新 revision 會重設嘗試次數
    pub revision: i32,
    pub action: DeployAction,
    pub package: PackageSpec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployStatus {
    /// 本來就符合（已安裝／已移除），沒有執行
    Compliant,
    Succeeded,
    RebootRequired,
    Failed,
}

impl DeployStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            DeployStatus::Compliant => "compliant",
            DeployStatus::Succeeded => "succeeded",
            DeployStatus::RebootRequired => "reboot_required",
            DeployStatus::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeployResult {
    pub revision: i32,
    pub status: DeployStatus,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub attempts: i32,
    /// 套件從哪裡下載（分點快取或中央）；舊版 Agent 沒有
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<crate::branch::DownloadSource>,
}

impl DeployResult {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.message.chars().count() > MAX_RESULT_MESSAGE {
            return Err("message too long");
        }
        if !(0..=100).contains(&self.attempts) {
            return Err("attempts out of range");
        }
        Ok(())
    }
}

/// 指派清單的雜湊（依 deployment_id 排序後的 JSON）：Agent 用來判斷清單有沒有變
pub fn assignments_hash(a: &[Assignment]) -> String {
    let mut sorted: Vec<&Assignment> = a.iter().collect();
    sorted.sort_by_key(|x| x.deployment_id);
    let json = serde_json::to_vec(&sorted).expect("serializable");
    hex::encode(Sha256::digest(&json))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(id: i64) -> Assignment {
        Assignment {
            deployment_id: id,
            revision: 1,
            action: DeployAction::Install,
            package: PackageSpec {
                id: 7,
                kind: PackageKind::Msi,
                sha256: "ab".repeat(32),
                size: 10,
                file_name: "x.msi".into(),
                install_args: String::new(),
                uninstall_args: String::new(),
                msi_product_code: Some("{11111111-1111-1111-1111-111111111111}".into()),
                success_codes: vec![],
                detect: Detect {
                    name: "X*".into(),
                    publisher: None,
                    min_version: Some("1.0".into()),
                },
            },
        }
    }

    #[test]
    fn hash_ignores_order_and_tracks_content() {
        let h = assignments_hash(&[a(1), a(2)]);
        assert_eq!(h, assignments_hash(&[a(2), a(1)]));
        let mut changed = a(2);
        changed.revision = 2;
        assert_ne!(h, assignments_hash(&[a(1), changed]));
        assert_ne!(h, assignments_hash(&[a(1)]));
    }

    #[test]
    fn wire_format_is_snake_case() {
        let v = serde_json::to_value(a(1)).unwrap();
        assert_eq!(v["action"], "install");
        assert_eq!(v["package"]["kind"], "msi");
        let s = serde_json::to_value(DeployStatus::RebootRequired).unwrap();
        assert_eq!(s, "reboot_required");
    }

    #[test]
    fn unknown_kinds_do_not_break_parsing() {
        let mut v = serde_json::to_value(a(1)).unwrap();
        v["action"] = "reinstall".into();
        v["package"]["kind"] = "appx".into();
        let parsed: Assignment = serde_json::from_value(v).unwrap();
        assert_eq!(
            (parsed.action, parsed.package.kind),
            (DeployAction::Unknown, PackageKind::Unknown)
        );
    }

    #[test]
    fn result_validation() {
        let ok = DeployResult {
            revision: 1,
            status: DeployStatus::Failed,
            exit_code: Some(1603),
            message: "x".repeat(1000),
            attempts: 3,
            source: None,
        };
        assert!(ok.validate().is_ok());
        let long = DeployResult {
            message: "x".repeat(1001),
            ..ok.clone()
        };
        assert!(long.validate().is_err());
        let bad = DeployResult {
            attempts: 101,
            ..ok
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn old_checkin_response_parses_without_deployments() {
        let r: crate::CheckinResponse = serde_json::from_value(serde_json::json!({
            "next_checkin_seconds": 60,
            "request_sections": [],
            "collection_intervals": {"software_secs": 1, "patches_secs": 1, "services_secs": 1, "hardware_secs": 1},
            "renew_certificate": false
        }))
        .unwrap();
        assert!(r.deployments.is_empty() && r.deployments_hash.is_none());
    }
}
