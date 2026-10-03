//! state.json：裝置身分（含私鑰）與被拒區段；以原子方式寫入。

use std::collections::BTreeMap;
use std::path::Path;

use protocol::Section;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const FILE: &str = "state.json";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentState {
    pub device_id: Option<Uuid>,
    pub chain_pem: Option<String>,
    pub key_pem: Option<String>,
    /// 被伺服器拒絕的區段 → 被拒時的 hash；hash 改變前不再重送
    #[serde(default)]
    pub rejected: BTreeMap<Section, String>,
}

pub use protocol::write_atomic;

impl AgentState {
    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        let path = dir.join(FILE);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.into()),
        };
        match serde_json::from_slice(&bytes) {
            Ok(s) => Ok(s),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "state.json is corrupt; moved to state.json.corrupt, re-enrollment required"
                );
                std::fs::rename(&path, dir.join("state.json.corrupt"))?;
                Ok(Self::default())
            }
        }
    }

    pub fn save(&self, dir: &Path) -> anyhow::Result<()> {
        write_atomic(&dir.join(FILE), &serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub fn is_enrolled(&self) -> bool {
        self.device_id.is_some() && self.chain_pem.is_some() && self.key_pem.is_some()
    }

    /// 裝置憑證（chain 的第一張）的到期時間。
    pub fn cert_not_after(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        let der = CertificateDer::from_pem_slice(self.chain_pem.as_ref()?.as_bytes()).ok()?;
        let (_, cert) = x509_parser::parse_x509_certificate(&der).ok()?;
        chrono::DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
    }

    pub fn identity_pem(&self) -> Option<String> {
        Some(format!(
            "{}{}",
            self.chain_pem.as_ref()?,
            self.key_pem.as_ref()?
        ))
    }
}

/// 資料目錄的安全描述元（SDDL）：擁有者 Administrators，DACL 受保護（不繼承），
/// 只有 SYSTEM 與 Administrators 完全控制。建立目錄時直接套用。
pub const DATA_DIR_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// 目錄現有的安全描述元是否可信：擁有者為 SYSTEM／Administrators，DACL 受保護，
/// 而且恰好只有 SYSTEM 與 Administrators 的完全控制（沒有其他項目、沒有繼承項目）。
/// 用在搶先建立目錄的一般使用者：他可能是擁有者，或自己加了權限項目。
pub fn sddl_is_trusted(sddl: &str) -> bool {
    const SYSTEM: [&str; 2] = ["SY", "S-1-5-18"];
    const ADMINS: [&str; 2] = ["BA", "S-1-5-32-544"];
    let Some(owner) = sddl
        .strip_prefix("O:")
        .map(|r| r.split(['G', 'D']).next().unwrap_or_default())
    else {
        return false;
    };
    if !SYSTEM.contains(&owner) && !ADMINS.contains(&owner) {
        return false;
    }
    let Some((_, dacl)) = sddl.split_once("D:") else {
        return false;
    };
    let (flags, aces) = dacl.split_at(dacl.find('(').unwrap_or(dacl.len()));
    if !flags.contains('P') {
        return false;
    }
    let (mut system, mut admins) = (false, false);
    for ace in aces.split(['(', ')']).filter(|a| !a.is_empty()) {
        let f: Vec<&str> = ace.split(';').collect();
        let full = f.len() == 6
            && f[0] == "A"
            && matches!(f[1], "OICI" | "CIOI")
            && matches!(f[2], "FA" | "0x1f01ff");
        match f.get(5) {
            Some(sid) if full && SYSTEM.contains(sid) && !system => system = true,
            Some(sid) if full && ADMINS.contains(sid) && !admins => admins = true,
            _ => return false,
        }
    }
    system && admins
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_sddl_is_exactly_system_and_admins() {
        for ok in [
            "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
            "O:SYD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)",
            "O:S-1-5-32-544D:P(A;CIOI;0x1f01ff;;;S-1-5-18)(A;OICI;FA;;;S-1-5-32-544)",
        ] {
            assert!(sddl_is_trusted(ok), "{ok}");
        }
        for bad in [
            // 擁有者是一般使用者：可以隨時改回權限
            "O:S-1-5-21-1-2-3-1001D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
            // 沒有 P：會繼承 ProgramData（Users 可讀）
            "O:BAD:AI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
            // 多一個使用者自己加的項目
            "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-21-1-2-3-1001)",
            "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)",
            // 拒絕項目、繼承項目、缺少其中一個、權限不足
            "O:BAD:P(D;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
            "O:BAD:P(A;OICIID;FA;;;SY)(A;OICI;FA;;;BA)",
            "O:BAD:P(A;OICI;FA;;;SY)",
            "O:BAD:P(A;OICI;FR;;;SY)(A;OICI;FA;;;BA)",
            // 沒有 DACL
            "O:BAG:SY",
            "",
        ] {
            assert!(!sddl_is_trusted(bad), "{bad}");
        }
    }

    #[test]
    fn missing_state_is_default() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(AgentState::load(dir.path()).unwrap(), AgentState::default());
    }

    #[test]
    fn roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = AgentState {
            device_id: Some(Uuid::new_v4()),
            chain_pem: Some("CHAIN".into()),
            key_pem: Some("KEY".into()),
            ..Default::default()
        };
        s.rejected.insert(Section::Software, "abc".into());
        s.save(dir.path()).unwrap();
        let back = AgentState::load(dir.path()).unwrap();
        assert_eq!(back, s);
        assert!(back.is_enrolled());
        assert_eq!(back.identity_pem().as_deref(), Some("CHAINKEY"));
        assert!(!dir.path().join("state.json.tmp").exists());
    }

    #[test]
    fn corrupt_state_is_set_aside() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("state.json"), b"{\"device_id\": \"not-a-uu").unwrap();
        assert_eq!(AgentState::load(dir.path()).unwrap(), AgentState::default());
        assert!(dir.path().join("state.json.corrupt").exists());
        assert!(!dir.path().join("state.json").exists());
    }
}
