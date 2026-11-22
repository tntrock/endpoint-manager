//! Hyper-V 虛擬機：WMI `root\virtualization\v2`。沒有安裝 Hyper-V 時這個命名空間不存在。

use std::collections::HashMap;

use protocol::{RuntimeInfo, VmItem, VmsInfo};
use serde::Deserialize;

use crate::serde_util::u64_any;
use crate::vms as parse;

/// 已實現（不是檢查點）的虛擬機設定：BIOSGUID 就是客體看到的 SMBIOS UUID
const SETTINGS: &str = "SELECT VirtualSystemIdentifier, ElementName, BIOSGUID \
                        FROM Msvm_VirtualSystemSettingData \
                        WHERE VirtualSystemType = 'Microsoft:Hyper-V:System:Realized'";

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Settings {
    virtual_system_identifier: Option<String>,
    element_name: Option<String>,
    #[serde(rename = "BIOSGUID")]
    bios_guid: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename = "Msvm_ComputerSystem", rename_all = "PascalCase")]
struct System {
    name: Option<String>,
    #[serde(default, deserialize_with = "u64_any")]
    enabled_state: Option<u64>,
}

/// 處理器與記憶體設定；InstanceID 是 `Microsoft:<VM GUID>\…`（檢查點用另一個 GUID）
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Resource {
    #[serde(rename = "InstanceID")]
    instance_id: Option<String>,
    #[serde(default, deserialize_with = "u64_any")]
    virtual_quantity: Option<u64>,
}

/// InstanceID 屬於哪台虛擬機
fn owner(instance_id: &str) -> Option<String> {
    let rest = instance_id.strip_prefix("Microsoft:")?;
    parse::guid(rest.split('\\').next()?)
}

fn by_vm(rows: Vec<Resource>) -> HashMap<String, u64> {
    rows.into_iter()
        .filter_map(|r| Some((owner(r.instance_id.as_deref()?)?, r.virtual_quantity?)))
        .collect()
}

fn list(con: &wmi::WMIConnection) -> anyhow::Result<Vec<VmItem>> {
    let settings: Vec<Settings> = con.raw_query(SETTINGS)?;
    let states: HashMap<String, u64> = con
        .query::<System>()?
        .into_iter()
        .filter_map(|s| Some((parse::guid(s.name.as_deref()?)?, s.enabled_state?)))
        .collect();
    let cpus = by_vm(
        con.raw_query("SELECT InstanceID, VirtualQuantity FROM Msvm_ProcessorSettingData")
            .unwrap_or_default(),
    );
    let memory = by_vm(
        con.raw_query("SELECT InstanceID, VirtualQuantity FROM Msvm_MemorySettingData")
            .unwrap_or_default(),
    );
    Ok(settings
        .into_iter()
        .filter_map(|s| {
            let id = parse::guid(s.virtual_system_identifier.as_deref()?)?;
            Some(VmItem {
                platform: "hyperv".into(),
                name: s.element_name.unwrap_or_else(|| id.clone()),
                state: parse::hyperv_state(states.get(&id).copied().unwrap_or(0)).into(),
                bios_uuid: s.bios_guid.as_deref().and_then(parse::guid),
                vcpus: cpus.get(&id).and_then(|&n| u32::try_from(n).ok()),
                memory_mb: memory.get(&id).copied(),
                os_hint: None,
                id,
            })
        })
        .collect())
}

pub fn collect() -> VmsInfo {
    // 連不上這個命名空間：沒有安裝 Hyper-V
    let Ok(con) = wmi::WMIConnection::with_namespace_path(r"root\virtualization\v2") else {
        return VmsInfo {
            platforms: vec![],
            vms: vec![],
            truncated: false,
        };
    };
    let (items, error) = match list(&con) {
        Ok(v) => (v, None),
        Err(e) => (vec![], Some(e.to_string().chars().take(500).collect())),
    };
    let (vms, truncated) = parse::finish(items);
    VmsInfo {
        platforms: vec![RuntimeInfo {
            kind: "hyperv".into(),
            version: None,
            error,
        }],
        vms,
        truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_owner() {
        assert_eq!(
            owner(r"Microsoft:6A1B2C3D-0000-1111-2222-333344445555\b637f346-6a0e-4dec-af52-bd70cb80a21d\0").as_deref(),
            Some("6a1b2c3d-0000-1111-2222-333344445555")
        );
        assert_eq!(owner("Other:x"), None);
        let m = by_vm(vec![
            Resource {
                instance_id: Some(r"Microsoft:6A1B2C3D-0000-1111-2222-333344445555\x".into()),
                virtual_quantity: Some(4),
            },
            Resource {
                instance_id: None,
                virtual_quantity: Some(1),
            },
        ]);
        assert_eq!(m.get("6a1b2c3d-0000-1111-2222-333344445555"), Some(&4));
        assert_eq!(m.len(), 1);
    }
}
