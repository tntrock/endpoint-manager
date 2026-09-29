//! WMI 收集。每次呼叫建立新的 WMIConnection（在 blocking 執行緒上初始化 COM）。

use anyhow::Context;
use chrono::Utc;
use protocol::{BasicInfo, Disk, HardwareInfo, InventoryPayload, PatchItem, Section, ServiceItem};
use serde::Deserialize;
use wmi::{WMIConnection, WMIDateTime};

use crate::collector::{Collector, Heartbeat, Identity};
use crate::serde_util::u64_any;

#[derive(Deserialize)]
#[serde(rename = "Win32_ComputerSystem", rename_all = "PascalCase")]
struct ComputerSystem {
    name: Option<String>,
    domain: Option<String>,
    part_of_domain: Option<bool>,
    user_name: Option<String>,
    manufacturer: Option<String>,
    model: Option<String>,
    #[serde(default, deserialize_with = "u64_any")]
    total_physical_memory: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename = "Win32_OperatingSystem", rename_all = "PascalCase")]
struct OperatingSystem {
    caption: Option<String>,
    build_number: Option<String>,
    last_boot_up_time: Option<WMIDateTime>,
}

#[derive(Deserialize)]
#[serde(rename = "Win32_ComputerSystemProduct")]
struct Product {
    #[serde(rename = "UUID")]
    uuid: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename = "Win32_BIOS", rename_all = "PascalCase")]
struct Bios {
    serial_number: Option<String>,
}

#[derive(Deserialize)]
struct Nic {
    #[serde(rename = "IPAddress")]
    ip_address: Option<Vec<String>>,
    #[serde(rename = "MACAddress")]
    mac_address: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename = "Win32_Processor", rename_all = "PascalCase")]
struct Processor {
    name: Option<String>,
}

#[derive(Deserialize)]
struct LogicalDisk {
    #[serde(rename = "DeviceID")]
    device_id: String,
    #[serde(rename = "Size", default, deserialize_with = "u64_any")]
    size: Option<u64>,
    #[serde(rename = "FreeSpace", default, deserialize_with = "u64_any")]
    free_space: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename = "Win32_QuickFixEngineering", rename_all = "PascalCase")]
struct QuickFix {
    #[serde(rename = "HotFixID")]
    hot_fix_id: Option<String>,
    installed_on: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename = "Win32_Service", rename_all = "PascalCase")]
struct Service {
    name: Option<String>,
    display_name: Option<String>,
    start_mode: Option<String>,
    state: Option<String>,
    path_name: Option<String>,
}

const NICS: &str =
    "SELECT IPAddress, MACAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE";
const FIXED_DISKS: &str =
    "SELECT DeviceID, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType = 3";

fn wmi() -> anyhow::Result<WMIConnection> {
    WMIConnection::new().context("connecting to WMI")
}

fn computer_system(con: &WMIConnection) -> anyhow::Result<ComputerSystem> {
    con.query::<ComputerSystem>()?
        .into_iter()
        .next()
        .context("Win32_ComputerSystem returned nothing")
}

fn hostname(cs: Option<&ComputerSystem>) -> String {
    cs.and_then(|c| c.name.clone())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_default()
}

/// 非必要的 WMI 查詢：失敗時記錄並當成沒有資料，不讓整個 identity／heartbeat 失敗
/// （例如某些虛擬機或損壞的 WMI 儲存庫查不到 BIOS）。
fn optional<T, E: std::fmt::Display>(what: &str, r: Result<Vec<T>, E>) -> Vec<T> {
    match r {
        Ok(v) => {
            recovered(what);
            v
        }
        Err(e) => {
            // 服務模式只把 INFO 以上寫進事件記錄；同一個錯誤只記一次，避免每分鐘洗版
            let e = e.to_string();
            if first_report(what, &e) {
                tracing::warn!(query = what, error = %e, "optional WMI query failed");
            }
            vec![]
        }
    }
}

/// 各查詢上一次記錄的錯誤
static LAST_ERROR: std::sync::Mutex<Vec<(String, String)>> = std::sync::Mutex::new(Vec::new());

/// 這個查詢的這個錯誤是否還沒記錄過（記錄過就不再記，錯誤改變或恢復後才再記）。
pub(crate) fn first_report(what: &str, err: &str) -> bool {
    let mut last = LAST_ERROR.lock().unwrap_or_else(|p| p.into_inner());
    match last.iter_mut().find(|(w, _)| w == what) {
        Some((_, e)) if e == err => false,
        Some((_, e)) => {
            *e = err.to_string();
            true
        }
        None => {
            last.push((what.to_string(), err.to_string()));
            true
        }
    }
}

pub(crate) fn recovered(what: &str) {
    let mut last = LAST_ERROR.lock().unwrap_or_else(|p| p.into_inner());
    last.retain(|(w, _)| w != what);
}

pub struct WindowsCollector;

impl Collector for WindowsCollector {
    fn identity(&self) -> anyhow::Result<Identity> {
        let con = wmi()?;
        let cs = computer_system(&con).ok();
        // 硬體識別（SMBIOS UUID、BIOS 序號）是重灌比對的依據：查不到就不註冊，等下一輪再試，
        // 避免建立一筆永遠比對不到的裝置記錄
        let product: Vec<Product> = con.query().context("Win32_ComputerSystemProduct")?;
        let bios: Vec<Bios> = con.query().context("Win32_BIOS")?;
        let nics: Vec<Nic> = optional("NICs", con.raw_query(NICS));
        Ok(Identity {
            hostname: hostname(cs.as_ref()),
            smbios_uuid: product.into_iter().next().and_then(|p| p.uuid),
            bios_serial: bios.into_iter().next().and_then(|b| b.serial_number),
            mac_addresses: nics.into_iter().filter_map(|n| n.mac_address).collect(),
        })
    }

    fn heartbeat(&self) -> anyhow::Result<Heartbeat> {
        let con = wmi()?;
        let cs = computer_system(&con).ok();
        let os: Vec<OperatingSystem> = optional("Win32_OperatingSystem", con.query());
        let nics: Vec<Nic> = optional("NICs", con.raw_query(NICS));
        Ok(Heartbeat {
            boot_time: os
                .into_iter()
                .next()
                .and_then(|o| o.last_boot_up_time)
                .map(|t| t.0.with_timezone(&Utc))
                .unwrap_or_else(Utc::now),
            logged_on_user: cs.and_then(|c| c.user_name),
            ip_addresses: nics
                .into_iter()
                .flat_map(|n| n.ip_address.unwrap_or_default())
                .collect(),
        })
    }

    fn collect_registry(
        &self,
        queries: &[protocol::RegistryQuery],
    ) -> anyhow::Result<InventoryPayload> {
        Ok(InventoryPayload::Registry(super::registry::read_values(
            queries,
        )))
    }

    fn collect(&self, section: Section) -> anyhow::Result<InventoryPayload> {
        if section == Section::Software {
            return Ok(InventoryPayload::Software(
                super::registry::read_all_software(),
            ));
        }
        if section == Section::Security {
            return Ok(InventoryPayload::Security(super::security::collect()));
        }
        let con = wmi()?;
        Ok(match section {
            Section::Basic => {
                let cs = computer_system(&con)?;
                let os = con.query::<OperatingSystem>()?.into_iter().next();
                InventoryPayload::Basic(BasicInfo {
                    hostname: hostname(Some(&cs)),
                    domain: cs.domain.clone(),
                    is_domain_joined: cs.part_of_domain.unwrap_or(false),
                    os_caption: os
                        .as_ref()
                        .and_then(|o| o.caption.clone())
                        .unwrap_or_default(),
                    os_build: os.and_then(|o| o.build_number).unwrap_or_default(),
                    os_ubr: read_ubr(),
                })
            }
            Section::Hardware => {
                let cs = computer_system(&con)?;
                let cpu: Vec<Processor> = con.query()?;
                let disks: Vec<LogicalDisk> = con.raw_query(FIXED_DISKS)?;
                InventoryPayload::Hardware(HardwareInfo {
                    manufacturer: cs.manufacturer,
                    model: cs.model,
                    cpu: cpu.into_iter().next().and_then(|p| p.name),
                    ram_mb: cs.total_physical_memory.unwrap_or(0) / (1024 * 1024),
                    disks: disks
                        .into_iter()
                        .map(|d| Disk {
                            name: d.device_id,
                            size_bytes: d.size.unwrap_or(0),
                            free_bytes: d.free_space.unwrap_or(0),
                        })
                        .collect(),
                })
            }
            Section::Patches => {
                let fixes: Vec<QuickFix> = con.query()?;
                InventoryPayload::Patches(
                    fixes
                        .into_iter()
                        .filter_map(|f| {
                            Some(PatchItem {
                                kb: f.hot_fix_id?,
                                installed_on: f.installed_on,
                            })
                        })
                        .collect(),
                )
            }
            // 這兩個區段不經 WMI：Security 在上面另外處理，Registry 走 collect_registry
            Section::Security | Section::Registry => {
                anyhow::bail!("section {} is not collected via WMI", section.as_str())
            }
            Section::Services => {
                let services: Vec<Service> = con.query()?;
                InventoryPayload::Services(
                    services
                        .into_iter()
                        .filter_map(|s| {
                            Some(ServiceItem {
                                name: s.name?,
                                display_name: s.display_name,
                                start_mode: s.start_mode.unwrap_or_default(),
                                state: s.state.unwrap_or_default(),
                                binary_path: s.path_name,
                            })
                        })
                        .collect(),
                )
            }
            Section::Software => unreachable!("handled above"),
        })
    }
}

/// 月更新小版號，例如 22631.4317 的 4317；讀不到就不報。
fn read_ubr() -> Option<u32> {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        .and_then(|k| k.get_value::<u32, _>("UBR"))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 非必要的查詢（Product、BIOS、網卡、OS）失敗時當成沒有資料，不讓整個呼叫失敗。
    #[test]
    fn optional_query_failure_is_empty() {
        let ok: Result<Vec<u8>, String> = Ok(vec![1, 2]);
        assert_eq!(optional("x", ok), vec![1, 2]);
        let err: Result<Vec<u8>, String> = Err("WBEM_E_FAILED".into());
        assert!(optional("x", err).is_empty());
    }

    /// 服務模式只記 INFO 以上：失敗要以 warning 記錄才看得到，但同一個查詢的同一個錯誤
    /// 只記一次（heartbeat 每分鐘都查，不能洗版事件記錄）；錯誤改變或恢復後再次失敗才再記
    #[test]
    fn same_failure_is_reported_once() {
        assert!(first_report("q-test", "E1"));
        assert!(!first_report("q-test", "E1"));
        assert!(first_report("q-test", "E2"), "錯誤改變");
        assert!(first_report("q-other", "E2"), "不同查詢各自計算");
        recovered("q-test");
        assert!(first_report("q-test", "E2"), "恢復後再次失敗");
    }
}
