//! 收集來源的抽象：Windows 上是 WMI + 登錄檔，測試用假資料。所有方法都是阻塞呼叫。

use chrono::{DateTime, Utc};
use protocol::{InventoryPayload, Section};

#[derive(Debug, Clone)]
pub struct Identity {
    pub hostname: String,
    pub smbios_uuid: Option<String>,
    pub bios_serial: Option<String>,
    pub mac_addresses: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Heartbeat {
    pub boot_time: DateTime<Utc>,
    pub logged_on_user: Option<String>,
    pub ip_addresses: Vec<String>,
}

pub trait Collector: Send + Sync + 'static {
    fn identity(&self) -> anyhow::Result<Identity>;
    fn heartbeat(&self) -> anyhow::Result<Heartbeat>;
    fn collect(&self, section: Section) -> anyhow::Result<InventoryPayload>;
}
