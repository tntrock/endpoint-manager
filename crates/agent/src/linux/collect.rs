//! Linux 收集器：把各區段的收集函式接到 `Collector`。

use anyhow::bail;
use protocol::{InventoryPayload, OsFamily, Section};

use crate::collector::{Collector, Heartbeat, Identity};

pub struct LinuxCollector;

impl Collector for LinuxCollector {
    fn identity(&self) -> anyhow::Result<Identity> {
        super::system::identity()
    }

    fn heartbeat(&self) -> anyhow::Result<Heartbeat> {
        super::system::heartbeat()
    }

    fn sections(&self) -> &'static [Section] {
        &Section::LINUX
    }

    fn os_family(&self) -> Option<OsFamily> {
        Some(OsFamily::Linux)
    }

    /// 「不支援」的說明以 Err 回傳：Agent 把它放進 section_errors、不上傳該區段，後台當說明顯示。
    fn collect(&self, section: Section) -> anyhow::Result<InventoryPayload> {
        Ok(match section {
            Section::Basic => InventoryPayload::Basic(super::system::basic()),
            Section::Hardware => InventoryPayload::Hardware(super::system::hardware()?),
            Section::Software => match super::packages::collect()? {
                (items, None) => InventoryPayload::Software(items),
                (_, Some(note)) => bail!(note),
            },
            Section::Services => match super::services::collect()? {
                (items, None) => InventoryPayload::Services(items),
                (_, Some(note)) => bail!(note),
            },
            Section::Accounts => InventoryPayload::Accounts(super::accounts::collect()),
            Section::Patches | Section::Security | Section::Registry => {
                bail!("Linux 不收集這個區段")
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_collector_declares_linux() {
        let c = LinuxCollector;
        assert_eq!(c.sections(), &Section::LINUX);
        assert_eq!(c.os_family(), Some(OsFamily::Linux));
        assert!(c.collect(Section::Registry).is_err());
        assert!(c.collect(Section::Patches).is_err());
        assert!(matches!(
            c.collect(Section::Accounts),
            Ok(InventoryPayload::Accounts(_))
        ));
    }
}
