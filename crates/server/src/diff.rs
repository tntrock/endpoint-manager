//! 把區段內容轉成 key/value，再比對新舊差異。
//!
//! | 區段     | key                        | value                         | 刻意排除     |
//! |----------|----------------------------|-------------------------------|--------------|
//! | basic    | 欄位名                     | 欄位值                        | —            |
//! | hardware | 欄位名、`disk:<name>`      | 值；磁碟只取 size_bytes       | free_bytes   |
//! | software | `name\|arch\|publisher`    | 同 key 所有版本排序後以 `, ` 串接 | install_date |
//! | patches  | kb                         | installed_on                  | —            |
//! | services | name                       | `start_mode\|binary_path`     | state        |

use std::collections::BTreeMap;

use protocol::InventoryPayload;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Removed,
    Updated,
}

impl ChangeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ChangeKind::Added => "added",
            ChangeKind::Removed => "removed",
            ChangeKind::Updated => "updated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub kind: ChangeKind,
    pub key: String,
    pub old: Option<String>,
    pub new: Option<String>,
}

fn opt(s: &Option<String>) -> String {
    s.clone().unwrap_or_default()
}

pub fn items_of(p: &InventoryPayload) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    match p {
        InventoryPayload::Basic(b) => {
            m.insert("hostname".into(), b.hostname.clone());
            m.insert("domain".into(), opt(&b.domain));
            m.insert("is_domain_joined".into(), b.is_domain_joined.to_string());
            m.insert("os_caption".into(), b.os_caption.clone());
            m.insert("os_build".into(), b.os_build.clone());
        }
        InventoryPayload::Hardware(h) => {
            m.insert("manufacturer".into(), opt(&h.manufacturer));
            m.insert("model".into(), opt(&h.model));
            m.insert("cpu".into(), opt(&h.cpu));
            m.insert("ram_mb".into(), h.ram_mb.to_string());
            for d in &h.disks {
                m.insert(format!("disk:{}", d.name), d.size_bytes.to_string());
            }
        }
        InventoryPayload::Software(v) => {
            let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for s in v {
                let key = format!("{}|{}|{}", s.name, s.arch.as_str(), opt(&s.publisher));
                grouped.entry(key).or_default().push(opt(&s.version));
            }
            for (k, mut versions) in grouped {
                versions.sort();
                m.insert(k, versions.join(", "));
            }
        }
        InventoryPayload::Patches(v) => {
            for p in v {
                m.insert(p.kb.clone(), opt(&p.installed_on));
            }
        }
        InventoryPayload::Services(v) => {
            for s in v {
                m.insert(
                    s.name.clone(),
                    format!("{}|{}", s.start_mode, opt(&s.binary_path)),
                );
            }
        }
    }
    m
}

pub fn diff(old: &BTreeMap<String, String>, new: &BTreeMap<String, String>) -> Vec<Change> {
    let mut out = Vec::new();
    for (k, nv) in new {
        match old.get(k) {
            None => out.push(Change {
                kind: ChangeKind::Added,
                key: k.clone(),
                old: None,
                new: Some(nv.clone()),
            }),
            Some(ov) if ov != nv => out.push(Change {
                kind: ChangeKind::Updated,
                key: k.clone(),
                old: Some(ov.clone()),
                new: Some(nv.clone()),
            }),
            _ => {}
        }
    }
    for (k, ov) in old {
        if !new.contains_key(k) {
            out.push(Change {
                kind: ChangeKind::Removed,
                key: k.clone(),
                old: Some(ov.clone()),
                new: None,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::{Arch, InventoryPayload, SoftwareItem};

    fn sw(name: &str, ver: &str) -> SoftwareItem {
        SoftwareItem {
            name: name.into(),
            version: Some(ver.into()),
            publisher: Some("P".into()),
            install_date: None,
            arch: Arch::X64,
        }
    }

    #[test]
    fn detects_added_removed_updated() {
        let old = items_of(&InventoryPayload::Software(vec![
            sw("A", "1"),
            sw("B", "1"),
        ]));
        let new = items_of(&InventoryPayload::Software(vec![
            sw("A", "2"),
            sw("C", "1"),
        ]));
        let d = diff(&old, &new);
        assert_eq!(d.len(), 3);
        assert!(d.contains(&Change {
            kind: ChangeKind::Updated,
            key: "A|x64|P".into(),
            old: Some("1".into()),
            new: Some("2".into())
        }));
        assert!(d.contains(&Change {
            kind: ChangeKind::Removed,
            key: "B|x64|P".into(),
            old: Some("1".into()),
            new: None
        }));
        assert!(d.contains(&Change {
            kind: ChangeKind::Added,
            key: "C|x64|P".into(),
            old: None,
            new: Some("1".into())
        }));
    }

    #[test]
    fn duplicate_software_entries_are_stable() {
        let a = InventoryPayload::Software(vec![sw("Java", "8"), sw("Java", "17")]);
        let b = InventoryPayload::Software(vec![sw("Java", "17"), sw("Java", "8")]);
        assert_eq!(items_of(&a)["Java|x64|P"], "17, 8");
        assert!(diff(&items_of(&a), &items_of(&b)).is_empty());
    }

    #[test]
    fn service_state_change_is_not_a_change() {
        let svc = |state: &str| protocol::ServiceItem {
            name: "Spooler".into(),
            display_name: None,
            start_mode: "Auto".into(),
            state: state.into(),
            binary_path: Some("spoolsv.exe".into()),
        };
        let a = items_of(&InventoryPayload::Services(vec![svc("Running")]));
        let b = items_of(&InventoryPayload::Services(vec![svc("Stopped")]));
        assert!(diff(&a, &b).is_empty());
    }
}
