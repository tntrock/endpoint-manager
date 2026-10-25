//! systemctl 輸出的解析與合併。

use protocol::ServiceItem;
use std::collections::BTreeMap;

/// 合併 `list-units`（UNIT LOAD ACTIVE SUB DESCRIPTION…）與 `list-unit-files`（UNIT STATE [PRESET]）。
/// 範本 unit（`foo@.service`）不列。
pub fn parse(units: &str, unit_files: &str) -> Vec<ServiceItem> {
    let mut map: BTreeMap<String, ServiceItem> = BTreeMap::new();
    for l in units.lines() {
        let mut it = l.split_whitespace();
        let (Some(name), Some(_load), Some(active), Some(sub)) =
            (it.next(), it.next(), it.next(), it.next())
        else {
            continue;
        };
        let desc = it.collect::<Vec<_>>().join(" ");
        map.insert(
            name.to_string(),
            ServiceItem {
                name: name.to_string(),
                display_name: (!desc.is_empty()).then_some(desc),
                start_mode: "unknown".into(),
                state: format!("{active}/{sub}"),
                binary_path: None,
            },
        );
    }
    for l in unit_files.lines() {
        let mut it = l.split_whitespace();
        let (Some(name), Some(st)) = (it.next(), it.next()) else {
            continue;
        };
        map.entry(name.to_string())
            .or_insert_with(|| ServiceItem {
                name: name.to_string(),
                display_name: None,
                start_mode: String::new(),
                state: "inactive/dead".into(),
                binary_path: None,
            })
            .start_mode = st.to_string();
    }
    map.into_values()
        .filter(|s| !s.name.contains("@.service"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn services_merge() {
        let units = "ssh.service loaded active running OpenBSD Secure Shell server\n\
                     getty@.service loaded inactive dead Getty\n";
        let files = "ssh.service enabled enabled\nfoo.service disabled enabled\ngetty@.service enabled enabled\n";
        let v = parse(units, files);
        assert_eq!(v.len(), 2);
        let foo = &v[0];
        assert_eq!(foo.name, "foo.service");
        assert_eq!(foo.state, "inactive/dead");
        assert_eq!(foo.start_mode, "disabled");
        let ssh = &v[1];
        assert_eq!(ssh.start_mode, "enabled");
        assert_eq!(ssh.state, "active/running");
        assert_eq!(
            ssh.display_name.as_deref(),
            Some("OpenBSD Secure Shell server")
        );
    }
}
