//! 送出前的字串清理：伺服器拒絕 NUL 與超長字串（見 protocol::validate_strings）。

use protocol::{InventoryPayload, MAX_ITEMS, MAX_STRING_LEN};

pub fn clean(s: &str) -> String {
    let no_nul: String = s.chars().filter(|c| *c != '\0').collect();
    no_nul.trim().chars().take(MAX_STRING_LEN).collect()
}

fn fix(s: &mut String) {
    *s = clean(s);
}

fn fix_opt(o: &mut Option<String>) {
    if let Some(s) = o {
        *s = clean(s);
        if s.is_empty() {
            *o = None;
        }
    }
}

pub fn sanitize(p: &mut InventoryPayload) {
    match p {
        InventoryPayload::Basic(b) => {
            fix(&mut b.hostname);
            fix_opt(&mut b.domain);
            fix(&mut b.os_caption);
            fix(&mut b.os_build);
        }
        InventoryPayload::Hardware(h) => {
            fix_opt(&mut h.manufacturer);
            fix_opt(&mut h.model);
            fix_opt(&mut h.cpu);
            h.disks.truncate(MAX_ITEMS);
            h.disks.iter_mut().for_each(|d| fix(&mut d.name));
        }
        InventoryPayload::Software(v) => {
            v.truncate(MAX_ITEMS);
            for s in v {
                fix(&mut s.name);
                fix_opt(&mut s.version);
                fix_opt(&mut s.publisher);
                fix_opt(&mut s.install_date);
            }
        }
        InventoryPayload::Patches(v) => {
            v.truncate(MAX_ITEMS);
            for p in v {
                fix(&mut p.kb);
                fix_opt(&mut p.installed_on);
            }
        }
        InventoryPayload::Services(v) => {
            v.truncate(MAX_ITEMS);
            for s in v {
                fix(&mut s.name);
                fix_opt(&mut s.display_name);
                fix(&mut s.start_mode);
                fix(&mut s.state);
                fix_opt(&mut s.binary_path);
            }
        }
        InventoryPayload::Security(s) => {
            fn fix_probe<T>(p: &mut protocol::Probe<T>, f: impl FnOnce(&mut T)) {
                match p {
                    protocol::Probe::Ok(v) => f(v),
                    protocol::Probe::Error(e) => fix(e),
                }
            }
            fix_probe(&mut s.firewall, |_| {});
            fix_probe(&mut s.defender, |_| {});
            fix_probe(&mut s.password, |_| {});
            fix_probe(&mut s.bitlocker, |v| {
                v.truncate(MAX_ITEMS);
                v.iter_mut().for_each(|d| fix(&mut d.drive));
            });
            fix_probe(&mut s.admins, |v| {
                v.truncate(MAX_ITEMS);
                for a in v {
                    fix(&mut a.name);
                    fix(&mut a.sid);
                }
            });
        }
        InventoryPayload::Registry(v) => {
            v.truncate(protocol::MAX_REGISTRY_VALUES);
            for r in v {
                fix(&mut r.path);
                // 值名稱可以是空字串（機碼的預設值），只移除 NUL 與截斷，不去頭尾空白
                r.name = r
                    .name
                    .chars()
                    .filter(|c| *c != '\0')
                    .take(protocol::MAX_STRING_LEN)
                    .collect();
                r.data = r
                    .data
                    .chars()
                    .filter(|c| *c != '\0')
                    .take(protocol::MAX_STRING_LEN)
                    .collect();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::{Arch, InventoryPayload, MAX_ITEMS, MAX_STRING_LEN, SoftwareItem};

    fn sw(name: &str) -> SoftwareItem {
        SoftwareItem {
            name: name.into(),
            version: Some("  ".into()),
            publisher: Some("Pub\0".into()),
            install_date: None,
            arch: Arch::X64,
        }
    }

    #[test]
    fn clean_strips_nul_and_trims() {
        assert_eq!(clean("  a\0b \0"), "ab");
    }

    #[test]
    fn clean_truncates_by_chars() {
        let s = "軟".repeat(MAX_STRING_LEN + 5);
        assert_eq!(clean(&s).chars().count(), MAX_STRING_LEN);
    }

    #[test]
    fn sanitize_makes_payload_valid() {
        let mut p = InventoryPayload::Software(
            (0..MAX_ITEMS + 3)
                .map(|i| sw(&format!("App\0{i}")))
                .collect(),
        );
        sanitize(&mut p);
        let InventoryPayload::Software(v) = &p else {
            unreachable!()
        };
        assert_eq!(v.len(), MAX_ITEMS);
        assert_eq!(v[0].name, "App0");
        assert_eq!(v[0].version, None, "空白字串變 None");
        assert_eq!(v[0].publisher.as_deref(), Some("Pub"));
        assert_eq!(p.validate(), Ok(()));
    }
}
