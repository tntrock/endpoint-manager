//! 送出前的字串清理：伺服器拒絕 NUL 與超長字串（見 protocol::validate_strings）。

use protocol::{InventoryPayload, MAX_ITEMS, MAX_STRING_LEN};

/// 每張網卡的位址、閘道、DNS 各自上限：256 張 × (1 + 16 × 3) 不會超過 MAX_ITEMS
const MAX_PER_NIC: usize = 16;

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
        InventoryPayload::Accounts(a) => {
            // 三個清單合計不超過 MAX_ITEMS（伺服器合計檢查），依序保留
            a.users.truncate(MAX_ITEMS);
            a.privileged.truncate(MAX_ITEMS - a.users.len());
            a.sudoers_unparsed
                .truncate(MAX_ITEMS - a.users.len() - a.privileged.len());
            for u in &mut a.users {
                fix(&mut u.name);
                fix(&mut u.shell);
            }
            for p in &mut a.privileged {
                fix(&mut p.principal);
                fix(&mut p.source);
            }
            a.sudoers_unparsed.iter_mut().for_each(fix);
        }
        InventoryPayload::Containers(c) => {
            c.containers.truncate(protocol::MAX_CONTAINERS);
            for r in &mut c.runtimes {
                fix(&mut r.kind);
                fix_opt(&mut r.version);
                fix_opt(&mut r.error);
            }
            for x in &mut c.containers {
                for s in [
                    &mut x.runtime,
                    &mut x.id,
                    &mut x.name,
                    &mut x.image,
                    &mut x.state,
                ] {
                    fix(s);
                }
                for o in [
                    &mut x.image_id,
                    &mut x.health,
                    &mut x.restart_policy,
                    &mut x.owner,
                ] {
                    fix_opt(o);
                }
                x.ports.iter_mut().for_each(fix);
                x.host_mounts.iter_mut().for_each(fix);
                if let Some(k) = &mut x.k8s {
                    fix(&mut k.namespace);
                    fix(&mut k.pod);
                }
            }
        }
        InventoryPayload::Network(n) => {
            n.interfaces.truncate(protocol::MAX_INTERFACES);
            for i in &mut n.interfaces {
                fix(&mut i.name);
                fix(&mut i.kind);
                fix_opt(&mut i.description);
                fix_opt(&mut i.mac);
                fix_opt(&mut i.ssid);
                // 每張網卡的清單各自限制在合理範圍，合計才不會超過 MAX_ITEMS
                for v in [&mut i.addresses, &mut i.gateways, &mut i.dns] {
                    v.truncate(MAX_PER_NIC);
                    v.iter_mut().for_each(fix);
                    v.retain(|s| !s.is_empty());
                }
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
    fn containers_are_cleaned_and_capped() {
        use protocol::{ContainerItem, ContainersInfo, MAX_CONTAINERS, RuntimeInfo};
        let item = |i: usize| ContainerItem {
            runtime: "docker".into(),
            id: format!("id{i}"),
            name: format!(" name\0{i} "),
            image: "x".repeat(MAX_STRING_LEN + 5),
            image_id: Some("  ".into()),
            state: "running".into(),
            health: Some("healthy".into()),
            created_at: None,
            started_at: None,
            finished_at: None,
            restart_policy: Some("".into()),
            privileged: None,
            host_network: None,
            ports: vec!["p\0".into()],
            host_mounts: vec![" /srv ".into()],
            owner: Some("alice".into()),
            k8s: None,
        };
        let mut p = InventoryPayload::Containers(ContainersInfo {
            runtimes: vec![RuntimeInfo {
                kind: " docker ".into(),
                version: Some("".into()),
                error: Some("e\0rr".into()),
            }],
            containers: (0..MAX_CONTAINERS + 2).map(item).collect(),
            truncated: true,
        });
        sanitize(&mut p);
        assert_eq!(p.validate(), Ok(()));
        let InventoryPayload::Containers(c) = &p else {
            unreachable!()
        };
        assert_eq!(c.containers.len(), MAX_CONTAINERS);
        let r = &c.runtimes[0];
        assert_eq!(
            (r.kind.as_str(), r.version.as_deref(), r.error.as_deref()),
            ("docker", None, Some("err"))
        );
        let x = &c.containers[0];
        assert_eq!(x.name, "name0");
        assert_eq!(x.image.chars().count(), MAX_STRING_LEN);
        assert_eq!(
            (x.image_id.as_deref(), x.restart_policy.as_deref()),
            (None, None)
        );
        assert_eq!(
            (x.ports[0].as_str(), x.host_mounts[0].as_str()),
            ("p", "/srv")
        );
    }

    #[test]
    fn network_is_cleaned_and_capped() {
        use protocol::{MAX_INTERFACES, NetInterface, NetworkInfo};
        let nic = |i: usize| NetInterface {
            name: format!(" eth\0{i} "),
            description: Some("  ".into()),
            kind: "ethernet".into(),
            up: true,
            mac: Some("AA:BB".into()),
            addresses: (0..100).map(|n| format!("10.0.0.{n}/24")).collect(),
            gateways: vec![" ".into(), "10.0.0.1".into()],
            dns: vec![],
            ssid: Some("x".repeat(MAX_STRING_LEN + 1)),
        };
        let mut p = InventoryPayload::Network(NetworkInfo {
            interfaces: (0..MAX_INTERFACES + 3).map(nic).collect(),
        });
        sanitize(&mut p);
        assert_eq!(p.validate(), Ok(()));
        let InventoryPayload::Network(n) = &p else {
            unreachable!()
        };
        assert_eq!(n.interfaces.len(), MAX_INTERFACES);
        let i = &n.interfaces[0];
        assert_eq!(i.name, "eth0");
        assert_eq!(i.description, None);
        assert_eq!(i.addresses.len(), MAX_PER_NIC);
        assert_eq!(i.gateways, ["10.0.0.1"]);
        assert_eq!(i.ssid.as_ref().unwrap().chars().count(), MAX_STRING_LEN);
    }

    #[test]
    fn accounts_total_is_capped() {
        use protocol::{AccountsInfo, LocalUser, PrincipalKind, PrivilegeEntry};
        let n = MAX_ITEMS;
        let mut p = InventoryPayload::Accounts(AccountsInfo {
            users: (0..n)
                .map(|i| LocalUser {
                    name: format!("u{i}"),
                    uid: 1000,
                    shell: "/bin/sh".into(),
                    locked: None,
                    password_changed: None,
                })
                .collect(),
            system_user_count: 0,
            privileged: (0..n)
                .map(|i| PrivilegeEntry {
                    principal: format!("p{i}"),
                    kind: PrincipalKind::User,
                    source: "/etc/sudoers".into(),
                })
                .collect(),
            sudoers_unparsed: (0..n).map(|i| format!("l{i}")).collect(),
        });
        sanitize(&mut p);
        let InventoryPayload::Accounts(a) = &p else {
            unreachable!()
        };
        assert_eq!(
            a.users.len() + a.privileged.len() + a.sudoers_unparsed.len(),
            MAX_ITEMS
        );
        assert_eq!(p.validate(), Ok(()));
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
