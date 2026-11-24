//! 把區段內容轉成 key/value，再比對新舊差異。
//!
//! | 區段     | key                        | value                         | 刻意排除     |
//! |----------|----------------------------|-------------------------------|--------------|
//! | basic    | 欄位名                     | 欄位值                        | —            |
//! | hardware | 欄位名、`disk:<name>`      | 值；磁碟只取 size_bytes       | free_bytes   |
//! | software | `name\|arch\|publisher`    | 同 key 所有版本排序後以 `, ` 串接 | install_date |
//! | patches  | kb                         | installed_on                  | —            |
//! | services | name                       | `start_mode\|binary_path`     | state        |
//! | security | `firewall.*`、`bitlocker:<磁碟>`、`defender.*`、`password.*`、`admin:<名稱>`；收集失敗時為項目名 | 值；失敗時 `error: <訊息>` | 病毒碼時間只到日 |
//! | registry | `<路徑>\<名稱>`             | `state\|kind\|data`            | —            |
//! | accounts | `user\|<名稱>`、`count\|system_users`、`priv\|<主體>\|<user/group>\|<來源>`、`unparsed\|<行>` | user：`uid\|shell\|locked\|password_changed`；數量；其餘為空 | 系統帳號只記數量 |

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

/// 同一個 key 出現多次時（重複的軟體、KB、磁碟名稱），值排序後以 `, ` 串接，
/// 結果與項目順序無關。
pub fn items_of(p: &InventoryPayload) -> BTreeMap<String, String> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    match p {
        InventoryPayload::Basic(b) => {
            pairs.push(("hostname".into(), b.hostname.clone()));
            pairs.push(("domain".into(), opt(&b.domain)));
            pairs.push(("is_domain_joined".into(), b.is_domain_joined.to_string()));
            pairs.push(("os_caption".into(), b.os_caption.clone()));
            pairs.push(("os_build".into(), b.os_build.clone()));
        }
        InventoryPayload::Hardware(h) => {
            pairs.push(("manufacturer".into(), opt(&h.manufacturer)));
            pairs.push(("model".into(), opt(&h.model)));
            pairs.push(("cpu".into(), opt(&h.cpu)));
            pairs.push(("ram_mb".into(), h.ram_mb.to_string()));
            for d in &h.disks {
                pairs.push((format!("disk:{}", d.name), d.size_bytes.to_string()));
            }
        }
        InventoryPayload::Software(v) => {
            for s in v {
                let key = format!("{}|{}|{}", s.name, s.arch.as_str(), opt(&s.publisher));
                pairs.push((key, opt(&s.version)));
            }
        }
        InventoryPayload::Patches(v) => {
            for p in v {
                pairs.push((p.kb.clone(), opt(&p.installed_on)));
            }
        }
        InventoryPayload::Services(v) => {
            for s in v {
                pairs.push((
                    s.name.clone(),
                    format!("{}|{}", s.start_mode, opt(&s.binary_path)),
                ));
            }
        }
        InventoryPayload::Security(s) => {
            use protocol::Probe;
            fn probe<T>(
                pairs: &mut Vec<(String, String)>,
                name: &str,
                p: &Probe<T>,
                f: impl FnOnce(&T, &mut Vec<(String, String)>),
            ) {
                match p {
                    Probe::Ok(v) => f(v, pairs),
                    Probe::Error(e) => pairs.push((name.into(), format!("error: {e}"))),
                }
            }
            probe(&mut pairs, "firewall", &s.firewall, |f, out| {
                out.push(("firewall.domain".into(), f.domain.to_string()));
                out.push(("firewall.private".into(), f.private.to_string()));
                out.push(("firewall.public".into(), f.public.to_string()));
            });
            probe(&mut pairs, "bitlocker", &s.bitlocker, |v, out| {
                for d in v {
                    out.push((format!("bitlocker:{}", d.drive), d.protected.to_string()));
                }
            });
            probe(&mut pairs, "defender", &s.defender, |d, out| {
                out.push(("defender.active".into(), d.active.to_string()));
                out.push(("defender.realtime".into(), d.realtime.to_string()));
                out.push(("defender.tamper".into(), d.tamper.to_string()));
                // 只記到日：病毒碼每天更新多次，不要每次都寫一筆變更
                let day = d
                    .signature_updated
                    .map(|t| protocol::timefmt::format_date(t.date()))
                    .unwrap_or_default();
                out.push(("defender.signature_updated".into(), day));
            });
            probe(&mut pairs, "password", &s.password, |p, out| {
                out.push(("password.min_length".into(), p.min_length.to_string()));
                out.push(("password.max_age_days".into(), p.max_age_days.to_string()));
                out.push((
                    "password.lockout_threshold".into(),
                    p.lockout_threshold.to_string(),
                ));
            });
            probe(&mut pairs, "admins", &s.admins, |v, out| {
                for a in v {
                    out.push((format!("admin:{}", a.name), a.sid.clone()));
                }
            });
        }
        InventoryPayload::Registry(v) => {
            for r in v {
                let state = serde_json::to_value(r.state).expect("serializable");
                let kind = serde_json::to_value(r.kind).expect("serializable");
                pairs.push((
                    format!("{}\\{}", r.path, r.name),
                    format!(
                        "{}|{}|{}",
                        state.as_str().unwrap_or(""),
                        kind.as_str().unwrap_or(""),
                        r.data
                    ),
                ));
            }
        }
        InventoryPayload::Network(n) => {
            // 網卡的種類、啟用狀態、位址與閘道；DNS 不記（VPN 連線時常常整組換掉）
            for i in &n.interfaces {
                pairs.push((
                    format!("nic|{}", i.name),
                    format!(
                        "{}|{}|{}|{}",
                        i.kind,
                        if i.up { "up" } else { "down" },
                        i.addresses.join(","),
                        i.gateways.join(",")
                    ),
                ));
            }
        }
        InventoryPayload::Exposure(e) => {
            // 監聽的連接埠新增、移除；位址改變也記（例如資料庫從只綁內部網卡改成所有介面）
            for l in &e.listening {
                pairs.push((
                    format!("{}/{}|{}", l.port, l.proto, opt(&l.process)),
                    l.addr.clone(),
                ));
            }
            if let Some(f) = &e.firewall_allow_all {
                for r in f {
                    pairs.push((format!("firewall:{r}"), "allow_all".into()));
                }
            }
            if let Some(s) = &e.sshd {
                pairs.push(("sshd.permitrootlogin".into(), s.permit_root_login.clone()));
                pairs.push((
                    "sshd.passwordauthentication".into(),
                    s.password_authentication.to_string(),
                ));
                pairs.push((
                    "sshd.permitemptypasswords".into(),
                    s.permit_empty_passwords.to_string(),
                ));
            }
            if let Some(r) = &e.rdp {
                pairs.push(("rdp.enabled".into(), r.enabled.to_string()));
                for u in &r.users {
                    pairs.push((format!("rdp.user:{}", u.name), u.sid.clone()));
                }
            }
        }
        InventoryPayload::Permissions(p) => {
            // 權限過寬的項目出現、消失，給了誰改變
            for x in &p.items {
                pairs.push((format!("{}|{}", x.kind, x.path), x.granted_to.join(",")));
            }
        }
        InventoryPayload::Shares(s) => {
            // 共用的新增、移除與權限改變
            for x in &s.shares {
                pairs.push((
                    format!("{}|{}", x.kind, x.name),
                    format!(
                        "{}|anonymous={}|all_users={}{}",
                        x.path,
                        x.anonymous.as_str(),
                        x.all_users.as_str(),
                        if x.no_root_squash {
                            "|no_root_squash"
                        } else {
                            ""
                        }
                    ),
                ));
            }
        }
        InventoryPayload::Vms(v) => {
            // 只記虛擬機的新增、移除與改名；開關機不記
            for x in &v.vms {
                pairs.push((format!("{}|{}|{}", x.name, x.platform, x.id), String::new()));
            }
        }
        InventoryPayload::Containers(c) => {
            // 只記容器的新增、移除與映像改變；狀態（執行中、停止）不記，排程工作會一直起停
            for x in &c.containers {
                // Kubernetes 的 Pod 名稱每次部署都會換：以「Namespace／容器名稱」為鍵，
                // 才不會每次滾動更新都記一堆新增與移除
                let name = match &x.k8s {
                    Some(k) => format!("{}/{}", k.namespace, x.name),
                    None => x.name.clone(),
                };
                pairs.push((
                    format!(
                        "{}|{}|{}",
                        name,
                        x.runtime,
                        x.owner.as_deref().unwrap_or("")
                    ),
                    x.image.clone(),
                ));
            }
        }
        InventoryPayload::Accounts(a) => {
            for u in &a.users {
                let locked = u.locked.map(|l| l.to_string()).unwrap_or_default();
                let changed = u
                    .password_changed
                    .map(|d| d.to_string())
                    .unwrap_or_default();
                // 旗標只在成立時附加，舊資料的值不變；最後登入時間不記（每次登入都會變）
                let mut value = format!("{}|{}|{}|{}", u.uid, u.shell, locked, changed);
                for (on, label) in [
                    (u.disabled, "disabled"),
                    (u.password_never_expires, "never_expires"),
                    (u.no_password == Some(true), "no_password"),
                ] {
                    if on {
                        value.push('|');
                        value.push_str(label);
                    }
                }
                pairs.push((format!("user|{}", u.name), value));
            }
            // 系統帳號只記數量（不列出），數量變動也算一筆變更
            pairs.push(("count|system_users".into(), a.system_user_count.to_string()));
            for p in &a.privileged {
                let kind = serde_json::to_value(p.kind).expect("serializable");
                pairs.push((
                    format!(
                        "priv|{}|{}|{}",
                        p.principal,
                        kind.as_str().unwrap_or(""),
                        p.source
                    ),
                    if p.nopasswd_all {
                        "nopasswd_all".into()
                    } else {
                        String::new()
                    },
                ));
            }
            if let Some(on) = a.autologon_password {
                pairs.push(("autologon_password".into(), on.to_string()));
            }
            for l in &a.sudoers_unparsed {
                pairs.push((format!("unparsed|{l}"), String::new()));
            }
        }
    }
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (k, v) in pairs {
        grouped.entry(k).or_default().push(v);
    }
    grouped
        .into_iter()
        .map(|(k, mut vs)| {
            vs.sort();
            (k, vs.join(", "))
        })
        .collect()
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

    #[test]
    fn security_items_flatten_probes() {
        let p = InventoryPayload::Security(protocol::SecurityInfo {
            firewall: protocol::Probe::Ok(protocol::FirewallInfo {
                domain: true,
                private: false,
                public: true,
            }),
            bitlocker: protocol::Probe::Error("x".into()),
            defender: protocol::Probe::Ok(protocol::DefenderInfo {
                active: true,
                realtime: false,
                tamper: true,
                signature_updated: None,
            }),
            password: protocol::Probe::Ok(protocol::PasswordPolicy {
                min_length: 8,
                max_age_days: 0,
                lockout_threshold: 0,
            }),
            admins: protocol::Probe::Ok(vec![protocol::AccountInfo {
                name: "PC\\A".into(),
                sid: "S-1".into(),
            }]),
        });
        let m = items_of(&p);
        assert_eq!(m["firewall.private"], "false");
        assert_eq!(m["bitlocker"], "error: x");
        assert_eq!(m["defender.realtime"], "false");
        assert_eq!(m["password.min_length"], "8");
        assert_eq!(m["admin:PC\\A"], "S-1");
        let r = InventoryPayload::Registry(vec![protocol::RegistryValue {
            path: "HKLM\\X".into(),
            name: "Y".into(),
            state: protocol::RegState::Present,
            kind: protocol::RegKind::Dword,
            data: "1".into(),
        }]);
        assert_eq!(items_of(&r)["HKLM\\X\\Y"], "present|dword|1");
    }

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
    fn duplicate_patches_and_disks_are_stable() {
        use protocol::{Disk, HardwareInfo, PatchItem};
        let kb = |on: Option<&str>| PatchItem {
            kb: "KB500".into(),
            installed_on: on.map(Into::into),
        };
        let a = InventoryPayload::Patches(vec![kb(Some("1/1/2026")), kb(None)]);
        let b = InventoryPayload::Patches(vec![kb(None), kb(Some("1/1/2026"))]);
        assert!(diff(&items_of(&a), &items_of(&b)).is_empty());

        let disk = |size| Disk {
            name: "SSD".into(),
            size_bytes: size,
            free_bytes: 0,
        };
        let hw = |disks| {
            InventoryPayload::Hardware(HardwareInfo {
                manufacturer: None,
                model: None,
                cpu: None,
                ram_mb: 1,
                disks,
            })
        };
        let a = hw(vec![disk(1), disk(2)]);
        let b = hw(vec![disk(2), disk(1)]);
        assert!(diff(&items_of(&a), &items_of(&b)).is_empty());
        assert_eq!(items_of(&a)["disk:SSD"], "1, 2");
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

    #[test]
    fn accounts_items_are_keyed() {
        use protocol::{AccountsInfo, LocalUser, PrincipalKind, PrivilegeEntry};
        let p = InventoryPayload::Accounts(AccountsInfo {
            users: vec![LocalUser {
                name: "alice".into(),
                uid: 1000,
                shell: "/bin/bash".into(),
                locked: Some(false),
                password_changed: protocol::timefmt::ymd(2026, 1, 2),
                ..Default::default()
            }],
            system_user_count: 30,
            privileged: vec![PrivilegeEntry {
                principal: "admin".into(),
                kind: PrincipalKind::Group,
                source: "/etc/sudoers".into(),
                ..Default::default()
            }],
            sudoers_unparsed: vec!["Defaults !x".into()],
            ..Default::default()
        });
        let m = items_of(&p);
        assert_eq!(m["user|alice"], "1000|/bin/bash|false|2026-01-02");
        assert_eq!(m["priv|admin|group|/etc/sudoers"], "");
        assert_eq!(m["unparsed|Defaults !x"], "");
        assert_eq!(m["count|system_users"], "30");
        // 旗標只在成立時附加；最後登入時間不算變更
        let p = InventoryPayload::Accounts(AccountsInfo {
            users: vec![LocalUser {
                name: "Guest".into(),
                uid: 501,
                disabled: true,
                password_never_expires: true,
                no_password: Some(true),
                last_logon: Some(time::OffsetDateTime::UNIX_EPOCH),
                ..Default::default()
            }],
            privileged: vec![PrivilegeEntry {
                principal: "ops".into(),
                kind: PrincipalKind::Group,
                source: "sudoers:x".into(),
                nopasswd_all: true,
            }],
            autologon_password: Some(false),
            ..Default::default()
        });
        let m = items_of(&p);
        assert_eq!(m["user|Guest"], "501||||disabled|never_expires|no_password");
        assert_eq!(m["priv|ops|group|sudoers:x"], "nopasswd_all");
        assert_eq!(m["autologon_password"], "false");
    }
}
