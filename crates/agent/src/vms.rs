//! vms 區段的純解析：libvirt（virsh）、Proxmox（qm／pct）的指令輸出與 Hyper-V 的狀態碼。
//! 不碰外部指令，兩個平台都能測試。

use protocol::{MAX_VMS, VmItem};

/// GUID 正規化成小寫、不含大括號；格式不對回 None
pub fn guid(s: &str) -> Option<String> {
    let s = s.trim().trim_start_matches('{').trim_end_matches('}');
    protocol::uuid_forms(s).map(|[u, _]| u)
}

/// Hyper-V `Msvm_ComputerSystem.EnabledState`
pub fn hyperv_state(code: u64) -> &'static str {
    match code {
        2 => "running",
        3 => "stopped",
        9 | 32768 => "paused",
        6 | 32769 => "saved",
        _ => "other",
    }
}

/// `virsh list --all --uuid`：每行一個 UUID
pub fn virsh_uuids(out: &str) -> Vec<String> {
    out.lines().filter_map(guid).collect()
}

fn fields(out: &str) -> impl Iterator<Item = (&str, &str)> {
    out.lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim(), v.trim()))
}

/// `virsh dominfo <uuid>`；libvirt 預設把網域 UUID 當成客體的 SMBIOS UUID
pub fn parse_dominfo(out: &str) -> Option<VmItem> {
    let (mut name, mut uuid, mut state) = (None, None, "");
    let (mut vcpus, mut memory_mb, mut managed_save) = (None, None, false);
    for (k, v) in fields(out) {
        match k {
            "Name" => name = Some(v.to_string()),
            "UUID" => uuid = guid(v),
            "State" => state = v,
            "CPU(s)" => vcpus = v.parse().ok(),
            "Max memory" => {
                memory_mb = v
                    .split_whitespace()
                    .next()
                    .and_then(|n| n.parse::<u64>().ok())
                    .map(|kib| kib / 1024)
            }
            "Managed save" => managed_save = v == "yes",
            _ => {}
        }
    }
    let uuid = uuid?;
    let state = match state {
        "running" | "idle" | "in shutdown" | "blocked" => "running",
        "paused" => "paused",
        "pmsuspended" => "saved",
        "shut off" | "crashed" if managed_save => "saved",
        "shut off" | "crashed" => "stopped",
        _ => "other",
    };
    Some(VmItem {
        platform: "libvirt".into(),
        id: uuid.clone(),
        name: name.unwrap_or_else(|| uuid.clone()),
        state: state.into(),
        bios_uuid: Some(uuid),
        vcpus,
        memory_mb,
        os_hint: None,
    })
}

/// Proxmox 的狀態（`qm list`／`pct list` 的 STATUS 欄）
fn proxmox_state(s: &str) -> &'static str {
    match s {
        "running" => "running",
        "stopped" => "stopped",
        "paused" => "paused",
        "suspended" => "saved",
        _ => "other",
    }
}

/// `qm list`：VMID NAME STATUS MEM(MB) BOOTDISK(GB) PID
pub fn qm_list(out: &str) -> Vec<VmItem> {
    out.lines()
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            let id = t
                .first()
                .filter(|v| v.bytes().all(|b| b.is_ascii_digit()))?;
            Some(VmItem {
                platform: "proxmox".into(),
                id: id.to_string(),
                name: t.get(1)?.to_string(),
                state: proxmox_state(t.get(2)?).into(),
                bios_uuid: None,
                vcpus: None,
                memory_mb: t.get(3).and_then(|m| m.parse().ok()),
                os_hint: None,
            })
        })
        .collect()
}

/// `pct list`：VMID Status Lock Name（Lock 常是空的，所以名稱取最後一欄）
pub fn pct_list(out: &str) -> Vec<VmItem> {
    out.lines()
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            let id = t
                .first()
                .filter(|v| v.bytes().all(|b| b.is_ascii_digit()))?;
            if t.len() < 3 {
                return None;
            }
            Some(VmItem {
                platform: "proxmox-lxc".into(),
                id: id.to_string(),
                name: t[t.len() - 1].to_string(),
                state: proxmox_state(t[1]).into(),
                bios_uuid: None,
                vcpus: None,
                memory_mb: None,
                os_hint: None,
            })
        })
        .collect()
}

/// Proxmox 的 ostype 換成看得懂的名稱
fn proxmox_os(t: &str) -> String {
    match t {
        "l24" | "l26" => "Linux".into(),
        "solaris" => "Solaris".into(),
        "other" => "其他".into(),
        t if t.starts_with('w') => format!("Windows（{t}）"),
        t => t.into(),
    }
}

/// `qm config <vmid>`／`pct config <vmid>`：補上 BIOS UUID、vCPU、記憶體與作業系統
pub fn apply_config(vm: &mut VmItem, out: &str) {
    let (mut cores, mut sockets, mut vcpus) = (None, 1u32, None);
    for (k, v) in fields(out) {
        match k {
            "cores" => cores = v.parse::<u32>().ok(),
            "sockets" => sockets = v.parse().unwrap_or(1),
            "vcpus" => vcpus = v.parse::<u32>().ok(),
            "memory" => vm.memory_mb = v.parse().ok().or(vm.memory_mb),
            "ostype" => vm.os_hint = Some(proxmox_os(v)),
            "smbios1" => {
                vm.bios_uuid = v
                    .split(',')
                    .find_map(|p| p.strip_prefix("uuid="))
                    .and_then(guid);
            }
            _ => {}
        }
    }
    vm.vcpus = vcpus.or_else(|| Some(cores.unwrap_or(1) * sockets.max(1)));
}

/// `pveversion`：`pve-manager/8.2.4/faa83925c9641325 (running kernel: …)`
pub fn pve_version(out: &str) -> Option<String> {
    out.split('/').nth(1).map(str::to_string)
}

/// 執行中的優先，超過上限截斷；回傳是否截斷
pub fn finish(mut vms: Vec<VmItem>) -> (Vec<VmItem>, bool) {
    vms.sort_by(|a, b| {
        b.is_running()
            .cmp(&a.is_running())
            .then_with(|| a.name.cmp(&b.name))
    });
    let truncated = vms.len() > MAX_VMS;
    vms.truncate(MAX_VMS);
    (vms, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guids_and_states() {
        assert_eq!(
            guid("{6A1B2C3D-0000-1111-2222-333344445555}").as_deref(),
            Some("6a1b2c3d-0000-1111-2222-333344445555")
        );
        assert_eq!(guid("not-a-guid"), None);
        assert_eq!(
            [2, 3, 32768, 32769, 6, 9, 4].map(hyperv_state),
            [
                "running", "stopped", "paused", "saved", "saved", "paused", "other"
            ]
        );
        assert_eq!(
            virsh_uuids("6a1b2c3d-0000-1111-2222-333344445555\n\nbad\n"),
            ["6a1b2c3d-0000-1111-2222-333344445555"]
        );
    }

    const DOMINFO: &str = "Id:             1\nName:           web01\n\
        UUID:           6A1B2C3D-0000-1111-2222-333344445555\nOS Type:        hvm\n\
        State:          running\nCPU(s):         2\nCPU time:       12.3s\n\
        Max memory:     2097152 KiB\nUsed memory:    2097152 KiB\nPersistent:     yes\n\
        Managed save:   no\n";

    #[test]
    fn dominfo() {
        let v = parse_dominfo(DOMINFO).unwrap();
        assert_eq!(
            v,
            VmItem {
                platform: "libvirt".into(),
                id: "6a1b2c3d-0000-1111-2222-333344445555".into(),
                name: "web01".into(),
                state: "running".into(),
                bios_uuid: Some("6a1b2c3d-0000-1111-2222-333344445555".into()),
                vcpus: Some(2),
                memory_mb: Some(2048),
                os_hint: None,
            }
        );
        let off = DOMINFO.replace("running", "shut off");
        assert_eq!(parse_dominfo(&off).unwrap().state, "stopped");
        let saved = off.replace("Managed save:   no", "Managed save:   yes");
        assert_eq!(parse_dominfo(&saved).unwrap().state, "saved");
        for (s, want) in [
            ("paused", "paused"),
            ("pmsuspended", "saved"),
            ("dying", "other"),
        ] {
            assert_eq!(
                parse_dominfo(&DOMINFO.replace("running", s)).unwrap().state,
                want
            );
        }
        assert!(parse_dominfo("Name: x\n").is_none(), "沒有 UUID");
        let no_name = DOMINFO.replace("Name:           web01\n", "");
        assert_eq!(
            parse_dominfo(&no_name).unwrap().name,
            "6a1b2c3d-0000-1111-2222-333344445555"
        );
    }

    #[test]
    fn proxmox() {
        let list = "      VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID\n\
                    \x20      100 web01                running    2048              32.00 1234\n\
                    \x20      101 win                  stopped    4096              64.00 0\n";
        let mut vms = qm_list(list);
        assert_eq!(vms.len(), 2);
        assert_eq!(
            (
                vms[0].id.as_str(),
                vms[0].name.as_str(),
                vms[0].state.as_str(),
                vms[0].memory_mb
            ),
            ("100", "web01", "running", Some(2048))
        );
        apply_config(
            &mut vms[0],
            "cores: 2\nmemory: 3072\nname: web01\nostype: l26\n\
             smbios1: uuid=7B1C0000-1111-2222-3333-444455556666,manufacturer=QEMU\nsockets: 2\n",
        );
        assert_eq!(
            vms[0].bios_uuid.as_deref(),
            Some("7b1c0000-1111-2222-3333-444455556666")
        );
        assert_eq!((vms[0].vcpus, vms[0].memory_mb), (Some(4), Some(3072)));
        assert_eq!(vms[0].os_hint.as_deref(), Some("Linux"));
        apply_config(&mut vms[1], "vcpus: 3\ncores: 4\nostype: win11\n");
        assert_eq!((vms[1].vcpus, vms[1].memory_mb), (Some(3), Some(4096)));
        assert_eq!(vms[1].os_hint.as_deref(), Some("Windows（win11）"));
        let mut other = vms[1].clone();
        apply_config(&mut other, "ostype: solaris\n");
        assert_eq!(
            (other.os_hint.as_deref(), other.vcpus),
            (Some("Solaris"), Some(1))
        );
        apply_config(&mut other, "ostype: other\n");
        assert_eq!(other.os_hint.as_deref(), Some("其他"));
        apply_config(&mut other, "ostype: freebsd\n");
        assert_eq!(other.os_hint.as_deref(), Some("freebsd"));

        let cts = pct_list(
            "VMID       Status     Lock         Name\n101        running                 ct1\n\
             102        stopped    backup       ct2\n103 suspended x\n104 x\n",
        );
        let got: Vec<(&str, &str, &str)> = cts
            .iter()
            .map(|c| (c.id.as_str(), c.name.as_str(), c.state.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("101", "ct1", "running"),
                ("102", "ct2", "stopped"),
                ("103", "x", "saved")
            ]
        );
        assert!(cts.iter().all(|c| c.platform == "proxmox-lxc"));
        assert_eq!(
            pve_version("pve-manager/8.2.4/faa83925c9641325 (running kernel: 6.8)").as_deref(),
            Some("8.2.4")
        );
        assert_eq!(qm_list("100 paused-only\n"), vec![], "欄位不足");
        assert_eq!(qm_list("100 a paused 1\n")[0].state, "paused");
    }

    #[test]
    fn finish_orders_and_truncates() {
        let vm = |name: &str, state: &str| VmItem {
            platform: "libvirt".into(),
            id: name.into(),
            name: name.into(),
            state: state.into(),
            bios_uuid: None,
            vcpus: None,
            memory_mb: None,
            os_hint: None,
        };
        let (v, t) = finish(vec![
            vm("b", "stopped"),
            vm("c", "running"),
            vm("a", "stopped"),
        ]);
        assert!(!t);
        assert_eq!(
            v.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(),
            ["c", "a", "b"]
        );
        let many: Vec<VmItem> = (0..=MAX_VMS)
            .map(|i| vm(&format!("{i:04}"), "stopped"))
            .collect();
        let (v, t) = finish(many);
        assert!(t && v.len() == MAX_VMS);
    }
}
