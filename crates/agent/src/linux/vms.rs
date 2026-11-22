//! 虛擬化主機上的虛擬機：libvirt（virsh）、Proxmox VE（qm 與 pct）。

use super::exec::{Run, is_not_found, real_run};
use crate::vms as parse;
use protocol::{RuntimeInfo, VmItem, VmsInfo};

/// 錯誤訊息最長幾個字
const MAX_ERROR_CHARS: usize = 500;

fn short(e: &anyhow::Error) -> String {
    e.to_string().chars().take(MAX_ERROR_CHARS).collect()
}

/// libvirt：`virsh list --all --uuid`，每台再讀 `virsh dominfo`
fn libvirt(run: Run, items: &mut Vec<VmItem>) -> Option<RuntimeInfo> {
    let error = match run("virsh", &["list", "--all", "--uuid"]) {
        Err(e) if is_not_found(&e) => return None,
        Err(e) => Some(short(&e)),
        Ok(out) => {
            let mut first_error = None;
            for uuid in parse::virsh_uuids(&out) {
                match run("virsh", &["dominfo", &uuid]) {
                    Ok(info) => items.extend(parse::parse_dominfo(&info)),
                    // 列出後才被刪除的虛擬機也會走到這裡：記第一個錯誤，其餘照常
                    Err(e) => {
                        first_error.get_or_insert_with(|| format!("{uuid}：{}", short(&e)));
                    }
                }
            }
            first_error
        }
    };
    Some(RuntimeInfo {
        kind: "libvirt".into(),
        version: run("virsh", &["--version"])
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
        error,
    })
}

/// Proxmox VE：`qm list` 與 `pct list`，每台再讀設定
fn proxmox(run: Run, items: &mut Vec<VmItem>) -> Option<RuntimeInfo> {
    let mut errors = vec![];
    match run("qm", &["list"]) {
        Err(e) if is_not_found(&e) => return None,
        Err(e) => errors.push(format!("qm：{}", short(&e))),
        Ok(out) => {
            for mut vm in parse::qm_list(&out) {
                if let Ok(cfg) = run("qm", &["config", &vm.id]) {
                    parse::apply_config(&mut vm, &cfg);
                }
                items.push(vm);
            }
        }
    }
    match run("pct", &["list"]) {
        Err(e) if is_not_found(&e) => {}
        Err(e) => errors.push(format!("pct：{}", short(&e))),
        Ok(out) => {
            for mut ct in parse::pct_list(&out) {
                if let Ok(cfg) = run("pct", &["config", &ct.id]) {
                    parse::apply_config(&mut ct, &cfg);
                }
                // LXC 容器沒有 SMBIOS
                ct.bios_uuid = None;
                items.push(ct);
            }
        }
    }
    Some(RuntimeInfo {
        kind: "proxmox".into(),
        version: run("pveversion", &[])
            .ok()
            .and_then(|o| parse::pve_version(&o)),
        error: (!errors.is_empty()).then(|| errors.join("；")),
    })
}

fn collect_with(run: Run) -> VmsInfo {
    let mut items = vec![];
    let mut platforms = vec![];
    // Proxmox 不用 libvirt；兩個都有時各自列出
    platforms.extend(proxmox(run, &mut items));
    platforms.extend(libvirt(run, &mut items));
    let (vms, truncated) = parse::finish(items);
    VmsInfo {
        platforms,
        vms,
        truncated,
    }
}

pub fn collect() -> VmsInfo {
    collect_with(&real_run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::exec::not_found;

    fn fake(
        table: Vec<(&'static str, anyhow::Result<&'static str>)>,
    ) -> impl Fn(&str, &[&str]) -> anyhow::Result<String> {
        move |program: &str, args: &[&str]| {
            let cmd = format!("{program} {}", args.join(" "));
            for (k, v) in &table {
                if cmd.starts_with(k) {
                    return match v {
                        Ok(s) => Ok(s.to_string()),
                        Err(e) => Err(anyhow::anyhow!("{e}")),
                    };
                }
            }
            Err(not_found(program))
        }
    }

    const U1: &str = "11111111-2222-3333-4444-555555555555";

    #[test]
    fn nothing_installed() {
        let v = collect_with(&fake(vec![]));
        assert!(v.platforms.is_empty() && v.vms.is_empty() && !v.truncated);
    }

    #[test]
    fn libvirt_lists_domains() {
        let run = fake(vec![
            (
                "virsh list",
                Ok("11111111-2222-3333-4444-555555555555\n22222222-2222-3333-4444-555555555555\n"),
            ),
            (
                "virsh dominfo 11111111",
                Ok("Name: db\nUUID: 11111111-2222-3333-4444-555555555555\nState: running\n"),
            ),
            (
                "virsh dominfo 22222222",
                Err(anyhow::anyhow!("Domain not found")),
            ),
            ("virsh --version", Ok("10.0.0\n")),
        ]);
        let v = collect_with(&run);
        assert_eq!(v.platforms.len(), 1);
        let p = &v.platforms[0];
        assert_eq!(
            (p.kind.as_str(), p.version.as_deref()),
            ("libvirt", Some("10.0.0"))
        );
        assert_eq!(
            p.error.as_deref(),
            Some("22222222-2222-3333-4444-555555555555：Domain not found")
        );
        assert_eq!(v.vms.len(), 1);
        assert_eq!(v.vms[0].bios_uuid.as_deref(), Some(U1));

        let v = collect_with(&fake(vec![(
            "virsh list",
            Err(anyhow::anyhow!("failed to connect to the hypervisor")),
        )]));
        assert_eq!(
            v.platforms[0].error.as_deref(),
            Some("failed to connect to the hypervisor")
        );
        assert_eq!(v.platforms[0].version, None);
    }

    #[test]
    fn proxmox_vms_and_containers() {
        let run = fake(vec![
            (
                "qm list",
                Ok("VMID NAME STATUS MEM(MB) BOOTDISK(GB) PID\n100 web running 2048 32.00 99\n"),
            ),
            (
                "qm config 100",
                Ok("cores: 2\nsmbios1: uuid=11111111-2222-3333-4444-555555555555\n"),
            ),
            ("pct list", Ok("VMID Status Lock Name\n200 stopped ct\n")),
            (
                "pct config 200",
                Ok("cores: 1\nmemory: 512\nostype: debian\n"),
            ),
            (
                "pveversion",
                Ok("pve-manager/8.2.4/abc (running kernel: 6.8)\n"),
            ),
        ]);
        let v = collect_with(&run);
        assert_eq!(v.platforms[0].kind, "proxmox");
        assert_eq!(v.platforms[0].version.as_deref(), Some("8.2.4"));
        assert_eq!(v.platforms[0].error, None);
        let names: Vec<(&str, &str)> = v
            .vms
            .iter()
            .map(|x| (x.platform.as_str(), x.name.as_str()))
            .collect();
        assert_eq!(names, [("proxmox", "web"), ("proxmox-lxc", "ct")]);
        assert_eq!(v.vms[0].bios_uuid.as_deref(), Some(U1));
        assert_eq!(v.vms[1].bios_uuid, None);
        assert_eq!(v.vms[1].os_hint.as_deref(), Some("debian"));

        let run = fake(vec![
            ("qm list", Err(anyhow::anyhow!("permission denied"))),
            ("pct list", Err(anyhow::anyhow!("locked"))),
        ]);
        let v = collect_with(&run);
        assert_eq!(
            v.platforms[0].error.as_deref(),
            Some("qm：permission denied；pct：locked")
        );
    }
}
