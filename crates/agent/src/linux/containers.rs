//! 主機上的容器：Docker、Podman（含一般使用者的 rootless Podman）、containerd（crictl／nerdctl）、
//! Incus／LXD 系統容器。

use std::path::Path;

use super::exec::{CMD_TIMEOUT, is_not_found, run_capture};
use crate::linux_parse::accounts::uid_min;
use crate::linux_parse::containers as parse;
use protocol::{ContainerItem, ContainersInfo, RuntimeInfo};

/// 最多讀幾個使用者的 rootless Podman
const MAX_ROOTLESS_USERS: usize = 50;
/// 錯誤訊息最長幾個字
const MAX_ERROR_CHARS: usize = 500;

/// 某個執行環境（以某個使用者身分，None 是 root）的所有容器
fn list(runtime: &str, prefix: &[&str], owner: Option<&str>) -> anyhow::Result<Vec<ContainerItem>> {
    let (program, mut args) = match prefix.split_first() {
        Some((p, rest)) => (*p, rest.to_vec()),
        None => (runtime, vec![]),
    };
    if !prefix.is_empty() {
        args.push(runtime);
    }
    let run = |extra: &[&str]| {
        let mut a = args.clone();
        a.extend_from_slice(extra);
        run_capture(program, &a, CMD_TIMEOUT)
    };
    let ids = run(&["ps", "-a", "-q", "--no-trunc"])?;
    let ids: Vec<&str> = ids.split_whitespace().collect();
    if ids.is_empty() {
        return Ok(vec![]);
    }
    let mut inspect = vec!["inspect"];
    inspect.extend(ids);
    parse::parse_inspect(runtime, &run(&inspect)?, owner)
}

fn version(runtime: &str) -> Option<String> {
    let format = if runtime == "docker" {
        "{{.Server.Version}}"
    } else {
        "{{.Client.Version}}"
    };
    run_capture(runtime, &["version", "--format", format], CMD_TIMEOUT)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn short(e: &anyhow::Error) -> String {
    e.to_string().chars().take(MAX_ERROR_CHARS).collect()
}

/// 一般使用者的 rootless Podman：只讀目前有登入工作階段（`/run/user/<UID>` 存在）、
/// 而且家目錄有容器儲存區的使用者
fn rootless(items: &mut Vec<ContainerItem>, errors: &mut Vec<String>) {
    let Ok(passwd) = std::fs::read_to_string("/etc/passwd") else {
        return;
    };
    let min = uid_min(&std::fs::read_to_string("/etc/login.defs").unwrap_or_default());
    let users = parse::regular_users(&passwd, min)
        .into_iter()
        .filter(|(_, uid, home)| {
            Path::new(&format!("/run/user/{uid}")).is_dir()
                && Path::new(home).join(".local/share/containers").is_dir()
        })
        .take(MAX_ROOTLESS_USERS);
    for (name, uid, _) in users {
        let runtime_dir = format!("XDG_RUNTIME_DIR=/run/user/{uid}");
        let prefix = [
            "runuser",
            "-u",
            name.as_str(),
            "--",
            "env",
            runtime_dir.as_str(),
        ];
        match list("podman", &prefix, Some(&name)) {
            Ok(v) => items.extend(v),
            Err(e) => errors.push(format!("使用者 {name}：{}", short(&e))),
        }
    }
}

fn run(program: &str, args: &[&str]) -> anyhow::Result<String> {
    run_capture(program, args, CMD_TIMEOUT)
}

/// Kubernetes 節點的 containerd：`crictl`（只有 k8s.io 命名空間）
fn crictl() -> anyhow::Result<Vec<ContainerItem>> {
    let ps = run("crictl", &["ps", "-a", "-o", "json"])?;
    // inspect 要完整的 ID；從 ps 的輸出取
    let full: Vec<String> = serde_json::from_str::<serde_json::Value>(&ps)?["containers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| c["id"].as_str().map(str::to_string))
        .collect();
    if full.is_empty() {
        return Ok(vec![]);
    }
    let mut args = vec!["inspect"];
    args.extend(full.iter().map(String::as_str));
    // inspect 失敗時仍回報 ps 的基本資料（名稱、映像、狀態、Pod）
    let inspect = run("crictl", &args).unwrap_or_default();
    parse::parse_crictl(&ps, &inspect)
}

/// 非 Kubernetes 的 containerd：`nerdctl`，逐一命名空間。`moby` 是 Docker 自己的（已由 docker 讀過），
/// `k8s.io` 有 crictl 時已經讀過
fn nerdctl(skip_k8s: bool) -> anyhow::Result<Vec<ContainerItem>> {
    let namespaces = run("nerdctl", &["namespace", "ls", "-q"])?;
    let mut out = Vec::new();
    for ns in namespaces.split_whitespace() {
        if ns == "moby" || (skip_k8s && ns == "k8s.io") {
            continue;
        }
        let ids = run(
            "nerdctl",
            &["--namespace", ns, "ps", "-a", "-q", "--no-trunc"],
        )?;
        let ids: Vec<&str> = ids.split_whitespace().collect();
        if ids.is_empty() {
            continue;
        }
        let mut args = vec!["--namespace", ns, "inspect"];
        args.extend(ids);
        out.extend(parse::parse_inspect(
            "containerd",
            &run("nerdctl", &args)?,
            None,
        )?);
    }
    Ok(out)
}

/// containerd：crictl 與 nerdctl 有哪個用哪個，合成一個執行環境。都沒有就回 None
fn containerd(items: &mut Vec<ContainerItem>) -> Option<RuntimeInfo> {
    let mut errors = Vec::new();
    let mut found = false;
    let mut version = None;
    match crictl() {
        Ok(v) => {
            found = true;
            items.extend(v);
        }
        Err(e) if is_not_found(&e) => {}
        Err(e) => {
            found = true;
            errors.push(format!("crictl：{}", short(&e)));
        }
    }
    let had_crictl = found;
    if found {
        version = run("crictl", &["version"])
            .ok()
            .and_then(|o| parse::crictl_runtime_version(&o));
    }
    match nerdctl(had_crictl && errors.is_empty()) {
        Ok(v) => {
            found = true;
            items.extend(v);
        }
        Err(e) if is_not_found(&e) => {}
        Err(e) => {
            found = true;
            errors.push(format!("nerdctl：{}", short(&e)));
        }
    }
    if version.is_none() {
        version = run("containerd", &["--version"]).ok().and_then(|o| {
            o.split_whitespace()
                .nth(2)
                .map(|v| v.trim_start_matches('v').to_string())
        });
    }
    found.then(|| RuntimeInfo {
        kind: "containerd".into(),
        version,
        error: (!errors.is_empty()).then(|| errors.join("；")),
    })
}

/// 系統容器：Incus，沒有時 LXD（`lxc`）
fn system_containers(items: &mut Vec<ContainerItem>) -> Option<RuntimeInfo> {
    for runtime in ["incus", "lxc"] {
        let listed = run(runtime, &["list", "--all-projects", "--format", "json"])
            .or_else(|_| run(runtime, &["list", "--format", "json"]));
        let error = match listed {
            Err(e) if is_not_found(&e) => continue,
            Err(e) => Some(short(&e)),
            Ok(json) => match parse::parse_incus(runtime, &json) {
                Ok(v) => {
                    items.extend(v);
                    None
                }
                Err(e) => Some(short(&e)),
            },
        };
        return Some(RuntimeInfo {
            kind: runtime.into(),
            version: run(runtime, &["--version"])
                .ok()
                .and_then(|o| parse::last_word(&o)),
            error,
        });
    }
    None
}

pub fn collect() -> ContainersInfo {
    let mut runtimes = Vec::new();
    let mut items = Vec::new();
    for runtime in ["docker", "podman"] {
        let mut errors = Vec::new();
        match list(runtime, &[], None) {
            Ok(v) => items.extend(v),
            // 沒有這個指令：這台沒有這種執行環境
            Err(e) if is_not_found(&e) => continue,
            Err(e) => errors.push(short(&e)),
        }
        if runtime == "podman" {
            rootless(&mut items, &mut errors);
        }
        let error = (!errors.is_empty()).then(|| {
            errors
                .join("；")
                .chars()
                .take(MAX_ERROR_CHARS)
                .collect::<String>()
        });
        runtimes.push(RuntimeInfo {
            kind: runtime.to_string(),
            version: version(runtime),
            error,
        });
    }
    runtimes.extend(containerd(&mut items));
    runtimes.extend(system_containers(&mut items));

    let (containers, truncated) = parse::select(items, time::OffsetDateTime::now_utc());
    ContainersInfo {
        runtimes,
        containers,
        truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 有 Docker 而且有權限的機器（CI）才真的跑一個容器；其他機器略過
    #[test]
    fn sees_a_running_container() {
        if run_capture("docker", &["info"], CMD_TIMEOUT).is_err() {
            eprintln!("skip: docker not available");
            return;
        }
        let name = format!("em-test-{}", std::process::id());
        let started = run_capture(
            "docker",
            &[
                "run",
                "-d",
                "--name",
                &name,
                "-e",
                "SECRET=hunter2",
                "busybox",
                "sleep",
                "120",
            ],
            std::time::Duration::from_secs(180),
        );
        if let Err(e) = started {
            eprintln!("skip: cannot start busybox: {e}");
            return;
        }
        let info = collect();
        let _ = run_capture("docker", &["rm", "-f", &name], CMD_TIMEOUT);
        let docker = info.runtimes.iter().find(|r| r.kind == "docker").unwrap();
        assert!(docker.error.is_none(), "{docker:?}");
        let c = info
            .containers
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("{info:?}"));
        assert_eq!((c.image.as_str(), c.state.as_str()), ("busybox", "running"));
        assert!(c.started_at.is_some());
        assert!(!serde_json::to_string(&info).unwrap().contains("hunter2"));
    }
}
