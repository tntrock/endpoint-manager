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

/// 執行外部指令；測試時換成回傳固定輸出的假指令
type Run<'a> = &'a dyn Fn(&str, &[&str]) -> anyhow::Result<String>;

fn real_run(program: &str, args: &[&str]) -> anyhow::Result<String> {
    run_capture(program, args, CMD_TIMEOUT)
}

/// Kubernetes 節點的 containerd：`crictl`（只有 k8s.io 命名空間）
fn crictl(run: Run) -> anyhow::Result<Vec<ContainerItem>> {
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
fn nerdctl(run: Run, skip_k8s: bool) -> anyhow::Result<Vec<ContainerItem>> {
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
fn containerd(run: Run, items: &mut Vec<ContainerItem>) -> Option<RuntimeInfo> {
    let mut errors = Vec::new();
    let mut found = false;
    let mut version = None;
    match crictl(run) {
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
    match nerdctl(run, had_crictl && errors.is_empty()) {
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
fn system_containers(run: Run, items: &mut Vec<ContainerItem>) -> Option<RuntimeInfo> {
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
    runtimes.extend(containerd(&real_run, &mut items));
    runtimes.extend(system_containers(&real_run, &mut items));

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
    use crate::linux::exec::not_found;

    /// 假的指令：依「程式 參數…」查表；查不到的程式當成不存在
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

    const PS: &str = r#"{"containers": [{"id": "aaaabbbbccccdddd", "metadata": {"name": "nginx"},
        "image": {"image": "nginx:1.27"}, "state": "CONTAINER_RUNNING",
        "labels": {"io.kubernetes.pod.name": "web", "io.kubernetes.pod.namespace": "shop"}}]}"#;
    const NERD: &str = r#"[{"Id": "1111222233334444", "Name": "job", "Image": "busybox:1",
        "State": {"Status": "exited"}, "Created": "2026-11-21T00:00:00Z"}]"#;

    #[test]
    fn containerd_via_crictl_and_nerdctl() {
        let run = fake(vec![
            ("crictl ps", Ok(PS)),
            ("crictl inspect", Err(anyhow::anyhow!("boom"))),
            ("crictl version", Ok("RuntimeVersion: v1.7.22\n")),
            ("nerdctl namespace", Ok("default\nk8s.io\nmoby\n")),
            ("nerdctl --namespace default ps", Ok("1111222233334444\n")),
            ("nerdctl --namespace default inspect", Ok(NERD)),
        ]);
        let mut items = vec![];
        let r = containerd(&run, &mut items).unwrap();
        assert_eq!(
            (r.kind.as_str(), r.version.as_deref(), r.error.as_deref()),
            ("containerd", Some("1.7.22"), None)
        );
        let names: Vec<&str> = items.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            ["nginx", "job"],
            "k8s.io 與 moby 略過；inspect 失敗仍有 ps 的資料"
        );
        assert!(items.iter().all(|c| c.runtime == "containerd"));
    }

    #[test]
    fn containerd_errors_and_absence() {
        // 兩個指令都沒有：這台沒有 containerd
        assert!(containerd(&fake(vec![]), &mut vec![]).is_none());
        // crictl 設定錯誤、只有 nerdctl 而且沒有容器；版本改讀 containerd --version
        let run = fake(vec![
            ("crictl ps", Err(anyhow::anyhow!("no runtime endpoint"))),
            ("nerdctl namespace", Ok("default\nk8s.io\n")),
            ("nerdctl --namespace default ps", Ok("")),
            ("nerdctl --namespace k8s.io ps", Ok("")),
            (
                "containerd --version",
                Ok("containerd github.com/containerd/containerd v1.6.9 abc\n"),
            ),
        ]);
        let mut items = vec![];
        let r = containerd(&run, &mut items).unwrap();
        assert!(items.is_empty());
        assert_eq!(r.version.as_deref(), Some("1.6.9"));
        assert!(r.error.unwrap().starts_with("crictl：no runtime endpoint"));
        // crictl 沒有容器、nerdctl 失敗
        let run = fake(vec![
            ("crictl ps", Ok(r#"{"containers": []}"#)),
            (
                "nerdctl namespace",
                Err(anyhow::anyhow!("permission denied")),
            ),
        ]);
        let r = containerd(&run, &mut vec![]).unwrap();
        assert!(r.error.unwrap().starts_with("nerdctl：permission denied"));
    }

    const INCUS: &str = r#"[{"name": "db", "type": "container", "status": "Running"}]"#;

    #[test]
    fn system_containers_prefers_incus() {
        let run = fake(vec![
            ("incus list --all-projects", Ok(INCUS)),
            ("incus --version", Ok("6.0.1\n")),
            ("lxc list", Ok("[]")),
        ]);
        let mut items = vec![];
        let r = system_containers(&run, &mut items).unwrap();
        assert_eq!(
            (r.kind.as_str(), r.version.as_deref()),
            ("incus", Some("6.0.1"))
        );
        assert_eq!(items[0].runtime, "incus");

        // 沒有 incus：LXD；舊版不支援 --all-projects 時改用不加的
        let run = fake(vec![
            (
                "lxc list --all-projects",
                Err(anyhow::anyhow!("unknown flag")),
            ),
            ("lxc list --format", Ok(INCUS)),
        ]);
        let mut items = vec![];
        let r = system_containers(&run, &mut items).unwrap();
        assert_eq!((r.kind.as_str(), r.version, r.error), ("lxc", None, None));
        assert_eq!(items.len(), 1);

        // 指令存在但失敗、輸出壞掉
        let r = system_containers(
            &fake(vec![("incus list", Err(anyhow::anyhow!("not running")))]),
            &mut vec![],
        )
        .unwrap();
        assert_eq!(r.error.as_deref(), Some("not running"));
        let r = system_containers(&fake(vec![("incus list", Ok("{}"))]), &mut vec![]).unwrap();
        assert!(r.error.is_some());
        // 都沒有
        assert!(system_containers(&fake(vec![]), &mut vec![]).is_none());
    }

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
