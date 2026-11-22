//! `docker inspect`／`podman inspect` 輸出的解析與篩選。
//!
//! 只取規格列出的欄位；環境變數、啟動參數、標籤一律不讀（常含密碼）。

use protocol::{ContainerItem, K8sRef, MAX_CONTAINERS};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

/// 已停止的容器只保留這幾天內結束（或建立）的
pub const STOPPED_KEEP_DAYS: i64 = 7;
/// 每個容器最多回報的 bind mount 數
pub const MAX_MOUNTS: usize = 20;

fn at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(v, |v, k| v.get(k))
}

fn text(v: &Value, path: &[&str]) -> Option<String> {
    at(v, path)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// RFC 3339 時間轉 UTC。Docker 用 `0001-01-01T00:00:00Z`、CRI 用 `1970-01-01T00:00:00Z` 表示「沒有」
fn time_at(v: &Value, path: &[&str]) -> Option<OffsetDateTime> {
    let t = OffsetDateTime::parse(&text(v, path)?, &Rfc3339).ok()?;
    (t.unix_timestamp() > 0).then(|| t.to_offset(time::UtcOffset::UTC))
}

/// `NetworkSettings.Ports`：`{"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}`；
/// 只有 EXPOSE 沒有對外發佈的是 null，不列
fn ports(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(map) = at(v, &["NetworkSettings", "Ports"]).and_then(Value::as_object) else {
        return out;
    };
    for (inner, binds) in map {
        for b in binds.as_array().into_iter().flatten() {
            let Some(port) = text(b, &["HostPort"]) else {
                continue;
            };
            let ip = text(b, &["HostIp"]).unwrap_or_else(|| "0.0.0.0".into());
            let ip = if ip.contains(':') {
                format!("[{ip}]")
            } else {
                ip
            };
            out.push(format!("{ip}:{port}->{inner}"));
        }
    }
    out.sort();
    out.dedup();
    out
}

fn host_mounts(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = at(v, &["Mounts"])
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|m| text(m, &["Type"]).as_deref() == Some("bind"))
        .filter_map(|m| text(m, &["Source"]))
        .collect();
    out.sort();
    out.dedup();
    out.truncate(MAX_MOUNTS);
    out
}

fn item(runtime: &str, v: &Value, owner: Option<&str>) -> Option<ContainerItem> {
    let id: String = text(v, &["Id"])?.chars().take(12).collect();
    let name = text(v, &["Name"])
        .map(|n| n.trim_start_matches('/').to_string())
        .unwrap_or_else(|| id.clone());
    // Docker 放在 Config.Image；Podman 另有 ImageName
    let image = text(v, &["Config", "Image"])
        .or_else(|| text(v, &["ImageName"]))
        .or_else(|| text(v, &["Image"]))
        .unwrap_or_default();
    let health = text(v, &["State", "Health", "Status"])
        .or_else(|| text(v, &["State", "Healthcheck", "Status"]));
    Some(ContainerItem {
        runtime: runtime.to_string(),
        id,
        name,
        image,
        image_id: text(v, &["Image"]),
        state: text(v, &["State", "Status"])
            .unwrap_or_else(|| "unknown".into())
            .to_ascii_lowercase(),
        health: health.map(|h| h.to_ascii_lowercase()),
        created_at: time_at(v, &["Created"]),
        started_at: time_at(v, &["State", "StartedAt"]),
        finished_at: time_at(v, &["State", "FinishedAt"]),
        restart_policy: text(v, &["HostConfig", "RestartPolicy", "Name"]),
        privileged: at(v, &["HostConfig", "Privileged"]).and_then(Value::as_bool),
        host_network: text(v, &["HostConfig", "NetworkMode"]).map(|m| m == "host"),
        ports: ports(v),
        host_mounts: host_mounts(v),
        owner: owner.map(str::to_string),
        k8s: None,
    })
}

/// 解析 `inspect` 的 JSON 陣列
pub fn parse_inspect(
    runtime: &str,
    json: &str,
    owner: Option<&str>,
) -> anyhow::Result<Vec<ContainerItem>> {
    let v: Value = serde_json::from_str(json)?;
    let arr = v
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("{runtime} inspect 的輸出不是陣列"))?;
    Ok(arr.iter().filter_map(|c| item(runtime, c, owner)).collect())
}

fn cri_state(s: &str) -> &'static str {
    match s {
        "CONTAINER_RUNNING" => "running",
        "CONTAINER_EXITED" => "exited",
        "CONTAINER_CREATED" => "created",
        _ => "unknown",
    }
}

/// `crictl ps -a -o json` 與 `crictl inspect <ID…>`（多個 JSON 物件接在一起）。
/// 標籤只讀 Pod 名稱與 Namespace，其他標籤與環境變數不讀
pub fn parse_crictl(ps: &str, inspect: &str) -> anyhow::Result<Vec<ContainerItem>> {
    let ps: Value = serde_json::from_str(ps)?;
    let details: Vec<Value> = serde_json::Deserializer::from_str(inspect)
        .into_iter::<Value>()
        .filter_map(Result::ok)
        .collect();
    let detail = |id: &str| {
        details
            .iter()
            .find(|d| text(d, &["status", "id"]).as_deref() == Some(id))
    };
    let mut out = Vec::new();
    for c in at(&ps, &["containers"])
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(full_id) = text(c, &["id"]) else {
            continue;
        };
        let d = detail(&full_id);
        let label = |k: &str| text(c, &["labels", k]);
        let k8s = match (
            label("io.kubernetes.pod.namespace"),
            label("io.kubernetes.pod.name"),
        ) {
            (Some(namespace), Some(pod)) => Some(K8sRef { namespace, pod }),
            _ => None,
        };
        let sec = d.and_then(|d| at(d, &["info", "config", "linux", "security_context"]));
        // NamespaceMode：2 = NODE（與主機共用網路）；不同版本可能輸出數字或名稱
        let host_network = sec
            .and_then(|s| at(s, &["namespace_options", "network"]))
            .map(|n| n.as_i64() == Some(2) || n.as_str() == Some("NODE"));
        let mut mounts: Vec<String> = d
            .and_then(|d| at(d, &["status", "mounts"]))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|m| text(m, &["hostPath"]))
            .collect();
        mounts.sort();
        mounts.dedup();
        mounts.truncate(MAX_MOUNTS);
        let created = text(c, &["createdAt"])
            .and_then(|n| n.parse::<i128>().ok())
            .and_then(|n| OffsetDateTime::from_unix_timestamp_nanos(n).ok())
            .filter(|t| t.unix_timestamp() > 0);
        out.push(ContainerItem {
            runtime: "containerd".into(),
            id: full_id.chars().take(12).collect(),
            name: text(c, &["metadata", "name"]).unwrap_or_else(|| full_id.clone()),
            // inspect 有人看得懂的映像名稱；ps 的常常只是映像 ID
            image: d
                .and_then(|d| text(d, &["status", "image", "image"]))
                .or_else(|| text(c, &["image", "image"]))
                .unwrap_or_default(),
            image_id: text(c, &["imageRef"]),
            state: cri_state(&text(c, &["state"]).unwrap_or_default()).into(),
            health: None,
            created_at: created,
            started_at: d.and_then(|d| time_at(d, &["status", "startedAt"])),
            finished_at: d.and_then(|d| time_at(d, &["status", "finishedAt"])),
            restart_policy: None,
            privileged: sec
                .and_then(|s| at(s, &["privileged"]))
                .and_then(Value::as_bool),
            host_network,
            ports: vec![],
            host_mounts: mounts,
            owner: None,
            k8s,
        });
    }
    Ok(out)
}

/// `incus list --format json`（LXD 的 `lxc list` 格式相同）。只取系統容器，虛擬機不在這裡
pub fn parse_incus(runtime: &str, json: &str) -> anyhow::Result<Vec<ContainerItem>> {
    let v: Value = serde_json::from_str(json)?;
    let arr = v
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("{runtime} list 的輸出不是陣列"))?;
    let mut out = Vec::new();
    for c in arr {
        if text(c, &["type"])
            .as_deref()
            .is_some_and(|t| t != "container")
        {
            continue;
        }
        let Some(name) = text(c, &["name"]) else {
            continue;
        };
        // 不同專案可以有同名的容器
        let name = match text(c, &["project"]) {
            Some(p) if p != "default" => format!("{p}/{name}"),
            _ => name,
        };
        let cfg = |k: &str| text(c, &["expanded_config", k]).or_else(|| text(c, &["config", k]));
        let image = cfg("image.description").unwrap_or_else(|| {
            [cfg("image.os"), cfg("image.release")]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ")
        });
        let state = text(c, &["status"])
            .unwrap_or_else(|| "unknown".into())
            .to_ascii_lowercase();
        let last_used = time_at(c, &["last_used_at"]);
        let mut mounts: Vec<String> = at(c, &["expanded_devices"])
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|m| m.values())
            .filter(|d| text(d, &["type"]).as_deref() == Some("disk"))
            .filter(|d| text(d, &["path"]).as_deref() != Some("/"))
            .filter_map(|d| text(d, &["source"]))
            .filter(|s| s.starts_with('/'))
            .collect();
        mounts.sort();
        mounts.dedup();
        mounts.truncate(MAX_MOUNTS);
        let running = state == "running";
        out.push(ContainerItem {
            runtime: runtime.to_string(),
            id: name.chars().take(64).collect(),
            image,
            image_id: cfg("volatile.base_image"),
            health: None,
            created_at: time_at(c, &["created_at"]),
            // 只有「最後啟動時間」：執行中的當成啟動時間，停止的當成大約的結束時間
            started_at: last_used.filter(|_| running),
            finished_at: last_used.filter(|_| !running),
            restart_policy: (cfg("boot.autostart").as_deref() == Some("true"))
                .then(|| "autostart".to_string()),
            privileged: Some(cfg("security.privileged").as_deref() == Some("true")),
            host_network: None,
            ports: vec![],
            host_mounts: mounts,
            owner: None,
            k8s: None,
            state,
            name,
        });
    }
    Ok(out)
}

/// `crictl version` 的 RuntimeVersion（containerd 的版本）
pub fn crictl_runtime_version(out: &str) -> Option<String> {
    out.lines()
        .find_map(|l| l.trim().strip_prefix("RuntimeVersion:"))
        .map(|v| v.trim().trim_start_matches('v').to_string())
        .filter(|v| !v.is_empty())
}

/// `--version` 的最後一個詞：`nerdctl version 1.7.6` → 1.7.6；`6.0.0` → 6.0.0
pub fn last_word(out: &str) -> Option<String> {
    out.split_whitespace()
        .last()
        .map(|v| v.trim_start_matches('v').to_string())
}

/// 一般使用者（可能有 rootless Podman 容器）：UID ≥ `uid_min`、不是 nobody。回 (名稱, UID, 家目錄)
pub fn regular_users(passwd: &str, uid_min: u32) -> Vec<(String, u32, String)> {
    passwd
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            let uid: u32 = f.get(2)?.parse().ok()?;
            (f.len() >= 6 && uid >= uid_min && uid != 65534 && !f[0].is_empty())
                .then(|| (f[0].to_string(), uid, f[5].to_string()))
        })
        .collect()
}

/// 篩選與排序：執行中全收；已停止的只收 [`STOPPED_KEEP_DAYS`] 天內結束（沒有結束時間就看建立時間）的；
/// 同一個 ID 只留第一個（`docker` 指令可能其實是 Podman）。執行中的在前，總數超過上限就截斷。
pub fn select(items: Vec<ContainerItem>, now: OffsetDateTime) -> (Vec<ContainerItem>, bool) {
    let cutoff = now - Duration::days(STOPPED_KEEP_DAYS);
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<ContainerItem> = items
        .into_iter()
        .filter(|c| seen.insert(c.id.clone()))
        .filter(|c| c.is_running() || c.finished_at.or(c.created_at).is_some_and(|t| t >= cutoff))
        .collect();
    out.sort_by(|a, b| {
        b.is_running()
            .cmp(&a.is_running())
            .then_with(|| {
                b.started_at
                    .or(b.created_at)
                    .cmp(&a.started_at.or(a.created_at))
            })
            .then_with(|| a.name.cmp(&b.name))
    });
    let truncated = out.len() > MAX_CONTAINERS;
    out.truncate(MAX_CONTAINERS);
    (out, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    /// `docker inspect` 的實際輸出（刪減）；Env 與 Cmd 含密碼，不能出現在結果裡
    const DOCKER: &str = r#"[
      {
        "Id": "3f1c0a9e8b7d6c5b4a3928170615f4e3d2c1b0a9",
        "Created": "2026-11-20T08:00:00.123456789Z",
        "State": {"Status": "running", "StartedAt": "2026-11-21T09:30:00.5+08:00",
                  "FinishedAt": "0001-01-01T00:00:00Z", "Health": {"Status": "healthy"}},
        "Image": "sha256:aaaabbbbcccc",
        "Name": "/web",
        "HostConfig": {"Privileged": true, "NetworkMode": "bridge",
                       "RestartPolicy": {"Name": "unless-stopped"}},
        "Mounts": [
          {"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"},
          {"Type": "volume", "Source": "/var/lib/docker/volumes/x/_data", "Destination": "/data"},
          {"Type": "bind", "Source": "/srv/web", "Destination": "/usr/share/nginx/html"}
        ],
        "Config": {"Image": "nginx:1.27", "Env": ["DB_PASSWORD=hunter2"], "Cmd": ["--token", "s3cret"],
                   "Labels": {"secret": "x"}},
        "NetworkSettings": {"Ports": {
          "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}, {"HostIp": "::", "HostPort": "8080"}],
          "443/tcp": null
        }}
      },
      {
        "Id": "99887766554433221100",
        "Created": "2026-11-01T00:00:00Z",
        "State": {"Status": "exited", "StartedAt": "2026-11-01T00:00:01Z",
                  "FinishedAt": "2026-11-18T00:00:00Z"},
        "Image": "sha256:dddd",
        "Name": "/job",
        "HostConfig": {"Privileged": false, "NetworkMode": "host", "RestartPolicy": {"Name": "no"}},
        "Mounts": [],
        "Config": {"Image": "busybox"},
        "NetworkSettings": {"Ports": {}}
      },
      {"Name": "/no-id"}
    ]"#;

    /// `podman inspect`：名稱沒有斜線、映像在 ImageName、健康檢查在 Healthcheck
    const PODMAN: &str = r#"[
      {
        "Id": "abcdef0123456789abcdef",
        "Created": "2026-11-21T10:00:00.000000001+08:00",
        "State": {"Status": "Running", "StartedAt": "2026-11-21T10:00:01+08:00",
                  "FinishedAt": "0001-01-01T00:00:00Z", "Healthcheck": {"Status": "Starting"}},
        "Image": "0123abcd",
        "ImageName": "quay.io/app/api:2.1",
        "Name": "api",
        "HostConfig": {"Privileged": false, "NetworkMode": "slirp4netns", "RestartPolicy": {"Name": ""}},
        "Mounts": [],
        "Config": {},
        "NetworkSettings": {"Ports": {"8000/tcp": [{"HostIp": "", "HostPort": "8000"}]}}
      }
    ]"#;

    /// `crictl ps -a -o json`（刪減）：createdAt 是奈秒；標籤含 Pod 以外的資料也不能讀出來
    const CRICTL_PS: &str = r#"{"containers": [
      {"id": "aaaabbbbccccddddeeee", "podSandboxId": "p1",
       "metadata": {"name": "nginx", "attempt": 0},
       "image": {"image": "sha256:1111"}, "imageRef": "docker.io/library/nginx@sha256:2222",
       "state": "CONTAINER_RUNNING", "createdAt": "1795305600000000000",
       "labels": {"io.kubernetes.pod.name": "web-7d9f", "io.kubernetes.pod.namespace": "shop",
                  "secret-token": "hunter2"}},
      {"id": "ffff00001111222233334444", "metadata": {"name": "migrate"},
       "image": {"image": "registry.example.com/tools:1"}, "imageRef": "sha256:3333",
       "state": "CONTAINER_EXITED", "createdAt": "0", "labels": {}},
      {"metadata": {"name": "no-id"}}
    ]}"#;

    /// `crictl inspect` 兩個 ID：兩個 JSON 物件接在一起
    const CRICTL_INSPECT: &str = r#"{"status": {"id": "aaaabbbbccccddddeeee",
        "image": {"image": "docker.io/library/nginx:1.27"},
        "startedAt": "2026-11-21T01:02:03.5Z", "finishedAt": "1970-01-01T00:00:00Z",
        "mounts": [{"containerPath": "/data", "hostPath": "/srv/data"},
                   {"containerPath": "/run", "hostPath": "/run/containerd/x"}]},
      "info": {"config": {"envs": [{"key": "PASSWORD", "value": "s3cret"}],
               "linux": {"security_context": {"privileged": true,
                         "namespace_options": {"network": 2}}}}}}
    {"status": {"id": "ffff00001111222233334444", "startedAt": "2026-11-20T00:00:00Z",
        "finishedAt": "2026-11-20T00:05:00Z", "mounts": []},
      "info": {"config": {"linux": {"security_context": {"namespace_options": {"network": "POD"}}}}}}"#;

    #[test]
    fn parses_crictl() {
        let v = parse_crictl(CRICTL_PS, CRICTL_INSPECT).unwrap();
        assert_eq!(v.len(), 2, "沒有 id 的略過");
        let n = &v[0];
        assert_eq!(
            (n.runtime.as_str(), n.id.as_str(), n.name.as_str()),
            ("containerd", "aaaabbbbcccc", "nginx")
        );
        assert_eq!(
            n.image, "docker.io/library/nginx:1.27",
            "inspect 的名稱優先"
        );
        assert_eq!(
            n.image_id.as_deref(),
            Some("docker.io/library/nginx@sha256:2222")
        );
        assert_eq!(n.state, "running");
        assert_eq!(
            n.k8s,
            Some(K8sRef {
                namespace: "shop".into(),
                pod: "web-7d9f".into()
            })
        );
        assert_eq!(n.created_at, Some(datetime!(2026-11-22 00:00 UTC)));
        assert_eq!(n.started_at, Some(datetime!(2026-11-21 01:02:03.5 UTC)));
        assert_eq!(n.finished_at, None, "1970 表示沒有");
        assert_eq!((n.privileged, n.host_network), (Some(true), Some(true)));
        assert_eq!(n.host_mounts, ["/run/containerd/x", "/srv/data"]);
        let m = &v[1];
        assert_eq!(
            m.image, "registry.example.com/tools:1",
            "沒有 inspect 名稱時用 ps 的"
        );
        assert_eq!((m.state.as_str(), m.created_at), ("exited", None));
        assert_eq!(m.finished_at, Some(datetime!(2026-11-20 00:05 UTC)));
        assert_eq!(
            (m.privileged, m.host_network, m.k8s.clone()),
            (None, Some(false), None)
        );
        let all = format!("{v:?}");
        assert!(!all.contains("hunter2") && !all.contains("s3cret"), "{all}");

        // inspect 失敗或缺漏：仍有 ps 的基本資料
        let v = parse_crictl(CRICTL_PS, "").unwrap();
        assert_eq!(v[0].image, "sha256:1111");
        assert_eq!(v[0].privileged, None);
        assert!(parse_crictl("not json", "").is_err());
        assert_eq!(cri_state("CONTAINER_UNKNOWN"), "unknown");
        assert_eq!(cri_state("CONTAINER_CREATED"), "created");
    }

    /// `incus list --format json`（刪減）：一個系統容器、一個停止的、一個虛擬機
    const INCUS: &str = r#"[
      {"name": "db", "project": "default", "type": "container", "status": "Running",
       "created_at": "2025-01-01T00:00:00Z", "last_used_at": "2026-11-21T08:00:00Z",
       "config": {"image.os": "Debian", "image.release": "bookworm"},
       "expanded_config": {"security.privileged": "true", "boot.autostart": "true",
                           "volatile.base_image": "abc123", "environment.PASSWORD": "x"},
       "expanded_devices": {"root": {"type": "disk", "path": "/", "pool": "default"},
                            "data": {"type": "disk", "source": "/srv/db", "path": "/var/lib/db"},
                            "eth0": {"type": "nic", "network": "incusbr0"}}},
      {"name": "old", "project": "lab", "type": "container", "status": "Stopped",
       "created_at": "2024-01-01T00:00:00Z", "last_used_at": "2026-11-20T00:00:00Z",
       "config": {"image.description": "Ubuntu noble amd64 (20240101_07:42)"},
       "expanded_config": {}, "expanded_devices": {}},
      {"name": "win", "type": "virtual-machine", "status": "Running"},
      {"type": "container"}
    ]"#;

    #[test]
    fn parses_incus() {
        let v = parse_incus("incus", INCUS).unwrap();
        assert_eq!(v.len(), 2, "虛擬機與沒有名稱的略過");
        let db = &v[0];
        assert_eq!(
            (db.id.as_str(), db.name.as_str(), db.image.as_str()),
            ("db", "db", "Debian bookworm")
        );
        assert_eq!(db.state, "running");
        assert_eq!(db.started_at, Some(datetime!(2026-11-21 08:00 UTC)));
        assert_eq!(db.finished_at, None);
        assert_eq!(db.privileged, Some(true));
        assert_eq!(db.restart_policy.as_deref(), Some("autostart"));
        assert_eq!(db.image_id.as_deref(), Some("abc123"));
        assert_eq!(db.host_mounts, ["/srv/db"]);
        assert!(!format!("{db:?}").contains("PASSWORD"));
        let old = &v[1];
        assert_eq!(old.name, "lab/old", "非預設專案加上專案名稱");
        assert_eq!(old.image, "Ubuntu noble amd64 (20240101_07:42)");
        assert_eq!((old.state.as_str(), old.started_at), ("stopped", None));
        assert_eq!(old.finished_at, Some(datetime!(2026-11-20 00:00 UTC)));
        assert_eq!(
            (old.privileged, old.restart_policy.clone()),
            (Some(false), None)
        );
        assert!(parse_incus("lxc", "{}").is_err());
    }

    #[test]
    fn versions() {
        let out = "Version:  0.1.0\nRuntimeName:  containerd\nRuntimeVersion:  v1.7.22\nRuntimeApiVersion:  v1\n";
        assert_eq!(crictl_runtime_version(out).as_deref(), Some("1.7.22"));
        assert_eq!(crictl_runtime_version("garbage"), None);
        assert_eq!(
            last_word("nerdctl version 1.7.6\n").as_deref(),
            Some("1.7.6")
        );
        assert_eq!(last_word("6.0.0").as_deref(), Some("6.0.0"));
        assert_eq!(last_word(""), None);
    }

    #[test]
    fn parses_docker() {
        let v = parse_inspect("docker", DOCKER, None).unwrap();
        assert_eq!(v.len(), 2, "沒有 Id 的略過");
        let web = &v[0];
        assert_eq!(
            (web.id.as_str(), web.name.as_str(), web.image.as_str()),
            ("3f1c0a9e8b7d", "web", "nginx:1.27")
        );
        assert_eq!(web.image_id.as_deref(), Some("sha256:aaaabbbbcccc"));
        assert_eq!(
            (web.state.as_str(), web.health.as_deref()),
            ("running", Some("healthy"))
        );
        assert_eq!(web.started_at, Some(datetime!(2026-11-21 01:30:00.5 UTC)));
        assert_eq!(web.finished_at, None, "0001 年表示沒有");
        assert_eq!(web.restart_policy.as_deref(), Some("unless-stopped"));
        assert_eq!(
            (web.privileged, web.host_network),
            (Some(true), Some(false))
        );
        assert_eq!(web.ports, ["0.0.0.0:8080->80/tcp", "[::]:8080->80/tcp"]);
        assert_eq!(web.host_mounts, ["/srv/web", "/var/run/docker.sock"]);
        assert_eq!(web.owner, None);
        let job = &v[1];
        assert_eq!((job.host_network, job.ports.len()), (Some(true), 0));
        // 不收集環境變數、參數與標籤
        let all = serde_json::to_string(&v).unwrap();
        for (i, needle) in ["hunter2", "s3cret", "DB_PASSWORD", "Labels", "secret"]
            .iter()
            .enumerate()
        {
            assert!(
                !all.contains(needle),
                "fixture value #{i} leaked into the result"
            );
        }
    }

    #[test]
    fn parses_podman() {
        let v = parse_inspect("podman", PODMAN, Some("alice")).unwrap();
        let api = &v[0];
        assert_eq!(
            (api.name.as_str(), api.image.as_str(), api.state.as_str()),
            ("api", "quay.io/app/api:2.1", "running")
        );
        assert_eq!(api.health.as_deref(), Some("starting"));
        assert_eq!(
            api.created_at,
            Some(datetime!(2026-11-21 02:00:00.000000001 UTC))
        );
        assert_eq!(api.restart_policy, None);
        assert_eq!(api.host_network, Some(false));
        assert_eq!(api.ports, ["0.0.0.0:8000->8000/tcp"]);
        assert_eq!(api.owner.as_deref(), Some("alice"));
        // 欄位缺漏時的預設：名稱用 ID、映像用 Image、狀態未知、沒有連接埠
        let minimal = r#"[{"Id": "0011223344556677", "Image": "sha256:ff",
            "NetworkSettings": {"Ports": {"80/tcp": [{"HostIp": "0.0.0.0"}]}}},
            {"Id": "8899aabbccdd", "NetworkSettings": {}}]"#;
        let v = parse_inspect("docker", minimal, None).unwrap();
        assert_eq!(
            (v[0].name.as_str(), v[0].image.as_str(), v[0].state.as_str()),
            ("001122334455", "sha256:ff", "unknown")
        );
        assert!(v[0].ports.is_empty() && v[1].ports.is_empty() && v[1].image.is_empty());
        assert!(parse_inspect("podman", "{}", None).is_err());
        assert!(parse_inspect("podman", "not json", None).is_err());
        assert!(parse_inspect("podman", "[]", None).unwrap().is_empty());
    }

    #[test]
    fn regular_users_from_passwd() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\n\
                      alice:x:1000:1000::/home/alice:/bin/bash\n\
                      nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n\
                      svc:x:999:999::/var/svc:/bin/false\n\
                      broken:x:abc:1::/x:/bin/sh\n\
                      short:x:1001\n";
        assert_eq!(
            regular_users(passwd, 1000),
            [("alice".to_string(), 1000, "/home/alice".to_string())]
        );
    }

    fn c(
        id: &str,
        state: &str,
        created: OffsetDateTime,
        finished: Option<OffsetDateTime>,
    ) -> ContainerItem {
        ContainerItem {
            runtime: "docker".into(),
            id: id.into(),
            name: id.into(),
            image: "x".into(),
            image_id: None,
            state: state.into(),
            health: None,
            created_at: Some(created),
            started_at: None,
            finished_at: finished,
            restart_policy: None,
            privileged: None,
            host_network: None,
            ports: vec![],
            host_mounts: vec![],
            owner: None,
            k8s: None,
        }
    }

    #[test]
    fn select_keeps_running_and_recent() {
        let now = datetime!(2026-11-22 00:00 UTC);
        let old = now - Duration::days(30);
        let recent = now - Duration::days(2);
        let (v, truncated) = select(
            vec![
                c("old-exited", "exited", old, Some(old)),
                c("recent-exited", "exited", old, Some(recent)),
                c("old-running", "running", old, None),
                c("new-created", "created", recent, None),
                c("old-created", "created", old, None),
                c("old-running", "running", old, None),
                c("paused", "paused", recent, None),
            ],
            now,
        );
        assert!(!truncated);
        let ids: Vec<&str> = v.iter().map(|c| c.id.as_str()).collect();
        // 執行中在前（新的先），已停止的只留 7 天內的；重複的 ID 只留一個
        assert_eq!(
            ids,
            ["paused", "old-running", "new-created", "recent-exited"]
        );

        let many = (0..MAX_CONTAINERS + 3)
            .map(|i| c(&format!("c{i:04}"), "running", recent, None))
            .collect();
        let (v, truncated) = select(many, now);
        assert!(truncated);
        assert_eq!(v.len(), MAX_CONTAINERS);
    }
}
