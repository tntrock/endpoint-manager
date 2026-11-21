//! `docker inspect`／`podman inspect` 輸出的解析與篩選。
//!
//! 只取規格列出的欄位；環境變數、啟動參數、標籤一律不讀（常含密碼）。

use protocol::{ContainerItem, MAX_CONTAINERS};
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

/// RFC 3339 時間轉 UTC；Docker 用 `0001-01-01T00:00:00Z` 表示「沒有」
fn time_at(v: &Value, path: &[&str]) -> Option<OffsetDateTime> {
    let t = OffsetDateTime::parse(&text(v, path)?, &Rfc3339).ok()?;
    (t.year() >= 1970).then(|| t.to_offset(time::UtcOffset::UTC))
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
