//! 裝置頁的「容器」分頁（Linux 主機上的 Docker、Podman 容器）。

use askama::Template;
use axum::response::Response;
use protocol::{ContainerItem, ContainersInfo};
use uuid::Uuid;

use super::{fmt_time, render};
use crate::AppState;
use crate::error::AppError;

pub struct RuntimeRow {
    pub kind: &'static str,
    pub version: String,
    pub error: String,
}

pub struct ContainerRow {
    pub name: String,
    pub id: String,
    pub owner: String,
    pub image: String,
    pub state: &'static str,
    pub state_tone: &'static str,
    pub health: &'static str,
    pub health_tone: &'static str,
    /// 執行中：啟動時間；已停止：結束時間
    pub at: String,
    pub ports: Vec<String>,
    pub warnings: Vec<&'static str>,
}

#[derive(Template)]
#[template(path = "containers_tab.html")]
struct ContainersTab {
    loaded: bool,
    runtimes: Vec<RuntimeRow>,
    running: Vec<ContainerRow>,
    stopped: Vec<ContainerRow>,
    truncated: bool,
}

fn runtime_label(kind: &str) -> &'static str {
    match kind {
        "docker" => "Docker",
        "podman" => "Podman",
        "containerd" => "containerd",
        "lxc" => "LXC",
        "incus" => "Incus",
        _ => "其他",
    }
}

fn state_label(state: &str) -> (&'static str, &'static str) {
    match state {
        "running" => ("執行中", "ok"),
        "paused" => ("已暫停", "warn"),
        "restarting" => ("重新啟動中", "warn"),
        "exited" | "stopped" => ("已停止", ""),
        "created" | "configured" => ("已建立", ""),
        "dead" => ("異常終止", "bad"),
        _ => ("未知", ""),
    }
}

fn health_label(health: Option<&str>) -> (&'static str, &'static str) {
    match health {
        Some("healthy") => ("健康", "ok"),
        Some("unhealthy") => ("不健康", "bad"),
        Some("starting") => ("檢查中", "warn"),
        Some(_) => ("未知", ""),
        None => ("", ""),
    }
}

/// 特權、使用主機網路、掛載 docker.sock 或根目錄
pub fn warnings(c: &ContainerItem) -> Vec<&'static str> {
    let mut w = Vec::new();
    if c.privileged == Some(true) {
        w.push("特權");
    }
    if c.host_network == Some(true) {
        w.push("主機網路");
    }
    if c.host_mounts.iter().any(|m| m.ends_with("docker.sock")) {
        w.push("掛載 docker.sock");
    }
    if c.host_mounts.iter().any(|m| m == "/") {
        w.push("掛載根目錄");
    }
    w
}

fn row(st: &AppState, c: ContainerItem) -> ContainerRow {
    let (state, state_tone) = state_label(&c.state);
    let (health, health_tone) = health_label(c.health.as_deref());
    let at = if c.is_running() {
        c.started_at
    } else {
        c.finished_at.or(c.created_at)
    };
    ContainerRow {
        warnings: warnings(&c),
        name: c.name,
        id: c.id,
        owner: c.owner.unwrap_or_default(),
        image: c.image,
        state,
        state_tone,
        health,
        health_tone,
        at: fmt_time(st, at),
        ports: c.ports,
    }
}

/// 這台是否有偵測到容器執行環境（決定裝置頁要不要顯示「容器」分頁）
pub async fn has_runtimes(st: &AppState, id: Uuid) -> Result<bool, sqlx::Error> {
    let n: Option<i32> = sqlx::query_scalar(
        "SELECT jsonb_array_length(data->'runtimes') FROM device_containers \
         WHERE device_id = $1 AND jsonb_typeof(data->'runtimes') = 'array'",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await?;
    Ok(n.unwrap_or(0) > 0)
}

pub async fn device_tab(st: &AppState, id: Uuid) -> Result<Response, AppError> {
    let data: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT data FROM device_containers WHERE device_id = $1")
            .bind(id)
            .fetch_optional(&st.pool)
            .await?;
    let Some(info) = data.and_then(|d| serde_json::from_value::<ContainersInfo>(d).ok()) else {
        return Ok(render(&ContainersTab {
            loaded: false,
            runtimes: vec![],
            running: vec![],
            stopped: vec![],
            truncated: false,
        }));
    };
    let runtimes = info
        .runtimes
        .into_iter()
        .map(|r| RuntimeRow {
            kind: runtime_label(&r.kind),
            version: r.version.unwrap_or_default(),
            error: r.error.unwrap_or_default(),
        })
        .collect();
    let (mut running, mut stopped): (Vec<_>, Vec<_>) = info
        .containers
        .into_iter()
        .partition(ContainerItem::is_running);
    // 有警示的在前，其餘依名稱
    running.sort_by(|a, b| {
        warnings(b)
            .len()
            .cmp(&warnings(a).len())
            .then_with(|| a.name.cmp(&b.name))
    });
    stopped.sort_by(|a, b| {
        b.finished_at
            .or(b.created_at)
            .cmp(&a.finished_at.or(a.created_at))
    });
    Ok(render(&ContainersTab {
        loaded: true,
        runtimes,
        running: running.into_iter().map(|c| row(st, c)).collect(),
        stopped: stopped.into_iter().map(|c| row(st, c)).collect(),
        truncated: info.truncated,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels() {
        for (k, want) in [
            ("docker", "Docker"),
            ("podman", "Podman"),
            ("containerd", "containerd"),
            ("lxc", "LXC"),
            ("incus", "Incus"),
            ("x", "其他"),
        ] {
            assert_eq!(runtime_label(k), want);
        }
        for (s, want) in [
            ("running", "執行中"),
            ("paused", "已暫停"),
            ("restarting", "重新啟動中"),
            ("exited", "已停止"),
            ("stopped", "已停止"),
            ("created", "已建立"),
            ("configured", "已建立"),
            ("dead", "異常終止"),
            ("weird", "未知"),
        ] {
            assert_eq!(state_label(s).0, want);
        }
        for (h, want) in [
            (Some("healthy"), "健康"),
            (Some("unhealthy"), "不健康"),
            (Some("starting"), "檢查中"),
            (Some("odd"), "未知"),
            (None, ""),
        ] {
            assert_eq!(health_label(h).0, want);
        }
    }
}
