//! 評估：純函式，不碰資料庫。

use std::cmp::Ordering;
use std::collections::HashMap;

use protocol::{Probe, RegKind, RegState, RegistryValue, SecurityInfo};
use serde_json::{Value, json};

use super::matcher::{Glob, cmp_version};
pub use super::rules::registry_key;
use super::rules::{AccountChecks, Check, RegOp, RuleSet, parse_number};

/// 支援 security／registry 區段的最低 Agent 版本：更舊的版本沒有這些資料時，未知原因寫「版本過舊」
pub const CONFIG_AGENT_VERSION: &str = "0.3.0";

/// 細節中最多列出的軟體數
pub const MAX_LISTED: usize = 50;
/// Windows 內建 Guest 帳號的 RID（可能被改名）
const GUEST_RID: u32 = 501;

/// 支援 network 區段與本機事件的最低 Agent 版本
pub const NETWORK_AGENT_VERSION: &str = "0.12.0";

/// 細節中最多列出的多重連線期間數
pub const MAX_PERIODS_LISTED: usize = 5;

/// 細節中最多列出的容器數
pub const MAX_CONTAINERS_LISTED: usize = 20;

/// 一段多重連線期間（`device_dual_homed_periods`）
#[derive(Debug, Clone, PartialEq)]
pub struct PeriodFact {
    pub started_at: time::OffsetDateTime,
    pub ended_at: Option<time::OffsetDateTime>,
    /// 期間開始時的網卡狀態：套用例外設定後重新判斷
    pub nics: Vec<protocol::NetInterface>,
    pub incomplete: bool,
}

/// 多重連線規則用的事實
#[derive(Debug, Clone, PartialEq)]
pub struct NetFacts {
    /// 最近的在前
    pub periods: Vec<PeriodFact>,
    pub sites: std::sync::Arc<Vec<crate::network::SiteNets>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SoftwareFact {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
}

/// 評估所需的裝置事實。Option 為 None 表示從未上傳該區段（os_build 代表 basic）。
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceFacts {
    pub active: bool,
    /// Linux 裝置只評估容器規則，Windows 裝置只評估其他規則
    pub linux: bool,
    pub group_id: Option<i64>,
    pub os_build: Option<String>,
    pub os_ubr: Option<u32>,
    pub software: Option<Vec<SoftwareFact>>,
    pub kbs: Option<Vec<String>>,
    /// 有效（未到期）豁免的規則 id
    pub exempt: Vec<i64>,
    pub security: Option<SecurityInfo>,
    /// 鍵為 registry_key(path, name)
    pub registry: Option<HashMap<(String, String), RegistryValue>>,
    pub services: Option<Vec<ServiceFact>>,
    pub agent_version: Option<String>,
    /// Agent 回報的 Windows Update 狀態（None：從未回報）
    pub update_status: Option<UpdateFact>,
    /// network 區段與多重連線期間（None：從未上傳 network 區段）
    pub network: Option<NetFacts>,
    /// containers 區段（None：從未上傳，容器規則不適用）
    pub containers: Option<protocol::ContainersInfo>,
    /// accounts 區段（Linux；None：從未上傳）
    pub accounts: Option<protocol::AccountsInfo>,
    /// shares 區段（None：從未上傳）
    pub shares: Option<protocol::SharesInfo>,
    /// exposure 區段（None：從未上傳）
    pub exposure: Option<protocol::ExposureInfo>,
    /// permissions 區段（None：從未上傳）
    pub permissions: Option<protocol::PermissionsInfo>,
    /// 評估時的「現在」（病毒碼天數用）：由呼叫端提供，評估本身維持純函式
    pub now: time::OffsetDateTime,
    /// 管理網頁時區的今天：修補的安裝日期是裝置本地日期，「太久沒更新」用它計算天數
    pub today: time::Date,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpdateFact {
    /// applied／conflict／error／unmanaged
    pub state: String,
    pub detail: String,
    pub reboot_pending: bool,
    pub reboot_pending_since: Option<time::OffsetDateTime>,
    pub last_patch_date: Option<time::Date>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServiceFact {
    pub name: String,
    pub start_mode: String,
    pub state: String,
    pub binary_path: Option<String>,
}

/// 服務路徑沒加引號、執行檔路徑含空白、又不在 Windows 目錄底下：可被拿來提權
pub fn unquoted_path(path: &str) -> bool {
    let p = path.trim();
    if p.starts_with('"') {
        return false;
    }
    let lower = p.to_ascii_lowercase();
    let Some(end) = lower.find(".exe") else {
        return false;
    };
    let exe = &lower[..end + 4];
    exe.contains(' ')
        && ![
            "c:\\windows\\",
            "%systemroot%\\",
            "%windir%\\",
            "\\systemroot\\",
        ]
        .iter()
        .any(|d| exe.starts_with(d))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Violating,
    Unknown,
    Exempt,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Violating => "violating",
            Status::Unknown => "unknown",
            Status::Exempt => "exempt",
        }
    }

    pub fn parse(s: &str) -> Option<Status> {
        [Status::Violating, Status::Unknown, Status::Exempt]
            .into_iter()
            .find(|x| x.as_str() == s)
    }

    pub fn label(self) -> &'static str {
        match self {
            Status::Violating => "違規",
            Status::Unknown => "未知",
            Status::Exempt => "豁免",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub rule_id: i64,
    pub status: Status,
    pub detail: Value,
}

/// 更新規則：Agent 沒有回報更新狀態（0.5.0 以前的 Agent 不支援）
fn no_update_status() -> Option<(Status, Value)> {
    Some((Status::Unknown, json!({"reason": "no_update_status"})))
}

fn no_data() -> Option<(Status, Value)> {
    Some((Status::Unknown, json!({"reason": "no_data"})))
}

/// exposure 區段裡和這條規則有關的讀取錯誤：有的話是「未知」，沒有的話符合
fn errors_about(info: &protocol::ExposureInfo, keys: &[&str]) -> Option<(Status, Value)> {
    let errs: Vec<&str> = info
        .errors
        .iter()
        .filter(|e| keys.iter().any(|k| e.contains(k)))
        .map(String::as_str)
        .collect();
    (!errs.is_empty()).then(|| {
        (
            Status::Unknown,
            json!({"reason": "exposure_error", "error": errs.join("；")}),
        )
    })
}

/// 以 S-1- 或 *- 開頭的樣式比對 SID（例如 *-500 是內建 Administrator，改名後也認得），
/// 其他比對名稱
fn account_matches(g: &Glob, a: &protocol::AccountInfo) -> bool {
    let p = g.as_str().trim();
    // get 以位元組切：非 ASCII 開頭時回 None，不會 panic
    let sid_pattern = p.len() > 2
        && (p.get(..2).is_some_and(|x| x.eq_ignore_ascii_case("*-"))
            || p.get(..4).is_some_and(|x| x.eq_ignore_ascii_case("S-1-")));
    if sid_pattern {
        g.is_match(&a.sid)
    } else {
        g.is_match(&a.name)
    }
}

fn listed(items: &[&SoftwareFact]) -> Value {
    Value::Array(
        items
            .iter()
            .take(MAX_LISTED)
            .map(|s| json!({"name": s.name, "version": s.version}))
            .collect(),
    )
}

fn matches(s: &SoftwareFact, name: &Glob, publisher: &Option<Glob>) -> bool {
    name.is_match(&s.name)
        && publisher
            .as_ref()
            .is_none_or(|p| s.publisher.as_deref().is_some_and(|v| p.is_match(v)))
}

fn older(s: &SoftwareFact, than: &str) -> bool {
    s.version
        .as_deref()
        .is_some_and(|v| cmp_version(v, than) == Ordering::Less)
}

/// security／registry 區段沒有資料：Agent 太舊就註明版本過舊，否則是尚未收到
fn missing_config(f: &DeviceFacts) -> Option<(Status, Value)> {
    let outdated = f
        .agent_version
        .as_deref()
        .is_none_or(|v| cmp_version(v, CONFIG_AGENT_VERSION) == Ordering::Less);
    if outdated {
        Some((Status::Unknown, json!({"reason": "agent_outdated"})))
    } else {
        no_data()
    }
}

/// 取出 security 區段的某一項；沒資料或收集失敗時回對應的「未知」結果
fn probe<'a, T>(
    f: &'a DeviceFacts,
    pick: impl FnOnce(&'a SecurityInfo) -> &'a Probe<T>,
) -> Result<&'a T, Option<(Status, Value)>> {
    let Some(sec) = &f.security else {
        return Err(missing_config(f));
    };
    match pick(sec) {
        Probe::Ok(v) => Ok(v),
        Probe::Error(e) => Err(Some((
            Status::Unknown,
            json!({"reason": "probe_error", "error": e}),
        ))),
    }
}

fn service_detail(s: &ServiceFact) -> (Status, Value) {
    (
        Status::Violating,
        json!({"service": s.name, "start_mode": s.start_mode, "state": s.state}),
    )
}

fn registry_check(
    v: &RegistryValue,
    label: &str,
    op: RegOp,
    expected: Option<&str>,
    absent_ok: bool,
) -> Option<(Status, Value)> {
    match v.state {
        RegState::Denied => {
            return Some((
                Status::Unknown,
                json!({"reason": "denied", "registry": label}),
            ));
        }
        RegState::Absent => {
            return match op {
                RegOp::NotExists => None,
                RegOp::Exists => Some((
                    Status::Violating,
                    json!({"registry": label, "reason": "absent"}),
                )),
                _ if absent_ok => None,
                _ => Some((
                    Status::Violating,
                    json!({"registry": label, "reason": "absent"}),
                )),
            };
        }
        RegState::Present => {}
    }
    let expected = expected.unwrap_or("");
    let numeric = matches!(v.kind, RegKind::Dword | RegKind::Qword);
    let nums = (parse_number(&v.data), parse_number(expected));
    let ok = match op {
        RegOp::Exists => true,
        RegOp::NotExists => false,
        RegOp::Contains => v.data.to_lowercase().contains(&expected.to_lowercase()),
        RegOp::Gte | RegOp::Lte => {
            let (Some(a), Some(b)) = nums else {
                return Some((
                    Status::Unknown,
                    json!({"reason": "not_numeric", "registry": label, "actual": v.data}),
                ));
            };
            if op == RegOp::Gte { a >= b } else { a <= b }
        }
        RegOp::Equals | RegOp::NotEquals => {
            let same = match nums {
                (Some(a), Some(b)) if numeric => a == b,
                _ => {
                    v.data.eq_ignore_ascii_case(expected)
                        || v.data.to_lowercase() == expected.to_lowercase()
                }
            };
            if op == RegOp::Equals { same } else { !same }
        }
    };
    if ok {
        return None;
    }
    let mut d = json!({"registry": label, "op": op.as_str(), "actual": v.data});
    if op.needs_expected() {
        d["expected"] = json!(expected);
    }
    Some((Status::Violating, d))
}

/// 去掉例外的網卡；位址全在例外網段內的網卡也去掉
fn filter_nics(
    nics: &[protocol::NetInterface],
    names: &[Glob],
    cidrs: &[(std::net::IpAddr, u8)],
) -> Vec<protocol::NetInterface> {
    let excluded = |addr: &str| {
        addr.split('/')
            .next()
            .and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| {
                cidrs
                    .iter()
                    .any(|c| crate::branch::sites::cidr_contains(c, &ip))
            })
    };
    nics.iter()
        .filter(|i| !names.iter().any(|g| g.is_match(&i.name)))
        .filter_map(|i| {
            let mut i = i.clone();
            let had = !i.addresses.is_empty();
            i.addresses.retain(|a| !excluded(a));
            (!had || !i.addresses.is_empty()).then_some(i)
        })
        .collect()
}

fn check_dual_homed(
    f: &DeviceFacts,
    lookback_days: u32,
    min_duration_secs: u32,
    names: &[Glob],
    cidrs: &[(std::net::IpAddr, u8)],
    only_cross_site: bool,
) -> Option<(Status, Value)> {
    let Some(n) = &f.network else {
        let outdated = f
            .agent_version
            .as_deref()
            .is_none_or(|v| cmp_version(v, NETWORK_AGENT_VERSION) == Ordering::Less);
        return if outdated {
            Some((Status::Unknown, json!({"reason": "agent_outdated"})))
        } else {
            no_data()
        };
    };
    let cutoff = f.now - time::Duration::days(i64::from(lookback_days));
    let hits: Vec<Value> = n
        .periods
        .iter()
        .filter(|p| p.ended_at.is_none_or(|e| e >= cutoff))
        .filter(|p| {
            (p.ended_at.unwrap_or(f.now) - p.started_at).whole_seconds()
                >= i64::from(min_duration_secs)
        })
        .filter_map(|p| {
            let dh = crate::network::dual_homed(&filter_nics(&p.nics, names, cidrs), &n.sites)?;
            if only_cross_site && !matches!(dh, crate::network::DualHomed::CrossesSite { .. }) {
                return None;
            }
            let mut v = json!({
                "started": super::display_time(p.started_at),
                "detail": dh.describe(),
            });
            // 持續中的不記長度：每次評估都會變，細節一直更新沒有意義
            match p.ended_at {
                Some(e) => v["duration_secs"] = json!((e - p.started_at).whole_seconds()),
                None => v["ongoing"] = json!(true),
            }
            if p.incomplete {
                v["incomplete"] = json!(true);
            }
            Some(v)
        })
        .collect();
    if hits.is_empty() {
        return None;
    }
    Some((
        Status::Violating,
        json!({
            "dual_homed": hits.iter().take(MAX_PERIODS_LISTED).collect::<Vec<_>>(),
            "count": hits.len(),
            "lookback_days": lookback_days,
        }),
    ))
}

/// 映像參照拆成倉庫、版本標籤與是否帶 digest
struct ImageRef<'a> {
    repo: &'a str,
    tag: Option<&'a str>,
    digest: bool,
}

fn image_ref(image: &str) -> ImageRef<'_> {
    let (name, digest) = match image.split_once('@') {
        Some((n, _)) => (n, true),
        None => (image, false),
    };
    // 冒號在最後一個斜線之後才是版本標籤（registry:5000/app 的冒號是連接埠）
    let slash = name.rfind('/').map_or(0, |i| i + 1);
    match name[slash..].rfind(':') {
        Some(i) => ImageRef {
            repo: &name[..slash + i],
            tag: Some(&name[slash + i + 1..]),
            digest,
        },
        None => ImageRef {
            repo: name,
            tag: None,
            digest,
        },
    }
}

/// Docker Hub 的完整寫法去掉前綴：containerd 回報 `docker.io/library/nginx:1`，Docker 回報 `nginx:1`
fn short_image(image: &str) -> &str {
    [
        "docker.io/library/",
        "index.docker.io/library/",
        "docker.io/",
        "index.docker.io/",
    ]
    .iter()
    .find_map(|p| image.strip_prefix(p))
    .unwrap_or(image)
}

/// 映像樣式比對完整寫法、去掉 Docker Hub 前綴的寫法，以及兩者不含版本標籤的倉庫名稱：
/// `nginx` 符合 `nginx:1.27` 與 `docker.io/library/nginx:1.27`
pub fn image_matches(g: &Glob, image: &str) -> bool {
    let short = short_image(image);
    [image, short, image_ref(image).repo, image_ref(short).repo]
        .iter()
        .any(|s| g.is_match(s))
}

/// 沒有版本標籤或標籤是 latest，而且沒有 digest。以映像 ID 參照（`sha256:…`）算固定。
fn unpinned(image: &str) -> bool {
    let is_id = image.starts_with("sha256:")
        || (image.len() == 64 && image.bytes().all(|b| b.is_ascii_hexdigit()));
    let r = image_ref(image);
    !is_id && !image.is_empty() && !r.digest && r.tag.is_none_or(|t| t == "latest")
}

/// 掛載的是容器執行環境的 socket：等於可以控制主機上所有容器
fn runtime_socket(path: &str) -> bool {
    let file = path.rsplit('/').next().unwrap_or(path);
    matches!(
        file,
        "docker.sock" | "podman.sock" | "containerd.sock" | "crio.sock"
    )
}

fn container_entry(c: &protocol::ContainerItem, issues: &[&str]) -> Value {
    let name = match &c.k8s {
        Some(k) => format!("{}/{}", k.namespace, c.name),
        None => c.name.clone(),
    };
    let mut v = json!({"name": name, "image": c.image});
    if !issues.is_empty() {
        v["issues"] = json!(issues);
    }
    v
}

/// 容器規則的共同流程：沒有 containers 區段不適用；有符合的容器就違規；
/// 都沒有但有執行環境讀取失敗就是未知（失敗的那個環境可能有符合的容器）
fn check_containers(
    f: &DeviceFacts,
    check: &str,
    hit: impl Fn(&protocol::ContainerItem) -> Option<Vec<&'static str>>,
    undetermined: usize,
) -> Option<(Status, Value)> {
    let info = f.containers.as_ref()?;
    let hits: Vec<Value> = info
        .containers
        .iter()
        .filter_map(|c| hit(c).map(|issues| container_entry(c, &issues)))
        .collect();
    if !hits.is_empty() {
        let mut d = json!({
            "check": check,
            "containers": hits.iter().take(MAX_CONTAINERS_LISTED).collect::<Vec<_>>(),
            "total": hits.len(),
        });
        if undetermined > 0 {
            d["undetermined"] = json!(undetermined);
        }
        return Some((Status::Violating, d));
    }
    let errors: Vec<String> = info
        .runtimes
        .iter()
        .filter_map(|r| r.error.as_ref().map(|e| format!("{}：{e}", r.kind)))
        .collect();
    (!errors.is_empty()).then(|| {
        (
            Status::Unknown,
            json!({"reason": "probe_error", "error": errors.join("；")}),
        )
    })
}

fn excepted(except: &[Glob], image: &str) -> bool {
    except.iter().any(|g| image_matches(g, image))
}

fn privilege_issues(
    c: &protocol::ContainerItem,
    privileged: bool,
    host_network: bool,
    socket: bool,
) -> Vec<&'static str> {
    let mut v = vec![];
    if privileged && c.privileged == Some(true) {
        v.push("特權");
    }
    if host_network && c.host_network == Some(true) {
        v.push("主機網路");
    }
    if socket && c.host_mounts.iter().any(|m| runtime_socket(m)) {
        v.push("掛載容器 socket");
    }
    v
}

/// 權限過寬項目種類的顯示名稱
pub fn permission_label(kind: &str) -> &'static str {
    match kind {
        "service_binary" => "服務執行檔可改寫",
        "service_dir" => "服務資料夾可新增檔案",
        "task_binary" => "SYSTEM 排程工作的程式可改寫",
        "etc_writable" => "所有人可寫入",
        "shadow_readable" => "所有人可讀取",
        "suid" => "不屬於任何套件的 SUID 程式",
        _ => "權限過寬",
    }
}

/// 權限過寬的一筆：`種類 路徑（名稱；給了誰）`
pub fn permission_text(kind: &str, path: &str, name: Option<&str>, granted_to: &[&str]) -> String {
    let mut extra: Vec<String> = vec![];
    if let Some(n) = name {
        extra.push(n.to_string());
    }
    if !granted_to.is_empty() && !matches!(kind, "etc_writable" | "shadow_readable") {
        extra.push(granted_to.join("、"));
    }
    if extra.is_empty() {
        format!("{} {path}", permission_label(kind))
    } else {
        format!("{} {path}（{}）", permission_label(kind), extra.join("；"))
    }
}

/// 帳號設定（錯誤設定規格 §6.2）：只看適用這台作業系統的勾選項目
fn account_flags(f: &DeviceFacts, c: &AccountChecks, except: &[Glob]) -> Option<(Status, Value)> {
    let Some(a) = &f.accounts else {
        return no_data();
    };
    if !a.flags {
        return Some((Status::Unknown, json!({"reason": "agent_outdated"})));
    }
    let excepted = |n: &str| except.iter().any(|g| g.is_match(n));
    // 停用或鎖定的帳號不能登入，不算
    let usable = a
        .users
        .iter()
        .filter(|u| !u.disabled && u.locked != Some(true));
    let mut issues: Vec<String> = vec![];
    if c.no_password {
        for u in usable.clone() {
            if u.no_password == Some(true) && !excepted(&u.name) {
                issues.push(format!("{} 沒有密碼", u.name));
            }
        }
    }
    if f.linux {
        if c.sudo_nopasswd {
            for p in a.privileged.iter().filter(|p| p.nopasswd_all) {
                let who = match p.kind {
                    protocol::PrincipalKind::Group => format!("%{}", p.principal),
                    protocol::PrincipalKind::User => p.principal.clone(),
                };
                if !excepted(&who) {
                    issues.push(format!("{who} 可以免密碼 sudo 執行任何指令"));
                }
            }
        }
    } else {
        if c.guest_disabled
            && let Some(g) = a.users.iter().find(|u| u.uid == GUEST_RID && !u.disabled)
        {
            issues.push(format!("Guest 帳號（{}）已啟用", g.name));
        }
        if c.password_expires {
            for u in usable {
                if u.password_never_expires && !excepted(&u.name) {
                    issues.push(format!("{} 密碼永不過期", u.name));
                }
            }
        }
        if c.no_autologon_password && a.autologon_password == Some(true) {
            issues.push("自動登入存了密碼".into());
        }
    }
    issues.dedup();
    if issues.is_empty() {
        // 有項目讀不到：不能說一定沒有
        return (!a.errors.is_empty()).then(|| {
            (
                Status::Unknown,
                json!({"reason": "account_error", "error": a.errors.join("；")}),
            )
        });
    }
    Some((
        Status::Violating,
        json!({"account_issues": issues.iter().take(MAX_LISTED).collect::<Vec<_>>(),
               "total": issues.len()}),
    ))
}

fn check_one(c: &Check, f: &DeviceFacts) -> Option<(Status, Value)> {
    match c {
        Check::UnquotedServicePath { except_services } => {
            let Some(services) = &f.services else {
                return no_data();
            };
            let bad: Vec<Value> = services
                .iter()
                .filter(|s| !except_services.iter().any(|g| g.is_match(&s.name)))
                .filter_map(|s| {
                    let p = s.binary_path.as_deref()?;
                    unquoted_path(p).then(|| json!({"service": s.name, "path": p}))
                })
                .collect();
            (!bad.is_empty()).then(|| {
                (
                    Status::Violating,
                    json!({"unquoted": bad.iter().take(MAX_LISTED).collect::<Vec<_>>(),
                           "total": bad.len()}),
                )
            })
        }
        Check::ExposedService {
            ports,
            any_interface_only,
            except_processes,
        } => {
            let Some(info) = &f.exposure else {
                return no_data();
            };
            let bad: Vec<Value> = info
                .listening
                .iter()
                .filter(|l| !*any_interface_only || l.any_interface())
                .filter(|l| {
                    !except_processes
                        .iter()
                        .any(|g| l.process.as_deref().is_some_and(|p| g.is_match(p)))
                })
                .filter_map(|l| {
                    let (_, label) = ports.iter().find(|(p, _)| *p == l.port)?;
                    Some(json!({"service": label, "port": l.port, "proto": l.proto,
                                "addr": l.addr, "process": l.process}))
                })
                .collect();
            if bad.is_empty() {
                return errors_about(info, &["連接埠", "/proc/net"]);
            }
            Some((
                Status::Violating,
                json!({"services": bad.iter().take(MAX_LISTED).collect::<Vec<_>>(),
                       "total": bad.len()}),
            ))
        }
        Check::FirewallAllowAll { except_rules } => {
            let Some(info) = &f.exposure else {
                return no_data();
            };
            let Some(rules) = &info.firewall_allow_all else {
                return errors_about(info, &["防火牆"]).or_else(no_data);
            };
            let bad: Vec<&str> = rules
                .iter()
                .filter(|r| !except_rules.iter().any(|g| g.is_match(r)))
                .map(String::as_str)
                .collect();
            (!bad.is_empty()).then(|| {
                (
                    Status::Violating,
                    json!({"firewall_rules": bad.iter().take(MAX_LISTED).collect::<Vec<_>>(),
                           "total": bad.len()}),
                )
            })
        }
        Check::SshConfig(p) => {
            let Some(info) = &f.exposure else {
                return no_data();
            };
            // 沒有安裝 sshd：符合；讀取失敗：未知
            let Some(s) = &info.sshd else {
                return errors_about(info, &["sshd"]);
            };
            let root = s.permit_root_login.as_str();
            let mut issues = vec![];
            if p.no_root_login && root != "no" {
                issues.push("允許 root 登入");
            } else if p.no_root_password && matches!(root, "yes" | "") {
                issues.push("允許 root 以密碼登入");
            }
            if p.no_password && s.password_authentication {
                issues.push("允許密碼登入");
            }
            if p.no_empty_passwords && s.permit_empty_passwords {
                issues.push("允許空密碼");
            }
            (!issues.is_empty()).then(|| (Status::Violating, json!({"ssh": issues})))
        }
        Check::RdpUsers { allowed } => {
            let Some(info) = &f.exposure else {
                return no_data();
            };
            let Some(r) = &info.rdp else {
                return errors_about(info, &["遠端桌面"]).or_else(no_data);
            };
            if !r.enabled {
                return None;
            }
            let bad: Vec<&str> = r
                .users
                .iter()
                .filter(|a| !allowed.iter().any(|g| account_matches(g, a)))
                .map(|a| a.name.as_str())
                .collect();
            (!bad.is_empty()).then(|| {
                (
                    Status::Violating,
                    json!({"rdp_users": bad.iter().take(MAX_LISTED).collect::<Vec<_>>(),
                           "total": bad.len()}),
                )
            })
        }
        Check::AccountFlags {
            checks,
            except_accounts,
        } => account_flags(f, checks, except_accounts),
        Check::WeakPermissions { except_paths } => {
            let Some(info) = &f.permissions else {
                return no_data();
            };
            let bad: Vec<Value> = info
                .items
                .iter()
                .filter(|x| {
                    !except_paths.iter().any(|g| {
                        g.is_match(&x.path) || x.name.as_deref().is_some_and(|n| g.is_match(n))
                    })
                })
                .map(|x| {
                    json!({"kind": x.kind, "path": x.path, "name": x.name,
                           "granted_to": x.granted_to})
                })
                .collect();
            if bad.is_empty() {
                // 部分項目讀不到：不能說一定沒有
                return (!info.errors.is_empty()).then(|| {
                    (
                        Status::Unknown,
                        json!({"reason": "permission_error", "error": info.errors.join("；")}),
                    )
                });
            }
            Some((
                Status::Violating,
                json!({"permissions": bad.iter().take(MAX_LISTED).collect::<Vec<_>>(),
                       "total": bad.len()}),
            ))
        }
        Check::OpenShare {
            anonymous,
            all_users,
            write_only,
            no_root_squash,
            except_shares,
        } => {
            let Some(info) = &f.shares else {
                return no_data();
            };
            let min = if *write_only {
                protocol::ShareAccess::Write
            } else {
                protocol::ShareAccess::Read
            };
            let verb = |a: protocol::ShareAccess| {
                if a == protocol::ShareAccess::Write {
                    "可寫入"
                } else {
                    "可讀取"
                }
            };
            let bad: Vec<Value> = info
                .shares
                .iter()
                .filter(|s| {
                    !except_shares
                        .iter()
                        .any(|g| g.is_match(&s.name) || g.is_match(&s.path))
                })
                .filter_map(|s| {
                    let mut issues = vec![];
                    // 匿名已經算了就不重複列「所有使用者」
                    if *anonymous && s.anonymous >= min {
                        issues.push(format!("匿名{}", verb(s.anonymous)));
                    } else if *all_users && s.all_users >= min {
                        issues.push(format!("所有使用者{}", verb(s.all_users)));
                    }
                    if *no_root_squash && s.no_root_squash {
                        issues.push("no_root_squash".to_string());
                    }
                    (!issues.is_empty()).then(|| {
                        json!({"name": s.name, "kind": s.kind, "path": s.path, "issues": issues})
                    })
                })
                .collect();
            if bad.is_empty() {
                // 部分來源讀不到：不能說一定沒有
                return (!info.errors.is_empty()).then(|| {
                    (
                        Status::Unknown,
                        json!({"reason": "share_error", "error": info.errors.join("；")}),
                    )
                });
            }
            Some((
                Status::Violating,
                json!({"shares": bad.iter().take(MAX_LISTED).collect::<Vec<_>>(),
                       "total": bad.len()}),
            ))
        }
        Check::ExtraRootAccount { except_accounts } => {
            let Some(a) = &f.accounts else {
                return no_data();
            };
            let mut bad: Vec<&str> = a
                .privileged
                .iter()
                .filter(|p| p.source == "uid0" && p.principal != "root")
                .map(|p| p.principal.as_str())
                .filter(|n| !except_accounts.iter().any(|g| g.is_match(n)))
                .collect();
            bad.sort_unstable();
            bad.dedup();
            (!bad.is_empty()).then(|| {
                (
                    Status::Violating,
                    json!({"root_accounts": bad.iter().take(MAX_LISTED).collect::<Vec<_>>(),
                           "total": bad.len()}),
                )
            })
        }
        Check::ForbiddenImage {
            image,
            running_only,
        } => check_containers(
            f,
            "forbidden",
            |c| {
                ((!running_only || c.is_running()) && image_matches(image, &c.image)).then(Vec::new)
            },
            0,
        ),
        Check::ContainerPrivilege {
            privileged,
            host_network,
            runtime_socket: socket,
            except_images,
        } => {
            let (p, h, s) = (*privileged, *host_network, *socket);
            let in_scope =
                |c: &protocol::ContainerItem| c.is_running() && !excepted(except_images, &c.image);
            // 讀不到特權或主機網路、其他勾選條件也沒命中的容器：不計入，細節註明數量
            let undetermined = f.containers.as_ref().map_or(0, |i| {
                i.containers
                    .iter()
                    .filter(|c| in_scope(c) && privilege_issues(c, p, h, s).is_empty())
                    .filter(|c| (p && c.privileged.is_none()) || (h && c.host_network.is_none()))
                    .count()
            });
            check_containers(
                f,
                "privilege",
                |c| Some(privilege_issues(c, p, h, s)).filter(|v| in_scope(c) && !v.is_empty()),
                undetermined,
            )
        }
        Check::UnpinnedImage { except_images } => check_containers(
            f,
            "unpinned",
            |c| {
                // 系統容器（LXC／Incus）的映像沒有版本標籤的概念
                (c.is_running()
                    && !matches!(c.runtime.as_str(), "lxc" | "incus")
                    && unpinned(&c.image)
                    && !excepted(except_images, &c.image))
                .then(Vec::new)
            },
            0,
        ),
        Check::PatchAge { max_days } => {
            let Some(u) = &f.update_status else {
                return no_update_status();
            };
            let Some(last) = u.last_patch_date else {
                return Some((Status::Unknown, json!({"reason": "no_patch_date"})));
            };
            let days = (f.today - last).whole_days();
            (days > i64::from(*max_days)).then(|| {
                (
                    Status::Violating,
                    json!({"last_patch_date": last.to_string(), "days": days}),
                )
            })
        }
        Check::RebootPending { max_days } => {
            let Some(u) = &f.update_status else {
                return no_update_status();
            };
            // 沒有起始時間無法判斷天數：不算違規
            let since = u.reboot_pending_since.filter(|_| u.reboot_pending)?;
            let days = (f.now - since).whole_days();
            (days > i64::from(*max_days)).then(|| {
                (
                    Status::Violating,
                    json!({"reboot_pending_since": offset_rfc3339(since), "days": days}),
                )
            })
        }
        Check::DualHomed {
            lookback_days,
            min_duration_secs,
            exclude_interfaces,
            exclude_cidrs,
            only_cross_site,
        } => check_dual_homed(
            f,
            *lookback_days,
            *min_duration_secs,
            exclude_interfaces,
            exclude_cidrs,
            *only_cross_site,
        ),
        Check::UpdatePolicy => {
            let Some(u) = &f.update_status else {
                return no_update_status();
            };
            matches!(u.state.as_str(), "conflict" | "error").then(|| {
                (
                    Status::Violating,
                    json!({"update_state": u.state, "update_detail": u.detail}),
                )
            })
        }
        Check::RegistryValue {
            path,
            name,
            key,
            op,
            expected,
            absent_ok,
        } => {
            let Some(reg) = &f.registry else {
                return missing_config(f);
            };
            let label = format!("{path}\\{name}");
            let Some(v) = reg.get(key) else {
                return Some((
                    Status::Unknown,
                    json!({"reason": "not_collected", "registry": label}),
                ));
            };
            registry_check(v, &label, *op, expected.as_deref(), *absent_ok)
        }
        Check::ServiceState {
            name,
            require_running,
        } => {
            let Some(services) = &f.services else {
                return no_data();
            };
            let svc = services.iter().find(|s| s.name.eq_ignore_ascii_case(name));
            let disabled = |s: &ServiceFact| s.start_mode.eq_ignore_ascii_case("Disabled");
            match (svc, require_running) {
                (None, false) => None,
                (None, true) => Some((
                    Status::Violating,
                    json!({"reason": "not_installed", "service": name}),
                )),
                (Some(s), false) => (!disabled(s)).then(|| service_detail(s)),
                (Some(s), true) => (disabled(s) || !s.state.eq_ignore_ascii_case("Running"))
                    .then(|| service_detail(s)),
            }
        }
        Check::Firewall {
            domain,
            private,
            public,
        } => {
            let fw = match probe(f, |s| &s.firewall) {
                Ok(v) => v,
                Err(u) => return u,
            };
            let off: Vec<&str> = [
                ("domain", *domain, fw.domain),
                ("private", *private, fw.private),
                ("public", *public, fw.public),
            ]
            .into_iter()
            .filter(|(_, required, on)| *required && !on)
            .map(|(n, _, _)| n)
            .collect();
            (!off.is_empty()).then(|| (Status::Violating, json!({"profiles_off": off})))
        }
        Check::Bitlocker { all_fixed } => {
            let vols = match probe(f, |s| &s.bitlocker) {
                Ok(v) => v,
                Err(u) => return u,
            };
            let in_scope: Vec<_> = vols.iter().filter(|v| *all_fixed || v.is_system).collect();
            if in_scope.is_empty() {
                return Some((Status::Violating, json!({"reason": "no_system_volume"})));
            }
            let bad: Vec<&str> = in_scope
                .iter()
                .filter(|v| !v.protected)
                .map(|v| v.drive.as_str())
                .collect();
            (!bad.is_empty()).then(|| (Status::Violating, json!({"drives": bad})))
        }
        Check::Defender {
            realtime,
            max_signature_age_days,
            tamper,
        } => {
            let d = match probe(f, |s| &s.defender) {
                Ok(v) => v,
                Err(u) => return u,
            };
            if !d.active {
                return Some((Status::Unknown, json!({"reason": "defender_inactive"})));
            }
            let mut failed = vec![];
            let mut detail = serde_json::Map::new();
            if *realtime && !d.realtime {
                failed.push("realtime");
            }
            if *tamper && !d.tamper {
                failed.push("tamper");
            }
            // 病毒碼日期未知不能蓋掉其他已確定的違規：先看其他項，全部通過才回報未知
            let mut signature_unknown = false;
            if let Some(max) = max_signature_age_days {
                match d.signature_updated {
                    None => signature_unknown = true,
                    Some(updated) => {
                        let age = (f.now - updated).whole_days().max(0);
                        if age > i64::from(*max) {
                            failed.push("signature");
                            detail.insert("signature_age_days".into(), json!(age));
                        }
                    }
                }
            }
            if failed.is_empty() {
                return signature_unknown
                    .then(|| (Status::Unknown, json!({"reason": "signature_unknown"})));
            }
            detail.insert("failed".into(), json!(failed));
            Some((Status::Violating, Value::Object(detail)))
        }
        Check::PasswordPolicy {
            min_length,
            max_age_days,
            max_lockout_threshold,
        } => {
            let p = match probe(f, |s| &s.password) {
                Ok(v) => v,
                Err(u) => return u,
            };
            let mut failed = vec![];
            let mut detail = serde_json::Map::new();
            if let Some(req) = min_length
                && p.min_length < *req
            {
                failed.push("min_length");
                detail.insert("min_length".into(), json!(p.min_length));
                detail.insert("required_min_length".into(), json!(req));
            }
            // 0 = 永不過期、不鎖定：一律算不符合
            if let Some(req) = max_age_days
                && (p.max_age_days == 0 || p.max_age_days > *req)
            {
                failed.push("max_age_days");
                detail.insert("max_age_days".into(), json!(p.max_age_days));
                detail.insert("required_max_age_days".into(), json!(req));
            }
            if let Some(req) = max_lockout_threshold
                && (p.lockout_threshold == 0 || p.lockout_threshold > *req)
            {
                failed.push("lockout_threshold");
                detail.insert("lockout_threshold".into(), json!(p.lockout_threshold));
                detail.insert("required_lockout_threshold".into(), json!(req));
            }
            if failed.is_empty() {
                return None;
            }
            detail.insert("failed".into(), json!(failed));
            Some((Status::Violating, Value::Object(detail)))
        }
        Check::LocalAdmins { allowed } => {
            let admins = match probe(f, |s| &s.admins) {
                Ok(v) => v,
                Err(u) => return u,
            };
            let bad: Vec<&str> = admins
                .iter()
                .filter(|a| !allowed.iter().any(|g| account_matches(g, a)))
                .map(|a| a.name.as_str())
                .collect();
            (!bad.is_empty()).then(|| {
                (
                    Status::Violating,
                    json!({"accounts": bad.iter().take(MAX_LISTED).collect::<Vec<_>>(), "total": bad.len()}),
                )
            })
        }
        Check::Forbidden {
            name,
            publisher,
            below,
        } => {
            let Some(sw) = &f.software else {
                return no_data();
            };
            let hits: Vec<&SoftwareFact> =
                sw.iter().filter(|s| matches(s, name, publisher)).collect();
            let Some(below) = below else {
                return (!hits.is_empty())
                    .then(|| (Status::Violating, json!({"software": listed(&hits)})));
            };
            let old: Vec<&SoftwareFact> =
                hits.iter().copied().filter(|s| older(s, below)).collect();
            let unversioned: Vec<&SoftwareFact> = hits
                .iter()
                .copied()
                .filter(|s| s.version.is_none())
                .collect();
            if !old.is_empty() {
                Some((Status::Violating, json!({"software": listed(&old)})))
            } else if !unversioned.is_empty() {
                Some((
                    Status::Unknown,
                    json!({"reason": "version_missing", "software": listed(&unversioned)}),
                ))
            } else {
                None
            }
        }
        Check::Required {
            name,
            publisher,
            min,
        } => {
            let Some(sw) = &f.software else {
                return no_data();
            };
            let hits: Vec<&SoftwareFact> =
                sw.iter().filter(|s| matches(s, name, publisher)).collect();
            if hits.is_empty() {
                return Some((Status::Violating, json!({"reason": "missing"})));
            }
            let min = min.as_ref()?;
            let ok = hits.iter().any(|s| s.version.is_some() && !older(s, min));
            if ok {
                None
            } else if hits.iter().any(|s| s.version.is_none()) {
                Some((
                    Status::Unknown,
                    json!({"reason": "version_missing", "software": listed(&hits)}),
                ))
            } else {
                Some((
                    Status::Violating,
                    json!({"reason": "outdated", "software": listed(&hits)}),
                ))
            }
        }
        Check::Allowlist { entries } => {
            let Some(sw) = &f.software else {
                return no_data();
            };
            let offenders: Vec<&SoftwareFact> = sw
                .iter()
                .filter(|s| {
                    !entries.iter().any(|(n, p)| {
                        n.as_ref().is_none_or(|n| n.is_match(&s.name))
                            && p.as_ref().is_none_or(|p| {
                                s.publisher.as_deref().is_some_and(|v| p.is_match(v))
                            })
                    })
                })
                .collect();
            (!offenders.is_empty()).then(|| {
                (
                    Status::Violating,
                    json!({"software": listed(&offenders), "total": offenders.len()}),
                )
            })
        }
        Check::MinBuild { min_build } => {
            let Some(build) = &f.os_build else {
                return no_data();
            };
            match build.trim().parse::<u32>() {
                Ok(b) if b < *min_build => Some((Status::Violating, json!({"build": build}))),
                Ok(_) => None,
                Err(_) => Some((
                    Status::Unknown,
                    json!({"reason": "build_unparsable", "build": build}),
                )),
            }
        }
        Check::PatchLevel {
            build: want,
            min_ubr,
        } => {
            let Some(build) = &f.os_build else {
                return no_data();
            };
            match build.trim().parse::<u32>() {
                Ok(b) if b != *want => None,
                Ok(_) => match f.os_ubr {
                    None => Some((
                        Status::Unknown,
                        json!({"reason": "ubr_missing", "build": build}),
                    )),
                    Some(u) if u < *min_ubr => Some((
                        Status::Violating,
                        json!({"build": build, "ubr": u, "min_ubr": min_ubr}),
                    )),
                    Some(_) => None,
                },
                Err(_) => Some((
                    Status::Unknown,
                    json!({"reason": "build_unparsable", "build": build}),
                )),
            }
        }
        Check::RequiredKb { kb } => {
            let Some(kbs) = &f.kbs else {
                return no_data();
            };
            (!kbs.iter().any(|k| k.eq_ignore_ascii_case(kb)))
                .then(|| (Status::Violating, json!({"kb": kb})))
        }
    }
}

fn software_list(d: &Value) -> String {
    let items = d["software"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    let mut s = items
        .iter()
        .map(|i| {
            let name = i["name"].as_str().unwrap_or("");
            match i["version"].as_str() {
                Some(v) => format!("{name} {v}"),
                None => name.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join("、");
    // 白名單細節只列前 50 筆，另附總數
    if let Some(total) = d["total"].as_u64()
        && total as usize > items.len()
    {
        s = format!("{s} 等 {total} 套");
    }
    s
}

fn container_summary(d: &Value, items: &[Value]) -> String {
    let list = items
        .iter()
        .map(|c| {
            let name = c["name"].as_str().unwrap_or("");
            let image = c["image"].as_str().unwrap_or("");
            match c["issues"].as_array() {
                Some(i) => {
                    let i: Vec<&str> = i.iter().filter_map(Value::as_str).collect();
                    format!("{name}（{image}：{}）", i.join("、"))
                }
                None => format!("{name}（{image}）"),
            }
        })
        .collect::<Vec<_>>()
        .join("、");
    let total = d["total"].as_u64().unwrap_or_default();
    let more = if total as usize > items.len() {
        format!(" 等 {total} 個")
    } else {
        String::new()
    };
    let head = match d["check"].as_str() {
        Some("forbidden") => "使用禁止的映像",
        Some("unpinned") => "映像未固定版本",
        _ => "權限過大",
    };
    let mut s = format!("{head}：{list}{more}");
    if let Some(n) = d["undetermined"].as_u64() {
        s.push_str(&format!("；另有 {n} 個容器無法判斷"));
    }
    s
}

/// 給人看的一行摘要（網頁、CSV、通知共用）。
pub fn summarize(d: &Value) -> String {
    let s = |k: &str| d[k].as_str().unwrap_or("").to_string();
    match d["reason"].as_str() {
        Some("no_data") => return "尚未收到盤點資料".into(),
        Some("rule_error") => return format!("規則參數錯誤：{}", s("error")),
        Some("missing") => return "未安裝".into(),
        Some("outdated") => return format!("版本過舊：{}", software_list(d)),
        Some("version_missing") => return format!("版本不明：{}", software_list(d)),
        Some("ubr_missing") => return format!("Agent 未回報 UBR（組建 {}）", s("build")),
        Some("build_unparsable") => return format!("無法解析組建號：{}", s("build")),
        Some("agent_outdated") => return "Agent 版本過舊，未回報這項資料".into(),
        Some("not_collected") => return "Agent 尚未回報這個登錄檔值".into(),
        Some("denied") => return "不允許讀取這個登錄檔值".into(),
        Some("defender_inactive") => return "Defender 不是作用中的防毒".into(),
        Some("probe_error") => return format!("收集失敗：{}", s("error")),
        Some("not_numeric") => return format!("{} = {}，不是數字", s("registry"), s("actual")),
        Some("signature_unknown") => return "無法取得病毒碼更新時間".into(),
        Some("no_system_volume") => return "找不到系統磁碟".into(),
        Some("not_installed") => return format!("服務 {} 未安裝", s("service")),
        Some("absent") => return format!("{} 未設定", s("registry")),
        Some("no_patch_date") => return "沒有可判讀的更新安裝日期".into(),
        Some("share_error") => return format!("無法讀取共用：{}", s("error")),
        Some("exposure_error") => return format!("無法讀取：{}", s("error")),
        Some("account_error") => return format!("無法讀取帳號：{}", s("error")),
        Some("permission_error") => return format!("無法讀取權限：{}", s("error")),
        Some("no_update_status") => {
            return "Agent 尚未回報更新狀態（需要 Agent 0.5.0 以上）".into();
        }
        _ => {}
    }
    if let Some(items) = d["containers"].as_array() {
        return container_summary(d, items);
    }
    if let Some(first) = d["dual_homed"].as_array().and_then(|a| a.first()) {
        let when = if first["ongoing"].as_bool() == Some(true) {
            format!("{} 起持續中", first["started"].as_str().unwrap_or(""))
        } else {
            format!(
                "{}，持續 {}",
                first["started"].as_str().unwrap_or(""),
                crate::network::duration_label(time::Duration::seconds(
                    first["duration_secs"].as_i64().unwrap_or_default()
                ))
            )
        };
        return format!(
            "{} 天內多重連線 {} 次，最近一次：{when}（{}）",
            d["lookback_days"].as_u64().unwrap_or_default(),
            d["count"].as_u64().unwrap_or_default(),
            first["detail"].as_str().unwrap_or("")
        );
    }
    let days = d["days"].as_i64().unwrap_or_default();
    if d.get("last_patch_date").is_some() {
        return format!("最後裝更新：{}（{days} 天前）", s("last_patch_date"));
    }
    if d.get("reboot_pending_since").is_some() {
        return format!("待重開機已 {days} 天");
    }
    if let Some(state) = d["update_state"].as_str() {
        let what = if state == "conflict" {
            "原則被改動"
        } else {
            "原則套用失敗"
        };
        return format!("{what}：{}", s("update_detail"));
    }
    let list = |k: &str| {
        d[k].as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join("、")
            })
            .unwrap_or_default()
    };
    if d.get("registry").is_some() {
        let op = super::rules::RegOp::parse(&s("op"))
            .map(|o| o.label())
            .unwrap_or("");
        return if d.get("expected").is_some() {
            format!(
                "{} = {}，要求 {op} {}",
                s("registry"),
                s("actual"),
                s("expected")
            )
        } else {
            format!("{} 存在，要求 {op}", s("registry"))
        };
    }
    if d.get("profiles_off").is_some() {
        let names: Vec<&str> = d["profiles_off"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        let zh: Vec<&str> = names
            .iter()
            .map(|n| match *n {
                "domain" => "網域",
                "private" => "私人",
                "public" => "公用",
                other => other,
            })
            .collect();
        return format!("防火牆未啟用：{}", zh.join("、"));
    }
    if d.get("drives").is_some() {
        return format!("未加密保護：{}", list("drives"));
    }
    if d.get("accounts").is_some() {
        return format!("不允許的管理員：{}", list("accounts"));
    }
    if let Some(items) = d["services"].as_array() {
        let names: Vec<String> = items
            .iter()
            .map(|i| {
                let process = i["process"].as_str().unwrap_or("未知程式");
                format!(
                    "{} {}/{}（{process}，{}）",
                    i["service"].as_str().unwrap_or(""),
                    i["port"].as_u64().unwrap_or_default(),
                    i["proto"].as_str().unwrap_or(""),
                    i["addr"].as_str().unwrap_or("")
                )
            })
            .collect();
        return format!("對外開放的服務：{}", names.join("、"));
    }
    if d.get("firewall_rules").is_some() {
        return format!("防火牆全開規則：{}", list("firewall_rules"));
    }
    if d.get("ssh").is_some() {
        return format!("sshd：{}", list("ssh"));
    }
    if d.get("rdp_users").is_some() {
        return format!("不允許的遠端桌面使用者：{}", list("rdp_users"));
    }
    if let Some(items) = d["permissions"].as_array() {
        let names: Vec<String> = items
            .iter()
            .map(|i| {
                let who: Vec<&str> = i["granted_to"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                    .unwrap_or_default();
                permission_text(
                    i["kind"].as_str().unwrap_or(""),
                    i["path"].as_str().unwrap_or(""),
                    i["name"].as_str(),
                    &who,
                )
            })
            .collect();
        return format!("權限過寬：{}", names.join("、"));
    }
    if d.get("account_issues").is_some() {
        return format!("帳號設定：{}", list("account_issues"));
    }
    if let Some(items) = d["shares"].as_array() {
        let names: Vec<String> = items
            .iter()
            .map(|i| {
                let issues: Vec<&str> = i["issues"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                    .unwrap_or_default();
                format!(
                    "{}（{}）",
                    i["name"].as_str().unwrap_or(""),
                    issues.join("、")
                )
            })
            .collect();
        return format!("開放的共用：{}", names.join("、"));
    }
    if d.get("root_accounts").is_some() {
        return format!("root 以外的 UID 0 帳號：{}", list("root_accounts"));
    }
    if let Some(items) = d["unquoted"].as_array() {
        let names: Vec<String> = items
            .iter()
            .map(|i| {
                format!(
                    "{}（{}）",
                    i["service"].as_str().unwrap_or(""),
                    i["path"].as_str().unwrap_or("")
                )
            })
            .collect();
        return format!("服務路徑沒加引號：{}", names.join("、"));
    }
    if d.get("service").is_some() {
        return format!("服務 {}：{}／{}", s("service"), s("start_mode"), s("state"));
    }
    if let Some(failed) = d["failed"].as_array() {
        let n = |k: &str| d[k].as_u64().map(|v| v.to_string()).unwrap_or_default();
        let parts: Vec<String> = failed
            .iter()
            .filter_map(|x| x.as_str())
            .map(|f| match f {
                "realtime" => "即時保護未開啟".to_string(),
                "tamper" => "防竄改未開啟".to_string(),
                "signature" => format!("病毒碼 {} 天未更新", n("signature_age_days")),
                "min_length" => format!(
                    "最短長度 {}，需要 {}",
                    n("min_length"),
                    n("required_min_length")
                ),
                "max_age_days" => {
                    let a = n("max_age_days");
                    let a = if a == "0" {
                        "永不過期".to_string()
                    } else {
                        format!("{a} 天")
                    };
                    format!(
                        "密碼最長使用 {a}，需要 {} 天以內",
                        n("required_max_age_days")
                    )
                }
                "lockout_threshold" => {
                    let a = n("lockout_threshold");
                    let a = if a == "0" {
                        "不鎖定".to_string()
                    } else {
                        format!("{a} 次")
                    };
                    format!(
                        "鎖定門檻 {a}，需要 {} 次以內",
                        n("required_lockout_threshold")
                    )
                }
                other => other.to_string(),
            })
            .collect();
        return parts.join("、");
    }
    if d.get("kb").is_some() {
        format!("缺少 {}", s("kb"))
    } else if let (Some(ubr), Some(min)) = (d["ubr"].as_u64(), d["min_ubr"].as_u64()) {
        let b = s("build");
        format!("組建 {b}.{ubr}，需要 {b}.{min} 以上")
    } else if d.get("build").is_some() {
        format!("組建 {} 低於最低支援版本", s("build"))
    } else if d.get("software").is_some() {
        software_list(d)
    } else {
        d.to_string()
    }
}

/// 回傳所有有結果（違規、未知、豁免）的規則；通過的規則不產生 Outcome。依規則順序。
pub fn evaluate(facts: &DeviceFacts, rules: &RuleSet) -> Vec<Outcome> {
    if !facts.active {
        return vec![];
    }
    rules
        .rules
        .iter()
        .filter(|r| r.applies_to(facts.group_id))
        // 參數壞掉的規則不知道類型，跟舊版一樣只對 Windows 顯示
        .filter(|r| {
            r.check
                .as_ref()
                .map_or(!facts.linux, |c| c.platform().covers(facts.linux))
        })
        .filter_map(|r| {
            let (status, detail) = match &r.check {
                Ok(c) => check_one(c, facts)?,
                Err(e) => (Status::Unknown, json!({"reason": "rule_error", "error": e})),
            };
            let status = if facts.exempt.contains(&r.id) {
                Status::Exempt
            } else {
                status
            };
            Some(Outcome {
                rule_id: r.id,
                status,
                detail,
            })
        })
        .collect()
}

/// 與先前（chrono `to_rfc3339`）相同的格式：UTC 寫成 `+00:00`，小數秒 0／3／6／9 位。
/// 違規細節存在資料庫，格式一變就會被當成內容變更。
fn offset_rfc3339(t: time::OffsetDateTime) -> String {
    let t = t.to_offset(time::UtcOffset::UTC);
    let base = t
        .format(time::macros::format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second]"
        ))
        .unwrap_or_default();
    let ns = t.nanosecond();
    let frac = if ns == 0 {
        String::new()
    } else if ns.is_multiple_of(1_000_000) {
        format!(".{:03}", ns / 1_000_000)
    } else if ns.is_multiple_of(1_000) {
        format!(".{:06}", ns / 1_000)
    } else {
        format!(".{ns:09}")
    };
    format!("{base}{frac}+00:00")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::rules::{Params, Rule, RuleSet, Severity};
    use protocol::{
        AccountInfo, DefenderInfo, FirewallInfo, PasswordPolicy, Probe, RegKind, RegState,
        RegistryValue, SecurityInfo, VolumeInfo,
    };
    use serde_json::json;
    use std::collections::HashMap;

    fn sw(name: &str, version: Option<&str>, publisher: Option<&str>) -> SoftwareFact {
        SoftwareFact {
            name: name.into(),
            version: version.map(Into::into),
            publisher: publisher.map(Into::into),
        }
    }

    fn facts(software: Vec<SoftwareFact>) -> DeviceFacts {
        DeviceFacts {
            active: true,
            group_id: Some(1),
            os_build: Some("22631".into()),
            os_ubr: Some(4000),
            software: Some(software),
            kbs: Some(vec!["KB5034439".into()]),
            exempt: vec![],
            security: None,
            registry: None,
            services: None,
            agent_version: Some("0.3.0".into()),
            update_status: None,
            network: None,
            linux: false,
            containers: None,
            accounts: None,
            shares: None,
            exposure: None,
            permissions: None,
            now: time::OffsetDateTime::now_utc(),
            today: time::OffsetDateTime::now_utc().date(),
        }
    }

    fn cfg_facts() -> DeviceFacts {
        let mut reg = HashMap::new();
        let mut put = |p: &str, n: &str, state: RegState, kind: RegKind, data: &str| {
            reg.insert(
                registry_key(p, n),
                RegistryValue {
                    path: p.into(),
                    name: n.into(),
                    state,
                    kind,
                    data: data.into(),
                },
            );
        };
        put(r"HKLM\A", "Dw", RegState::Present, RegKind::Dword, "5");
        put(
            r"HKLM\A",
            "Sz",
            RegState::Present,
            RegKind::String,
            "Hello World",
        );
        put(r"HKLM\A", "Gone", RegState::Absent, RegKind::None, "");
        put(r"HKLM\A", "Secret", RegState::Denied, RegKind::None, "");
        DeviceFacts {
            security: Some(SecurityInfo {
                firewall: Probe::Ok(FirewallInfo {
                    domain: true,
                    private: true,
                    public: false,
                }),
                bitlocker: Probe::Ok(vec![
                    VolumeInfo {
                        drive: "C:".into(),
                        is_system: true,
                        protected: true,
                    },
                    VolumeInfo {
                        drive: "D:".into(),
                        is_system: false,
                        protected: false,
                    },
                ]),
                defender: Probe::Ok(DefenderInfo {
                    active: true,
                    realtime: true,
                    tamper: false,
                    signature_updated: Some(
                        time::OffsetDateTime::now_utc() - time::Duration::days(10),
                    ),
                }),
                password: Probe::Ok(PasswordPolicy {
                    min_length: 8,
                    max_age_days: 0,
                    lockout_threshold: 5,
                }),
                admins: Probe::Ok(vec![
                    AccountInfo {
                        name: r"PC\Administrator".into(),
                        sid: "S-1-5-21-1-500".into(),
                    },
                    AccountInfo {
                        name: r"CORP\bob".into(),
                        sid: "S-1-5-21-2-1100".into(),
                    },
                ]),
            }),
            registry: Some(reg),
            services: Some(vec![
                ServiceFact {
                    name: "RemoteRegistry".into(),
                    start_mode: "Manual".into(),
                    state: "Stopped".into(),
                    binary_path: Some(r"C:\Windows\system32\svchost.exe -k localService".into()),
                },
                ServiceFact {
                    name: "WinDefend".into(),
                    start_mode: "Auto".into(),
                    state: "Running".into(),
                    binary_path: Some(
                        r#""C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe""#.into(),
                    ),
                },
            ]),
            ..facts(vec![])
        }
    }

    fn status(kind: &str, p: serde_json::Value) -> Option<Status> {
        one(&cfg_facts(), kind, p).map(|x| x.0)
    }

    #[test]
    fn registry_value_rules() {
        let r = |op: &str, name: &str, exp: Option<&str>| {
            let mut v = json!({"path": r"hklm\a", "name": name, "op": op});
            if let Some(e) = exp {
                v["expected"] = json!(e);
            }
            status("registry_value", v)
        };
        assert_eq!(r("equals", "Dw", Some("5")), None, "路徑、名稱不分大小寫");
        assert_eq!(r("equals", "dw", Some("0x5")), None, "十六進位");
        assert_eq!(r("gte", "Dw", Some("6")), Some(Status::Violating));
        assert_eq!(r("lte", "Dw", Some("5")), None);
        assert_eq!(
            r("equals", "Sz", Some("hello world")),
            None,
            "字串不分大小寫"
        );
        assert_eq!(r("contains", "Sz", Some("WORLD")), None);
        assert_eq!(
            r("not_equals", "Sz", Some("Hello World")),
            Some(Status::Violating)
        );
        assert_eq!(r("gte", "Sz", Some("1")), Some(Status::Unknown), "非數字");
        assert_eq!(r("equals", "Gone", Some("1")), Some(Status::Violating));
        assert_eq!(r("exists", "Gone", None), Some(Status::Violating));
        assert_eq!(r("not_exists", "Gone", None), None);
        assert_eq!(r("not_exists", "Dw", None), Some(Status::Violating));
        assert_eq!(
            r("equals", "Secret", Some("1")),
            Some(Status::Unknown),
            "拒絕讀取"
        );
        assert_eq!(
            r("equals", "NotCollectedYet", Some("1")),
            Some(Status::Unknown)
        );
        let ok = status(
            "registry_value",
            json!({"path": r"HKLM\A", "name": "Gone", "op": "equals", "expected": "1", "absent_ok": true}),
        );
        assert_eq!(ok, None, "未設定時視為符合");
    }

    #[test]
    fn service_rules() {
        let s =
            |name: &str, req: &str| status("service_state", json!({"name": name, "require": req}));
        assert_eq!(s("remoteregistry", "disabled"), Some(Status::Violating));
        assert_eq!(s("NotInstalled", "disabled"), None, "沒安裝算符合");
        assert_eq!(s("WinDefend", "running"), None);
        assert_eq!(s("NotInstalled", "running"), Some(Status::Violating));
        assert_eq!(s("RemoteRegistry", "running"), Some(Status::Violating));
    }

    #[test]
    fn security_rules() {
        assert_eq!(
            status("firewall", json!({"profiles": ["domain", "private"]})),
            None
        );
        let (st, d) = one(&cfg_facts(), "firewall", json!({"profiles": ["public"]})).unwrap();
        assert_eq!(
            (st, d["profiles_off"].clone()),
            (Status::Violating, json!(["public"]))
        );
        assert_eq!(status("bitlocker", json!({"scope": "system"})), None);
        assert_eq!(
            status("bitlocker", json!({"scope": "all_fixed"})),
            Some(Status::Violating)
        );
        assert_eq!(status("defender", json!({"realtime": true})), None);
        assert_eq!(
            status("defender", json!({"tamper": true})),
            Some(Status::Violating)
        );
        assert_eq!(
            status("defender", json!({"max_signature_age_days": 7})),
            Some(Status::Violating)
        );
        assert_eq!(
            status("defender", json!({"max_signature_age_days": 14})),
            None
        );
        assert_eq!(
            status("password_policy", json!({"min_length": 12})),
            Some(Status::Violating)
        );
        assert_eq!(
            status("password_policy", json!({"max_age_days": 365})),
            Some(Status::Violating),
            "0＝永不過期"
        );
        assert_eq!(
            status("password_policy", json!({"max_lockout_threshold": 10})),
            None
        );
        let (st, d) = one(
            &cfg_facts(),
            "local_admins",
            json!({"allowed": ["*\\administrator"]}),
        )
        .unwrap();
        assert_eq!(
            (st, d["accounts"].clone()),
            (Status::Violating, json!(["CORP\\bob"]))
        );
        assert_eq!(
            status(
                "local_admins",
                json!({"allowed": ["*\\Administrator", "CORP\\*"]})
            ),
            None
        );
    }

    /// 允許清單可以用 SID 樣式（S-1-… 或 *-500）：改名後的內建 Administrator 仍符合；
    /// 名稱剛好像 SID 的帳號不會因此符合
    #[test]
    fn local_admins_matches_sid_patterns() {
        let mut f = cfg_facts();
        if let Some(s) = f.security.as_mut() {
            s.admins = Probe::Ok(vec![
                AccountInfo {
                    name: r"PC\LocalBoss".into(),
                    sid: "S-1-5-21-1-500".into(),
                },
                AccountInfo {
                    name: r"PC\x-500".into(),
                    sid: "S-1-5-21-1-1001".into(),
                },
            ]);
        }
        let (st, d) = one(&f, "local_admins", json!({"allowed": ["*-500"]})).unwrap();
        assert_eq!(
            (st, d["accounts"].clone()),
            (Status::Violating, json!([r"PC\x-500"]))
        );
        // 非 ASCII 開頭的名稱樣式（例如中文網域）不能讓判斷崩潰
        let (st, _) = one(
            &f,
            "local_admins",
            json!({"allowed": [r"網域\Domain Admins", "管"]}),
        )
        .unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(
            one(
                &f,
                "local_admins",
                json!({"allowed": ["*-500", "S-1-5-21-1-1001"]})
            ),
            None
        );
    }

    /// 病毒碼日期未知時，已確定的其他違規仍要回報違規，不能被蓋成未知
    #[test]
    fn defender_known_failure_beats_unknown_signature() {
        let mut f = cfg_facts();
        if let Some(s) = f.security.as_mut() {
            s.defender = Probe::Ok(DefenderInfo {
                active: true,
                realtime: false,
                tamper: true,
                signature_updated: None,
            });
        }
        let r = one(
            &f,
            "defender",
            json!({"realtime": true, "max_signature_age_days": 7}),
        );
        assert_eq!(r.map(|x| x.0), Some(Status::Violating));
        let r = one(
            &f,
            "defender",
            json!({"tamper": true, "max_signature_age_days": 7}),
        );
        assert_eq!(
            r.map(|x| x.0),
            Some(Status::Unknown),
            "其他項都通過時才是未知"
        );
    }

    /// 範圍「所有固定磁碟」卻一個磁碟都沒有：和「系統磁碟」範圍一樣算違規
    #[test]
    fn bitlocker_without_volumes_is_violating_for_both_scopes() {
        let mut f = cfg_facts();
        if let Some(s) = f.security.as_mut() {
            s.bitlocker = Probe::Ok(vec![]);
        }
        for scope in ["system", "all_fixed"] {
            let r = one(&f, "bitlocker", json!({ "scope": scope }));
            assert_eq!(r.map(|x| x.0), Some(Status::Violating), "{scope}");
        }
    }

    #[test]
    fn missing_config_data_is_unknown_with_reason() {
        let mut f = cfg_facts();
        f.security = None;
        f.registry = None;
        f.agent_version = Some("0.2.1".into());
        let (st, d) = one(&f, "firewall", json!({"profiles": ["public"]})).unwrap();
        assert_eq!(
            (st, d["reason"].as_str()),
            (Status::Unknown, Some("agent_outdated"))
        );
        f.agent_version = Some("0.3.0".into());
        let (_, d) = one(
            &f,
            "registry_value",
            json!({"path": r"HKLM\A", "name": "x", "op": "exists"}),
        )
        .unwrap();
        assert_eq!(d["reason"], "no_data");
        let mut f = cfg_facts();
        if let Some(s) = f.security.as_mut() {
            s.defender = Probe::Ok(DefenderInfo {
                active: false,
                realtime: false,
                tamper: false,
                signature_updated: None,
            });
            s.bitlocker = Probe::Error("no BitLocker".into());
        }
        let (st, d) = one(&f, "defender", json!({"realtime": true})).unwrap();
        assert_eq!(
            (st, d["reason"].as_str()),
            (Status::Unknown, Some("defender_inactive"))
        );
        let (st, d) = one(&f, "bitlocker", json!({"scope": "system"})).unwrap();
        assert_eq!(
            (st, d["reason"].as_str()),
            (Status::Unknown, Some("probe_error"))
        );
    }

    #[test]
    fn config_summaries() {
        for (d, want) in [
            (
                json!({"reason": "agent_outdated"}),
                "Agent 版本過舊，未回報這項資料",
            ),
            (
                json!({"reason": "not_collected"}),
                "Agent 尚未回報這個登錄檔值",
            ),
            (json!({"reason": "denied"}), "不允許讀取這個登錄檔值"),
            (
                json!({"reason": "defender_inactive"}),
                "Defender 不是作用中的防毒",
            ),
            (
                json!({"reason": "probe_error", "error": "x"}),
                "收集失敗：x",
            ),
            (
                json!({"reason": "not_numeric", "registry": "HKLM\\A\\B", "actual": "abc"}),
                "HKLM\\A\\B = abc，不是數字",
            ),
            (
                json!({"reason": "signature_unknown"}),
                "無法取得病毒碼更新時間",
            ),
            (json!({"profiles_off": ["public"]}), "防火牆未啟用：公用"),
            (json!({"drives": ["D:"]}), "未加密保護：D:"),
            (json!({"reason": "no_system_volume"}), "找不到系統磁碟"),
            (
                json!({"accounts": ["CORP\\bob"]}),
                "不允許的管理員：CORP\\bob",
            ),
            (
                json!({"service": "Spooler", "start_mode": "Auto", "state": "Running"}),
                "服務 Spooler：Auto／Running",
            ),
            (
                json!({"reason": "not_installed", "service": "X"}),
                "服務 X 未安裝",
            ),
            (
                json!({"registry": "HKLM\\A\\B", "actual": "0", "op": "equals", "expected": "1"}),
                "HKLM\\A\\B = 0，要求 等於 1",
            ),
            (
                json!({"registry": "HKLM\\A\\B", "op": "not_exists"}),
                "HKLM\\A\\B 存在，要求 不存在",
            ),
            (
                json!({"registry": "HKLM\\A\\B", "reason": "absent"}),
                "HKLM\\A\\B 未設定",
            ),
            (
                json!({"failed": ["min_length"], "min_length": 8, "required_min_length": 12}),
                "最短長度 8，需要 12",
            ),
            (
                json!({"failed": ["realtime", "signature"], "signature_age_days": 10}),
                "即時保護未開啟、病毒碼 10 天未更新",
            ),
        ] {
            assert_eq!(summarize(&d), want, "{d}");
        }
    }

    fn set(kind: &str, params: serde_json::Value) -> RuleSet {
        RuleSet::new(
            1,
            vec![Rule {
                id: 7,
                name: "r".into(),
                severity: Severity::High,
                include: vec![],
                exclude: vec![],
                check: Params::parse(kind, &params).map(|p| p.compile()),
            }],
        )
    }

    #[test]
    fn summaries() {
        let cases = [
            (json!({"reason": "no_data"}), "尚未收到盤點資料"),
            (
                json!({"reason": "rule_error", "error": "x"}),
                "規則參數錯誤：x",
            ),
            (json!({"reason": "missing"}), "未安裝"),
            (
                json!({"reason": "outdated", "software": [{"name": "Falcon", "version": "7.1"}]}),
                "版本過舊：Falcon 7.1",
            ),
            (
                json!({"reason": "version_missing", "software": [{"name": "A", "version": null}]}),
                "版本不明：A",
            ),
            (
                json!({"reason": "ubr_missing", "build": "22631"}),
                "Agent 未回報 UBR（組建 22631）",
            ),
            (
                json!({"reason": "build_unparsable", "build": "abc"}),
                "無法解析組建號：abc",
            ),
            (json!({"kb": "KB5031455"}), "缺少 KB5031455"),
            (
                json!({"build": "22631", "ubr": 4000, "min_ubr": 4317}),
                "組建 22631.4000，需要 22631.4317 以上",
            ),
            (json!({"build": "19044"}), "組建 19044 低於最低支援版本"),
            (
                json!({"software": [{"name": "A", "version": "1"}, {"name": "B", "version": null}]}),
                "A 1、B",
            ),
            (
                json!({"software": [{"name": "A", "version": null}], "total": 60}),
                "A 等 60 套",
            ),
        ];
        for (d, want) in cases {
            assert_eq!(summarize(&d), want, "{d}");
        }
    }

    fn one(
        f: &DeviceFacts,
        kind: &str,
        params: serde_json::Value,
    ) -> Option<(Status, serde_json::Value)> {
        let out = evaluate(f, &set(kind, params));
        assert!(out.len() <= 1);
        out.into_iter().next().map(|o| {
            assert_eq!(o.rule_id, 7);
            (o.status, o.detail)
        })
    }

    fn upd(state: &str) -> UpdateFact {
        UpdateFact {
            state: state.into(),
            detail: String::new(),
            reboot_pending: false,
            reboot_pending_since: None,
            last_patch_date: None,
        }
    }

    /// 舊版 Agent 沒有回報更新狀態：不能說成「尚未收到盤點資料」
    #[test]
    fn update_rules_without_status_say_agent_has_not_reported() {
        let f = facts(vec![]);
        for (kind, p) in [
            ("patch_age", json!({"max_days": 30})),
            ("reboot_pending", json!({"max_days": 7})),
            ("update_policy", json!({})),
        ] {
            let (st, d) = one(&f, kind, p).unwrap();
            assert_eq!(st, Status::Unknown);
            assert_eq!(d["reason"], "no_update_status", "{kind}");
            assert!(summarize(&d).contains("0.5.0"), "{}", summarize(&d));
        }
    }

    #[test]
    fn patch_age() {
        let mut f = facts(vec![]);
        let p = json!({"max_days": 30});
        assert_eq!(one(&f, "patch_age", p.clone()).unwrap().0, Status::Unknown);
        f.update_status = Some(upd("applied"));
        let (st, d) = one(&f, "patch_age", p.clone()).unwrap();
        assert_eq!(
            (st, d["reason"].as_str()),
            (Status::Unknown, Some("no_patch_date"))
        );
        let today = f.today;
        f.update_status.as_mut().unwrap().last_patch_date = Some(today - time::Duration::days(30));
        assert_eq!(one(&f, "patch_age", p.clone()), None, "剛好 30 天不算");
        f.update_status.as_mut().unwrap().last_patch_date = Some(today - time::Duration::days(31));
        let (st, d) = one(&f, "patch_age", p).unwrap();
        assert_eq!((st, d["days"].as_i64()), (Status::Violating, Some(31)));
        assert!(summarize(&d).contains("31 天前"), "{}", summarize(&d));
    }

    /// 違規細節裡的時間要和 chrono 時代寫進資料庫的格式完全相同
    #[test]
    fn offset_rfc3339_matches_previous_format() {
        use time::macros::datetime;
        assert_eq!(
            offset_rfc3339(datetime!(2026-10-02 20:00 UTC)),
            "2026-10-02T20:00:00+00:00"
        );
        assert_eq!(
            offset_rfc3339(datetime!(2026-10-02 20:00:01.5 UTC)),
            "2026-10-02T20:00:01.500+00:00"
        );
        assert_eq!(
            offset_rfc3339(datetime!(2026-10-02 20:00:01.123456 UTC)),
            "2026-10-02T20:00:01.123456+00:00"
        );
        assert_eq!(
            offset_rfc3339(datetime!(2026-10-03 04:00 +08:00)),
            "2026-10-02T20:00:00+00:00"
        );
    }

    #[test]
    fn patch_age_uses_display_date() {
        let mut f = facts(vec![]);
        // UTC 還是 10/2，管理網頁的時區（+8）已是 10/3：以 10/3 計算是 31 天
        f.now = time::macros::datetime!(2026-10-02 20:00 UTC);
        f.today = protocol::timefmt::ymd(2026, 10, 3).unwrap();
        let mut u = upd("applied");
        u.last_patch_date = protocol::timefmt::ymd(2026, 9, 2);
        f.update_status = Some(u);
        let (st, d) = one(&f, "patch_age", json!({"max_days": 30})).unwrap();
        assert_eq!((st, d["days"].as_i64()), (Status::Violating, Some(31)));
    }

    #[test]
    fn reboot_pending() {
        let mut f = facts(vec![]);
        let p = json!({"max_days": 7});
        assert_eq!(
            one(&f, "reboot_pending", p.clone()).unwrap().0,
            Status::Unknown
        );
        f.update_status = Some(upd("applied"));
        assert_eq!(one(&f, "reboot_pending", p.clone()), None);
        let u = f.update_status.as_mut().unwrap();
        u.reboot_pending = true;
        assert_eq!(
            one(&f, "reboot_pending", p.clone()),
            None,
            "沒有起始時間不判違規"
        );
        f.update_status.as_mut().unwrap().reboot_pending_since =
            Some(f.now - time::Duration::days(6));
        assert_eq!(one(&f, "reboot_pending", p.clone()), None);
        f.update_status.as_mut().unwrap().reboot_pending_since =
            Some(f.now - time::Duration::days(8));
        let (st, d) = one(&f, "reboot_pending", p).unwrap();
        assert_eq!((st, d["days"].as_i64()), (Status::Violating, Some(8)));
        assert!(
            summarize(&d).contains("待重開機已 8 天"),
            "{}",
            summarize(&d)
        );
    }

    #[test]
    fn update_policy_state() {
        let mut f = facts(vec![]);
        assert_eq!(
            one(&f, "update_policy", json!({})).unwrap().0,
            Status::Unknown
        );
        for ok in ["applied", "unmanaged"] {
            f.update_status = Some(upd(ok));
            assert_eq!(one(&f, "update_policy", json!({})), None, "{ok}");
        }
        let mut u = upd("conflict");
        u.detail = "DeferQualityUpdates".into();
        f.update_status = Some(u);
        let (st, d) = one(&f, "update_policy", json!({})).unwrap();
        assert_eq!(st, Status::Violating);
        assert!(summarize(&d).contains("原則被改動：DeferQualityUpdates"));
        f.update_status = Some(upd("error"));
        let (st, d) = one(&f, "update_policy", json!({})).unwrap();
        assert_eq!(st, Status::Violating);
        assert!(summarize(&d).contains("原則套用失敗"));
    }

    #[test]
    fn forbidden_software() {
        let f = facts(vec![
            sw("TeamViewer 15", Some("15.1"), Some("TeamViewer GmbH")),
            sw("7-Zip", Some("23.01"), None),
        ]);
        let (st, d) = one(&f, "forbidden_software", json!({"name": "*teamviewer*"})).unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(
            d,
            json!({"software": [{"name": "TeamViewer 15", "version": "15.1"}]})
        );
        assert!(one(&f, "forbidden_software", json!({"name": "*AnyDesk*"})).is_none());
        assert!(
            one(
                &f,
                "forbidden_software",
                json!({"name": "*TeamViewer*", "publisher": "Other*"})
            )
            .is_none(),
            "發行者不符"
        );
        assert!(
            one(
                &f,
                "forbidden_software",
                json!({"name": "7-Zip", "publisher": "*"})
            )
            .is_none(),
            "沒有發行者時不符合發行者條件"
        );
        // 版本條件：低於才算
        assert!(
            one(
                &f,
                "forbidden_software",
                json!({"name": "7-Zip", "below_version": "23.01"})
            )
            .is_none()
        );
        let (st, _) = one(
            &f,
            "forbidden_software",
            json!({"name": "7-Zip", "below_version": "24"}),
        )
        .unwrap();
        assert_eq!(st, Status::Violating);
        // 沒有版本 → 未知
        let f2 = facts(vec![sw("7-Zip", None, None)]);
        let (st, d) = one(
            &f2,
            "forbidden_software",
            json!({"name": "7-Zip", "below_version": "24"}),
        )
        .unwrap();
        assert_eq!(st, Status::Unknown);
        assert_eq!(d["reason"], "version_missing");
    }

    #[test]
    fn required_software() {
        let f = facts(vec![sw("CrowdStrike Falcon", Some("7.10"), None)]);
        assert!(one(&f, "required_software", json!({"name": "CrowdStrike*"})).is_none());
        let (st, d) = one(&f, "required_software", json!({"name": "Symantec*"})).unwrap();
        assert_eq!((st, d), (Status::Violating, json!({"reason": "missing"})));
        let (st, d) = one(
            &f,
            "required_software",
            json!({"name": "CrowdStrike*", "min_version": "7.11"}),
        )
        .unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(d["reason"], "outdated");
        assert!(
            one(
                &f,
                "required_software",
                json!({"name": "CrowdStrike*", "min_version": "7.9"})
            )
            .is_none()
        );
        // 一套沒版本、一套夠新 → 通過；只有沒版本或太舊 → 未知
        let f2 = facts(vec![sw("A", None, None), sw("A", Some("2"), None)]);
        assert!(
            one(
                &f2,
                "required_software",
                json!({"name": "A", "min_version": "2"})
            )
            .is_none()
        );
        let f3 = facts(vec![sw("A", None, None), sw("A", Some("1"), None)]);
        assert_eq!(
            one(
                &f3,
                "required_software",
                json!({"name": "A", "min_version": "2"})
            )
            .unwrap()
            .0,
            Status::Unknown
        );
    }

    #[test]
    fn allowlist_lists_offenders_capped() {
        let mut items: Vec<SoftwareFact> = (0..60)
            .map(|i| sw(&format!("Game {i:02}"), None, Some("Fun Inc")))
            .collect();
        items.push(sw("Office", None, Some("Microsoft Corporation")));
        let f = facts(items);
        let (st, d) = one(
            &f,
            "software_allowlist",
            json!({"entries": [{"publisher": "Microsoft*"}]}),
        )
        .unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(d["total"], 60);
        assert_eq!(d["software"].as_array().unwrap().len(), MAX_LISTED);
        assert!(
            one(
                &f,
                "software_allowlist",
                json!({"entries": [{"publisher": "Microsoft*"}, {"name": "Game*"}]})
            )
            .is_none()
        );
    }

    #[test]
    fn os_build_rules() {
        let f = facts(vec![]);
        let (st, d) = one(&f, "os_build", json!({"build": 22631, "min_ubr": 4317})).unwrap();
        assert_eq!(
            (st, d),
            (
                Status::Violating,
                json!({"build": "22631", "ubr": 4000, "min_ubr": 4317})
            )
        );
        assert!(one(&f, "os_build", json!({"build": 22631, "min_ubr": 4000})).is_none());
        assert!(
            one(&f, "os_build", json!({"build": 19045, "min_ubr": 9999})).is_none(),
            "其他組建不受影響"
        );
        let (st, _) = one(&f, "os_build", json!({"min_build": 26100})).unwrap();
        assert_eq!(st, Status::Violating);
        assert!(one(&f, "os_build", json!({"min_build": 19045})).is_none());
        let mut old_agent = facts(vec![]);
        old_agent.os_ubr = None;
        assert_eq!(
            one(
                &old_agent,
                "os_build",
                json!({"build": 22631, "min_ubr": 1})
            )
            .unwrap()
            .0,
            Status::Unknown
        );
        let mut weird = facts(vec![]);
        weird.os_build = Some("abc".into());
        assert_eq!(
            one(&weird, "os_build", json!({"min_build": 1})).unwrap().0,
            Status::Unknown
        );
    }

    #[test]
    fn required_kb_is_case_insensitive() {
        let mut f = facts(vec![]);
        f.kbs = Some(vec!["kb5034439".into()]);
        assert!(one(&f, "required_kb", json!({"kb": "KB5034439"})).is_none());
        let (st, d) = one(&f, "required_kb", json!({"kb": "KB5031455"})).unwrap();
        assert_eq!((st, d), (Status::Violating, json!({"kb": "KB5031455"})));
    }

    #[test]
    fn missing_sections_are_unknown() {
        let f = DeviceFacts {
            os_build: None,
            software: None,
            kbs: None,
            ..facts(vec![])
        };
        for (kind, p) in [
            ("forbidden_software", json!({"name": "x"})),
            ("software_allowlist", json!({"entries": [{"name": "x"}]})),
            ("os_build", json!({"min_build": 1})),
            ("required_kb", json!({"kb": "KB5034439"})),
        ] {
            let (st, d) = one(&f, kind, p).unwrap();
            assert_eq!(
                (st, d["reason"].as_str()),
                (Status::Unknown, Some("no_data")),
                "{kind}"
            );
        }
    }

    fn net(name: &str, kind: &str, addr: &str, gw: bool) -> protocol::NetInterface {
        protocol::NetInterface {
            name: name.into(),
            description: None,
            kind: kind.into(),
            up: true,
            mac: None,
            addresses: vec![addr.into()],
            gateways: if gw { vec!["x".into()] } else { vec![] },
            dns: vec![],
            ssid: None,
        }
    }

    #[test]
    fn dual_homed_rule() {
        let now = time::macros::datetime!(2026-11-22 12:00 UTC);
        let hq = std::sync::Arc::new(vec![crate::network::SiteNets {
            name: "總部".into(),
            cidrs: vec![crate::branch::sites::parse_cidr("10.1.0.0/16").unwrap()],
        }]);
        let two = vec![
            net("eth", "ethernet", "10.1.2.3/24", true),
            net("Npcap Loopback", "ethernet", "192.168.56.1/24", true),
        ];
        let cross = vec![
            net("eth", "ethernet", "10.1.2.3/24", false),
            net("Wi-Fi", "wifi", "192.168.43.5/24", true),
        ];
        let period =
            |start_h: i64, end_h: Option<i64>, nics: &Vec<protocol::NetInterface>| PeriodFact {
                started_at: now - time::Duration::hours(start_h),
                ended_at: end_h.map(|h| now - time::Duration::hours(h)),
                nics: nics.clone(),
                incomplete: false,
            };
        let mut f = facts(vec![]);
        f.now = now;

        // 沒有 network 區段：Agent 太舊或還沒上傳
        let (st, d) = one(&f, "dual_homed", json!({})).unwrap();
        assert_eq!(
            (st, d["reason"].as_str()),
            (Status::Unknown, Some("agent_outdated"))
        );
        f.agent_version = Some("0.12.0".into());
        assert_eq!(
            one(&f, "dual_homed", json!({})).unwrap().1["reason"],
            "no_data"
        );

        f.network = Some(NetFacts {
            periods: vec![
                period(1, None, &two),
                period(30, Some(29), &cross),
                period(24 * 10, Some(24 * 10 - 1), &cross),
            ],
            sites: hq.clone(),
        });
        // 預設 7 天：10 天前那段不算；持續中的不記長度
        let (st, d) = one(&f, "dual_homed", json!({})).unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(d["count"], 2);
        assert_eq!(d["dual_homed"][0]["ongoing"], true);
        assert!(d["dual_homed"][0].get("duration_secs").is_none());
        assert_eq!(d["dual_homed"][1]["duration_secs"], 3600);
        let s = summarize(&d);
        assert!(s.starts_with("7 天內多重連線 2 次，最近一次："), "{s}");
        assert!(s.contains("起持續中") && s.contains("兩條對外路徑"), "{s}");

        // 回溯 14 天：三段都算
        assert_eq!(
            one(&f, "dual_homed", json!({"lookback_days": 14}))
                .unwrap()
                .1["count"],
            3
        );
        // 例外網卡：Npcap 那段不算
        let d = one(&f, "dual_homed", json!({"exclude_interfaces": ["*npcap*"]}))
            .unwrap()
            .1;
        assert_eq!(d["count"], 1);
        let s = summarize(&d);
        assert!(
            s.contains("持續 1 小時 0 分") && s.contains("據點以外"),
            "{s}"
        );
        // 例外網段：同樣排除 Npcap（它的位址都在例外網段內）
        let d = one(
            &f,
            "dual_homed",
            json!({"exclude_cidrs": ["192.168.56.0/24"]}),
        )
        .unwrap()
        .1;
        assert_eq!(d["count"], 1);
        // 只看條件 2
        let d = one(&f, "dual_homed", json!({"only_cross_site": true}))
            .unwrap()
            .1;
        assert_eq!(d["count"], 1);
        // 最短持續時間：持續中的那段（已 1 小時）與 1 小時那段都算；設 2 小時就都不算
        assert!(one(&f, "dual_homed", json!({"min_duration_secs": 7200})).is_none());
        // 兩個例外一起：沒有違規
        assert!(
            one(
                &f,
                "dual_homed",
                json!({"exclude_interfaces": ["*npcap*"], "exclude_cidrs": ["192.168.43.0/24"]})
            )
            .is_none()
        );
        // 可能不完整的期間有註記
        if let Some(n) = f.network.as_mut() {
            n.periods[0].incomplete = true;
        }
        let d = one(&f, "dual_homed", json!({})).unwrap().1;
        assert_eq!(d["dual_homed"][0]["incomplete"], true);
        // 沒有期間：符合
        f.network = Some(NetFacts {
            periods: vec![],
            sites: hq,
        });
        assert!(one(&f, "dual_homed", json!({})).is_none());
    }

    #[test]
    fn broken_rule_is_unknown_and_others_still_run() {
        let mut rs = set("required_kb", json!({"kb": "KB5031455"}));
        rs.rules.push(Rule {
            id: 8,
            name: "broken".into(),
            severity: Severity::Low,
            include: vec![],
            exclude: vec![],
            check: Err("參數格式錯誤".into()),
        });
        let out = evaluate(&facts(vec![]), &rs);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].status, Status::Violating);
        assert_eq!(out[1].status, Status::Unknown);
        assert_eq!(out[1].detail["reason"], "rule_error");
    }

    #[test]
    fn exemption_scope_and_inactive() {
        let mut f = facts(vec![]);
        f.exempt = vec![7];
        let (st, d) = one(&f, "required_kb", json!({"kb": "KB5031455"})).unwrap();
        assert_eq!(
            (st, d),
            (Status::Exempt, json!({"kb": "KB5031455"})),
            "豁免仍保留細節"
        );
        let mut rs = set("required_kb", json!({"kb": "KB5031455"}));
        rs.rules[0].exclude = vec![1];
        assert!(evaluate(&facts(vec![]), &rs).is_empty(), "不在範圍內");
        let inactive = DeviceFacts {
            active: false,
            ..facts(vec![])
        };
        assert!(evaluate(&inactive, &set("required_kb", json!({"kb": "KB5031455"}))).is_empty());
    }

    fn ctr(name: &str, image: &str, state: &str) -> protocol::ContainerItem {
        protocol::ContainerItem {
            runtime: "docker".into(),
            id: "0123456789ab".into(),
            name: name.into(),
            image: image.into(),
            image_id: None,
            state: state.into(),
            health: None,
            created_at: None,
            started_at: None,
            finished_at: None,
            restart_policy: None,
            privileged: Some(false),
            host_network: Some(false),
            ports: vec![],
            host_mounts: vec![],
            owner: None,
            k8s: None,
        }
    }

    fn linux(containers: Vec<protocol::ContainerItem>) -> DeviceFacts {
        DeviceFacts {
            linux: true,
            containers: Some(protocol::ContainersInfo {
                runtimes: vec![protocol::RuntimeInfo {
                    kind: "docker".into(),
                    version: None,
                    error: None,
                }],
                containers,
                truncated: false,
            }),
            ..facts(vec![])
        }
    }

    #[test]
    fn image_refs() {
        let r = image_ref("registry.local:5000/team/app:1.2@sha256:ab");
        assert_eq!(
            (r.repo, r.tag, r.digest),
            ("registry.local:5000/team/app", Some("1.2"), true)
        );
        let r = image_ref("registry.local:5000/app");
        assert_eq!(
            (r.repo, r.tag, r.digest),
            ("registry.local:5000/app", None, false)
        );
        assert_eq!(short_image("docker.io/library/nginx:1"), "nginx:1");
        assert_eq!(short_image("docker.io/bitnami/redis"), "bitnami/redis");
        assert_eq!(short_image("ghcr.io/x/y"), "ghcr.io/x/y");

        let g = Glob::new("nginx");
        assert!(image_matches(&g, "nginx:1.27"));
        assert!(image_matches(&g, "docker.io/library/nginx:1.27"));
        assert!(image_matches(&g, "nginx@sha256:ab"));
        assert!(!image_matches(&g, "nginx-proxy:1"));
        assert!(image_matches(
            &Glob::new("nginx:1.1*"),
            "docker.io/library/nginx:1.18"
        ));
        assert!(!image_matches(&Glob::new("nginx:1.1*"), "nginx:1.27"));

        for (image, want) in [
            ("nginx", true),
            ("nginx:latest", true),
            ("docker.io/library/nginx:LATEST", false),
            ("registry.local:5000/app", true),
            ("nginx:1.27", false),
            ("nginx@sha256:ab", false),
            ("nginx:latest@sha256:ab", false),
            ("sha256:0123", false),
            (&"a".repeat(64), false),
            ("", false),
        ] {
            assert_eq!(unpinned(image), want, "{image}");
        }
        assert!(runtime_socket("/var/run/docker.sock"));
        assert!(runtime_socket("/run/k3s/containerd/containerd.sock"));
        assert!(!runtime_socket("/var/run/docker.sock.d/x"));
        assert!(!runtime_socket("/srv/data"));
    }

    #[test]
    fn unquoted_paths() {
        for p in [
            r"C:\Program Files\My App\svc.exe",
            r"C:\Tools\my app.exe -run",
            r"D:\Vendor Soft\bin\agent.EXE /service",
        ] {
            assert!(unquoted_path(p), "{p}");
        }
        for p in [
            r#""C:\Program Files\My App\svc.exe""#,
            r"C:\Program\svc.exe -arg with spaces",
            r"C:\Windows\System32\svchost.exe -k netsvcs",
            r"%SystemRoot%\Program Files\x y.exe",
            r"\SystemRoot\System32\drivers\a b.sys",
            r"C:\no exe here\driver.sys",
            "",
        ] {
            assert!(!unquoted_path(p), "{p}");
        }
    }

    #[test]
    fn unquoted_service_rule() {
        let mut f = cfg_facts();
        assert!(one(&f, "unquoted_service_path", json!({})).is_none());
        f.services.as_mut().unwrap().push(ServiceFact {
            name: "VendorSvc".into(),
            start_mode: "Auto".into(),
            state: "Running".into(),
            binary_path: Some(r"C:\Program Files\Vendor App\svc.exe".into()),
        });
        f.services.as_mut().unwrap().push(ServiceFact {
            name: "NoPath".into(),
            start_mode: "Auto".into(),
            state: "Running".into(),
            binary_path: None,
        });
        let (st, d) = one(&f, "unquoted_service_path", json!({})).unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(d["total"], 1);
        assert_eq!(
            summarize(&d),
            r"服務路徑沒加引號：VendorSvc（C:\Program Files\Vendor App\svc.exe）"
        );
        assert!(
            one(
                &f,
                "unquoted_service_path",
                json!({"except_services": ["vendor*"]})
            )
            .is_none()
        );
        let none = DeviceFacts {
            services: None,
            ..f.clone()
        };
        assert_eq!(
            one(&none, "unquoted_service_path", json!({})).unwrap().0,
            Status::Unknown
        );
        // Linux 裝置不適用
        let lx = DeviceFacts { linux: true, ..f };
        assert!(one(&lx, "unquoted_service_path", json!({})).is_none());
    }

    fn exposure(listening: Vec<(u16, &str, Option<&str>)>) -> protocol::ExposureInfo {
        protocol::ExposureInfo {
            listening: listening
                .into_iter()
                .map(|(port, addr, process)| protocol::ListenItem {
                    proto: "tcp".into(),
                    addr: addr.into(),
                    port,
                    process: process.map(Into::into),
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn exposed_service_rule() {
        let mut f = facts(vec![]);
        let p = json!({"services": ["mysql", "telnet"], "ports": [8080]});
        assert_eq!(
            one(&f, "exposed_service", p.clone()).unwrap().0,
            Status::Unknown,
            "沒有資料"
        );
        f.exposure = Some(exposure(vec![
            (3306, "10.0.0.5", Some("mysqld")),
            (23, "0.0.0.0", None),
            (443, "0.0.0.0", Some("nginx")),
            (8080, "::", Some("java")),
        ]));
        let (st, d) = one(&f, "exposed_service", p.clone()).unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(d["total"], 3);
        assert_eq!(
            summarize(&d),
            "對外開放的服務：MySQL 3306/tcp（mysqld，10.0.0.5）、Telnet 23/tcp（未知程式，0.0.0.0）、連接埠 8080 8080/tcp（java，::）"
        );
        // 只算所有介面；例外程式
        let (_, d) = one(
            &f,
            "exposed_service",
            json!({"services": ["mysql", "telnet"], "ports": [8080], "any_interface_only": true,
                   "except_processes": ["java"]}),
        )
        .unwrap();
        assert_eq!(d["total"], 1);
        assert_eq!(d["services"][0]["port"], 23);
        // 沒有違規但讀不到連接埠：未知；只有別的錯誤：符合
        f.exposure = Some(protocol::ExposureInfo {
            errors: vec!["無法讀取 TCP 連接埠：x".into()],
            ..Default::default()
        });
        let (st, d) = one(&f, "exposed_service", p.clone()).unwrap();
        assert_eq!(st, Status::Unknown);
        assert_eq!(summarize(&d), "無法讀取：無法讀取 TCP 連接埠：x");
        f.exposure = Some(protocol::ExposureInfo {
            errors: vec!["無法讀取 sshd 設定：x".into()],
            ..Default::default()
        });
        assert!(one(&f, "exposed_service", p).is_none());
    }

    #[test]
    fn firewall_allow_all_rule() {
        let mut f = facts(vec![]);
        assert_eq!(
            one(&f, "firewall_allow_all", json!({})).unwrap().0,
            Status::Unknown
        );
        f.exposure = Some(protocol::ExposureInfo {
            firewall_allow_all: Some(vec!["Open all".into(), "Lab test".into()]),
            ..Default::default()
        });
        let (st, d) = one(&f, "firewall_allow_all", json!({})).unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(summarize(&d), "防火牆全開規則：Open all、Lab test");
        let (_, d) = one(&f, "firewall_allow_all", json!({"except_rules": ["Lab*"]})).unwrap();
        assert_eq!(d["total"], 1);
        f.exposure.as_mut().unwrap().firewall_allow_all = Some(vec![]);
        assert!(one(&f, "firewall_allow_all", json!({})).is_none());
        // 讀不到防火牆規則：有錯誤是未知，沒有錯誤（舊資料）也是未知
        f.exposure = Some(protocol::ExposureInfo {
            errors: vec!["無法讀取防火牆規則：x".into()],
            ..Default::default()
        });
        assert_eq!(
            one(&f, "firewall_allow_all", json!({})).unwrap().1["reason"],
            "exposure_error"
        );
        f.exposure = Some(protocol::ExposureInfo::default());
        assert_eq!(
            one(&f, "firewall_allow_all", json!({})).unwrap().1["reason"],
            "no_data"
        );
    }

    #[test]
    fn ssh_config_rule() {
        let sshd = |root: &str, pw: bool, empty: bool| protocol::ExposureInfo {
            sshd: Some(protocol::SshdInfo {
                permit_root_login: root.into(),
                password_authentication: pw,
                permit_empty_passwords: empty,
                ports: vec![22],
            }),
            ..Default::default()
        };
        let mut f = linux(vec![]);
        let all =
            json!({"no_root_password": true, "no_password": true, "no_empty_passwords": true});
        assert_eq!(
            one(&f, "ssh_config", all.clone()).unwrap().0,
            Status::Unknown
        );
        f.exposure = Some(sshd("yes", true, true));
        let (st, d) = one(&f, "ssh_config", all.clone()).unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(
            summarize(&d),
            "sshd：允許 root 以密碼登入、允許密碼登入、允許空密碼"
        );
        f.exposure = Some(sshd("prohibit-password", false, false));
        assert!(
            one(&f, "ssh_config", all.clone()).is_none(),
            "只用金鑰的 root 符合"
        );
        let (_, d) = one(&f, "ssh_config", json!({"no_root_login": true})).unwrap();
        assert_eq!(d["ssh"], json!(["允許 root 登入"]));
        f.exposure = Some(sshd("no", false, false));
        assert!(one(&f, "ssh_config", json!({"no_root_login": true})).is_none());
        // 沒有安裝 sshd：符合；讀取失敗：未知
        f.exposure = Some(protocol::ExposureInfo::default());
        assert!(one(&f, "ssh_config", all.clone()).is_none());
        f.exposure = Some(protocol::ExposureInfo {
            errors: vec!["無法讀取 sshd 設定：x".into()],
            ..Default::default()
        });
        assert_eq!(
            one(&f, "ssh_config", all.clone()).unwrap().0,
            Status::Unknown
        );
        // Windows 不適用
        assert!(one(&facts(vec![]), "ssh_config", all).is_none());
    }

    #[test]
    fn rdp_users_rule() {
        let user = |name: &str, sid: &str| protocol::AccountInfo {
            name: name.into(),
            sid: sid.into(),
        };
        let mut f = facts(vec![]);
        assert_eq!(one(&f, "rdp_users", json!({})).unwrap().0, Status::Unknown);
        f.exposure = Some(protocol::ExposureInfo {
            rdp: Some(protocol::RdpInfo {
                enabled: true,
                users: vec![
                    user(r"CORP\helpdesk", "S-1-5-21-9-1105"),
                    user(r"CORP\Domain Users", "S-1-5-21-9-513"),
                    user(r"PC\guest", "S-1-5-21-1-501"),
                ],
            }),
            ..Default::default()
        });
        let (st, d) = one(
            &f,
            "rdp_users",
            json!({"allowed": [r"CORP\helpdesk", "*-501"]}),
        )
        .unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(summarize(&d), r"不允許的遠端桌面使用者：CORP\Domain Users");
        f.exposure.as_mut().unwrap().rdp.as_mut().unwrap().enabled = false;
        assert!(one(&f, "rdp_users", json!({})).is_none(), "遠端桌面沒開");
        f.exposure = Some(protocol::ExposureInfo {
            errors: vec!["無法讀取遠端桌面設定：x".into()],
            ..Default::default()
        });
        assert_eq!(
            one(&f, "rdp_users", json!({})).unwrap().1["reason"],
            "exposure_error"
        );
    }

    #[test]
    fn open_share_rule() {
        use protocol::{ShareAccess, ShareItem, SharesInfo};
        let share = |name: &str, anon: ShareAccess, users: ShareAccess| ShareItem {
            kind: "smb".into(),
            name: name.into(),
            path: format!(r"D:\{name}"),
            anonymous: anon,
            all_users: users,
            no_root_squash: false,
            clients: vec![],
        };
        let mut f = facts(vec![]);
        assert_eq!(
            one(&f, "open_share", json!({"anonymous": true})).unwrap().0,
            Status::Unknown,
            "沒有共用資料"
        );
        let mut nfs = share("/srv/x", ShareAccess::Read, ShareAccess::Read);
        nfs.kind = "nfs".into();
        nfs.no_root_squash = true;
        f.shares = Some(SharesInfo {
            shares: vec![
                share("public", ShareAccess::Write, ShareAccess::Write),
                share("docs", ShareAccess::None, ShareAccess::Read),
                share("team", ShareAccess::None, ShareAccess::Write),
                share("dist", ShareAccess::Read, ShareAccess::Read),
                nfs,
            ],
            errors: vec![],
        });
        let p = json!({"anonymous": true, "all_users": true});
        let (st, d) = one(&f, "open_share", p.clone()).unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(
            summarize(&d),
            "開放的共用：public（匿名可寫入）、team（所有使用者可寫入）"
        );
        let (_, d) = one(
            &f,
            "open_share",
            json!({"anonymous": true, "access": "read", "no_root_squash": true,
                   "except_shares": ["dist"]}),
        )
        .unwrap();
        assert_eq!(
            summarize(&d),
            "開放的共用：public（匿名可寫入）、/srv/x（匿名可讀取、no_root_squash）"
        );
        // 例外可以比對路徑
        let (_, d) = one(
            &f,
            "open_share",
            json!({"anonymous": true, "all_users": true, "except_shares": [r"D:\p*"]}),
        )
        .unwrap();
        assert_eq!(d["total"], 1);
        // 沒有違規但部分來源讀不到：未知
        f.shares = Some(SharesInfo {
            shares: vec![],
            errors: vec!["無法讀取 Samba 設定：x".into()],
        });
        let (st, d) = one(&f, "open_share", p.clone()).unwrap();
        assert_eq!(st, Status::Unknown);
        assert_eq!(d["reason"], "share_error");
        assert_eq!(summarize(&d), "無法讀取共用：無法讀取 Samba 設定：x");
        f.shares = Some(SharesInfo::default());
        assert!(one(&f, "open_share", p.clone()).is_none());
        // 兩邊都適用
        let lx = DeviceFacts { linux: true, ..f };
        assert!(one(&lx, "open_share", p).is_none());
    }

    fn user(name: &str, uid: u32) -> protocol::LocalUser {
        protocol::LocalUser {
            name: name.into(),
            uid,
            no_password: Some(false),
            ..Default::default()
        }
    }

    #[test]
    fn weak_permissions_rule() {
        let item =
            |kind: &str, path: &str, name: Option<&str>, who: &[&str]| protocol::PermissionItem {
                kind: kind.into(),
                path: path.into(),
                name: name.map(Into::into),
                granted_to: who.iter().map(|w| w.to_string()).collect(),
            };
        let mut f = facts(vec![]);
        assert_eq!(
            one(&f, "weak_permissions", json!({})).unwrap().0,
            Status::Unknown
        );
        f.permissions = Some(protocol::PermissionsInfo {
            items: vec![
                item(
                    "service_binary",
                    r"C:\Vendor\svc.exe",
                    Some("VendorSvc"),
                    &["Users"],
                ),
                item(
                    "task_binary",
                    r"C:\Tools\t.exe",
                    Some(r"\Upd"),
                    &["Everyone", "Users"],
                ),
                item("etc_writable", "/etc/cron.d/job", None, &["所有人"]),
                item("suid", "/usr/local/bin/x", None, &["SUID"]),
            ],
            ..Default::default()
        });
        let (st, d) = one(&f, "weak_permissions", json!({})).unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(d["total"], 4);
        assert_eq!(
            summarize(&d),
            r"權限過寬：服務執行檔可改寫 C:\Vendor\svc.exe（VendorSvc；Users）、SYSTEM 排程工作的程式可改寫 C:\Tools\t.exe（\Upd；Everyone、Users）、所有人可寫入 /etc/cron.d/job、不屬於任何套件的 SUID 程式 /usr/local/bin/x（SUID）"
        );
        // 例外：路徑或名稱
        assert!(
            one(
                &f,
                "weak_permissions",
                json!({"except_paths": [r"c:\vendor\*", r"\Upd", "/etc/*", "/usr/local/*"]}),
            )
            .is_none()
        );
        // 沒有項目但讀取失敗：未知；完全沒有：符合
        f.permissions = Some(protocol::PermissionsInfo {
            errors: vec!["無法讀取排程工作：x".into()],
            ..Default::default()
        });
        let (st, d) = one(&f, "weak_permissions", json!({})).unwrap();
        assert_eq!(st, Status::Unknown);
        assert_eq!(summarize(&d), "無法讀取權限：無法讀取排程工作：x");
        f.permissions = Some(protocol::PermissionsInfo::default());
        assert!(one(&f, "weak_permissions", json!({})).is_none());
        assert_eq!(permission_label("x"), "權限過寬");
        assert_eq!(
            permission_text("shadow_readable", "/etc/shadow", None, &["所有人"]),
            "所有人可讀取 /etc/shadow"
        );
        assert_eq!(permission_label("service_dir"), "服務資料夾可新增檔案");
    }

    #[test]
    fn account_flags_windows() {
        let all = json!({"no_password": true, "guest_disabled": true, "password_expires": true,
                         "sudo_nopasswd": true, "no_autologon_password": true,
                         "except_accounts": ["svc_*"]});
        let mut f = facts(vec![]);
        assert_eq!(
            one(&f, "account_flags", all.clone()).unwrap().0,
            Status::Unknown
        );
        // 舊版 Agent：沒有旗標
        f.accounts = Some(protocol::AccountsInfo::default());
        assert_eq!(
            summarize(&one(&f, "account_flags", all.clone()).unwrap().1),
            "Agent 版本過舊，未回報這項資料"
        );
        let mut guest = user("Visitor", 501);
        guest.no_password = Some(true);
        let mut bob = user("bob", 1001);
        bob.no_password = Some(true);
        bob.password_never_expires = true;
        let mut svc = user("svc_backup", 1002);
        svc.password_never_expires = true;
        let mut old = user("old", 1003);
        old.disabled = true;
        old.no_password = Some(true);
        f.accounts = Some(protocol::AccountsInfo {
            users: vec![user("Administrator", 500), guest, bob, svc, old],
            privileged: vec![protocol::PrivilegeEntry {
                principal: "x".into(),
                nopasswd_all: true,
                ..Default::default()
            }],
            flags: true,
            autologon_password: Some(true),
            ..Default::default()
        });
        let (st, d) = one(&f, "account_flags", all.clone()).unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(
            summarize(&d),
            "帳號設定：Visitor 沒有密碼、bob 沒有密碼、Guest 帳號（Visitor）已啟用、bob 密碼永不過期、自動登入存了密碼"
        );
        // Guest 停用、沒存密碼；只勾 Linux 的項目：符合
        let a = f.accounts.as_mut().unwrap();
        a.users[1].disabled = true;
        a.users[2].no_password = Some(false);
        a.users[2].password_never_expires = false;
        a.autologon_password = Some(false);
        assert!(one(&f, "account_flags", all.clone()).is_none());
        assert!(one(&f, "account_flags", json!({"sudo_nopasswd": true})).is_none());
        // 讀取失敗：未知
        f.accounts.as_mut().unwrap().errors = vec!["無法讀取本機帳號：x".into()];
        let (st, d) = one(&f, "account_flags", all).unwrap();
        assert_eq!(st, Status::Unknown);
        assert_eq!(summarize(&d), "無法讀取帳號：無法讀取本機帳號：x");
    }

    #[test]
    fn account_flags_linux() {
        let mut f = linux(vec![]);
        let mut alice = user("alice", 1000);
        alice.no_password = Some(true);
        let mut locked = user("bob", 1001);
        locked.no_password = Some(true);
        locked.locked = Some(true);
        let sudo =
            |p: &str, kind: protocol::PrincipalKind, nopasswd_all: bool| protocol::PrivilegeEntry {
                principal: p.into(),
                kind,
                source: "sudoers:sudoers".into(),
                nopasswd_all,
            };
        f.accounts = Some(protocol::AccountsInfo {
            users: vec![user("root", 0), alice, locked, user("Visitor", 501)],
            privileged: vec![
                sudo("deploy", protocol::PrincipalKind::User, true),
                sudo("ops", protocol::PrincipalKind::Group, true),
                sudo("wheel", protocol::PrincipalKind::Group, false),
            ],
            flags: true,
            autologon_password: Some(true),
            ..Default::default()
        });
        let all = json!({"no_password": true, "guest_disabled": true, "password_expires": true,
                         "sudo_nopasswd": true, "no_autologon_password": true});
        let (st, d) = one(&f, "account_flags", all).unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(
            summarize(&d),
            "帳號設定：alice 沒有密碼、deploy 可以免密碼 sudo 執行任何指令、%ops 可以免密碼 sudo 執行任何指令"
        );
        assert!(
            one(
                &f,
                "account_flags",
                json!({"sudo_nopasswd": true, "except_accounts": ["%ops", "dep*"]})
            )
            .is_none()
        );
    }

    #[test]
    fn extra_root_account_rule() {
        let entry = |p: &str, src: &str| protocol::PrivilegeEntry {
            principal: p.into(),
            kind: protocol::PrincipalKind::User,
            source: src.into(),
            ..Default::default()
        };
        let mut f = linux(vec![]);
        assert_eq!(
            one(&f, "extra_root_account", json!({})).unwrap().0,
            Status::Unknown,
            "沒有帳號資料"
        );
        f.accounts = Some(protocol::AccountsInfo {
            users: vec![],
            system_user_count: 0,
            privileged: vec![
                entry("root", "uid0"),
                entry("admin", "/etc/sudoers"),
                entry("toor", "uid0"),
                entry("backdoor", "uid0"),
            ],
            sudoers_unparsed: vec![],
            ..Default::default()
        });
        let (st, d) = one(&f, "extra_root_account", json!({})).unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(summarize(&d), "root 以外的 UID 0 帳號：backdoor、toor");
        let (_, d) = one(
            &f,
            "extra_root_account",
            json!({"except_accounts": ["toor"]}),
        )
        .unwrap();
        assert_eq!(d["root_accounts"], json!(["backdoor"]));
        assert!(one(&f, "extra_root_account", json!({"except_accounts": ["*"]})).is_none());
        // Windows 裝置不適用
        assert!(one(&facts(vec![]), "extra_root_account", json!({})).is_none());
    }

    #[test]
    fn container_rules_platform_and_applicability() {
        // Windows 裝置不跑容器規則；Linux 裝置不跑其他規則
        assert!(one(&facts(vec![]), "unpinned_image", json!({})).is_none());
        let f = linux(vec![ctr("web", "nginx", "running")]);
        assert!(one(&f, "required_kb", json!({"kb": "KB5031455"})).is_none());
        // 沒有回報容器：不適用
        let none = DeviceFacts {
            containers: None,
            ..f.clone()
        };
        assert!(one(&none, "unpinned_image", json!({})).is_none());
        // 參數壞掉的規則只對 Windows
        let mut rs = set("unpinned_image", json!({}));
        rs.rules[0].check = Err("壞掉".into());
        assert!(evaluate(&f, &rs).is_empty());
        assert_eq!(evaluate(&facts(vec![]), &rs).len(), 1);
    }

    #[test]
    fn forbidden_and_unpinned_images() {
        let f = linux(vec![
            ctr("a", "xmrig/xmrig:6", "running"),
            ctr("b", "xmrig/xmrig:5", "exited"),
            ctr("c", "nginx:1.27", "running"),
        ]);
        let (st, d) = one(&f, "forbidden_image", json!({"image": "xmrig/*"})).unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(d["total"], 1);
        let (_, d) = one(
            &f,
            "forbidden_image",
            json!({"image": "xmrig/*", "running_only": false}),
        )
        .unwrap();
        assert_eq!(d["total"], 2);
        assert_eq!(
            summarize(&d),
            "使用禁止的映像：a（xmrig/xmrig:6）、b（xmrig/xmrig:5）"
        );
        assert!(one(&f, "unpinned_image", json!({})).is_none());

        let mut sys = ctr("lxd", "ubuntu", "running");
        sys.runtime = "lxc".into();
        let many: Vec<_> = (0..25)
            .map(|i| ctr(&format!("w{i}"), "busybox", "running"))
            .chain([sys, ctr("pause", "registry.k8s.io/pause", "running")])
            .collect();
        let (st, d) = one(
            &linux(many),
            "unpinned_image",
            json!({"except_images": ["*pause*"]}),
        )
        .unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(d["total"], 25, "系統容器與例外不算");
        assert_eq!(
            d["containers"].as_array().unwrap().len(),
            MAX_CONTAINERS_LISTED
        );
        assert!(summarize(&d).starts_with("映像未固定版本：w0（busybox）、"));
        assert!(summarize(&d).ends_with(" 等 25 個"));
    }

    #[test]
    fn container_privilege() {
        let mut p = ctr("p", "app:1", "running");
        p.privileged = Some(true);
        p.host_network = Some(true);
        let mut stopped = ctr("s", "app:1", "exited");
        stopped.privileged = Some(true);
        let mut k8s = ctr("k", "app:1", "running");
        k8s.privileged = None;
        k8s.host_network = None;
        k8s.k8s = Some(protocol::K8sRef {
            namespace: "ns".into(),
            pod: "pod".into(),
        });
        let mut sock = k8s.clone();
        sock.name = "sock".into();
        sock.host_mounts = vec!["/var/run/docker.sock".into()];
        let f = linux(vec![p, stopped, k8s, sock]);

        let (st, d) = one(
            &f,
            "container_privilege",
            json!({"privileged": true, "host_network": true, "runtime_socket": true}),
        )
        .unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(
            d,
            json!({"check": "privilege", "total": 2, "undetermined": 1, "containers": [
                {"name": "p", "image": "app:1", "issues": ["特權", "主機網路"]},
                {"name": "ns/sock", "image": "app:1", "issues": ["掛載容器 socket"]},
            ]})
        );
        assert_eq!(
            summarize(&d),
            "權限過大：p（app:1：特權、主機網路）、ns/sock（app:1：掛載容器 socket）；另有 1 個容器無法判斷"
        );
        // 只檢查主機網路、而且有例外
        let r = one(
            &f,
            "container_privilege",
            json!({"host_network": true, "except_images": ["app"]}),
        );
        assert_eq!(r, None, "全部都在例外");
        // 只檢查 socket：讀不到特權的容器不算無法判斷
        let (_, d) = one(&f, "container_privilege", json!({"runtime_socket": true})).unwrap();
        assert_eq!(d.get("undetermined"), None);
    }

    #[test]
    fn container_runtime_errors_are_unknown() {
        let mut f = linux(vec![]);
        let info = f.containers.as_mut().unwrap();
        info.runtimes[0].error = Some("daemon down".into());
        info.runtimes.push(protocol::RuntimeInfo {
            kind: "podman".into(),
            version: None,
            error: Some("denied".into()),
        });
        let (st, d) = one(&f, "forbidden_image", json!({"image": "x"})).unwrap();
        assert_eq!(st, Status::Unknown);
        assert_eq!(
            summarize(&d),
            "收集失敗：docker：daemon down；podman：denied"
        );
        // 有命中就算違規，不因為另一個環境失敗變成未知
        f.containers
            .as_mut()
            .unwrap()
            .containers
            .push(ctr("x", "x", "running"));
        let (st, _) = one(&f, "forbidden_image", json!({"image": "x"})).unwrap();
        assert_eq!(st, Status::Violating);
    }
}
