//! 作業系統紀錄裡和竄改有關的事件（竄改偵測規格 §4.2、§4.3）。
//!
//! 這裡只有解析與判斷的純函式，各平台都能測試；實際讀取紀錄在 `windows::oslog`、`linux::oslog`。
//!
//! - Windows：系統紀錄 7031、7034（服務意外終止，7031 是設了失敗復原動作的服務）、
//!   7036（服務停止；新版 Windows 預設不記）、7040（啟動類型被改變）只看
//!   Agent 自己的服務；104（系統紀錄被清除）、安全性紀錄 1102（稽核紀錄被清除）全部都看。
//! - Linux：journald 裡 systemd 對 Agent 服務的「Stopping」「code=killed」等訊息。

use protocol::{OsLogCleared, OsServiceStopped, timefmt};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// 從紀錄裡讀到的一筆
#[derive(Debug, Clone, PartialEq)]
pub enum OsEvent {
    ServiceStopped(OsServiceStopped),
    LogCleared(OsLogCleared),
    /// Agent 服務的啟動類型被改變（7040）：立刻重新檢查啟動類型
    StartTypeChanged,
}

/// 解析後的 Windows 事件（只取需要的欄位）
#[derive(Debug, Clone, PartialEq)]
pub struct WinEvent {
    pub provider: String,
    pub event_id: u32,
    pub record_id: u64,
    pub time: OffsetDateTime,
    pub channel: String,
    pub user_sid: Option<String>,
    xml: String,
}

pub(crate) fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// `<name>` 或 `<name 屬性…>` 到 `</name>` 之間的文字
fn tag_text<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let mut from = 0;
    while let Some(i) = xml[from..].find(&format!("<{name}")) {
        let start = from + i + name.len() + 1;
        let rest = &xml[start..];
        match rest.chars().next() {
            Some('>') | Some(' ') => {
                let gt = rest.find('>')?;
                if rest[..gt].ends_with('/') {
                    return Some("");
                }
                let body = &rest[gt + 1..];
                let end = body.find(&format!("</{name}>"))?;
                return Some(&body[..end]);
            }
            _ => from = start,
        }
    }
    None
}

/// `<elem … attr='值'…>` 的屬性值（單引號或雙引號）
fn attr<'a>(xml: &'a str, elem: &str, name: &str) -> Option<&'a str> {
    let mut from = 0;
    loop {
        let i = xml[from..].find(&format!("<{elem}"))?;
        let start = from + i + elem.len() + 1;
        let rest = &xml[start..];
        if !rest.starts_with(' ') {
            from = start;
            continue;
        }
        let tag = &rest[..rest.find('>')?];
        for q in ['\'', '"'] {
            let key = format!(" {name}={q}");
            if let Some(k) = tag.find(&key) {
                let v = &tag[k + key.len()..];
                return Some(&v[..v.find(q)?]);
            }
        }
        return None;
    }
}

/// `<Data Name='param1'>值</Data>`
fn data<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    for q in ['\'', '"'] {
        let key = format!("<Data Name={q}{name}{q}>");
        if let Some(i) = xml.find(&key) {
            let v = &xml[i + key.len()..];
            return Some(&v[..v.find("</Data>")?]);
        }
    }
    None
}

/// `<Binary>` 的十六進位 UTF-16LE 文字（服務控制管理員寫成「服務名稱/狀態」）
fn binary_text(xml: &str) -> Option<String> {
    let hex = tag_text(xml, "Binary")?.trim();
    if hex.len() % 4 != 0 {
        return None;
    }
    let units: Option<Vec<u16>> = (0..hex.len())
        .step_by(4)
        .map(|i| {
            let lo = u8::from_str_radix(hex.get(i..i + 2)?, 16).ok()?;
            let hi = u8::from_str_radix(hex.get(i + 2..i + 4)?, 16).ok()?;
            Some(u16::from_le_bytes([lo, hi]))
        })
        .collect();
    let s = String::from_utf16(&units?).ok()?;
    Some(s.trim_end_matches('\0').to_string())
}

/// 解析 `EvtRender(EvtRenderEventXml)` 的結果
pub fn parse_event_xml(xml: &str) -> Option<WinEvent> {
    let system = tag_text(xml, "System")?;
    Some(WinEvent {
        provider: unescape(attr(system, "Provider", "Name")?),
        event_id: tag_text(system, "EventID")?.trim().parse().ok()?,
        record_id: tag_text(system, "EventRecordID")?.trim().parse().ok()?,
        time: timefmt::parse_rfc3339(attr(system, "TimeCreated", "SystemTime")?).ok()?,
        channel: unescape(tag_text(system, "Channel").unwrap_or_default()),
        user_sid: attr(system, "Security", "UserID").map(unescape),
        xml: xml.to_string(),
    })
}

const SCM: &str = "Service Control Manager";
const EVENTLOG: &str = "Microsoft-Windows-Eventlog";

/// `網域\帳號`（沒有網域時只有帳號）
fn subject(user_data: &str) -> Option<String> {
    let user = unescape(tag_text(user_data, "SubjectUserName")?.trim());
    if user.is_empty() {
        return None;
    }
    let domain = tag_text(user_data, "SubjectDomainName")
        .map(|d| unescape(d.trim()))
        .unwrap_or_default();
    Some(if domain.is_empty() {
        user
    } else {
        format!("{domain}\\{user}")
    })
}

/// 判斷這筆事件和 Agent 服務（`service` 是服務名稱，`display` 是顯示名稱）有沒有關係
pub fn classify(ev: &WinEvent, service: &str, display: &str) -> Option<OsEvent> {
    let ours = || {
        let by_binary = binary_text(&ev.xml)
            .and_then(|b| b.split('/').next().map(str::to_string))
            .is_some_and(|name| name.eq_ignore_ascii_case(service));
        let by_name = data(&ev.xml, "param1").is_some_and(|p| unescape(p) == display);
        by_binary || by_name
    };
    let stopped = |killed: bool| {
        OsEvent::ServiceStopped(OsServiceStopped {
            at: ev.time,
            source: "eventlog".into(),
            event_id: Some(ev.event_id),
            killed,
            user: ev.user_sid.clone(),
            message: None,
        })
    };
    match (ev.provider.as_str(), ev.event_id) {
        (SCM, 7031 | 7034) if ours() => Some(stopped(true)),
        // 狀態寫在 Binary 的「服務名稱/1」（1 = 已停止），param2 是翻譯過的文字
        (SCM, 7036) => {
            let b = binary_text(&ev.xml)?;
            let (name, state) = b.split_once('/')?;
            (name.eq_ignore_ascii_case(service) && state == "1").then(|| stopped(false))
        }
        (SCM, 7040) => data(&ev.xml, "param4")
            .is_some_and(|p| p.eq_ignore_ascii_case(service))
            .then_some(OsEvent::StartTypeChanged),
        (EVENTLOG, 1102 | 104) => {
            let user_data = tag_text(&ev.xml, "UserData").unwrap_or_default();
            let log = if ev.event_id == 1102 {
                "Security".to_string()
            } else {
                tag_text(user_data, "Channel")
                    .map(|c| unescape(c.trim()))
                    .filter(|c| !c.is_empty())
                    .unwrap_or_else(|| ev.channel.clone())
            };
            Some(OsEvent::LogCleared(OsLogCleared {
                at: ev.time,
                log,
                event_id: ev.event_id,
                user: subject(user_data),
            }))
        }
        _ => None,
    }
}

/// 每個紀錄讀到哪裡：時間（查詢條件）與那個時間點已讀過的最大紀錄編號。
/// 不用紀錄編號當條件：紀錄被清除後編號會從頭開始。
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Cursor {
    #[serde(with = "timefmt::rfc3339")]
    pub time: OffsetDateTime,
    pub record: u64,
}

impl Cursor {
    /// 這筆是否已經讀過
    pub fn seen(&self, ev: &WinEvent) -> bool {
        ev.time < self.time || (ev.time == self.time && ev.record_id <= self.record)
    }

    pub fn advance(&mut self, ev: &WinEvent) {
        if !self.seen(ev) {
            self.time = ev.time;
            self.record = ev.record_id;
        }
    }
}

/// 系統紀錄要看的事件
pub const SYSTEM_IDS: [u32; 5] = [104, 7031, 7034, 7036, 7040];
/// 安全性紀錄要看的事件
pub const SECURITY_IDS: [u32; 1] = [1102];

/// 查詢條件：指定的事件 ID、時間不早於 `since`
pub fn xpath(ids: &[u32], since: OffsetDateTime) -> String {
    let ids = ids
        .iter()
        .map(|i| format!("EventID={i}"))
        .collect::<Vec<_>>()
        .join(" or ");
    let t = timefmt::format_rfc3339(since).unwrap_or_default();
    format!("*[System[({ids}) and TimeCreated[@SystemTime>='{t}']]]")
}

/// journald 一筆（`journalctl -o json`）
#[derive(Deserialize)]
struct JournalEntry {
    #[serde(rename = "MESSAGE")]
    message: Option<serde_json::Value>,
    #[serde(rename = "__REALTIME_TIMESTAMP")]
    realtime: Option<String>,
    #[serde(rename = "_PID")]
    pid: Option<String>,
}

/// 解析 `journalctl -u <服務> -o json` 的輸出：只看 systemd（PID 1）對服務的停止訊息
pub fn parse_journal(output: &str) -> Vec<OsServiceStopped> {
    output
        .lines()
        .filter_map(|l| serde_json::from_str::<JournalEntry>(l).ok())
        .filter(|e| e.pid.as_deref() == Some("1"))
        .filter_map(|e| {
            let msg = e.message?.as_str()?.to_string();
            let killed = msg.contains("code=killed") || msg.contains("code=dumped");
            if !killed && !msg.starts_with("Stopping ") {
                return None;
            }
            let us: i128 = e.realtime?.parse().ok()?;
            let at = OffsetDateTime::from_unix_timestamp_nanos(us * 1000).ok()?;
            Some(OsServiceStopped {
                at,
                source: "journald".into(),
                event_id: None,
                killed,
                user: None,
                message: Some(msg),
            })
        })
        .collect()
}

/// 從 `/proc/self/cgroup` 找出 Agent 所在的 systemd 服務（例如 `endpoint-agent.service`）
pub fn unit_from_cgroup(cgroup: &str) -> Option<String> {
    cgroup.lines().find_map(|l| {
        let path = l.rsplit(':').next()?;
        path.split('/')
            .rev()
            .find(|seg| seg.ends_with(".service"))
            .map(str::to_string)
    })
}

/// `systemctl show -p UnitFileState --value` 對應到啟動類型
pub fn start_type_from_unit_file_state(state: &str) -> Option<&'static str> {
    use protocol::start_type::*;
    match state.trim() {
        "enabled" | "enabled-runtime" | "alias" => Some(AUTO),
        "disabled" | "masked" | "masked-runtime" => Some(DISABLED),
        // 沒有安裝成服務（例如手動執行）
        "" | "bad" => None,
        _ => Some(MANUAL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn hex16(s: &str) -> String {
        s.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .map(|b| format!("{b:02X}"))
            .collect()
    }

    fn scm(id: u32, params: &[(&str, &str)], binary: Option<&str>) -> String {
        let data: String = params
            .iter()
            .map(|(k, v)| format!("<Data Name='{k}'>{v}</Data>"))
            .collect();
        let bin = binary
            .map(|b| format!("<Binary>{}</Binary>", hex16(b)))
            .unwrap_or_default();
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
             <Provider Name='Service Control Manager' Guid='{{555908d1-a6d7-4695-8e1e-26931d2012f4}}' EventSourceName='Service Control Manager'/>\
             <EventID Qualifiers='16384'>{id}</EventID><Version>0</Version><Level>4</Level>\
             <TimeCreated SystemTime='2026-11-24T01:02:03.1234567Z'/><EventRecordID>500</EventRecordID>\
             <Correlation/><Execution ProcessID='800' ThreadID='900'/><Channel>System</Channel>\
             <Computer>PC1</Computer><Security UserID='S-1-5-21-1-2-3-1001'/></System>\
             <EventData>{data}{bin}</EventData></Event>"
        )
    }

    fn stopped(e: Option<OsEvent>) -> OsServiceStopped {
        let Some(OsEvent::ServiceStopped(s)) = e else {
            unreachable!()
        };
        s
    }

    fn cleared_of(e: Option<OsEvent>) -> OsLogCleared {
        let Some(OsEvent::LogCleared(c)) = e else {
            unreachable!()
        };
        c
    }

    const SVC: &str = "EndpointManagerAgent";
    const DISPLAY: &str = "Endpoint Manager Agent";

    #[test]
    fn parses_system_fields() {
        let ev = parse_event_xml(&scm(7036, &[], None)).unwrap();
        assert_eq!(ev.provider, SCM);
        assert_eq!(ev.event_id, 7036);
        assert_eq!(ev.record_id, 500);
        assert_eq!(ev.channel, "System");
        assert_eq!(ev.user_sid.as_deref(), Some("S-1-5-21-1-2-3-1001"));
        assert_eq!(ev.time, datetime!(2026-11-24 01:02:03.1234567 UTC));
        assert_eq!(parse_event_xml("<Event><System></System></Event>"), None);
        assert_eq!(parse_event_xml("garbage"), None);
    }

    #[test]
    fn service_stop_only_for_our_service() {
        let stop = |name: &str, state: &str| {
            let xml = scm(
                7036,
                &[("param1", "顯示名稱"), ("param2", "已停止")],
                Some(&format!("{name}/{state}")),
            );
            classify(&parse_event_xml(&xml).unwrap(), SVC, DISPLAY)
        };
        let s = stopped(stop("EndpointManagerAgent", "1"));
        assert!(!s.killed);
        assert_eq!(s.event_id, Some(7036));
        assert_eq!(s.source, "eventlog");
        assert_eq!(s.user.as_deref(), Some("S-1-5-21-1-2-3-1001"));
        // 進入執行中、別的服務、沒有 Binary 都不算
        assert_eq!(stop("EndpointManagerAgent", "4"), None);
        assert_eq!(stop("BITS", "1"), None);
        let xml = scm(7036, &[("param1", DISPLAY)], None);
        assert_eq!(
            classify(&parse_event_xml(&xml).unwrap(), SVC, DISPLAY),
            None
        );
    }

    #[test]
    fn unexpected_termination_is_killed() {
        let xml = scm(7034, &[("param1", DISPLAY), ("param2", "1")], None);
        assert!(stopped(classify(&parse_event_xml(&xml).unwrap(), SVC, DISPLAY)).killed);
        let xml = scm(7034, &[("param1", "Other")], Some("endpointmanageragent/0"));
        assert!(classify(&parse_event_xml(&xml).unwrap(), SVC, DISPLAY).is_some());
        let xml = scm(7034, &[("param1", "Other")], None);
        assert_eq!(
            classify(&parse_event_xml(&xml).unwrap(), SVC, DISPLAY),
            None
        );
        // 有失敗復原動作時記的是 7031，Binary 只有服務名稱（實機格式）
        let xml = scm(
            7031,
            &[
                ("param1", DISPLAY),
                ("param2", "1"),
                ("param5", "重新啟動服務"),
            ],
            Some(SVC),
        );
        let s = stopped(classify(&parse_event_xml(&xml).unwrap(), SVC, DISPLAY));
        assert!(s.killed);
        assert_eq!(s.event_id, Some(7031));
        // 別的提供者用同樣的 ID 不算
        let xml = scm(7031, &[("param1", DISPLAY)], Some(SVC)).replace(SCM, "VfpExt");
        assert_eq!(
            classify(&parse_event_xml(&xml).unwrap(), SVC, DISPLAY),
            None
        );
    }

    #[test]
    fn start_type_change_of_our_service() {
        let xml = scm(
            7040,
            &[
                ("param1", DISPLAY),
                ("param2", "自動啟動"),
                ("param3", "已停用"),
                ("param4", SVC),
            ],
            None,
        );
        assert_eq!(
            classify(&parse_event_xml(&xml).unwrap(), SVC, DISPLAY),
            Some(OsEvent::StartTypeChanged)
        );
        let xml = scm(7040, &[("param4", "BITS")], None);
        assert_eq!(
            classify(&parse_event_xml(&xml).unwrap(), SVC, DISPLAY),
            None
        );
    }

    fn cleared(id: u32, channel: &str, user_data: &str) -> String {
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
             <Provider Name='Microsoft-Windows-Eventlog' Guid='{{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}}'/>\
             <EventID>{id}</EventID><TimeCreated SystemTime='2026-11-24T05:00:00.5Z'/>\
             <EventRecordID>1</EventRecordID><Channel>{channel}</Channel><Computer>PC1</Computer>\
             <Security/></System><UserData>{user_data}</UserData></Event>"
        )
    }

    #[test]
    fn log_cleared_with_user() {
        let xml = cleared(
            1102,
            "Security",
            "<LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>\
             <SubjectUserSid>S-1-5-21-9</SubjectUserSid><SubjectUserName>wang&amp;co</SubjectUserName>\
             <SubjectDomainName>CORP</SubjectDomainName><SubjectLogonId>0x1</SubjectLogonId></LogFileCleared>",
        );
        let ev = parse_event_xml(&xml).unwrap();
        assert_eq!(ev.user_sid, None);
        let c = cleared_of(classify(&ev, SVC, DISPLAY));
        assert_eq!(c.log, "Security");
        assert_eq!(c.event_id, 1102);
        assert_eq!(c.user.as_deref(), Some("CORP\\wang&co"));
        assert_eq!(c.at, datetime!(2026-11-24 05:00:00.5 UTC));
        let xml = cleared(
            104,
            "System",
            "<LogFileCleared><SubjectUserName>admin</SubjectUserName><SubjectDomainName></SubjectDomainName>\
             <Channel>Application</Channel><BackupPath></BackupPath></LogFileCleared>",
        );
        let c = cleared_of(classify(&parse_event_xml(&xml).unwrap(), SVC, DISPLAY));
        assert_eq!(c.log, "Application");
        assert_eq!(c.user.as_deref(), Some("admin"));
        // 沒有 UserData：用事件所在的紀錄，沒有使用者
        let xml = cleared(104, "System", "");
        let c = cleared_of(classify(&parse_event_xml(&xml).unwrap(), SVC, DISPLAY));
        assert_eq!(c.log, "System");
        assert_eq!(c.user, None);
        // 別的來源的 104 不算
        let xml = cleared(104, "System", "").replace(EVENTLOG, "Other");
        assert_eq!(
            classify(&parse_event_xml(&xml).unwrap(), SVC, DISPLAY),
            None
        );
    }

    #[test]
    fn xml_helpers_edge_cases() {
        assert_eq!(tag_text("<Ab>x</Ab><A>y</A>", "A"), Some("y"));
        assert_eq!(tag_text("<A />", "A"), Some(""));
        assert_eq!(tag_text("<A>open", "A"), None);
        assert_eq!(tag_text("<B>x</B>", "A"), None);
        assert_eq!(attr("<Ax b='1'/><A b=\"2\"/>", "A", "b"), Some("2"));
        assert_eq!(attr("<A c='1'/>", "A", "b"), None);
        assert_eq!(attr("<B b='1'/>", "A", "b"), None);
        assert_eq!(data("<Data Name=\"p\">v</Data>", "p"), Some("v"));
        assert_eq!(data("<Data Name='q'>v</Data>", "p"), None);
        assert_eq!(binary_text("<Binary>ABC</Binary>"), None);
        assert_eq!(binary_text("<Binary>ZZZZ</Binary>"), None);
        assert_eq!(
            binary_text("<Binary>41004200</Binary>").as_deref(),
            Some("AB")
        );
        // 沒有帳號
        assert_eq!(subject("<SubjectUserName> </SubjectUserName>"), None);
        assert_eq!(subject(""), None);
    }

    #[test]
    fn cursor_skips_seen_events() {
        let ev = |t: OffsetDateTime, r: u64| WinEvent {
            provider: String::new(),
            event_id: 1,
            record_id: r,
            time: t,
            channel: String::new(),
            user_sid: None,
            xml: String::new(),
        };
        let t = datetime!(2026-11-24 01:00 UTC);
        let mut c = Cursor {
            time: t,
            record: 10,
        };
        assert!(c.seen(&ev(t, 10)));
        assert!(c.seen(&ev(t - time::Duration::SECOND, 99)));
        assert!(!c.seen(&ev(t, 11)));
        // 紀錄清除後編號從頭開始，但時間比較晚：沒讀過
        let later = t + time::Duration::SECOND;
        assert!(!c.seen(&ev(later, 1)));
        c.advance(&ev(later, 1));
        assert_eq!(
            c,
            Cursor {
                time: later,
                record: 1
            }
        );
        c.advance(&ev(t, 50));
        assert_eq!(c.record, 1);
    }

    #[test]
    fn xpath_lists_ids_and_time() {
        assert_eq!(
            xpath(&SYSTEM_IDS, datetime!(2026-11-24 01:00:00.5 UTC)),
            "*[System[(EventID=104 or EventID=7031 or EventID=7034 or EventID=7036 or EventID=7040) \
             and TimeCreated[@SystemTime>='2026-11-24T01:00:00.5Z']]]"
        );
    }

    #[test]
    fn journal_stop_messages() {
        let out = [
            r#"{"MESSAGE":"Stopping endpoint-agent.service - Endpoint Manager Agent...","__REALTIME_TIMESTAMP":"1764000000000000","_PID":"1"}"#,
            r#"{"MESSAGE":"endpoint-agent.service: Main process exited, code=killed, status=9/KILL","__REALTIME_TIMESTAMP":"1764000100500000","_PID":"1"}"#,
            r#"{"MESSAGE":"Stopping is what the agent logs","__REALTIME_TIMESTAMP":"1764000000000000","_PID":"4242"}"#,
            r#"{"MESSAGE":"Started endpoint-agent.service","__REALTIME_TIMESTAMP":"1764000000000000","_PID":"1"}"#,
            r#"{"MESSAGE":[1,2,3],"__REALTIME_TIMESTAMP":"1","_PID":"1"}"#,
            "not json",
        ]
        .join("\n");
        let v = parse_journal(&out);
        assert_eq!(v.len(), 2);
        assert!(!v[0].killed);
        assert_eq!(v[0].at, datetime!(2025-11-24 16:00 UTC));
        assert!(v[1].killed);
        assert_eq!(v[1].source, "journald");
        assert!(v[1].message.as_deref().unwrap().contains("status=9"));
    }

    #[test]
    fn unit_and_start_type() {
        assert_eq!(
            unit_from_cgroup("0::/system.slice/endpoint-agent.service\n").as_deref(),
            Some("endpoint-agent.service")
        );
        assert_eq!(
            unit_from_cgroup("12:pids:/system.slice/em-demo-agent.service/x\n1:name=systemd:/")
                .as_deref(),
            Some("em-demo-agent.service")
        );
        assert_eq!(unit_from_cgroup("0::/user.slice/session-1.scope"), None);
        assert_eq!(start_type_from_unit_file_state("enabled\n"), Some("auto"));
        assert_eq!(start_type_from_unit_file_state("masked"), Some("disabled"));
        assert_eq!(start_type_from_unit_file_state("static"), Some("manual"));
        assert_eq!(start_type_from_unit_file_state(""), None);
    }
}
