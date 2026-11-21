//! 時間欄位的 JSON 格式（`time` crate）。
//!
//! 與先前 chrono 的格式相容：時間是 RFC 3339（UTC 以 `Z` 結尾，可有小數秒），
//! 日期是 `YYYY-MM-DD`。新舊版本的 Agent 與伺服器互相看得懂，也讀得懂舊的狀態檔。

use serde::{Deserialize, Deserializer, Serializer, de::Error as _, ser::Error as _};
use time::format_description::BorrowedFormatItem;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, OffsetDateTime, UtcOffset};

const DATE: &[BorrowedFormatItem<'static>] = format_description!("[year]-[month]-[day]");

/// 轉成 UTC 的 RFC 3339 字串
pub fn format_rfc3339(t: OffsetDateTime) -> Result<String, time::error::Format> {
    t.to_offset(UtcOffset::UTC).format(&Rfc3339)
}

pub fn parse_rfc3339(s: &str) -> Result<OffsetDateTime, time::error::Parse> {
    OffsetDateTime::parse(s, &Rfc3339).map(|t| t.to_offset(UtcOffset::UTC))
}

pub fn format_date(d: Date) -> String {
    d.format(DATE).expect("date format")
}

pub fn parse_date(s: &str) -> Result<Date, time::error::Parse> {
    Date::parse(s, DATE)
}

/// 年月日；不存在的日期回 None
pub fn ymd(year: i32, month: u8, day: u8) -> Option<Date> {
    Date::from_calendar_date(year, time::Month::try_from(month).ok()?, day).ok()
}

/// `#[serde(with = "protocol::timefmt::rfc3339")]`
pub mod rfc3339 {
    use super::*;

    pub fn serialize<S: Serializer>(t: &OffsetDateTime, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format_rfc3339(*t).map_err(S::Error::custom)?)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<OffsetDateTime, D::Error> {
        let s = String::deserialize(d)?;
        parse_rfc3339(&s).map_err(D::Error::custom)
    }
}

/// `#[serde(with = "protocol::timefmt::rfc3339_option", default)]`
pub mod rfc3339_option {
    use super::*;

    pub fn serialize<S: Serializer>(t: &Option<OffsetDateTime>, s: S) -> Result<S::Ok, S::Error> {
        match t {
            Some(t) => s.serialize_some(&format_rfc3339(*t).map_err(S::Error::custom)?),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<OffsetDateTime>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| parse_rfc3339(&s).map_err(D::Error::custom))
            .transpose()
    }
}

/// `#[serde(with = "protocol::timefmt::rfc3339_vec", default)]`
pub mod rfc3339_vec {
    use super::*;
    use serde::ser::SerializeSeq;

    pub fn serialize<S: Serializer>(v: &[OffsetDateTime], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for t in v {
            seq.serialize_element(&format_rfc3339(*t).map_err(S::Error::custom)?)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<OffsetDateTime>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|s| parse_rfc3339(s).map_err(D::Error::custom))
            .collect()
    }
}

/// `#[serde(with = "protocol::timefmt::date_option", default)]`
pub mod date_option {
    use super::*;

    pub fn serialize<S: Serializer>(d: &Option<Date>, s: S) -> Result<S::Ok, S::Error> {
        match d {
            Some(d) => s.serialize_some(&format_date(*d)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Date>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| parse_date(&s).map_err(D::Error::custom))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;
    use time::macros::{date, datetime};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct T {
        #[serde(with = "rfc3339")]
        at: OffsetDateTime,
        #[serde(with = "rfc3339_option", default)]
        maybe: Option<OffsetDateTime>,
        #[serde(with = "date_option", default)]
        day: Option<Date>,
    }

    /// 舊版（chrono）送出的格式都要讀得懂
    #[test]
    fn reads_chrono_output() {
        let t: T = serde_json::from_str(
            r#"{"at":"2026-11-21T10:32:43.123456789Z","maybe":"2026-11-21T18:32:43+08:00","day":"2026-01-02"}"#,
        )
        .unwrap();
        assert_eq!(t.at, datetime!(2026-11-21 10:32:43.123456789 UTC));
        assert_eq!(t.maybe, Some(datetime!(2026-11-21 10:32:43 UTC)));
        assert_eq!(t.day, Some(date!(2026 - 01 - 02)));
        let t: T = serde_json::from_str(r#"{"at":"1970-01-01T00:00:00Z","maybe":null}"#).unwrap();
        assert_eq!(t.at, OffsetDateTime::UNIX_EPOCH);
        assert_eq!((t.maybe, t.day), (None, None));
        assert!(serde_json::from_str::<T>(r#"{"at":"yesterday"}"#).is_err());
        assert!(
            serde_json::from_str::<T>(r#"{"at":"1970-01-01T00:00:00Z","day":"2026-1-2"}"#).is_err()
        );
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct V {
        #[serde(with = "rfc3339_vec", default)]
        all: Vec<OffsetDateTime>,
    }

    #[test]
    fn vec_and_helpers() {
        let v = V {
            all: vec![
                OffsetDateTime::UNIX_EPOCH,
                datetime!(2026-11-21 10:00 +08:00),
            ],
        };
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(
            s,
            r#"{"all":["1970-01-01T00:00:00Z","2026-11-21T02:00:00Z"]}"#
        );
        assert_eq!(serde_json::from_str::<V>(&s).unwrap(), v);
        assert!(serde_json::from_str::<V>("{}").unwrap().all.is_empty());
        assert!(serde_json::from_str::<V>(r#"{"all":["nope"]}"#).is_err());

        assert_eq!(ymd(2026, 2, 28), Some(date!(2026 - 02 - 28)));
        assert_eq!(ymd(2026, 2, 29), None);
        assert_eq!(ymd(2026, 13, 1), None);
        assert_eq!(format_date(date!(2026 - 01 - 02)), "2026-01-02");
        assert_eq!(parse_date("2026-01-02").unwrap(), date!(2026 - 01 - 02));
        assert!(parse_date("2026/01/02").is_err());
        // 年份超出 RFC 3339 範圍時寫出失敗，而不是寫出錯誤的字串
        assert!(
            format_rfc3339(OffsetDateTime::new_utc(
                date!(-0001 - 01 - 01),
                time::Time::MIDNIGHT
            ))
            .is_err()
        );
    }

    /// 寫出的格式與 chrono 相同（UTC 以 Z 結尾）
    #[test]
    fn writes_chrono_compatible() {
        let t = T {
            at: datetime!(2026-11-21 18:32:43.5 +08:00),
            maybe: None,
            day: Some(date!(2026 - 01 - 02)),
        };
        assert_eq!(
            serde_json::to_string(&t).unwrap(),
            r#"{"at":"2026-11-21T10:32:43.5Z","maybe":null,"day":"2026-01-02"}"#
        );
        let back: T = serde_json::from_str(&serde_json::to_string(&t).unwrap()).unwrap();
        assert_eq!(back, t);
    }
}
