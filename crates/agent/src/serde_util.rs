//! WMI 的 uint64 屬性有時以字串、有時以數字回傳，也可能是 null。

use serde::{Deserialize, Deserializer};

pub fn u64_any<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Num {
        N(u64),
        S(String),
    }
    Ok(match Option::<Num>::deserialize(d)? {
        Some(Num::N(n)) => Some(n),
        Some(Num::S(s)) => s.trim().parse().ok(),
        None => None,
    })
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct T {
        #[serde(default, deserialize_with = "super::u64_any")]
        n: Option<u64>,
    }

    #[test]
    fn u64_any_accepts_number_string_and_null() {
        let p = |j: &str| serde_json::from_str::<T>(j).unwrap().n;
        assert_eq!(p(r#"{"n": 42}"#), Some(42));
        assert_eq!(p(r#"{"n": "17179869184"}"#), Some(17_179_869_184));
        assert_eq!(p(r#"{"n": " 7 "}"#), Some(7));
        assert_eq!(p(r#"{"n": "garbage"}"#), None);
        assert_eq!(p(r#"{"n": null}"#), None);
        assert_eq!(p(r#"{}"#), None);
    }
}
