//! 名稱比對（`*` 萬用字元，不分大小寫）與版本比較。

use std::cmp::Ordering;

/// `*` 代表任意長度字串；整串比對；不分大小寫（Unicode 小寫化）。
#[derive(Debug, Clone, PartialEq)]
pub struct Glob {
    source: String,
    parts: Vec<String>,
}

impl Glob {
    pub fn new(pattern: &str) -> Glob {
        Glob {
            source: pattern.to_string(),
            parts: pattern
                .to_lowercase()
                .split('*')
                .map(str::to_string)
                .collect(),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.source
    }

    pub fn is_match(&self, s: &str) -> bool {
        let s = s.to_lowercase();
        let (first, last) = (&self.parts[0], &self.parts[self.parts.len() - 1]);
        if self.parts.len() == 1 {
            return s == *first;
        }
        if s.len() < first.len() + last.len()
            || !s.starts_with(first.as_str())
            || !s.ends_with(last.as_str())
        {
            return false;
        }
        // 中間各段依序取最左邊的出現位置（貪婪即正確）
        let mut rest = &s[first.len()..s.len() - last.len()];
        for mid in &self.parts[1..self.parts.len() - 1] {
            match rest.find(mid.as_str()) {
                Some(i) => rest = &rest[i + mid.len()..],
                None => return false,
            }
        }
        true
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Seg {
    Num(u64),
    Text(String),
}

fn segments(v: &str) -> Vec<Seg> {
    v.split(['.', '-', '_', '+', ' '])
        .filter(|s| !s.is_empty())
        .map(|s| match s.parse::<u64>() {
            Ok(n) => Seg::Num(n),
            Err(_) => Seg::Text(s.to_lowercase()),
        })
        .collect()
}

/// 逐段比較：數字對數字比數值、文字對文字比字串（不分大小寫）、數字大於文字；段數不足補 0。
pub fn cmp_version(a: &str, b: &str) -> Ordering {
    let (a, b) = (segments(a), segments(b));
    let zero = Seg::Num(0);
    for i in 0..a.len().max(b.len()) {
        let ord = match (a.get(i).unwrap_or(&zero), b.get(i).unwrap_or(&zero)) {
            (Seg::Num(x), Seg::Num(y)) => x.cmp(y),
            (Seg::Text(x), Seg::Text(y)) => x.cmp(y),
            (Seg::Num(_), Seg::Text(_)) => Ordering::Greater,
            (Seg::Text(_), Seg::Num(_)) => Ordering::Less,
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matches() {
        let cases = [
            ("Google Chrome", "google chrome", true),
            ("Google Chrome", "Google Chrome Beta", false),
            ("Google Chrome*", "Google Chrome Beta", true),
            ("*TeamViewer*", "TeamViewer 15", true),
            ("*TeamViewer*", "My teamviewer host", true),
            ("*viewer", "TeamViewer 15", false),
            ("a*b*c", "abc", true),
            ("a*b*c", "aXbYc", true),
            ("a*b*c", "acb", false),
            ("ab*ba", "aba", false),
            ("*", "", true),
            ("", "", true),
            ("", "x", false),
            ("ÄRGER*", "ärger 2", true),
            ("7-Zip*", "7-Zip 23.01 (x64)", true),
        ];
        for (pat, s, want) in cases {
            assert_eq!(Glob::new(pat).is_match(s), want, "{pat:?} vs {s:?}");
        }
    }

    #[test]
    fn version_order() {
        use Ordering::*;
        let cases = [
            ("10.0.9", "10.0.10", Less),
            ("1.2", "1.2.0", Equal),
            ("1.2.0.0", "1.2", Equal),
            ("1.0", "1.0-beta", Greater),
            ("1.0-alpha", "1.0-beta", Less),
            ("1.0-BETA", "1.0-beta", Equal),
            ("120.0.6099.130", "120.0.6099.71", Greater),
            ("2", "10", Less),
            ("", "0", Equal),
            ("99999999999999999999999", "1", Less), // 超過 u64 當文字，文字小於數字
        ];
        for (a, b, want) in cases {
            assert_eq!(cmp_version(a, b), want, "{a:?} vs {b:?}");
            assert_eq!(cmp_version(b, a), want.reverse(), "{b:?} vs {a:?}");
        }
    }
}
