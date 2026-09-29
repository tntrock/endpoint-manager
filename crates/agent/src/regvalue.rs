//! 登錄檔原始值 → 回報格式（純函式，可在任何平台測試）。

use protocol::{MAX_STRING_LEN, RegKind};

fn cap(s: String) -> String {
    s.chars().take(MAX_STRING_LEN).collect()
}

/// UTF-16LE → 以 NUL 分隔的字串；奇數長度（格式錯誤）回 None。
fn utf16(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some(
        units
            .split(|u| *u == 0)
            .map(String::from_utf16_lossy)
            .collect(),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(MAX_STRING_LEN / 2)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// 依登錄檔型別（REG_*）轉成回報的類型與文字：數字為十進位、多字串以換行連接、
/// 二進位與未知型別為 hex；格式錯誤時內容為空字串，不會 panic。
pub fn render(vtype: u32, bytes: &[u8]) -> (RegKind, String) {
    match vtype {
        4 => (
            RegKind::Dword,
            bytes
                .get(..4)
                .map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")).to_string())
                .unwrap_or_default(),
        ),
        11 => (
            RegKind::Qword,
            bytes
                .get(..8)
                .map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes")).to_string())
                .unwrap_or_default(),
        ),
        1 | 2 => {
            let kind = if vtype == 1 {
                RegKind::String
            } else {
                RegKind::ExpandString
            };
            let s = utf16(bytes)
                .and_then(|v| v.into_iter().next())
                .unwrap_or_default();
            (kind, cap(s))
        }
        7 => {
            let parts = utf16(bytes).unwrap_or_default();
            let s = parts
                .into_iter()
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>()
                .join("\n");
            (RegKind::MultiString, cap(s))
        }
        3 => (RegKind::Binary, hex(bytes)),
        _ => (RegKind::Other, hex(bytes)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REG_SZ: u32 = 1;
    const REG_EXPAND_SZ: u32 = 2;
    const REG_BINARY: u32 = 3;
    const REG_DWORD: u32 = 4;
    const REG_MULTI_SZ: u32 = 7;
    const REG_QWORD: u32 = 11;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    #[test]
    fn renders_each_type() {
        assert_eq!(
            render(REG_DWORD, &5u32.to_le_bytes()),
            (RegKind::Dword, "5".into())
        );
        assert_eq!(
            render(REG_QWORD, &(1u64 << 40).to_le_bytes()),
            (RegKind::Qword, (1u64 << 40).to_string())
        );
        assert_eq!(
            render(REG_SZ, &utf16("Windows 11")),
            (RegKind::String, "Windows 11".into())
        );
        assert_eq!(
            render(REG_EXPAND_SZ, &utf16("%SystemRoot%")),
            (RegKind::ExpandString, "%SystemRoot%".into())
        );
        let mut multi: Vec<u8> = utf16("a");
        multi.extend(utf16("b"));
        multi.extend([0, 0]);
        assert_eq!(
            render(REG_MULTI_SZ, &multi),
            (RegKind::MultiString, "a\nb".into())
        );
        assert_eq!(
            render(REG_BINARY, &[0xde, 0xad]),
            (RegKind::Binary, "dead".into())
        );
    }

    #[test]
    fn malformed_data_does_not_panic() {
        assert_eq!(
            render(REG_DWORD, &[1, 2]),
            (RegKind::Dword, String::new()),
            "長度不足"
        );
        assert_eq!(
            render(REG_SZ, &[0x41]),
            (RegKind::String, String::new()),
            "奇數長度"
        );
        let (k, d) = render(REG_SZ, &[0x00, 0xd8, 0x41, 0x00, 0, 0]); // 孤立的 surrogate
        assert_eq!(k, RegKind::String);
        assert!(d.contains('A'), "{d:?}");
        let (_, d) = render(REG_BINARY, &[0xab; 5000]);
        assert_eq!(d.chars().count(), protocol::MAX_STRING_LEN, "截斷");
        assert_eq!(render(99, &[1]), (RegKind::Other, "01".into()));
        assert_eq!(render(REG_SZ, &[]), (RegKind::String, String::new()));
    }
}
