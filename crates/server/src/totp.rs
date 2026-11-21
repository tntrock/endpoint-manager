//! TOTP（RFC 6238）：HMAC-SHA1、6 位數、30 秒一步。驗證器 App 的共同預設值。

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

pub const STEP_SECS: i64 = 30;
pub const DIGITS: u32 = 6;
/// 接受目前時間前後各幾步
pub const SKEW: i64 = 1;
pub const SECRET_LEN: usize = 20;
pub const RECOVERY_CODES: usize = 10;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 Base32，不補 `=`（驗證器 App 接受的格式）
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// 解碼時忽略空白、`=` 與大小寫；有其他字元回 None
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let v = BASE32
            .iter()
            .position(|&b| b as char == c.to_ascii_uppercase())? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// 指定時間步的驗證碼（`digits` 位數，RFC 測試向量用 8 位）
pub fn code_at(secret: &[u8], step: i64, digits: u32) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&step.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    bin % 10u32.pow(digits)
}

pub fn step_of(unix_secs: i64) -> i64 {
    unix_secs.div_euclid(STEP_SECS)
}

/// 驗證 6 位數驗證碼。成功回傳符合的時間步；步數必須大於 `last_step`（防重放）。
pub fn verify(secret: &[u8], code: &str, unix_secs: i64, last_step: Option<i64>) -> Option<i64> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let want: u32 = code.parse().ok()?;
    let now = step_of(unix_secs);
    // 檢查完所有候選步數再回傳，耗時不因哪一步符合而不同
    let mut found = None;
    for step in (now - SKEW)..=(now + SKEW) {
        if code_at(secret, step, DIGITS) == want && last_step.is_none_or(|l| step > l) {
            found = Some(step);
        }
    }
    found
}

/// 作業系統亂數
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("OS random source");
    b
}

pub fn new_secret() -> String {
    base32_encode(&random_bytes::<SECRET_LEN>())
}

/// 驗證器 App 掃描用的網址
pub fn otpauth_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    let enc = |s: &str| form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    // label 裡的空白要用 %20，byte_serialize 會產生 +
    let label = enc(&format!("{issuer}:{account}")).replace('+', "%20");
    format!(
        "otpauth://totp/{label}?secret={secret_b32}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        enc(issuer).replace('+', "%20")
    )
}

/// 去掉 0/o、1/l/i 等容易看錯的字元
const RECOVERY_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";

/// 一組復原碼：`xxxx-xxxx`，約 39 bits
pub fn new_recovery_code() -> String {
    let raw = random_bytes::<8>();
    let chars: String = raw
        .iter()
        .map(|b| RECOVERY_ALPHABET[*b as usize % RECOVERY_ALPHABET.len()] as char)
        .collect();
    format!("{}-{}", &chars[..4], &chars[4..])
}

/// 復原碼正規化後的 SHA-256：忽略大小寫、空白與連字號
pub fn recovery_hash(code: &str) -> String {
    use sha2::{Digest, Sha256};
    let norm: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    hex::encode(Sha256::digest(norm.as_bytes()))
}

/// 看起來像復原碼（8 個英數字元；驗證碼是 6 位數）
pub fn looks_like_recovery(code: &str) -> bool {
    code.chars().filter(|c| c.is_ascii_alphanumeric()).count() == 8
}

/// QR code 的 SVG（伺服器產生，頁面不需要 JavaScript）
pub fn qr_svg(data: &str) -> String {
    use qrcode::render::svg;
    qrcode::QrCode::new(data.as_bytes())
        .expect("otpauth URI fits in a QR code")
        .render::<svg::Color>()
        .min_dimensions(200, 200)
        .quiet_zone(true)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 附錄 B，SHA-1 的金鑰與 8 位數結果
    #[test]
    fn rfc6238_vectors() {
        let key = b"12345678901234567890";
        for (t, want) in [
            (59, 94287082),
            (1111111109, 7081804),
            (1111111111, 14050471),
            (1234567890, 89005924),
            (2000000000, 69279037),
            (20000000000, 65353130),
        ] {
            assert_eq!(code_at(key, step_of(t), 8), want, "t={t}");
        }
    }

    #[test]
    fn base32_roundtrip() {
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_decode("mzxw6ytboi").unwrap(), b"foobar");
        assert_eq!(base32_decode("MZXW 6YTB OI==").unwrap(), b"foobar");
        assert!(base32_decode("MZXW1").is_none());
        let s = new_secret();
        assert_eq!(s.len(), 32);
        assert_eq!(base32_decode(&s).unwrap().len(), SECRET_LEN);
    }

    #[test]
    fn verify_window_and_replay() {
        let key = b"12345678901234567890";
        let now = 1_700_000_000;
        let step = step_of(now);
        let code = |s: i64| format!("{:06}", code_at(key, s, DIGITS));
        assert_eq!(verify(key, &code(step), now, None), Some(step));
        assert_eq!(verify(key, &code(step - 1), now, None), Some(step - 1));
        assert_eq!(verify(key, &code(step + 1), now, None), Some(step + 1));
        assert_eq!(verify(key, &code(step - 2), now, None), None);
        assert_eq!(verify(key, &code(step + 2), now, None), None);
        // 已用過這一步（或更新的）就拒絕
        assert_eq!(verify(key, &code(step), now, Some(step)), None);
        assert_eq!(verify(key, &code(step - 1), now, Some(step - 1)), None);
        assert_eq!(verify(key, &code(step), now, Some(step - 1)), Some(step));
        // 格式
        let c = code(step);
        assert_eq!(
            verify(key, &format!("{} {}", &c[..3], &c[3..]), now, None),
            Some(step)
        );
        assert_eq!(verify(key, "12345", now, None), None);
        assert_eq!(verify(key, "abcdef", now, None), None);
    }

    #[test]
    fn recovery_codes() {
        let c = new_recovery_code();
        assert_eq!(c.len(), 9);
        assert!(looks_like_recovery(&c));
        assert_eq!(recovery_hash("AbCd-EfGh"), recovery_hash(" abcd efgh "));
        assert!(!looks_like_recovery("123456"));
        assert!(looks_like_recovery("abcd-2345"));
    }

    #[test]
    fn uri_and_qr() {
        let u = otpauth_uri("Endpoint Manager", "alice", "MZXW6YTBOI");
        assert!(
            u.starts_with("otpauth://totp/Endpoint%20Manager%3Aalice?secret=MZXW6YTBOI&issuer=Endpoint%20Manager"),
            "{u}"
        );
        assert!(qr_svg(&u).contains("<svg"));
    }
}
