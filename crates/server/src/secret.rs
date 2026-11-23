//! 資料庫裡的機密（SNMP 帳密）加密保存：ChaCha20-Poly1305，金鑰來自 `EM_SECRET_KEY_FILE`。
//!
//! 密文格式：12 位元組 nonce ＋ 密文與驗證標籤。nonce 每次隨機產生。
//! 附加資料（AAD）放用途字串，同一把金鑰加密的不同種類資料不能互換。

use std::path::Path;

use anyhow::{Context, bail};
use ring::aead::{self, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};

const NONCE_LEN: usize = 12;

pub struct SecretBox {
    key: LessSafeKey,
    rng: SystemRandom,
}

impl std::fmt::Debug for SecretBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBox(***)")
    }
}

impl SecretBox {
    pub fn new(key: &[u8; 32]) -> Self {
        let key = UnboundKey::new(&CHACHA20_POLY1305, key).expect("32-byte key");
        Self {
            key: LessSafeKey::new(key),
            rng: SystemRandom::new(),
        }
    }

    /// 金鑰檔：64 個十六進位字元（例如 `openssl rand -hex 32` 的輸出），前後空白忽略
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading secret key {}", path.display()))?;
        Self::from_hex(text.trim()).with_context(|| format!("secret key {}", path.display()))
    }

    pub fn from_hex(s: &str) -> anyhow::Result<Self> {
        let bytes = hex::decode(s).context("must be 64 hexadecimal characters")?;
        let Ok(key) = <[u8; 32]>::try_from(bytes.as_slice()) else {
            bail!("must be 64 hexadecimal characters (32 bytes)");
        };
        Ok(Self::new(&key))
    }

    pub fn seal(&self, purpose: &str, plain: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        self.rng.fill(&mut nonce).expect("system random");
        let mut buf = plain.to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(purpose.as_bytes()),
                &mut buf,
            )
            .expect("seal");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&buf);
        out
    }

    /// 金鑰不對、資料被改過或用途不同時回 Err
    pub fn open(&self, purpose: &str, sealed: &[u8]) -> anyhow::Result<Vec<u8>> {
        if sealed.len() < NONCE_LEN + aead::MAX_TAG_LEN {
            bail!("ciphertext too short");
        }
        let (nonce, rest) = sealed.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).expect("12-byte nonce");
        let mut buf = rest.to_vec();
        let plain = self
            .key
            .open_in_place(nonce, Aad::from(purpose.as_bytes()), &mut buf)
            .map_err(|_| anyhow::anyhow!("cannot decrypt (wrong key or corrupted data)"))?;
        Ok(plain.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> SecretBox {
        SecretBox::new(&[b; 32])
    }

    #[test]
    fn roundtrip_and_random_nonce() {
        let k = key(1);
        let a = k.seal("snmp", b"public");
        let b = k.seal("snmp", b"public");
        assert_ne!(a, b, "每次 nonce 不同");
        assert_eq!(k.open("snmp", &a).unwrap(), b"public");
        assert!(!a.windows(6).any(|w| w == b"public"));
    }

    #[test]
    fn wrong_key_purpose_or_tamper_fails() {
        let k = key(1);
        let sealed = k.seal("snmp", b"secret");
        assert!(key(2).open("snmp", &sealed).is_err());
        assert!(k.open("other", &sealed).is_err());
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(k.open("snmp", &bad).is_err());
        assert!(k.open("snmp", &sealed[..10]).is_err());
    }

    #[test]
    fn key_file_formats() {
        let hex64 = "ab".repeat(32);
        assert!(SecretBox::from_hex(&hex64).is_ok());
        assert!(SecretBox::from_hex("abcd").is_err());
        assert!(SecretBox::from_hex(&"zz".repeat(32)).is_err());
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k");
        std::fs::write(&p, format!("{hex64}\n")).unwrap();
        let k = SecretBox::load(&p).unwrap();
        assert_eq!(
            k.open("x", &SecretBox::from_hex(&hex64).unwrap().seal("x", b"y"))
                .unwrap(),
            b"y"
        );
        assert!(SecretBox::load(&dir.path().join("missing")).is_err());
        assert!(format!("{k:?}").contains("***"));
    }
}
