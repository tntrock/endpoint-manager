//! `endpoint-sign`：產生簽章金鑰、對腳本與套件的簽章請求簽章。
//!
//! 金鑰檔是 JSON：公鑰明文，私鑰（PKCS#8）以密語加密
//! （Argon2id 推導金鑰、ChaCha20-Poly1305，公鑰當附加資料）。

use std::io::Read;
use std::path::Path;

use anyhow::{Context, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload as AeadPayload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use protocol::signing::{Payload, SigningRequest, encode_public_key, format_signature, key_id};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const KEY_FILE_TYPE: &str = "endpoint-manager-signing-key";
pub const MIN_PASSPHRASE: usize = 12;

/// Argon2id 參數：64 MiB、3 次。簽章不常做，慢一點沒關係
const M_COST: u32 = 64 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFile {
    #[serde(rename = "type")]
    pub kind: String,
    pub version: u32,
    pub public_key: String,
    pub key_id: String,
    pub kdf: Kdf,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Kdf {
    pub alg: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: String,
}

fn random<const N: usize>() -> anyhow::Result<[u8; N]> {
    let mut b = [0u8; N];
    SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| anyhow::anyhow!("系統亂數來源無法使用"))?;
    Ok(b)
}

fn derive(passphrase: &str, kdf: &Kdf) -> anyhow::Result<Key> {
    ensure!(kdf.alg == "argon2id", "不支援的金鑰推導：{}", kdf.alg);
    let salt = B64.decode(&kdf.salt).context("金鑰檔的 salt 格式錯誤")?;
    let params = argon2::Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(32))
        .map_err(|e| anyhow::anyhow!("金鑰檔的推導參數錯誤：{e}"))?;
    let mut out = [0u8; 32];
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), &salt, &mut out)
        .map_err(|e| anyhow::anyhow!("金鑰推導失敗：{e}"))?;
    Ok(Key::from(out))
}

fn raw_public(k: &Ed25519KeyPair) -> [u8; 32] {
    k.public_key()
        .as_ref()
        .try_into()
        .expect("Ed25519 public key is 32 bytes")
}

/// 產生新金鑰，以密語加密
pub fn generate(passphrase: &str) -> anyhow::Result<KeyFile> {
    ensure!(
        passphrase.chars().count() >= MIN_PASSPHRASE,
        "密語至少 {MIN_PASSPHRASE} 個字元"
    );
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| anyhow::anyhow!("產生金鑰失敗"))?;
    let pair =
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| anyhow::anyhow!("產生金鑰失敗"))?;
    let public = raw_public(&pair);
    let kdf = Kdf {
        alg: "argon2id".into(),
        m_cost: M_COST,
        t_cost: T_COST,
        p_cost: P_COST,
        salt: B64.encode(random::<16>()?),
    };
    let nonce = random::<12>()?;
    let ciphertext = ChaCha20Poly1305::new(&derive(passphrase, &kdf)?)
        .encrypt(
            &Nonce::from(nonce),
            AeadPayload {
                msg: pkcs8.as_ref(),
                aad: &public,
            },
        )
        .map_err(|_| anyhow::anyhow!("加密私鑰失敗"))?;
    Ok(KeyFile {
        kind: KEY_FILE_TYPE.into(),
        version: 1,
        public_key: encode_public_key(&public),
        key_id: key_id(&public),
        kdf,
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ciphertext),
    })
}

impl KeyFile {
    pub fn load(path: &Path) -> anyhow::Result<KeyFile> {
        let bytes = std::fs::read(path).with_context(|| format!("讀取 {}", path.display()))?;
        let k: KeyFile = serde_json::from_slice(&bytes)
            .with_context(|| format!("{} 不是簽章金鑰檔", path.display()))?;
        ensure!(
            k.kind == KEY_FILE_TYPE && k.version == 1,
            "{} 不是支援的簽章金鑰檔",
            path.display()
        );
        Ok(k)
    }

    /// 寫入新檔；檔案已存在就失敗（不覆蓋既有金鑰）
    pub fn save_new(&self, path: &Path) -> anyhow::Result<()> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("建立 {}（檔案已存在時不會覆蓋）", path.display()))?;
        f.write_all(&serde_json::to_vec_pretty(self)?)?;
        f.sync_all()?;
        Ok(())
    }

    /// 以密語解開私鑰
    pub fn unlock(&self, passphrase: &str) -> anyhow::Result<Ed25519KeyPair> {
        let public = protocol::signing::decode_public_key(&self.public_key)?;
        let nonce: [u8; 12] = B64
            .decode(&self.nonce)
            .ok()
            .and_then(|v| v.try_into().ok())
            .context("金鑰檔的 nonce 格式錯誤")?;
        let ciphertext = B64
            .decode(&self.ciphertext)
            .context("金鑰檔的私鑰格式錯誤")?;
        let pkcs8 = ChaCha20Poly1305::new(&derive(passphrase, &self.kdf)?)
            .decrypt(
                &Nonce::from(nonce),
                AeadPayload {
                    msg: &ciphertext,
                    aad: &public,
                },
            )
            .map_err(|_| anyhow::anyhow!("密語錯誤，或金鑰檔已損毀"))?;
        let pair = Ed25519KeyPair::from_pkcs8(&pkcs8)
            .map_err(|_| anyhow::anyhow!("金鑰檔的私鑰格式錯誤"))?;
        ensure!(raw_public(&pair) == public, "金鑰檔的公鑰與私鑰不符");
        Ok(pair)
    }
}

/// 讀取並檢查簽章請求；腳本會自己計算內容的雜湊比對
pub fn load_request(path: &Path) -> anyhow::Result<SigningRequest> {
    let bytes = std::fs::read(path).with_context(|| format!("讀取 {}", path.display()))?;
    let req: SigningRequest = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} 不是簽章請求", path.display()))?;
    ensure!(
        req.kind == SigningRequest::TYPE,
        "{} 不是簽章請求",
        path.display()
    );
    if let Payload::Script { sha256, .. } = &req.payload {
        let content = req
            .content
            .as_deref()
            .context("腳本的簽章請求沒有附上內容")?;
        let actual = hex::encode(Sha256::digest(content.as_bytes()));
        ensure!(
            actual.eq_ignore_ascii_case(sha256),
            "腳本內容的 SHA-256（{actual}）與請求不符（{sha256}），拒絕簽章"
        );
    }
    Ok(req)
}

/// 套件：比對簽章者手上的安裝檔
pub fn check_file(req: &SigningRequest, path: &Path) -> anyhow::Result<()> {
    let Payload::Package { sha256, size, .. } = &req.payload else {
        bail!("--file 只用於套件");
    };
    let mut f = std::fs::File::open(path).with_context(|| format!("讀取 {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut n_total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        n_total += n as u64;
    }
    let actual = hex::encode(h.finalize());
    ensure!(
        n_total == *size && actual.eq_ignore_ascii_case(sha256),
        "{} 與請求的套件不符（大小 {n_total}／{size}，SHA-256 {actual}／{sha256}），拒絕簽章",
        path.display()
    );
    Ok(())
}

/// 給簽章者看的摘要
pub fn describe(req: &SigningRequest) -> String {
    match &req.payload {
        Payload::Script {
            sha256,
            language,
            timeout_minutes,
        } => format!(
            "腳本：{}\n語言：{}\n逾時：{timeout_minutes} 分鐘\nSHA-256：{sha256}\n",
            req.name,
            language.as_str()
        ),
        Payload::Package {
            sha256,
            size,
            package_kind,
            install_args,
            uninstall_args,
            msi_product_code,
        } => format!(
            "套件：{}\n類型：{}\n大小：{size} bytes\nSHA-256：{sha256}\n安裝參數：{install_args}\n移除參數：{uninstall_args}\nMSI ProductCode：{}\n",
            req.name,
            serde_json::to_value(package_kind)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
            msi_product_code.as_deref().unwrap_or("（無）")
        ),
    }
}

pub fn sign(pair: &Ed25519KeyPair, req: &SigningRequest) -> String {
    format_signature(
        &key_id(&raw_public(pair)),
        pair.sign(&req.payload.signed_bytes()).as_ref(),
    )
}

/// 以公鑰檢查簽章（給簽章者事後確認用）
pub fn verify(public_key: &str, req: &SigningRequest, signature: &str) -> anyhow::Result<String> {
    let keys = protocol::signing::parse_public_keys([public_key])?;
    Ok(protocol::signing::verify(
        &keys,
        &req.payload,
        Some(signature),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::command::ScriptLanguage;

    const PW: &str = "correct horse battery";

    fn script_request(content: &str) -> SigningRequest {
        SigningRequest {
            kind: SigningRequest::TYPE.into(),
            name: "清暫存".into(),
            payload: Payload::Script {
                sha256: hex::encode(Sha256::digest(content.as_bytes())),
                language: ScriptLanguage::PowerShell,
                timeout_minutes: 30,
            },
            content: Some(content.into()),
        }
    }

    fn write(dir: &Path, name: &str, data: &[u8]) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, data).unwrap();
        p
    }

    #[test]
    fn keyfile_roundtrip_and_wrong_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.json");
        let kf = generate(PW).unwrap();
        kf.save_new(&path).unwrap();
        assert!(kf.save_new(&path).is_err(), "不覆蓋");
        let back = KeyFile::load(&path).unwrap();
        assert_eq!(back.public_key, kf.public_key);
        let pair = back.unlock(PW).unwrap();
        assert_eq!(encode_public_key(&raw_public(&pair)), kf.public_key);
        let err = back.unlock("wrong passphrase!!").unwrap_err();
        assert!(format!("{err:#}").contains("密語錯誤"));
        assert!(generate("short").is_err());
        // 私鑰不以明文出現
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("PRIVATE"));
    }

    #[test]
    fn tampered_public_key_is_rejected() {
        let mut kf = generate(PW).unwrap();
        let other = generate(PW).unwrap();
        kf.public_key = other.public_key;
        assert!(kf.unlock(PW).is_err(), "公鑰是加密的附加資料，換掉就解不開");
    }

    #[test]
    fn sign_script_request() {
        let dir = tempfile::tempdir().unwrap();
        let req = script_request("Remove-Item $env:TEMP\\* -Recurse\r\n");
        let path = write(dir.path(), "req.json", &serde_json::to_vec(&req).unwrap());
        let loaded = load_request(&path).unwrap();
        assert!(describe(&loaded).contains("清暫存"));
        let kf = generate(PW).unwrap();
        let sig = sign(&kf.unlock(PW).unwrap(), &loaded);
        assert_eq!(verify(&kf.public_key, &loaded, &sig).unwrap(), kf.key_id);
        // Agent 以收到的欄位重組也驗得過
        let spec = protocol::command::ScriptSpec {
            sha256: match &loaded.payload {
                Payload::Script { sha256, .. } => sha256.clone(),
                _ => unreachable!(),
            },
            content: loaded.content.clone().unwrap(),
            timeout_minutes: 30,
            language: ScriptLanguage::PowerShell,
            signature: Some(sig),
        };
        assert!(
            protocol::signing::verify_script(std::slice::from_ref(&kf.public_key), &spec).is_ok()
        );
    }

    #[test]
    fn script_content_must_match_hash() {
        let dir = tempfile::tempdir().unwrap();
        let mut req = script_request("echo hi");
        req.content = Some("echo evil".into());
        let path = write(dir.path(), "req.json", &serde_json::to_vec(&req).unwrap());
        let err = load_request(&path).unwrap_err();
        assert!(format!("{err:#}").contains("拒絕簽章"), "{err:#}");
        req.content = None;
        let path = write(dir.path(), "req2.json", &serde_json::to_vec(&req).unwrap());
        assert!(load_request(&path).is_err());
        let path = write(dir.path(), "x.json", b"{\"type\":\"other\"}");
        assert!(load_request(&path).is_err());
    }

    #[test]
    fn package_file_must_match() {
        let dir = tempfile::tempdir().unwrap();
        let data = b"MZ installer bytes";
        let req = SigningRequest {
            kind: SigningRequest::TYPE.into(),
            name: "7-Zip".into(),
            payload: Payload::Package {
                sha256: hex::encode(Sha256::digest(data)),
                size: data.len() as u64,
                package_kind: protocol::deploy::PackageKind::Exe,
                install_args: "/S".into(),
                uninstall_args: String::new(),
                msi_product_code: None,
            },
            content: None,
        };
        let good = write(dir.path(), "a.exe", data);
        check_file(&req, &good).unwrap();
        let bad = write(dir.path(), "b.exe", b"MZ other bytes!!!!");
        let err = check_file(&req, &bad).unwrap_err();
        assert!(format!("{err:#}").contains("拒絕簽章"));
        assert!(describe(&req).contains("安裝參數：/S"));
        assert!(check_file(&script_request("x"), &good).is_err());
    }
}
