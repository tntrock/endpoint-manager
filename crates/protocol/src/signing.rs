//! 腳本與套件的 Ed25519 簽章。簽章金鑰在伺服器以外；Agent 只信任本機設定的公鑰。
//!
//! 被簽的位元組 = [`DOMAIN`] + 欄位結構的 JSON。Agent 以收到的欄位自己重組，
//! 不採用伺服器提供的「已組好的內容」。

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::command::{ScriptLanguage, ScriptSpec};
use crate::deploy::{PackageKind, PackageSpec};

/// 網域分隔：避免同一把金鑰簽的其他東西被拿來冒充
pub const DOMAIN: &str = "endpoint-manager signed artifact v1\n";
pub const PUBLIC_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SigningError {
    #[error("公鑰格式錯誤（應為 32 bytes Ed25519 公鑰的 Base64）")]
    BadPublicKey,
    #[error("簽章格式錯誤（應為「金鑰 ID:Base64 簽章」）")]
    BadSignature,
    #[error("沒有簽章")]
    Missing,
    #[error("簽章的金鑰 {0} 不在信任清單內")]
    UnknownKey(String),
    #[error("簽章驗證失敗（內容或欄位與簽章時不同）")]
    Invalid,
    #[error("不支援的類型")]
    Unsupported,
}

/// 被簽的欄位。序列化的欄位順序就是宣告順序，兩端一致
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Payload {
    Script {
        sha256: String,
        language: ScriptLanguage,
        timeout_minutes: u32,
    },
    Package {
        sha256: String,
        size: u64,
        package_kind: PackageKind,
        install_args: String,
        uninstall_args: String,
        msi_product_code: Option<String>,
    },
}

impl Payload {
    pub fn script(spec: &ScriptSpec) -> Payload {
        Payload::Script {
            sha256: spec.sha256.to_ascii_lowercase(),
            language: spec.language,
            timeout_minutes: spec.timeout_minutes,
        }
    }

    pub fn package(spec: &PackageSpec) -> Payload {
        Payload::Package {
            sha256: spec.sha256.to_ascii_lowercase(),
            size: spec.size,
            package_kind: spec.kind,
            install_args: spec.install_args.clone(),
            uninstall_args: spec.uninstall_args.clone(),
            msi_product_code: spec.msi_product_code.clone(),
        }
    }

    /// 實際簽章／驗證的位元組
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut out = DOMAIN.as_bytes().to_vec();
        out.extend(serde_json::to_vec(self).expect("payload serializes"));
        out
    }
}

/// 公鑰（Base64）解碼成 32 bytes
pub fn decode_public_key(b64: &str) -> Result<[u8; PUBLIC_KEY_LEN], SigningError> {
    B64.decode(b64.trim())
        .ok()
        .and_then(|v| <[u8; PUBLIC_KEY_LEN]>::try_from(v).ok())
        .ok_or(SigningError::BadPublicKey)
}

pub fn encode_public_key(raw: &[u8; PUBLIC_KEY_LEN]) -> String {
    B64.encode(raw)
}

/// 金鑰 ID：公鑰 SHA-256 的前 16 個十六進位字元
pub fn key_id(raw: &[u8; PUBLIC_KEY_LEN]) -> String {
    hex::encode(&Sha256::digest(raw)[..8])
}

/// 檢查公鑰清單格式，回傳正規化（去空白）的清單
pub fn parse_public_keys<'a>(
    keys: impl IntoIterator<Item = &'a str>,
) -> Result<Vec<String>, SigningError> {
    keys.into_iter()
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(|k| decode_public_key(k).map(|raw| encode_public_key(&raw)))
        .collect()
}

pub fn format_signature(key_id: &str, sig: &[u8]) -> String {
    format!("{key_id}:{}", B64.encode(sig))
}

/// 簽章字串拆成（金鑰 ID、64 bytes 簽章）
pub fn parse_signature(s: &str) -> Result<(String, [u8; SIGNATURE_LEN]), SigningError> {
    let (id, sig) = s.trim().split_once(':').ok_or(SigningError::BadSignature)?;
    let id = id.trim().to_ascii_lowercase();
    if id.len() != 16 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(SigningError::BadSignature);
    }
    let sig = B64
        .decode(sig.trim())
        .ok()
        .and_then(|v| <[u8; SIGNATURE_LEN]>::try_from(v).ok())
        .ok_or(SigningError::BadSignature)?;
    Ok((id, sig))
}

/// 以信任的公鑰（Base64 清單）驗證。成功回傳用到的金鑰 ID
pub fn verify(
    trusted: &[String],
    payload: &Payload,
    signature: Option<&str>,
) -> Result<String, SigningError> {
    let sig = signature
        .filter(|s| !s.trim().is_empty())
        .ok_or(SigningError::Missing)?;
    let (id, sig) = parse_signature(sig)?;
    let key = trusted
        .iter()
        .filter_map(|k| decode_public_key(k).ok())
        .find(|raw| key_id(raw) == id)
        .ok_or_else(|| SigningError::UnknownKey(id.clone()))?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(&payload.signed_bytes(), &sig)
        .map_err(|_| SigningError::Invalid)?;
    Ok(id)
}

/// 腳本：伺服器下發的簽章
pub fn verify_script(trusted: &[String], spec: &ScriptSpec) -> Result<String, SigningError> {
    verify(trusted, &Payload::script(spec), spec.signature.as_deref())
}

/// 套件：伺服器下發的簽章
pub fn verify_package(trusted: &[String], spec: &PackageSpec) -> Result<String, SigningError> {
    if spec.kind == PackageKind::Unknown {
        return Err(SigningError::Unsupported);
    }
    verify(trusted, &Payload::package(spec), spec.signature.as_deref())
}

/// 伺服器提供下載、`endpoint-sign` 讀取的簽章請求
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningRequest {
    /// 固定為 [`SigningRequest::TYPE`]
    #[serde(rename = "type")]
    pub kind: String,
    /// 給人看的名稱（腳本或套件名稱）
    pub name: String,
    pub payload: Payload,
    /// 腳本全文：工具自己計算雜湊並顯示給簽章者
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

impl SigningRequest {
    pub const TYPE: &'static str = "endpoint-manager-signing-request";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::Detect;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn keypair() -> Ed25519KeyPair {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn public(k: &Ed25519KeyPair) -> [u8; 32] {
        k.public_key().as_ref().try_into().unwrap()
    }

    fn sign(k: &Ed25519KeyPair, p: &Payload) -> String {
        format_signature(&key_id(&public(k)), k.sign(&p.signed_bytes()).as_ref())
    }

    fn script() -> ScriptSpec {
        ScriptSpec {
            sha256: "AB".repeat(32),
            content: "echo hi".into(),
            timeout_minutes: 30,
            language: ScriptLanguage::Sh,
            signature: None,
        }
    }

    fn package() -> PackageSpec {
        PackageSpec {
            id: 1,
            kind: PackageKind::Exe,
            sha256: "cd".repeat(32),
            size: 1234,
            file_name: "setup.exe".into(),
            install_args: "/S".into(),
            uninstall_args: "/uninstall /S".into(),
            msi_product_code: None,
            success_codes: vec![],
            detect: Detect {
                name: "X".into(),
                publisher: None,
                min_version: None,
            },
            signature: None,
        }
    }

    #[test]
    fn script_roundtrip_and_tamper() {
        let k = keypair();
        let trusted = vec![encode_public_key(&public(&k))];
        let mut s = script();
        assert_eq!(verify_script(&trusted, &s), Err(SigningError::Missing));
        s.signature = Some(sign(&k, &Payload::script(&s)));
        assert_eq!(verify_script(&trusted, &s), Ok(key_id(&public(&k))));
        // 雜湊大小寫不影響
        let mut upper = s.clone();
        upper.sha256 = upper.sha256.to_lowercase();
        assert!(verify_script(&trusted, &upper).is_ok());
        // 任一欄位被改
        for change in [
            |s: &mut ScriptSpec| s.sha256 = "ef".repeat(32),
            |s: &mut ScriptSpec| s.timeout_minutes = 31,
            |s: &mut ScriptSpec| s.language = ScriptLanguage::PowerShell,
        ] {
            let mut t = s.clone();
            change(&mut t);
            assert_eq!(verify_script(&trusted, &t), Err(SigningError::Invalid));
        }
        // 內容本身不在簽章裡（由雜湊涵蓋，Agent 另外比對內容與雜湊）
        let mut c = s.clone();
        c.content = "rm -rf /".into();
        assert!(verify_script(&trusted, &c).is_ok());
    }

    #[test]
    fn package_roundtrip_and_tamper() {
        let k = keypair();
        let trusted = vec![encode_public_key(&public(&k))];
        let mut p = package();
        p.signature = Some(sign(&k, &Payload::package(&p)));
        assert!(verify_package(&trusted, &p).is_ok());
        for change in [
            |p: &mut PackageSpec| p.sha256 = "ef".repeat(32),
            |p: &mut PackageSpec| p.size = 1,
            |p: &mut PackageSpec| p.kind = PackageKind::Msi,
            |p: &mut PackageSpec| p.install_args = "/S /D=C:\\evil".into(),
            |p: &mut PackageSpec| p.uninstall_args = String::new(),
            |p: &mut PackageSpec| p.msi_product_code = Some("{X}".into()),
        ] {
            let mut t = p.clone();
            change(&mut t);
            assert_eq!(verify_package(&trusted, &t), Err(SigningError::Invalid));
        }
        // 偵測規則與檔名不影響執行內容，不在簽章裡
        let mut t = p.clone();
        t.file_name = "other.exe".into();
        t.detect.name = "Y".into();
        assert!(verify_package(&trusted, &t).is_ok());
        // 腳本的簽章不能拿來當套件的
        let mut cross = p.clone();
        cross.signature = Some(sign(&k, &Payload::script(&script())));
        assert_eq!(verify_package(&trusted, &cross), Err(SigningError::Invalid));
    }

    #[test]
    fn untrusted_or_malformed() {
        let k = keypair();
        let other = keypair();
        let trusted = vec![encode_public_key(&public(&other))];
        let mut s = script();
        s.signature = Some(sign(&k, &Payload::script(&s)));
        assert_eq!(
            verify_script(&trusted, &s),
            Err(SigningError::UnknownKey(key_id(&public(&k))))
        );
        // 金鑰 ID 冒用信任的金鑰：簽章本身驗不過
        let forged = format!(
            "{}:{}",
            key_id(&public(&other)),
            s.signature.as_ref().unwrap().split_once(':').unwrap().1
        );
        s.signature = Some(forged);
        assert_eq!(verify_script(&trusted, &s), Err(SigningError::Invalid));
        for bad in [
            "",
            "   ",
            "nocolon",
            "zz:AAAA",
            "0123456789abcdef:notbase64!",
        ] {
            s.signature = Some(bad.into());
            assert!(verify_script(&trusted, &s).is_err(), "{bad}");
        }
        // 不同網域分隔字串簽的不算
        let raw = serde_json::to_vec(&Payload::script(&script())).unwrap();
        s.signature = Some(format_signature(
            &key_id(&public(&other)),
            other.sign(&raw).as_ref(),
        ));
        assert_eq!(verify_script(&trusted, &s), Err(SigningError::Invalid));
    }

    #[test]
    fn public_keys() {
        let k = keypair();
        let b64 = encode_public_key(&public(&k));
        assert_eq!(
            parse_public_keys([format!(" {b64} ").as_str(), ""]).unwrap(),
            vec![b64.clone()]
        );
        assert_eq!(parse_public_keys(["abc"]), Err(SigningError::BadPublicKey));
        assert_eq!(key_id(&public(&k)).len(), 16);
    }

    #[test]
    fn payload_json_is_stable() {
        // 欄位順序是格式的一部分：改了就是另一個版本，要換 DOMAIN
        assert_eq!(
            String::from_utf8(Payload::script(&script()).signed_bytes()).unwrap(),
            format!(
                "{DOMAIN}{{\"kind\":\"script\",\"sha256\":\"{}\",\"language\":\"sh\",\"timeout_minutes\":30}}",
                "ab".repeat(32)
            )
        );
        let req = SigningRequest {
            kind: SigningRequest::TYPE.into(),
            name: "x".into(),
            payload: Payload::package(&package()),
            content: None,
        };
        let back: SigningRequest =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(back, req);
    }
}
