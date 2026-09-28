//! 私有 CA：根 CA（應離線保存）→ 中繼 CA（伺服器持有）→ 裝置／伺服器憑證。

use std::path::Path;

use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SerialNumber,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const DEVICE_CERT_DAYS: i64 = 365;

pub struct IssuedCert {
    pub serial: String,
    pub fingerprint: String,
    pub pem: String,
    pub not_after: DateTime<Utc>,
}

pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    chain_pem: String,
    root_pem: String,
}

/// server.pem 第一張（伺服器）憑證的 SAN：DNS 名稱與 IP。
pub fn server_names(dir: &Path) -> anyhow::Result<Vec<String>> {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    use x509_parser::extensions::GeneralName;
    let pem = std::fs::read(dir.join("server.pem")).context("reading server.pem")?;
    let der = CertificateDer::pem_slice_iter(&pem)
        .next()
        .context("server.pem is empty")??;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)?;
    let mut names = Vec::new();
    if let Some(san) = cert.subject_alternative_name()? {
        for n in &san.value.general_names {
            match n {
                GeneralName::DNSName(d) => names.push(d.to_string()),
                GeneralName::IPAddress(b) => {
                    if let Ok(v4) = <[u8; 4]>::try_from(*b) {
                        names.push(std::net::Ipv4Addr::from(v4).to_string());
                    } else if let Ok(v6) = <[u8; 16]>::try_from(*b) {
                        names.push(std::net::Ipv6Addr::from(v6).to_string());
                    }
                }
                _ => {}
            }
        }
    }
    Ok(names)
}

fn to_time(dt: DateTime<Utc>) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(dt.timestamp()).expect("valid timestamp")
}

fn cn(name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    dn
}

/// 128-bit 隨機序號；首位元組確保 1..=0x7f，DER 編碼後長度固定、不會補零。
fn random_serial() -> [u8; 16] {
    let mut s = Uuid::new_v4().into_bytes();
    s[0] = (s[0] & 0x7f).max(1);
    s
}

pub fn fingerprint(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

pub fn device_id_of(der: &[u8]) -> Option<Uuid> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let cn = cert.subject().iter_common_name().next()?.as_str().ok()?;
    Uuid::parse_str(cn).ok()
}

fn write_secret(path: &Path, contents: &str) -> anyhow::Result<()> {
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn init_ca(dir: &Path, server_names: Vec<String>) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let now = Utc::now();

    let mut root_params = CertificateParams::default();
    root_params.distinguished_name = cn("Endpoint Manager Root CA");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    root_params.not_before = to_time(now - Duration::minutes(5));
    root_params.not_after = to_time(now + Duration::days(3650));
    let root_key = KeyPair::generate()?;
    let root_cert = root_params.self_signed(&root_key)?;
    let root_key_pem = root_key.serialize_pem();
    let root_issuer = Issuer::new(root_params, root_key);

    let mut int_params = CertificateParams::default();
    int_params.distinguished_name = cn("Endpoint Manager Intermediate CA");
    int_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    int_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    int_params.use_authority_key_identifier_extension = true;
    int_params.not_before = to_time(now - Duration::minutes(5));
    int_params.not_after = to_time(now + Duration::days(1825));
    let int_key = KeyPair::generate()?;
    let int_cert = int_params.signed_by(&int_key, &root_issuer)?;
    let int_key_pem = int_key.serialize_pem();
    let int_issuer = Issuer::new(int_params, int_key);

    let mut srv_params = CertificateParams::new(server_names)?;
    srv_params.distinguished_name = cn("Endpoint Manager Server");
    srv_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    srv_params.use_authority_key_identifier_extension = true;
    srv_params.not_before = to_time(now - Duration::minutes(5));
    srv_params.not_after = to_time(now + Duration::days(825));
    let srv_key = KeyPair::generate()?;
    let srv_cert = srv_params.signed_by(&srv_key, &int_issuer)?;

    std::fs::write(dir.join("root.pem"), root_cert.pem())?;
    write_secret(&dir.join("root.key"), &root_key_pem)?;
    std::fs::write(dir.join("intermediate.pem"), int_cert.pem())?;
    write_secret(&dir.join("intermediate.key"), &int_key_pem)?;
    std::fs::write(
        dir.join("server.pem"),
        format!("{}{}", srv_cert.pem(), int_cert.pem()),
    )?;
    write_secret(&dir.join("server.key"), &srv_key.serialize_pem())?;
    Ok(())
}

impl Ca {
    pub fn load(dir: &Path) -> anyhow::Result<Ca> {
        let read =
            |f: &str| std::fs::read_to_string(dir.join(f)).with_context(|| format!("reading {f}"));
        let int_pem = read("intermediate.pem")?;
        let int_key = KeyPair::from_pem(&read("intermediate.key")?)?;
        let issuer = Issuer::from_ca_cert_pem(&int_pem, int_key)?;
        let root_pem = read("root.pem")?;
        let chain_pem = format!("{int_pem}{root_pem}");
        Ok(Ca {
            issuer,
            chain_pem,
            root_pem,
        })
    }

    pub fn chain_pem(&self) -> &str {
        &self.chain_pem
    }

    pub fn root_pem(&self) -> &str {
        &self.root_pem
    }

    /// 只取 CSR 的公鑰；主體、用途、效期一律由伺服器決定。
    pub fn sign_device_csr(
        &self,
        csr_pem: &str,
        device_id: Uuid,
        now: DateTime<Utc>,
    ) -> anyhow::Result<IssuedCert> {
        let csr = CertificateSigningRequestParams::from_pem(csr_pem).context("invalid CSR")?;
        let serial = random_serial();
        let not_after = now + Duration::days(DEVICE_CERT_DAYS);

        let mut params = CertificateParams::default();
        params.distinguished_name = cn(&device_id.to_string());
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        params.not_before = to_time(now - Duration::minutes(5));
        params.not_after = to_time(not_after);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.use_authority_key_identifier_extension = true;

        let cert = params.signed_by(&csr.public_key, &self.issuer)?;
        Ok(IssuedCert {
            serial: hex::encode(serial),
            fingerprint: fingerprint(cert.der()),
            pem: cert.pem(),
            not_after: DateTime::from_timestamp(not_after.timestamp(), 0).expect("valid"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};

    fn csr() -> String {
        let key = KeyPair::generate().unwrap();
        CertificateParams::default()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap()
    }

    #[test]
    fn init_then_sign_device_cert() {
        let dir = tempfile::tempdir().unwrap();
        init_ca(dir.path(), vec!["localhost".into()]).unwrap();
        for f in [
            "root.pem",
            "root.key",
            "intermediate.pem",
            "intermediate.key",
            "server.pem",
            "server.key",
        ] {
            assert!(dir.path().join(f).exists(), "{f} missing");
        }

        let ca = Ca::load(dir.path()).unwrap();
        let id = Uuid::new_v4();
        let now = Utc::now();
        let issued = ca.sign_device_csr(&csr(), id, now).unwrap();

        let der = pem_to_der(&issued.pem);
        assert_eq!(device_id_of(&der), Some(id));
        assert_eq!(fingerprint(&der), issued.fingerprint);
        assert_eq!(issued.serial.len(), 32);
        assert!(
            (issued.not_after - now - chrono::Duration::days(DEVICE_CERT_DAYS))
                .num_seconds()
                .abs()
                < 5
        );
        assert_eq!(ca.chain_pem().matches("BEGIN CERTIFICATE").count(), 2);
    }

    #[test]
    fn serials_are_unique() {
        let dir = tempfile::tempdir().unwrap();
        init_ca(dir.path(), vec!["localhost".into()]).unwrap();
        let ca = Ca::load(dir.path()).unwrap();
        let a = ca
            .sign_device_csr(&csr(), Uuid::new_v4(), Utc::now())
            .unwrap();
        let b = ca
            .sign_device_csr(&csr(), Uuid::new_v4(), Utc::now())
            .unwrap();
        assert_ne!(a.serial, b.serial);
    }

    #[test]
    fn garbage_csr_is_error() {
        let dir = tempfile::tempdir().unwrap();
        init_ca(dir.path(), vec!["localhost".into()]).unwrap();
        let ca = Ca::load(dir.path()).unwrap();
        assert!(
            ca.sign_device_csr("not a csr", Uuid::new_v4(), Utc::now())
                .is_err()
        );
    }

    #[test]
    fn server_names_and_root_pem() {
        let dir = tempfile::tempdir().unwrap();
        init_ca(dir.path(), vec!["em.example.com".into(), "10.1.2.3".into()]).unwrap();
        assert_eq!(
            server_names(dir.path()).unwrap(),
            vec!["em.example.com", "10.1.2.3"]
        );
        let ca = Ca::load(dir.path()).unwrap();
        assert_eq!(
            ca.root_pem(),
            std::fs::read_to_string(dir.path().join("root.pem")).unwrap()
        );
    }

    fn pem_to_der(pem: &str) -> Vec<u8> {
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        CertificateDer::from_pem_slice(pem.as_bytes())
            .unwrap()
            .to_vec()
    }
}
