//! dpkg-query／rpm 輸出的解析。

use chrono::DateTime;
use protocol::{Arch, SoftwareItem};

/// 套件架構對應：amd64／x86_64 → X64，i386～i686 → X86，其他（all、noarch、aarch64…）→ Other
pub fn arch_of(s: &str) -> Arch {
    match s.trim() {
        "amd64" | "x86_64" => Arch::X64,
        "i386" | "i486" | "i586" | "i686" => Arch::X86,
        _ => Arch::Other,
    }
}

fn non_empty(s: &str) -> Option<String> {
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// `${Status}\t${Package}\t${Version}\t${Maintainer}\t${Architecture}`；只收 `install ok installed`
pub fn parse_dpkg(out: &str) -> Vec<SoftwareItem> {
    out.lines()
        .filter_map(|l| {
            let mut f = l.split('\t');
            let (status, name, ver, maint, arch) =
                (f.next()?, f.next()?, f.next()?, f.next()?, f.next()?);
            if status.trim() != "install ok installed" || name.is_empty() {
                return None;
            }
            Some(SoftwareItem {
                name: name.to_string(),
                version: non_empty(ver),
                publisher: non_empty(maint),
                install_date: None,
                arch: arch_of(arch),
            })
        })
        .collect()
}

/// `%{NAME}\t%{EPOCH}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{INSTALLTIME}\t%{ARCH}`
pub fn parse_rpm(out: &str) -> Vec<SoftwareItem> {
    out.lines()
        .filter_map(|l| {
            let mut f = l.split('\t');
            let (name, epoch, vr, vendor, time, arch) = (
                f.next()?,
                f.next()?,
                f.next()?,
                f.next()?,
                f.next()?,
                f.next()?,
            );
            if name.is_empty() {
                return None;
            }
            let version = match epoch.trim() {
                "(none)" | "" => vr.to_string(),
                e => format!("{e}:{vr}"),
            };
            let install_date = time
                .trim()
                .parse::<i64>()
                .ok()
                .and_then(|s| DateTime::from_timestamp(s, 0))
                .map(|d| d.format("%Y-%m-%d").to_string());
            Some(SoftwareItem {
                name: name.to_string(),
                version: non_empty(&version),
                publisher: non_empty(vendor).filter(|v| v != "(none)"),
                install_date,
                arch: arch_of(arch),
            })
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpkg_only_installed() {
        let out = "install ok installed\tbash\t5.2\tUbuntu Developers <u@x>\tamd64\n\
                   deinstall ok config-files\told\t1\tM\tamd64\n\
                   install ok installed\ttzdata\t2024a\tMaint <m@x>\tall\n";
        let v = parse_dpkg(out);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].name, "bash");
        assert_eq!(v[0].arch, Arch::X64);
        assert_eq!(v[1].arch, Arch::Other);
        assert_eq!(v[1].publisher.as_deref(), Some("Maint <m@x>"));
    }

    #[test]
    fn rpm_epoch_vendor_date() {
        let out = "bash\t(none)\t5.1.8-9.el9\tRocky Enterprise Software Foundation\t1729700000\tx86_64\n\
                   openssl\t1\t3.0.7-27.el9\t(none)\t1729700000\tx86_64\n";
        let v = parse_rpm(out);
        assert_eq!(v[0].version.as_deref(), Some("5.1.8-9.el9"));
        assert_eq!(v[0].install_date.as_deref(), Some("2024-10-23"));
        assert_eq!(v[0].arch, Arch::X64);
        assert_eq!(v[1].version.as_deref(), Some("1:3.0.7-27.el9"));
        assert_eq!(v[1].publisher, None);
    }

    #[test]
    fn arch_mapping() {
        assert_eq!(arch_of("i686"), Arch::X86);
        assert_eq!(arch_of("noarch"), Arch::Other);
        assert_eq!(arch_of("aarch64"), Arch::Other);
    }
}
