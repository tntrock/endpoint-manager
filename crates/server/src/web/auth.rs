//! 管理員角色、密碼、工作階段與 CSRF。

use argon2::password_hash::phc::PasswordHash;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use uuid::Uuid;

pub const MIN_PASSWORD_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Platform,
    GroupAdmin,
    Viewer,
}

impl Role {
    pub const ALL: [Role; 3] = [Role::Platform, Role::GroupAdmin, Role::Viewer];

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Platform => "platform_admin",
            Role::GroupAdmin => "group_admin",
            Role::Viewer => "viewer",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        Role::ALL.into_iter().find(|r| r.as_str() == s)
    }

    pub fn label(self) -> &'static str {
        match self {
            Role::Platform => "平台管理員",
            Role::GroupAdmin => "群組管理員",
            Role::Viewer => "唯讀檢視者",
        }
    }
}

pub fn hash_password(pw: &str) -> anyhow::Result<String> {
    let salt = Uuid::new_v4().into_bytes();
    Ok(Argon2::default()
        .hash_password_with_salt(pw.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hash: {e}"))?
        .to_string())
}

pub fn verify_password(pw: &str, phc: &str) -> bool {
    PasswordHash::new(phc)
        .is_ok_and(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
}
