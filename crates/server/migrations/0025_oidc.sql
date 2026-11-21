-- 管理網頁單一登入（OIDC）：帳號與身分提供者使用者的綁定，以及進行中的登入流程
ALTER TABLE admins ADD COLUMN oidc_issuer TEXT;
ALTER TABLE admins ADD COLUMN oidc_subject TEXT;
ALTER TABLE admins ADD CONSTRAINT admins_oidc_pair
    CHECK ((oidc_issuer IS NULL) = (oidc_subject IS NULL));
CREATE UNIQUE INDEX admins_oidc_idx ON admins (oidc_issuer, oidc_subject)
    WHERE oidc_subject IS NOT NULL;

CREATE TABLE oidc_logins (
    id_hash       TEXT PRIMARY KEY,
    state         TEXT NOT NULL,
    nonce         TEXT NOT NULL,
    code_verifier TEXT NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL
);
