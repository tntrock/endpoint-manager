-- 管理網頁兩步驟驗證（TOTP）
ALTER TABLE admins
    ADD COLUMN mfa_secret         TEXT,
    ADD COLUMN mfa_pending_secret TEXT,
    ADD COLUMN mfa_enabled_at     TIMESTAMPTZ,
    ADD COLUMN mfa_last_step      BIGINT,
    ADD CONSTRAINT admins_mfa_enabled_has_secret
        CHECK ((mfa_secret IS NULL) = (mfa_enabled_at IS NULL));

CREATE TABLE admin_recovery_codes (
    admin_id  BIGINT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at   TIMESTAMPTZ,
    PRIMARY KEY (admin_id, code_hash)
);

-- 密碼正確、等待輸入驗證碼的登入
CREATE TABLE mfa_challenges (
    token_hash TEXT PRIMARY KEY,
    admin_id   BIGINT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    failures   INT NOT NULL DEFAULT 0
);
CREATE INDEX mfa_challenges_admin_idx ON mfa_challenges (admin_id);

-- 只能設定兩步驟驗證的工作階段（系統要求 MFA、帳號還沒設定時）
ALTER TABLE sessions ADD COLUMN setup_only BOOLEAN NOT NULL DEFAULT false;

INSERT INTO settings (key, value) VALUES ('mfa_required', 'false')
ON CONFLICT (key) DO NOTHING;
