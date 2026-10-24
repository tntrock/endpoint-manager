-- Linux Agent 第一版
ALTER TABLE devices ADD COLUMN os_family TEXT NOT NULL DEFAULT 'windows'
    CHECK (os_family IN ('windows', 'linux'));
CREATE INDEX devices_os_family_idx ON devices (os_family) WHERE os_family <> 'windows';

CREATE TABLE device_accounts (
    device_id  UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    data       JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE scripts ADD COLUMN language TEXT NOT NULL DEFAULT 'powershell'
    CHECK (language IN ('powershell', 'sh'));
ALTER TABLE command_runs ADD COLUMN script_language TEXT
    CHECK (script_language IN ('powershell', 'sh'));
UPDATE command_runs SET script_language = 'powershell' WHERE action = 'script';
-- 名稱不能用 command_runs_script_language_check：那是上面欄位 CHECK 自動產生的名稱
ALTER TABLE command_runs ADD CONSTRAINT command_runs_script_has_language
    CHECK ((action = 'script') = (script_language IS NOT NULL));
ALTER TABLE command_runs ADD COLUMN skipped_os INT NOT NULL DEFAULT 0 CHECK (skipped_os >= 0);
