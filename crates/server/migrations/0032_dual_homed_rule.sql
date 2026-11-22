-- 期間開始時的完整網卡狀態與判斷原因：合規規則的例外（網卡名稱、網段、只看條件 2）要拿它重新判斷
ALTER TABLE device_dual_homed_periods
    ADD COLUMN nics   JSONB NOT NULL DEFAULT '[]',
    ADD COLUMN reason TEXT  NOT NULL DEFAULT '';

-- 合規規則類型加上多重連線
ALTER TABLE compliance_rules DROP CONSTRAINT compliance_rules_kind_check;
ALTER TABLE compliance_rules ADD CONSTRAINT compliance_rules_kind_check CHECK (kind IN (
    'forbidden_software', 'required_software', 'software_allowlist', 'os_build', 'required_kb',
    'registry_value', 'service_state', 'firewall', 'bitlocker', 'defender', 'password_policy',
    'local_admins', 'patch_age', 'reboot_pending', 'update_policy', 'dual_homed'));
