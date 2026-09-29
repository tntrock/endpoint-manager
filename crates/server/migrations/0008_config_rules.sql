-- 第三期：組態規則類型；範本識別
ALTER TABLE compliance_rules DROP CONSTRAINT compliance_rules_kind_check;
ALTER TABLE compliance_rules ADD CONSTRAINT compliance_rules_kind_check CHECK (kind IN (
    'forbidden_software', 'required_software', 'software_allowlist', 'os_build', 'required_kb',
    'registry_value', 'service_state', 'firewall', 'bitlocker', 'defender', 'password_policy',
    'local_admins'));
ALTER TABLE compliance_rules ADD COLUMN template_key TEXT;
CREATE UNIQUE INDEX compliance_rules_template_key_idx ON compliance_rules (template_key)
    WHERE template_key IS NOT NULL;
