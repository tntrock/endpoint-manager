-- 錯誤設定偵測第一期：服務路徑沒加引號（Windows）、多餘的 UID 0 帳號（Linux）
ALTER TABLE compliance_rules DROP CONSTRAINT compliance_rules_kind_check;
ALTER TABLE compliance_rules ADD CONSTRAINT compliance_rules_kind_check CHECK (kind IN (
    'forbidden_software', 'required_software', 'software_allowlist', 'os_build', 'required_kb',
    'registry_value', 'service_state', 'firewall', 'bitlocker', 'defender', 'password_policy',
    'local_admins', 'patch_age', 'reboot_pending', 'update_policy', 'dual_homed',
    'forbidden_image', 'container_privilege', 'unpinned_image',
    'unquoted_service_path', 'extra_root_account'));
