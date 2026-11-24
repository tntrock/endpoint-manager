-- 錯誤設定偵測第三期：對外開放的服務與遠端登入（exposure 區段）與四種規則
CREATE TABLE device_exposure (
    device_id  UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    data       JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE compliance_rules DROP CONSTRAINT compliance_rules_kind_check;
ALTER TABLE compliance_rules ADD CONSTRAINT compliance_rules_kind_check CHECK (kind IN (
    'forbidden_software', 'required_software', 'software_allowlist', 'os_build', 'required_kb',
    'registry_value', 'service_state', 'firewall', 'bitlocker', 'defender', 'password_policy',
    'local_admins', 'patch_age', 'reboot_pending', 'update_policy', 'dual_homed',
    'forbidden_image', 'container_privilege', 'unpinned_image',
    'unquoted_service_path', 'extra_root_account', 'open_share',
    'exposed_service', 'firewall_allow_all', 'ssh_config', 'rdp_users'));
