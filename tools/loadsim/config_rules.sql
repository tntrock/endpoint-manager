-- 負載測試用：1,000 條登錄檔規則（每條一個值）＋防火牆、密碼原則各一條。
-- 用法：psql -f tools/loadsim/config_rules.sql（配合 loadsim config）
INSERT INTO compliance_rules (name, kind, severity, params, created_by)
SELECT 'load registry ' || i, 'registry_value', 'low',
       jsonb_build_object('path', 'HKLM\SOFTWARE\Loadsim\K' || (i / 100), 'name', 'V' || i,
                          'op', 'equals', 'expected', '1'), 'loadsim'
FROM generate_series(0, 999) i;
INSERT INTO compliance_rules (name, kind, severity, params, created_by) VALUES
  ('load firewall', 'firewall', 'high', '{"profiles": ["domain", "private", "public"]}', 'loadsim'),
  ('load password', 'password_policy', 'medium', '{"min_length": 12}', 'loadsim');
UPDATE compliance_state SET generation = generation + 1;
