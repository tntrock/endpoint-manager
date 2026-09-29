-- 負載測試用：50 條合規規則（配合 loadsim 產生的「Loadsim Product NNNN」軟體清單）。
-- 用法：psql -f tools/loadsim/rules.sql
INSERT INTO compliance_rules (name, kind, severity, params, created_by)
SELECT 'load forbidden ' || i, 'forbidden_software', 'high',
       jsonb_build_object('name', '*Product ' || lpad(i::text, 4, '0')), 'loadsim'
FROM generate_series(1, 20) i;
INSERT INTO compliance_rules (name, kind, severity, params, created_by)
SELECT 'load required ' || i, 'required_software', 'medium',
       jsonb_build_object('name', 'Loadsim Product ' || lpad((20 + i)::text, 4, '0'),
                          'min_version', '3.0'), 'loadsim'
FROM generate_series(1, 20) i;
INSERT INTO compliance_rules (name, kind, severity, params, created_by)
SELECT 'load kb ' || i, 'required_kb', 'low',
       jsonb_build_object('kb', 'KB50000' || lpad(i::text, 2, '0')), 'loadsim'
FROM generate_series(1, 8) i;
INSERT INTO compliance_rules (name, kind, severity, params, created_by) VALUES
  ('load allowlist', 'software_allowlist', 'low', '{"entries": [{"name": "Loadsim*"}]}', 'loadsim'),
  ('load build', 'os_build', 'high', '{"min_build": 19045}', 'loadsim');
UPDATE compliance_state SET generation = generation + 1;
