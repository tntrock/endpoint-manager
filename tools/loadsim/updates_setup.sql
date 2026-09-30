-- 負載測試用：5 個群組、每個群組一個更新原則，所有裝置平均分到這 5 個群組。
--   psql -v ON_ERROR_STOP=1 -f tools/loadsim/updates_setup.sql
INSERT INTO device_groups (name)
SELECT 'load wu ' || i FROM generate_series(1, 5) i
ON CONFLICT (name) DO NOTHING;
UPDATE devices SET group_id = (
    SELECT id FROM device_groups WHERE name = 'load wu ' || (1 + abs(hashtext(devices.id::text)) % 5)
);
INSERT INTO update_policies (name, settings, created_by)
SELECT 'load wu ' || i,
       '{"quality_defer_days": 7, "quality_deadline": {"days": 3, "grace": 2}, "active_hours": {"start": 8, "end": 18}}',
       'loadsim'
FROM generate_series(1, 5) i
ON CONFLICT (name) DO NOTHING;
INSERT INTO update_policy_groups (group_id, policy_id)
SELECT g.id, p.id FROM device_groups g JOIN update_policies p ON p.name = g.name
WHERE g.name LIKE 'load wu %'
ON CONFLICT (group_id) DO NOTHING;
UPDATE update_state SET generation = generation + 1;
