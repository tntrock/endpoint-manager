-- 負載測試用：把前 5,000 台放進群組「load cmd」，對這個群組下一個「重新收集」，量展開時間。
-- 用 psql 執行（需要 \timing）：
--   psql -v ON_ERROR_STOP=1 -f tools/loadsim/commands_setup.sql
INSERT INTO device_groups (name) VALUES ('load cmd') ON CONFLICT (name) DO NOTHING;
UPDATE devices SET group_id = (SELECT id FROM device_groups WHERE name = 'load cmd')
WHERE id IN (SELECT id FROM devices ORDER BY id LIMIT 5000);

\timing on
-- 與 commands::runs::create_run 相同的兩個 INSERT（同一個交易）
BEGIN;
WITH run AS (
    INSERT INTO command_runs (action, target_label, created_by, expires_at)
    VALUES ('collect', '群組 load cmd', 'loadsim', now() + interval '7 days')
    RETURNING id
)
INSERT INTO command_targets (run_id, device_id)
SELECT run.id, d.id FROM run, devices d
WHERE d.status = 'active' AND d.group_id = (SELECT id FROM device_groups WHERE name = 'load cmd');
COMMIT;
\timing off
SELECT count(*) AS targets FROM command_targets;
-- 量完後把裝置移回原本的群組（這裡把它們改回未分組；原本有群組的話請自行調整）：
--   UPDATE devices SET group_id = NULL WHERE group_id = (SELECT id FROM device_groups WHERE name = 'load cmd');
--   DELETE FROM device_groups WHERE name = 'load cmd';
-- 執行 loadsim commands 時用 --expect 5000 確認回報成功的台數。
