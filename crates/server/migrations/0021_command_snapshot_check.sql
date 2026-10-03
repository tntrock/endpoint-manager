-- 腳本快照欄位逐一檢查：非腳本的指令三個欄位都必須是 NULL（0018 的寫法允許只填一部分）
ALTER TABLE command_runs DROP CONSTRAINT command_runs_script_snapshot;
ALTER TABLE command_runs ADD CONSTRAINT command_runs_script_snapshot CHECK (
    (action = 'script') = (script_sha256 IS NOT NULL)
    AND (action = 'script') = (script_content IS NOT NULL)
    AND (action = 'script') = (script_timeout_minutes IS NOT NULL));
