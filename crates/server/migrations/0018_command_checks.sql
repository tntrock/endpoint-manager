-- 指令的資料完整性：腳本快照欄位只用於腳本（而且一定齊全）；延遲只用於重新開機／關機
ALTER TABLE command_runs
    ADD CONSTRAINT command_runs_script_snapshot CHECK
        ((action = 'script') = (script_sha256 IS NOT NULL AND script_content IS NOT NULL
                                AND script_timeout_minutes IS NOT NULL)),
    ADD CONSTRAINT command_runs_delay_action CHECK
        (delay_minutes IS NULL OR action IN ('reboot', 'shutdown'));
