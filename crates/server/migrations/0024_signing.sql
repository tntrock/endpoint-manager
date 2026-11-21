-- 腳本與套件簽章（金鑰在伺服器以外，伺服器只保存與轉送簽章）
ALTER TABLE scripts ADD COLUMN signature TEXT;
ALTER TABLE packages ADD COLUMN signature TEXT;
-- 建立指令時快照，之後腳本換簽章不影響已建立的指令
ALTER TABLE command_runs ADD COLUMN script_signature TEXT;
-- Agent 回報的信任公鑰（Base64）。只用於顯示與預先檢查，不影響 Agent 的判斷
ALTER TABLE devices ADD COLUMN signing_keys TEXT[] NOT NULL DEFAULT '{}';
CREATE INDEX devices_signing_idx ON devices ((cardinality(signing_keys) > 0))
    WHERE cardinality(signing_keys) > 0;
