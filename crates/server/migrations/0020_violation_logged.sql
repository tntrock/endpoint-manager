-- 違規列轉入「未知」時是否寫過歷程：寫過的話回到符合時要補一筆「未知 → 符合」，
-- 沒寫過（規則剛上線時的「無 → 未知」）就不寫，避免歷程暴增
ALTER TABLE device_violations ADD COLUMN logged boolean NOT NULL DEFAULT true;
-- 既有資料：沒有對應「→ 未知」歷程的未知列（規則上線後就一直是未知）不補記；
-- 歷程已被清理的也一樣（沒有前一筆可以收尾）
UPDATE device_violations v SET logged = false
WHERE v.status = 'unknown' AND NOT EXISTS (
    SELECT 1 FROM violation_events e
    WHERE e.device_id = v.device_id AND e.rule_id = v.rule_id AND e.to_status = 'unknown');
