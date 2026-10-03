-- 違規列轉入「未知」時是否寫過歷程：寫過的話回到符合時要補一筆「未知 → 符合」，
-- 沒寫過（規則剛上線時的「無 → 未知」）就不寫，避免歷程暴增
ALTER TABLE device_violations ADD COLUMN logged boolean NOT NULL DEFAULT true;
