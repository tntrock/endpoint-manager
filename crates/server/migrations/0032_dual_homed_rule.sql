-- 期間開始時的完整網卡狀態與判斷原因：合規規則的例外（網卡名稱、網段、只看條件 2）要拿它重新判斷
ALTER TABLE device_dual_homed_periods
    ADD COLUMN nics   JSONB NOT NULL DEFAULT '[]',
    ADD COLUMN reason TEXT  NOT NULL DEFAULT '';
