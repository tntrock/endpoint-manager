-- 總覽與主管報告的每日裝置統計。group_id 0 代表未分組；不設外鍵，群組刪除後歷史仍算在全部的加總裡
CREATE TABLE device_daily (
    day       DATE NOT NULL,
    group_id  BIGINT NOT NULL,
    managed   INTEGER NOT NULL,
    seen      INTEGER NOT NULL,
    compliant INTEGER NOT NULL,
    high_risk INTEGER NOT NULL,
    PRIMARY KEY (day, group_id)
);
