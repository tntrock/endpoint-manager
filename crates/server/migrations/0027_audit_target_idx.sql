-- 裝置頁時間軸：查某台裝置的管理記錄
CREATE INDEX audit_log_target_idx ON audit_log (target, at DESC) WHERE target IS NOT NULL;
