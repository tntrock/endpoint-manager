-- devices.last_ip 是 Agent 回報的文字：無法解析時回 NULL，不讓據點查詢出錯
CREATE FUNCTION try_inet(t TEXT) RETURNS INET LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
    RETURN t::inet;
EXCEPTION WHEN others THEN
    RETURN NULL;
END $$;
