-- paused_from 只在 paused 階段有值，且 paused 一定記得暫停前的階段
ALTER TABLE deployments
    ADD CONSTRAINT deployments_paused_from_matches_stage
    CHECK ((stage = 'paused') = (paused_from IS NOT NULL));
