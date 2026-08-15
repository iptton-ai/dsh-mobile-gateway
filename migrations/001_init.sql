-- dsh-gateway 设备令牌登记表。
-- jti 为 JWT ID;revoked=1 后中间件立即拒绝该令牌(吊销即时生效)。
CREATE TABLE IF NOT EXISTS tokens (
    jti         TEXT PRIMARY KEY,
    device      TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_tokens_revoked ON tokens(revoked);
