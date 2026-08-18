-- 004 多宿主登记 + 多租户。
-- tenants:显式租户(管理密钥 sha256 hex;公开面 /admin/* 按钥解析)。
--   'default' 为隐式运营者租户 —— 不落本表;管理面(8103,env token/ssh)
--   的所有操作以它进行,operator ctx 可跨租户。
-- hosts:宿主登记表(隧道端口归属,claim 时校验)。
--   端口已登记 → 必须归属当前租户且启用;未登记端口仅运营者/default
--   沿用范围白名单(单运营者旧部署零迁移成本);显式租户必须先登记。
CREATE TABLE IF NOT EXISTS tenants (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL DEFAULT '',
    admin_key_hash TEXT NOT NULL UNIQUE,
    created_at     INTEGER NOT NULL,
    revoked        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS hosts (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL DEFAULT 'default',
    label      TEXT NOT NULL DEFAULT '',
    port       INTEGER NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_hosts_tenant ON hosts(tenant_id, enabled);
