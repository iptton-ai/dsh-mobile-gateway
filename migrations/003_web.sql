-- Web 面(浏览器远程访问 dsh web)登录密码:argon2 hash + 版本号。
-- 版本号纳入会话签名派生 → 改密码 = 全量旧会话失效。
-- 单行表(id=1);hash 为空行不存在 = web 面关闭(env 兜底除外)。
CREATE TABLE IF NOT EXISTS web_password (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    hash TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL DEFAULT 0
);
