-- 002 配对面(pair 鉴权,取代手动密码为主渠道)。
-- 手机侧 pending 配对:code_d 存活期内唯一(抄码抢注 → 后到者 409)。
CREATE TABLE IF NOT EXISTS pairings (
    id         TEXT PRIMARY KEY,
    code_d     TEXT NOT NULL,
    secret     TEXT NOT NULL,
    device     TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    status     TEXT NOT NULL DEFAULT 'pending',
    token_jti  TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_pairings_code ON pairings(code_d, status);

-- Mac 侧应约:同一 code_d 可多条(多台 Mac/异常场景)→ 手机端全列出,
-- 人工比对各自的主机码后点选;claim 单次消费。
CREATE TABLE IF NOT EXISTS claims (
    id            TEXT PRIMARY KEY,
    pairing_code  TEXT NOT NULL,
    host_code     TEXT NOT NULL,
    host_label    TEXT NOT NULL DEFAULT '',
    upstream_port INTEGER NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    status        TEXT NOT NULL DEFAULT 'offered'
);

CREATE INDEX IF NOT EXISTS idx_claims_code ON claims(pairing_code, status);
