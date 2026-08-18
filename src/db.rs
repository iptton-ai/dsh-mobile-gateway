// 令牌 + 配对登记表(rusqlite bundled,单文件 SQLite)。
// 连接数极低,Mutex<Connection> 足够。
//
// 表:
// - tokens   已签发设备令牌;pair 配对来的令牌带 upstream_port(绑定某台
//            Mac 的隧道端口),密码登录的令牌为 NULL(回落配置默认端口)。
// - pairings 手机侧发起的配对请求;code_d 在存活 pending 间唯一(防抄码抢注)。
// - claims   Mac 侧对某 code_d 的应约(带主机码);同一 code 可多条 →
//            手机端全列出,人工比对主机码后点选确认。
use rusqlite::{params, Connection, OptionalExtension};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct TokenDb {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TokenRow {
    pub jti: String,
    pub device: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub revoked: bool,
    /// 配对绑定的隧道端口;None = 密码登录令牌,中转回落配置默认上游。
    pub upstream_port: Option<u16>,
    /// 配对时的来源机器名(如 mac-mini);密码登录为空。
    pub host_label: String,
    /// 归属租户(004;旧行迁移为 'default' = 运营者)。
    pub tenant_id: String,
}

#[derive(Debug, Clone)]
pub struct PairingRow {
    pub id: String,
    pub code_d: String,
    pub secret: String,
    pub device: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub status: String, // pending | confirmed | expired
    pub token_jti: String,
    /// 配对锚定的租户('' = 开放:任意租客可应约,手机人工核对主机码把关;
    /// 非 '' = QR 邀请带 t= 参数锚定,只显示/接受该租户的 offers)。
    pub tenant_id: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ClaimRow {
    pub id: String,
    pub pairing_code: String,
    pub host_code: String,
    pub host_label: String,
    pub upstream_port: u16,
    pub created_at: i64,
    pub expires_at: i64,
    pub status: String, // offered | consumed | expired
    /// 应约方租户(令牌签发时继承为 tokens.tenant_id)。
    pub tenant_id: String,
}

#[derive(Debug, Clone)]
pub struct TenantRow {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub revoked: bool,
}

#[derive(Debug, Clone)]
pub struct HostRow {
    pub id: String,
    pub tenant_id: String,
    pub label: String,
    pub port: u16,
    pub created_at: i64,
    pub enabled: bool,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl TokenDb {
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        Self::migrate(conn)
    }

    pub fn open_in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::migrate(conn)
    }

    fn migrate(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(include_str!("../migrations/001_init.sql"))?;
        conn.execute_batch(include_str!("../migrations/002_pairing.sql"))?;
        conn.execute_batch(include_str!("../migrations/003_web.sql"))?;
        conn.execute_batch(include_str!("../migrations/004_multi_tenant.sql"))?;
        // 旧表升级(已存在的部署):补列。幂等。
        ensure_column(&conn, "tokens", "upstream_port", "INTEGER")?;
        ensure_column(&conn, "tokens", "host_label", "TEXT NOT NULL DEFAULT ''")?;
        ensure_column(&conn, "tokens", "tenant_id", "TEXT NOT NULL DEFAULT 'default'")?;
        ensure_column(&conn, "pairings", "tenant_id", "TEXT NOT NULL DEFAULT ''")?;
        ensure_column(&conn, "claims", "tenant_id", "TEXT NOT NULL DEFAULT 'default'")?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    // ── tokens ───────────────────────────────────────────────────────────

    pub fn insert(
        &self,
        jti: &str,
        device: &str,
        upstream_port: Option<u16>,
        host_label: &str,
        tenant_id: &str,
    ) -> rusqlite::Result<()> {
        self.conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO tokens (jti, device, created_at, upstream_port, host_label, tenant_id) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![jti, device, now(), upstream_port, host_label, tenant_id],
            )
            .map(|_| ())
    }

    /// 吊销令牌;返回是否真的变更(未知 jti 返回 false)。
    pub fn revoke(&self, jti: &str) -> rusqlite::Result<bool> {
        let n = self.conn.lock().unwrap().execute(
            "UPDATE tokens SET revoked = 1 WHERE jti = ?1 AND revoked = 0",
            params![jti],
        )?;
        Ok(n > 0)
    }

    /// 租户围栏吊销:仅当目标令牌归属该租户才生效(跨租户 jti 一律 false,
    /// 不区分「不存在」与「别人的」—— 不给探测面)。
    pub fn revoke_in_tenant(&self, jti: &str, tenant_id: &str) -> rusqlite::Result<bool> {
        let n = self.conn.lock().unwrap().execute(
            "UPDATE tokens SET revoked = 1 \
             WHERE jti = ?1 AND revoked = 0 AND tenant_id = ?2",
            params![jti, tenant_id],
        )?;
        Ok(n > 0)
    }

    pub fn is_valid(&self, jti: &str) -> bool {
        let Ok(Some(revoked)) = self
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT revoked FROM tokens WHERE jti = ?1", params![jti], |r| {
                r.get::<_, i64>(0)
            })
            .optional()
        else {
            return false;
        };
        revoked == 0
    }

    /// 令牌路由(隧道端口 + 租户;None = 未知/已吊销 jti,由吊销检查把关)。
    pub fn route_for(&self, jti: &str) -> Option<(Option<u16>, String)> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT upstream_port, tenant_id FROM tokens WHERE jti = ?1 AND revoked = 0",
                params![jti],
                |r| {
                    Ok((
                        r.get::<_, Option<i64>>(0)?.map(|p| p as u16),
                        r.get::<_, String>(1)?,
                    ))
                },
            )
            .optional()
            .ok()
            .flatten()
    }

    /// 按 jti 找配对来源机器(撤销提示用)。
    pub fn host_label_for(&self, jti: &str) -> Option<String> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT host_label FROM tokens WHERE jti = ?1",
                params![jti],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .ok()
            .flatten()
    }

    /// 刷新最后使用时间;失败不打断请求。
    pub fn touch(&self, jti: &str) {
        let _ = self.conn.lock().unwrap().execute(
            "UPDATE tokens SET last_used_at = ?2 WHERE jti = ?1",
            params![jti, now()],
        );
    }

    pub fn list(&self) -> rusqlite::Result<Vec<TokenRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT jti, device, created_at, last_used_at, revoked, upstream_port, host_label, \
             tenant_id FROM tokens ORDER BY created_at DESC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(TokenRow {
                    jti: r.get(0)?,
                    device: r.get(1)?,
                    created_at: r.get(2)?,
                    last_used_at: r.get(3)?,
                    revoked: r.get::<_, i64>(4)? != 0,
                    upstream_port: r.get::<_, Option<i64>>(5)?.map(|p| p as u16),
                    host_label: r.get(6)?,
                    tenant_id: r.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// 租户围栏清单(/auth/devices 数据源:只看本租户的设备)。
    pub fn list_for_tenant(&self, tenant_id: &str) -> rusqlite::Result<Vec<TokenRow>> {
        Ok(self.list()?.into_iter().filter(|t| t.tenant_id == tenant_id).collect())
    }

    // ── pairings(手机侧)────────────────────────────────────────────────

    /// 注册 pending。同码冲突(防抄码抢注 + 防完成后残留码复用)→ Err(409):
    /// - 存活 pending 占用中;
    /// - 30 分钟内创建过的同码配对(含已确认)—— 已用/废弃的码同样不可注册,
    ///   否则攻击者可在真实配对完成后抢注同码等误操作 claim。
    pub fn pairing_insert(
        &self,
        id: &str,
        code_d: &str,
        secret: &str,
        device: &str,
        ttl_secs: i64,
        tenant_id: &str,
    ) -> rusqlite::Result<()> {
        self.pairing_sweep();
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "INSERT INTO pairings (id, code_d, secret, device, created_at, expires_at, status, \
             tenant_id) \
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?8 \
             WHERE NOT EXISTS (\
               SELECT 1 FROM pairings WHERE code_d = ?2 \
               AND (status = 'pending' OR created_at > ?7 - 1800)\
             )",
            params![id, code_d, secret, device, now(), now() + ttl_secs, now(), tenant_id],
        )?;
        if n == 0 {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
                Some("live pairing with this code exists".into()),
            ));
        }
        Ok(())
    }

    pub fn pairing_get(&self, id: &str) -> Option<PairingRow> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT id, code_d, secret, device, created_at, expires_at, status, token_jti, tenant_id \
                 FROM pairings WHERE id = ?1",
                params![id],
                row_pairing,
            )
            .optional()
            .ok()
            .flatten()
    }

    pub fn pairing_set_status(&self, id: &str, status: &str) {
        let _ = self.conn.lock().unwrap().execute(
            "UPDATE pairings SET status = ?2 WHERE id = ?1",
            params![id, status],
        );
    }

    /// confirm 成功后记录签发的令牌 jti(管理口 status 精确回显用)。
    pub fn pairing_set_token(&self, id: &str, jti: &str) {
        let _ = self.conn.lock().unwrap().execute(
            "UPDATE pairings SET token_jti = ?2 WHERE id = ?1",
            params![id, jti],
        );
    }

    /// 管理口 status:配对(任意状态)+ 其签发令牌(如有)。
    pub fn pairing_status_with_token(
        &self,
        code_d: &str,
    ) -> Option<(PairingRow, Option<TokenRow>)> {
        let p = self
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT id, code_d, secret, device, created_at, expires_at, status, token_jti, tenant_id \
                 FROM pairings WHERE code_d = ?1 ORDER BY created_at DESC LIMIT 1",
                params![code_d],
                row_pairing,
            )
            .optional()
            .ok()
            .flatten()?;
        let token = if p.token_jti.is_empty() {
            None
        } else {
            self.list()
                .ok()?
                .into_iter()
                .find(|t| t.jti == p.token_jti)
        };
        Some((p, token))
    }

    /// 过期清理(pending/claimed 过期置 expired;顺带删已被消费行的秘密)。
    pub fn pairing_sweep(&self) {
        let t = now();
        let _ = self.conn.lock().unwrap().execute_batch(&format!(
            "UPDATE pairings SET status='expired' WHERE status='pending' AND expires_at < {t}; \
             UPDATE claims SET status='expired' WHERE status='offered' AND expires_at < {t};"
        ));
    }

    // ── claims(Mac 侧)──────────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    pub fn claim_insert(
        &self,
        id: &str,
        pairing_code: &str,
        host_code: &str,
        host_label: &str,
        upstream_port: u16,
        ttl_secs: i64,
        tenant_id: &str,
    ) -> rusqlite::Result<()> {
        self.conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO claims (id, pairing_code, host_code, host_label, upstream_port, \
                 created_at, expires_at, status, tenant_id) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'offered', ?8)",
                params![
                    id,
                    pairing_code,
                    host_code,
                    host_label,
                    upstream_port,
                    now(),
                    now() + ttl_secs,
                    tenant_id
                ],
            )
            .map(|_| ())
    }

    /// 某配对码的全部存活 offers(手机端展示)。
    pub fn claims_for(&self, pairing_code: &str) -> Vec<ClaimRow> {
        self.pairing_sweep();
        let conn = self.conn.lock().unwrap();
        let Ok(mut stmt) = conn.prepare(
            "SELECT id, pairing_code, host_code, host_label, upstream_port, created_at, \
             expires_at, status, tenant_id FROM claims \
             WHERE pairing_code = ?1 AND status = 'offered' ORDER BY created_at",
        ) else {
            return Vec::new();
        };
        stmt.query_map(params![pairing_code], row_claim)
            .map(|rows| rows.filter_map(Result::ok).collect())
            .unwrap_or_default()
    }

    pub fn claim_get(&self, id: &str) -> Option<ClaimRow> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT id, pairing_code, host_code, host_label, upstream_port, created_at, \
                 expires_at, status, tenant_id FROM claims WHERE id = ?1",
                params![id],
                row_claim,
            )
            .optional()
            .ok()
            .flatten()
    }

    /// 单次消费:仅当仍为 offered 时置 consumed(原子)。
    pub fn claim_consume(&self, id: &str) -> bool {
        let n = self.conn.lock().unwrap().execute(
            "UPDATE claims SET status = 'consumed' WHERE id = ?1 AND status = 'offered'",
            params![id],
        );
        matches!(n, Ok(n) if n > 0)
    }

    /// 按 code_d 查待确认配对(claim 前置校验:必须有手机在等)。
    pub fn pairing_by_code(&self, code_d: &str) -> Option<PairingRow> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT id, code_d, secret, device, created_at, expires_at, status, token_jti, tenant_id \
                 FROM pairings WHERE code_d = ?1 AND status = 'pending'",
                params![code_d],
                row_pairing,
            )
            .optional()
            .ok()
            .flatten()
    }

    // ── tenants / hosts(004 多租户)─────────────────────────────────────

    pub fn tenant_insert(&self, id: &str, name: &str, admin_key_hash: &str) -> rusqlite::Result<()> {
        self.conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO tenants (id, name, admin_key_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![id, name, admin_key_hash, now()],
            )
            .map(|_| ())
    }

    /// 按密钥摘要查活跃租户(公开面 /admin/* 鉴权路径)。
    pub fn tenant_by_key(&self, admin_key_hash: &str) -> Option<TenantRow> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT id, name, created_at, revoked FROM tenants \
                 WHERE admin_key_hash = ?1 AND revoked = 0",
                params![admin_key_hash],
                row_tenant,
            )
            .optional()
            .ok()
            .flatten()
    }

    pub fn tenant_by_id(&self, id: &str) -> Option<TenantRow> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT id, name, created_at, revoked FROM tenants WHERE id = ?1",
                params![id],
                row_tenant,
            )
            .optional()
            .ok()
            .flatten()
    }

    pub fn tenants_list(&self) -> rusqlite::Result<Vec<TenantRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, name, created_at, revoked FROM tenants ORDER BY created_at")?;
        let rows = stmt
            .query_map([], row_tenant)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// 吊销租户(密钥立即失效);返回是否命中。
    pub fn tenant_set_revoked(&self, id: &str, revoked: bool) -> rusqlite::Result<bool> {
        let n = self.conn.lock().unwrap().execute(
            "UPDATE tenants SET revoked = ?2 WHERE id = ?1",
            params![id, revoked as i64],
        )?;
        Ok(n > 0)
    }

    pub fn host_insert(&self, id: &str, tenant_id: &str, label: &str, port: u16) -> rusqlite::Result<()> {
        self.conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO hosts (id, tenant_id, label, port, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![id, tenant_id, label, port, now()],
            )
            .map(|_| ())
    }

    /// 按端口查宿主登记(claim 归属仲裁)。
    pub fn host_by_port(&self, port: u16) -> Option<HostRow> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT id, tenant_id, label, port, created_at, enabled FROM hosts WHERE port = ?1",
                params![port],
                row_host,
            )
            .optional()
            .ok()
            .flatten()
    }

    pub fn hosts_list(&self) -> rusqlite::Result<Vec<HostRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, tenant_id, label, port, created_at, enabled FROM hosts ORDER BY port",
        )?;
        let rows = stmt.query_map([], row_host)?.collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// 删除宿主登记;返回是否命中。
    pub fn host_remove(&self, id: &str) -> rusqlite::Result<bool> {
        let n = self
            .conn
            .lock()
            .unwrap()
            .execute("DELETE FROM hosts WHERE id = ?1", params![id])?;
        Ok(n > 0)
    }

    // ── web_password(Web 面登录密码)──────────────────────────────────

    /// 当前 web 面密码哈希与版本号;未设置返回 None。
    pub fn web_password(&self) -> Option<(String, i64)> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT hash, version FROM web_password WHERE id = 1",
                [],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            )
            .optional()
            .ok()
            .flatten()
    }

    /// 写入/更新 web 面密码哈希;版本号自增(旧会话签名失效)。返回新版本。
    pub fn set_web_password(&self, hash: &str) -> rusqlite::Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO web_password (id, hash, version, updated_at) VALUES (1, ?1, 1, ?2) \
             ON CONFLICT(id) DO UPDATE SET hash = ?1, \
             version = version + 1, updated_at = ?2",
            params![hash, now()],
        )?;
        Ok(conn.query_row(
            "SELECT version FROM web_password WHERE id = 1",
            [],
            |r| r.get::<_, i64>(0),
        )?)
    }

    /// 清除 web 面密码(整行删除 = 关闭登录)。
    pub fn clear_web_password(&self) -> rusqlite::Result<()> {
        self.conn
            .lock()
            .unwrap()
            .execute("DELETE FROM web_password WHERE id = 1", [])?;
        Ok(())
    }
}

fn row_pairing(r: &rusqlite::Row<'_>) -> rusqlite::Result<PairingRow> {
    Ok(PairingRow {
        id: r.get(0)?,
        code_d: r.get(1)?,
        secret: r.get(2)?,
        device: r.get(3)?,
        created_at: r.get(4)?,
        expires_at: r.get(5)?,
        status: r.get(6)?,
        token_jti: r.get(7)?,
        tenant_id: r.get(8)?,
    })
}

fn row_claim(r: &rusqlite::Row<'_>) -> rusqlite::Result<ClaimRow> {
    Ok(ClaimRow {
        id: r.get(0)?,
        pairing_code: r.get(1)?,
        host_code: r.get(2)?,
        host_label: r.get(3)?,
        upstream_port: r.get(4)?,
        created_at: r.get(5)?,
        expires_at: r.get(6)?,
        status: r.get(7)?,
        tenant_id: r.get(8)?,
    })
}

fn row_tenant(r: &rusqlite::Row<'_>) -> rusqlite::Result<TenantRow> {
    Ok(TenantRow {
        id: r.get(0)?,
        name: r.get(1)?,
        created_at: r.get(2)?,
        revoked: r.get::<_, i64>(3)? != 0,
    })
}

fn row_host(r: &rusqlite::Row<'_>) -> rusqlite::Result<HostRow> {
    Ok(HostRow {
        id: r.get(0)?,
        tenant_id: r.get(1)?,
        label: r.get(2)?,
        port: r.get::<_, i64>(3)? as u16,
        created_at: r.get(4)?,
        enabled: r.get::<_, i64>(5)? != 0,
    })
}

/// 幂等补列(旧部署升级)。
fn ensure_column(
    conn: &Connection,
    table: &str,
    column: &str,
    decl: &str,
) -> rusqlite::Result<()> {
    let exists = conn
        .prepare(&format!("PRAGMA table_info({table})"))?
        .query_map([], |r| r.get::<_, String>(1))?
        .filter_map(Result::ok)
        .any(|c| c == column);
    if !exists {
        conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl};"))?;
    }
    Ok(())
}
