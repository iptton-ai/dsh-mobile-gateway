// 多租户(004):租户上下文、公开面按钥解析中间件、运营者租户/宿主管理面。
//
// 信任模型:
// - 运营者 = 管理面(8103,loopback + env token/ssh)—— 跨租户超管;
// - 显式租户 = tenants 表登记 + 独立管理密钥(sha256 hex 入库,明文只在
//   创建响应里出现一次),经公开面 /admin/* 以 Bearer 密钥访问,
//   全部操作被围栏在本租户(claim 端口归属 / tokens / revoke / status);
// - 未登记任何租户的部署:公开面 /admin/* 恒 401,行为与 004 之前一致。
use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use gateway_shared::error::{AppError, AppResult};

use crate::auth::client_ip;
use crate::AppState;

/// 隐式运营者租户 id(不出现在 tenants 表)。
pub const DEFAULT_TENANT: &str = "default";

/// 请求级租户上下文(经 Extension 注入;operator=true 时 id 恒 default)。
#[derive(Debug, Clone)]
pub struct TenantCtx {
    pub id: String,
    pub operator: bool,
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 生成租户管理密钥(32 字节随机 → 64 hex 字符,Bearer 兼容)。
pub fn generate_tenant_key() -> String {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    hex(&b)
}

/// 密钥摘要(sha256 hex;密钥为高熵随机串,无盐摘要足够,常数时间比较由
/// 64 位定长 hex 字符串承载 —— 长度恒等,逐字节异或不提前泄内容)。
pub fn key_hash(key: &str) -> String {
    hex(&Sha256::digest(key.as_bytes()))
}

/// 公开面租户鉴权:Bearer 密钥 → sha256 → tenants 表查租户(revoked=0)。
/// 按 IP 限速防密钥爆破(窗口宽:插件配对期 3s 轮 status 属合法流量)。
pub async fn tenant_auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let ip = client_ip(req.headers());
    if !state.admin_limiter.allow(&ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "too many admin requests, retry later"})),
        )
            .into_response();
    }
    let key = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned);
    let hash = key.map(|k| key_hash(&k));
    let tenant = hash.as_deref().and_then(|h| state.db.tenant_by_key(h));
    match tenant {
        Some(t) => {
            req.extensions_mut()
                .insert(TenantCtx { id: t.id, operator: false });
            next.run(req).await
        }
        // 不区分「没带钥/钥错/租户已吊销」—— 不给探测面。
        None => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "tenant key required"})),
        )
            .into_response(),
    }
}

// ── 租户管理(运营者,管理面)────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TenantCreateRequest {
    #[serde(default)]
    pub name: String,
}

/// 创建租户:服务端生成 id 与密钥;**密钥明文只在本次响应出现一次**。
pub async fn tenant_create_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TenantCreateRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let id = format!("t-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let key = generate_tenant_key();
    state
        .db
        .tenant_insert(&id, &req.name.chars().take(64).collect::<String>(), &key_hash(&key))
        .map_err(|e| AppError::Internal(anyhow::anyhow!("tenant insert: {e}")))?;
    tracing::info!(tenant = %id, "tenant created");
    Ok(Json(serde_json::json!({
        "id": id,
        "name": req.name,
        "admin_key": key, // 只回显一次
    })))
}

pub async fn tenant_list_handler(
    State(state): State<Arc<AppState>>,
) -> AppResult<Json<serde_json::Value>> {
    let rows = state
        .db
        .tenants_list()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("tenants list: {e}")))?;
    Ok(Json(serde_json::Value::Array(
        rows.into_iter()
            .map(|t| serde_json::json!({
                "id": t.id, "name": t.name,
                "created_at": t.created_at, "revoked": t.revoked,
            }))
            .collect(),
    )))
}

#[derive(Deserialize)]
pub struct TenantRevokeRequest {
    pub id: String,
}

/// 吊销/恢复租户(吊销后其密钥立即失效,已有令牌由 tokens 行独立吊销)。
pub async fn tenant_revoke_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TenantRevokeRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if req.id == DEFAULT_TENANT {
        return Err(AppError::BadRequest("cannot revoke the implicit operator tenant".into()));
    }
    let ok = state
        .db
        .tenant_set_revoked(&req.id, true)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("tenant revoke: {e}")))?;
    tracing::warn!(tenant = %req.id, ok, "tenant revoked");
    Ok(Json(serde_json::json!({ "revoked": ok })))
}

// ── 宿主登记(运营者,管理面)────────────────────────────────────────────

#[derive(Deserialize)]
pub struct HostCreateRequest {
    pub tenant_id: String,
    #[serde(default)]
    pub label: String,
    pub port: u16,
}

/// 登记宿主:把隧道端口绑定到某租户(端口全局唯一 —— 两台 Mac 撞端口 =
/// 流量串台,登记表就是仲裁者)。显式租户 claim 必须命中登记。
pub async fn host_create_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<HostCreateRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if req.tenant_id != DEFAULT_TENANT && state.db.tenant_by_id(&req.tenant_id).is_none() {
        return Err(AppError::BadRequest("unknown tenant".into()));
    }
    if !(state.config.tunnel_port_min..=state.config.tunnel_port_max).contains(&req.port) {
        return Err(AppError::BadRequest(format!(
            "tunnel port must be {}-{}",
            state.config.tunnel_port_min, state.config.tunnel_port_max
        )));
    }
    let id = format!("h-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    state
        .db
        .host_insert(&id, &req.tenant_id, &req.label.chars().take(64).collect::<String>(), req.port)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("host insert: {e}")))?;
    tracing::info!(host = %id, tenant = %req.tenant_id, port = req.port, "host registered");
    Ok(Json(serde_json::json!({ "id": id, "port": req.port, "tenant_id": req.tenant_id })))
}

pub async fn host_list_handler(
    State(state): State<Arc<AppState>>,
) -> AppResult<Json<serde_json::Value>> {
    let rows = state
        .db
        .hosts_list()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("hosts list: {e}")))?;
    Ok(Json(serde_json::Value::Array(
        rows.into_iter()
            .map(|h| serde_json::json!({
                "id": h.id, "tenant_id": h.tenant_id, "label": h.label,
                "port": h.port, "created_at": h.created_at, "enabled": h.enabled,
            }))
            .collect(),
    )))
}

#[derive(Deserialize)]
pub struct HostRemoveRequest {
    pub id: String,
}

/// 删除宿主登记(端口回到未登记态;显式租户的 claim 随之收紧为 403,
/// 已签发令牌不受影响 —— 令牌吊销是独立动作)。
pub async fn host_remove_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<HostRemoveRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let ok = state
        .db
        .host_remove(&req.id)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("host remove: {e}")))?;
    Ok(Json(serde_json::json!({ "removed": ok })))
}
