// 鉴权面:配对为主渠道(M6.1)、密码登录为可选兜底、设备管理、
// Bearer 中间件(含按令牌解析隧道端口)、登录/配对限速。
use argon2::password_hash::{PasswordHash, PasswordVerifier};
use argon2::Argon2;
use axum::{
    extract::{Request, State},
    http::HeaderMap,
    middleware::Next,
    response::Response,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use gateway_shared::error::{AppError, AppResult};
use gateway_shared::jwt::{decode_jwt, encode_jwt, extract_bearer_token};

use crate::db::TokenRow;
use crate::AppState;

/// 设备令牌 claims。exp 由签发时刻 + TTL 决定;吊销以 DB 里的 jti 状态为准。
#[derive(Debug, Serialize, Deserialize)]
pub struct GatewayClaims {
    pub sub: String,
    pub jti: String,
    pub device: String,
    pub iat: i64,
    pub exp: i64,
}

/// 中间件解析成功后塞进 request extensions 的当前设备 + 上游路由。
#[derive(Debug, Clone)]
pub struct AuthedDevice {
    pub jti: String,
    pub device: String,
    /// 本令牌绑定的隧道端口(配对来源机器);None = 默认上游(密码登录令牌)。
    pub upstream_port: Option<u16>,
    /// 本令牌归属租户(devices/revoke 的围栏键)。
    pub tenant_id: String,
}

/// Handler 提取器:从 extensions 取出中间件鉴权结果。
impl axum::extract::FromRequestParts<std::sync::Arc<crate::AppState>> for AuthedDevice {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &std::sync::Arc<crate::AppState>,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthedDevice>()
            .cloned()
            .ok_or(AppError::Unauthorized)
    }
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub password: String,
    #[serde(default)]
    pub device: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    /// Unix 秒。
    pub expires_at: i64,
}

#[derive(Deserialize)]
pub struct RevokeRequest {
    pub jti: String,
}

/// 每 IP 滑动窗口限速器(登录与配对面共用结构,实例独立)。
pub struct LoginRateLimiter {
    attempts: Mutex<HashMap<String, Vec<Instant>>>,
    window: Duration,
    max_attempts: usize,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            window: Duration::from_secs(300),
            max_attempts: 8,
        }
    }

    /// 配对面专用:窗口更宽(输码是人工动作)。
    pub fn new_pairing() -> Self {
        Self::new_limits(20, 300)
    }

    /// 自定义窗口/上限(公开面租户 admin:宽窗口容纳插件 3s 轮询,
    /// 上限压密钥爆破)。
    pub fn new_limits(max_attempts: usize, window_secs: u64) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            window: Duration::from_secs(window_secs),
            max_attempts,
        }
    }

    /// 超限返回 false(本次不计数);放行则计数并返回 true。
    pub fn allow(&self, key: &str) -> bool {
        let mut map = self.attempts.lock().unwrap();
        let now = Instant::now();
        let entry = map.entry(key.to_string()).or_default();
        entry.retain(|t| now.duration_since(*t) < self.window);
        if entry.len() >= self.max_attempts {
            return false;
        }
        entry.push(now);
        true
    }
}

impl Default for LoginRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// 从 X-Real-IP / X-Forwarded-For 取来源 IP(nginx 注入),兜底 socket 对端。
pub fn client_ip(headers: &HeaderMap) -> String {
    if let Some(v) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        return v.to_string();
    }
    if let Some(v) = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
    {
        if !v.is_empty() {
            return v.to_string();
        }
    }
    "unknown".to_string()
}

/// 密码登录(可选兜底):未配置 DSH_GATEWAY_PASSWORD_HASH 时禁用(仅配对)。
pub async fn login_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> AppResult<Json<LoginResponse>> {
    if state.config.password_hash.is_empty() {
        return Err(AppError::Forbidden(
            "password login disabled; use pairing".into(),
        ));
    }
    let ip = client_ip(&headers);
    if !state.login_limiter.allow(&ip) {
        // 409 而非 401,避免给爆破者密码校验信号。
        return Err(AppError::Conflict("too many attempts, retry later".into()));
    }

    let parsed = PasswordHash::new(&state.config.password_hash)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("password hash malformed: {e}")))?;
    if Argon2::default()
        .verify_password(req.password.as_bytes(), &parsed)
        .is_err()
    {
        return Err(AppError::Unauthorized);
    }

    let jti = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    let exp = (now + chrono::Duration::days(state.config.token_ttl_days)).timestamp();
    let claims = GatewayClaims {
        sub: "dsh-client".into(),
        jti: jti.clone(),
        device: req.device.chars().take(64).collect(),
        iat: now.timestamp(),
        exp,
    };
    let token = encode_jwt(&claims, &state.config.jwt_secret)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("jwt encode: {e}")))?;
    state
        .db
        .insert(&jti, &claims.device, None, "", crate::tenant::DEFAULT_TENANT)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("db insert: {e}")))?;
    tracing::info!(ip = %ip, jti = %jti, "login ok");
    Ok(Json(LoginResponse { token, expires_at: exp }))
}

/// 本租户令牌清单(多租户围栏:看不到别家设备)。
pub async fn devices_handler(
    State(state): State<Arc<AppState>>,
    device: AuthedDevice,
) -> AppResult<Json<Vec<TokenRow>>> {
    let rows = state
        .db
        .list_for_tenant(&device.tenant_id)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("db list: {e}")))?;
    Ok(Json(rows))
}

pub async fn revoke_handler(
    State(state): State<Arc<AppState>>,
    device: AuthedDevice,
    Json(req): Json<RevokeRequest>,
) -> AppResult<Json<serde_json::Value>> {
    // 只能吊销本租户令牌;跨租户 jti 与未知 jti 同样返回 revoked:false,
    // 不给「这个 jti 存在但属于别人」的探测面。
    let ok = state
        .db
        .revoke_in_tenant(&req.jti, &device.tenant_id)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("db revoke: {e}")))?;
    tracing::info!(by = %device.jti, revoked = %req.jti, ok, "token revoked");
    Ok(Json(serde_json::json!({ "revoked": ok })))
}

/// Bearer JWT 校验 + 吊销检查 + 按令牌解析上游隧道端口与租户。
/// 所有中转请求(含 WS upgrade)与设备管理接口共用。
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = extract_bearer_token(req.headers()).map_err(|_| AppError::Unauthorized)?;
    let claims: GatewayClaims = decode_jwt(token, &state.config.jwt_secret)
        .map_err(|_| AppError::Unauthorized)?;
    if !state.db.is_valid(&claims.jti) {
        return Err(AppError::Unauthorized);
    }
    state.db.touch(&claims.jti);
    let Some((upstream_port, tenant_id)) = state.db.route_for(&claims.jti) else {
        return Err(AppError::Unauthorized);
    };
    req.extensions_mut().insert(AuthedDevice {
        jti: claims.jti,
        device: claims.device,
        upstream_port,
        tenant_id,
    });
    Ok(next.run(req).await)
}
