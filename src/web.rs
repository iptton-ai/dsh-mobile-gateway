// Web 面:浏览器远程访问 dsh web 的鉴权层(设计:docs/REMOTE-WEB-ACCESS.md)。
//
// 独立监听端口(build_web_router;nginx 按 server_name 分流到 web_bind:web_port)。
// Host 路由归 TLS 反代管,不在网关内做 —— axum Router::layer 包的是各条路由
// 而非路由决策本身,中间件改写 URI 无法影响路由(实测嵌套路由收不到)。
//
// 鉴权:argon2 密码登录(密码哈希存 DB,管理面写入;env 为兜底)→ 签发
// HttpOnly cookie(HMAC 签名 payload,密钥从 JWT_SECRET 域分离派生)。
// 会话与 App 的 30 天设备令牌是两套独立凭证,互不通用。
//
// CSRF(cookie 鉴权必补的环):非 GET 请求过 Sec-Fetch-Site / Origin 同源门。
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::{
    extract::{Form, Request, State},
    http::{header, HeaderMap, StatusCode, Uri},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Json, Router,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use gateway_shared::error::{AppError, AppResult};
use gateway_shared::jwt::{decode_jwt, encode_jwt};

use crate::auth::{client_ip, AuthedDevice};
use crate::relay;
use crate::AppState;

/// cookie 名。
const COOKIE: &str = "dshweb";
/// 会话有效期(秒)。
const SESSION_TTL: i64 = 12 * 3600;
/// 剩余不足该值时滑动续期(秒)。
const SESSION_REFRESH: i64 = 6 * 3600;
/// 登录/中转非 GET 请求体上限(与公开面其它未鉴权接口对齐)。
const BODY_LIMIT: usize = 64 * 1024;

// ── 会话签名 ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct WebClaims {
    sub: String,
    jti: String,
    iat: i64,
    exp: i64,
}

/// 从 JWT_SECRET 派生 web 会话签名密钥(SHA-256,域分离 + 密码版本绑定:
/// 改密码 → version 变 → 旧会话全部失效)。
fn web_secret(jwt_secret: &str, pw_version: i64) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"dsh-web-session-v1\x00");
    h.update(jwt_secret.as_bytes());
    h.update(b"\x00");
    h.update(pw_version.to_string().as_bytes());
    let d = h.finalize();
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// 当前生效的密码哈希与版本:DB 优先,env 兜底;两处都空 = web 面关闭。
/// env 兜底固定 version 0 —— 首次 DB 写入即 version 1,签名域随 version 变化,
/// env 时代的存量会话全部失效(改密码 = 全量下线语义)。
fn web_creds(state: &AppState) -> Option<(String, i64)> {
    state
        .db
        .web_password()
        .or_else(|| {
            (!state.config.web_password_hash.is_empty())
                .then(|| (state.config.web_password_hash.clone(), 0))
        })
}

fn issue_session(state: &AppState, pw_version: i64) -> AppResult<(String, i64)> {
    let now = chrono::Utc::now().timestamp();
    let exp = now + SESSION_TTL;
    // jti 带随机前缀(不以 uuid 定长格式出现,避免与设备令牌 jti 混淆)。
    let mut rnd = [0u8; 8];
    OsRng.fill_bytes(&mut rnd);
    let jti = format!(
        "web:{}",
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let secret = web_secret(&state.config.jwt_secret, pw_version);
    let token = encode_jwt(
        &WebClaims { sub: "dsh-web".into(), jti: jti.clone(), iat: now, exp },
        &secret,
    )
    .map_err(|e| AppError::Internal(anyhow::anyhow!("web jwt encode: {e}")))?;
    Ok((token, exp))
}

/// 验 cookie → (jti, exp);无效/过期/密码已轮换返回 None。
fn verify_session(state: &AppState, headers: &HeaderMap) -> Option<(String, i64)> {
    let (hash, version) = web_creds(state)?;
    let raw = headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(|s| s.trim())
        .find_map(|s| s.strip_prefix(&format!("{COOKIE}=")))?;
    let secret = web_secret(&state.config.jwt_secret, version);
    let claims: WebClaims = decode_jwt(raw, &secret).ok()?;
    if claims.sub != "dsh-web" || claims.exp <= chrono::Utc::now().timestamp() {
        return None;
    }
    // 密码哈希存在性再确认(清空 DB 且 env 为空 = 整面关闭,存量 cookie 也不放行)。
    let _ = PasswordHash::new(&hash).ok()?;
    Some((claims.jti, claims.exp))
}

fn cookie_header(token: &str, max_age: i64) -> String {
    format!("{COOKIE}={token}; Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite=Strict")
}

// ── CSRF 门(非 GET/HEAD/OPTIONS)───────────────────────────────────────────

/// 跨源即真:Sec-Fetch-Site 优先(现代浏览器必带),回落 Origin 比对;
/// 两者都缺 = 非浏览器客户端(curl / 插件 ssh 通道),放行。
fn is_cross_origin(state: &AppState, headers: &HeaderMap) -> bool {
    if let Some(v) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        return !(v == "same-origin" || v == "none");
    }
    if let Some(o) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        if let Ok(uri) = o.parse::<Uri>() {
            if let Some(host) = uri.host() {
                return host.to_lowercase() != state.config.web_hostname;
            }
        }
        return true; // 形如 Origin: null(沙箱 iframe)一律拒
    }
    false
}

// ── 路由 ───────────────────────────────────────────────────────────────────

pub fn build_web_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/_gateway/login", get(login_page).post(login_submit))
        .route("/_gateway/logout", get(logout).post(logout))
        // 登录是未鉴权可达的写入口:body 收紧(route_layer 只作用于已注册
        // 路由,不影响下面的中转 fallback —— 那边吃外层 160 MiB 大口子)。
        .route_layer(axum::extract::DefaultBodyLimit::max(BODY_LIMIT))
        .fallback(web_relay)
        .with_state(state)
}

/// 免鉴权静态 GET 白名单:浏览器 credentialless 怪癖(Chrome manifest 请求
/// 默认不携带 cookie,即便同源;favicon 同族)。均非敏感静态资源,放行无害。
const PUBLIC_GET_PATHS: &[&str] = &["/manifest.webmanifest", "/favicon.ico"];

/// 远程封禁区:宿主侧管理面(dsh-mobile 插件的 /pair/* —— 配对/令牌/Web 密码
/// 管理)。Host 改写给它们披上了 loopback 外衣,宿主围栏拦不住;web 面持有者
/// 若能触达 = 可配对新设备/改 Web 密码(击穿信任根),必须网关侧封死。
/// 本机(loopback 直连 dsh)不受影响。
const BLOCKED_PREFIXES: &[&str] = &["/pair"];

fn path_of(req: &Request) -> String {
    req.uri().path().to_string()
}

/// 登录页(网关自渲染,内联自足,无外部资产)。已登录则直接回首页。
async fn login_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if web_creds(&state).is_none() {
        return not_enabled();
    }
    if verify_session(&state, &headers).is_some() {
        return Redirect::to("/").into_response();
    }
    Html(login_html(None)).into_response()
}

#[derive(Deserialize)]
struct LoginForm {
    password: String,
    #[serde(default)]
    next: String,
}

/// 登录提交(HTML form POST):限速 + CSRF 门 + argon2 → cookie + 303 回跳。
async fn login_submit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let (hash, version) = match web_creds(&state) {
        Some(v) => v,
        None => return not_enabled(),
    };
    if is_cross_origin(&state, &headers) {
        return (StatusCode::FORBIDDEN, "cross-origin request rejected").into_response();
    }
    let ip = client_ip(&headers);
    if !state.login_limiter.allow(&format!("web:{ip}")) {
        // 429 而非 401,不给爆破者密码校验信号(与 App 登录同思路)。
        return (StatusCode::TOO_MANY_REQUESTS, Html(login_html(Some("尝试过于频繁,稍后再试"))))
            .into_response();
    }
    let parsed = match PasswordHash::new(&hash) {
        Ok(p) => p,
        Err(_) => return login_failed("服务端密码配置异常"),
    };
    if Argon2::default()
        .verify_password(form.password.as_bytes(), &parsed)
        .is_err()
    {
        tracing::warn!(ip = %ip, "web login failed");
        return login_failed("密码错误");
    }
    let (token, _) = match issue_session(&state, version) {
        Ok(v) => v,
        Err(_) => return login_failed("会话签发失败"),
    };
    tracing::info!(ip = %ip, "web login ok");
    let next = safe_next(&form.next);
    let mut resp = Redirect::to(&next).into_response();
    *resp.status_mut() = StatusCode::SEE_OTHER;
    if let Ok(hv) = axum::http::HeaderValue::from_str(&cookie_header(&token, SESSION_TTL)) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

fn login_failed(msg: &str) -> Response {
    (StatusCode::UNAUTHORIZED, Html(login_html(Some(msg)))).into_response()
}

fn not_enabled() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

/// 回跳目标白名单:站内绝对路径,拒绝 `//host`(协议相对)与外链。
fn safe_next(next: &str) -> String {
    if next.starts_with('/') && !next.starts_with("//") {
        next.to_string()
    } else {
        "/".to_string()
    }
}

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let _ = verify_session(&state, &headers);
    let mut resp = Redirect::to("/_gateway/login").into_response();
    *resp.status_mut() = StatusCode::SEE_OTHER;
    if let Ok(hv) = axum::http::HeaderValue::from_str(&format!(
        "{COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict"
    )) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

// ── 中转(cookie 门 → 复用 relay)───────────────────────────────────────────

/// web 面鉴权中转:cookie 校验(浏览器导航 302 登录页 / XHR 401)→ CSRF 门 →
/// 剥 cookie(会话凭证不进隧道)→ 剥 FACE_PREFIX → 交既有 relay 管道
/// (Host 改写 loopback / 剥 Authorization / UDS 优先 / WS 计数全部复用)。
async fn web_relay(
    State(state): State<Arc<AppState>>,
    mut req: Request,
) -> Response {
    // 管理面封禁优先于一切(含未登录流量):不探测、不放行,恒 403。
    let path = path_of(&req);
    if BLOCKED_PREFIXES.iter().any(|p| path == *p || path.starts_with(&format!("{p}/"))) {
        return (
            StatusCode::FORBIDDEN,
            "host management plane is not reachable through the web face",
        )
            .into_response();
    }
    if web_creds(&state).is_none() {
        return not_enabled();
    }
    // credentialless 静态 GET:无会话也放行(manifest/favicon,见白名单注释)。
    if *req.method() == axum::http::Method::GET && PUBLIC_GET_PATHS.contains(&path.as_str()) {
        req.headers_mut().remove(header::COOKIE);
        req.headers_mut().remove(header::AUTHORIZATION);
        let device = AuthedDevice {
            jti: "web-anon".into(),
            device: "web".into(),
            upstream_port: state.config.web_upstream_port,
        };
        return relay::relay_handler(State(state), device, req).await;
    }
    let session = match verify_session(&state, req.headers()) {
        Some(s) => s,
        None => return auth_challenge(&req),
    };
    let method_safe = req.method().is_safe() || matches!(*req.method(), axum::http::Method::OPTIONS);
    if !method_safe && is_cross_origin(&state, req.headers()) {
        return (StatusCode::FORBIDDEN, "cross-origin request rejected").into_response();
    }
    // 剥会话/凭证/浏览器来源头:cookie 到网关为止(与 App Bearer 令牌同款
    // 语义);Origin 描述的是「浏览器→网关」关系,而 dsh 围栏要求 Origin ==
    // 请求自身 Host(网关已改写为 loopback),带着必 403 —— 网关已在自己的
    // CSRF 门完成同源校验,转发放行即“网关发起的请求”(App 原生客户端无
    // Origin,同款语义)。Sec-Fetch-Site 同理不代传(cross-site 标记会让
    // 上游围栏误拒;same-origin 缺失无损 —— 围栏只拒绝显式 cross-site)。
    req.headers_mut().remove(header::COOKIE);
    req.headers_mut().remove(header::AUTHORIZATION);
    req.headers_mut().remove(header::ORIGIN);
    req.headers_mut().remove("sec-fetch-site");
    let device = AuthedDevice {
        jti: session.0,
        device: "web".into(),
        upstream_port: state.config.web_upstream_port,
    };
    let resp = relay::relay_handler(State(state.clone()), device, req).await;
    // 滑动续期:剩余 < 6h 顺手刷新(101 升级响应不碰)。
    let remaining = session.1 - chrono::Utc::now().timestamp();
    let mut resp = resp;
    if remaining < SESSION_REFRESH
        && resp.status() != StatusCode::SWITCHING_PROTOCOLS
        && remaining > 0
    {
        if let Some((_, version)) = web_creds(&state) {
            if let Ok((token, _)) = issue_session(&state, version) {
                if let Ok(hv) = axum::http::HeaderValue::from_str(&cookie_header(&token, SESSION_TTL)) {
                    resp.headers_mut().append(header::SET_COOKIE, hv);
                }
            }
        }
    }
    resp
}

/// 未认证响应:浏览器导航(带 text/html)→ 302 登录页(带 next);其余 401。
fn auth_challenge(req: &Request) -> Response {
    let is_nav = req
        .headers()
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("text/html"))
        .unwrap_or(false);
    if is_nav {
        let target = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".into());
        Redirect::to(&format!("/_gateway/login?next={}", urlencode(&target))).into_response()
    } else {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "web session required"}))).into_response()
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ── 登录页 HTML(内联自足)─────────────────────────────────────────────────

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn login_html(err: Option<&str>) -> String {
    format!(
        r#"<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>DSH 登录</title>
<style>
body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:#16181d;color:#e6e6e6;font:14px/1.5 system-ui,-apple-system,sans-serif}}
.card{{width:320px;padding:28px;background:#1e2128;border:1px solid #2c3039;border-radius:12px}}
h1{{margin:0 0 18px;font-size:16px;font-weight:600}}
input{{width:100%;box-sizing:border-box;padding:10px 12px;margin-bottom:12px;
background:#16181d;border:1px solid #2c3039;border-radius:8px;color:#e6e6e6;font-size:14px}}
input:focus{{outline:none;border-color:#7ab0ff}}
button{{width:100%;padding:10px;background:#7ab0ff;border:none;border-radius:8px;
color:#10131a;font-size:14px;font-weight:600;cursor:pointer}}
.err{{color:#ff7a7a;margin:-6px 0 12px;font-size:13px}}
.foot{{margin-top:16px;color:#7c8290;font-size:12px;text-align:center}}
</style></head><body><div class="card">
<h1>DSH Web 访问</h1>
{err}
<form method="post" action="/_gateway/login">
<input type="password" name="password" placeholder="访问密码" autofocus autocomplete="current-password">
<input type="hidden" name="next" value="">
<button type="submit">登录</button>
</form>
<div class="foot">DeepSeek Harness · 网关保护中</div>
</div></body></html>"#,
        err = err
            .map(|m| format!(r#"<div class="err">{}</div>"#, esc(m)))
            .unwrap_or_default(),
    )
}

// ── 管理面(仅 loopback + ssh;经 dsh-mobile 插件调用)──────────────────────

#[derive(Deserialize)]
pub struct WebPasswordRequest {
    /// 明文密码(经 ssh 通道来;网关侧 argon2 哈希落库)。与 hash 二选一。
    #[serde(default)]
    pub password: String,
    /// 已生成的 argon2 哈希(免服务器做哈希)。
    #[serde(default)]
    pub hash: String,
    /// true = 清除密码,关闭 web 面登录。
    #[serde(default)]
    pub clear: bool,
}

#[derive(Serialize)]
pub struct WebPasswordStatus {
    pub ok: bool,
    pub enabled: bool,
    /// db = 管理面写入;env = 环境变量兜底;null = 未启用。
    pub source: Option<&'static str>,
    pub version: Option<i64>,
}

pub async fn admin_web_password_get(
    State(state): State<Arc<AppState>>,
) -> AppResult<Json<WebPasswordStatus>> {
    let db = state.db.web_password();
    let (enabled, source, version) = match (&db, state.config.web_password_hash.is_empty()) {
        (Some((_, v)), _) => (true, Some("db"), Some(*v)),
        (None, false) => (true, Some("env"), Some(1)),
        (None, true) => (false, None, None),
    };
    Ok(Json(WebPasswordStatus { ok: true, enabled, source, version }))
}

pub async fn admin_web_password_post(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WebPasswordRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if req.clear {
        state
            .db
            .clear_web_password()
            .map_err(|e| AppError::Internal(anyhow::anyhow!("db clear: {e}")))?;
        tracing::info!("web password cleared (web face login disabled)");
        return Ok(Json(serde_json::json!({ "ok": true, "enabled": false })));
    }
    let hash = if !req.password.is_empty() {
        if req.password.len() > 256 {
            return Err(AppError::BadRequest("password too long".into()));
        }
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(req.password.as_bytes(), &salt)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("argon2: {e}")))?
            .to_string()
    } else if req.hash.starts_with("$argon2") && req.hash.len() <= 512 {
        req.hash
    } else {
        return Err(AppError::BadRequest(
            "provide `password` or a valid argon2 `hash`, or `clear: true`".into(),
        ));
    };
    let version = state
        .db
        .set_web_password(&hash)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("db set: {e}")))?;
    tracing::info!(version, "web password updated (old sessions invalidated)");
    Ok(Json(serde_json::json!({ "ok": true, "enabled": true, "version": version })))
}
