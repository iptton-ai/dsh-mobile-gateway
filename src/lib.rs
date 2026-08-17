// dsh-gateway 库面:模块、AppState 与路由组装(测试与二进制共用)。
//
// 两个监听面:
// - 公开面(build_public_router,nginx 反代):配对三接口 + 密码兜底登录 +
//   健康探测 + 鉴权后全量中转/设备管理;
// - 管理面(build_admin_router,仅绑 127.0.0.1):pair.sh 经 ssh 调用的
//   claim/status/revoke —— 公网路径根本到不了;DSH_GATEWAY_ADMIN_TOKEN
//   非空时再加一道 bearer 校验(管理面虽绑 loopback,同机任意进程都能连)。
pub mod auth;
pub mod config;
pub mod db;
pub mod pair;
pub mod relay;
pub mod web;

use std::sync::Arc;

use axum::{
    extract::{DefaultBodyLimit, Request},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use tower_http::trace::TraceLayer;

use auth::LoginRateLimiter;
use config::Config;
use db::TokenDb;

pub struct AppState {
    pub config: Config,
    pub db: TokenDb,
    pub login_limiter: LoginRateLimiter,
    /// 配对面限速(与登录独立计数)。
    pub pair_limiter: LoginRateLimiter,
    /// 在线计数:jti → 当前持有的下行 WS 条数。RAII 增减见 relay.rs;
    /// admin/pair/tokens 的 `connected` 字段以此为准(App 前台在线/
    /// 后台挂起离线)。
    pub ws_sessions: std::sync::Mutex<std::collections::HashMap<String, u32>>,
}

impl AppState {
    /// 当前在线(持有 ≥1 条下行 WS)的令牌 jti 集合。
    pub fn ws_online(&self) -> Vec<String> {
        self.ws_sessions
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, &n)| n > 0)
            .map(|(k, _)| k.clone())
            .collect()
    }
}

/// 上游恒为 loopback(本机隧道口 TCP 或 Unix socket),relay 自行拨号直连,
/// 不经任何 HTTP 代理(环境变量 http_proxy 等天然无效)。

/// 管理面 bearer 校验:token 未配置 = 放行(本地联调);配置后缺失/错误
/// 一律 401(不区分两种情形,不给探测面)。
async fn admin_auth_middleware(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let expected = state.config.admin_token.clone();
    if !expected.is_empty() {
        let ok = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|got| constant_time_eq(got.as_bytes(), expected.as_bytes()))
            .unwrap_or(false);
        if !ok {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({"error": "admin token required"})),
            )
                .into_response();
        }
    }
    next.run(req).await
}

/// 常数时间比较(长度差异也走满循环,不提前泄长度)。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 公开面(nginx 反代到 :port)。
pub fn build_public_router(state: Arc<AppState>) -> Router {
    // 完全公开:配对三接口 + 扫码落地页 + 密码兜底登录 + 健康探测。
    let public_routes = Router::new()
        .route("/pair/start", post(pair::start_handler))
        .route("/pair/poll", post(pair::poll_handler))
        .route("/pair/confirm", post(pair::confirm_handler))
        .route("/pair", get(pair::pair_page_handler))
        .route("/auth/login", post(auth::login_handler))
        .route("/healthz", get(relay::healthz));

    // 鉴权面:设备管理 + 全量中转(fallback)。
    let protected_routes = Router::new()
        .route("/auth/devices", get(auth::devices_handler))
        .route("/auth/revoke", post(auth::revoke_handler))
        .fallback(relay::relay_handler)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ));

    // 公开面 body 收紧:配对/登录载荷只有几 KB,未鉴权可达的接口不得
    // 与中转共享 160 MiB 大口子(Json 提取器会全量缓冲进内存)。
    // 同类型 limit 扩展以内层为准 —— 覆盖语义有 integration 测试钉死。
    let public_routes = public_routes.layer(DefaultBodyLimit::max(64 * 1024));

    public_routes
        .merge(protected_routes)
        // 中转请求体上限对齐 dsh 默认(160 MiB,为聚合图片 base64 留余量)。
        .layer(DefaultBodyLimit::max(160 * 1024 * 1024))
        .layer(TraceLayer::new_for_http())
        // 无 CORS 层:原生 App 不发 Origin,浏览器同源(/pair 落地页)也不
        // 需要;显式放行 any-origin + any-headers 是给未来 web 客户端埋雷。
        .with_state(state)
}

/// 管理面(仅绑 127.0.0.1:admin_port;pair.sh 经 `ssh host curl` 调用)。
/// DSH_GATEWAY_ADMIN_TOKEN 非空时全路由要求 bearer(同机进程防线)。
pub fn build_admin_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/admin/pair/claim", post(pair::admin_claim_handler))
        .route("/admin/pair/status", get(pair::admin_status_handler))
        .route("/admin/pair/revoke-token", post(pair::admin_revoke_token_handler))
        .route("/admin/pair/tokens", get(pair::admin_tokens_handler))
        .route("/admin/pair/qr", post(pair::admin_qr_handler))
        // Web 面密码管理(明文/hashing 经 ssh 通道来;dsh-mobile 插件调用)。
        .route(
            "/admin/web/password",
            get(web::admin_web_password_get).post(web::admin_web_password_post),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admin_auth_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Web 面(独立监听 web_bind:web_port;nginx 按 server_name 分流到此)。
/// 登录页 + cookie 会话 + 复用 relay 中转;密码未配置时全路由 404(fail-closed)。
pub fn build_web_router(state: Arc<AppState>) -> Router {
    web::build_web_router(state)
}
