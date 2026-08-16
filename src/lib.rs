// dsh-gateway 库面:模块、AppState 与路由组装(测试与二进制共用)。
//
// 两个监听面:
// - 公开面(build_public_router,nginx 反代):配对三接口 + 密码兜底登录 +
//   健康探测 + 鉴权后全量中转/设备管理;
// - 管理面(build_admin_router,仅绑 127.0.0.1):pair.sh 经 ssh 调用的
//   claim/status/revoke —— 公网路径根本到不了。
pub mod auth;
pub mod config;
pub mod db;
pub mod pair;
pub mod relay;

use std::sync::Arc;

use axum::{
    extract::DefaultBodyLimit,
    middleware,
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
    pub http: reqwest::Client,
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

/// 上游恒为 loopback(本机隧道口),永远直连 —— 显式忽略 http_proxy 等环境变量,
/// 否则本机代理(如 Clash)会接管并拒绝转发 loopback 流量。
pub fn direct_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(std::time::Duration::from_secs(5))
        .pool_idle_timeout(std::time::Duration::from_secs(90))
        .build()
        .expect("reqwest client")
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
pub fn build_admin_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/admin/pair/claim", post(pair::admin_claim_handler))
        .route("/admin/pair/status", get(pair::admin_status_handler))
        .route("/admin/pair/revoke-token", post(pair::admin_revoke_token_handler))
        .route("/admin/pair/tokens", get(pair::admin_tokens_handler))
        .route("/admin/pair/qr", post(pair::admin_qr_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
