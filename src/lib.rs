// dsh-gateway 库面:模块、AppState 与路由组装(测试与二进制共用)。
//
// 监听面:
// - 公开面(build_public_router,nginx 反代):配对三接口 + 密码兜底登录 +
//   健康探测 + 鉴权后全量中转/设备管理 + 租户管理端点(/admin/*,按钥
//   解析租户 —— 未登记租户的部署恒 401,行为与 004 之前完全一致);
// - 管理面(build_admin_router,仅绑 127.0.0.1):pair.sh 经 ssh 调用的
//   claim/status/revoke(运营者超管 ctx,可跨租户)+ 租户/宿主登记;
//   DSH_GATEWAY_ADMIN_TOKEN 非空时再加一道 bearer 校验(管理面虽绑
//   loopback,同机任意进程都能连)。
pub mod auth;
pub mod config;
pub mod db;
pub mod pair;
pub mod relay;
pub mod tenant;
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
use tenant::{TenantCtx, DEFAULT_TENANT};

pub struct AppState {
    pub config: Config,
    pub db: TokenDb,
    pub login_limiter: LoginRateLimiter,
    /// 配对面限速(与登录独立计数)。
    pub pair_limiter: LoginRateLimiter,
    /// 公开面租户 admin 限速(宽窗口:插件配对期 3s 轮 status 属合法流量;
    /// 上限压密钥爆破)。
    pub admin_limiter: LoginRateLimiter,
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
/// 一律 401(不区分两种情形,不给探测面)。通过后注入运营者超管 ctx。
async fn admin_auth_middleware(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    mut req: Request,
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
    req.extensions_mut()
        .insert(TenantCtx { id: DEFAULT_TENANT.to_string(), operator: true });
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

    // 租户管理面(公开,按钥):与 8103 同一组 handler,租户 ctx 由
    // tenant_auth_middleware 注入 —— 全部围栏在本租户。未登记租户的
    // 部署这里恒 401,零新增暴露。
    let tenant_admin_routes = Router::new()
        .route("/admin/pair/claim", post(pair::admin_claim_handler))
        .route("/admin/pair/status", get(pair::admin_status_handler))
        .route("/admin/pair/revoke-token", post(pair::admin_revoke_token_handler))
        .route("/admin/pair/tokens", get(pair::admin_tokens_handler))
        .route("/admin/pair/qr", post(pair::admin_qr_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            tenant::tenant_auth_middleware,
        ));

    // 鉴权面:设备管理 + 全量中转(fallback)。
    let protected_routes = Router::new()
        .route("/auth/devices", get(auth::devices_handler))
        .route("/auth/revoke", post(auth::revoke_handler))
        .fallback(relay::relay_handler)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ));

    // 公开面 body 收紧:配对/登录/租户管理载荷只有几 KB,未鉴权可达的
    // 接口不得与中转共享 160 MiB 大口子(Json 提取器会全量缓冲进内存)。
    // 同类型 limit 扩展以内层为准 —— 覆盖语义有 integration 测试钉死。
    let public_routes = public_routes
        .merge(tenant_admin_routes)
        .layer(DefaultBodyLimit::max(64 * 1024));

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
/// 运营者超管 ctx 可跨租户;租户/宿主登记只在管理面(信任根 = 服务器 ssh)。
pub fn build_admin_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/admin/pair/claim", post(pair::admin_claim_handler))
        .route("/admin/pair/status", get(pair::admin_status_handler))
        .route("/admin/pair/revoke-token", post(pair::admin_revoke_token_handler))
        .route("/admin/pair/tokens", get(pair::admin_tokens_handler))
        .route("/admin/pair/qr", post(pair::admin_qr_handler))
        .route(
            "/admin/web/password",
            get(web::admin_web_password_get).post(web::admin_web_password_post),
        )
        // 多租户登记(004):租户与宿主只由运营者(ssh/env token)管理。
        .route(
            "/admin/tenants",
            post(tenant::tenant_create_handler).get(tenant::tenant_list_handler),
        )
        .route("/admin/tenants/revoke", post(tenant::tenant_revoke_handler))
        .route(
            "/admin/hosts",
            post(tenant::host_create_handler).get(tenant::host_list_handler),
        )
        .route("/admin/hosts/remove", post(tenant::host_remove_handler))
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
