// Web 面集成测试:Host 分流 + 登录页 + cookie 会话 + CSRF 门 + 中转
// (Host 改写 / cookie 不进上游 / WS)+ 管理面密码轮换。
//
// 全程本机回环:mock 上游 = 测试内 axum 应用(记录 Host/Cookie;WS echo)。
// Web 面在独立端口(与生产同构:nginx 按 server_name 分流到 web_port)。
use axum::{
    extract::WebSocketUpgrade,
    http::{HeaderMap, StatusCode},
    routing::{any, post},
    Json, Router,
};
use dsh_mobile_gateway::{
    auth::LoginRateLimiter,
    build_admin_router,
    build_public_router,
    config::Config,
    db::TokenDb,
    AppState,
};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

const WEB_HOST: &str = "web.example.test";
const PASSWORD: &str = "web-password-123";
const UPSTREAM_HOST: &str = "127.0.0.1:3080";

struct TestEnv {
    gateway_port: u16,
    web_port: u16,
    admin_port: u16,
    #[allow(dead_code)]
    upstream_port: u16,
}

/// 生成 argon2 哈希(与网关 --hash-password 同参数族)。
fn argon_hash(password: &str) -> String {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    let salt = SaltString::generate(&mut OsRng);
    argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

/// password_hash 为空串 = web 面关闭态(DB 无行 + env 兜底为空)。
async fn spawn_env(web_hostname: &str, password_hash: &str) -> TestEnv {
    // mock 上游:POST /api/echo 回显所见 Host/Cookie;GET /api/events.mux = WS echo;
    // GET /static/logo.png = 模拟静态资源。
    let upstream = Router::new()
        .route(
            "/api/echo",
            post(|headers: HeaderMap, body: String| async move {
                let host = headers
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("<none>")
                    .to_string();
                Json(serde_json::json!({
                    "host": host,
                    "auth_seen": headers.contains_key("authorization"),
                    "cookie_seen": headers.contains_key("cookie"),
                    "origin_seen": headers.contains_key("origin"),
                    "body": body,
                }))
            }),
        )
        .route(
            "/manifest.webmanifest",
            any(|| async { ([("content-type", "application/manifest+json")], "{}") }),
        )
        .route(
            "/static/logo.png",
            any(|| async { ([("content-type", "image/png")], b"fake-png-bytes") }),
        )
        .route(
            "/api/events.mux",
            any(|ws: WebSocketUpgrade| async move {
                ws.on_upgrade(|socket| async move {
                    let (mut sink, mut stream) = socket.split();
                    while let Some(Ok(msg)) = stream.next().await {
                        match msg {
                            axum::extract::ws::Message::Text(t) => {
                                sink.send(axum::extract::ws::Message::Text(t)).await.unwrap();
                            }
                            axum::extract::ws::Message::Binary(b) => {
                                sink.send(axum::extract::ws::Message::Binary(b)).await.unwrap();
                            }
                            _ => {}
                        }
                    }
                })
            }),
        );

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(upstream_listener, upstream).await.unwrap();
    });

    let hash = password_hash.to_string();

    let config = Config {
        bind: "127.0.0.1".into(),
        port: 0,
        admin_port: 0,
        upstream_addr: format!("127.0.0.1:{upstream_port}"),
        upstream_host: UPSTREAM_HOST.into(),
        jwt_secret: format!("test-secret-{}", uuid::Uuid::new_v4()),
        password_hash: hash.clone(),
        admin_token: String::new(),
        tunnel_sock_dir: None,
        token_ttl_days: 30,
        database_path: String::new(),
        tunnel_port_min: 1024,
        tunnel_port_max: 65535,
        web_hostname: web_hostname.into(),
        web_bind: "127.0.0.1".into(),
        web_port: 0,
        // env 兜底路径:web 密码与 App 兜底同 hash(测试简化;生产建议分设)。
        web_password_hash: hash,
        web_upstream_port: None,
    };
    let state = Arc::new(AppState {
        config,
        db: TokenDb::open_in_memory().unwrap(),
        login_limiter: LoginRateLimiter::new(),
        pair_limiter: LoginRateLimiter::new_pairing(),
        admin_limiter: LoginRateLimiter::new_limits(300, 300),
        ws_sessions: Default::default(),
    });
    let state_for_web = state.clone();
    let gateway_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_port = gateway_listener.local_addr().unwrap().port();
    let pub_state = state.clone();
    tokio::spawn(async move {
        axum::serve(gateway_listener, build_public_router(pub_state)).await.unwrap();
    });
    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_port = admin_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(admin_listener, build_admin_router(state)).await.unwrap();
    });
    let web_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let web_port = web_listener.local_addr().unwrap().port();
    let web_state = state_for_web;
    tokio::spawn(async move {
        axum::serve(web_listener, dsh_mobile_gateway::build_web_router(web_state)).await.unwrap();
    });

    TestEnv { gateway_port, web_port, admin_port, upstream_port }
}

/// 直连客户端:本机 http_proxy 会把「Host 覆盖过的请求」当远程域名转发
/// (502 空响应),测试一律绕过系统代理。
fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        // 禁跟随重定向:303/302 断言要看第一跳,Set-Cookie 也在第一跳上。
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

/// 公开面(App API)地址。
fn gateway_url(env: &TestEnv, path: &str) -> String {
    format!("http://127.0.0.1:{}{path}", env.gateway_port)
}

/// Web 面直连地址(独立端口,同构生产 nginx→web_port)。
fn web_url(env: &TestEnv, path: &str) -> String {
    format!("http://127.0.0.1:{}{path}", env.web_port)
}

/// 表单登录(带同源 Origin,模拟浏览器)。成功返回 Set-Cookie 原始值。
async fn login(env: &TestEnv, password: &str) -> Result<Option<String>, StatusCode> {
    let client = http_client();
    let resp = client
        .post(web_url(env, "/_gateway/login"))
        .header("origin", format!("https://{WEB_HOST}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("password={}&next=/", urlencode(password)))
        .send()
        .await
        .unwrap();
    if !resp.status().is_success() && resp.status() != StatusCode::SEE_OTHER {
        return Err(resp.status());
    }
    Ok(resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string()))
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn cookie_only(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap_or("").to_string()
}

// ── 测试 ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn host_not_matching_goes_to_app_api() {
    // 公开面(8102 同构端口)完全不知晓 web 面:中转仍要求 Bearer。
    let env = spawn_env(WEB_HOST, &argon_hash(PASSWORD)).await;
    let client = http_client();
    let resp = client
        .post(gateway_url(&env, "/api/echo"))
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn disabled_when_no_password() {
    // 配了 hostname 但无密码(DB 无行 + env 兜底空):一切路径 404,fail-closed。
    let env = spawn_env(WEB_HOST, "").await;
    let client = http_client();
    let resp = client
        .get(web_url(&env, "/_gateway/login"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = client
        .get(web_url(&env, "/"))
        .header("accept", "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn login_flow_and_relay() {
    let env = spawn_env(WEB_HOST, &argon_hash(PASSWORD)).await;
    let client = http_client();

    // 1. 未登录:导航请求 302 → 登录页。
    let resp = client
        .get(web_url(&env, "/"))
        .header("accept", "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(resp.headers()["location"].to_str().unwrap().contains("/_gateway/login"));

    // 2. XHR(非 text/html)未登录 → 401 JSON。
    let resp = client
        .get(web_url(&env, "/api/echo"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 3. 登录页可渲染。
    let resp = client
        .get(web_url(&env, "/_gateway/login"))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    assert!(resp.text().await.unwrap().contains("DSH"));

    // 4. 错误密码 → 401。
    assert!(login(&env, "wrong").await.is_err());

    // 5. 正确密码 → 303 + Set-Cookie。
    let cookie = login(&env, PASSWORD).await.unwrap().expect("set-cookie missing");
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Strict"));

    // 6. 带 cookie 中转:Host 改写 + 凭证与 Origin 均不进上游
    //    (dsh 围栏要求 Origin == 自身 Host,带着必 403;网关代传会话已自校)。
    let resp = client
        .post(web_url(&env, "/api/echo"))
        .header("cookie", cookie_only(&cookie))
        .header("origin", format!("https://{WEB_HOST}"))
        .header("sec-fetch-site", "same-origin")
        .body("hello")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["host"], UPSTREAM_HOST);
    assert_eq!(body["auth_seen"], false);
    assert_eq!(body["cookie_seen"], false);
    assert_eq!(body["origin_seen"], false);
    assert_eq!(body["body"], "hello");

    // 7. 静态资源同样带 cookie 畅通。
    let resp = client
        .get(web_url(&env, "/static/logo.png"))
        .header("cookie", cookie_only(&cookie))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 8. 登出 → cookie 清除。
    let resp = client
        .get(web_url(&env, "/_gateway/logout"))
        .header("cookie", cookie_only(&cookie))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn csrf_gate_rejects_cross_site() {
    let env = spawn_env(WEB_HOST, &argon_hash(PASSWORD)).await;
    let client = http_client();

    // 登录提交:Sec-Fetch-Site: cross-site → 403。
    let resp = client
        .post(web_url(&env, "/_gateway/login"))
        .header("sec-fetch-site", "cross-site")
        .header("content-type", "application/x-www-form-urlencoded")
        .body("password=x")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 中转写操作:Origin 不匹配 → 403(先伪造一个有效 cookie 再打)。
    let cookie = login(&env, PASSWORD).await.unwrap().unwrap();
    let resp = client
        .post(web_url(&env, "/api/echo"))
        .header("cookie", cookie_only(&cookie))
        .header("origin", "https://evil.example")
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_rotation_invalidates_sessions() {
    let env = spawn_env(WEB_HOST, &argon_hash(PASSWORD)).await;
    let client = http_client();

    let cookie = login(&env, PASSWORD).await.unwrap().unwrap();
    let resp = client
        .post(web_url(&env, "/api/echo"))
        .header("cookie", cookie_only(&cookie))
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 管理面轮换密码(明文经 ssh 通道来,网关侧 argon2)。
    let admin = http_client();
    let resp = admin
        .post(format!("http://127.0.0.1:{}/admin/web/password", env.admin_port))
        .json(&serde_json::json!({ "password": "new-password-456" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["enabled"], true);
    // env 兜底时代 version=0;首次 DB 写入 version=1 即应令旧会话失效。
    assert_eq!(body["version"].as_i64().unwrap(), 1);

    // 旧 cookie 失效;新密码可登录。
    let resp = client
        .post(web_url(&env, "/api/echo"))
        .header("cookie", cookie_only(&cookie))
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(login(&env, "new-password-456").await.is_ok());

    // 状态查询 + 清除 = 关闭。
    let resp = admin
        .get(format!("http://127.0.0.1:{}/admin/web/password", env.admin_port))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["enabled"], true);
    assert_eq!(body["source"], "db");

    let resp = admin
        .post(format!("http://127.0.0.1:{}/admin/web/password", env.admin_port))
        .json(&serde_json::json!({ "clear": true }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // 清除后回落 env 兜底(DB 优先、env 兜底):本测试 env 配了 hash,
    // 登录页仍可用;生产未配 env 时清除 = 整面关闭(disabled 测试已覆盖)。
    let resp = admin
        .get(format!("http://127.0.0.1:{}/admin/web/password", env.admin_port))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["enabled"], true);
    assert_eq!(body["source"], "env");
}

#[tokio::test]
async fn websocket_with_cookie() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let env = spawn_env(WEB_HOST, &argon_hash(PASSWORD)).await;
    let cookie = login(&env, PASSWORD).await.unwrap().unwrap();

    let mut req = format!("ws://127.0.0.1:{}/api/events.mux", env.web_port)
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("cookie", cookie_only(&cookie).parse().unwrap());

    let (mut ws, _resp) = tokio_tungstenite::connect_async(req).await.unwrap();
    ws.send(Message::Text("ping-web".into())).await.unwrap();
    let msg = ws.next().await.unwrap().unwrap();
    assert_eq!(msg.into_text().unwrap(), "ping-web");
}

#[tokio::test]
async fn app_api_unaffected_by_web_face() {
    // web 面开着,普通 App API(无 web Host)原样工作:登录接口 404 路径不变、
    // /auth/login 仍走 App 形态。
    let env = spawn_env(WEB_HOST, &argon_hash(PASSWORD)).await;
    let client = http_client();
    let resp = client
        .post(gateway_url(&env, "/auth/login"))
        .json(&serde_json::json!({ "password": PASSWORD, "device": "t" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["token"].as_str().is_some());
}

#[tokio::test]
async fn management_plane_blocked() {
    // 宿主管理面(/pair/*:配对/令牌/Web 密码)不得经 web 面触达 —— 未登录、
    // 已登录一律 403(Host 改写会骗过宿主 loopback 围栏,必须网关封)。
    let env = spawn_env(WEB_HOST, &argon_hash(PASSWORD)).await;
    let client = http_client();
    for (method, path) in [
        ("GET", "/pair/api/tokens"),
        ("POST", "/pair/api/web-password"),
        ("GET", "/pair/api/label"),
        ("POST", "/pair/api/revoke"),
        ("GET", "/pair"),
    ] {
        let resp = client
            .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), web_url(&env, path))
            .header("cookie", "dshweb=whatever")
            .body("x")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{method} {path}");
    }
}

#[tokio::test]
async fn manifest_fetched_without_cookie() {
    // Chrome 怪癖:manifest 请求默认不带 cookie —— 免鉴权放行该静态 GET,
    // 否则已登录页面的 PWA manifest 也 401 刷屏。
    let env = spawn_env(WEB_HOST, &argon_hash(PASSWORD)).await;
    let client = http_client();
    let resp = client.get(web_url(&env, "/manifest.webmanifest")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // 白名单之外的无 cookie GET 不放行。
    let resp = client.get(web_url(&env, "/static/logo.png")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
