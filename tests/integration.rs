// 集成测试:登录 → 令牌 → 中转(HTTP Host 改写 / WS upgrade)→ 吊销。
// 全程本机回环:mock 上游 = 测试内 axum 应用(记录所见 Host;WS echo)。
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
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

const PASSWORD: &str = "test-password-123";
const UPSTREAM_HOST: &str = "127.0.0.1:3080";

struct TestEnv {
    gateway_port: u16,
    admin_port: u16,
    upstream_port: u16,
    #[allow(dead_code)]
    secret: String,
    seen_hosts: Arc<Mutex<Vec<String>>>,
}

async fn spawn_all() -> TestEnv {
    // ---- mock 上游:记录 Host;POST /api/echo 回显;GET /api/events.mux = WS echo ----
    let seen_hosts: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sh = seen_hosts.clone();
    let sh2 = seen_hosts.clone();
    let upstream = Router::new()
        .route(
            "/api/echo",
            post(move |headers: HeaderMap, body: String| async move {
                let host = headers
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("<none>")
                    .to_string();
                // 上游不该看到网关的 Bearer 令牌(relay 转发前剥除)。
                let auth_seen = headers.contains_key("authorization");
                sh.lock().unwrap().push(host.clone());
                Json(serde_json::json!({ "host": host, "auth_seen": auth_seen, "body": body }))
            }),
        )
        .route(
            "/api/events.mux",
            any(move |ws: WebSocketUpgrade, headers: HeaderMap| {
                async move {
                    let host = headers
                        .get("host")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("<none>")
                        .to_string();
                    sh2.lock().unwrap().push(host);
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
                }) }
            }),
        );

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(upstream_listener, upstream).await.unwrap();
    });

    // ---- 网关本体 ----
    let secret = format!("test-secret-{}", uuid::Uuid::new_v4());
    let hash = {
        use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
        let salt = SaltString::generate(&mut OsRng);
        argon2::Argon2::default()
            .hash_password(PASSWORD.as_bytes(), &salt)
            .unwrap()
            .to_string()
    };
    let config = Config {
        bind: "127.0.0.1".into(),
        port: 0,
        admin_port: 0,
        upstream_addr: format!("127.0.0.1:{upstream_port}"),
        upstream_host: UPSTREAM_HOST.into(),
        jwt_secret: secret.clone(),
        password_hash: hash,
        admin_token: String::new(),
        tunnel_sock_dir: None,
        token_ttl_days: 30,
        database_path: String::new(),
        tunnel_port_min: 1024,
        tunnel_port_max: 65535,
        web_hostname: String::new(),
        web_bind: "127.0.0.1".into(),
        web_port: 0,
        web_password_hash: String::new(),
        web_upstream_port: None,
    };
    let state = Arc::new(AppState {
        config: config.clone(),
        db: TokenDb::open_in_memory().unwrap(),
        login_limiter: LoginRateLimiter::new(),
        pair_limiter: LoginRateLimiter::new_pairing(),
        admin_limiter: LoginRateLimiter::new_limits(300, 300),
        ws_sessions: Default::default(),
    });
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

    TestEnv { gateway_port, admin_port, upstream_port, secret, seen_hosts }
}

fn gateway_url(env: &TestEnv, path: &str) -> String {
    format!("http://127.0.0.1:{}{path}", env.gateway_port)
}

async fn login(env: &TestEnv, password: &str) -> Result<String, StatusCode> {
    let client = reqwest::Client::new();
    let resp = client
        .post(gateway_url(env, "/auth/login"))
        .json(&serde_json::json!({ "password": password, "device": "pytest" }))
        .send()
        .await
        .unwrap();
    if !resp.status().is_success() {
        return Err(resp.status());
    }
    let body: serde_json::Value = resp.json().await.unwrap();
    Ok(body["token"].as_str().unwrap().to_string())
}

#[tokio::test]
async fn login_rejects_wrong_password() {
    let env = spawn_all().await;
    assert_eq!(login(&env, "wrong").await.unwrap_err(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn relay_requires_bearer_and_rewrites_host() {
    let env = spawn_all().await;
    let client = reqwest::Client::new();

    // 无令牌 → 401。
    let resp = client
        .post(gateway_url(&env, "/api/echo"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 登录 → 携带令牌中转。
    let token = login(&env, PASSWORD).await.unwrap();
    let resp = client
        .post(gateway_url(&env, "/api/echo"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body("{\"hello\":\"world\"}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    // Host 改写 = dsh 信任围栏所要求的 loopback authority。
    assert_eq!(body["host"].as_str().unwrap(), UPSTREAM_HOST);
    // 网关 Bearer 令牌不得透传到上游。
    assert_eq!(body["auth_seen"], false);
    assert_eq!(body["body"].as_str().unwrap(), "{\"hello\":\"world\"}");
}

#[tokio::test]
async fn revoked_token_is_rejected() {
    let env = spawn_all().await;
    let client = reqwest::Client::new();
    let token = login(&env, PASSWORD).await.unwrap();

    // 设备列表里有刚登录的令牌。
    let devices: serde_json::Value = client
        .get(gateway_url(&env, "/auth/devices"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let jti = devices[0]["jti"].as_str().unwrap().to_string();

    // 吊销后立即 401。
    let revoke = client
        .post(gateway_url(&env, "/auth/revoke"))
        .header("authorization", format!("Bearer {token}"))
        .json(&serde_json::json!({ "jti": jti }))
        .send()
        .await
        .unwrap();
    assert!(revoke.status().is_success());

    let resp = client
        .post(gateway_url(&env, "/api/echo"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn websocket_end_to_end_echo() {
    let env = spawn_all().await;
    let token = login(&env, PASSWORD).await.unwrap();

    // 手工构造带 Authorization 头的 WS 握手请求。
    let mut req = tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
        format!("ws://127.0.0.1:{}/api/events.mux", env.gateway_port).as_str(),
    )
    .unwrap();
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().unwrap(),
    );

    let (mut ws, resp) = tokio_tungstenite::connect_async(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);

    ws.send(Message::text("ping-through-gateway")).await.unwrap();
    let echoed = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
        .await
        .expect("timeout waiting echo")
        .unwrap()
        .unwrap();
    assert_eq!(echoed.into_text().unwrap(), "ping-through-gateway");

    // 上游看到的 Host 必须被改写为 loopback authority。
    let hosts = env.seen_hosts.lock().unwrap().clone();
    assert!(hosts.iter().any(|h| h == UPSTREAM_HOST), "hosts: {hosts:?}");
}

#[tokio::test]
async fn healthz_reports_upstream() {
    let env = spawn_all().await;
    let client = reqwest::Client::new();
    let body: serde_json::Value = client
        .get(gateway_url(&env, "/healthz"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["upstream"], true);

    // 指向不存在的上游 → upstream:false。
    let secret = format!("s-{}", uuid::Uuid::new_v4());
    let hash = {
        use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
        let salt = SaltString::generate(&mut OsRng);
        argon2::Argon2::default()
            .hash_password(PASSWORD.as_bytes(), &salt)
            .unwrap()
            .to_string()
    };
    let config = Config {
        bind: "127.0.0.1".into(),
        port: 0,
        admin_port: 0,
        upstream_addr: "127.0.0.1:1".into(),
        upstream_host: UPSTREAM_HOST.into(),
        jwt_secret: secret,
        password_hash: hash,
        admin_token: String::new(),
        tunnel_sock_dir: None,
        token_ttl_days: 30,
        database_path: String::new(),
        tunnel_port_min: 1024,
        tunnel_port_max: 65535,
        web_hostname: String::new(),
        web_bind: "127.0.0.1".into(),
        web_port: 0,
        web_password_hash: String::new(),
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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, build_public_router(state)).await.unwrap();
    });
    let body: serde_json::Value = client
        .get(format!("http://127.0.0.1:{port}/healthz"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["upstream"], false);
}

#[tokio::test]
async fn login_rate_limited_after_burst() {
    let env = spawn_all().await;
    // 8 次错误密码(默认上限)后第 9 次即使是正确密码也 409。
    for _ in 0..8 {
        let _ = login(&env, "wrong").await;
    }
    let client = reqwest::Client::new();
    let resp = client
        .post(gateway_url(&env, "/auth/login"))
        .json(&serde_json::json!({ "password": PASSWORD }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

/// 公开面(未鉴权路由)body 上限收紧到 64KiB,中转面仍按 160MiB 放行 ——
/// 钉死「内层 limit 覆盖合并层」的分层语义。
#[tokio::test]
async fn public_routes_body_limit_small_relay_stays_large() {
    let env = spawn_all().await;
    let client = reqwest::Client::new();
    let big = "a".repeat(100 * 1024);

    // 未鉴权公开路由:>64KiB → 413。
    let resp = client
        .post(gateway_url(&env, "/pair/poll"))
        .header("content-type", "application/json")
        .body(big.as_bytes().to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // 中转 fallback:100KiB 远小于 160MiB → 正常到达上游。
    let token = login(&env, PASSWORD).await.unwrap();
    let resp = client
        .post(gateway_url(&env, "/api/echo"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(big.into_bytes())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// 网关不再挂 CORS 层:任何 Origin 都得不到 Access-Control-Allow-Origin。
#[tokio::test]
async fn no_cors_allow_origin_header() {
    let env = spawn_all().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(gateway_url(&env, "/healthz"))
        .header("origin", "https://evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("access-control-allow-origin").is_none());
}

// ── WS 在线计数(第三十八轮侧栏在线指示器的服务端数据源)───────────────────

async fn admin_tokens(env: &TestEnv) -> Vec<serde_json::Value> {
    let client = reqwest::Client::new();
    client
        .get(format!("http://127.0.0.1:{}/admin/pair/tokens", env.admin_port))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// 轮询等 connected 到达期望值(断开归零是异步的)。
async fn wait_connected(env: &TestEnv, jti: &str, want: bool) -> bool {
    for _ in 0..50 {
        if admin_tokens(env)
            .await
            .iter()
            .any(|t| t["jti"] == jti && t["connected"] == want)
        {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    false
}

/// 下行 WS 建立 → admin/pair/tokens 该令牌 connected=true;
/// 断开 → 异步归零 false。
#[tokio::test]
async fn ws_presence_marks_token_connected() {
    let env = spawn_all().await;
    let client = reqwest::Client::new();
    let token = login(&env, PASSWORD).await.unwrap();
    let devices: serde_json::Value = client
        .get(gateway_url(&env, "/auth/devices"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let jti = devices[0]["jti"].as_str().unwrap().to_string();

    // 尚无 WS → 不在线。
    assert!(wait_connected(&env, &jti, false).await);

    // 建立下行 WS(带 Bearer 过鉴权中转)→ 在线。
    let mut req = tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
        format!("ws://127.0.0.1:{}/api/events.mux", env.gateway_port).as_str(),
    )
    .unwrap();
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().unwrap(),
    );
    let (mut ws, resp) = tokio_tungstenite::connect_async(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
    assert!(wait_connected(&env, &jti, true).await, "ws 建立后应在线");

    // 断开 → 异步归零。
    let _ = ws.close(None).await;
    drop(ws);
    assert!(wait_connected(&env, &jti, false).await, "ws 断开后应离线");
}

// 管理面 bearer 校验:DSH_GATEWAY_ADMIN_TOKEN 配置后,无/错 token 一律 401,
// 正确 token 放行(同机任意进程防线;空值 = 放行由其余既有测试覆盖)。
#[tokio::test]
async fn admin_routes_require_bearer_token_when_configured() {
    let config = Config {
        bind: "127.0.0.1".into(),
        port: 0,
        admin_port: 0,
        upstream_addr: "127.0.0.1:1".into(),
        upstream_host: UPSTREAM_HOST.into(),
        jwt_secret: "s".into(),
        password_hash: String::new(),
        admin_token: "sekrit-admin-token".into(),
        tunnel_sock_dir: None,
        token_ttl_days: 30,
        database_path: String::new(),
        tunnel_port_min: 1024,
        tunnel_port_max: 65535,
        web_hostname: String::new(),
        web_bind: "127.0.0.1".into(),
        web_port: 0,
        web_password_hash: String::new(),
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
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let st = state.clone();
    tokio::spawn(async move { axum::serve(l, build_admin_router(st)).await.unwrap(); });

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/admin/pair/tokens");
    // 无 token / 错 token → 401(两者不可区分)。
    assert_eq!(
        client.get(&url).send().await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        client
            .get(&url)
            .header("authorization", "Bearer wrong")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // 正确 token → 200(清单为空数组也算成功)。
    let resp = client
        .get(&url)
        .header("authorization", "Bearer sekrit-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
