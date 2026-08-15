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
                sh.lock().unwrap().push(host.clone());
                Json(serde_json::json!({ "host": host, "body": body }))
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
        port: 0,
        admin_port: 0,
        upstream_addr: format!("127.0.0.1:{upstream_port}"),
        upstream_host: UPSTREAM_HOST.into(),
        jwt_secret: secret.clone(),
        password_hash: hash,
        token_ttl_days: 30,
        database_path: String::new(),
        tunnel_port_min: 1024,
        tunnel_port_max: 65535,
    };
    let state = Arc::new(AppState {
        config: config.clone(),
        db: TokenDb::open_in_memory().unwrap(),
        login_limiter: LoginRateLimiter::new(),
        pair_limiter: LoginRateLimiter::new_pairing(),
        http: dsh_mobile_gateway::direct_client(),
    });
    let gateway_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_port = gateway_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(gateway_listener, build_public_router(state)).await.unwrap();
    });

    TestEnv { gateway_port, upstream_port, secret, seen_hosts }
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
        port: 0,
        admin_port: 0,
        upstream_addr: "127.0.0.1:1".into(),
        upstream_host: UPSTREAM_HOST.into(),
        jwt_secret: secret,
        password_hash: hash,
        token_ttl_days: 30,
        database_path: String::new(),
        tunnel_port_min: 1024,
        tunnel_port_max: 65535,
    };
    let state = Arc::new(AppState {
        config,
        db: TokenDb::open_in_memory().unwrap(),
        login_limiter: LoginRateLimiter::new(),
        pair_limiter: LoginRateLimiter::new_pairing(),
        http: dsh_mobile_gateway::direct_client(),
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
