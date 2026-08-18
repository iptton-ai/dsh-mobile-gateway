// 配对协议集成测试(M6.1):抢注 409 / 亮码 claim / 手机端多 offer 人工比对 /
// 主机码不匹配拒绝 / 令牌绑定隧道端口(多机路由)/ 密码未配置禁用。
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
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

const PASSWORD: &str = "test-password-123";
const UPSTREAM_HOST: &str = "127.0.0.1:3080";

struct PairEnv {
    pub_port: u16,
    admin_port: u16,
    upstream_ports: Vec<u16>,
    #[allow(dead_code)]
    password_hash: String,
}

/// 起 1 公开面 + 1 管理面 + N 个 mock 上游(每个记 Host)。
async fn spawn_env(upstreams: usize, with_password: bool) -> PairEnv {
    let mut upstream_ports = Vec::new();
    let hosts_log: Arc<Mutex<Vec<(u16, String)>>> = Arc::new(Mutex::new(Vec::new()));
    for i in 0..upstreams {
        let hl = hosts_log.clone();
        let app: Router = Router::new().route(
            "/api/echo",
            post(move |headers: HeaderMap| async move {
                let host = headers
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("<none>")
                    .to_string();
                // 通过自定义头回传上游自己的编号,断言路由用。
                let tag = format!("up-{i}");
                hl.lock().unwrap().push((i as u16, host.clone()));
                Json(serde_json::json!({ "host": host, "upstream": tag }))
            }),
        );
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        upstream_ports.push(p);
        tokio::spawn(async move { axum::serve(l, app).await.unwrap(); });
    }
    let _ws_app: Router = Router::new().route(
        "/api/events.mux",
        any(|ws: WebSocketUpgrade| async move { ws.on_upgrade(|s| async move { let _ = s; }) }),
    );

    let hash = if with_password {
        use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
        let salt = SaltString::generate(&mut OsRng);
        argon2::Argon2::default()
            .hash_password(PASSWORD.as_bytes(), &salt)
            .unwrap()
            .to_string()
    } else {
        String::new()
    };
    let config = Config {
        bind: "127.0.0.1".into(),
        port: 0,
        admin_port: 0,
        upstream_addr: format!("127.0.0.1:{}", upstream_ports[0]),
        upstream_host: UPSTREAM_HOST.into(),
        jwt_secret: "pair-test-secret".into(),
        password_hash: hash.clone(),
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
    let pl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pub_port = pl.local_addr().unwrap().port();
    let st = state.clone();
    tokio::spawn(async move { axum::serve(pl, build_public_router(st)).await.unwrap(); });
    let al = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_port = al.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(al, build_admin_router(state)).await.unwrap(); });

    PairEnv { pub_port, admin_port, upstream_ports, password_hash: hash }
}

fn pub_url(env: &PairEnv, path: &str) -> String {
    format!("http://127.0.0.1:{}{path}", env.pub_port)
}
fn admin_url(env: &PairEnv, path: &str) -> String {
    format!("http://127.0.0.1:{}{path}", env.admin_port)
}

/// 手机侧发起材料:code(10 位,字符集与网关一致)+ secret(纯字母数字)。
fn phone_materials(seed: u32) -> (String, String) {
    const CHARS: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let mut x = seed.wrapping_mul(2654435761) | 1;
    let mut code = String::new();
    for _ in 0..10 {
        code.push(CHARS[(x as usize) % CHARS.len()] as char);
        x = x.rotate_left(3).wrapping_add(0x9E3779B9);
    }
    let secret = format!("s{:06x}abcdefghijklmnopqrstuvwxyz0123456789", seed);
    (code, secret)
}

async fn pair_start(env: &PairEnv, code: &str, secret: &str, device: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(pub_url(env, "/pair/start"))
        .json(&serde_json::json!({ "code": code, "secret": secret, "device": device }))
        .send()
        .await
        .unwrap()
}

async fn admin_claim(env: &PairEnv, code: &str, host_code: &str, label: &str, port: u16) -> reqwest::Response {
    reqwest::Client::new()
        .post(admin_url(env, "/admin/pair/claim"))
        .json(&serde_json::json!({ "code": code, "host_code": host_code, "host_label": label, "port": port }))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn pair_full_flow_binds_token_to_claimed_tunnel_port() {
    // 两个上游 = 两台 Mac;确认第二个 claim,令牌必须路由到第二个上游。
    let env = spawn_env(2, false).await;
    let (code, secret) = phone_materials(1);
    let start: serde_json::Value = pair_start(&env, &code, &secret, "Pixel-9")
        .await
        .json()
        .await
        .unwrap();
    let pairing_id = start["pairing_id"].as_str().unwrap().to_string();

    // 轮询:无 claim → waiting。
    let poll: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/pair/poll"))
        .json(&serde_json::json!({ "pairing_id": pairing_id, "secret": secret }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(poll["status"], "waiting");

    // 两台 Mac 各自 claim(不同主机码、不同隧道端口)。
    admin_claim(&env, &code, "ABC234", "mac-mini", env.upstream_ports[0]).await;
    admin_claim(&env, &code, "XYZ789", "mbp", env.upstream_ports[1]).await;

    // 手机端看到两个 offer。
    let poll: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/pair/poll"))
        .json(&serde_json::json!({ "pairing_id": pairing_id, "secret": secret }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(poll["status"], "offers");
    assert_eq!(poll["offers"].as_array().unwrap().len(), 2);

    // 人工比对后点选 mbp 的主机码。
    let mbp_offer = poll["offers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["host_label"] == "mbp")
        .unwrap()
        .clone();
    let confirm: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/pair/confirm"))
        .json(&serde_json::json!({
            "pairing_id": pairing_id,
            "secret": secret,
            "claim_id": mbp_offer["claim_id"],
            "host_code": mbp_offer["host_code"],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = confirm["token"].as_str().unwrap();
    assert_eq!(confirm["host_label"], "mbp");

    // 经中转调用:必须打到 mbp 的上游(up-1)。
    let resp: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/api/echo"))
        .header("authorization", format!("Bearer {token}"))
        .json(&serde_json::json!({ "x": 1 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["upstream"], "up-1", "token must route to the claimed Mac's tunnel");
    assert_eq!(resp["host"], UPSTREAM_HOST);
}

#[tokio::test]
async fn duplicate_live_code_rejected_409() {
    let env = spawn_env(1, false).await;
    let (code, s1) = phone_materials(2);
    let (c2, s2) = (code.clone(), phone_materials(3).1);

    let r1 = pair_start(&env, &code, &s1, "phone-a").await;
    assert!(r1.status().is_success());
    // 抄码抢注:同码第二个 pending → 409。
    let r2 = pair_start(&env, &c2, &s2, "attacker").await;
    assert_eq!(r2.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn confirm_with_wrong_host_code_rejected() {
    let env = spawn_env(1, false).await;
    let (code, secret) = phone_materials(4);
    let start: serde_json::Value = pair_start(&env, &code, &secret, "Pixel")
        .await
        .json()
        .await
        .unwrap();
    let pairing_id = start["pairing_id"].as_str().unwrap().to_string();
    admin_claim(&env, &code, "ABC234", "mac", env.upstream_ports[0]).await;
    let poll: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/pair/poll"))
        .json(&serde_json::json!({ "pairing_id": pairing_id, "secret": secret }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let claim_id = poll["offers"][0]["claim_id"].as_str().unwrap().to_string();

    // 主机码输错 → 400,claim 仍可再次尝试(未消费)。
    let wrong = reqwest::Client::new()
        .post(pub_url(&env, "/pair/confirm"))
        .json(&serde_json::json!({
            "pairing_id": pairing_id, "secret": secret,
            "claim_id": claim_id, "host_code": "ZZZ999",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);

    // 改对了 → 成功。
    let ok: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/pair/confirm"))
        .json(&serde_json::json!({
            "pairing_id": pairing_id, "secret": secret,
            "claim_id": claim_id, "host_code": "ABC-234",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(ok["token"].is_string());
}

#[tokio::test]
async fn claim_single_use_and_secret_required() {
    let env = spawn_env(1, false).await;
    let (code, secret) = phone_materials(5);
    let start: serde_json::Value = pair_start(&env, &code, &secret, "Pixel")
        .await
        .json()
        .await
        .unwrap();
    let pairing_id = start["pairing_id"].as_str().unwrap().to_string();
    admin_claim(&env, &code, "ABC234", "mac", env.upstream_ports[0]).await;
    let poll: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/pair/poll"))
        .json(&serde_json::json!({ "pairing_id": pairing_id, "secret": secret }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let claim_id = poll["offers"][0]["claim_id"].as_str().unwrap().to_string();
    let body = serde_json::json!({
        "pairing_id": pairing_id, "secret": secret,
        "claim_id": claim_id, "host_code": "ABC234",
    });
    let first: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/pair/confirm"))
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(first["token"].is_string());
    // 第二次(即使码对)→ claim 已消费;pairing 已 confirmed → 400。
    let second = reqwest::Client::new()
        .post(pub_url(&env, "/pair/confirm"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);

    // secret 错 → poll 401。
    let bad_secret = reqwest::Client::new()
        .post(pub_url(&env, "/pair/poll"))
        .json(&serde_json::json!({ "pairing_id": pairing_id, "secret": "wrong-secret" }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_secret.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_claim_requires_live_pairing_and_port_range() {
    let env = spawn_env(1, false).await;
    // 没有手机在等 → 404。
    let r = admin_claim(&env, "AAAAAAAAAA", "ABC234", "mac", 13100).await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);

    let (code, secret) = phone_materials(6);
    pair_start(&env, &code, &secret, "Pixel").await;
    // 端口越界(< 测试放宽范围下限 1024)→ 400。
    let r = admin_claim(&env, &code, "ABC234", "mac", 80).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    // 正常 → 200 且回显等待中的设备名。
    let r: serde_json::Value = admin_claim(&env, &code, "ABC234", "mac", 13105)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(r["device"], "Pixel");
}

#[tokio::test]
async fn password_login_disabled_when_hash_absent() {
    let env = spawn_env(1, false).await;
    let r = reqwest::Client::new()
        .post(pub_url(&env, "/auth/login"))
        .json(&serde_json::json!({ "password": "anything" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_status_reports_confirmation() {
    let env = spawn_env(1, false).await;
    let (code, secret) = phone_materials(7);
    let start: serde_json::Value = pair_start(&env, &code, &secret, "Pixel-9")
        .await
        .json()
        .await
        .unwrap();
    let pairing_id = start["pairing_id"].as_str().unwrap().to_string();
    admin_claim(&env, &code, "ABC234", "mac-mini", env.upstream_ports[0]).await;

    let status: serde_json::Value = reqwest::Client::new()
        .get(admin_url(&env, "/admin/pair/status"))
        .query(&[("code", code.clone())])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["status"], "pending");
    assert_eq!(status["device"], "Pixel-9");

    let poll: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/pair/poll"))
        .json(&serde_json::json!({ "pairing_id": pairing_id, "secret": secret }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let claim = &poll["offers"][0];
    let _: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/pair/confirm"))
        .json(&serde_json::json!({
            "pairing_id": pairing_id, "secret": secret,
            "claim_id": claim["claim_id"], "host_code": claim["host_code"],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let status: serde_json::Value = reqwest::Client::new()
        .get(admin_url(&env, "/admin/pair/status"))
        .query(&[("code", code)])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["confirmed"], true);
    assert_eq!(status["token"]["device"], "Pixel-9");
    assert_eq!(status["token"]["host_label"], "mac-mini");
}

// UDS 隧道落点:令牌绑定端口的 tunnel-{N}.sock 存在时,中转必须走 Unix
// socket(TCP 回落指到死端口 —— 若错误回落,relay 502,测试必红)。
#[tokio::test]
async fn relay_prefers_unix_socket_when_present() {
    use tokio::net::UnixListener;

    const TUNNEL_PORT: u16 = 13100;

    // 1. mock 上游 = UDS socket(记 Host;回自身 tag 以资断言)。
    // 短路径:macOS 的 $TMPDIR 前缀很长,UDS 路径超 sun_path(104B)会炸。
    let dir = std::path::PathBuf::from(format!("/tmp/dshgw-uds-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]));
    std::fs::create_dir_all(&dir).unwrap();
    let sock_path = dir.join(format!("tunnel-{TUNNEL_PORT}.sock"));
    let listener = UnixListener::bind(&sock_path).unwrap();
    let seen_host: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sh = seen_host.clone();
    let app = Router::new().route(
        "/api/echo",
        post(move |headers: HeaderMap| async move {
            let host = headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("<none>")
                .to_string();
            sh.lock().unwrap().push(host);
            Json(serde_json::json!({ "host": "uds-upstream" }))
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });

    // 2. 网关:sock 目录生效;TCP 默认上游故意指死端口。
    let config = Config {
        bind: "127.0.0.1".into(),
        port: 0,
        admin_port: 0,
        upstream_addr: "127.0.0.1:1".into(),
        upstream_host: UPSTREAM_HOST.into(),
        jwt_secret: "uds-test-secret".into(),
        password_hash: String::new(),
        admin_token: String::new(),
        tunnel_sock_dir: Some(dir.to_string_lossy().to_string()),
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
    let pl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pub_port = pl.local_addr().unwrap().port();
    let st = state.clone();
    tokio::spawn(async move { axum::serve(pl, build_public_router(st)).await.unwrap(); });
    let al = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_port = al.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(al, build_admin_router(state)).await.unwrap(); });
    let env = PairEnv {
        pub_port,
        admin_port,
        upstream_ports: vec![TUNNEL_PORT],
        password_hash: String::new(),
    };

    // 3. 完整配对(claim 绑 TUNNEL_PORT)拿令牌。
    let (code, secret) = phone_materials(42);
    let start: serde_json::Value = pair_start(&env, &code, &secret, "Pixel-9")
        .await
        .json()
        .await
        .unwrap();
    let pairing_id = start["pairing_id"].as_str().unwrap().to_string();
    admin_claim(&env, &code, "ABC234", "mac-mini", TUNNEL_PORT).await;
    let poll: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/pair/poll"))
        .json(&serde_json::json!({ "pairing_id": pairing_id, "secret": secret }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let offer = poll["offers"].as_array().unwrap()[0].clone();
    let confirm: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/pair/confirm"))
        .json(&serde_json::json!({
            "pairing_id": pairing_id,
            "secret": secret,
            "claim_id": offer["claim_id"],
            "host_code": offer["host_code"],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = confirm["token"].as_str().unwrap();

    // 4. 经中转调用 → 必须命中 UDS 上游(否则 TCP 死端口 502)。
    let resp: serde_json::Value = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{pub_port}/api/echo"))
        .header("authorization", format!("Bearer {token}"))
        .json(&serde_json::json!({ "x": 1 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["host"], "uds-upstream", "中转必须走 UDS 而非 TCP 回落");
    assert!(
        seen_host.lock().unwrap().iter().all(|h| h == UPSTREAM_HOST),
        "Host 必须改写为 loopback authority:{:?}",
        seen_host.lock().unwrap()
    );

    let _ = std::fs::remove_dir_all(&dir);
}
