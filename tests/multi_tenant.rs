// 多租户(004)集成测试:租户创建/宿主登记、公开面按钥 claim、端口归属
// 仲裁、devices/revoke 跨租户围栏、配对租户锚定(offer 不可见 + confirm 拒)、
// 无钥/错钥/吊销租户恒 401、运营者旧语义(未登记端口范围白名单)不回归。
use axum::{http::{HeaderMap, StatusCode}, routing::post, Json, Router};
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
const UPSTREAM_HOST: &str = "127.0.0.1:3080";

struct MtEnv {
    pub_port: u16,
    admin_port: u16,
    upstream_ports: Vec<u16>,
}

/// 1 公开面 + 1 管理面 + 2 个 mock 上游(随机端口,登记进 hosts 表用)。
async fn spawn_env() -> MtEnv {
    let mut upstream_ports = Vec::new();
    for i in 0..2 {
        let app: Router = Router::new().route(
            "/api/echo",
            post(move |headers: HeaderMap| async move {
                let host = headers
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("<none>")
                    .to_string();
                Json(serde_json::json!({ "host": host, "upstream": i }))
            }),
        );
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        upstream_ports.push(p);
        tokio::spawn(async move { axum::serve(l, app).await.unwrap(); });
    }
    let config = Config {
        bind: "127.0.0.1".into(),
        port: 0,
        admin_port: 0,
        upstream_addr: format!("127.0.0.1:{}", upstream_ports[0]),
        upstream_host: UPSTREAM_HOST.into(),
        jwt_secret: "mt-test-secret".into(),
        password_hash: String::new(),
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
    MtEnv { pub_port, admin_port, upstream_ports }
}

fn pub_url(env: &MtEnv, path: &str) -> String {
    format!("http://127.0.0.1:{}{path}", env.pub_port)
}
fn admin_url(env: &MtEnv, path: &str) -> String {
    format!("http://127.0.0.1:{}{path}", env.admin_port)
}

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

/// 运营者建租户 → (id, admin_key)。
async fn create_tenant(env: &MtEnv, name: &str) -> (String, String) {
    let v: serde_json::Value = reqwest::Client::new()
        .post(admin_url(env, "/admin/tenants"))
        .json(&serde_json::json!({ "name": name }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (v["id"].as_str().unwrap().into(), v["admin_key"].as_str().unwrap().into())
}

/// 运营者登记宿主(port → tenant)。
async fn register_host(env: &MtEnv, tenant_id: &str, port: u16) {
    let r = reqwest::Client::new()
        .post(admin_url(env, "/admin/hosts"))
        .json(&serde_json::json!({ "tenant_id": tenant_id, "port": port, "label": "host" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

/// 公开面按租户钥 claim。
async fn tenant_claim(env: &MtEnv, key: &str, body: serde_json::Value) -> StatusCode {
    reqwest::Client::new()
        .post(pub_url(env, "/admin/pair/claim"))
        .bearer_auth(key)
        .json(&body)
        .send()
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn tenant_lifecycle_port_ownership_and_scoped_devices() {
    let env = spawn_env().await;
    let (tenant_a, key_a) = create_tenant(&env, "alpha").await;
    let (tenant_b, key_b) = create_tenant(&env, "beta").await;

    // 宿主登记:端口 0 归 alpha,端口 1 归 beta;撞端口登记被 UNIQUE 拒。
    register_host(&env, &tenant_a, env.upstream_ports[0]).await;
    register_host(&env, &tenant_b, env.upstream_ports[1]).await;
    let dup = reqwest::Client::new()
        .post(admin_url(&env, "/admin/hosts"))
        .json(&serde_json::json!({ "tenant_id": tenant_b, "port": env.upstream_ports[0] }))
        .send()
        .await
        .unwrap();
    assert_eq!(dup.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // 公开面无钥/错钥恒 401。
    let no_key = reqwest::Client::new()
        .get(pub_url(&env, "/admin/pair/tokens"))
        .send()
        .await
        .unwrap();
    assert_eq!(no_key.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        tenant_claim(&env, "bogus-key", serde_json::json!({ "code": "AAAAAAAAAA" }))
            .await,
        StatusCode::UNAUTHORIZED
    );

    // 锚定 alpha 的配对:beta 的 claim 按「无人在等」拒(404)。
    let (code, secret) = phone_materials(7);
    let start_resp: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/pair/start"))
        .json(&serde_json::json!({ "code": code, "secret": secret, "device": "phone-a", "tenant": tenant_a }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let pairing_id = start_resp["pairing_id"].as_str().unwrap().to_string();
    let claim_body = serde_json::json!({
        "code": code, "host_code": "AB3456", "host_label": "mac-b", "port": env.upstream_ports[1]
    });
    assert_eq!(
        tenant_claim(&env, &key_b, claim_body.clone()).await,
        StatusCode::NOT_FOUND
    );
    // beta 用 alpha 的端口 claim 开放配对场景之外 —— 这里码是锚定的,
    // 先验命中锚定检查;换成 alpha 钥但 beta 端口 → 403 归属。
    let wrong_port = serde_json::json!({
        "code": code, "host_code": "AB3456", "host_label": "mac-a", "port": env.upstream_ports[1]
    });
    assert_eq!(
        tenant_claim(&env, &key_a, wrong_port).await,
        StatusCode::FORBIDDEN
    );
    // 正路:alpha 钥 + alpha 端口 → 200。
    let ok = serde_json::json!({
        "code": code, "host_code": "AB3456", "host_label": "mac-a", "port": env.upstream_ports[0]
    });
    assert_eq!(tenant_claim(&env, &key_a, ok).await, StatusCode::OK);

    // 手机侧确认(锚定配对只看到 alpha 的 offer)。
    let confirmed: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/pair/poll"))
        .json(&serde_json::json!({ "pairing_id": pairing_id, "secret": secret }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(confirmed["status"], "offers");
    let offers = confirmed["offers"].as_array().unwrap();
    assert_eq!(offers.len(), 1);
    let token_a: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/pair/confirm"))
        .json(&serde_json::json!({
            "pairing_id": pairing_id,
            "secret": secret,
            "claim_id": offers[0]["claim_id"],
            "host_code": offers[0]["host_code"],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(token_a["host_ref"], env.upstream_ports[0].to_string());
    let jwt_a = token_a["token"].as_str().unwrap();

    // beta 经开放配对(无锚定)也拿一个令牌。
    let (code_b, secret_b) = phone_materials(8);
    let start_b: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/pair/start"))
        .json(&serde_json::json!({ "code": code_b, "secret": secret_b, "device": "phone-b" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        tenant_claim(
            &env,
            &key_b,
            serde_json::json!({
                "code": code_b, "host_code": "XYZ789", "host_label": "mac-b",
                "port": env.upstream_ports[1]
            })
        )
        .await,
        StatusCode::OK
    );
    let poll_b: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/pair/poll"))
        .json(&serde_json::json!({
            "pairing_id": start_b["pairing_id"], "secret": secret_b
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let offers_b = poll_b["offers"].as_array().unwrap();
    let token_b: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/pair/confirm"))
        .json(&serde_json::json!({
            "pairing_id": start_b["pairing_id"], "secret": secret_b,
            "claim_id": offers_b[0]["claim_id"], "host_code": offers_b[0]["host_code"],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let jwt_b = token_b["token"].as_str().unwrap();

    // devices 围栏:alpha 令牌只看到 alpha 的设备(1 行),看不到 beta。
    let devices_a: serde_json::Value = reqwest::Client::new()
        .get(pub_url(&env, "/auth/devices"))
        .bearer_auth(jwt_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rows_a = devices_a.as_array().unwrap();
    assert_eq!(rows_a.len(), 1);
    assert_eq!(rows_a[0]["tenant_id"], tenant_a.as_str());

    // 跨租户吊销:alpha 令牌吊销 beta 的 jti → revoked:false,beta 令牌仍活。
    let jti_b = dsh_mobile_gateway_test_support::jti_of(jwt_b);
    let cross: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/auth/revoke"))
        .bearer_auth(jwt_a)
        .json(&serde_json::json!({ "jti": jti_b }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cross["revoked"], false);
    let still_ok = reqwest::Client::new()
        .get(pub_url(&env, "/auth/devices"))
        .bearer_auth(jwt_b)
        .send()
        .await
        .unwrap();
    assert_eq!(still_ok.status(), StatusCode::OK);

    // 公开面租户 tokens 清单只列本租户;吊销本租户 jti 成功。
    let tokens_a: serde_json::Value = reqwest::Client::new()
        .get(pub_url(&env, "/admin/pair/tokens"))
        .bearer_auth(&key_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(tokens_a.as_array().unwrap().len(), 1);
    let jti_a = dsh_mobile_gateway_test_support::jti_of(jwt_a);
    let self_revoke: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/admin/pair/revoke-token"))
        .bearer_auth(&key_a)
        .json(&serde_json::json!({ "jti": jti_a }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(self_revoke["revoked"], true);

    // 运营者(8103)仍可跨租户吊销任意令牌(超管语义不回归)。
    let op_revoke: serde_json::Value = reqwest::Client::new()
        .post(admin_url(&env, "/admin/pair/revoke-token"))
        .json(&serde_json::json!({ "jti": jti_b }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(op_revoke["revoked"], true);

    // 吊销租户:其钥立即 401。
    reqwest::Client::new()
        .post(admin_url(&env, "/admin/tenants/revoke"))
        .json(&serde_json::json!({ "id": tenant_b }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        reqwest::Client::new()
            .get(pub_url(&env, "/admin/pair/tokens"))
            .bearer_auth(&key_b)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn operator_legacy_and_tenant_requires_registered_host() {
    let env = spawn_env().await;
    let (tenant_a, key_a) = create_tenant(&env, "alpha").await;
    // 未登记端口:运营者(8103)沿用范围白名单 → 200(单运营者旧语义)。
    let (code, secret) = phone_materials(11);
    let start: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/pair/start"))
        .json(&serde_json::json!({ "code": code, "secret": secret, "device": "p" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(start["pairing_id"].is_string());
    let op_claim = reqwest::Client::new()
        .post(admin_url(&env, "/admin/pair/claim"))
        .json(&serde_json::json!({
            "code": code, "host_code": "AB3456", "host_label": "op-mac",
            "port": env.upstream_ports[0]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(op_claim.status(), StatusCode::OK);

    // 同一端口给租户 claim(未登记)→ 403:显式租户必须先登记宿主。
    let (code2, secret2) = phone_materials(12);
    reqwest::Client::new()
        .post(pub_url(&env, "/pair/start"))
        .json(&serde_json::json!({ "code": code2, "secret": secret2, "device": "p2" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        tenant_claim(
            &env,
            &key_a,
            serde_json::json!({
                "code": code2, "host_code": "ABC234", "host_label": "a-mac",
                "port": env.upstream_ports[1]
            })
        )
        .await,
        StatusCode::FORBIDDEN
    );

    // 登记后同端口放行;运营者 claim 该端口(归属 alpha)→ 403。
    register_host(&env, &tenant_a, env.upstream_ports[1]).await;
    assert_eq!(
        tenant_claim(
            &env,
            &key_a,
            serde_json::json!({
                "code": code2, "host_code": "ABC234", "host_label": "a-mac",
                "port": env.upstream_ports[1]
            })
        )
        .await,
        StatusCode::OK
    );
    let (code3, secret3) = phone_materials(13);
    reqwest::Client::new()
        .post(pub_url(&env, "/pair/start"))
        .json(&serde_json::json!({ "code": code3, "secret": secret3, "device": "p3" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        reqwest::Client::new()
            .post(admin_url(&env, "/admin/pair/claim"))
            .json(&serde_json::json!({
                "code": code3, "host_code": "ABC345", "host_label": "op-mac",
                "port": env.upstream_ports[1]
            }))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn anchored_pairing_hides_foreign_offers_and_rejects_direct_confirm() {
    let env = spawn_env().await;
    let (tenant_a, key_a) = create_tenant(&env, "alpha").await;
    let (tenant_b, key_b) = create_tenant(&env, "beta").await;
    register_host(&env, &tenant_a, env.upstream_ports[0]).await;
    register_host(&env, &tenant_b, env.upstream_ports[1]).await;

    // 开放配对(不锚定):两个租户都能 offer,poll 全可见(手输模式)。
    let (code, secret) = phone_materials(21);
    let start: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/pair/start"))
        .json(&serde_json::json!({ "code": code, "secret": secret, "device": "p" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    for (key, port, hc) in [
        (&key_a, env.upstream_ports[0], "AAA333"),
        (&key_b, env.upstream_ports[1], "BBB222"),
    ] {
        assert_eq!(
            tenant_claim(
                &env,
                key,
                serde_json::json!({ "code": code, "host_code": hc, "host_label": "m", "port": port })
            )
            .await,
            StatusCode::OK
        );
    }
    let poll: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/pair/poll"))
        .json(&serde_json::json!({ "pairing_id": start["pairing_id"], "secret": secret }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(poll["offers"].as_array().unwrap().len(), 2);

    // 锚定配对:beta offer 存在(claim 时配对未锚定…… 本例锚定在前)——
    // 重新走锚定 alpha 的配对,beta claim 被 404 拒,poll 只见 alpha。
    let (code2, secret2) = phone_materials(22);
    let start2: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/pair/start"))
        .json(&serde_json::json!({
            "code": code2, "secret": secret2, "device": "p2", "tenant": tenant_a
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        tenant_claim(
            &env,
            &key_b,
            serde_json::json!({
                "code": code2, "host_code": "CCC333", "host_label": "b-mac",
                "port": env.upstream_ports[1]
            })
        )
        .await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        tenant_claim(
            &env,
            &key_a,
            serde_json::json!({
                "code": code2, "host_code": "AAA222", "host_label": "a-mac",
                "port": env.upstream_ports[0]
            })
        )
        .await,
        StatusCode::OK
    );
    let poll2: serde_json::Value = reqwest::Client::new()
        .post(pub_url(&env, "/pair/poll"))
        .json(&serde_json::json!({ "pairing_id": start2["pairing_id"], "secret": secret2 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let offers2 = poll2["offers"].as_array().unwrap();
    assert_eq!(offers2.len(), 1);
    assert_eq!(offers2[0]["host_label"], "a-mac");

    // 深度防御:直发 confirm 一个不属于本配对/锚定的 claim → 拒。
    // (构造:用 alpha 的 claim_id 但 host_code 对不上 —— 400 host code mismatch,
    // 协议原有防线仍在。)
    let wrong = reqwest::Client::new()
        .post(pub_url(&env, "/pair/confirm"))
        .json(&serde_json::json!({
            "pairing_id": start2["pairing_id"], "secret": secret2,
            "claim_id": offers2[0]["claim_id"], "host_code": "WRONG99",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
}

/// 测试支撑:从 JWT 载荷解 jti(纯 base64 解码,不验签 —— 网关侧验)。
mod dsh_mobile_gateway_test_support {
    pub fn jti_of(token: &str) -> String {
        use base64::Engine;
        let payload = token.split('.').nth(1).unwrap();
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        v["jti"].as_str().unwrap().to_string()
    }
}
