// 扫码配对集成测试(M6.2):终端 QR 渲染 + 公开落地页 + claim 幂等语义。
use axum::http::StatusCode;
use dsh_mobile_gateway::{
    auth::LoginRateLimiter,
    build_admin_router,
    build_public_router,
    config::Config,
    db::TokenDb,
    AppState,
};
use std::sync::Arc;
use tokio::net::TcpListener;

struct QrEnv {
    public_port: u16,
    admin_port: u16,
}

async fn spawn_all() -> QrEnv {
    let config = Config {
        port: 0,
        admin_port: 0,
        upstream_addr: "127.0.0.1:13100".into(),
        upstream_host: "127.0.0.1:3080".into(),
        jwt_secret: format!("test-secret-{}", uuid::Uuid::new_v4()),
        password_hash: String::new(),
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
    let pub_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_port = pub_listener.local_addr().unwrap().port();
    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_port = admin_listener.local_addr().unwrap().port();
    let pub_state = state.clone();
    tokio::spawn(async move {
        axum::serve(pub_listener, build_public_router(pub_state)).await.unwrap();
    });
    tokio::spawn(async move {
        axum::serve(admin_listener, build_admin_router(state)).await.unwrap();
    });
    QrEnv { public_port, admin_port }
}

#[tokio::test]
async fn qr_renders_half_blocks_with_ansi_and_quiet_zone() {
    let env = spawn_all().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/admin/pair/qr", env.admin_port))
        .json(&serde_json::json!({ "text": "https://dsh.example.com/pair#c=ABCDEFGHJK&h=ABC234" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    let qr = body["qr"].as_str().unwrap();
    // ANSI 黑字白底包尾(终端主题无关的标准极性)。
    assert!(qr.starts_with("\u{1b}[30;47m"), "missing fg-black/bg-white prefix");
    assert!(qr.ends_with("\u{1b}[0m"));
    // 半块字符 + 空白;行数 = ceil((modules+4)/2)(两模块一行,余数独占一行)。
    let stripped = qr.replace("\u{1b}[30;47m", "").replace("\u{1b}[0m", "");
    let lines: Vec<&str> = stripped.split('\n').collect();
    let modules = body["modules"].as_u64().unwrap() as usize;
    assert_eq!(lines.len(), (modules + 4 + 1) / 2);
    assert!(lines.iter().all(|l| l.chars().all(|c| "█▀▄ ".contains(c))));
    // 静区:首行/末行全空(四周 2 模块)。
    assert!(lines.first().unwrap().trim().is_empty());
    assert!(lines.last().unwrap().trim().is_empty());
    // 模块数合理性:URL ~50B,EcLevel::M → 29×29 左右(版本 3)。
    assert!((25..=45).contains(&modules), "unexpected module count {modules}");
    assert_eq!(lines[0].chars().count(), modules + 4);

    // 半块解码回模块矩阵,校验三个定位图形(finder pattern)——
    // 抓渲染的翻转/镜像/行序错误:每个角标是 7×7 黑框+白环+3×3 黑心。
    let mut grid = vec![vec![false; modules]; modules];
    for (ly, line) in stripped.split('\n').enumerate() {
        for (lx, ch) in line.chars().enumerate() {
            let y = ly * 2;
            let x = lx as isize - 2; // 去静区(负 = 静区列,跳过)
            let (top, bottom) = match ch {
                '█' => (true, true),
                '▀' => (true, false),
                '▄' => (false, true),
                _ => (false, false),
            };
            for (yy, dd) in [(y as isize, top), (y as isize + 1, bottom)] {
                let gy = yy - 2;
                if x >= 0 && gy >= 0 && (gy as usize) < modules && (x as usize) < modules {
                    grid[gy as usize][x as usize] = dd;
                }
            }
        }
    }
    let finder_ok = |fx: usize, fy: usize| -> bool {
        // 以 (fx,fy) 为左上角的 7×7:外框全黑、白环全白、3×3 黑心。
        for i in 0..7 {
            for j in 0..7 {
                let dark = grid[fy + j][fx + i];
                let ring = i.min(6 - i).min(j.min(6 - j)); // 0=外框 1=白环 2..=3 中心
                let expect = if ring == 1 { false } else { true };
                if dark != expect {
                    return false;
                }
            }
        }
        true
    };
    let last = modules - 7;
    assert!(finder_ok(0, 0), "top-left finder broken");
    assert!(finder_ok(last, 0), "top-right finder broken");
    assert!(finder_ok(0, last), "bottom-left finder broken");
}

#[tokio::test]
async fn qr_rejects_empty_and_oversized_text() {
    let env = spawn_all().await;
    let client = reqwest::Client::new();
    for bad in ["", &"x".repeat(513)] {
        let resp = client
            .post(format!("http://127.0.0.1:{}/admin/pair/qr", env.admin_port))
            .json(&serde_json::json!({ "text": bad }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn pair_landing_page_is_static_no_store_html() {
    let env = spawn_all().await;
    let resp = reqwest::get(format!("http://127.0.0.1:{}/pair", env.public_port))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("cache-control").unwrap(),
        "no-store"
    );
    let body = resp.text().await.unwrap();
    // 解析逻辑在页面内联(不依赖外部资源);锚定主机码展示存在。
    assert!(body.contains("URLSearchParams"));
    assert!(body.contains("锚定主机码"));
    assert!(!body.contains("http://cdn") && !body.contains("https://cdn"));
}

#[tokio::test]
async fn admin_claim_rejects_when_no_phone_waiting() {
    let env = spawn_all().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/admin/pair/claim", env.admin_port))
        .json(&serde_json::json!({
            "code": "ABCDEFGHJK", "host_code": "ABC234", "host_label": "mac", "port": 13100
        }))
        .send()
        .await
        .unwrap();
    // 无手机 pending → 404(不创建悬空 offer;pair.sh 换码重试的依据)。
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
