// dsh-gateway — singleman 移动端配对鉴权中转网关(二进制入口)。
//
// 形态:
//   手机 ─https→ nginx(<your-domain>) → 公开面 :8102(配对/令牌/中转)
//   Mac pair.sh ─ssh→ 服务器本机 → 管理面 :8103(仅 127.0.0.1,claim/亮码确认)
//   中转上游 = 各 Mac 的 SSH 反向隧道(127.0.0.1:131xx;令牌绑定端口)
//
// 鉴权:配对为主(手机亮码 → Mac 亮主机码 → 手机人工比对点选 → 30 天设备
// 令牌,SQLite 登记可吊销);密码登录为可选兜底(未配置哈希即禁用)。
use std::sync::Arc;

use dsh_mobile_gateway::{
    auth::LoginRateLimiter,
    build_admin_router,
    build_public_router,
    config::Config,
    db::TokenDb,
    AppState,
};

fn hash_password(password: &str) -> anyhow::Result<String> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)?
        .to_string();
    Ok(hash)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 工具模式:生成 argon2 密码哈希(不启动服务)。
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--hash-password") {
        let password = std::env::var("PASSWORD").unwrap_or_else(|_| {
            eprintln!("用法: PASSWORD='你的密码' dsh-gateway --hash-password");
            std::process::exit(2);
        });
        let hash = hash_password(&password)?;
        println!("{hash}");
        return Ok(());
    }

    gateway_shared::tracing_setup::init_tracing("dsh_mobile_gateway=info,tower_http=warn");
    let _ = dotenvy::dotenv();

    let config = Config::from_env();
    let db = TokenDb::open(&config.database_path)?;

    let public_addr = format!("{}:{}", config.bind, config.port);
    let admin_addr = format!("127.0.0.1:{}", config.admin_port);
    tracing::info!(
        "dsh-gateway public {public_addr} (pair + relay, default upstream {}) / admin {admin_addr} (ssh-only)",
        config.upstream_addr
    );
    if config.password_hash.is_empty() {
        tracing::info!("password login disabled (pairing only)");
    }

    let state = Arc::new(AppState {
        config: config.clone(),
        db,
        login_limiter: LoginRateLimiter::new(),
        pair_limiter: LoginRateLimiter::new_pairing(),
        ws_sessions: Default::default(),
    });

    let public_app = build_public_router(state.clone());
    let admin_app = build_admin_router(state);

    let public_listener = match tokio::net::TcpListener::bind(&public_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("端口绑定失败 {public_addr}: {e}");
            std::process::exit(1);
        }
    };
    let admin_listener = match tokio::net::TcpListener::bind(&admin_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("管理端口绑定失败 {admin_addr}: {e}");
            std::process::exit(1);
        }
    };

    // 公开与管理两个 serve 并行;任一退出即整体退出(systemd 拉起)。
    let (a, b) = tokio::join!(
        axum::serve(public_listener, public_app),
        axum::serve(admin_listener, admin_app)
    );
    a?;
    b?;
    Ok(())
}
