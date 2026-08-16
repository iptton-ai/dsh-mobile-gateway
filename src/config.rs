// 环境变量配置(DSH_GATEWAY_ 前缀)。
// JWT 密钥必须显式提供;密码哈希可选(未配置 = 密码登录禁用,仅配对)。
use gateway_shared::config::{env_or, env_parse, env_required};

/// 生产默认:配对 claim 允许绑定的隧道端口范围(每台 Mac 一个端口)。
pub const TUNNEL_PORT_MIN: u16 = 13100;
pub const TUNNEL_PORT_MAX: u16 = 13199;

#[derive(Clone, Debug)]
pub struct Config {
    /// 公开监听绑定地址。默认 127.0.0.1(fail-closed:公开面只该被同机
    /// 反代触达;直绑 0.0.0.0 依赖云安全组挡直连,X-Real-IP 可伪造 =
    /// 限速失效 + 明文 HTTP)。Docker 端口映射形态显式设 0.0.0.0。
    pub bind: String,
    /// 公开监听端口(nginx 反代目标)。
    pub port: u16,
    /// 管理监听端口(仅绑 127.0.0.1;claim/status/revoke,pair.sh 经 ssh 走这里)。
    pub admin_port: u16,
    /// 默认上游 TCP 地址 = SSH 反向隧道端口(通向 Mac 上的 dsh)。
    /// 密码登录令牌与未指定端口的 claim 回落到这里。
    pub upstream_addr: String,
    /// 转发时改写的 Host 头。dsh 的信任围栏按 Host 判定 loopback,
    /// 必须写成 dsh 实际监听的 loopback authority。
    pub upstream_host: String,
    pub jwt_secret: String,
    /// argon2 哈希(--hash-password 生成)。空 = 密码登录禁用(仅配对)。
    pub password_hash: String,
    /// 管理面 bearer token(DSH_GATEWAY_ADMIN_TOKEN)。非空 = 管理面所有路由
    /// 要求 `authorization: Bearer <token>`;空 = 不鉴权(仅限本地联调 ——
    /// 管理面虽绑 loopback,同机任意进程都能连,生产必须设置)。
    pub admin_token: String,
    /// 隧道 UDS 落点目录(DSH_GATEWAY_TUNNEL_SOCK_DIR,如 /run/dsh-gateway)。
    /// 设置后,令牌绑定端口 N 的上游优先取 `{dir}/tunnel-{N}.sock`(Unix socket,
    /// sshd 侧 `ssh -R` 直落 socket,权限由目录/属主把守);socket 不存在则
    /// 回落 TCP 127.0.0.1:N —— 切换期/未切换的隧道双模并存。
    pub tunnel_sock_dir: Option<String>,
    /// 设备令牌有效期(天)。
    pub token_ttl_days: i64,
    /// SQLite 数据库文件路径(令牌/配对登记表)。
    pub database_path: String,
    /// claim 端口白名单(测试放宽;生产默认 13100–13199)。
    pub tunnel_port_min: u16,
    pub tunnel_port_max: u16,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            bind: env_or("DSH_GATEWAY_BIND", "127.0.0.1"),
            port: env_parse("DSH_GATEWAY_PORT", 8102u16),
            admin_port: env_parse("DSH_GATEWAY_ADMIN_PORT", 8103u16),
            upstream_addr: env_or("DSH_GATEWAY_UPSTREAM", "127.0.0.1:13100"),
            upstream_host: env_or("DSH_GATEWAY_UPSTREAM_HOST", "127.0.0.1:3080"),
            jwt_secret: env_required("DSH_GATEWAY_JWT_SECRET"),
            password_hash: env_or("DSH_GATEWAY_PASSWORD_HASH", ""),
            admin_token: env_or("DSH_GATEWAY_ADMIN_TOKEN", ""),
            tunnel_sock_dir: match env_or("DSH_GATEWAY_TUNNEL_SOCK_DIR", "") {
                s if s.is_empty() => None,
                s => Some(s),
            },
            token_ttl_days: env_parse("DSH_GATEWAY_TOKEN_TTL_DAYS", 30i64),
            database_path: env_or("DSH_GATEWAY_DATABASE", "dsh-gateway.db"),
            tunnel_port_min: env_parse("DSH_GATEWAY_TUNNEL_PORT_MIN", TUNNEL_PORT_MIN),
            tunnel_port_max: env_parse("DSH_GATEWAY_TUNNEL_PORT_MAX", TUNNEL_PORT_MAX),
        }
    }

    /// 默认隧道端口(从 upstream_addr 尾部解析)。
    pub fn default_tunnel_port(&self) -> u16 {
        self.upstream_addr
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or(self.tunnel_port_min)
    }
}
