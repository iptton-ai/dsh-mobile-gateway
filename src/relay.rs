// 上游中转:把通过鉴权的请求原样送往 dsh(经 SSH 反向隧道)。
//
// 两个面:
// - 普通 HTTP(POST /api/*、GET 导出流):hyper client conn 逐请求建连
//   (TCP 与 Unix socket 双模),请求/响应体全程流式不落盘。
// - WebSocket upgrade(/api/events.mux、/api/events.host):对上游手写 HTTP/1.1
//   升级握手,拿到 101 后对下游同样回 101,之后裸管双向拷贝。
//
// 上游落点形态(resolve_upstream):
// - 令牌绑定端口 N,且 DSH_GATEWAY_TUNNEL_SOCK_DIR 里存在 tunnel-N.sock →
//   Unix socket(隧道 ssh -R 直落 socket,目录/属主权限即访问控制);
// - 否则 TCP 127.0.0.1:N(经典 ssh -R 端口转发)。切换期双模并存,socket
//   出现即自动采用,无需重启网关。
// HTTP 侧逐请求建连是有意为之:回环/UDS 建连代价极小,换掉连接池复杂度;
// 双下行 WS 本就是长连接,不受影响。
//
// 关键点:Host 头改写为 dsh 的 loopback authority —— dsh 的信任围栏按 Host 判定,
// 隧道出口的 TCP 来源本就是 loopback(sshd 本地转发),Host 改写后整条链路在
// dsh 看来与桌面同机客户端无异(特权方法也随之可用;安全性由本网关的鉴权把守)。
use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderName, HeaderValue, Response, StatusCode},
};
use hyper::upgrade::OnUpgrade;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use gateway_shared::error::{AppError, AppResult};

use crate::AppState;

/// 读写的合一 trait(Rust trait object 不允许多主 trait,包一层)。
pub trait Io: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> Io for T {}

/// 上游连接的装箱类型:TCP 与 Unix socket 统一。
pub type BoxedIo = Box<dyn Io + Unpin + Send>;

/// 单次请求的上游目标。
#[derive(Clone, Debug)]
pub enum UpstreamTarget {
    Tcp(String),
    Unix(PathBuf),
}

/// 目标拨号(TCP / Unix socket;HTTP 与 WS 共用)。
async fn connect_target(target: &UpstreamTarget) -> std::io::Result<BoxedIo> {
    match target {
        UpstreamTarget::Tcp(addr) => Ok(Box::new(TcpStream::connect(addr).await?) as BoxedIo),
        UpstreamTarget::Unix(path) => Ok(Box::new(UnixStream::connect(path).await?) as BoxedIo),
    }
}

/// RFC 7230 hop-by-hop 头,转发时丢弃(帧结构由本层自建)。
fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "x-forwarded-for"
            | "x-forwarded-proto"
            | "x-real-ip"
    )
}

fn is_websocket_upgrade(req: &Request) -> bool {
    let conn_upgrade = req
        .headers()
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);
    let ws = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    conn_upgrade && ws
}

fn relay_error(status: StatusCode, msg: &str) -> Response<Body> {
    let body = serde_json::json!({ "error": msg });
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("static response")
}

/// 解析本次请求的上游:配对令牌绑定端口 → 该 Mac 的隧道口
/// (UDS socket 存在优先,否则 TCP);密码登录令牌(无绑定)→ 配置默认上游。
fn resolve_upstream(state: &Arc<AppState>, device: &crate::auth::AuthedDevice) -> UpstreamTarget {
    match device.upstream_port {
        Some(port) => {
            if let Some(sock) = tunnel_sock(state, port) {
                return UpstreamTarget::Unix(sock);
            }
            UpstreamTarget::Tcp(format!("127.0.0.1:{port}"))
        }
        None => default_upstream_target(state),
    }
}

/// 端口 N 的隧道 UDS 路径(sock 目录配置了且 socket 已落地才算)。
fn tunnel_sock(state: &Arc<AppState>, port: u16) -> Option<PathBuf> {
    let dir = state.config.tunnel_sock_dir.as_ref()?;
    let path = PathBuf::from(dir).join(format!("tunnel-{port}.sock"));
    path.exists().then_some(path)
}

/// 默认上游(healthz / 无绑定令牌):upstream_addr 的端口若有对应
/// tunnel-{N}.sock 则优先 UDS,否则按配置 TCP 直连。
fn default_upstream_target(state: &Arc<AppState>) -> UpstreamTarget {
    let port = state
        .config
        .upstream_addr
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok());
    if let Some(port) = port {
        if let Some(sock) = tunnel_sock(state, port) {
            return UpstreamTarget::Unix(sock);
        }
    }
    UpstreamTarget::Tcp(state.config.upstream_addr.clone())
}

/// WS 在线计数 RAII:构造即 +1,Drop 即减(下限 0)。
/// 握手失败/上游拒绝升级等提前退出同样经过 Drop,计数不会悬挂。
struct WsPresenceGuard {
    state: Arc<AppState>,
    jti: String,
}

impl WsPresenceGuard {
    fn enter(state: Arc<AppState>, jti: &str) -> Self {
        {
            let mut m = state.ws_sessions.lock().unwrap();
            *m.entry(jti.to_string()).or_insert(0) += 1;
        }
        Self { state, jti: jti.to_string() }
    }
}

impl Drop for WsPresenceGuard {
    fn drop(&mut self) {
        let mut m = self.state.ws_sessions.lock().unwrap();
        if let Some(n) = m.get_mut(&self.jti) {
            *n = n.saturating_sub(1);
        }
        if m.get(&self.jti).copied() == Some(0) {
            m.remove(&self.jti);
        }
    }
}

/// 中转入口:WS upgrade 与普通 HTTP 分流。
pub async fn relay_handler(
    State(state): State<Arc<AppState>>,
    device: crate::auth::AuthedDevice,
    req: Request,
) -> Response<Body> {
    let upstream = resolve_upstream(&state, &device);
    if is_websocket_upgrade(&req) {
        // 计数随连接生命周期:成功路径 guard 移交 pipe 任务,断开时 Drop;
        // 失败路径在本次调用栈内 Drop。
        let presence = WsPresenceGuard::enter(state.clone(), &device.jti);
        match relay_websocket(&state, &upstream, req, presence).await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::warn!("ws relay failed: {e:#}");
                relay_error(StatusCode::BAD_GATEWAY, "upstream websocket unavailable")
            }
        }
    } else {
        match relay_http(&state, &upstream, req).await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::warn!("http relay failed: {e:#}");
                // 隧道断开/宿主离线时给客户端一个可识别的 502。
                relay_error(StatusCode::BAD_GATEWAY, "upstream unavailable")
            }
        }
    }
}

/// 普通 HTTP 流式转发:逐请求对上游建连(hyper client conn,TCP/UDS 双模)。
async fn relay_http(
    state: &Arc<AppState>,
    upstream: &UpstreamTarget,
    req: Request,
) -> AppResult<Response<Body>> {
    let (mut parts, body) = req.into_parts();
    // URI 只保留 path+query(authority 是下游侧信息,对上游无意义)。
    parts.uri = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().parse().unwrap_or_default())
        .unwrap_or_else(|| "/".parse().unwrap());

    // Host 改写为 dsh 的 loopback authority;网关 Bearer 令牌到此为止:
    // dsh 围栏不消费它,透传只会把 30 天设备令牌泄进上游进程的内存/日志。
    // WS 路径天然不带(只转 sec-websocket-* 头)。
    let mut out_headers = axum::http::HeaderMap::new();
    if let Ok(hv) = HeaderValue::from_str(&state.config.upstream_host) {
        out_headers.insert(header::HOST, hv);
    }
    for (name, value) in parts.headers.iter() {
        if is_hop_by_hop(name) || name == header::AUTHORIZATION {
            continue;
        }
        out_headers.append(name, value.clone());
    }
    parts.headers = out_headers;

    // 建连 + 握手 + 发送(连接驱动任务随响应结束自然回收)。
    let io = connect_target(upstream)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("upstream connect: {e}")))?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(io))
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("upstream handshake: {e}")))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let out = hyper::Request::from_parts(parts, body);
    let resp = sender
        .send_request(out)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("upstream request failed: {e}")))?;

    let (resp_parts, incoming) = resp.into_parts();
    let mut builder = Response::builder().status(resp_parts.status);
    for (name, value) in resp_parts.headers.iter() {
        if is_hop_by_hop(name) {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder
        .body(Body::new(incoming))
        .map_err(|e| AppError::Internal(anyhow::anyhow!("response build: {e}")))
}

/// WebSocket 双向中转:对上游手写握手,下游回 101,裸管拷贝。
/// `presence` 随成功路径移入 pipe 任务(连接存续期间保持计数);
/// 一切提前返回路径由 Drop 兜底减数。
async fn relay_websocket(
    state: &Arc<AppState>,
    upstream: &UpstreamTarget,
    req: Request,
    presence: WsPresenceGuard,
) -> AppResult<Response<Body>> {
    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let headers = req.headers().clone();
    let on_upgrade = hyper::upgrade::on(req);

    // 1. 连上游隧道口(TCP 或 UDS)。
    let mut upstream = connect_target(upstream)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("upstream connect: {e}")))?;

    // 2. 手写 HTTP/1.1 升级请求(Host 必须是 loopback authority)。
    let mut handshake = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n",
        method, path, state.config.upstream_host
    );
    for (name, value) in headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if is_hop_by_hop(name) && lower != "sec-websocket-extensions" {
            continue;
        }
        if !lower.starts_with("sec-websocket-") {
            continue;
        }
        if let Ok(v) = value.to_str() {
            handshake.push_str(&format!("{}: {}\r\n", name.as_str(), v));
        }
    }
    handshake.push_str("\r\n");
    upstream
        .write_all(handshake.as_bytes())
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("upstream write: {e}")))?;

    // 3. 读上游响应头(到 \r\n\r\n)。
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    let head_end;
    loop {
        let n = upstream
            .read(&mut chunk)
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("upstream read: {e}")))?;
        if n == 0 {
            return Err(AppError::Internal(anyhow::anyhow!(
                "upstream closed before handshake completed"
            )));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_head_end(&buf) {
            head_end = pos;
            break;
        }
        if buf.len() > 64 * 1024 {
            return Err(AppError::Internal(anyhow::anyhow!(
                "upstream handshake head too large"
            )));
        }
    }
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let status_line = head.lines().next().unwrap_or_default();
    if !status_line.contains("101") {
        // 非 101(如 dsh 围栏 403):原样把状态带给下游。
        let code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(502);
        let msg = status_line.to_string();
        return Ok(relay_error(
            StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY),
            &msg,
        ));
    }

    // 4. 给下游回 101(Upgrade/Connection 已定值;只透传上游的握手应答头)。
    let mut builder = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "Upgrade");
    for line in head.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let lower = name.to_ascii_lowercase();
            if matches!(
                lower.as_str(),
                "date" | "server" | "content-length" | "connection" | "upgrade"
            ) {
                continue;
            }
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value.trim()),
            ) {
                builder = builder.header(hn, hv);
            }
        }
    }
    let resp = builder
        .body(Body::empty())
        .map_err(|e| AppError::Internal(anyhow::anyhow!("101 build: {e}")))?;

    // 5. 双向裸管拷贝(升级完成后 hyper 把控制权交给我们)。
    let leftover = buf[head_end + 4..].to_vec();
    tokio::spawn(pipe_after_upgrade(on_upgrade, upstream, leftover, presence));
    Ok(resp)
}

async fn pipe_after_upgrade(
    on_upgrade: OnUpgrade,
    mut upstream: BoxedIo,
    leftover: Vec<u8>,
    // 下划线命名:仅靠存活到任务结束持有计数(Drop 即减),不显式读取。
    _presence: WsPresenceGuard,
) {
    let downstream = match on_upgrade.await {
        Ok(up) => up,
        Err(e) => {
            tracing::debug!("downstream upgrade not completed: {e}");
            let _ = upstream.shutdown().await;
            return;
        }
    };
    let mut down = hyper_util::rt::TokioIo::new(downstream);
    if !leftover.is_empty() {
        if let Err(e) = down.write_all(&leftover).await {
            tracing::debug!("ws relay: leftover write: {e}");
            return;
        }
    }
    // 两侧都已适配 tokio IO,直接对拷。
    match tokio::io::copy_bidirectional(&mut down, &mut upstream).await {
        Ok(_) => tracing::debug!("ws relay: closed"),
        Err(e) => tracing::debug!("ws relay ended: {e}"),
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// healthz:探测默认上游隧道口是否可连(TCP 或 UDS;不鉴权;只暴露布尔)。
pub async fn healthz(State(state): State<Arc<AppState>>) -> Response<Body> {
    let upstream_ok = connect_target(&default_upstream_target(&state))
        .await
        .is_ok();
    let body = serde_json::json!({ "ok": true, "upstream": upstream_ok });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("static response")
}
