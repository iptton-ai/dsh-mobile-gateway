// 上游中转:把通过鉴权的请求原样送往 dsh(经 SSH 反向隧道)。
//
// 两个面:
// - 普通 HTTP(POST /api/*、GET 导出流):reqwest 流式转发,请求/响应体都不落盘。
// - WebSocket upgrade(/api/events.mux、/api/events.host):对上游手写 HTTP/1.1
//   升级握手,拿到 101 后对下游同样回 101,之后裸管双向拷贝。
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
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use gateway_shared::error::{AppError, AppResult};

use crate::AppState;

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

/// 解析本次请求的上游:配对令牌绑定端口 → 该 Mac 的隧道口;
/// 密码登录令牌(无绑定)→ 配置默认上游。
fn resolve_upstream(state: &Arc<AppState>, device: &crate::auth::AuthedDevice) -> String {
    match device.upstream_port {
        Some(port) => format!("127.0.0.1:{port}"),
        None => state.config.upstream_addr.clone(),
    }
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

/// 普通 HTTP 流式转发。
async fn relay_http(
    state: &Arc<AppState>,
    upstream: &str,
    req: Request,
) -> AppResult<Response<Body>> {
    let (parts, body) = req.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let url = format!("http://{}{}", upstream, path);

    let mut out = state
        .http
        .request(parts.method, &url)
        .header(header::HOST, state.config.upstream_host.as_str());
    for (name, value) in parts.headers.iter() {
        if is_hop_by_hop(name) {
            continue;
        }
        // 网关 Bearer 令牌到此为止:dsh 围栏不消费它,透传只会把 30 天
        // 设备令牌泄进上游进程的内存/日志。WS 路径天然不带(只转
        // sec-websocket-* 头)。
        if name == header::AUTHORIZATION {
            continue;
        }
        out = out.header(name, value);
    }
    let stream = body.into_data_stream();
    let req_body = reqwest::Body::wrap_stream(stream);
    let out = out.body(req_body);

    let resp = out.send().await.map_err(|e| {
        AppError::Internal(anyhow::anyhow!("upstream request failed: {e}"))
    })?;

    let mut builder = Response::builder().status(resp.status());
    for (name, value) in resp.headers().iter() {
        if is_hop_by_hop(name) {
            continue;
        }
        builder = builder.header(name, value);
    }
    let body = Body::from_stream(resp.bytes_stream());
    builder
        .body(body)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("response build: {e}")))
}

/// WebSocket 双向中转:对上游手写握手,下游回 101,裸管拷贝。
/// `presence` 随成功路径移入 pipe 任务(连接存续期间保持计数);
/// 一切提前返回路径由 Drop 兜底减数。
async fn relay_websocket(
    state: &Arc<AppState>,
    upstream_addr: &str,
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

    // 1. 连上游隧道口。
    let mut upstream = TcpStream::connect(upstream_addr)
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
    mut upstream: TcpStream,
    leftover: Vec<u8>,
    presence: WsPresenceGuard,
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
    // 上游 TcpStream 本就是 tokio IO,无需桥接;down 侧才需要 hyper→tokio 桥。
    match tokio::io::copy_bidirectional(&mut down, &mut upstream).await {
        Ok(_) => tracing::debug!("ws relay: closed"),
        Err(e) => tracing::debug!("ws relay ended: {e}"),
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// healthz:探测上游隧道口是否可连(不鉴权;只暴露布尔)。
pub async fn healthz(State(state): State<Arc<AppState>>) -> Response<Body> {
    let upstream_ok = tokio::net::TcpStream::connect(&state.config.upstream_addr)
        .await
        .is_ok();
    let body = serde_json::json!({ "ok": true, "upstream": upstream_ok });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("static response")
}
