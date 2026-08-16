// 配对面(M6.1):手机发起亮码 → Mac 侧 pair.sh 亮主机码应约 →
// 手机端列出全部 offers 人工比对主机码点选 → 令牌绑定该 Mac 的隧道端口。
//
// 抢注防御(三层):
// 1. code_d 存活 pending 唯一(后到同码 start → 409,抄码者只能拿到被废弃的码);
// 2. 双向亮码:claim 不自动成交,手机端必须人工点选「主机码与 Mac 终端一致」的 offer;
// 3. claim 单次消费 + 短 TTL;pair.sh 侧完成回显设备名(不对劲即 revoke)。
use axum::{
    extract::State,
    http::HeaderMap,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use gateway_shared::error::{AppError, AppResult};
use gateway_shared::jwt::encode_jwt;

use crate::auth::{client_ip, GatewayClaims};
use crate::db::ClaimRow;
use crate::AppState;

/// pending 配对存活期(手机亮码等人来输,给足输入时间)。
pub const PAIRING_TTL_SECS: i64 = 600;
/// offer 存活期(亮码后一直没人确认就作废)。
pub const CLAIM_TTL_SECS: i64 = 300;

/// 手机亮码字符集(Crockford 风格,去易混字符);10 字符 ≈ 50 bit。
const CODE_CHARS: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

// ── 请求/响应模型 ────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PairStartRequest {
    /// 手机生成并显示的配对码(10 位,防抢注的唯一键)。
    pub code: String,
    /// 手机生成的配对秘密(不显示;poll/confirm 必须出示)。
    pub secret: String,
    #[serde(default)]
    pub device: String,
}

#[derive(Serialize)]
pub struct PairStartResponse {
    pub pairing_id: String,
    pub expires_at: i64,
}

#[derive(Deserialize)]
pub struct PairPollRequest {
    pub pairing_id: String,
    pub secret: String,
}

#[derive(Serialize)]
pub struct PairOffer {
    pub claim_id: String,
    /// Mac 终端上显示的主机码 —— 人工比对这个。
    pub host_code: String,
    pub host_label: String,
    pub upstream_port: u16,
    pub expires_at: i64,
}

#[derive(Serialize)]
pub struct PairPollResponse {
    pub status: String, // waiting | offers | confirmed | expired
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub offers: Vec<PairOffer>,
}

#[derive(Deserialize)]
pub struct PairConfirmRequest {
    pub pairing_id: String,
    pub secret: String,
    pub claim_id: String,
    /// 人工核对后回传的主机码(必须与 offer 一致)。
    pub host_code: String,
}

#[derive(Serialize)]
pub struct PairConfirmResponse {
    pub token: String,
    pub expires_at: i64,
    /// 令牌绑定的来源机器(回显给手机端人工核对)。
    pub host_label: String,
}

#[derive(Deserialize)]
pub struct AdminClaimRequest {
    /// 手机屏幕上的配对码(人工输入)。
    pub code: String,
    /// Mac 本地生成并在终端显示的主机码(dsh 侧发出,服务器不生成)。
    pub host_code: String,
    #[serde(default)]
    pub host_label: String,
    /// 本机隧道端口(多机部署各占一个;缺省 = 配置默认)。
    #[serde(default)]
    pub port: Option<u16>,
}

#[derive(Serialize)]
pub struct AdminClaimResponse {
    pub claim_id: String,
    pub device: String,
    pub host_code: String,
    pub port: u16,
    pub expires_at: i64,
}

// ── 校验 ────────────────────────────────────────────────────────────────

fn valid_code_d(code: &str) -> bool {
    code.len() == 10 && code.bytes().all(|b| CODE_CHARS.contains(&b))
}

fn valid_host_code(code: &str) -> bool {
    let c = code.strip_prefix('-').unwrap_or(code);
    (c.len() == 6 || c.len() == 7) && c.bytes().all(|b| CODE_CHARS.contains(&b))
}

fn valid_secret(s: &str) -> bool {
    (32..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

// ── 公开面(经 nginx)────────────────────────────────────────────────────

pub async fn start_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<PairStartRequest>,
) -> AppResult<Json<PairStartResponse>> {
    let ip = client_ip(&headers);
    if !state.pair_limiter.allow(&ip) {
        return Err(AppError::Conflict("too many pairing attempts, retry later".into()));
    }
    let code = req.code.trim().to_ascii_uppercase().replace(['-', ' ', ':'], "");
    if !valid_code_d(&code) {
        return Err(AppError::BadRequest("code must be 10 chars (A-Z minus I,L,O + 2-9)".into()));
    }
    if !valid_secret(&req.secret) {
        return Err(AppError::BadRequest("secret must be 32-128 alphanumerics".into()));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let expires_at = Utc::now().timestamp() + PAIRING_TTL_SECS;
    // 同码存活 pending 唯一:后到者 409(手机端换码重试)。
    state
        .db
        .pairing_insert(&id, &code, &req.secret, &req.device, PAIRING_TTL_SECS)
        .map_err(|_| AppError::Conflict("code already in use; generate a new one".into()))?;
    tracing::info!(ip = %ip, code = %code, "pairing started");
    Ok(Json(PairStartResponse { pairing_id: id, expires_at }))
}

pub async fn poll_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PairPollRequest>,
) -> AppResult<Json<PairPollResponse>> {
    let Some(p) = state.db.pairing_get(&req.pairing_id) else {
        return Err(AppError::NotFound("unknown pairing".into()));
    };
    if p.secret != req.secret {
        return Err(AppError::Unauthorized);
    }
    if p.status == "expired" || p.expires_at < Utc::now().timestamp() {
        return Ok(Json(PairPollResponse { status: "expired".into(), offers: vec![] }));
    }
    if p.status == "confirmed" {
        return Ok(Json(PairPollResponse { status: "confirmed".into(), offers: vec![] }));
    }
    let offers: Vec<PairOffer> = state
        .db
        .claims_for(&p.code_d)
        .into_iter()
        .map(|c: ClaimRow| PairOffer {
            claim_id: c.id,
            host_code: c.host_code,
            host_label: c.host_label,
            upstream_port: c.upstream_port,
            expires_at: c.expires_at,
        })
        .collect();
    if offers.is_empty() {
        Ok(Json(PairPollResponse { status: "waiting".into(), offers: vec![] }))
    } else {
        Ok(Json(PairPollResponse { status: "offers".into(), offers }))
    }
}

pub async fn confirm_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<PairConfirmRequest>,
) -> AppResult<Json<PairConfirmResponse>> {
    let ip = client_ip(&headers);
    if !state.pair_limiter.allow(&ip) {
        return Err(AppError::Conflict("too many attempts, retry later".into()));
    }
    let Some(p) = state.db.pairing_get(&req.pairing_id) else {
        return Err(AppError::NotFound("unknown pairing".into()));
    };
    if p.secret != req.secret {
        return Err(AppError::Unauthorized);
    }
    if p.status != "pending" || p.expires_at < Utc::now().timestamp() {
        return Err(AppError::BadRequest("pairing no longer active".into()));
    }
    let Some(claim) = state.db.claim_get(&req.claim_id) else {
        return Err(AppError::NotFound("unknown claim".into()));
    };
    if claim.pairing_code != p.code_d || claim.status != "offered" {
        return Err(AppError::BadRequest("claim not applicable".into()));
    }
    if claim.expires_at < Utc::now().timestamp() {
        return Err(AppError::BadRequest("claim expired".into()));
    }
    // 人工比对凭证:回传的主机码必须与 offer 一致(大小写/连字符宽容)。
    let echo = req.host_code.trim().to_ascii_uppercase().replace(['-', ' ', ':'], "");
    if echo != claim.host_code {
        return Err(AppError::BadRequest("host code mismatch".into()));
    }
    // 单次消费:并发 confirm 只成一个。
    if !state.db.claim_consume(&req.claim_id) {
        return Err(AppError::Conflict("claim already consumed".into()));
    }
    let jti = uuid::Uuid::new_v4().to_string();
    state.db.pairing_set_status(&req.pairing_id, "confirmed");
    state.db.pairing_set_token(&req.pairing_id, &jti);
    let now = Utc::now();
    let exp = (now + chrono::Duration::days(state.config.token_ttl_days)).timestamp();
    let claims = GatewayClaims {
        sub: "dsh-client".into(),
        jti: jti.clone(),
        device: p.device.clone(),
        iat: now.timestamp(),
        exp,
    };
    let token = encode_jwt(&claims, &state.config.jwt_secret)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("jwt encode: {e}")))?;
    state
        .db
        .insert(&jti, &p.device, Some(claim.upstream_port), &claim.host_label)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("db insert: {e}")))?;
    tracing::info!(
        ip = %ip, jti = %jti, device = %p.device,
        host = %claim.host_label, port = claim.upstream_port,
        "paired (token bound to tunnel port)"
    );
    Ok(Json(PairConfirmResponse {
        token,
        expires_at: exp,
        host_label: claim.host_label,
    }))
}

// ── 管理面(仅 127.0.0.1 admin 监听;pair.sh 经 ssh 调用)─────────────────

pub async fn admin_claim_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AdminClaimRequest>,
) -> AppResult<Json<AdminClaimResponse>> {
    let code = req.code.trim().to_ascii_uppercase().replace(['-', ' ', ':'], "");
    if !valid_code_d(&code) {
        return Err(AppError::BadRequest("code must be 10 chars".into()));
    }
    let host_code = req.host_code.trim().to_ascii_uppercase().replace(['-', ' ', ':'], "");
    if !valid_host_code(&host_code) {
        return Err(AppError::BadRequest("host_code must be 6-7 chars".into()));
    }
    let port = req.port.unwrap_or_else(|| state.config.default_tunnel_port());
    if !(state.config.tunnel_port_min..=state.config.tunnel_port_max).contains(&port) {
        return Err(AppError::BadRequest(format!(
            "tunnel port must be {}-{}",
            state.config.tunnel_port_min, state.config.tunnel_port_max
        )));
    }
    // 必须有手机在等这个码(不创建悬空 offer)。
    let Some(pending) = state.db.pairing_by_code(&code) else {
        return Err(AppError::NotFound("no phone waiting with this code".into()));
    };
    let id = uuid::Uuid::new_v4().to_string();
    let host_label = if req.host_label.is_empty() {
        "mac".to_string()
    } else {
        req.host_label.chars().take(32).collect()
    };
    state
        .db
        .claim_insert(&id, &code, &host_code, &host_label, port, CLAIM_TTL_SECS)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("claim insert: {e}")))?;
    tracing::info!(code = %code, host = %host_label, port, "pair claim offered");
    Ok(Json(AdminClaimResponse {
        claim_id: id,
        device: pending.device,
        host_code,
        port,
        expires_at: Utc::now().timestamp() + CLAIM_TTL_SECS,
    }))
}

/// 管理面兜底撤销:pair.sh 发现配对到的设备不对时一键吊销其令牌。
#[derive(Deserialize)]
pub struct AdminRevokeRequest {
    pub jti: String,
}

pub async fn admin_revoke_token_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AdminRevokeRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let ok = state
        .db
        .revoke(&req.jti)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("db revoke: {e}")))?;
    tracing::warn!(jti = %req.jti, ok, "admin revoke-token");
    Ok(Json(serde_json::json!({ "revoked": ok })))
}

/// pair.sh 轮询:配对是否被手机确认(完成时回显设备名供人眼核对)。
pub async fn admin_status_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> AppResult<Json<serde_json::Value>> {
    let Some(code) = q.get("code") else {
        return Err(AppError::BadRequest("code required".into()));
    };
    let code = code.trim().to_ascii_uppercase().replace(['-', ' ', ':'], "");
    let Some((p, token)) = state.db.pairing_status_with_token(&code) else {
        return Err(AppError::NotFound("no pairing with this code".into()));
    };
    Ok(Json(serde_json::json!({
        "status": p.status,
        "device": p.device,
        "confirmed": p.status == "confirmed",
        "token": token.map(|t| serde_json::json!({
            "jti": t.jti,
            "device": t.device,
            "host_label": t.host_label,
            "upstream_port": t.upstream_port,
            "revoked": t.revoked,
            "created_at": t.created_at,
        })),
    })))
}

/// 管理面令牌清单(pair.sh 异常撤销提示的可操作化)。
/// 每行附 `connected`:该令牌当前是否持有下行 WS(在线)—— 侧栏在线指示器数据源。
pub async fn admin_tokens_handler(
    State(state): State<Arc<AppState>>,
) -> AppResult<Json<serde_json::Value>> {
    let rows = state
        .db
        .list()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("db list: {e}")))?;
    let online = state.ws_online();
    let out = rows
        .into_iter()
        .map(|r| {
            let mut v = serde_json::to_value(&r)
                .map_err(|e| AppError::Internal(anyhow::anyhow!("serialize token: {e}")))?;
            v["connected"] = serde_json::Value::Bool(online.contains(&r.jti));
            Ok(v)
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    Ok(Json(serde_json::Value::Array(out)))
}

// ── 扫码配对(M6.2):终端 QR(管理面)+ 系统相机落地页(公开面) ────────────

#[derive(Deserialize)]
pub struct AdminQrRequest {
    /// 编码进二维码的文本(pair.sh 拼好的邀请 URL)。
    pub text: String,
}

/// 管理面:文本 → 半块字符二维码。服务端包 ANSI 黑字白底 —— 终端主题无关,
/// 手机相机看到的始终是标准极性(黑模块/白底)。pair.sh 经 ssh 调用,公网不可达。
pub async fn admin_qr_handler(
    Json(req): Json<AdminQrRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let text = req.text.trim();
    if text.is_empty() || text.len() > 512 {
        return Err(AppError::BadRequest("text must be 1-512 bytes".into()));
    }
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M)
        .map_err(|e| AppError::BadRequest(format!("qr encode failed: {e}")))?;
    let width = code.width();
    let colors = code.to_colors();
    let is_dark = |x: i32, y: i32| -> bool {
        let (mx, my) = (x - 2, y - 2); // 四周 2 模块静区
        if mx < 0 || my < 0 || mx >= width as i32 || my >= width as i32 {
            return false;
        }
        colors[my as usize * width + mx as usize] == qrcode::types::Color::Dark
    };
    let total = width as i32 + 4;
    let mut lines: Vec<String> = Vec::new();
    let mut y = 0;
    while y < total {
        let mut line = String::new();
        for x in 0..total {
            let top = is_dark(x, y);
            let bottom = y + 1 < total && is_dark(x, y + 1);
            line.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        lines.push(line);
        y += 2;
    }
    let qr = format!("\x1b[30;47m{}\x1b[0m", lines.join("\n"));
    tracing::debug!(bytes = text.len(), modules = width, "pair qr rendered");
    Ok(Json(serde_json::json!({ "modules": width, "qr": qr })))
}

/// 公开落地页:手机系统相机扫终端 QR 后到达。展示邀请码 + 一键复制,回到
/// singleman 粘贴即完成配对发起。纯静态、零外部资源、fragment 不出浏览器。
pub async fn pair_page_handler() -> axum::response::Response {
    use axum::response::IntoResponse;
    let html = r#"<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>DSH 配对</title>
<style>
 body{font-family:system-ui,-apple-system,sans-serif;background:#111;color:#eee;max-width:480px;margin:0 auto;padding:24px 16px;text-align:center}
 .code{font-size:38px;font-weight:700;letter-spacing:4px;margin:8px 0;font-family:ui-monospace,monospace}
 .host{font-size:26px;letter-spacing:3px;color:#7fd38a;font-family:ui-monospace,monospace}
 .card{background:#1d1d1f;border-radius:14px;padding:18px;margin:14px 0}
 button{width:100%;padding:14px;font-size:16px;border:none;border-radius:12px;background:#2f6fed;color:#fff}
 .hint{color:#999;font-size:13px;line-height:1.7}
</style></head><body>
<div id="app" class="card">正在读取邀请信息…</div>
<div class="hint">此页由网关静态提供,邀请信息只在本机浏览器解析,不上传服务器。</div>
<script>
const q=new URLSearchParams(location.hash.startsWith('#')?location.hash.slice(1):location.hash);
const norm=s=>(s||'').toUpperCase().replace(/[^A-Z0-9]/g,'');
const c=norm(q.get('c')),h=norm(q.get('h'));
const l=(q.get('l')||'').replace(/[^A-Za-z0-9 _.\-]/g,'').slice(0,32);
const app=document.getElementById('app');
if(c.length!==10){app.innerHTML='邀请链接无效或已损坏。<br>请回 Mac 终端重新运行 pair.sh 后再扫。';}
else{
 const fmt=c.slice(0,5)+'-'+c.slice(5);
 const hh=h.length>=6?h.slice(0,3)+'-'+h.slice(3,6):'';
 app.innerHTML='<div class="hint">配对码</div><div class="code">'+fmt+'</div>'+
  (hh?'<div class="hint">锚定主机码</div><div class="host">'+hh+'</div>':'')+
  (l?'<div class="hint">'+l+'</div>':'')+
  '</div><button id="cp">复制配对信息,回到 singleman 粘贴</button>'+
  '<div class="hint" style="margin-top:14px">打开 singleman App → 配对页 → 点地址栏右侧粘贴按钮</div>';
 document.getElementById('cp').onclick=()=>navigator.clipboard.writeText(location.href)
  .then(()=>{document.getElementById('cp').textContent='✅ 已复制,请回到 singleman 粘贴';});
}
</script></body></html>"#;
    (
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        axum::response::Html(html.to_string()),
    )
        .into_response()
}

