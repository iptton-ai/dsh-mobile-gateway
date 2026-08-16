# dsh-mobile-gateway

DeepSeek Harness 移动接入的服务端网关:密码/扫码配对鉴权 + HTTP/WebSocket
流式中转。手机 App 经它安全到达你 Mac 上跑的 dsh(绑 loopback,零改动)。

配套:

- Mac 侧 dsh 插件(隧道 + 扫码配对 UI):[dsh-mobile](https://github.com/iptton-ai/dsh-mobile)
- 移动客户端(Flutter):[DeepseekHarnessApp](https://github.com/iptton-ai/DeepseekHarnessApp)

## 架构

```
手机 App ─https→ 你的 TLS 反代(nginx/Caddy)→ 网关(公开面 :8102,配对+令牌+中转)
                                        网关管理面 :8103(仅 127.0.0.1,Mac 侧插件经 ssh 调用)
                  Mac(dsh 插件)←─ SSH 反向隧道(服务器 127.0.0.1:131xx → Mac dsh :3080)
```

- **鉴权**:扫码配对为主(双向亮码防抢注,令牌 30 天、SQLite 登记可吊销);
  密码登录(argon2)为可选兜底,不配置即禁用;
- **中转**:纯字节管道(HTTP 流式 + WS 手写握手裸管),dsh↔LLM 供应商流量不经服务器;
- **多机**:每台 Mac 一条隧道(13100–13199 端口段),令牌绑定来源端口按令牌路由。

## 部署(Docker,推荐)

```bash
cp .env.example .env && vi .env     # 必填 DSH_GATEWAY_JWT_SECRET(openssl rand -hex 32)
docker compose up -d                # :8102 公开 / :8103 管理面(仅容器内 loopback 映射宿主 127.0.0.1)
```

前面放你的 TLS 反代(WS upgrade + 流式透传;样例见 [deploy/nginx-site.conf.example](deploy/nginx-site.conf.example))。
裸机部署用 systemd([deploy/dsh-mobile-gateway.service.example](deploy/dsh-mobile-gateway.service.example))。

## 配置

全部环境变量见 [.env.example](.env.example);要点:

| 变量 | 说明 | 默认 |
|---|---|---|
| `DSH_GATEWAY_JWT_SECRET` | 令牌签名密钥(必填) | — |
| `DSH_GATEWAY_BIND` | 公开面绑定地址;裸机 + 同机 nginx 应设 127.0.0.1 | 0.0.0.0 |
| `DSH_GATEWAY_UPSTREAM` | 默认上游(SSH 隧道落地口) | 127.0.0.1:13100 |
| `DSH_GATEWAY_UPSTREAM_HOST` | 转发改写的 Host(dsh 信任围栏要求 loopback) | 127.0.0.1:3080 |
| `DSH_GATEWAY_TUNNEL_PORT_MIN/MAX` | 配对 claim 允许的隧道端口段 | 13100–13199 |
| `DSH_GATEWAY_PASSWORD_HASH` | 可选密码兜底(`--hash-password` 生成) | 空=仅配对 |

## 配对流程

Mac 上装 [dsh-mobile](https://github.com/iptton-ai/dsh-mobile) 插件(dsh web GUI 内
「📱 移动接入」→ 配对手机 → 出二维码);手机扫码 → 落地页「复制」→ App 粘贴 →
核对主机码点选即成。CLI 兜底:插件仓库内含 `pair.sh`。

## 安全模型

- 唯一公网暴露面:TLS 反代后的公开面(配对三接口 + 健康探测 + 鉴权中转);
- 管理面仅绑服务器 127.0.0.1 —— 「能发起配对 claim = 有服务器 ssh 权限」,信任根单一;
- 配对码 10 位(≈50bit)存活唯一、30 分钟不可复用;主机码 6 位由 Mac 本地生成;
- 登录/配对均有每 IP 限速;令牌可吊销(管理面或 App 内)。

## 开发

```bash
cargo test          # 19 项集成测试(配对/中转/Host 改写/WS/QR/限速/body 分层)
```

MIT License.