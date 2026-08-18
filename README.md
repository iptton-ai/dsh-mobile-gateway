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

## Web 面(浏览器远程访问 dsh web)

独立监听口(默认 `127.0.0.1:8104`,nginx 按 server_name 分流;样例
[deploy/nginx-web.conf.example](deploy/nginx-web.conf.example)):密码登录页
(argon2)→ HttpOnly 签名 cookie(12h,SameSite=Strict)→ 复用中转管道到达
dsh(Host 改写 loopback 语义同 App 面)。dsh web 零改动、与 App 令牌体系
完全独立。详见客户端仓库 `docs/REMOTE-WEB-ACCESS.md`。

| 变量 | 说明 | 默认 |
|---|---|---|
| `DSH_GATEWAY_WEB_HOSTNAME` | Web 面公网主机名(CSRF Origin 比对) | 空 |
| `DSH_GATEWAY_WEB_BIND` / `DSH_GATEWAY_WEB_PORT` | Web 面监听 | 127.0.0.1 / 8104 |
| `DSH_GATEWAY_WEB_PASSWORD_HASH` | argon2 哈希 env 兜底;首选 DB | 空=仅 DB |
| `DSH_GATEWAY_WEB_UPSTREAM_PORT` | Web 面钉住的隧道端口 | 默认上游 |

密码管理走管理面 `/admin/web/password`(GET 状态 / POST `{password}` 明文
或 `{hash}` / `{clear:true}` 关闭)—— 经 ssh 调用,Mac 侧 dsh-mobile 插件
「移动接入」dialog 可直接改密,改密即全量旧会话失效(版本号入签名域)。
未配密码时 Web 面全路由 404(fail-closed)。

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
## 多宿主 / 多租户(004 迁移,2026-08-18)

一个网关实例可服务 **N 台 dsh 宿主**(同一运营者)与 **多个租户**(各自
拥有互不相交的宿主集合)。旧单运营者部署零迁移:未登记租户时公开面
`/admin/*` 恒 401,行为与 004 之前完全一致。

### 信任模型

- **运营者**(`default` 租户,不出现在 tenants 表):管理面 :8103
  (loopback + env token / ssh)—— 跨租户超管,可建租户、登记宿主、吊销任意令牌;
- **显式租户**(tenants 表 + 独立管理密钥):经**公开面** `/admin/*`
  以 `Authorization: Bearer <租户密钥>` 访问,claim/status/tokens/revoke
  全部围栏在本租户(限速 300 次/5min/IP,密钥 sha256 入库、明文只在创建
  响应出现一次)。

### 运营者管理面(仅 :8103)

```
POST /admin/tenants           {name}          → {id, admin_key}(密钥只回显一次)
GET  /admin/tenants                           → 租户清单
POST /admin/tenants/revoke    {id}            → 吊销租户(其密钥即刻失效)
POST /admin/hosts             {tenant_id, port, label}  → 宿主登记(端口全局唯一)
GET  /admin/hosts                             → 宿主清单
POST /admin/hosts/remove      {id}            → 删除登记(端口回到未登记态)
```

### 宿主端口归属仲裁(claim)

- 端口**已登记**:必须归属当前租户且启用,否则 403(撞端口=流量串台,
  登记表是唯一仲裁者 —— 显式租户不能 claim 别家端口);
- 端口**未登记**:仅运营者/default 沿用范围白名单(13100–13199,
  单运营者旧语义);显式租户必须先登记宿主,否则 403;
- 配对可带租户锚定(QR 邀请 `t=` → `/pair/start` 的 `tenant` 字段):
  跨租户 claim 按「无人在等」404 拒绝,poll 只显示该租户的 offers;
  开放配对(手输)靠手机端人工核对主机码把关,confirm 再做一次租户一致性
  深度防御。

### 租户数据面与设备端点围栏

- `/auth/devices` 只列本租户令牌;`/auth/revoke` 只能吊销本租户 jti
  (跨租户/未知同样返回 `revoked:false`,不给探测面);
- `/pair/confirm` 响应新增 `host_ref`(隧道端口字符串):App 主机簿复合键,
  同网关多宿主 = 不同条目;
- 租户的 Mac 侧数据隧道仍是 `ssh -R`(推荐每租户一个受限 ssh 账号 +
  sshd `Match` 块 `PermitListen` 钉死本宿主端口);控制面可走公开面
  HTTPS 直连(dsh-mobile 插件配 `adminUrl` + 租户密钥,免 ssh)。

### 已知边界(有意保留)

- Web 面(:8104)仍为运营者单宿主形态(`DSH_GATEWAY_WEB_UPSTREAM_PORT`
  钉死单端口);多租户 Web 面待后续按需开发;
- 密码登录令牌恒属 default 租户(多租户部署建议禁用密码登录);
- 131xx 端口本身的最终防线是服务器 ssh 层:能 bind 端口的进程即上游 ——
  运营者应保证服务器登录面仅限自己(租户只给受限 ssh 账号)。
