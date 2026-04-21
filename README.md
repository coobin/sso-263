# SSO 263

`SSO 263` 是一个很小的网关服务，用来把你自己的认证系统接到 263 企业邮箱的 WebMail SSO。

它最适合这样的场景：

- 已经有自己的统一认证入口
- 反向代理使用 `Nginx Proxy Manager`、`Nginx` 或其他支持转发认证头的网关
- 希望用户访问 `mail.example.com` 后，认证通过就直接进入 263 邮箱

当前项目优先支持两种认证接入方式：

- `trusted_headers`
  推荐给 `Authelia + Nginx Proxy Manager` 这类方案
- `exchange_code`
  推荐给你已经有自己认证后端、并且能提供一次性换码接口的场景

**工作流程**

`trusted_headers` 模式：

1. 用户访问 `https://mail.example.com`
2. 反向代理先交给认证系统校验是否已登录
3. 认证通过后，反向代理把 `Remote-User`、`Remote-Email`、`Remote-Name` 等头转发给 `SSO 263`
4. `SSO 263` 使用邮箱地址生成 263 SSO 跳转链接
5. 浏览器被 302 跳转到 263 WebMail 收件箱

`exchange_code` 模式：

1. 用户访问 `https://mail.example.com`
2. `SSO 263` 重定向到你的认证系统
3. 认证系统登录成功后回跳 `/auth/callback?code=...`
4. `SSO 263` 用 `code` 换取用户信息
5. `SSO 263` 生成 263 SSO 跳转链接

**路由**

- `GET /`
  主入口。已认证则跳转到 `/sso/mail`，否则等待上游认证或重定向到登录入口。
- `GET /auth/callback`
  `exchange_code` 模式使用的认证回调。
- `GET /sso/mail`
  生成 263 SSO 跳转链接并返回 `302`。
- `GET /debug/session`
  查看当前是否已经识别到登录用户，便于联调。
- `GET /healthz`
  健康检查。
- `GET /logout`
  清理本地会话 Cookie。

**环境变量**

可以直接复制 `.env.example` 作为起点。

最关键的变量有这些：

- `APP_BASE_URL`
  当前服务对外访问的完整地址，例如 `https://mail.example.com`
- `AUTH_MODE`
  可选 `trusted_headers` 或 `exchange_code`
- `AUTH_CORP_ID`
  263 企业域名，例如 `example.com`
- `PARTNER_ID`
  263 提供的合作商 ID
- `API_SECRET`
  263 提供的 SSO 密钥
- `SESSION_SECRET`
  用于本地签名 Cookie 的随机字符串

`trusted_headers` 模式额外依赖：

- `REMOTE_USER_HEADER`
- `REMOTE_EMAIL_HEADER`
- `REMOTE_NAME_HEADER`

`exchange_code` 模式额外依赖：

- `AUTH_LOGIN_URL`
- `AUTH_EXCHANGE_URL`
- `AUTH_EXCHANGE_TOKEN`

**快速开始**

1. 复制示例配置：

```bash
cp .env.example .env
```

2. 按你的环境修改 `.env`

3. 启动服务：

```bash
docker compose up -d --build
```

默认的 `docker-compose.yml` 只把端口绑定到 `127.0.0.1:3000`，适合与反向代理部署在同一台主机上。  
如果你的反向代理和本服务不在同一台机器，需要自行改成例如 `3000:3000`，并配合防火墙限制来源 IP。

**Authelia + Nginx Proxy Manager**

如果你使用 `Authelia + Nginx Proxy Manager`，推荐使用 `trusted_headers` 模式。

关键点只有两个：

- 让 `mail.example.com` 这条代理先经过 Authelia 校验
- 把以下头转发给后端：
  - `Remote-User`
  - `Remote-Email`
  - `Remote-Name`

一个典型的 Nginx 配置思路大致如下：

```nginx
location / {
    auth_request /authelia;
    auth_request_set $target_url $scheme://$http_host$request_uri;
    auth_request_set $user $upstream_http_remote_user;
    auth_request_set $name $upstream_http_remote_name;
    auth_request_set $email $upstream_http_remote_email;
    error_page 401 =302 https://auth.example.com?rd=$target_url;

    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Remote-User $user;
    proxy_set_header Remote-Name $name;
    proxy_set_header Remote-Email $email;
}

location /authelia {
    internal;
    proxy_pass http://authelia:9091/api/verify;
    proxy_set_header Host $http_host;
    proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Content-Length "";
    proxy_pass_request_body off;
}
```

`/debug/session` 是联调时最好用的接口。  
如果看到：

```json
{
  "authenticated": true,
  "session": {
    "email": "alice@example.com"
  },
  "authMode": "trusted_headers"
}
```

就说明上游认证身份已经传通了。

**263 SSO 规则**

本项目按 263 WebMail SSO 文档实现，默认跳转地址为：

`https://weixin.263.net/partner/web/third/mail/loginMail.do`

核心参数包括：

- `loginPlatform`
- `type=READMAIL`
- `partnerid`
- `authcorpid`
- `userid`
- `timestamp`
- `sign`

签名规则：

```text
MD5(secret + loginPlatform + type + partnerid + authcorpid + userid + timestamp)
```

部署前请确认 263 后台至少已经配置好这些内容：

- 已开启 SSO 权限
- `partnerid` 正确
- `authcorpid` 正确
- 当前服务的真实出口 IP 已加白
- 相关域名已加入允许列表

**调试建议**

- 先测 `/healthz`
  确认反向代理到服务本身没问题
- 再测 `/debug/session`
  确认认证头是否成功传给后端
- 最后再测 `/sso/mail`
  确认 263 跳转是否生成成功

**登录审计日志**

服务会默认把登录相关事件按一行一个 JSON 写到标准输出，容器部署时可以直接用 `docker logs sso-263` 查看。

记录的事件包括：

- `auth_entry_success`
- `auth_missing`
- `auth_callback_success`
- `auth_callback_rejected`
- `mail_sso_success`
- `mail_sso_rejected`
- `logout`
- `request_error`

每条日志会包含时间、认证模式、请求路径、来源 IP、`X-Forwarded-For`、`X-Real-IP`、浏览器 UA、邮箱、用户 ID、姓名、状态码和拒绝原因等字段。日志不会记录 263 签名、密钥或生成后的 SSO 跳转地址。

如果需要关闭审计日志，可以设置：

```env
AUDIT_LOG_ENABLED=false
```

如果最终停在 263 错误页，优先检查：

- `API_SECRET` 是否正确
- 263 是否已对出口 IP 放行
- 用户邮箱是否属于 `AUTH_CORP_ID`
- 263 账号状态是否正常

**仓库说明**

仓库地址：

`git@github.com:coobin/sso-263.git`

如果你准备把它用于生产环境，建议再补充：

- 自己的 `LICENSE`
- `systemd` 或容器编排配置
- 更严格的日志与监控配置
