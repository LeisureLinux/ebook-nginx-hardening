# 第 3 章：Nginx 五层纵深防御体系

第 2 章我们站在攻击者视角，看了他们怎么五步拿下 Nginx。现在换到**防御者视角**。

这一章是全书的核心——五层纵深防御体系。每一层对应攻击链的一个环节，层层递进，形成一个完整的安全屏障。

```
攻击者步骤        →  纵深防御层
────────────────────────────────
摸配置 / 找路径    →  第 1 层：减少暴露面
绕认证            →  第 2 层：访问控制
提权 / SQL 注入   →  第 3 层：行为约束（WAF）
模块注入 / 篡改    →  第 4 层：完整性保护
隐攻击 / 日志逃逸   →  第 5 层：可观测性 + 入侵检测
```

## 防御的总原则

在深入每一层之前，先定三条总原则。后面所有具体的 nginx.conf 配置，都围绕这三条设计：

**原则 1：默认拒绝（Default Deny）**

```
# 好的
location /api/ {
    deny all;               ← 先全部拒绝
    allow 10.0.0.0/8;       ← 再开放白名单
}

# 坏的
location /api/ {
    allow 10.0.0.0/8;       ← 先开放（没拒绝？）
    ...                      ← 可能会被其他规则意外覆盖
}
```

**原则 2：防御不是功能，是架构**

不要把安全当成"最后一道门"。它应该在**设计阶段**就嵌入——比如 TLS 1.3、mTLS、JWT 认证——而不是等 CVE 爆发了再补。

**原则 3：可观测性是安全的基础**

如果你看不到攻击，你就防不了攻击。第 5 层的日志、指标、告警体系，不是"锦上添花"，是"安全基础设施"——就跟防火墙一样重要。

## 第 1 层：减少暴露面

第一层是最便宜的——它不涉及复杂的技术，就两件事：**关掉不需要的东西**、**抹掉不需要的信息**。

### server_tokens off —— 抹掉版本号

```nginx
# 最基础的配置，**所有生产环境强制开启**
server_tokens off;
```

效果：

```bash
$ curl -I https://target.com/
# 之前：Server: nginx/1.18.0
# 之后：Server: nginx
```

### default_server 黑洞

每个监听端口**必须配一个 default_server**，拒绝所有未匹配的域名请求。

```nginx
server {
    listen 80 default_server;          # IPv4 default
    listen [::]:80 default_server;     # IPv6 default
    server_name _;                     # 匹配所有没匹配的域名

    return 444;                        # 空断开，不给任何响应
    # 或者：return 301 https://$host$request_uri;
}
```

为什么是 `return 444`？这是 Nginx 自己的非标准响应码——断开连接不返回任何内容。攻击者的扫描器会收到"连接断开"而不是 HTTP 响应，从而在常规扫描工具里标记为"不可达"。

### 限制允许的 HTTP 方法

```nginx
# 只允许 GET + POST + HEAD，拒绝其他方法
if ($request_method !~ ^(GET|POST|HEAD)$) {
    return 405;
}

# 或者用 limit_except（更准确）
location / {
    limit_except GET POST HEAD {
        deny all;
    }
}
```

### 隐藏内部路径

```nginx
# 拒绝所有以点开头的路径（排除 .well-known）
location ~ /\.(?!well-known) {
    deny all;
    return 404;

    # 为什么返回 404 而不是 403？
    # 403 = "我知道这路径存在，但你没权限" → 攻击者知道这是一条真实路径
    # 404 = "我不知道这路径是什么"     → 攻击者啥也确认不了
}

# 拒绝常见的敏感路径
location ~ /(backup|database|sql|dump|private|export|import|config|admin) {
    deny all;
    return 404;
}

# 拒绝 /vendor/（PHP / Laravel 项目常见问题）
location ~ /vendor/ {
    deny all;
    return 404;
}
```

### 隐藏 CGI 探测

```nginx
# 很多人把 Nginx 当 Apache 用，在 /cgi-bin/ 下挂 CGI 脚本
location ~ \.(pl|cgi|sh|bak|old|php~)$ {
    deny all;
    return 404;
}
```

### 隐藏错误页信息

```nginx
server {
    error_page 404 403 500 502 503 504 /error.html;

    location = /error.html {
        root /var/www/errors/;
        internal;   # 只能内部重定向访问，外部直接请求返回 404
    }
}
```

`/var/www/errors/error.html` 内容：

```html
<!DOCTYPE html>
<html>
<head><title>Service Unavailable</title></head>
<body>
<h1>Service Unavailable</h1>
<p>Please try again later.</p>
</body>
</html>
```

不写 "404 Not Found"（确认路径不存在），不写 "403 Forbidden"（确认路径存在），不显示任何版本信息。

### 拒绝代理协议探测

```nginx
# HTTP/0.9 协议已废弃，但某些扫描器用这个方法探测 Nginx
server {
    listen 80;
    server_name _;
    if ($server_protocol !~ "HTTP/(1\.0|1\.1|2|3)") {
        return 400;
    }
}
```

## 第 2 层：访问控制

第一层掩盖了信息。但如果攻击者确定了目标 Nginx 确实存在，他们会尝试访问——第二层就是这里：**谁可以进来，谁必须离开**。

### IP 白名单 / 黑名单

```nginx
# 区域一：管理后台 — 只允许内网
location /admin/ {
    allow 10.0.0.0/8;
    allow 172.16.0.0/12;
    allow 192.168.0.0/16;
    deny all;                                     ← 默认拒绝

    proxy_pass http://admin-backend:9000/;
}

# 区域二：API — 对内网开放，可配置白名单
location /api/ {
    allow 10.0.0.0/8;
    deny all;

    auth_jwt "API";
    auth_jwt_key_file /etc/nginx/jwt_public_key.pem;
    proxy_pass http://api-backend:8000/;
}

# 区域三：静态 CDN — 对所有人开放
location /static/ {
    root /var/www/static;
    expires 30d;
    add_header Cache-Control "public, immutable";
}
```

**关键技巧**：`allow` 和 `deny` 的顺序是**顺序匹配**的。Nginx 的 `allow` / `deny` 指令按照**写在配置文件里的顺序**评估。一旦匹配了 `allow`，评估就结束（"允许"）；如果碰到 `deny`，拒绝；如果既没 `allow` 也没 `deny`，**默认允许**。

```
# 正确
location /admin/ {
    allow 10.0.0.0/8;     # 1. 如果是内网 → 允许
    deny all;              # 2. 其他全部拒绝
}

# 错误
location /admin/ {
    deny all;              # ← 这行相当于：即使内网也拒绝
    allow 10.0.0.0/8;     # ← 不会走到这行
}
```

### GeoIP 模块：国家维度限流

GeoIP 模块可以根据请求的 IP 来源限制访问。比如只允许国内 IP 访问。

```nginx
# 安装 GeoIP2 模块（开源版 Nginx 需编译，或使用 ngx_http_geoip2_module）
load_module /usr/lib/nginx/modules/ngx_http_geoip2_module.so;

http {
    geoip2 /etc/nginx/geoip/GeoLite2-Country.mmdb {
        $geoip2_data_country_code source=$remote_addr country iso_code;
    }

    server {
        location /admin/ {
            # 只允许中国 IP 访问管理后台
            if ($geoip2_data_country_code != "CN") {
                return 403;
            }
            # ... 其余认证配置
        }
    }
}
```

**注意**：GeoIP 不是完美的访问控制。使用 VPN / 代理的攻击者可以伪装来源国家。它适合做**第一层筛选**，而不是唯一的安全措施。

### JWT 验证

Nginx 1.25+ 原生支持 JWT 验证（`auth_jwt` 模块）。

```nginx
location /api/ {
    auth_jwt "API Access";
    auth_jwt_key_file /etc/nginx/jwt_public_key.pem;

    # 可选：限制 JWT 的角色字段
    auth_jwt_require $jwt_claim_role "admin";

    proxy_pass http://api-backend:8000/;
}
```

JWT key 文件（公钥格式）：

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCYZM...
-----END PUBLIC KEY-----
```

### OAuth 2.0 / OIDC 集成

通过 openid-connect 模块集成 Keycloak / Auth0：

```nginx
auth_jwt "OIDC";
auth_jwt_key_file /etc/nginx/oidc_jwt_keys.json;
# 从认证服务器获取公钥的 URL
auth_jwt_require $jwt_claim_sub;
# 跳转到认证服务器
error_page 401 = @oidc_login;

location @oidc_login {
    return 302 https://auth.target.com/oauth/authorize?client_id=nginx&redirect_uri=$scheme://$host/oauth/callback;
}

location /oauth/callback {
    proxy_pass http://auth-service:9000/oauth/callback;
}
```

### 限流：limit_req 和 limit_conn

这是防御"认证爆破"的核心工具。攻击者就算知道密码，也撑不住 `limit_req` 卡的请求速率。

```nginx
# 定义限流区域（共享内存）
http {
    # 针对登录接口的限流
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;

    # 针对 API 的限流（对每个 IP 限制）
    limit_req_zone $binary_remote_addr zone=api:50m rate=30r/s;

    # 连接数限制
    limit_conn_zone $binary_remote_addr zone=addr:40m;

    server {
        location /login {
            # 1 RPM 的登录限流（爆破一次要 60 秒才能再试一次）
            limit_req zone=login burst=5 nodelay;

            proxy_pass http://login-backend;
        }

        location /api/ {
            # 30 请求/秒/IP
            limit_req zone=api burst=20 nodelay;

            # 同 IP 最多 10 个并发连接
            limit_conn addr 10;

            proxy_pass http://api-backend;
        }

        location /static/ {
            # 静态文件不做严格的 IP 限流
            limit_req zone=static burst=100 nodelay;
        }
    }
}
```

## 第 3 层：行为约束（WAF 核心）

前面两层控制的是"谁能进来"——现在假设攻击者已经绕过前两层。第三层是防火墙的防火墙：**即使攻击者进来了，他们能做的动作也受到约束**。

### ModSecurity v3 + OWASP CRS 4.x

ModSecurity 是 Web 应用防火墙（WAF）的行业标准。v3 是 Nginx 原生模块（不再需要 Apache 兼容层）。

**安装**：

```bash
# 从源码编译
$ git clone --depth 1 https://github.com/ModSecurity/ModSecurity
$ cd ModSecurity
$ git submodule init && git submodule update
$ ./build.sh
$ ./configure --with-pcre2 --with-yajl
$ make -j$(nproc)
$ sudo make install

# Nginx 动态模块编译（需要 Nginx 源码和对应版本的 nginx-module）
$ git clone --depth 1 https://github.com/ModSecurity/ModSecurity-nginx.git
$ cd nginx-1.26.0
$ ./configure --with-compat --add-dynamic-module=../ModSecurity-nginx
$ make modules
$ sudo cp objs/ngx_http_modsecurity_module.so /usr/lib/nginx/modules/
```

**基础配置**：

```nginx
load_module /usr/lib/nginx/modules/ngx_http_modsecurity_module.so;

http {
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsecurity/main.conf;

    server {
        location / {
            proxy_pass http://backend;
        }

        # 对 admin 路径开启更严格的 WAF
        location /admin/ {
            modsecurity_rules_file /etc/nginx/modsecurity/admin.conf;
            proxy_pass http://admin-backend;
        }
    }
}
```

**`main.conf` 核心规则**：

```
# 启用 OWASP CRS 的核心规则集
Include /etc/nginx/modsecurity/crs-setup.conf
Include /etc/nginx/modsecurity/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
Include /etc/nginx/modsecurity/rules/REQUEST-901-INITIALIZATION.conf
Include /etc/nginx/modsecurity/rules/REQUEST-903.9001-DRUPAL-EXCLUSION-RULES.conf
Include /etc/nginx/modsecurity/rules/REQUEST-903.9002-WORDPRESS-EXCLUSION-RULES.conf
Include /etc/nginx/modsecurity/rules/REQUEST-905-COMMON-EXCEPTIONS.conf
Include /etc/nginx/modsecurity/rules/REQUEST-910-IP-REPUTATION.conf
Include /etc/nginx/modsecurity/rules/REQUEST-911-METHOD-ENFORCEMENT.conf
Include /etc/nginx/modsecurity/rules/REQUEST-912-DOS-PROTECTION.conf
Include /etc/nginx/modsecurity/rules/REQUEST-913-SCANNER-DETECTION.conf
Include /etc/nginx/modsecurity/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
Include /etc/nginx/modsecurity/rules/REQUEST-921-PROTOCOL-ATTACK.conf
Include /etc/nginx/modsecurity/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf
Include /etc/nginx/modsecurity/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf
Include /etc/nginx/modsecurity/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf
Include /etc/nginx/modsecurity/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf
Include /etc/nginx/modsecurity/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf
Include /etc/nginx/modsecurity/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
Include /etc/nginx/modsecurity/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf
Include /etc/nginx/modsecurity/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf
Include /etc/nginx/modsecurity/rules/REQUEST-949-BLOCKING-EVALUATION.conf
Include /etc/nginx/modsecurity/rules/RESPONSE-950-DATA-LEAKAGES.conf
Include /etc/nginx/modsecurity/rules/RESPONSE-951-DATA-LEAKAGES-SQL.conf
Include /etc/nginx/modsecurity/rules/RESPONSE-952-DATA-LEAKAGES-JAVA.conf
Include /etc/nginx/modsecurity/rules/RESPONSE-953-DATA-LEAKAGES-PHP.conf
Include /etc/nginx/modsecurity/rules/RESPONSE-954-DATA-LEAKAGES-IIS.conf
Include /etc/nginx/modsecurity/rules/RESPONSE-959-BLOCKING-EVALUATION.conf
Include /etc/nginx/modsecurity/rules/RESPONSE-980-CORRELATION.conf
```

### 国产替代：雷池（SafeLine）

[雷池 WAF](https://github.com/chaitin/safeline) 是长亭科技开源的企业级 WAF，支持 Nginx 反向代理模式。

**架构**：

```
Internet → Nginx → SafeLine Agent → Upstream
```

优势：

- 基于语义分析（不是简单的正则检测），对 SQL 注入、XSS、命令注入的检出率更高
- 内置 Bot 检测、爬虫检测
- 管理面板可视化，适合国内运维团队

### 自研规则：基于 OpenResty + Lua 的自定义 WAF

如果 ModSecurity 太重，可以基于 OpenResty + Lua 做轻量级 WAF：

```lua
-- /etc/nginx/lua/waf.lua

local waf = {}

-- 黑名单 User-Agent
waf.blocked_agents = {
    "sqlmap",
    "nmap",
    "nikto",
    "dirbuster",
    "gobuster",
    "masscan",
    "zgrab",
}

-- SQL 注入检测（简化版）
local sql_patterns = {
    "\\bSELECT\\b.*\\bFROM\\b",
    "\\bUNION\\b.*\\bSELECT\\b",
    "\\bINSERT\\b.*\\bINTO\\b",
    "\\bDELETE\\b.*\\bFROM\\b",
    "\\bDROP\\b.*\\bTABLE\\b",
    "\\bOR\\b.*\\b1\\s*=\\s*1\\b",
    "'\\s*--\\s*",
    "'\\s*#\\s*",
}

-- XSS 检测
local xss_patterns = {
    "<script[^>]*>",
    "onerror\\s*=",
    "onload\\s*=",
    "javascript\\s*:",
    "<iframe[^>]*>",
    "eval\\s*\\(\\s*request",
}

function waf.check()
    -- 检查请求 URI
    local uri = ngx.var.request_uri
    
    for _, pattern in ipairs(sql_patterns) do
        if ngx.re.find(uri, pattern, "is") then
            ngx.log(ngx.ERR, "SQL injection detected: " .. uri)
            ngx.exit(403)
        end
    end

    -- 检查 cookie
    local cookie = ngx.var.http_cookie
    if cookie then
        for _, pattern in ipairs(xss_patterns) do
            if ngx.re.find(cookie, pattern, "is") then
                ngx.log(ngx.ERR, "XSS in cookie: " .. cookie)
                ngx.exit(403)
            end
        end
    end

    -- 检查 User-Agent
    local ua = ngx.var.http_user_agent
    if ua then
        for _, agent in ipairs(waf.blocked_agents) do
            if string.find(string.lower(ua), agent) then
                ngx.log(ngx.ERR, "Blocked user-agent: " .. ua)
                ngx.exit(403)
            end
        end
    end
end

return waf
```

**在 Nginx 中启用**：

```nginx
# OpenResty / 编译了 Lua 模块的 Nginx
http {
    lua_package_path "/etc/nginx/lua/?.lua;;";

    server {
        location / {
            access_by_lua_block {
                local waf = require "waf"
                waf.check()
            }
            proxy_pass http://backend;
        }
    }
}
```

### Bot 防护

```nginx
# User-Agent 黑名单
map $http_user_agent $blocked_agent {
    default 0;
    "~*curl" 1;           # 不是所有 curl 都是扫描器，但有风险
    "~*sqlmap" 1;
    "~*nmap" 1;
    "~*masscan" 1;
    "~*zgrab" 1;
    "~*gobuster" 1;
    "~*dirbuster" 1;
    "~*nikto" 1;
    "~*^$" 1;             # 空 User-Agent（扫描器特征）
}

server {
    if ($blocked_agent) {
        return 403;
    }
}
```

## 第 4 层：完整性保护

前三层控制的是"人能否进来"——第四层保护的是"数据是否被篡改"。

### TLS 强制

```nginx
server {
    listen 80;
    server_name target.com;
    return 301 https://$host$request_uri;  # HTTP → HTTPS 强制跳转
}

server {
    listen 443 ssl http2;
    server_name target.com;

    # TLS 1.3 配置（截止 2026 年，TLS 1.0/1.1 已不应再使用）
    ssl_protocols TLSv1.2 TLSv1.3;

    # 选择安全的 cipher
    ssl_ciphers HIGH:!aNULL:!eNULL:!EXPORT:!CAMELLIA:!DES:!MD5:!PSK:!RC4:!3DES;
    ssl_prefer_server_ciphers on;

    # 证书
    ssl_certificate /etc/nginx/ssl/target.com.crt;
    ssl_certificate_key /etc/nginx/ssl/target.com.key;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/nginx/ssl/ca-chain.crt;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # 响应头安全增强
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "0" always;         # 现代浏览器不再需要 XSS 保护头
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
}
```

### mTLS：服务间双向认证

在微服务架构中，只有 Nginx 对公网暴露。Nginx 和上游服务之间需要 mTLS 通信。

```nginx
# mTLS 模式：Nginx 客户端认证 + proxy pass 到上游
server {
    listen 443 ssl http2;
    server_name api.target.com;

    # 标准 TLS 配置
    ssl_protocols TLSv1.3;
    ssl_certificate /etc/nginx/ssl/api.target.com.crt;
    ssl_certificate_key /etc/nginx/ssl/api.target.com.key;

    # mTLS：要求客户端证书
    ssl_client_certificate /etc/nginx/ssl/ca.crt;
    ssl_verify_client on;
    ssl_verify_depth 2;

    # 验证客户端证书的 CN
    if ($ssl_client_s_dn !~ "CN=authorized-client") {
        return 403;
    }
}
```

**Curl 测试 mTLS**：

```bash
$ curl --cacert ca.crt --cert client.crt --key client.key \
  https://api.target.com/secure-endpoint
```

### 配置文件签名

Nginx 配置文件的完整性保护无法 100% 防止本机攻击（如果攻击者拿到 root，一切都没用），但可以防止**配置漂移**——即有人不小心修改了配置，或者 GitOps 系统的配置有跳变。

```bash
# 每次修改 nginx.conf 后，生成签名
$ openssl dgst -sha256 -sign /etc/nginx/ssl/config-sign.key \
    -out /etc/nginx/conf.d/nginx.conf.sig /etc/nginx/nginx.conf

# 定时检查配置签名完整性（cron）
$ cat /etc/cron.daily/nginx-config-check
#!/bin/bash
if ! openssl dgst -sha256 -verify /etc/nginx/ssl/config-sign.pub \
    -signature /etc/nginx/conf.d/nginx.conf.sig /etc/nginx/nginx.conf; then
    echo "Nginx config has been tampered!" | mail -s "ALERT" admin@example.com
fi
```

## 第 5 层：可观测性 + 入侵检测

如果前四层都没挡住——或者攻击者做的是"看不到的"慢速攻击（Slowloris、Credential Stuffing）——第五层是最后一道防线：**你看到了攻击**。

### 指标监控：nginx-prometheus-exporter

```nginx
# 启用 Nginx 状态页
location /basic_status {
    stub_status;
    allow 127.0.0.1;
    allow 10.0.0.0/8;
    deny all;
}
```

Prometheus 配置：

```yaml
scrape_configs:
  - job_name: nginx
    static_configs:
      - targets:
        - localhost:9113  # nginx-prometheus-exporter 端口
```

Grafana 仪表盘要关注的指标：

| 指标 | 含义 | 告警阈值 |
|---|---|---|
| `nginx_connections_active` | 活跃连接数 | > max_worker_connections × 0.8 |
| `nginx_http_requests_total` | 总请求数增量 | 超过正常基线 5 倍 |
| `nginx_upstream_response_time_seconds` | 上游响应时间 P99 | > 5s |
| `nginx_http_4xx_total` | 4XX 响应数 | 超过正常基线 10 倍 |
| `nginx_http_5xx_total` | 5XX 响应数 | 超过 0 |

### 日志接入 ELK / Loki

```nginx
# 启用 JSON 格式日志（结构化日志，方便 ElasticSearch 解析）
log_format json escape=json
    '{'
    '"timestamp":"$time_iso8601",'
    '"remote_addr":"$remote_addr",'
    '"remote_user":"$remote_user",'
    '"request":"$request",'
    '"status":$status,'
    '"body_bytes":$body_bytes_sent,'
    '"request_time":$request_time,'
    '"upstream_response_time":"$upstream_response_time",'
    '"http_referrer":"$http_referer",'
    '"http_user_agent":"$http_user_agent",'
    '"http_x_forwarded_for":"$http_x_forwarded_for",'
    '"request_body":"$request_body"'
    '}';

access_log /var/log/nginx/access.log json;
error_log /var/log/nginx/error.log warn;
```

### ModSecurity audit log 接入

ModSecurity 的 audit log 记录被 WAF 拦截的请求详情，必须接入分析系统：

```nginx
# ModSecurity 配置：将 audit log 发到 syslog（接入 SIEM）
SecAuditEngine RelevantOnly
SecAuditLog /var/log/nginx/modsec_audit.log
SecAuditLogType Serial
SecAuditLogFormat JSON
```

### 异常流量检测

```nginx
# 基于 limit_req 的异常检测
http {
    # 慢速攻击检测区域
    limit_req_zone $binary_remote_addr zone=slow:10m rate=10r/s;

    server {
        location / {
            # 正常限流
            limit_req zone=slow burst=20 nodelay;

            # 如果请求被限流，记录到独立日志
            limit_req_status 429;

            proxy_pass http://backend;
        }
    }

    # DDoS 检测：独立区域对特定路径做更严格的限流
    limit_req_zone $binary_remote_addr zone=ddos:10m rate=5r/s;

    server {
        location /login/ {
            limit_req zone=ddos burst=10 nodelay;
            proxy_pass http://login-backend;
        }
    }
}
```

### 实战自动化：fail2ban + Nginx

fail2ban 读取 Nginx 日志，自动封禁攻击 IP。

```ini
# /etc/fail2ban/jail.d/nginx.conf
[nginx-auth]
enabled = true
port = http,https
filter = nginx-auth
logpath = /var/log/nginx/access.log
maxretry = 5
bantime = 600
findtime = 300

[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 1
bantime = 86400  # 直接封一天
```

```ini
# /etc/fail2ban/filter.d/nginx-auth.conf
[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD) /(admin|login|wp-admin).*" 401
            ^<HOST> -.*"(GET|POST|HEAD) /api/.*" 403
ignoreregex =
```

## 实战案例：一家电商的 Nginx 纵深防御 90 天落地

**背景**：月活 500 万的电商平台，日 PV 约 2000 万。原有 Nginx 配置是"装上就行"，无安全配置。

**第 1 层（1-7 天）**：
- `server_tokens off`
- 自定义错误页（抹掉所有 Nginx 指纹）
- 拒绝 `.git/`、`/backup/`、`/admin/`（外面看不到）
- `default_server` 返回 444

**第 2 层（8-21 天）**：
- 管理后台 IP 白名单（只开放内网 + VPN）
- API 做 JWT 认证
- `limit_req`：登录 1r/s，API 30r/s
- Fail2ban 集成

**第 3 层（22-45 天）**：
- 部署雷池 WAF（开源版）
- 自研 Lua WAF 规则（SQL 注入 + XSS + 命令注入）
- 拦截统计：前 30 天拦截 2300+ 次攻击（其中 70% SQL 注入扫描）

**第 4 层（46-60 天）**：
- 全站 TLS 1.3 + HSTS
- SSL 证书自动化（Let's Encrypt + acme.sh）
- mTLS 内部服务通信（Kong 网关到上游服务）

**第 5 层（61-90 天）**：
- JSON 格式日志接入 Loki + Grafana
- 告警规则：5XX > 0、4XX 异常飙升、Upstream 超时
- ModSecurity audit log 接入 ES
- 月度安全报告：攻击趋势、命中规则 TOP 10、封禁 IP 统计

**结果**：
- CVE-2022-2258（SSRF）爆发时，0 台受影响（因为 upstream 做了 mTLS，攻击者无法从 Nginx 穿透到内部服务）
- 登录爆破 → `limit_req` 拦截 → fail2ban 封禁 → 日均拦截 200+ 次尝试
- 慢 SQL 注入扫描 → 雷池 WAF 拦截 → ModSecurity audit log 记录（取证已用上）

## 小结 & 练习

五层纵深防御体系不是一个检查清单——它是一个工程实践。每一层的存在是因为攻击者可能突破上一层。

```
第 1 层（暴露面）：抹掉指纹，隐藏入口
第 2 层（访问控制）：限制谁可以进来
第 3 层（行为约束）：即使进来，攻击也受限
第 4 层（完整性）：数据不被篡改
第 5 层（可观测性）：看到攻击、回溯攻击
```

### 自测题

**题 1**：找您生产环境的 Nginx，检查是否配置了 `default_server`。如果没有，配一个。

**题 2**：您的 Nginx access log 是文本格式还是 JSON 格式？如果是文本格式，改为 JSON 格式（方便 ES / Loki 解析）。

**题 3**：如果您的 Nginx 暴露了 `/api/` 路径，确认它是否有 JWT 认证或 IP 白名单保护。

**题 4**：部署 fail2ban 集成 Nginx 日志，测试一个假的爆破场景看能否自动封禁。

**题 5（硬核）**：在测试环境部署 ModSecurity + OWASP CRS，用 sqlmap 测试拦截效果。
