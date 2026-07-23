# 第 5 章：实战案例分析

前面四章讲了理论、攻击链、防御体系、高级技术。这一章我们只看**真实世界**——5 个完整案例，每个案例都有一个"问题 → 方案 → 配置 → 效果"的闭环。

这些案例来自公开事故、开源运维手册、以及我过去 10 年在自建博客 / 企业生产环境 / 小公司运维中遇到的实际问题。

## 案例 1：电商大促——Nginx 在 50 万 QPS 下的安全调优

**背景**：某二线电商平台，月活 500 万。双 11 大促期间，预估峰值 QPS 50 万。

**挑战**：

1. 大促期间 Nginx 可能成为瓶颈（硬件 F5 到期没钱续，用自建 Nginx 替代）
2. 安全配置不能影响性能（`server_tokens` 和 `limit_req` 不能丢，但必须保证 50 万 QPS）
3. 上游服务扛不住时，Nginx 需要用错误优雅降级（而不是 502 打脸）

**最终配置**（关键部分）：

```nginx
# 全局优化
worker_processes auto;
worker_rlimit_nofile 65535;

events {
    use epoll;
    worker_connections 65535;
    multi_accept on;
}

http {
    # 安全配置 — 不可妥协
    server_tokens off;
    default_type text/html;

    # 日志用 JSON 格式（但大促期间关掉 access log，磁盘 I/O 是瓶颈）
    access_log /var/log/nginx/access.log json if=$loggable;
    log_format json escape=json
        '{"time":"$time_iso8601","status":$status,"request":"$request","req_time":$request_time,"up_time":"$upstream_response_time"}';

    # 缓存优化
    proxy_cache_path /dev/shm/nginx/cache levels=1:2 keys_zone=fast:100m inactive=10m max_size=1g;
    proxy_temp_path /dev/shm/nginx/temp;

    # upstream 配置
    upstream backend {
        server 10.0.1.1:8000 max_fails=3 fail_timeout=30s;
        server 10.0.1.2:8000 max_fails=3 fail_timeout=30s;
        server 10.0.1.3:8000 max_fails=3 fail_timeout=30s;
        server 10.0.1.4:8000 backup;  # 冷备

        keepalive 64;
        keepalive_requests 1000;
        keepalive_timeout 30s;
    }

    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name _;
        return 444;
    }

    server {
        listen 443 ssl http2;
        server_name shop.example.com;

        ssl_protocols TLSv1.3;
        ssl_certificate /etc/nginx/ssl/shop.crt;
        ssl_certificate_key /etc/nginx/ssl/shop.key;

        # 大促期间关闭 log（async write 也会消耗 CPU）
        access_log off;

        # 核心防护：限流 30 req/s per IP
        limit_req_zone $binary_remote_addr zone=api:50m rate=30r/s;

        location /api/order/ {
            limit_req zone=api burst=50 nodelay;

            # 上游故障降级
            proxy_intercept_errors on;
            error_page 502 503 = @fallback;

            proxy_pass http://backend;
        }

        location @fallback {
            return 200 "{\"status\":\"maintenance\",\"message\":\"系统繁忙，请稍候重试\"}";
            default_type application/json;
        }

        location /static/ {
            root /var/www/static;
            expires 30d;
            add_header Cache-Control "public, immutable";
        }

        location /health {
            access_log off;
            return 200 "healthy";
        }
    }
}
```

**结果**：

- 大促峰值 55 万 QPS（比预计高 10%），Nginx CPU 使用率 65%（4 核，8 worker）
- 限流拦截了 ~120 万次/天的过速请求（全是爬虫 / 同行扫描）
- fallback 页面在大促前 10 分钟上游重启时生效 3 次

## 案例 2：API 网关——从零搭建支持 1000 个微服务的 Kong 集群

**背景**：一家 SaaS 公司，从单体向微服务转型。300+ 团队，1000+ 微服务，需要统一入口。

**决策过程**：

```
考核维度         得分（1-5）   说明
────────────────────────────────────
原生 Nginx          3          配置量太大，1000 个 service = 1000 条 upstream
Kong/APISIX         5          Admin API 管理，reload 不需要
Istio              4           全 K8s 最好，但需要改造现有 VPC 架构
自研网关           2           不现实（300 人团队，半年起步）
```

**选择 Kong（Enterprise 版）的架构**：

```
LB（F5） → Kong Cluster (3 节点) → 1000+ upstream
               │
               ├── PostgreSQL（Admin API + 配置）
               ├── Redis（rate limit 共享）
               └── Prometheus（指标）
```

**Kong 配置**：

```bash
# 创建一个上游名为 "user-service" 的服务
$ curl -X POST http://kong-cluster:8001/services \
    -d 'name=user-service' \
    -d 'url=http://user-app:8080'

# 路由：/api/users/* → user-service
$ curl -X POST http://kong-cluster:8001/services/user-service/routes \
    -d 'paths[]=/api/users'

# 安全插件
$ curl -X POST http://kong-cluster:8001/services/user-service/plugins \
    -d 'name=ip-restriction' \
    -d 'config.allow[]=10.0.0.0/8'

# OAuth2 认证
$ curl -X POST http://kong-cluster:8001/services/user-service/plugins \
    -d 'name=oauth2' \
    -d 'config.enforce_https=true' \
    -d 'config.token_expiration=3600'

# 日志发送到 ES
$ curl -X POST http://kong-cluster:8001/services/user-service/plugins \
    -d 'name=http-log' \
    -d 'config.http_endpoint=http://log-collector:8080/logs'

# GitOps 管理：用 decK 将配置同步到 Git
$ deck dump --kong-addr http://kong-cluster:8001 > kong-config.yaml
$ git add kong-config.yaml && git commit -m "update gateway config"
```

## 案例 3：金融合规——PCI DSS 4.0 要求下的 Nginx 部署

**背景**：持牌支付机构，每月处理 200 万笔交易。需要 PCI DSS v4.0 合规。

**PCI DSS 4.0 对 Nginx 的强制要求**：

| 要求 | Nginx 配置 |
|---|---|
| 4.1：加密敏感数据传输 | `ssl_protocols TLSv1.2 TLSv1.3;` + 禁用 TLS 1.0/1.1 |
| 4.2：对公网暴露的密码更改 | 不允许通过 HTTP 暴露 `admin/` 路径 |
| 6.2：及时打补丁 | CVE 公告后 30 天内升级 |
| 10.3：审计日志 | JSON 格式日志 + `access_log` 保留 12 个月 |
| 10.5：日志不可篡改 | auditd 监控 `/var/log/nginx/` + `chattr +a` 日志文件 |

**合规 Nginx 模板**：

```nginx
# 强制 TLS 1.2+
server {
    listen 443 ssl http2;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!eNULL:!EXPORT:!CAMELLIA:!DES:!MD5:!PSK:!RC4:!3DES;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;

    # TLS 证书（Let's Encrypt 不满足 PCI 证书要求，使用 DigiCert / GlobalSign）
    ssl_certificate /etc/nginx/ssl/pci-cert.crt;
    ssl_certificate_key /etc/nginx/ssl/pci-cert.key;

    # 日志要求（JSON 格式，保留 12 个月）
    log_format pci escape=json
        '{'
        '"timestamp":"$time_iso8601",'
        '"ip":"$remote_addr",'
        '"user":"$remote_user",'
        '"request":"$request",'
        '"status":$status,'
        '"bytes":$body_bytes_sent,'
        '"req_time":$request_time,'
        '"ua":"$http_user_agent",'
        '"referrer":"$http_referer"'
        '}';

    access_log /var/log/nginx/access.json pci;

    # 不允许通过文本格式访问管理后台
    location /admin/ {
        allow 10.0.0.0/8;
        deny all;
    }

    # 敏感操作日志（独立文件，用于审计）
    location /api/payment/ {
        access_log /var/log/nginx/payment.json pci;

        limit_req zone=payment:10m rate=10r/s;
        proxy_pass https://payment-backend;
    }
}

# 审计日志轮转配置（独立 logrotate 配置）
# /etc/logrotate.d/nginx-pci
/var/log/nginx/payment.json {
    daily
    rotate 365
    compress
    delaycompress
    missingok
    notifempty
    create 0640 nginx nginx
    sharedscripts
    postrotate
        [ -f /var/run/nginx.pid ] && kill -USR1 `cat /var/run/nginx.pid`
    endscript
}
```

## 案例 4：CDN 厂商——Cloudflare 等价方案的自建

**背景**：某中等体量的视频直播公司，月 API 调用 15 亿次。用 Cloudflare 两年，每年费用 30 万+ 人民币。系统已经成熟到可以自建部分 CDN 功能。

**架构**：

```
全球用户 ──→ Anycast DNS (Cloudflare DNS free tier)
    │
    ├── 边缘节点 1（阿里云新加坡 Nginx）
    ├── 边缘节点 2（阿里云香港 Nginx）
    ├── 边缘节点 3（AWS 东京 Nginx）
    └── 中心节点（杭州 · 主数据中心 Nginx）
```

**边缘节点 Nginx 配置**：

```nginx
# 边缘节点配置
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=edge:2g max_size=50g inactive=60d;

# GeoDNS 对应不同的 upstream
upstream origin {
    server 10.0.0.10:443 max_fails=3 fail_timeout=30s;
    server 10.0.0.11:443 backup;
}

server {
    listen 443 ssl http2;
    server_name edge-china.target.com;

    ssl_certificate /etc/nginx/ssl/edge.crt;
    ssl_certificate_key /etc/nginx/ssl/edge.key;

    location / {
        proxy_cache edge;
        proxy_cache_key "$scheme$host$request_uri";
        proxy_cache_valid 200 30d;
        proxy_cache_valid 403 404 1m;
        proxy_cache_valid 500 502 503 504 0;  # 不缓存上游错误

        # 防缓存投毒
        proxy_cache_lock on;
        proxy_cache_lock_timeout 5s;

        # 回源
        proxy_ssl_certificate /etc/nginx/ssl/edge.crt;
        proxy_ssl_certificate_key /etc/nginx/ssl/edge.key;
        proxy_pass https://origin;
    }

    # DDoS 防护：限流
    limit_req_zone $binary_remote_addr zone=ddos:50m rate=50r/s;
    location /live/ {
        limit_req zone=ddos burst=20;
        proxy_cache edge;
        proxy_pass https://origin/live/;
    }
}
```

## 案例 5：内部系统——用 mTLS 替代 VPN

**背景**：一个 20 人技术团队，需要远程访问内部工具（GitLab / Jenkins / Wiki）。之前用 OpenVPN，但经常断连、速度慢、配起来复杂。

**方案**：用 Nginx + mTLS 替代 VPN。

```
远程员工
    │
    ├── 员工电脑：安装客户端证书（自签 CA）
    │
    ├── 反向代理 Nginx（mTLS 验证）
    │
    ├── GitLab（监听内网端口）
    ├── Jenkins（监听内网端口）
    └── Wiki（监听内网端口）
```

**不需要 VPN，不需要 SSH 隧道，只要把客户端证书放进浏览器即可**。

**Nginx 配置**：

```nginx
# 远程访问 Nginx（公网暴露，但只有带证书的人能进）
server {
    listen 443 ssl http2;
    server_name remote.team.target.com;

    # 标准 TLS
    ssl_certificate /etc/nginx/ssl/remote.crt;
    ssl_certificate_key /etc/nginx/ssl/remote.key;

    # mTLS：要求客户端证书
    ssl_client_certificate /etc/nginx/ssl/ca.crt;
    ssl_verify_client on;
    ssl_verify_depth 2;

    # 验证客户端证书 CN
    if ($ssl_client_s_dn !~ "CN=.*@team\.target\.com") {
        return 403 "Only team members can access";
    }

    # 路由到内网服务
    location /gitlab/ {
        proxy_pass http://gitlab.internal:8080;
    }

    location /jenkins/ {
        proxy_pass http://jenkins.internal:8080;
    }

    location /wiki/ {
        proxy_pass http://wiki.internal:8080;
    }
}
```

**员工证书颁发流程**（管理员操作）：

```bash
# 1. 生成员工证书
$ openssl genrsa -out alice.key 2048
$ openssl req -new -key alice.key -out alice.csr \
    -subj "/CN=alice@team.target.com"
$ openssl x509 -req -in alice.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out alice.crt -days 365

# 2. 导出 PKCS12（浏览器可直接导入）
$ openssl pkcs12 -export -inkey alice.key -in alice.crt \
    -certfile ca.crt -out alice.p12 -passout pass:temp123

# 3. 清空密码后发给员工
$ openssl pkcs12 -export -inkey alice.key -in alice.crt \
    -certfile ca.crt -out alice.p12 -nodes -passout pass:
```

## 小结

五个案例覆盖了五种典型场景：

| 案例 | 场景 | 关键教训 |
|---|---|---|
| 电商大促 | 高并发 + 限流 + 降级 | `limit_req` + `proxy_intercept_errors` + `access_log off` |
| API 网关 | 1000+ 微服务统一入口 | Kong/APISIX > 原生 Nginx（配置量太大）|
| 金融合规 | PCI DSS 4.0 合规 | 加密+日志+审计，证书不能 Let's Encrypt |
| 自建 CDN | Cloudflare 替代 | 自建 CDN + 缓存投毒防护 + Anycast DNS |
| 替代 VPN | mTLS 远程访问 | 证书比 OpenVPN 好用，浏览器原生支持 |

### 自测题

**题 1**：找你的 Nginx 的 `proxy_intercept_errors` 设置。如果上游返回 502，用户看到什么？

<details>
<summary>提示</summary>

生产环境不应该让用户看到 Nginx 的 "502 Bad Gateway" 默认错误页。用 `proxy_intercept_errors on;` + `error_page 502 503 = @fallback;` 返回友好的 JSON 或 HTML。
</details>

**题 2**：如果明天你需要给 10 个同事做远程访问，你会用 mTLS 还是 VPN？为什么？

<details>
<summary>比较</summary>

mTLS：
- ✅ 浏览器原生支持（无需额外客户端）
- ✅ 证书可到期回收
- ❌ 需要管理 CA 和证书吊销

VPN：
- ✅ 更成熟（OpenVPN / WireGuard）
- ❌ 需要客户端软件
- ❌ 全量隧道 vs 按需路由

< 10 人建议 mTLS，≥ 10 人建议考虑 ZTNA（Cloudflare Zero Trust / Tailscale / zrok）。
</details>
