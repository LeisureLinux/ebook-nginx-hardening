# 第 4 章：高级防御技术

前三章我们构建了从基础配置到纵深防御的完整体系。但如果您的场景是**高并发 API 网关**、**多数据中心 CDN**、**微服务 mTLS 架构**——您需要更深入的防御技术。

这一章是"进阶级"——每一节都是一个独立专题，可以选择适用的部分阅读。

## TLS 1.3 实战（OpenSSL 3.x + BoringSSL）

### 为什么 TLS 1.3 比 1.2 更安全

| 维度 | TLS 1.2 | TLS 1.3 |
|---|---|---|
| 握手次数 | 2-RTT（往返延迟） | 1-RTT（首次）、0-RTT（恢复） |
| 支持的 cipher suite | 100+ 种组合 | 5 种 AEAD cipher |
| 前向安全性 | 可选（需要正确配置 cipher） | **强制**（所有 cipher 都提供完美前向安全） |
| 协商阶段 | 明文证书传输 | 加密证书传输（Encrypted Client Hello） |
| 重协商攻击 | 存在已知攻击向量 | 已移除 |

**底线**：TLS 1.3 不仅仅是为了快 1 个 RTT——它的设计假设是"TLS 1.2 有太多漏洞"。所以 2026 年的今天，所有新部署都应该**只启用 TLS 1.3**。

```nginx
# TLS 1.3 only 配置（2026 年推荐）
ssl_protocols TLSv1.3;
ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256;

# 证书链优化
ssl_certificate /etc/nginx/ssl/fullchain.pem;  # 包含中间证书
ssl_certificate_key /etc/nginx/ssl/privkey.pem;

# OCSP Stapling（让浏览器不需要自己做 OCSP 查询）
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/nginx/ssl/chain.pem;

# 会话恢复（减少后续握手）
ssl_session_cache shared:SSL:40m;
ssl_session_timeout 4h;
ssl_session_tickets off;  # session ticket 不安全，禁用
```

### OpenSSL 3.x vs BoringSSL

| | OpenSSL 3.x | BoringSSL |
|---|---|---|
| 维护方 | OpenSSL Project | Google (Chromium 用) |
| 版本 | 3.0+（2024 年新的 LTS 分支 3.3） | 持续更新 |
| 对 QUIC/HTTP3 支持 | OpenSSL 3.2+ | 原生支持（Nginx QUIC 默认用 BoringSSL） |
| 合规性 | FIPS 140-3 | 不 FIPS 认证 |
| 性能 | 基线 | 优化了一些 side-channel |
| 国内发行版 | 默认（Debian 12 有 OpenSSL 3.0） | 需自编译 |

**选择决策**：

- 需要 HTTP/3（QUIC） → 编译 BoringSSL
- 需要 FIPS 合规（金融、政企） → 使用 OpenSSL 3.x FIPS 模块
- Debian/Ubuntu 默认用 OpenSSL 3.0+，`apt install` 即可

### 证书链优化

一个优化好的证书链可以**把海外的 TLS 握手时间减少 300-500ms**。

```bash
# 查看当前证书链
$ openssl s_client -connect target.com:443 -showcerts < /dev/null 2>&1 | grep -E "subject|issuer"

subject=CN = target.com
issuer=CN = R3, O = Let's Encrypt
```

**最佳实践**：

```bash
# 把服务器证书 + 中间证书合并
$ cat cert.pem intermediate.pem > fullchain.pem

# 用 openssl 查看链长度
$ openssl crl2pkcs7 -nocrl -certfile fullchain.pem \
    | openssl pkcs7 -print_certs -text | grep Subject

# 优化：只保留必需的中间证书，去掉根证书
# 🔹 不要包含根证书（浏览器自带根证书库）
# 🔹 可以去掉不必要的中间证书（减少 1-2KB 的手握手）
```

**精简后的配置**：

```nginx
# 服务器证书 + 中间证书 = ~4KB（而不是 6-8KB）
ssl_certificate /etc/nginx/ssl/fullchain.pem;
ssl_trusted_certificate /etc/nginx/ssl/chain.pem;  # 只有中间 CA
```

### 性能压测

```bash
# 安装 h2load（nghttp2 工具）
$ sudo apt install nghttp2-client

# 测试 TLS 1.3 性能
$ h2load -n 10000 -c 50 -m 10 https://target.com/

# 对比 TLS 1.2 vs 1.3
$ h2load -n 10000 -c 50 -m 10 --npn-list h2 https://target.com/
# 预期：TLS 1.3 在连接建立阶段快 30-50%（1-RTT vs 2-RTT）
```

## mTLS 在微服务中的落地

mTLS（双向 TLS）是微服务架构中"零信任"的基础设施——不仅仅是外部客户端到 Nginx 加密，Nginx 到上游服务也要加密+认证。

### 基础 mTLS 架构

```
客户端 ──TLS──→ Nginx ──mTLS──→ API 网关 ──mTLS──→ 上游服务
```

### 自签 CA + 证书颁发

```bash
# 1. 创建私有 CA
$ openssl req -x509 -new -nodes -days 3650 \
    -keyout ca.key -out ca.crt \
    -subj "/CN=Nginx mTLS CA"

# 2. 为 Nginx 签服务器证书
$ openssl genrsa -out nginx.key 2048
$ openssl req -new -key nginx.key -out nginx.csr \
    -subj "/CN=nginx.target.com"
$ openssl x509 -req -in nginx.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out nginx.crt -days 365

# 3. 为上游服务签客户端证书
$ openssl genrsa -out client.key 2048
$ openssl req -new -key client.key -out client.csr \
    -subj "/CN=authorized-client"
$ openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt -days 365
```

### Nginx 全 mTLS 配置

```nginx
# mTLS 模式：Nginx 既要求客户端证书，又用客户端证书连接 upstream
server {
    listen 443 ssl http2;
    server_name api.target.com;

    # 验证客户端的 TLS
    ssl_certificate /etc/nginx/ssl/nginx.crt;
    ssl_certificate_key /etc/nginx/ssl/nginx.key;
    ssl_client_certificate /etc/nginx/ssl/ca.crt;
    ssl_verify_client on;
    ssl_verify_depth 3;

    # 传递客户端证书信息给上游
    proxy_set_header X-SSL-Client-Serial $ssl_client_serial;
    proxy_set_header X-SSL-Client-S-DN $ssl_client_s_dn;
    proxy_set_header X-SSL-Client-Cert $ssl_client_cert;

    location /secure/ {
        proxy_pass https://upstream-service:8443;
    }
}

# upstream 使用 mTLS（Nginx 作为客户端连接上游）
proxy_ssl_certificate /etc/nginx/ssl/client.crt;
proxy_ssl_certificate_key /etc/nginx/ssl/client.key;
proxy_ssl_trusted_certificate /etc/nginx/ssl/ca.crt;
proxy_ssl_verify on;
proxy_ssl_verify_depth 2;
```

### SPIFFE / SPIRE 集成

[SPIFFE](https://spiffe.io/) 是云原生环境下服务身份的标准。[SPIRE](https://spiffe.io/projects/spire/) 是 SPIFFE 的参考实现。

```bash
# 安装 SPIRE Agent
$ sudo apt install spire-agent

# 获得 SPIFFE ID（自动签的短期证书）
$ spire-agent api fetch x509 \
    -write /etc/nginx/spiffe/svid.pem \
    -write-key /etc/nginx/spiffe/svid.key

# 自动更新证书（cron + 脚本）
$ cat /etc/cron.hourly/spiffe-cert-renew
#!/bin/bash
/usr/bin/spire-agent api fetch x509 \
    -write /etc/nginx/spiffe/svid.pem \
    -write-key /etc/nginx/spiffe/svid.key \
    && systemctl reload nginx
```

### 对比：Linkerd / Istio sidecar + Nginx

| 方案 | 是否修改 Nginx 配置 | 性能开销 | 适用场景 |
|---|---|---|---|
| Nginx mTLS 原生 | 是（改 nginx.conf） | 低（内核 TLS） | 经典架构，已有 Nginx |
| Linkerd（Service Mesher） | 否（注入 sidecar） | 中（HTTP/2 开销） | 纯 Kubernetes 环境 |
| Istio（Envoy） | 否（注入 sidecar） | 中-高（L7 处理） | 要求流量管理 + 安全组合 |

**选择建议**：

- 如果您已经在用 Nginx 做 API 网关，且上游服务不在同一 K8s 集群 → **Nginx 原生 mTLS**
- 如果您是全 K8s 集群，且已经在用 Istio → 不需要专门配 Nginx mTLS，sidecar 自动帮你做
- 如果您不想改 Nginx 配置，又需要 mTLS → **Linkerd**

## API 网关化 Nginx

### Kong

Kong 是开源 API 网关，底层基于 OpenResty（Nginx + LuaJIT）。

```bash
# 安装 Kong（需要先装 PostgreSQL 或 Cassandra）
$ sudo apt install kong
$ kong migrations bootstrap
$ kong start

# 添加一个 Service 并启用插件
$ curl -X POST http://localhost:8001/services \
    -H 'Content-Type: application/json' \
    -d '{"name":"my-api","url":"http://backend:8000"}'

$ curl -X POST http://localhost:8001/services/my-api/routes \
    -d '{"paths":["/api/v1"]}'

# 启用 Rate Limiting 插件
$ curl -X POST http://localhost:8001/services/my-api/plugins \
    -d '{"name":"rate-limiting","config":{"minute":30}}'

# 启用 Key Auth 插件
$ curl -X POST http://localhost:8001/services/my-api/plugins \
    -d '{"name":"key-auth"}'

# 启用 IP Restriction 插件
$ curl -X POST http://localhost:8001/services/my-api/plugins \
    -d '{"name":"ip-restriction","config":{"deny":["10.0.0.0/8"]}}'
```

**Kong vs 原生 Nginx**：

| | Nginx 原生 | Kong |
|---|---|---|
| 配置方式 | nginx.conf + reload | Admin API（RESTful） |
| 插件系统 | Lua + Nginx 模块 | 内置 100+ 插件（反滥用、认证、日志、变换） |
| 动态配置 | 需 reload | 实时生效 |
| 管理面板 | 无 | Kong Manager / Konga（社区版） |
| 性能 | 最高 | 略低于原生（Lua 解释器开销） |

### APISIX

[APISIX](https://apisix.apache.org/) 是 Apache 孵化项目，也是基于 OpenResty。

```bash
# 安装 APISIX
$ curl https://raw.githubusercontent.com/apache/apisix/master/utils/install-dependencies.sh -sL | bash -
$ sudo apt install apisix
$ apisix init
$ apisix start

# 创建路由
$ curl -X POST http://localhost:9180/apisix/admin/routes \
    -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' \
    -d '{
        "uri": "/api/v1/*",
        "upstream": {
            "type": "roundrobin",
            "nodes": {
                "backend:8000": 1
            }
        },
        "plugins": {
            "rate-limit": {"rate": 100, "burst": 200, "key_type": "var", "key": "remote_addr"},
            "jwt-auth": {}
        }
    }'
```

**APISIX vs Kong**：

| | Kong | APISIX |
|---|---|---|
| 社区 | Kong Inc.（商业版 + 开源版） | Apache 孵化器（华为发起的中国社区） |
| 配置中心 | PostgreSQL | etcd（更好的动态配置） |
| 路由规则 | 路径 + 方法 + host | 路径 + 方法 + host + 多维度（支持 L4） |
| 插件开发 | Lua (不能热加载) | Lua + WASM + Java + Go + Python (200+ 插件，热加载) |
| 国内支持 | 中文文档较少 | 中文社区活跃（Apache 中文社区） |

### OpenResty

OpenResty = Nginx + LuaJIT + Lua 模块生态。如果你对性能要求极高且需要自定义逻辑，这是最灵活的选择。

```nginx
# OpenResty Lua 处理请求
http {
    lua_package_path "/etc/nginx/lua/?.lua;;";

    server {
        location /api/ {
            # 先执行 Lua 认证
            access_by_lua_block {
                local jwt = require "resty.jwt"
                local auth_header = ngx.var.http_authorization

                if not auth_header then
                    ngx.status = 401
                    ngx.say("Unauthorized")
                    ngx.exit(401)
                end

                local token = auth_header:match("Bearer%-(.+)")
                if not token then
                    ngx.status = 401
                    ngx.exit(401)
                end

                local jwt_obj = jwt:verify(
                    ngx.shared.jwt_secret:get("key"),
                    token
                )

                if not jwt_obj.verified then
                    ngx.status = 401
                    ngx.exit(401)
                end

                -- 把 decoded payload 传递给 upstream
                ngx.ctx.user = jwt_obj.payload
            }

            # 代理到 upstream
            proxy_set_header X-User-Id $uid_set;
            proxy_pass http://backend:8000;
        }
    }
}
```

**OpenResty 性能对比**：

```
裸 Nginx:         ~100k req/s（纯静态）
Nginx + ModSecurity: ~60k req/s（WAF 开启）
OpenResty + Lua:  ~80k req/s（取决于 Lua 逻辑复杂度）
Kong:              ~50k req/s（Admin API + 插件）
APISIX:            ~55k req/s（etcd 配置中心）
```

## 反向代理 + 负载均衡的纵深防御

这一节专门讲 Nginx 作为上游代理的纵深防御——不是保护 Nginx 本身，而是防止 Nginx 成为攻击者攻击后端服务的"放大器"。

### upstream keepalive 防止慢攻击

```nginx
upstream backend {
    # 核心参数
    server 10.0.1.1:8000 weight=5 max_fails=3 fail_timeout=30s;
    server 10.0.1.2:8000 weight=5 max_fails=3 fail_timeout=30s;
    server 10.0.1.3:8000 backup;   # 冷备

    # keepalive 连接池
    keepalive 32;                    # 保持 32 个上游连接
    keepalive_requests 100;          # 每个连接最多 100 个请求
    keepalive_timeout 60s;           # 空闲 60s 后关闭
}
```

### 健康检查 + 熔断

```nginx
# 主动健康检查（需要 nginx-plus 或 Tengine 的 check 模块）
# 开源版使用 nginx_upstream_check_module（需编译）

location /upstream_status {
    check_status;           # 查看所有 upstream 健康状态
    allow 127.0.0.1;
    deny all;
}

# 被动健康检查（开源版也有）
upstream backend {
    server 10.0.1.1:8000 max_fails=5 fail_timeout=30s;
    server 10.0.1.2:8000 max_fails=5 fail_timeout=30s;
}

# 优雅的熔断（用 proxy_next_upstream 做 retry）
proxy_next_upstream error timeout invalid_header http_500 http_502 http_503;
proxy_next_upstream_tries 3;
proxy_next_upstream_timeout 10s;
```

### 多层 LB 架构

```
Internet
    │
    ├── 边缘 LB（硬件 F5 / NSX / 阿里云 SLB）
    │
    ├── 内部 LB（自建 Nginx，做 TLS termination）
    │
    ├── 应用层 Nginx（做 WAF + 路由 + rate limit）
    │
    └── 上游服务
```

**每一层的职责**：

| 层级 | 职责 | 暴露面 |
|---|---|---|
| 边缘 LB | 防 DDoS、TLS offloading、健康检查 | 公网 |
| 内网 LB | 服务发现、与云 API 交互 | 内网 |
| 应用层 Nginx | WAF、认证、路由、灰度、可观测性 | 内网 (mTLS) |
| 上游服务 | 业务逻辑 | 内网 (mTLS) |

## CDN 与 Nginx 的边界

### Cloudflare / Fastly 模式

如果您在用 Cloudflare CDN：

```nginx
# Nginx 判断请求来源是不是 Cloudflare
# Cloudflare 的 CDN 节点 IP 列表：https://www.cloudflare.com/ips-v4
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
# ...（完整列表 ~20 个网段）
real_ip_header CF-Connecting-IP;
real_ip_recursive on;

# 只有 Cloudflare IP 才能访问回源接口
location /api/private/ {
    allow 10.0.0.0/8;        # 内网直接访问
    deny all;
}

location / {
    # Cloudflare 请求 + 正常流量
    satisfy any;
    allow 10.0.0.0/8;
    deny all;
}
```

### 自建 CDN：Nginx + GeoDNS

```nginx
# 多数据中心权重
upstream dc-beijing {
    server 10.0.1.1:8000 weight=10;
    server 10.0.1.2:8000 weight=10;
}

upstream dc-shanghai {
    server 10.0.2.1:8000 weight=10;
    server 10.0.2.2:8000 weight=10;
}

upstream dc-shenzhen {
    server 10.0.3.1:8000 weight=5;
    server 10.0.3.2:8000 weight=5;
    server 10.0.3.3:8000 weight=5 backup;  # 第三地做冷备
}

# 缓存 CDN 节点
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=cdn:500m max_size=20g inactive=60d use_temp_path=off;

server {
    location /static/ {
        proxy_cache cdn;
        proxy_cache_key "$scheme$host$request_uri$http_x_forwarded_proto";
        proxy_cache_valid 200 30d;
        proxy_cache_valid 404 1m;
        proxy_cache_use_stale error timeout updating http_500 http_502 http_503;

        # 防止缓存投毒
        proxy_cache_lock on;
        proxy_cache_lock_timeout 5s;

        # 缓存 key 中加入 cookie（如果不希望缓存投毒跨用户）
        add_header X-Cache-Status $upstream_cache_status;

        proxy_pass http://dc-shanghai;
    }
}
```

### Cache Poisoning 防护

缓存投毒是 CDN 独有的攻击面。攻击者通过构造恶意请求，让 CDN 节点缓存错误的响应，然后所有用户都看到恶意内容。

```nginx
# 关键：proxy_cache_key 必须包含影响响应的 header / cookie / argument
proxy_cache_key "$scheme$host$request_uri$http_x_forwarded_proto";

# 更严格的 key（考虑 cookie 中的用户标识）
proxy_cache_key "$scheme$host$request_uri$cookie_user_type$http_x_forwarded_proto";

# 或者，只有 GET 请求才缓存（POST 请求不应缓存）
proxy_cache_methods GET HEAD;

# 限制可缓存的响应类型
proxy_cache_valid 200 302 30m;
proxy_cache_valid 404 1m;
proxy_cache_valid 500 0;      # 服务器错误不缓存
```

## 灰度发布

灰度发布不是传统意义上的"安全"功能，但在生产环境中，**没有灰度发布的配置变更≈安全漏洞**——因为一行配错的 nginx.conf 可能导致全网瘫痪。

### 基于 HTTP header 的 A/B 路由

```nginx
# 通过特定的 header 进行灰度分发
map $http_x_canary $backend {
    default    default;
    "canary"   canary;
}

upstream default {
    server 10.0.1.1:8000;
    server 10.0.1.2:8000;
}

upstream canary {
    server 10.0.1.3:8000;  # 金丝雀版本
}

server {
    location / {
        proxy_pass http://$backend;
    }
}
```

**测试**：

```bash
# 正常用户（走 default）
$ curl https://target.com/

# 金丝雀用户（走 canary）
$ curl -H "X-Canary: canary" https://target.com/
```

### 基于 cookie 的用户分桶

```nginx
# 根据 user_id 分 100 个桶，桶 0-4 走灰度版本
map $cookie_user_id $bucket {
    ~^(0|[1-9][0-9]*)$ $1;
    default 101;
}

split_clients "${remote_addr}${http_user_agent}" $variant {
    5%     canary;
    *      stable;
}

upstream stable {
    server 10.0.1.1:8000;
}

upstream canary {
    server 10.0.1.2:8000;  # v2 版本
}

server {
    location / {
        proxy_pass http://$variant;
    }
}
```

### 基于权重的金丝雀发布

```nginx
# 逐步增加灰度流量权重
upstream stable {
    server 10.0.1.1:8000 weight=90;
}

upstream canary {
    server 10.0.1.2:8000 weight=10;  # 先 10% 流量
}
```

## 小结

这一章的技术不是"安全加固"，是**高级架构安全**——当您的业务规模达到 Nginx 做 API 网关 + 多数据中心 + 灰度发布 + CDN，这些能力就成了安全的基础设施。

| 技术 | 解决的问题 | 适用场景 |
|---|---|---|
| TLS 1.3 | 加密层 | 所有新部署 |
| mTLS | 服务间认证 | 微服务架构 |
| API 网关（Kong / APISIX） | 多服务入口 | 10+ 个 API 路由 |
| 多层 LB | 性能 + DDoS | 高可用部署 |
| CDN + 缓存 | 性能 + 安全 | 全球分发 |
| 灰度发布 | 变更安全 | 所有生产环境 |

### 自测题

**题 1**：用 `openssl s_client` 验证你的 TLS 配置是否支持 TLS 1.3。

<details>
<summary>参考答案</summary>

```bash
$ openssl s_client -connect target.com:443 -tls1_3 < /dev/null 2>&1
# 如果输出包含 "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384" → 支持
# 如果输出 "No peer certificate available" → 不支持 TLS 1.3
```
</details>

**题 2**：您的 Nginx 与上游服务之间是 HTTP 还是 HTTPS？是否需要 mTLS？

<details>
<summary>检查清单</summary>

- 查看 `proxy_pass` 是 `http://` 还是 `https://`
- 如果是 `http://` → 流量在内网以明文传输，建议上 mTLS
- 是否在云 VPC 内？在 VPC 内可以信任 VPC 边界安全，不在 VPC 内必须上 mTLS
</details>

**题 3**：您生产环境的 `proxy_cache_key` 是什么？它是否合理？

<details>
<summary>提示</summary>

翻看 nginx.conf 里的 `proxy_cache_key`。常见错误：
- 没有包含 `$http_x_forwarded_proto` → HTTP/HTTPS 混存
- 包含了 `$cookie_session_id` → 缓存 key 膨胀到每个 session 一个
- 理想设计：`$scheme$host$request_uri$http_x_forwarded_proto`
</details>
