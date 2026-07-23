# 附录 A：Nginx 配置速查表

## A.1 HTTP 模块全表（最常用指令）

| 指令 | 上下文 | 说明 | 默认值 | 安全影响 |
|---|---|---|---|---|
| `server_tokens` | http server location | 显示 Nginx 版本 | on | **高**：暴露版本号触发 CVE 扫描 |
| `add_header` | http server location | 添加响应头 | — | **高**：HSTS / CSP 头 |
| `ssl_protocols` | http server | TLS 可用版本 | TLSv1 TLSv1.1 TLSv1.2 | **高**：影响加密强度 |
| `ssl_ciphers` | http server | 允许的 cipher | HIGH:!aNULL:!MD5 | **中**：影响前向安全 |
| `limit_req_zone` | http | 请求限流区域定义 | — | **高**：防爆力破解 |
| `limit_conn_zone` | http | 连接限流区域定义 | — | **中**：防连接耗尽 |
| `proxy_pass` | location | 上游代理 | — | **高**：SSRF 攻击面 |
| `alias` | location | 路径别名 | — | **高**：目录遍历漏洞 |
| `root` | http server location | 根目录路径 | — | **高**：路径泄露 |
| `resolver` | http server location | DNS 解析器 | — | **高**：SSRF + RCE |

## A.2 核心指令速查（按场景）

### 安全加固必配

```nginx
server_tokens off;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
```

### 限流

```nginx
# 请求频率
limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;

# 连接数
limit_conn_zone $binary_remote_addr zone=addr:40m;

# 使用
location /login/ {
    limit_req zone=login burst=5 nodelay;
    limit_conn addr 10;
}
```

### 访问控制

```nginx
# IP 白名单
location /admin/ {
    allow 10.0.0.0/8;
    allow 172.16.0.0/12;
    allow 192.168.0.0/16;
    deny all;
}

# JWT 认证
auth_jwt "API";
auth_jwt_key_file /etc/nginx/jwt_public_key.pem;
auth_jwt_require $jwt_claim_role "admin";

# HTTP Basic Auth
auth_basic "Restricted";
auth_basic_user_file /etc/nginx/.htpasswd;
```

### Upstream

```nginx
upstream backend {
    server 10.0.1.1:8000 weight=5 max_fails=3 fail_timeout=30s;
    server 10.0.1.2:8000 weight=5 max_fails=3 fail_timeout=30s;
    server 10.0.1.3:8000 backup;
    keepalive 32;
    keepalive_requests 100;
    keepalive_timeout 60s;
}
```

## A.3 内置变量全集（按类别）

### HTTP 请求相关

| 变量名 | 说明 | 安全注意事项 |
|---|---|---|
| `$remote_addr` | 客户端 IP | 默认，`set_real_ip_from` 配置后可能被覆盖 |
| `$http_x_forwarded_for` | X-Forwarded-For 头 | 攻击者伪造源 IP |
| `$http_user_agent` | User-Agent | 可用于 Bot 检测 |
| `$http_referer` | Referer | 可能泄露内部 URL |
| `$request_uri` | 原始请求 URL | 包含查询参数 |
| `$request_method` | GET/POST/HEAD/... | 用于限制方法 |

### Upstream 相关

| 变量名 | 说明 | 安全注意事项 |
|---|---|---|
| `$upstream_addr` | 上游服务的地址 | 暴露内部 IP |
| `$upstream_status` | 上游返回的 HTTP 状态码 | 用于熔断决策 |
| `$upstream_response_time` | 上游响应时间 | 用于性能监控 |
| `$upstream_cache_status` | 缓存是否命中 | HIT / MISS / BYPASS |

### SSL/TLS 相关

| 变量名 | 说明 | 安全注意事项 |
|---|---|---|
| `$ssl_protocol` | TLS 版本（TLSv1.2/TLSv1.3） | mTLS 客户端证书 |
| `$ssl_cipher` | 使用的 cipher | mTLS 客户端证书 |
| `$ssl_client_cert` | 客户端证书（PEM base64） | mTLS 客户端证书 |
| `$ssl_client_s_dn` | 客户端证书 DN | 用于验证证书内容 |
| `$ssl_client_serial` | 客户端证书序列号 | 用于证书吊销检查 |

## A.4 性能调优 Checklist

### 基础系统配置

```bash
# 内核参数
$ cat >> /etc/sysctl.conf <<'EOF'
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.ip_local_port_range = 1024 65000
EOF
$ sysctl -p

# 文件描述符
$ ulimit -n 65535
```

### Nginx worker 配置

```nginx
# CPU 亲和性配置
worker_processes auto;
worker_cpu_affinity auto;

# 事件模块
events {
    worker_connections 65535;
    use epoll;
    multi_accept on;
}

# 缓冲区
http {
    client_body_buffer_size 128k;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 8k;
    client_max_body_size 10m;
    client_body_timeout 12s;
    client_header_timeout 12s;
    send_timeout 10s;

    # 静态文件
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;

    # gzip
    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
    gzip_min_length 1000;
    gzip_vary on;
    gzip_proxied any;
}
```

### Benchmark 工具

```bash
# 压测
$ ab -n 100000 -c 100 -k https://target.com/
$ wrk -t4 -c100 -d30s https://target.com/
$ siege -c100 -t30s https://target.com/

# h2load（HTTP/2 压测）
$ h2load -n 50000 -c 50 -m 10 https://target.com/
```
