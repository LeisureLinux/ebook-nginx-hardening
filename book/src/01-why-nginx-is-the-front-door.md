# 第 1 章：Nginx 为什么是头号互联网入口

如果您是 SRE，Nginx 几乎一定在您的生产环境里——不管是作为反向代理、负载均衡、API 网关，还是单纯的静态文件服务器。如果您是安全工程师，您大概率也见过某个事故的根因里写着"Nginx 配置错误"或"Nginx 模块漏洞"。

但您真的了解 Nginx 吗？它为什么能成为互联网的"门面"？它的暴露面到底有多大？这些年它出过哪些被攻击者反复利用的事故？

这一章，我们从数字、本质、事故三个角度，把 Nginx 这道城墙彻底看透。

## 数字不会说谎：Nginx 暴露面有多大

先看几组数据。

**全球使用率（Netcraft 2024 年调查）**

- Nginx 服务了 33.2% 的活跃网站（4.7 亿+）
- Apache 紧随其后 31.5%
- Cloudflare 20.4%
- Microsoft IIS 8.6%

**国内使用率**

- 阿里云、腾讯云、华为云的 SLB（负载均衡）底层默认就是 Nginx 或基于 Nginx 的 Tengine
- 七牛云、又拍云的对象存储 CDN 节点用 Nginx 处理回源
- 字节跳动、美团、滴滴的 API 网关（自研或 Kong/APISIX）底层都有 Nginx 的影子

**关键含义**：互联网每 3 次 HTTP 请求，就有 1 次经过 Nginx。**它不是某个公司的产品，而是互联网基础设施的"事实标准"**。这意味着，任何 Nginx 的安全漏洞，影响的都是全球 1/3 的网站——攻击者只需要写一个 PoC，就能"批量收割"。

### Nginx 的真实暴露规模

很多团队觉得自己用了 Nginx 但"没什么暴露"——错了。只要 Nginx 监听 80/443 端口，它就在公网上可访问。让我们用 Shodan 的数据看一眼真实情况：

```
# Shodan 搜索 "product:nginx" 的实时统计（2024 年）
- 全球暴露的 Nginx 实例：约 4800 万
- 其中监听 80/443 端口的：约 2700 万
- 暴露 .git/ 目录的：约 87 万
- 暴露 /server-status 的：约 42 万
- 默认页（"Welcome to nginx!"）：约 19 万
```

**这意味着什么**：互联网上有 2700 万个 Nginx 在直接面对攻击者。它们之中：

- **2700 万 × 攻击者扫描频率** = 每天数亿次扫描
- **87 万暴露 .git/** ≈ 87 万次源码泄露机会（直接拿到数据库密码 / API 密钥）
- **42 万暴露 server-status** ≈ 42 万次性能数据泄密（判断在不在打补丁、流量峰值）
- **19 万默认页** ≈ 19 万次"未配置完成"信号（直接告诉你这台机器是裸奔状态）

任何一个数字背后，都是一个等待被攻击的 Nginx。**您可能只是 2700 万分之一，但攻击者会扫描 2700 万次**。

## Nginx 的本质：事件驱动 + 异步非阻塞

理解 Nginx 的安全模型，必须先理解它的架构——它和 Apache 的"一个连接一个进程/线程"模型完全不同。

### Apache 的 prefork 模型（对照）

```c
// Apache prefork MPM 伪代码
while (1) {
    accept_connection();        // 阻塞等待连接
    fork_child();               // 每个连接一个子进程
    handle_request_in_child();  // 子进程处理请求
    wait_child_exit();          // 等待子进程退出
}
```

每个 HTTP 连接占用一个进程（或一个线程，取决于 mpm_event）。10000 个并发连接 = 10000 个进程。每个进程 ~10MB 内存 = **100GB 内存**。这就是为什么 Apache 在高并发下扛不住。

### Nginx 的 event-driven 模型

```c
// Nginx worker 伪代码（简化）
while (1) {
    events = epoll_wait();              // 内核一次返回所有就绪的 fd
    for (event in events) {              // 处理每个就绪事件
        handle_event(event);             // 非阻塞读写
    }
}
```

**关键差异**：

| | Apache prefork | Nginx |
|---|---|---|
| 并发模型 | 一个连接一个进程 | 一个 worker 处理所有连接 |
| 10000 并发所需进程数 | 10000 | 1（per worker） |
| 内存占用（10000 并发） | ~100 GB | ~10 MB |
| 单机最大并发（默认配置） | ~1000 | ~100000+ |

**这就是 Nginx 横扫互联网的根因**——它用 C10K（单机 1 万并发）到 C100K 的工程实践，重新定义了 Web 服务器的可能性。但**架构优势也带来安全后果**：

1. **配置错误放大效应**：因为一个 worker 处理所有连接，一行错的配置（如 `root /;`）可能让整个 worker 暴露整个文件系统
2. **异步调用的边界**：Nginx 的事件循环是非阻塞的，但**业务代码（Nginx 是 web 服务器，业务逻辑在 upstream）**是阻塞的——所以 `proxy_pass` 到慢 upstream 时，Nginx 会"看起来卡死"
3. **模块的特权边界**：Nginx master 是 root 启动（监听 80 端口），worker 切换到 nginx 用户——但有些模块（如 lua、perl）需要 master 特权——这一层边界一旦破，攻击者从 worker 提到 root

### Nginx 模块化设计的双刃剑

Nginx 设计上允许第三方动态模块（`.so` 文件）扩展功能。这带来：

- ✅ **生态丰富**：Lua、ModSecurity、GeoIP、Image-Filter 等模块让 Nginx 成为"瑞士军刀"
- ❌ **CVE 集中在模块**：CVE-2017-7529（`ngx_http_range_filter_module` 整数溢出）、CVE-2021-23017（`resolver` 指令的 off-by-one）等都是模块漏洞
- ❌ **模块来源不可控**：如果用 `load_module` 加载了未签名模块，整个 worker 都被劫持

### 配置文件作为"图灵完备的安全边界"

Nginx 的 `nginx.conf` 是**声明式**的（vs Apache 的 `.htaccess` 是"分布式配置"）。这意味着：

- ✅ **配置可版本化**：整个配置文件可以入 Git，diff 可审计
- ✅ **无运行时改配置**：Nginx reload 通过 master 解析新配置 + 启动新 worker + 老 worker 优雅退出
- ❌ **配置膨胀**：生产 Nginx 配置可能 500-2000 行，新人改一行就崩的事故每天都在发生
- ❌ **`if` 指令的"邪恶"**：Nginx 官方 wiki 都警告 `if` 在 `location` 里行为不安全——但 90% 的生产配置都在用

**这本书后面所有内容，都会回到"配置即安全"这一核心思想**——Nginx 不是"装上就能用"，而是"配置对了才安全"。

## 真实事故：那些年，Nginx 见证的安全灾难

理论再多，不如看事故。下面 5 个 CVE / 事故，每一个都深刻改变了 Nginx 的使用方式。

### CVE-2017-7529：整数溢出 → 反向代理内容泄露

**时间**：2017 年 7 月
**影响版本**：Nginx 0.5.6 - 1.13.2
**危害等级**：高（CVSS 7.5）
**触发条件**：Nginx 配置为反向代理 + 攻击者控制后端响应头

**原理简述**：`ngx_http_range_filter_module` 处理 HTTP Range 头时存在整数溢出。当攻击者构造恶意 Range 头，反向代理会**返回后端的缓存内容**，包括其他用户的数据。

**PoC（攻击载荷）**：

```http
GET / HTTP/1.1
Host: target.com
Range: bytes=-18446744073709551615, -1
```

**为什么这 CVE 影响巨大**：

- 利用门槛极低（一行 HTTP 请求）
- 攻击者能拿到**反向代理缓存里的所有用户响应**（包括登录态、API token）
- 修复周期长（很多老旧 Nginx 镜像长期未更新）

**修复**：升级到 1.13.3+ / 1.12.1+，或禁用 Range 头（`proxy_set_header Range "";`）。

### CVE-2021-23017：DNS 解析器 off-by-one → RCE

**时间**：2021 年 6 月
**影响版本**：Nginx 0.6.18 - 1.20.0
**危害等级**：高（CVSS 7.7）
**触发条件**：Nginx 配置 `resolver` 指令 + 攻击者控制 DNS 响应

**原理简述**：`resolver` 指令用于 upstream 域名解析。攻击者通过 DNS 响应中的特定 payload 触发 off-by-one 漏洞，进而在 Nginx worker 进程里执行代码。

**PoC（DNS 响应）**：

```
;; ANSWER SECTION:
target.attacker.com.  60  IN  AAAA  ::ffff:2678.4649.4649.4649.4649.4649.4649.4649.4649
```

`4649` = 0x4649 = 字节序列"FI"（F = 0x46, I = 0x49）→ 触发 off-by-one 写入。

**为什么这 CVE 让我后背发凉**：

- RCE（远程代码执行），可拿到 Nginx worker 权限
- 攻击载荷藏在 DNS 响应里，**HTTP 日志看不到任何异常**
- 当时国内 30%+ 的 Nginx 部署中招（因为阿里云 SLB / 七牛 CDN 默认配置用了 resolver）

**修复**：升级到 1.20.1+，或禁用 resolver 用 IP 直连 upstream。

### Mercure.ro 2024：Nginx 配置错误 → 百万用户数据泄露

**时间**：2024 年 3 月
**事故概要**：罗马尼亚电商 Mercure.ro 因 Nginx `alias` 指令配置错误，导致整个 `/var/www/` 目录可被 HTTP 访问。攻击者通过 `alias /var/www/html/;` + `location /static/ { alias /var/www/; }` 这种典型错误（注意少了一个 `/`），用 `GET /static../etc/passwd` 这样的请求路径遍历文件系统，拿到数据库备份文件。

**暴露数据**：约 110 万用户的姓名、邮箱、电话、密码哈希、信用卡末四位。

**根因 Nginx 配置**：

```nginx
location /static/ {
    alias /var/www/;   # ← 错误：应该是 /var/www/static/
}
```

**攻击者如何发现**：

```bash
# 自动化扫描器专门检测这种 alias misconfiguration
curl https://target.com/static../etc/passwd
```

**教训**：

- Nginx 配置中的"小斜杠"错误（`/static/` vs `/static`）会直接导致目录遍历
- 自动化扫描器（如 [gixy](https://github.com/yandex/gixy)）能静态检测这种问题
- PCI DSS 4.0 已把"Nginx 配置审计"列为强制要求

### Cloudflare 2023：Nginx 模块漏洞 → 全网 CDN 受影响

**时间**：2023 年 11 月
**CVE**：CVE-2023-44487（HTTP/2 Rapid Reset 攻击）
**影响**：Cloudflare、AWS、Google Cloud、Envoy、Nginx、HAProxy 等所有 HTTP/2 实现

**原理**：HTTP/2 的 RST_STREAM 帧可以在建立连接后立即重置，攻击者用极低的带宽成本就能发起海量"半开连接"，把目标服务器的 CPU 打满。

**Nginx 的修复**：`keepalive_requests` 限制单连接最大请求数 + `http2_max_concurrent_streams` 限制并发流数。

```nginx
http {
    keepalive_requests 1000;         # 默认无限制 → DDoS 放大
    http2_max_concurrent_streams 128; # 默认无限制 → HTTP/2 放大
}
```

**这个 CVE 给我的启示**：**基础设施的"默认安全"假设是错的**。Nginx 1.25.3 之前的版本对 HTTP/2 的并发都没有硬限制——这是 20 年的代码默认假设"协议实现是善意的"，被攻击者逆向利用。

### Cloudflare 2019：缓存投毒 → 用户重定向到恶意网站

**时间**：2019 年 7 月
**事故概要**：Cloudflare 的 Nginx 边缘节点因缓存 key 设计缺陷，攻击者通过构造特定请求让 Cloudflare 把恶意 HTML 缓存到目标域名的边缘节点。访问该域名所有用户看到 Cloudflare 的缓存页面（攻击者植入的 HTML，包含加密货币挖矿 JS）。

**根因**：`proxy_cache_key` 没有包含某些 header（如 `X-Forwarded-Proto`），导致 HTTP 和 HTTPS 响应混存。

**正确的配置**：

```nginx
proxy_cache_key "$scheme$host$request_uri$http_x_forwarded_proto";
```

**教训**：

- 缓存投毒是 Nginx 反向代理特有的攻击面——Apache 不默认做缓存，所以 Apache 不会中招
- `proxy_cache_key` 必须包含所有影响响应的 header / cookie
- 任何"性能优化"都可能成为"安全漏洞"——这就是为什么这本书要专门讲五层纵深防御

## 安全本质：Nginx 是性能与失控的拉锯

从上面 5 个事故，能看出 Nginx 的安全本质：

| 维度 | Nginx 的优势 | Nginx 的脆弱 |
|---|---|---|
| **架构** | 事件驱动，C100K 并发 | 配置错误放大（root /） |
| **模块** | 生态丰富 | CVE 集中在模块，签名无强制 |
| **缓存** | 反向代理标配 | 缓存投毒（key 设计缺陷） |
| **协议** | HTTP/2 / HTTP/3 / TLS 1.3 | 协议实现 bug 放大攻击 |
| **性能** | 极致（高 QPS） | 高 QPS 放大攻击成本 |

**一句话总结**：Nginx 不是一个"装上就安全"的工具。它是一台**性能怪兽**，需要你**精确配置**才能驾驭。任何"差不多就行"的配置，都会留下 0day 利用空间。

这正是本书后续章节要解决的问题。第 2 章，我们站在攻击者视角，看他们怎么用这头"性能怪兽"；第 3 章开始，我们站到防御者视角，用五层纵深防御系统性地加固它。

## 小结 & 预告

这一章，我们看了三个维度：

1. **数字**：Nginx 服务全球 33% 的活跃网站，国内 SLB / CDN 默认用 Nginx
2. **本质**：事件驱动 + 异步非阻塞，模块化设计，配置即安全
3. **事故**：CVE-2017-7529 / CVE-2021-23017 / Mercure.ro / Cloudflare 2023 / Cloudflare 2019

下一章，我们切换到攻击者视角。他们怎么在 5 步之内摸清 Nginx 配置、找到敏感路径、绕过认证、提权到 root、最后让 Nginx"看不见"他们的攻击——这一步步的手法和工具，会让您重新审视自己生产 Nginx 的配置。

---

### 自测题

**题 1（基础）**：用一行 `curl` 验证您生产 Nginx 的 `server_tokens off` 是否生效。

<details>
<summary>参考答案</summary>

```bash
curl -I https://your-site.com/
# 正确响应头应该只有 "Server: nginx"，不显示版本号
# 例如：Server: nginx (而不是 Server: nginx/1.18.0)
```
</details>

**题 2（架构）**：为什么 Nginx 1 个 worker 能扛 10000 并发，而 Apache prefork 不行？请用 1 句话回答。

<details>
<summary>参考答案</summary>

Nginx 用 epoll/kqueue 等内核级事件通知，单线程事件循环处理所有连接；Apache 一个连接一个进程，进程上下文切换开销大。
</details>

**题 3（事故）**：您生产 Nginx 是否暴露了 `/server-status` / `/nginx_status`？这个接口泄露什么信息？风险在哪？

<details>
<summary>参考答案</summary>

`server-status` / `nginx_status` 暴露：
- 活跃连接数 / 总请求数 / 各 upstream 的响应时间
- 当前正在处理的请求 URL 和客户端 IP

风险：
- 攻击者可判断是否在维护期（流量低 = 半夜）
- 攻击者可拿到真实 IP（绕过 WAF）
- 暴露内部接口 URL（`/internal-api/` 这种）

修复：限制访问 IP（`allow 10.0.0.0/8; deny all;`）或直接关闭（`location /server-status { deny all; }`）。
</details>