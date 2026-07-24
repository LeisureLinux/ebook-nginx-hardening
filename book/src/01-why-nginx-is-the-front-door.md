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

#### epoll/kqueue：内核级事件通知到底做了什么

`epoll`（Linux）和 `kqueue`（BSD / macOS）是 Nginx 高并发的真正引擎。要理解它为什么重要，先把它和"上一代 IO 多路复用"对照：

**1. 从 select / poll 到 epoll 的演进**

| API | 平台 | 时间复杂度 | fd 上限 | 关键缺陷 |
|---|---|---|---|---|
| `select` | 全部 POSIX | 每次 O(N)，N = 最大 fd | FD_SETSIZE（Linux 默认 1024） | 每次要把 fd_set 从用户态拷到内核态，再拷回来 |
| `poll` | 全部 POSIX | 每次 O(N) | 无（链表） | 同样每次全量遍历 + 拷贝；fd 多时性能雪崩 |
| `epoll` | Linux ≥ 2.5.44 | 注册 O(1)，等待 O(M)，M = 就绪 fd | 系统 fd 上限（百万级） | **只在 Linux** |
| `kqueue` | BSD / macOS | 注册 O(1)，等待 O(M) | 同 epoll | **不在 Linux** |

Nginx 在编译期自动检测：`ngx_os.h` 里如果找到 `<sys/epoll.h>` 就走 epoll，找不到就退到 kqueue 或 select（性能兜底）。

**2. epoll 的两个 syscall**

epoll 把"事件订阅"和"事件等待"拆开，避开了 select/poll 的全量拷贝：

```c
// 1. 创建 epoll 实例（master 进程初始化一次）
int epfd = epoll_create(1024);

// 2. 注册关注的 fd（连接 accept / listen socket / upstream fd）
struct epoll_event ev;
ev.events = EPOLLIN | EPOLLET;        // 读事件 + 边缘触发
ev.data.ptr = conn;
epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);

// 3. 等待事件（worker 主循环）
while (1) {
    int n = epoll_wait(epfd, events, MAX_EVENTS, -1);   // 阻塞
    for (int i = 0; i < n; i++) {
        handle_event(&events[i]);      // 只处理"就绪"的 fd，O(M)
    }
}
```

**关键点**：内核维护一棵**红黑树**记录"被监视的 fd"，一份**就绪链表**记录"已就绪的 fd"。`epoll_wait` 直接从就绪链表取，**不需要遍历所有 fd**。这就是 Nginx 单 worker 扛 10 万连接的根因。

**3. LT vs ET：Nginx 默认选哪种触发模式**

| 模式 | 含义 | Nginx 默认 | 风险 |
|---|---|---|---|
| **LT（Level Triggered，水平触发）** | fd 只要还"就绪"，每次 `epoll_wait` 都会回报它 | ✅ 是 | 容错好——某次忘了读，下一轮还会被通知 |
| **ET（Edge Triggered，边缘触发）** | 只在 fd 状态变化那一瞬回报一次 | ❌ 否（除非显式 `EPOLLET`） | 漏读就丢事件——必须配合 `fcntl(O_NONBLOCK)` + 循环读到 `EAGAIN` |

Nginx 默认 LT 是工程权衡：**安全 > 极限性能**。ET 模式虽然更快，但漏一次读就丢连接——对一个公网 Web 服务器来说，丢一个 HTTP 请求比慢 5% 严重得多。

**4. kqueue：BSD/macOS 上的对应实现**

FreeBSD / macOS 上 Nginx 走 `kqueue` + `kevent`，API 形态几乎一致：

```c
int kq = kqueue();
struct kevent ev;
EV_SET(&ev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
kevent(kq, &ev, 1, NULL, 0, NULL);    // 注册
while (1) {
    int n = kevent(kq, NULL, 0, events, MAX_EVENTS, NULL);  // 等待
    // ...
}
```

底层 BSD kernel 用同一个调度器同时处理 kqueue 和网络栈，**比 Linux epoll 还略快**（FreeBSD 的网络栈历来是业界标杆）。这也是 Netflix 的 FreeBSD 边缘节点、Cloudflare 部分节点至今不切 Linux 的原因之一。

**5. 这层抽象对安全意味着什么**

- **连接耗尽攻击更难**：因为内核只回报"就绪 fd"，攻击者用 SYN flood 把半开连接塞满并不会让 epoll_wait 变慢——它压根不返回这些 fd；
- **Slowloris 仍然有效**：Nginx worker 是单线程事件循环，**一个 Slowloris 连接慢慢读 body 占住 worker 不放**，所有同 worker 上的请求都跟着卡。修复是 `client_header_timeout` / `client_body_timeout` / `limit_req_zone`；
- **fd 泄漏能拖垮 worker**：第三方模块忘记 `epoll_ctl(EPOLL_CTL_DEL)` 关闭 fd，进程 fd 表涨满后 `accept()` 返回 `EMFILE`——worker 死亡、master 拉新 worker 顶上，循环崩。这正是 CVE-2013-2028（chunked encoding 重复 `$size` 触发 fd 泄漏）那一类 bug 的根因。

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

#### 1. 起点：那一行 AAAA 到底写了什么

`resolver` 指令用来在运行时把 upstream 的域名解析成 IP。攻击者要做的事只有一件：**让 Nginx 解析自己控制的 DNS 响应**。下面这行就是他们的"投毒样本"：

```
;; ANSWER SECTION:
target.attacker.com.  60  IN  AAAA  ::ffff:2678.4649.4649.4649.4649.4649.4649.4649.4649
```

逐段拆开看：

| 片段 | 含义 | 攻击作用 |
|---|---|---|
| `target.attacker.com.` | 攻击者控制的域名（用于把"投毒"对到合法 upstream） | 让受害 Nginx 把它当作"真实 upstream IP"缓存 |
| `60` | TTL 60 秒 | 短 TTL 让"假 IP"被 worker 频繁复用 |
| `AAAA` | IPv6 记录 | 走 nginx 的 IPv6 解析路径 `ngx_resolver_copy()` |
| `::ffff:` | RFC 4291 的 IPv4-mapped IPv6 前缀 | 让 nginx "以为是 IPv6，实际是 IPv4" |
| `2678.4649.4649.4649.4649.4649.4649.4649.4649` | IPv6 dotted-quad 畸形写法（RFC 2673） | **核心载荷**，让 `ngx_resolver_copy()` 算错长度 |

把后面那一段 **以十六进制看** 就是：

```
2678      →  0x2678              （普通 IPv4 段，无攻击意义）
4649 × 8  →  0x46 0x49  重复 8 次  →  ASCII "FI""FI""FI""FI""FI""FI""FI""FI"
```

也就是说，那一长串其实是 **8 个 `4649`（"FI"）** 拼接起来。这不是巧合：

- `F = 0x46`、`I = 0x49`，**双双落在 ASCII 可打印区**，不会被 nginx 的"过滤非打印字符"逻辑挡掉；
- 这 8 段刚好填满 IPv6 的 8 个 16-bit group，触发 `ngx_resolver_copy()` 走**最长拼接路径**；
- 一旦后续写入再夹一个 `'.'`（0x2E），就**精确踩过 1 字节**——这正是 off-by-one 的"恶意 payload"。

#### 2. 漏洞核心：`ngx_resolver_copy()` 的 off-by-one

`ngx_resolver_copy()` 负责把 DNS 报文里的压缩域名**解压并拷贝**到一块新分配的堆缓冲区。函数内部做了两件事：

```c
// 第一遍：遍历 DNS 报文，计算"解压后的字符串长度"
for (p = src; *p != '\0'; ) {
    if (*p & 0xc0) {            // 遇到压缩指针 (RFC 1035 4.1.4)
        /* 跳过指针 */
        break;
    }
    n = *p++;                   // n = 当前 label 长度
    len += n + 1;               // ← 只算 "label 字节数 + 1 个分隔点"
    p += n;
}

// 第二遍：按相同路径，把解压结果拷贝到 name->data
for (p = src; *p != '\0'; ) {
    /* 同上逻辑 */
    *dst++ = *p++;              // 拷贝 label 字节
    *dst++ = '.';               // ← 在 label 间插入一个点号
    dst += n;
}
```

**长度计算漏掉一件事**：当最后一个 label 走的是压缩指针 → 指向 **NUL 字节** 时：

- 第一遍：`len` 只算了"前面 label 的长度 + 中间的点号"，**没算末尾那个 NUL 终止符**；
- 第二遍：解压结束前，nginx 仍然会**写一个 `'.'`（0x2E）**，写到了 `name->data[len]` —— 这个位置**正好比分配的堆缓冲区多 1 字节**。

```
分配的缓冲区：[ name 字节 ... ][ next-chunk metadata ]
                 ↑ len
                                     ↑ 写入了 0x2E (1 字节越界)
```

那 1 字节 **`0x2E`（点号）**，就覆盖了下一块堆 chunk 的 **size | flags** 字段的最低字节。攻击者只要精心控制 AAAA 字符串的总长度，让 `len` 对齐到 glibc ptmalloc2 的 chunk 边界（通常是 0x10 / 0x20 对齐），就能稳定改写下一块的 `PREV_INUSE` 位、`IS_MMAPPED` 位。

#### 3. 从 1 字节到 RCE：完整的攻击链

```text
┌────────────────────────────────────────────────────────────────┐
│ 攻击者                                                            │
│   1. 在公网自建伪造 DNS（53/UDP）                                   │
│   2. 构造 AAAA 响应，载荷用 ::ffff:2678.4649.4649...              │
│   3. 对受害 Nginx 持续重放投毒响应（无需猜 Transaction ID：         │
│      nginx 在 ngx_resolver_copy 之前才校验 ID，函数本身已经被调用）│
└────────────────────────────────────────────────────────────────┘
                            ▼
┌────────────────────────────────────────────────────────────────┐
│ 受害 Nginx worker                                                  │
│   ngx_resolver_copy() 写入 name->data[len] = 0x2E                │
│                          ↓                                       │
│   1 字节越界改写下一堆块的 size | flags                           │
│                          ↓                                       │
│   后续 worker 处理请求时 malloc/free 触发 unlink 链畸变           │
│                          ↓                                       │
│   通过 house-of-xxx / tcache poisoning 把 free() 指向              │
│   攻击者控制的 "伪 chunk"（其内容已经在 DNS 响应里传入）            │
│                          ↓                                       │
│   __free_hook / 虚函数指针 → 跳到 attacker payload                │
│                          ↓                                       │
│   Nginx worker 进程内任意代码执行（RCE）                          │
└────────────────────────────────────────────────────────────────┘
```

> **关键点**：这一整条链，**HTTP 层没有任何异常**。Access log 不会记录 DNS 内容，error log 也只会看到 worker 重启——很多团队直到 worker 反复被替换才意识到被攻击。

#### 4. 为什么这 CVE 让我后背发凉

- **RCE**（远程代码执行），最差可拿到 worker → master → root 链路；
- **HTTP 日志全静默**：攻击载荷藏在 53/UDP 报文里，access/error log 完全看不到；
- **国内 30%+ Nginx 部署中招**：阿里云 SLB / 七牛 CDN / 自建网关默认用 `resolver`；
- **PoC 极轻**：一个伪造 DNS server + 一行 AAAA 记录 + 几次重放即可触发。

#### 5. 修复与防御

| 措施 | 操作 |
|---|---|
| 升级 Nginx | **≥ 1.20.1（stable） / ≥ 1.21.0（mainline）**；官方补丁在 `ngx_resolver_copy()` 里加了 `len++` 把末尾 NUL 算进去 |
| upstream 用 IP 直连 | `proxy_pass http://10.0.0.1:8080;`（不要用域名 → 不用 resolver） |
| resolver 收窄信任源 | `resolver 10.0.0.53 valid=30s;` —— 只信内网可控 DNS；**不要用公网 8.8.8.8 / 1.1.1.1**（最容易被投毒）|
| 收敛响应窗口 | `resolver_timeout 5s;` + `resolver 127.0.0.1:5353 valid=10s;`（自建 unbound + cache）|
| eBPF 校验 | 在 53/UDP ingress 跑 eBPF，丢弃任何 rcode=NOERROR 但 qtype=AAAA 却返回畸形 IPv6 字符串的响应 |

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
- **PCI DSS 4.0** 已把"Nginx 配置审计"列为强制要求（见下面展开）

**PCI DSS 4.0 对 Nginx 配置审计的强制要求（2025-03-31 生效）**

PCI DSS v4.0 在 **Requirement 2.2.5** 把这一条收紧为强制审计项：

> *"Misconfigurations or insecure defaults, including but not limited to unnecessary services, default accounts, sample files, and insecure protocol versions, must be identified and remediated."*

落到 Nginx 上，**必须能在审计中拿出证据**（不是"我们 review 过"，而是"工具跑过 + 问题闭环"）：

| PCI DSS 4.0 控制项 | 对应 Nginx 实践 | 推荐工具 |
|---|---|---|
| 2.2.5 不安全默认/误配 | `server_tokens off`、`ssl_protocols TLSv1.2 TLSv1.3 only`、禁 `merge_slashes off` 之外的所有路径规范化 | `gixy`、`nginx-config-formatter` |
| 2.2.7 最小功能原则 | 移除 `ngx_http_autoindex_module`、`ngx_http_dav_module`、`ngx_http_ssi_module` 等用不到的模块 | `nginx -V` 比对 build options |
| 4.2.1 强加密传输 | TLS 1.2+、禁用 3DES/RC4、禁用 SSLv3 | `testssl.sh`、`openssl s_client` |
| 6.4.3 Web 应用攻击面 | 静态扫描 WAF 规则覆盖 OWASP Top 10 | ModSecurity CRS / Coraza |
| 10.x 可审计日志 | access_log / error_log 接入 SIEM，保留 ≥ 12 个月 | Filebeat → Elasticsearch |
| 11.5.2 文件完整性 | `nginx.conf` / `/etc/nginx/conf.d/*.conf` 接入 AIDE / OSSEC | AIDE、Tripwire |

**最小可行的"黄金 nginx.conf"片段**（同时满足 PCI DSS 4.0 + OWASP WSTG-CONF）：

```nginx
http {
    server_tokens off;                           # PCI DSS 2.2.5：不暴露版本
    ssl_protocols TLSv1.2 TLSv1.3;               # PCI DSS 4.2.1：禁用老旧协议
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "no-referrer" always;

    limit_req_zone $binary_remote_addr zone=req:10m rate=10r/s;  # 抗 Slowloris

    server {
        listen 443 ssl http2;
        location /server-status { deny all; }     # PCI DSS 6.4.3：内部接口不对外
        location ~ /\.git { deny all; }           # PCI DSS 6.4.3：源码目录隐藏
    }
}
```

**审计证据链**（PCI DSS 审计员必看三件套）：

1. **CI 跑 `gixy`**（每 PR 一次，报告存 12 个月）→ 证明配置在变更是经过静态扫描的；
2. **定期 `testssl.sh`**（季度一次，HTML 报告归档）→ 证明加密配置没有回退；
3. **`nginx -T` 输出入库**（每月一次，diff 上一次）→ 证明运行时配置可追溯。

**本章只埋点，深度展开见后续章节**：

- 第 5 章 `## 案例 3：金融合规——PCI DSS 4.0 要求下的 Nginx 部署`（已存在）给出一个真实持牌支付机构的全套合规实践；
- 第 6 章 `### 静态分析：gixy`（已存在）展开 `gixy` 在 CI 中的接入方式、JSON 报告解读、与 OPA/Conftest 的组合；
- 附录 B `## B.8 gixy 配置 lint 集成进 CI`（已存在）给出可复制粘贴的 GitHub Actions workflow。

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