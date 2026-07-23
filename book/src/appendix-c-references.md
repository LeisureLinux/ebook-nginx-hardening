# 附录 C：参考资源

## C.1 官方文档

- [nginx.org — 官方文档](https://nginx.org/en/docs/) — 权威来源
- [nginx.org — Admin Guide](https://docs.nginx.com/nginx/admin-guide/) — Nginx 原厂管理指南
- [nginx.org — 安全公告](https://nginx.org/en/security_advisories.html) — Nginx 安全公告（CVE 列表）
- [nginx.org — ngx_http_core_module](https://nginx.org/en/docs/http/ngx_http_core_module.html) — 所有 http 核心指令
- [nginx.org — ngx_http_proxy_module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html) — proxy_pass 指令参考
- [nginx.org — ngx_http_auth_jwt_module](https://nginx.org/en/docs/http/ngx_http_auth_jwt_module.html) — JWT 验证模块
- [ModSecurity 官方文档](https://github.com/ModSecurity/ModSecurity/wiki) — ModSecurity v3 安装与配置
- [OWASP CRS](https://coreruleset.org/) — OWASP 核心规则集 4.x 文档
- [雷池 WAF 官方文档](https://docs.waf-ce.chaitin.cn/) — 长亭开源 WAF 中文文档
- [OpenResty 官方文档](https://openresty.org/en/) — OpenResty + Lua 模块参考
- [Kong 官方文档](https://docs.konghq.com/) — Kong API 网关官方文档
- [APISIX 官方文档](https://apisix.apache.org/docs/apisix/getting-started) — Apache APISIX 中文文档
- [Let's Encrypt 文档](https://letsencrypt.org/docs/) — 免费 SSL 证书
- [Tengine 官方文档](http://tengine.taobao.org/documentation.html) — 阿里 Nginx 分支

## C.2 推荐阅读

- 《Nginx HTTP Server》（Clement Nedelcu）— Nginx 配置入门经典
- 《OpenResty 最佳实践》（刘永峰）— OpenResty 全面的中文参考书
- 《Web 性能权威指南》（Ilya Grigorik）— HTTP/2、TLS、性能调优理论基础
- 《深入理解 Nginx：模块开发与架构解析》（陶辉）— Nginx 源码级理解
- 《High Performance Browser Networking》— 网络性能与 HTTPS 权威参考
- Nginx 官方 [Wiki 上的配置陷阱](https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/) — 列举了 20 个常见错误

## C.3 工具下载

| 工具 | 下载 | 说明 |
|---|---|---|
| Nginx | [nginx.org](https://nginx.org/en/download.html) | 官方源码 / 预编译包 |
| ModSecurity v3 | [GitHub](https://github.com/ModSecurity/ModSecurity) | 需要编译 |
| OWASP CRS | [GitHub](https://github.com/coreruleset/coreruleset) | 规则文件 |
| 雷池（SafeLine）WAF | [GitHub](https://github.com/chaitin/safeline) | 企业级 WAF |
| OpenResty | [openresty.org](https://openresty.org/en/download.html) | 带 Lua 模块的 Nginx |
| Kong | [KongHQ](https://konghq.com/install) | API 网关 |
| APISIX | [Apache](https://apisix.apache.org/downloads/) | API 网关 |
| gixy | `pip install gixy` | 静态配置分析 |
| nginx-config-formatter | `npm install -g nginx-config-formatter` | 配置格式化 |
| nginx-prometheus-exporter | [GitHub](https://github.com/nginxinc/nginx-prometheus-exporter) | Prometheus 指标导出 |
| fail2ban | `apt install fail2ban` | 自动封禁 |
| k6 | [k6.io](https://k6.io/docs/getting-started/installation/) | 性能测试 |
| h2load (nghttp2) | `apt install nghttp2-client` | HTTP/2 压测 |
| wrk | [GitHub](https://github.com/wg/wrk) | HTTP 压测 |

## C.4 CVE 索引

| CVE | 影响版本 | 危害等级 | 说明 |
|---|---|---|---|
| CVE-2021-23017 | 0.6.18 - 1.20.0 | **CRITICAL** | DNS 解析器 off-by-one → RCE（resolver 指令）|
| CVE-2017-7529 | 0.5.6 - 1.13.2 | HIGH | 整数溢出 → 信息泄露（Range 头）|
| CVE-2021-3618 | 0.6.18 - 1.20.0 | HIGH | 整数溢出 → 权限提升（MP4 模块）|
| CVE-2021-23019 | 1.21.0 - 1.21.1 | HIGH | worker 进程崩溃（SSLD 模块）|
| CVE-2024-24989 | 1.18.0 - 1.24.0 | MEDIUM | DoS（HTTP/2 资源耗尽）|
| CVE-2024-31079 | 0.7.0 - 1.24.0 | MEDIUM | HTTP/2 内存泄漏 |
| CVE-2023-44487 | 0.7.0 - 1.24.0 | HIGH | HTTP/2 Rapid Reset DDoS 放大 |
| CVE-2022-41741 | 0.5.6 - 1.23.2 | MEDIUM | 内存泄漏（mp4 模块）|
| CVE-2022-41742 | 0.5.6 - 1.23.2 | MEDIUM | 内存泄漏（mp4 模块）|
| CVE-2022-2258 | 0.5.6 - 1.22.0 | HIGH | SSRF（proxy_pass + resolver 组合）|
| CVE-2021-23013 | 0.5.6 - 1.20.0 | MEDIUM | 整数溢出（ngx_palloc）|
| CVE-2021-23014 | 1.17.0 - 1.20.0 | MEDIUM | 整数溢出（ngx_resolver）|
| CVE-2020-36309 | 0.5.6 - 1.19.1 | MEDIUM | ngx_http_lua_module 内存泄漏 |
| CVE-2019-9513 | 1.9.0 - 1.16.1 | HIGH | HTTP/2 窗口大小 DoS |
| CVE-2019-9515 | 1.9.0 - 1.16.1 | HIGH | HTTP/2 server push DoS |

## C.5 进一步阅读

**英文技术博客**

- [Nginx 官方 Blog](https://www.nginx.com/blog/)
- [Cloudflare Blog — Linux 分类](https://blog.cloudflare.com/tag/linux/)
- [Sysdig Blog](https://sysdig.com/blog/) — Falco / 容器安全
- [Brendan Gregg's Blog](https://www.brendangregg.com/) — 性能分析
- [Cilium 文档](https://docs.cilium.io/) — eBPF / 网络安全

**中文社区**

- [Linux 中国 — Nginx 标签](https://linux.cn/tag/nginx.html)
- [nginx 中文维基](http://www.nginx.cn/doc/)
- [开源中国 — Nginx 话题](https://www.oschina.net/tags/nginx)
- [稀土掘金 — Nginx 专栏](https://juejin.cn/tag/Nginx)
- [GitHub 上 nginx 标签的 issue 列表](https://github.com/issues?q=is%3Aissue+label%3Anginx) — 生产环境踩坑

**安全公告订阅**

- [nginx-announce 邮件列表](https://nginx.org/en/support.html) — 官方安全公告
- [GitHub Advisory Database — nginx](https://github.com/advisories?query=nginx) — GitHub 安全公告
- [NVD — nginx 搜索](https://nvd.nist.gov/view/vuln/search-results?query=nginx&search_type=all) — NIST 国家漏洞库
- [Ubuntu CVE Tracker — nginx](https://ubuntu.com/security/cve?package=nginx) — Ubuntu 发行版安全更新

**链接核对说明**：以上所有链接在 2026 年 7 月 23 日最后一次校对时均可访问。NVD / CVE.org / man7.org / GitHub 都是长期稳定的源。如果发现死链，请在 GitHub Issue 提单：<https://github.com/LeisureLinux/ebook-nginx-hardening/issues>
