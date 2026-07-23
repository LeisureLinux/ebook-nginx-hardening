# Nginx 纵深加固：从反向代理到 WAF 实战

> 一本关于 Nginx 反向代理、负载均衡与 WAF 纵深防御的电子书。by [LeisureLinux](https://github.com/LeisureLinux).

[![build](https://github.com/LeisureLinux/ebook-nginx-hardening/actions/workflows/build.yml/badge.svg)](https://github.com/LeisureLinux/ebook-nginx-hardening/actions/workflows/build.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

## 在线阅读 / 下载

| 格式 | 入口 |
|---|---|
| HTML 在线版 | <https://leisurelinux.github.io/ebook-nginx-hardening/> |
| PDF | [Releases](../../releases) 或 [直接下载](https://leisurelinux.github.io/ebook-nginx-hardening/nginx-hardening.pdf) |
| ePub | [Releases](../../releases) 或 [直接下载](https://leisurelinux.github.io/ebook-nginx-hardening/nginx-hardening.epub) |

## 目录

- **第 1 章** — 为什么 Nginx 是头号互联网入口
- **第 2 章** — 攻击侧：五步一气呵成（摸配置 / 找路径 / 绕认证 / 提权 / 隐攻击）
- **第 3 章** — 五层纵深防御体系（暴露面 / 访问控制 / 行为约束 / 完整性 / 可观测性 + WAF 实战）
- **第 4 章** — 高级防御（TLS 1.3 / mTLS / API 网关 / CDN / 灰度发布）
- **第 5 章** — 实战案例（电商大促 / API 网关 / 金融合规 / 自建 CDN / mTLS 替代 VPN）
- **第 6 章** — 自动化防御（nginx.conf CI 集成 / gixy lint / GitOps / CVE 应急响应）
- **第 7 章** — 思维升华（零信任 / 国产化 / NGINX Unit / eBPF + Nginx）
- **附录 A** — Nginx 配置速查表（指令 / 变量 / 调优 checklist）
- **附录 B** — 12 个可复现实验脚本
- **附录 C** — 参考资源 / CVE 索引（带超链接）

## 系列姊妹篇

本仓库是 LeisureLinux **"一主题一电子书"** 纵深系列的第三本。同系列的姊妹篇：

- 📕 **[SSH 纵深加固](https://github.com/LeisureLinux/ebook-ssh-hardening)** — 主机访问入口的纵深防御（系列第一本）
- 📘 **[`/proc` 攻防演义](https://github.com/LeisureLinux/ebook-procfs-hardening)** — 从 Linux 进程真相到可观测性实战（系列第二本）

系列持续更新中。

## 仓库结构

```
.
├── book/
│   ├── src/             # Pandoc 输入：每章一个 Markdown
│   ├── metadata.yml     # Pandoc 元数据 (title/author/date/lang)
│   ├── theme/html.css   # HTML 主题
│   ├── theme/landing.html # Pages 首页
│   ├── cover.svg/.png   # 封面
│   └── (构建产物不入仓：dist/ 见 .gitignore)
├── scripts/             # render_colophon.py / strip_landmarks.py
├── .github/workflows/   # GitHub Action：build PDF + ePub + HTML
├── .gitignore
├── LICENSE              # MIT
└── README.md
```

## 本地构建

需要：

- `pandoc` ≥ 3.1
- `texlive-xetex` + `texlive-lang-chinese` + `fonts-noto-cjk`
- `librsvg2-bin`（SVG → PNG 封面渲染，可选）

```bash
# 安装依赖 (Debian/Ubuntu)
sudo apt-get install -y pandoc texlive-xetex texlive-lang-chinese fonts-noto-cjk librsvg2-bin

# 构建（与 Action 一致的命令）
cd book
pandoc --pdf-engine=xelatex --metadata-file=metadata.yml \
       --toc --toc-depth=2 --number-sections \
       --include-in-header=theme/latex-header.tex \
       -V documentclass=book -V papersize=a4 \
       -V mainfont="Noto Serif CJK SC" \
       src/*.md -o ../nginx-hardening.pdf

pandoc --to=epub3 --metadata-file=metadata.yml \
       --css=theme/epub.css \
       --toc --toc-depth=3 --number-sections \
       --epub-cover-image=cover.png \
       src/*.md -o ../nginx-hardening.epub

pandoc --to=html5 --standalone --metadata-file=metadata.yml \
       --toc --css=theme/html.css --self-contained \
       src/*.md -o ../nginx-hardening.html
```

## 发布流程

| 触发 | 行为 |
|---|---|
| Push 到 `main` | 构建 PDF / ePub / HTML；更新 GitHub Pages |
| `git tag v*` 并 push | 上述 + 附加到 GitHub Release |
| `workflow_dispatch` | 手动触发 |

## License

MIT — see [LICENSE](./LICENSE).