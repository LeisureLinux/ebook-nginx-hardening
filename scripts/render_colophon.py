#!/usr/bin/env python3
"""
Render 99-colophon.md by substituting placeholders with values derived
from git tags + commit log.

Approach: build the output entirely in memory from a canonical template
string (the file on disk is treated as the template). This avoids the
fragility of trying to 'restore' placeholders from a previously-rendered
file.
"""
import datetime
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
COLOPHON = REPO / "book" / "src" / "99-colophon.md"

# Canonical template.
TEMPLATE = r"""# 本书信息

## 版本历史

| 版本 | 日期 | 说明 |
|------|------|----------|
{{HISTORY_TABLE}}

## 仓库

- **GitHub**：<https://github.com/LeisureLinux/ebook-nginx-hardening>
- **在线阅读**：<https://leisurelinux.github.io/ebook-nginx-hardening/>
- **下载**：[PDF](https://leisurelinux.github.io/ebook-nginx-hardening/nginx-hardening.pdf) · [ePub](https://leisurelinux.github.io/ebook-nginx-hardening/nginx-hardening.epub) · [HTML](https://leisurelinux.github.io/ebook-nginx-hardening/nginx-hardening.html)

## 工具链

本书使用 Pandoc + XeLaTeX 构建，主题结构、构建脚本、GitHub Actions 流水线直接复用 [ebook-ssh-hardening](https://github.com/LeisureLinux/ebook-ssh-hardening) 的模板。

## License

MIT — see [LICENSE](https://github.com/LeisureLinux/ebook-nginx-hardening/blob/main/LICENSE).
"""


def list_tags():
    out = subprocess.run(
        ["git", "tag", "--list", "v*", "--sort=version:refname"],
        cwd=REPO, capture_output=True, text=True, check=False,
    ).stdout.strip().splitlines()
    return [t for t in out if t]


def render_history_table():
    tags = list_tags()
    if not tags:
        return "| (尚无版本标记) | | |"
    lines = []
    for tag in reversed(tags):
        date_str = subprocess.run(
            ["git", "log", "-1", "--format=%cd", "--date=short", tag],
            cwd=REPO, capture_output=True, text=True, check=False,
        ).stdout.strip()
        subject = subprocess.run(
            ["git", "log", "-1", "--format=%s", tag],
            cwd=REPO, capture_output=True, text=True, check=False,
        ).stdout.strip()
        lines.append(f"| {tag} | {date_str} | {subject} |")
    return "\n".join(lines) if lines else "| (无版本标记) | | |"


def main():
    history = render_history_table()

    text = TEMPLATE.replace("{{HISTORY_TABLE}}", history)

    COLOPHON.write_text(text, encoding="utf-8")
    print(f"rendered colophon at {COLOPHON}")
    print(f"  tags: {list_tags()}")


if __name__ == "__main__":
    main()
