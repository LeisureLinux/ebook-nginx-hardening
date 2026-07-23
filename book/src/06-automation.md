# 第 6 章：自动化防御

前几章我们构建了防御体系。但现实是——这些配置会漂移、证书会过期、CVE 会爆发。

没有自动化的防御，只是**静态的防御**。这一章我们把所有手动操作都变成自动化。

## nginx.conf 集成测试

### 基础：nginx -t 在 CI 里跑

```yaml
# .github/workflows/nginx-config-check.yml
name: Nginx Config Check
on:
  push:
    paths:
      - 'nginx/**'
      - 'conf/**'
  pull_request:
    paths:
      - 'nginx/**'
      - 'conf/**'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Nginx
        run: |
          sudo apt-get update
          sudo apt-get install -y nginx

      - name: Validate nginx.conf
        run: |
          sudo nginx -t -c $PWD/nginx/nginx.conf
        # 如果配置有问题，`nginx -t` 会返回 non-zero → Action 自动失败

      - name: Validate conf.d includes
        run: |
          for f in nginx/conf.d/*.conf; do
            echo "Validating $f..."
            sudo nginx -t -c $PWD/nginx/nginx.conf
          done
```

### 静态分析：gixy

[gixy](https://github.com/yandex/gixy) 是 Yandex 开源的 Nginx 配置静态分析工具。它能自动检测 alias traversal、SSRF、CRLF injection、变量注入等问题。

```bash
# 安装
$ pip install gixy

# 运行
$ gixy /etc/nginx/nginx.conf

# 输出样例
=================== Results ===================

>> Problem: [alias_traversal] 
   Severity: MEDIUM
   Description: Using alias outside location with trailing slash may lead to path traversal.
   Additional: https://github.com/yandex/gixy/blob/main/docs/en/plugins/aliastraversal.md
   Rewrite: http://example.com/assets..%2f..%2fetc/passwd

   nginx.conf:21
   location /static {                                   ← 这里没有 /
        alias /var/www/static/;

>> Problem: [ssrf] 
   Severity: HIGH
   Description: Resolver may lead to SSRF.
   Additional: https://github.com/yandex/gixy/blob/main/docs/en/plugins/ssrf.md

   nginx.conf:33
   resolver 8.8.8.8;

>> Problem: [add_header_redefinition]
   Severity: LOW
   Description: ...
```

**CI 集成**：

```yaml
# 在 CI 中运行 gixy
- name: Static analysis with gixy
  run: |
    pip install gixy
    gixy nginx/nginx.conf --format json | tee gixy-report.json

- name: Fail on HIGH severity issues
  run: |
    python3 -c "
    import json
    with open('gixy-report.json') as f:
        report = json.load(f)
    for p in report.get('problems', []):
        if p['severity'] == 'HIGH':
            print(f'FAIL: {p[\"description\"]} ({p[\"location\"]})')
            exit(1)
    print('No HIGH severity issues found.')
    "
```

### 格式化规范：nginx-config-formatter

团队 5+ 人维护 nginx.conf 时，格式风格必须统一。

```bash
# 安装
$ npm install -g nginx-config-formatter

# 格式化
$ nginx-config-formatter -i nginx/conf.d/*.conf -o nginx/conf.d/*.conf

# 在 pre-commit hook 中自动格式化
$ cat .git/hooks/pre-commit
#!/bin/bash
for f in $(git diff --cached --name-only --diff-filter=ACM -- '*.conf'); do
    nginx-config-formatter -i "$f" -o "$f"
    git add "$f"
done
```

## 灰度发布

### 基于 Git 分支的灰度管理

```nginx
# 用 git tag 控制灰度范围
server {
    location / {
        # 读取灰度配置（来自 Git 仓库）
        set $variant "stable";
        if (-f /etc/nginx/features/canary.enabled) {
            set $variant "canary";
        }
        
        proxy_pass http://$variant;
    }
}

upstream stable {
    server 10.0.1.1:8000;
    server 10.0.1.2:8000;
}

upstream canary {
    server 10.0.1.3:8000;
    server 10.0.1.4:8000;
}
```

**灰度演进流程**：

```bash
# 第 1 天：5% 灰度
$ echo "5" > /etc/nginx/features/canary-percent.conf
$ nginx -s reload

# 第 3 天：30% 灰度
$ echo "30" > /etc/nginx/features/canary-percent.conf
$ nginx -s reload

# 第 7 天：100% → 正式发布
$ rm /etc/nginx/features/canary.enabled
$ nginx -s reload
```

## 配置漂移检测

### GitOps + ArgoCD / Flux

Nginx 配置入 Git 后，配置漂移检测自动化：

```yaml
# ArgoCD Application（用于 Nginx 配置部署）
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: nginx-config
spec:
  project: default
  source:
    repoURL: git@github.com:team/nginx-config.git
    targetRevision: HEAD
    path: nginx/
  destination:
    server: https://kubernetes.default.svc
    namespace: nginx
  syncPolicy:
    automated:
      prune: true
      selfHeal: true  # 检测漂移后自动恢复
  sync:
    compareOptions:
      ignore: {}       # 忽略运行时的动态变量（如 pid）
```

**非 K8s 场景**：用 Ansible / SaltStack 定期强制应用配置。

```yaml
# ansible/roles/nginx/tasks/config-check.yml
- name: Check if nginx.conf matches Git checkout
  command: diff /etc/nginx/nginx.conf /var/lib/nginx-config/nginx.conf
  register: config_diff
  failed_when: false

- name: Alert on config drift
  mail:
    to: admin@example.com
    subject: "[ALERT] Nginx config drift detected on {{ inventory_hostname }}"
    body: "{{ config_diff.stdout }}"
  when: config_diff.rc != 0
```

### Configuration signing（从第 4 章复用）

```bash
# 加上自动签名流程
$ cat /etc/cron.hourly/nginx-config-sign
#!/bin/bash
# 每小时检查配置文件的签名
if ! openssl dgst -sha256 -verify /etc/nginx/ssl/config-sign.pub \
    -signature /etc/nginx/conf.d/nginx.conf.sig /etc/nginx/nginx.conf; then
    logger -p auth.alert "NGINX CONFIG TAMPERED on $(hostname)"
    # 触发告警
    curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "{\"text\":\"Nginx config tampered on $(hostname)\"}" \
        https://hooks.alert.example.com/webhook/nginx-alert
fi
```

## 漏洞应急响应

### 自动 CVE 订阅

```bash
# GitHub Advisory CLI
$ gh api repos/nginx/nginx-advisories/security-advisories --paginate \
    --jq '.[].summary'

2026-06-15: CVE-2026-XXXXX — HTTP/2 内存泄漏 (affects 1.24.x - 1.26.x)
2026-05-01: CVE-2026-YYYYY — proxy_pass 目录遍历 (affects 1.22.x - 1.25.y)
```

**集成到告警**：

```bash
$ cat /usr/local/bin/check-nginx-cve.sh
#!/bin/bash
# 检查 Nginx 版本是否受已知 CVE 影响
VERSION=$(nginx -v 2>&1 | grep -oP '\d+\.\d+\.\d+')
ALERT_URL="https://hooks.alert.example.com/webhook/cve"

curl -s "https://api.nvd.nist.gov/vulns/search?query=nginx+$VERSION" \
    | python3 -c "
import json, sys
data = json.load(sys.stdin)
for cve in data.get('result', {}).get('CVE_Items', [])[:5]:
    print(f'{cve[\"cve\"][\"CVE_data_meta\"][\"ID\"]}: {cve[\"cve\"][\"description\"][\"description_data\"][0][\"value\"][:120]}')
    # 如果是关键漏洞，立刻告警
    severity = cve.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity', 'UNKNOWN')
    if severity == 'CRITICAL':
        import requests
        requests.post('$ALERT_URL', json={'text': f'🚨 CRITICAL CVE: {cve[\"cve\"][\"CVE_data_meta\"][\"ID\"]} affects Nginx $VERSION'})
"
```

**效果**：当 Nginx CVE 爆发时，**自动**检测受影响的版本并告警。您不需要等公关邮件，不需要手动查 NVD。

### 一键回滚脚本

```bash
$ cat /usr/local/bin/nginx-rollback.sh
#!/bin/bash
set -euo pipefail

BACKUP_DIR="/var/backup/nginx"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <backup-name>"
    echo "Available backups:"
    ls $BACKUP_DIR/
    exit 1
fi

BACKUP="$BACKUP_DIR/$1"

if [ ! -d "$BACKUP" ]; then
    echo "Backup $BACKUP not found"
    exit 1
fi

echo "[$(date)] Rolling back nginx config to $1"

# 1. 保存当前配置
mkdir -p "$BACKUP_DIR/pre-rollback"
cp -r /etc/nginx/ "$BACKUP_DIR/pre-rollback/$TIMESTAMP"

# 2. 恢复备份
cp -r "$BACKUP/etc/nginx/" /etc/

# 3. 验证配置
if nginx -t; then
    systemctl reload nginx
    echo "[$(date)] Rollback successful. Reloaded Nginx."
else
    echo "[$(date)] Rollback failed: nginx -t error"
    # 自动恢复
    cp -r "$BACKUP_DIR/pre-rollback/$TIMESTAMP" /etc/nginx/
    nginx -t && systemctl reload nginx
    exit 1
fi
```

### 灰度修复

当 CVE 公告发布后，不可能同时重启所有机器。灰度修复流程：

```bash
# 阶段 1：测试环境（5 分钟）
$ ansible-playbook -i inventory/staging.ini upgrade-nginx.yml

# 阶段 2：金丝雀节点（30% 流量，15 分钟）
$ ansible-playbook -i inventory/canary.ini upgrade-nginx.yml
# 观察 15 分钟：error rate、avg latency、4XX 曲线

# 阶段 3：剩余节点（70% 流量，30 分钟）
$ ansible-playbook -i inventory/prod.json upgrade-nginx.yml --limit 'group:prod[0:50%]'
# 观察 15 分钟

# 阶段 4：全量（100%）
$ ansible-playbook -i inventory/prod.json upgrade-nginx.yml --limit 'group:prod'
```

**Ansible playbook**：

```yaml
# upgrade-nginx.yml
- hosts: nginx
  vars:
    nginx_upgrade_package: "nginx=1.26.0"
    nginx_health_check: "https://{{ inventory_hostname }}/health"
  tasks:
    - name: Stop monitoring (so nagios doesn't alert)
      shell: echo "PRE-CHECK: $NGINX_CURRENT_VERSION"
    
    - name: Upgrade nginx package
      apt:
        name: "{{ nginx_upgrade_package }}"
        state: present
      register: upgrade_result

    - name: Validate new config
      command: nginx -t
      when: upgrade_result.changed

    - name: Graceful reload
      service:
        name: nginx
        state: reloaded
      when: upgrade_result.changed

    - name: Health check
      uri:
        url: "{{ nginx_health_check }}"
        method: GET
        status_code: 200
      register: health
      retries: 10
      delay: 3
      until: health.status == 200
```

## 完整自动化流水线

把上面所有组件拼成一个完整的 CI/CD 流水线：

```yaml
# .github/workflows/nginx-full-pipeline.yml
name: Nginx Full Pipeline
on:
  push:
    paths:
      - 'nginx/**'
      - 'scripts/**'
  pull_request:
    paths:
      - 'nginx/**'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install nginx
        run: sudo apt-get install -y nginx
      - name: Validate config
        run: sudo nginx -t -c $PWD/nginx/nginx.conf
      - name: Static analysis (gixy)
        run: |
          pip install gixy
          gixy nginx/nginx.conf --format json | tee gixy-report.json
      - name: Fail on HIGH severity
        run: |
          python3 -c "
          import json
          with open('gixy-report.json') as f:
              report = json.load(f)
          for p in report.get('problems', []):
              if p['severity'] == 'HIGH':
                  print(f'FAIL: {p[\"description\"]} ({p[\"location\"]})')
                  exit(1)
          print('All checks passed.')
          "

  deploy:
    needs: validate
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    environment:
      name: production
    steps:
      - uses: actions/checkout@v4
      - name: Deploy config to servers
        run: |
          ansible-playbook -i inventory/prod.yaml \
            --private-key <(echo "$ANSIBLE_SSH_KEY") \
            deploy-nginx.yml

  healthcheck:
    needs: deploy
    runs-on: ubuntu-latest
    steps:
      - name: Check production Nginx health
        run: |
          for host in $PROD_HOSTS; do
            if ! curl -f --max-time 5 https://$host/health; then
              echo "Health check failed on $host"
              exit 1
            fi
          done
```

## 小结

| 自动化内容 | 工具 | 收益 |
|---|---|---|
| 配置集成测试 | `nginx -t` + GitHub CI | 永远不会有语法错误的配置上线 |
| 静态分析 | gixy | 发现 alias traversal、SSRF、CRLF 注入 |
| 格式统一 | nginx-config-formatter | 团队协作时配置可读性高 |
| 灰度发布 | 条件 nginx.conf + Ansible | 变更安全 |
| 配置漂移检测 | ArgoCD / ansible + diff | 防范未经授权的修改 |
| CVE 应急响应 | 自动化脚本 | 30 分钟内响应，而不是 2 天 |
| 一键回滚 | 备份脚本 | 误操作恢复时间 < 5 分钟 |
| 完整 CI/CD | GitHub Actions + Ansible | 全流程无人值守 |

### 自测题

**题 1**：用 gixy 扫描您生产环境的 nginx.conf，报告了几条 HIGH severity issue？

**题 2**：您的 Nginx 配置是否入 Git？离上一次 git commit 过去多少天了？

**题 3**：如果明天公布一个 Nginx CRITICAL CVE，您的团队能在多少小时内修复所有机器？怎么做到？
