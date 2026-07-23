# 附录 B：12 个可复现实验脚本

## B.1 编译安装 Nginx（含 ModSecurity / OpenResty）

```bash
#!/bin/bash
# scripts/01-compile-nginx.sh
# 编译 Nginx 1.26.0 + ModSecurity + OpenResty Lua 模块

set -euo pipefail

NGINX_VERSION="1.26.0"
INSTALL_DIR="/opt/nginx"

# 依赖
sudo apt-get install -y \
    build-essential libpcre3-dev libssl-dev zlib1g-dev \
    libxml2-dev libxslt1-dev libgd-dev libgeoip-dev \
    libgoogle-perftools-dev

# 下载 Nginx 源码
cd /tmp
wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
tar xf nginx-${NGINX_VERSION}.tar.gz

# ModSecurity 模块
git clone --depth 1 https://github.com/ModSecurity/ModSecurity-nginx.git

# OpenResty Lua 模块
git clone --depth 1 https://github.com/openresty/lua-nginx-module.git
git clone --depth 1 https://github.com/openresty/luajit2.git
cd luajit2 && make && sudo make install && cd ..

# 编译 Nginx
cd /tmp/nginx-${NGINX_VERSION}
./configure \
    --prefix=${INSTALL_DIR} \
    --with-http_ssl_module --with-http_v2_module --with-http_stub_status_module \
    --with-threads --with-file-aio --with-stream \
    --add-dynamic-module=../ModSecurity-nginx \
    --add-dynamic-module=../lua-nginx-module \
    --with-ld-opt="-Wl,-rpath,/usr/local/lib"

make -j$(nproc)
sudo make install

echo "Nginx installed at ${INSTALL_DIR}"
${INSTALL_DIR}/sbin/nginx -v
```

## B.2 TLS 1.3 配置 + 性能压测

```bash
#!/bin/bash
# scripts/02-tls-benchmark.sh
# 对比 TLS 1.2 vs TLS 1.3 性能

set -euo pipefail

TARGET="${1:-https://localhost:443}"

echo "=== TLS Benchmark: $TARGET ==="

# 1. 检查当前 TLS 版本
echo ""
echo "--- Current TLS version ---"
openssl s_client -connect $(echo $TARGET | sed 's|https://||'):443 -tls1_3 < /dev/null 2>&1 | grep -E "New, TLSv"

# 2. 压测 TLS 1.2
echo ""
echo "--- Benchmark: TLS 1.2 (h2load) ---"
h2load -n 10000 -c 50 -m 10 \
    --npn-list h2 $TARGET 2>&1 | grep -E "finished|req/s|traffic"

# 3. 压测 TLS 1.3
echo ""
echo "--- Benchmark: TLS 1.3 (h2load) ---"
h2load -n 10000 -c 50 -m 10 $TARGET 2>&1 | grep -E "finished|req/s|traffic"

# 4. 证书链检查
echo ""
echo "--- Certificate chain ---"
echo | openssl s_client -connect $(echo $TARGET | sed 's|https://||'):443 -showcerts 2>&1 | grep -E "subject"
```

## B.3 ModSecurity + OWASP CRS 部署

```bash
#!/bin/bash
# scripts/03-deploy-modsecurity.sh
# 部署 ModSecurity + OWASP Core Rule Set 4.x

set -euo pipefail

MODSEC_DIR="/etc/nginx/modsecurity"

# 创建目录
sudo mkdir -p $MODSEC_DIR

# 下载 OWASP CRS
cd /tmp
git clone --depth 1 https://github.com/coreruleset/coreruleset.git
sudo cp -r coreruleset/rules $MODSEC_DIR/
sudo cp coreruleset/crs-setup.conf.example $MODSEC_DIR/crs-setup.conf

# ModSecurity 配置
cat <<'EOF' | sudo tee $MODSEC_DIR/main.conf
# ModSecurity v3 主配置
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html text/xml application/json

# 请求体限制（防止内存溢出）
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072

# 审计日志
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLog /var/log/nginx/modsec_audit.log
SecAuditLogType Serial
SecAuditLogFormat JSON

# 上传文件临时目录
SecUploadDir /tmp/modsecurity_upload

# 默认响应
SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"

# OWASP CRS
Include /etc/nginx/modsecurity/crs-setup.conf
Include /etc/nginx/modsecurity/rules/REQUEST-901-INITIALIZATION.conf
Include /etc/nginx/modsecurity/rules/REQUEST-905-COMMON-EXCEPTIONS.conf
Include /etc/nginx/modsecurity/rules/REQUEST-910-IP-REPUTATION.conf
Include /etc/nginx/modsecurity/rules/REQUEST-911-METHOD-ENFORCEMENT.conf
Include /etc/nginx/modsecurity/rules/REQUEST-912-DOS-PROTECTION.conf
Include /etc/nginx/modsecurity/rules/REQUEST-913-SCANNER-DETECTION.conf
Include /etc/nginx/modsecurity/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
Include /etc/nginx/modsecurity/rules/REQUEST-921-PROTOCOL-ATTACK.conf
Include /etc/nginx/modsecurity/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf
Include /etc/nginx/modsecurity/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf
Include /etc/nginx/modsecurity/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf
Include /etc/nginx/modsecurity/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf
Include /etc/nginx/modsecurity/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
Include /etc/nginx/modsecurity/rules/REQUEST-949-BLOCKING-EVALUATION.conf
Include /etc/nginx/modsecurity/rules/RESPONSE-950-DATA-LEAKAGES.conf
Include /etc/nginx/modsecurity/rules/RESPONSE-959-BLOCKING-EVALUATION.conf
Include /etc/nginx/modsecurity/rules/RESPONSE-980-CORRELATION.conf
EOF

# Nginx 启用 ModSecurity
cat <<'EOF' | sudo tee /etc/nginx/modsecurity/include.conf
modsecurity on;
modsecurity_rules_file /etc/nginx/modsecurity/main.conf;
EOF

echo "ModSecurity CRS deployed at $MODSEC_DIR"
echo "Add 'include /etc/nginx/modsecurity/include.conf;' to your nginx.conf"
```

## B.4 mTLS 自签 CA + curl 测试

```bash
#!/bin/bash
# scripts/04-mtls-setup.sh
# 自签 CA + 颁发客户端证书 + 配置 mTLS 测试

set -euo pipefail

WORK_DIR="/tmp/mtls-demo"
mkdir -p $WORK_DIR/{ca,server,client}

# 1. 创建 CA
echo "--- 创建 CA ---"
openssl genrsa -out $WORK_DIR/ca/ca.key 2048
openssl req -x509 -new -nodes -days 3650 \
    -key $WORK_DIR/ca/ca.key -out $WORK_DIR/ca/ca.crt \
    -subj "/CN=Nginx mTLS CA"

# 2. 生成服务器证书
echo "--- 生成服务器证书 ---"
openssl genrsa -out $WORK_DIR/server/nginx.key 2048
openssl req -new -key $WORK_DIR/server/nginx.key \
    -out $WORK_DIR/server/nginx.csr \
    -subj "/CN=localhost"
openssl x509 -req -in $WORK_DIR/server/nginx.csr \
    -CA $WORK_DIR/ca/ca.crt -CAkey $WORK_DIR/ca/ca.key \
    -CAcreateserial -out $WORK_DIR/server/nginx.crt \
    -days 365

# 3. 生成客户端证书
echo "--- 生成客户端证书 ---"
openssl genrsa -out $WORK_DIR/client/client.key 2048
openssl req -new -key $WORK_DIR/client/client.key \
    -out $WORK_DIR/client/client.csr \
    -subj "/CN=alice@example.com"
openssl x509 -req -in $WORK_DIR/client/client.csr \
    -CA $WORK_DIR/ca/ca.crt -CAkey $WORK_DIR/ca/ca.key \
    -CAcreateserial -out $WORK_DIR/client/client.crt \
    -days 365

# 4. 配置 Nginx mTLS
cat <<'EOF' | sudo tee /etc/nginx/sites-enabled/mtls-test.conf
server {
    listen 8443 ssl;
    server_name localhost;

    ssl_certificate /tmp/mtls-demo/server/nginx.crt;
    ssl_certificate_key /tmp/mtls-demo/server/nginx.key;
    ssl_client_certificate /tmp/mtls-demo/ca/ca.crt;
    ssl_verify_client on;
    ssl_verify_depth 2;

    location / {
        return 200 "mTLS OK! client: $ssl_client_s_dn\n";
        add_header Content-Type text/plain;
    }
}
EOF

# 5. 启动测试
sudo nginx -t && sudo systemctl reload nginx
echo "Nginx mTLS configured on port 8443"

# 6. 测试
echo ""
echo "--- 测试：无客户端证书 → 应返回 400 Bad Request ---"
curl -k https://localhost:8443/ 2>&1 || true

echo ""
echo "--- 测试：有客户端证书 → 应返回 mTLS OK ---"
curl -k --cert $WORK_DIR/client/client.crt \
    --key $WORK_DIR/client/client.key \
    https://localhost:8443/
```

## B.5 JWT 验证 + OpenID Connect 集成

```bash
#!/bin/bash
# scripts/05-jwt-test.sh
# 测试 Nginx auth_jwt 模块

set -euo pipefail

# 1. 生成 RSA 密钥对
openssl genrsa -out /tmp/jwt-private.pem 2048
openssl rsa -in /tmp/jwt-private.pem -pubout -out /tmp/jwt-public.pem

# 2. 生成测试 JWT
cat <<'PYEOF' | python3 -
import jwt, datetime

# 加载私钥
with open('/tmp/jwt-private.pem', 'rb') as f:
    private_key = f.read()

# 生成 JWT
payload = {
    'sub': 'user-12345',
    'role': 'admin',
    'iat': datetime.datetime.utcnow(),
    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
}

token = jwt.encode(payload, private_key, algorithm='RS256')
print(token)
PYEOF
```

## B.6 Kong / APISIX 集群搭建

详见第 4 章 4.3 节的 Admin API 示例。简化版：

```bash
#!/bin/bash
# scripts/06-gateway-setup.sh

set -euo pipefail

echo "--- 选择网关 ---"
select GW in kong apisix; do
    case $GW in
        kong)
            echo "Installing Kong..."
            sudo apt-get install -y kong
            kong migrations bootstrap
            kong start
            ;;
        apisix)
            echo "Installing APISIX..."
            curl -sL https://raw.githubusercontent.com/apache/apisix/master/utils/install-dependencies.sh | bash
            sudo apt-get install -y apisix
            apisix init
            apisix start
            ;;
    esac
    break
done

echo "Gateway installed. Admin API available at http://localhost:8001 (Kong) or :9180 (APISIX)"
```

## B.7 Nginx + Prometheus + Grafana 监控

```bash
#!/bin/bash
# scripts/07-monitoring-setup.sh
set -euo pipefail

# 启用 Nginx 状态页
echo "--- 配置 Nginx stub_status ---"
cat <<'EOF' | sudo tee /etc/nginx/sites-enabled/status.conf
server {
    listen 127.0.0.1:8080;
    location /basic_status {
        stub_status;
    }
}
EOF
sudo nginx -t && sudo systemctl reload nginx

# 启动 Prometheus 导出器实例
docker run -d \
    --name nginx-prometheus-exporter \
    --network host \
    nginx/nginx-prometheus-exporter:1.0.0 \
    -nginx.scrape-uri http://127.0.0.1:8080/basic_status

# 启动 Prometheus
docker run -d --name prometheus -p 9090:9090 \
    -v $PWD/prometheus.yml:/etc/prometheus/prometheus.yml \
    prom/prometheus

# 启动 Grafana
docker run -d --name grafana -p 3000:3000 \
    grafana/grafana

echo "Nginx metrics → Prometheus (localhost:9090) → Grafana (localhost:3000)"
```

## B.8 gixy 配置 lint 集成进 CI

```yaml
# .github/workflows/gixy-check.yml
name: Nginx Config Static Analysis
on:
  push:
    paths:
      - 'nginx/**'
  pull_request:
    paths:
      - 'nginx/**'

jobs:
  gixy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install gixy
        run: pip install gixy
      - name: Run gixy
        run: |
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
          "
```

## B.9 灰度发布（基于 header）实战

```nginx
# /etc/nginx/conf.d/canary.conf
map $http_x_canary $backend {
    default    stable;
    "canary"   canary;
}

upstream stable {
    server 10.0.1.1:8000;
    server 10.0.1.2:8000;
}

upstream canary {
    server 10.0.1.3:8000;  # 新版本
}

server {
    location / {
        proxy_pass http://$backend;
        # 透传灰度版本信息给上游
        proxy_set_header X-Version $backend;
    }
}
```

## B.10 慢速攻击防护（limit_req + limit_conn）

```bash
#!/bin/bash
# scripts/10-slow-attack-defense.sh
set -euo pipefail

# Nginx 限流配置
cat <<'EOF' | sudo tee /etc/nginx/conf.d/rate-limit.conf
limit_req_zone $binary_remote_addr zone=all:10m rate=30r/s;
limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;

server {
    location / {
        limit_req zone=all burst=50;
    }
    location /login/ {
        limit_req zone=login burst=5 nodelay;
    }
}
EOF

sudo nginx -t && sudo systemctl reload nginx

# 测试慢速攻击
echo "模拟慢攻击..."
for i in $(seq 1 10); do
    curl -s -o /dev/null -w "%{http_code} " \
        -d "username=admin&password=test$i" \
        https://localhost/login/
done
echo ""

# 正常请求应返回 200，超过限流应返回 429
# 查看日志
sudo tail -20 /var/log/nginx/access.log | grep "429"
```

## B.11 IP 黑名单自动同步（fail2ban + GeoIP）

```bash
#!/bin/bash
# scripts/11-ip-blacklist.sh
set -euo pipefail

echo "--- 自动同步威胁情报 IP 黑名单 ---"

# 从开源威胁情报拉取恶意 IP
curl -s "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset" \
    | grep -v "^#" \
    > /tmp/malicious-ips.txt

# 生成 Nginx 黑名单文件
{
    echo "# Auto-generated blacklist ($(date))"
    echo "# Source: firehol_level1"
    while IFS= read -r ip; do
        if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
            echo "deny $ip;"
        elif [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
            echo "deny $ip;"
        fi
    done < /tmp/malicious-ips.txt
} | sudo tee /etc/nginx/conf.d/blacklist.conf > /dev/null

# reload Nginx
sudo nginx -t && sudo systemctl reload nginx
echo "Blacklist updated: $(wc -l < /tmp/malicious-ips.txt) IPs blocked."
```

## B.12 异常流量演练（k6 + Grafana）

```bash
#!/bin/bash
# scripts/12-traffic-drill.sh
# 用 k6 模拟 DDoS / 慢速攻击 / 认证爆破

set -euo pipefail

TARGET="${1:-http://localhost}"

# 安装 k6
sudo apt-get install -y k6

# 测试 1：正常流量
echo "--- 测试 1：正常流量（50 用户，持续 30s） ---"
k6 run --vus 50 --duration 30s \
    -e TARGET=$TARGET \
    <(cat <<'EOF'
import http from 'k6/http';
export default function() {
    http.get(`${__ENV.TARGET}/`);
}
EOF
)

# 测试 2：慢速攻击（Slowloris 风格）
echo ""
echo "--- 测试 2：慢速攻击（低带宽，长连接） ---"
k6 run --vus 50 --duration 30s \
    -e TARGET=$TARGET \
    <(cat <<'EOF'
import http from 'k6/http';
export const options = {
    thresholds: {
        http_req_duration: ['p(95)<2000'],  # 95% 请求应在 2s 内
    },
};
export default function() {
    const url = `${__ENV.TARGET}/`;
    const response = http.get(url, {
        timeout: 60000,  // 1 分钟超时
    });
}
EOF
)

# 测试 3：认证爆破模拟
echo ""
echo "--- 测试 3：认证爆破（随机用户名密码） ---"
k6 run --vus 10 --duration 30s \
    -e TARGET=$TARGET \
    <(cat <<'EOF'
import http from 'k6/http';
export default function() {
    const username = `user${Math.floor(Math.random() * 10000)}`;
    const password = `pass${Math.floor(Math.random() * 10000)}`;
    http.post(`${__ENV.TARGET}/login`, {
        username: username,
        password: password,
    });
}
EOF
)
```
