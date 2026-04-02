#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/infrazero-bootstrap.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[egress] $(date -Is) start"

BOOTSTRAP_ROLE="egress"

load_env() {
  local file="$1"
  if [ -f "$file" ]; then
    set -a
    # shellcheck disable=SC1090
    source "$file"
    set +a
  fi
}

ENV_FILE="/etc/infrazero/egress.env"
load_env "$ENV_FILE"

BOOTSTRAP_ENV_FILE="/etc/infrazero/egress.bootstrap.env"
download_offloaded_bootstrap_env() {
  local payload_url="${INFISICAL_BOOTSTRAP_SECRETS_ENV_URL:-}"
  local payload_sha256="${INFISICAL_BOOTSTRAP_SECRETS_ENV_SHA256:-}"
  local payload_endpoint="${INFISICAL_BOOTSTRAP_SECRETS_ENV_ENDPOINT:-${S3_ENDPOINT:-}}"
  local payload_bucket="${INFISICAL_BOOTSTRAP_SECRETS_ENV_BUCKET:-}"
  local payload_key="${INFISICAL_BOOTSTRAP_SECRETS_ENV_KEY:-}"
  local tmp_file
  local http_code=""
  local -a aws_args=()

  if [ -f "$BOOTSTRAP_ENV_FILE" ]; then
    return 0
  fi

  if [ -z "$payload_url" ] && { [ -z "$payload_bucket" ] || [ -z "$payload_key" ]; }; then
    return 0
  fi

  tmp_file=$(mktemp)
  if [ -n "$payload_url" ]; then
    for _ in {1..20}; do
      http_code=$(curl -sS -L -o "$tmp_file" -w "%{http_code}" --connect-timeout 5 --max-time 30 "$payload_url" || true)
      if [ "$http_code" != "200" ]; then
        sleep 3
        continue
      fi

      if [ -n "$payload_sha256" ] && ! echo "$payload_sha256  $tmp_file" | sha256sum -c - >/dev/null; then
        rm -f "$tmp_file"
        echo "[egress] offloaded Infisical bootstrap payload checksum mismatch" >&2
        return 0
      fi

      install -D -m 0600 "$tmp_file" "$BOOTSTRAP_ENV_FILE"
      rm -f "$tmp_file"
      echo "[egress] loaded offloaded Infisical bootstrap payload (url)"
      return 0
    done
  fi

  if command -v aws >/dev/null 2>&1 && [ -n "$payload_bucket" ] && [ -n "$payload_key" ]; then
    if [ -n "$payload_endpoint" ]; then
      aws_args=(--endpoint-url "$payload_endpoint")
    fi
    for _ in {1..20}; do
      if aws "${aws_args[@]}" s3 cp "s3://${payload_bucket}/${payload_key}" "$tmp_file" >/dev/null 2>&1; then
        if [ -n "$payload_sha256" ] && ! echo "$payload_sha256  $tmp_file" | sha256sum -c - >/dev/null; then
          rm -f "$tmp_file"
          echo "[egress] offloaded Infisical bootstrap payload checksum mismatch (s3)" >&2
          return 0
        fi

        install -D -m 0600 "$tmp_file" "$BOOTSTRAP_ENV_FILE"
        rm -f "$tmp_file"
        echo "[egress] loaded offloaded Infisical bootstrap payload (s3)"
        return 0
      fi
      sleep 3
    done
  fi

  rm -f "$tmp_file"
  echo "[egress] unable to download offloaded Infisical bootstrap payload (http ${http_code:-000}); continuing" >&2
  return 0
}

download_offloaded_bootstrap_env
load_env "$BOOTSTRAP_ENV_FILE"

NETWORK_ENV="/etc/infrazero/network.env"
load_env "$NETWORK_ENV"

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[egress] missing required env: $name" >&2
    exit 1
  fi
}

require_env "S3_ACCESS_KEY_ID"
require_env "S3_SECRET_ACCESS_KEY"
require_env "S3_ENDPOINT"
require_env "S3_REGION"
require_env "DB_BACKUP_BUCKET"
require_env "INFISICAL_DB_BACKUP_AGE_PUBLIC_KEY"
require_env "INFISICAL_PASSWORD"
require_env "INFISICAL_EMAIL"
require_env "INFISICAL_ORGANIZATION"
require_env "INFISICAL_POSTGRES_DB"
require_env "INFISICAL_POSTGRES_USER"
require_env "INFISICAL_POSTGRES_PASSWORD"
require_env "INFISICAL_ENCRYPTION_KEY"
require_env "INFISICAL_AUTH_SECRET"
require_env "GRAFANA_ADMIN_PASSWORD"

export AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$S3_SECRET_ACCESS_KEY"
export AWS_DEFAULT_REGION="$S3_REGION"

ensure_aws_cli() {
  if command -v aws >/dev/null 2>&1; then
    return 0
  fi

  if command -v apt-get >/dev/null 2>&1; then
    if ! command -v unzip >/dev/null 2>&1; then
      apt-get install -y unzip
    fi
    if ! command -v curl >/dev/null 2>&1; then
      apt-get install -y curl
    fi
  fi

  if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
    echo "[egress] awscli install requires curl and unzip" >&2
    return 1
  fi

  local tmp_dir=""
  local archive=""
  local attempt=0
  tmp_dir=$(mktemp -d)
  archive="$tmp_dir/awscliv2.zip"

  for attempt in {1..20}; do
    if curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "$archive"; then
      rm -rf "$tmp_dir/aws"
      if unzip -q "$archive" -d "$tmp_dir" \
        && "$tmp_dir/aws/install" --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli --update \
        && command -v aws >/dev/null 2>&1; then
        rm -rf "$tmp_dir"
        return 0
      fi
    fi
    echo "[egress] awscli install attempt ${attempt}/20 failed; retrying in 3s" >&2
    sleep 3
  done

  rm -rf "$tmp_dir"
  return 1
}

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y docker.io docker-compose age jq iptables unzip openssl nginx certbot python3-certbot-dns-cloudflare haproxy
fi

systemctl enable --now docker

ensure_dns() {
  local default_if=""
  default_if=$(ip -4 route show default 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
  if [ -z "$default_if" ]; then
    return 0
  fi

  if [ -f /etc/systemd/resolved.conf ]; then
    sed -i 's/^#\?FallbackDNS=.*/FallbackDNS=1.1.1.1 1.0.0.1 8.8.8.8/' /etc/systemd/resolved.conf || true
    systemctl restart systemd-resolved || true
  fi

  if command -v resolvectl >/dev/null 2>&1; then
    resolvectl dns "$default_if" 1.1.1.1 1.0.0.1 8.8.8.8 || true
    resolvectl domain "$default_if" "~." || true
  fi
}

compose_cmd() {
  if command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    docker compose "$@"
  fi
}

# NAT/egress setup (before any external downloads)
cat > /etc/sysctl.d/99-infrazero-forward.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
sysctl --system

PRIVATE_CIDR="${PRIVATE_CIDR:-}"
if [ -z "$PRIVATE_CIDR" ]; then
  echo "[egress] PRIVATE_CIDR missing; NAT may be incomplete" >&2
fi

PUBLIC_IF=$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
PRIVATE_IF=$(ip -4 -o addr show | awk -v pub="$PUBLIC_IF" '$2 != pub && $2 != "lo" {print $2; exit}')

if [ -z "$PUBLIC_IF" ] || [ -z "$PRIVATE_IF" ]; then
  echo "[egress] unable to determine network interfaces" >&2
  exit 1
fi

PUBLIC_IP=$(ip -4 -o addr show dev "$PUBLIC_IF" | awk '{split($4, parts, "/"); print parts[1]; exit}')
if [ -z "$PUBLIC_IP" ]; then
  echo "[egress] unable to determine public ip address" >&2
fi

PRIVATE_IP=$(ip -4 -o addr show dev "$PRIVATE_IF" | awk '{split($4, parts, "/"); print parts[1]; exit}')
if [ -z "$PRIVATE_IP" ]; then
  echo "[egress] unable to determine private ip address" >&2
  exit 1
fi

CHAIN="DOCKER-USER"
if ! iptables -S "$CHAIN" >/dev/null 2>&1; then
  CHAIN="FORWARD"
fi

if [ -n "$PRIVATE_CIDR" ]; then
  iptables -t nat -C POSTROUTING -s "$PRIVATE_CIDR" -o "$PUBLIC_IF" -j MASQUERADE \
    || iptables -t nat -A POSTROUTING -s "$PRIVATE_CIDR" -o "$PUBLIC_IF" -j MASQUERADE
  iptables -C "$CHAIN" -i "$PRIVATE_IF" -o "$PUBLIC_IF" -s "$PRIVATE_CIDR" -j ACCEPT \
    || iptables -I "$CHAIN" 1 -i "$PRIVATE_IF" -o "$PUBLIC_IF" -s "$PRIVATE_CIDR" -j ACCEPT
  iptables -C "$CHAIN" -i "$PUBLIC_IF" -o "$PRIVATE_IF" -d "$PRIVATE_CIDR" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT \
    || iptables -I "$CHAIN" 1 -i "$PUBLIC_IF" -o "$PRIVATE_IF" -d "$PRIVATE_CIDR" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
fi

ensure_dns

if ! ensure_aws_cli; then
  echo "[egress] unable to install awscli" >&2
  exit 1
fi

mkdir -p /opt/infrazero/egress /opt/infrazero/infisical /opt/infrazero/infisical/backups

cat > /opt/infrazero/egress/loki-config.yaml <<'EOF'
auth_enabled: false
server:
  http_listen_port: 3100
common:
  path_prefix: /loki
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory: /loki/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory
schema_config:
  configs:
    - from: 2020-10-24
      store: boltdb-shipper
      object_store: filesystem
      schema: v11
      index:
        prefix: index_
        period: 24h
ruler:
  alertmanager_url: http://localhost:9093
EOF

cat > /opt/infrazero/egress/docker-compose.loki.yml <<'EOF'
version: "3.8"
services:
  loki:
    image: grafana/loki:2.9.3
    command: -config.file=/etc/loki/config.yaml
    restart: unless-stopped
    ports:
      - "3100:3100"
    volumes:
      - /opt/infrazero/egress/loki-config.yaml:/etc/loki/config.yaml:ro
      - /opt/infrazero/egress/loki-data:/loki
  grafana:
    image: grafana/grafana:10.4.2
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_USER: "admin"
      GF_SECURITY_ADMIN_PASSWORD: "${GRAFANA_ADMIN_PASSWORD}"
      GF_USERS_ALLOW_SIGN_UP: "false"
    volumes:
      - /opt/infrazero/egress/grafana-data:/var/lib/grafana
      - /opt/infrazero/egress/grafana-provisioning:/etc/grafana/provisioning:ro
      - /opt/infrazero/egress/grafana-dashboards:/var/lib/grafana/dashboards:ro
EOF

mkdir -p \
  /opt/infrazero/egress/loki-data \
  /opt/infrazero/egress/grafana-data \
  /opt/infrazero/egress/grafana-provisioning/datasources \
  /opt/infrazero/egress/grafana-provisioning/dashboards \
  /opt/infrazero/egress/grafana-dashboards
chown -R 10001:10001 /opt/infrazero/egress/loki-data
chown -R 472:472 /opt/infrazero/egress/grafana-data

cat > /opt/infrazero/egress/grafana-provisioning/datasources/loki.yml <<'EOF'
apiVersion: 1

datasources:
  - name: Loki
    uid: infrazero-loki
    type: loki
    access: proxy
    url: http://loki:3100
    isDefault: true
    editable: false
EOF

cat > /opt/infrazero/egress/grafana-provisioning/dashboards/infrazero.yml <<'EOF'
apiVersion: 1

providers:
  - name: infrazero
    orgId: 1
    folder: Infrazero / Operations
    type: file
    disableDeletion: false
    editable: true
    updateIntervalSeconds: 30
    options:
      path: /var/lib/grafana/dashboards
EOF

cat > /opt/infrazero/egress/grafana-dashboards/infrazero-platform-health.json <<'EOF'
{
  "annotations": {"list": []},
  "editable": true,
  "graphTooltip": 0,
  "panels": [
    {
      "datasource": {"type": "loki", "uid": "infrazero-loki"},
      "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}}, "overrides": []},
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
      "id": 1,
      "options": {"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "single"}},
      "targets": [
        {"expr": "sum by (cluster) (count_over_time({cluster=~\".+\"}[5m]))", "legendFormat": "{{cluster}}", "refId": "A"}
      ],
      "title": "Log Throughput by Cluster",
      "type": "timeseries"
    },
    {
      "datasource": {"type": "loki", "uid": "infrazero-loki"},
      "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}}, "overrides": []},
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
      "id": 2,
      "options": {"legend": {"displayMode": "table", "placement": "right"}, "tooltip": {"mode": "single"}},
      "targets": [
        {"expr": "sum by (namespace) (count_over_time({namespace=~\".+\"}[5m]))", "legendFormat": "{{namespace}}", "refId": "A"}
      ],
      "title": "Namespace Log Volume",
      "type": "timeseries"
    },
    {
      "datasource": {"type": "loki", "uid": "infrazero-loki"},
      "gridPos": {"h": 9, "w": 24, "x": 0, "y": 8},
      "id": 3,
      "options": {"dedupStrategy": "none", "enableLogDetails": true, "showLabels": true, "sortOrder": "Descending", "wrapLogMessage": true},
      "targets": [{"expr": "{job=~\".+\"} |= \"error\" or {job=~\".+\"} |= \"panic\" or {job=~\".+\"} |= \"fatal\"", "refId": "A"}],
      "title": "Recent Error Logs",
      "type": "logs"
    }
  ],
  "refresh": "30s",
  "schemaVersion": 39,
  "style": "dark",
  "tags": ["infrazero", "platform", "health"],
  "templating": {"list": []},
  "time": {"from": "now-6h", "to": "now"},
  "title": "Infrazero Platform Health",
  "uid": "infrazero-platform-health",
  "version": 1
}
EOF

cat > /opt/infrazero/egress/grafana-dashboards/infrazero-app-logs.json <<'EOF'
{
  "annotations": {"list": []},
  "editable": true,
  "graphTooltip": 0,
  "panels": [
    {
      "datasource": {"type": "loki", "uid": "infrazero-loki"},
      "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}}, "overrides": []},
      "gridPos": {"h": 8, "w": 24, "x": 0, "y": 0},
      "id": 1,
      "options": {"legend": {"displayMode": "table", "placement": "right"}, "tooltip": {"mode": "single"}},
      "targets": [
        {"expr": "sum by (namespace, app) (count_over_time({namespace=~\"$namespace\", app=~\"$app\"}[5m]))", "legendFormat": "{{namespace}} / {{app}}", "refId": "A"}
      ],
      "title": "App Log Throughput",
      "type": "timeseries"
    },
    {
      "datasource": {"type": "loki", "uid": "infrazero-loki"},
      "gridPos": {"h": 12, "w": 24, "x": 0, "y": 8},
      "id": 2,
      "options": {"dedupStrategy": "none", "enableLogDetails": true, "showLabels": true, "sortOrder": "Descending", "wrapLogMessage": true},
      "targets": [
        {"expr": "{namespace=~\"$namespace\", app=~\"$app\", pod=~\"$pod\"} |~ \"$query\"", "refId": "A"}
      ],
      "title": "Application Logs",
      "type": "logs"
    }
  ],
  "refresh": "15s",
  "schemaVersion": 39,
  "style": "dark",
  "tags": ["infrazero", "apps", "logs"],
  "templating": {
    "list": [
      {
        "current": {"selected": true, "text": ".*", "value": ".*"},
        "datasource": {"type": "loki", "uid": "infrazero-loki"},
        "definition": "label_values({namespace=~\".+\"}, namespace)",
        "hide": 0,
        "includeAll": false,
        "label": "namespace",
        "multi": false,
        "name": "namespace",
        "options": [],
        "query": "label_values({namespace=~\".+\"}, namespace)",
        "refresh": 2,
        "regex": "",
        "type": "query"
      },
      {
        "current": {"selected": true, "text": ".*", "value": ".*"},
        "datasource": {"type": "loki", "uid": "infrazero-loki"},
        "definition": "label_values({namespace=~\"$namespace\", app=~\".+\"}, app)",
        "hide": 0,
        "includeAll": false,
        "label": "app",
        "multi": false,
        "name": "app",
        "options": [],
        "query": "label_values({namespace=~\"$namespace\", app=~\".+\"}, app)",
        "refresh": 2,
        "regex": "",
        "type": "query"
      },
      {
        "current": {"selected": true, "text": ".*", "value": ".*"},
        "datasource": {"type": "loki", "uid": "infrazero-loki"},
        "definition": "label_values({namespace=~\"$namespace\", app=~\"$app\", pod=~\".+\"}, pod)",
        "hide": 0,
        "includeAll": false,
        "label": "pod",
        "multi": false,
        "name": "pod",
        "options": [],
        "query": "label_values({namespace=~\"$namespace\", app=~\"$app\", pod=~\".+\"}, pod)",
        "refresh": 2,
        "regex": "",
        "type": "query"
      },
      {
        "current": {"selected": true, "text": ".*", "value": ".*"},
        "hide": 0,
        "label": "search",
        "name": "query",
        "options": [],
        "query": ".*",
        "type": "textbox"
      }
    ]
  },
  "time": {"from": "now-6h", "to": "now"},
  "title": "Infrazero App Logs",
  "uid": "infrazero-app-logs",
  "version": 1
}
EOF

cat > /opt/infrazero/egress/grafana-dashboards/infrazero-bootstrap-and-security.json <<'EOF'
{
  "annotations": {"list": []},
  "editable": true,
  "graphTooltip": 0,
  "panels": [
    {
      "datasource": {"type": "loki", "uid": "infrazero-loki"},
      "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}}, "overrides": []},
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
      "id": 1,
      "options": {"legend": {"displayMode": "table", "placement": "right"}, "tooltip": {"mode": "single"}},
      "targets": [
        {"expr": "sum by (host, unit) (count_over_time({unit=~\"infrazero-bootstrap|cloud-init.*|k3s.*|docker.*\"}[5m]))", "legendFormat": "{{host}} / {{unit}}", "refId": "A"}
      ],
      "title": "Bootstrap and Runtime Service Activity",
      "type": "timeseries"
    },
    {
      "datasource": {"type": "loki", "uid": "infrazero-loki"},
      "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}}, "overrides": []},
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
      "id": 2,
      "options": {"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "single"}},
      "targets": [
        {"expr": "sum by (host) (count_over_time({job=\"systemd-journal\"} |= \"Failed password\" [5m])) + sum by (host) (count_over_time({job=\"systemd-journal\"} |= \"authentication failure\" [5m]))", "legendFormat": "{{host}}", "refId": "A"}
      ],
      "title": "Auth Failure Signal",
      "type": "timeseries"
    },
    {
      "datasource": {"type": "loki", "uid": "infrazero-loki"},
      "gridPos": {"h": 9, "w": 24, "x": 0, "y": 8},
      "id": 3,
      "options": {"dedupStrategy": "none", "enableLogDetails": true, "showLabels": true, "sortOrder": "Descending", "wrapLogMessage": true},
      "targets": [
        {"expr": "{job=\"systemd-journal\"} |= \"infisical-bootstrap\" or {job=\"systemd-journal\"} |= \"[node1]\" or {job=\"systemd-journal\"} |= \"[egress]\" or {job=\"systemd-journal\"} |= \"Failed password\" or {job=\"systemd-journal\"} |= \"authentication failure\"", "refId": "A"}
      ],
      "title": "Bootstrap + Security Audit Trail",
      "type": "logs"
    }
  ],
  "refresh": "30s",
  "schemaVersion": 39,
  "style": "dark",
  "tags": ["infrazero", "bootstrap", "security", "audit"],
  "templating": {"list": []},
  "time": {"from": "now-24h", "to": "now"},
  "title": "Infrazero Bootstrap and Security",
  "uid": "infrazero-bootstrap-security",
  "version": 1
}
EOF

compose_cmd -f /opt/infrazero/egress/docker-compose.loki.yml up -d

for i in {1..30}; do
  if curl -sf http://127.0.0.1:3100/ready >/dev/null; then
    echo "[egress] loki ready"
    break
  fi
  sleep 2
done

# Infisical + Postgres + Redis
INFISICAL_FQDN="${INFISICAL_FQDN:-}"
GRAFANA_FQDN="${GRAFANA_FQDN:-}"
LOKI_FQDN="${LOKI_FQDN:-}"
ARGOCD_FQDN="${ARGOCD_FQDN:-}"
KUBERNETES_FQDN="${KUBERNETES_FQDN:-}"
LETSENCRYPT_EMAIL="${LETSENCRYPT_EMAIL:-${INFISICAL_EMAIL}}"
INFISICAL_BIND_ADDR=${INFISICAL_BIND_ADDR:-"$PRIVATE_IP"}
INFISICAL_SITE_URL=${INFISICAL_SITE_URL:-""}
if [ -z "$INFISICAL_SITE_URL" ]; then
  if [ -n "$INFISICAL_FQDN" ]; then
    INFISICAL_SITE_URL="https://${INFISICAL_FQDN}"
  else
    INFISICAL_SITE_URL="http://${INFISICAL_BIND_ADDR}:8080"
  fi
fi
if [ -n "$INFISICAL_FQDN" ] && [[ "$INFISICAL_SITE_URL" != https://* ]]; then
  echo "[egress] INFISICAL_SITE_URL must be https for FQDN; overriding to https://${INFISICAL_FQDN}"
  INFISICAL_SITE_URL="https://${INFISICAL_FQDN}"
fi
export INFISICAL_SITE_URL
export INFISICAL_FQDN

cleanup_k3s_iptables() {
  local rules=()
  if [ -n "$PUBLIC_IP" ]; then
    rules+=("-p tcp --dport 6443 -s ${PUBLIC_IP}/32 -j ACCEPT")
  fi
  if [ -n "$PRIVATE_IP" ]; then
    rules+=("-p tcp --dport 6443 -s ${PRIVATE_IP}/32 -j ACCEPT")
  fi
  rules+=("-p tcp --dport 6443 -s 127.0.0.1/32 -j ACCEPT")
  rules+=("-p tcp --dport 6443 -j DROP")

  for rule in "${rules[@]}"; do
    # shellcheck disable=SC2086
    while iptables -C INPUT $rule >/dev/null 2>&1; do
      # shellcheck disable=SC2086
      iptables -D INPUT $rule || true
    done
  done
}

if [ -n "$KUBERNETES_FQDN" ]; then
  cleanup_k3s_iptables
fi

mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4

cat > /etc/systemd/system/infrazero-iptables.service <<'EOF'
[Unit]
Description=Restore iptables rules for Infrazero
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/iptables-restore /etc/iptables/rules.v4
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now infrazero-iptables.service

if [ -n "$INFISICAL_FQDN" ] || [ -n "$GRAFANA_FQDN" ] || [ -n "$LOKI_FQDN" ] || [ -n "$ARGOCD_FQDN" ] || [ -n "$KUBERNETES_FQDN" ]; then
  require_env "CLOUDFLARE_API_TOKEN"
fi
DB_CONNECTION_URI="postgres://${INFISICAL_POSTGRES_USER}:${INFISICAL_POSTGRES_PASSWORD}@infisical-db:5432/${INFISICAL_POSTGRES_DB}"
REDIS_URL="redis://redis:6379"

cat > /opt/infrazero/infisical/infisical.env <<EOF
ENCRYPTION_KEY=${INFISICAL_ENCRYPTION_KEY}
AUTH_SECRET=${INFISICAL_AUTH_SECRET}
SITE_URL=${INFISICAL_SITE_URL}
PORT=8080
HOST=0.0.0.0
DB_CONNECTION_URI=${DB_CONNECTION_URI}
REDIS_URL=${REDIS_URL}
POSTGRES_DB=${INFISICAL_POSTGRES_DB}
POSTGRES_USER=${INFISICAL_POSTGRES_USER}
POSTGRES_PASSWORD=${INFISICAL_POSTGRES_PASSWORD}
EOF

INFISICAL_TLS_CERT="/etc/letsencrypt/live/infrazero-services/fullchain.pem"
INFISICAL_TLS_KEY="/etc/letsencrypt/live/infrazero-services/privkey.pem"
INFISICAL_NGINX_CONF="/etc/nginx/conf.d/infrazero-services.conf"
INFISICAL_UPSTREAM_ADDR="${INFISICAL_BIND_ADDR}"
if [ "$INFISICAL_UPSTREAM_ADDR" = "0.0.0.0" ]; then
  INFISICAL_UPSTREAM_ADDR="127.0.0.1"
fi
ARGOCD_UPSTREAM_ADDR="${ARGOCD_UPSTREAM_ADDR:-${K3S_SERVER_PRIVATE_IP:-}}"
ARGOCD_UPSTREAM_PORT="${ARGOCD_UPSTREAM_PORT:-30080}"
KUBERNETES_UPSTREAM_ADDR="${KUBERNETES_UPSTREAM_ADDR:-${K3S_API_LB_PRIVATE_IP:-${K3S_SERVER_PRIVATE_IP:-}}}"
KUBERNETES_UPSTREAM_PORT="${KUBERNETES_UPSTREAM_PORT:-6443}"

write_https_server_block() {
  local name="$1"
  local upstream="$2"
  cat >> "$INFISICAL_NGINX_CONF" <<EOF
server {
  listen 80;
  server_name ${name};
  return 301 https://\$host\$request_uri;
}

server {
  listen 443 ssl;
  server_name ${name};

  ssl_certificate ${INFISICAL_TLS_CERT};
  ssl_certificate_key ${INFISICAL_TLS_KEY};
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers HIGH:!aNULL:!MD5;

  location / {
    proxy_pass ${upstream};
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Host \$host;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
  }
}
EOF
}

write_https_server_block_insecure_upstream() {
  local name="$1"
  local upstream="$2"
  cat >> "$INFISICAL_NGINX_CONF" <<EOF
server {
  listen 80;
  server_name ${name};
  return 301 https://\$host\$request_uri;
}

server {
  listen 443 ssl;
  server_name ${name};

  ssl_certificate ${INFISICAL_TLS_CERT};
  ssl_certificate_key ${INFISICAL_TLS_KEY};
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers HIGH:!aNULL:!MD5;

  location / {
    proxy_pass ${upstream};
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Host \$host;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_ssl_server_name on;
    proxy_ssl_verify off;
  }
}
EOF
}

setup_k3s_haproxy() {
  if [ -z "$KUBERNETES_FQDN" ]; then
    return 0
  fi

  local target_ip="${K3S_API_LB_PRIVATE_IP:-${K3S_SERVER_PRIVATE_IP:-}}"
  if [ -z "$target_ip" ]; then
    echo "[egress] KUBERNETES_FQDN set but no k3s upstream (K3S_API_LB_PRIVATE_IP or K3S_SERVER_PRIVATE_IP); skipping haproxy" >&2
    return 1
  fi

  cat > /etc/haproxy/haproxy.cfg <<EOF
global
  log /dev/log local0
  maxconn 2048
  user haproxy
  group haproxy
  daemon

defaults
  log global
  mode tcp
  timeout connect 10s
  timeout client 1m
  timeout server 1m

frontend k3s_api
  bind 0.0.0.0:6443
  default_backend k3s_api

backend k3s_api
  server k3s ${target_ip}:6443 check
EOF

  systemctl enable --now haproxy
  systemctl restart haproxy
}

setup_service_tls() {
  local domains=()
  if [ -n "$INFISICAL_FQDN" ]; then
    domains+=("$INFISICAL_FQDN")
  fi
  if [ -n "$GRAFANA_FQDN" ]; then
    domains+=("$GRAFANA_FQDN")
  fi
  if [ -n "$LOKI_FQDN" ]; then
    domains+=("$LOKI_FQDN")
  fi
  if [ -n "$ARGOCD_FQDN" ]; then
    domains+=("$ARGOCD_FQDN")
  fi
  if [ -n "$KUBERNETES_FQDN" ]; then
    domains+=("$KUBERNETES_FQDN")
  fi

  if [ "${#domains[@]}" -eq 0 ]; then
    echo "[egress] no service FQDNs set; skipping Let's Encrypt"
    return 0
  fi

  if [ -z "${CLOUDFLARE_API_TOKEN:-}" ]; then
    echo "[egress] CLOUDFLARE_API_TOKEN not set; skipping Let's Encrypt"
    return 0
  fi

  mkdir -p /etc/letsencrypt /etc/letsencrypt/renewal-hooks/deploy
  umask 077
  cat > /etc/letsencrypt/cloudflare.ini <<EOF
dns_cloudflare_api_token = ${CLOUDFLARE_API_TOKEN}
EOF
  umask 022

  local domain_args=()
  for domain in "${domains[@]}"; do
    domain_args+=("-d" "$domain")
  done

  if certbot certonly --non-interactive --agree-tos --email "$LETSENCRYPT_EMAIL" \
    --dns-cloudflare --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
    --dns-cloudflare-propagation-seconds 30 \
    --cert-name infrazero-services --expand "${domain_args[@]}"; then
    echo "[egress] Let's Encrypt cert issued for ${domains[*]}"
  else
    echo "[egress] Let's Encrypt issuance failed" >&2
    return 1
  fi

  cat > /etc/letsencrypt/renewal-hooks/deploy/infrazero-nginx-reload.sh <<'EOF'
#!/usr/bin/env bash
systemctl reload nginx
EOF
  chmod +x /etc/letsencrypt/renewal-hooks/deploy/infrazero-nginx-reload.sh

  : > "$INFISICAL_NGINX_CONF"
  if [ -n "$INFISICAL_FQDN" ]; then
    write_https_server_block "$INFISICAL_FQDN" "http://${INFISICAL_UPSTREAM_ADDR}:8080"
  fi
  if [ -n "$GRAFANA_FQDN" ]; then
    write_https_server_block "$GRAFANA_FQDN" "http://127.0.0.1:3000"
  fi
  if [ -n "$LOKI_FQDN" ]; then
    write_https_server_block "$LOKI_FQDN" "http://127.0.0.1:3100"
  fi
  if [ -n "$ARGOCD_FQDN" ]; then
    if [ -n "$ARGOCD_UPSTREAM_ADDR" ]; then
      write_https_server_block "$ARGOCD_FQDN" "http://${ARGOCD_UPSTREAM_ADDR}:${ARGOCD_UPSTREAM_PORT}"
    else
      echo "[egress] ARGOCD_FQDN set but no K3S_SERVER_PRIVATE_IP; skipping argocd proxy" >&2
    fi
  fi
  if [ -n "$KUBERNETES_FQDN" ]; then
    if [ -n "$KUBERNETES_UPSTREAM_ADDR" ]; then
      write_https_server_block_insecure_upstream "$KUBERNETES_FQDN" "https://${KUBERNETES_UPSTREAM_ADDR}:${KUBERNETES_UPSTREAM_PORT}"
    else
      echo "[egress] KUBERNETES_FQDN set but no k3s upstream; skipping kubernetes proxy" >&2
    fi
  fi

  nginx -t
  systemctl enable --now nginx
  systemctl reload nginx
  systemctl enable --now certbot.timer || true
}

cat > /opt/infrazero/infisical/docker-compose.yml <<EOF
version: "3.8"
services:
  infisical-db:
    image: postgres:15
    restart: unless-stopped
    env_file: /opt/infrazero/infisical/infisical.env
    volumes:
      - /opt/infrazero/infisical/db:/var/lib/postgresql/data
  redis:
    image: redis:7
    restart: unless-stopped
  infisical:
    image: infisical/infisical:latest
    restart: unless-stopped
    env_file: /opt/infrazero/infisical/infisical.env
    depends_on:
      - infisical-db
      - redis
    ports:
      - "${INFISICAL_BIND_ADDR}:8080:8080"
EOF

compose_cmd -f /opt/infrazero/infisical/docker-compose.yml up -d infisical-db redis

for i in {1..30}; do
  if compose_cmd -f /opt/infrazero/infisical/docker-compose.yml exec -T infisical-db pg_isready -U "$INFISICAL_POSTGRES_USER" >/dev/null 2>&1; then
    echo "[egress] postgres ready"
    break
  fi
  sleep 2
done

INFISICAL_RESTORE_FROM_S3="${INFISICAL_RESTORE_FROM_S3:-false}"

scrub_infisical_private_key_from_run_sh() {
  # The Infisical DB Age private key is only needed during bootstrap restore.
  # Scrub it from the persisted bootstrap script to avoid leaving it on disk.
  if [ -f /opt/infrazero/bootstrap/run.sh ]; then
    sed -i 's/^export INFISICAL_DB_BACKUP_AGE_PRIVATE_KEY=.*$/export INFISICAL_DB_BACKUP_AGE_PRIVATE_KEY=""/' /opt/infrazero/bootstrap/run.sh || true
  fi
}

restore_infisical() {
  local tmpdir
  tmpdir=$(mktemp -d /run/infrazero-restore.XXXX)
  chmod 700 "$tmpdir"
  if [ -z "${INFISICAL_DB_BACKUP_AGE_PRIVATE_KEY:-}" ]; then
    echo "[egress] no age private key set; skipping restore"
    rm -rf "$tmpdir"
    scrub_infisical_private_key_from_run_sh
    return 0
  fi

  echo "$INFISICAL_DB_BACKUP_AGE_PRIVATE_KEY" > "$tmpdir/age.key"
  chmod 600 "$tmpdir/age.key"

  if ! aws --endpoint-url "$S3_ENDPOINT" s3 cp "s3://${DB_BACKUP_BUCKET}/infisical/latest-dump.json" "$tmpdir/latest-dump.json" >/dev/null 2>&1; then
    echo "[egress] no latest-dump manifest found; skipping restore"
    rm -f "$tmpdir/age.key"
    rm -rf "$tmpdir"
    unset INFISICAL_DB_BACKUP_AGE_PRIVATE_KEY
    scrub_infisical_private_key_from_run_sh
    return 0
  fi

  local key
  local sha
  key=$(jq -r '.key' "$tmpdir/latest-dump.json")
  sha=$(jq -r '.sha256' "$tmpdir/latest-dump.json")

  if [ -z "$key" ] || [ "$key" = "null" ]; then
    echo "[egress] latest-dump manifest missing key" >&2
    rm -f "$tmpdir/age.key"
    rm -rf "$tmpdir"
    unset INFISICAL_DB_BACKUP_AGE_PRIVATE_KEY
    scrub_infisical_private_key_from_run_sh
    return 1
  fi

  aws --endpoint-url "$S3_ENDPOINT" s3 cp "s3://${DB_BACKUP_BUCKET}/${key}" "$tmpdir/dump.age"
  echo "$sha  $tmpdir/dump.age" | sha256sum -c -

  age -d -i "$tmpdir/age.key" -o "$tmpdir/dump.sql.gz" "$tmpdir/dump.age"
  gunzip -c "$tmpdir/dump.sql.gz" | compose_cmd -f /opt/infrazero/infisical/docker-compose.yml exec -T infisical-db psql -U "$INFISICAL_POSTGRES_USER" -d "$INFISICAL_POSTGRES_DB"

  rm -f "$tmpdir/age.key"
  rm -rf "$tmpdir"
  unset INFISICAL_DB_BACKUP_AGE_PRIVATE_KEY
  scrub_infisical_private_key_from_run_sh
  echo "[egress] restore complete"
}

if [ "${INFISICAL_RESTORE_FROM_S3,,}" = "true" ]; then
  echo "[egress] infisical_restore_from_s3=true; attempting restore"
  restore_infisical
else
  echo "[egress] infisical_restore_from_s3 not true; skipping restore"
fi

scrub_infisical_private_key_from_run_sh
unset INFISICAL_DB_BACKUP_AGE_PRIVATE_KEY

if [ "${INFISICAL_RESTORE_FROM_S3,,}" != "true" ]; then
  echo "[egress] clearing infisical bootstrap tokens manifest before bootstrap"
  aws --endpoint-url "$S3_ENDPOINT" s3 rm "s3://${DB_BACKUP_BUCKET}/infisical/bootstrap/latest-tokens.json" >/dev/null 2>&1 || true
fi

compose_cmd -f /opt/infrazero/infisical/docker-compose.yml up -d infisical

setup_k3s_haproxy || true
setup_service_tls || true

cat > /opt/infrazero/egress/grafana-bootstrap.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

load_env() {
  local file="$1"
  if [ -f "$file" ]; then
    set -a
    # shellcheck disable=SC1090
    source "$file"
    set +a
  fi
}

load_env /etc/infrazero/egress.env
load_env /etc/infrazero/egress.bootstrap.env

if [ -z "${GRAFANA_ADMIN_PASSWORD:-}" ]; then
  echo "[grafana-bootstrap] GRAFANA_ADMIN_PASSWORD is required" >&2
  exit 1
fi

if [ -z "${PLATFORM_ADMINS_JSON:-}" ]; then
  echo "[grafana-bootstrap] PLATFORM_ADMINS_JSON not set; skipping per-admin Grafana users"
  exit 0
fi

for i in {1..60}; do
  if curl -fsS -u "admin:${GRAFANA_ADMIN_PASSWORD}" http://127.0.0.1:3000/api/health >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

lookup_tmp=$(mktemp)
create_tmp=$(mktemp)
org_tmp=$(mktemp)
cleanup() {
  rm -f "$lookup_tmp" "$create_tmp" "$org_tmp"
}
trap cleanup EXIT

echo "$PLATFORM_ADMINS_JSON" | jq -c '.[]?' | while read -r admin; do
  email=$(echo "$admin" | jq -r '.email // empty')
  password=$(echo "$admin" | jq -r '.grafana_password // empty')
  if [ -z "$email" ] || [ -z "$password" ]; then
    continue
  fi

  lookup_email_uri=$(printf '%s' "$email" | jq -sRr @uri)
  lookup_code=$(curl -sS -u "admin:${GRAFANA_ADMIN_PASSWORD}" -o "$lookup_tmp" -w "%{http_code}" \
    "http://127.0.0.1:3000/api/users/lookup?loginOrEmail=${lookup_email_uri}" || true)

  user_id=""
  if [ "$lookup_code" = "200" ]; then
    user_id=$(jq -r '.id // empty' "$lookup_tmp")
  elif [ "$lookup_code" = "404" ]; then
    create_payload=$(jq -n --arg email "$email" --arg password "$password" \
      '{name:$email,email:$email,login:$email,password:$password}')
    create_code=$(curl -sS -u "admin:${GRAFANA_ADMIN_PASSWORD}" -o "$create_tmp" -w "%{http_code}" \
      -H "Content-Type: application/json" \
      -d "$create_payload" \
      "http://127.0.0.1:3000/api/admin/users" || true)
    if [[ "$create_code" != 2* ]]; then
      echo "[grafana-bootstrap] failed to create user ${email} (http ${create_code})" >&2
      continue
    fi
    user_id=$(jq -r '.id // empty' "$create_tmp")
  else
    echo "[grafana-bootstrap] failed to lookup user ${email} (http ${lookup_code})" >&2
    continue
  fi

  if [ -z "$user_id" ]; then
    echo "[grafana-bootstrap] unable to resolve user id for ${email}" >&2
    continue
  fi

  password_payload=$(jq -n --arg password "$password" '{password:$password}')
  curl -sS -u "admin:${GRAFANA_ADMIN_PASSWORD}" -o /dev/null \
    -H "Content-Type: application/json" \
    -d "$password_payload" \
    "http://127.0.0.1:3000/api/admin/users/${user_id}/password" || true

  org_code=$(curl -sS -u "admin:${GRAFANA_ADMIN_PASSWORD}" -o "$org_tmp" -w "%{http_code}" \
    "http://127.0.0.1:3000/api/org/users" || true)
  if [ "$org_code" = "200" ]; then
    org_user_id=$(jq -r --arg email "$email" '.[] | select((.email // "") == $email or (.login // "") == $email) | .userId' "$org_tmp" | head -n 1)
    if [ -n "$org_user_id" ]; then
      role_payload='{"role":"Admin"}'
      curl -sS -u "admin:${GRAFANA_ADMIN_PASSWORD}" -o /dev/null \
        -X PATCH \
        -H "Content-Type: application/json" \
        -d "$role_payload" \
        "http://127.0.0.1:3000/api/org/users/${org_user_id}" || true
    fi
  fi
done

echo "[grafana-bootstrap] complete"
EOF
chmod +x /opt/infrazero/egress/grafana-bootstrap.sh
/opt/infrazero/egress/grafana-bootstrap.sh || true

if [ -n "$INFISICAL_FQDN" ]; then
  echo "[egress] infisical https enabled at https://${INFISICAL_FQDN}"
else
  echo "[egress] infisical https not configured (missing INFISICAL_FQDN)"
fi

if [ -n "${INFISICAL_FQDN:-}" ] || [ -n "${INFISICAL_SITE_URL:-}" ]; then
  if [ -f "./infisical-bootstrap.sh" ]; then
    chmod +x ./infisical-bootstrap.sh
    ./infisical-bootstrap.sh
  else
    echo "[egress] infisical-bootstrap.sh missing; skipping infisical bootstrap" >&2
  fi
fi

cat > /opt/infrazero/infisical/backup.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/etc/infrazero/egress.env"
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

export AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$S3_SECRET_ACCESS_KEY"
export AWS_DEFAULT_REGION="$S3_REGION"

TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
WORKDIR="/opt/infrazero/infisical/backups"
mkdir -p "$WORKDIR"

DUMP_PATH="$WORKDIR/infisical-${TIMESTAMP}.sql.gz"
ENC_PATH="$DUMP_PATH.age"

if command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  COMPOSE=(docker compose)
fi

"${COMPOSE[@]}" -f /opt/infrazero/infisical/docker-compose.yml exec -T infisical-db pg_dump -U "$INFISICAL_POSTGRES_USER" -d "$INFISICAL_POSTGRES_DB" | gzip > "$DUMP_PATH"

age -r "$INFISICAL_DB_BACKUP_AGE_PUBLIC_KEY" -o "$ENC_PATH" "$DUMP_PATH"
SHA=$(sha256sum "$ENC_PATH" | awk '{print $1}')
KEY="infisical/${TIMESTAMP}.sql.gz.age"

aws --endpoint-url "$S3_ENDPOINT" s3 cp "$ENC_PATH" "s3://${DB_BACKUP_BUCKET}/${KEY}"

jq -n --arg key "$KEY" --arg sha "$SHA" --arg created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{key:$key, sha256:$sha, created_at:$created_at}' > "$WORKDIR/latest-dump.json"
aws --endpoint-url "$S3_ENDPOINT" s3 cp "$WORKDIR/latest-dump.json" "s3://${DB_BACKUP_BUCKET}/infisical/latest-dump.json"

rm -f "$DUMP_PATH" "$ENC_PATH"
EOF

chmod +x /opt/infrazero/infisical/backup.sh

cat > /etc/cron.d/infisical-backup <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

15 2 * * * root /opt/infrazero/infisical/backup.sh >> /var/log/infrazero-infisical-backup.log 2>&1
EOF

chmod 0644 /etc/cron.d/infisical-backup

beacon_status "complete" "Bootstrap complete" 100

echo "[egress] $(date -Is) complete"
