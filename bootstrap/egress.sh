#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/infrazero-bootstrap.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[egress] $(date -Is) start"

ENV_FILE="/etc/infrazero/egress.env"
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

NETWORK_ENV="/etc/infrazero/network.env"
if [ -f "$NETWORK_ENV" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$NETWORK_ENV"
  set +a
fi

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
require_env "INFISICAL_NAME"
require_env "INFISICAL_SURNAME"
require_env "INFISICAL_POSTGRES_DB"
require_env "INFISICAL_POSTGRES_USER"
require_env "INFISICAL_POSTGRES_PASSWORD"
require_env "INFISICAL_ENCRYPTION_KEY"
require_env "INFISICAL_AUTH_SECRET"

export AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$S3_SECRET_ACCESS_KEY"
export AWS_DEFAULT_REGION="$S3_REGION"

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

if ! command -v aws >/dev/null 2>&1; then
  if curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip; then
    unzip -q /tmp/awscliv2.zip -d /tmp
    /tmp/aws/install --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli --update
  else
    echo "[egress] awscli download failed; continuing without aws" >&2
  fi
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
    volumes:
      - /opt/infrazero/egress/grafana-data:/var/lib/grafana
      - /opt/infrazero/egress/grafana-provisioning:/etc/grafana/provisioning:ro
EOF

mkdir -p /opt/infrazero/egress/loki-data /opt/infrazero/egress/grafana-data /opt/infrazero/egress/grafana-provisioning/datasources
chown -R 10001:10001 /opt/infrazero/egress/loki-data
chown -R 472:472 /opt/infrazero/egress/grafana-data

cat > /opt/infrazero/egress/grafana-provisioning/datasources/loki.yml <<'EOF'
apiVersion: 1

datasources:
  - name: Loki
    type: loki
    access: proxy
    url: http://loki:3100
    isDefault: true
    editable: false
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

echo "[egress] $(date -Is) complete"
