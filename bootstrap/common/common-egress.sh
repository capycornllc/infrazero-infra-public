#!/usr/bin/env bash

infrazero_enable_egress_forwarding_early() {
  cat > /etc/sysctl.d/99-infrazero-forward-early.conf <<'SYSCTL'
net.ipv4.ip_forward=1
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
SYSCTL
  sysctl --system >/dev/null 2>&1 || true
}

infrazero_enable_egress_forwarding() {
  cat > /etc/sysctl.d/99-infrazero-forward.conf <<'SYSCTL'
net.ipv4.ip_forward=1
SYSCTL
  sysctl --system
}

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

infrazero_require_egress_env() {
  infrazero_require_env "S3_ACCESS_KEY_ID" "egress"
  infrazero_require_env "S3_SECRET_ACCESS_KEY" "egress"
  infrazero_require_env "S3_ENDPOINT" "egress"
  infrazero_require_env "S3_REGION" "egress"
  infrazero_require_env "DB_BACKUP_BUCKET" "egress"
  infrazero_require_env "INFISICAL_DB_BACKUP_AGE_PUBLIC_KEY" "egress"
  infrazero_require_env "INFISICAL_PASSWORD" "egress"
  infrazero_require_env "INFISICAL_EMAIL" "egress"
  infrazero_require_env "INFISICAL_ORGANIZATION" "egress"
  infrazero_require_env "INFISICAL_POSTGRES_DB" "egress"
  infrazero_require_env "INFISICAL_POSTGRES_USER" "egress"
  infrazero_require_env "INFISICAL_POSTGRES_PASSWORD" "egress"
  infrazero_require_env "INFISICAL_ENCRYPTION_KEY" "egress"
  infrazero_require_env "INFISICAL_AUTH_SECRET" "egress"
  infrazero_require_env "GRAFANA_ADMIN_PASSWORD" "egress"
}

infrazero_export_egress_runtime_env() {
  export AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY_ID"
  export AWS_SECRET_ACCESS_KEY="$S3_SECRET_ACCESS_KEY"
  export AWS_DEFAULT_REGION="$S3_REGION"
  export EGRESS_DOCKER_LOG_MAX_SIZE="${EGRESS_DOCKER_LOG_MAX_SIZE:-100m}"
  export EGRESS_DOCKER_LOG_MAX_FILES="${EGRESS_DOCKER_LOG_MAX_FILES:-5}"
  export LOKI_EGRESS_DOCKER_LOGS_ENABLED="${LOKI_EGRESS_DOCKER_LOGS_ENABLED:-true}"
  export LOKI_LOG_FILTER_ENABLED="${LOKI_LOG_FILTER_ENABLED:-false}"
  export LOKI_LOG_DROP_REGEX="${LOKI_LOG_DROP_REGEX:-}"
}

infrazero_require_cloudflare_for_public_fqdns() {
  if [ -n "${INFISICAL_FQDN:-}" ] \
    || [ -n "${GRAFANA_FQDN:-}" ] \
    || [ -n "${LOKI_FQDN:-}" ] \
    || [ -n "${ARGOCD_FQDN:-}" ] \
    || [ -n "${KUBERNETES_FQDN:-}" ]; then
    infrazero_require_env "CLOUDFLARE_API_TOKEN" "egress"
  fi
}

infrazero_prepare_egress_service_env() {
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
}

infrazero_prepare_egress_tls_env() {
  INFRAZERO_CERT_NAME="${INFRAZERO_CERT_NAME:-infrazero-services}"
  INFRAZERO_TLS_DIR="/etc/infrazero/tls/${INFRAZERO_CERT_NAME}"
  INFRAZERO_LE_LIVE_DIR="/etc/letsencrypt/live/${INFRAZERO_CERT_NAME}"
  INFISICAL_TLS_CERT="${INFRAZERO_TLS_DIR}/fullchain.pem"
  INFISICAL_TLS_KEY="${INFRAZERO_TLS_DIR}/privkey.pem"
  INFISICAL_NGINX_CONF="/etc/nginx/conf.d/infrazero-services.conf"
  INFISICAL_UPSTREAM_ADDR="${INFISICAL_BIND_ADDR}"
  if [ "$INFISICAL_UPSTREAM_ADDR" = "0.0.0.0" ]; then
    INFISICAL_UPSTREAM_ADDR="127.0.0.1"
  fi
  ARGOCD_UPSTREAM_ADDR="${ARGOCD_UPSTREAM_ADDR:-${K3S_SERVER_PRIVATE_IP:-}}"
  ARGOCD_UPSTREAM_PORT="${ARGOCD_UPSTREAM_PORT:-80}"
  KUBERNETES_UPSTREAM_ADDR="${KUBERNETES_UPSTREAM_ADDR:-${K3S_API_LB_PRIVATE_IP:-${K3S_SERVER_PRIVATE_IP:-}}}"
  KUBERNETES_UPSTREAM_PORT="${KUBERNETES_UPSTREAM_PORT:-6443}"
}

infrazero_write_infisical_env() {
  local db_connection_uri="postgres://${INFISICAL_POSTGRES_USER}:${INFISICAL_POSTGRES_PASSWORD}@infisical-db:5432/${INFISICAL_POSTGRES_DB}"
  local redis_url="redis://redis:6379"

  cat > /opt/infrazero/infisical/infisical.env <<EOF
ENCRYPTION_KEY=${INFISICAL_ENCRYPTION_KEY}
AUTH_SECRET=${INFISICAL_AUTH_SECRET}
SITE_URL=${INFISICAL_SITE_URL}
PORT=8080
HOST=0.0.0.0
DB_CONNECTION_URI=${db_connection_uri}
REDIS_URL=${redis_url}
EOF

  if infrazero_bool_is_true "${INFISICAL_ALLOW_INTERNAL_IP_CONNECTIONS:-false}"; then
    cat >> /opt/infrazero/infisical/infisical.env <<'EOF'
ALLOW_INTERNAL_IP_CONNECTIONS=true
EOF
  fi

  cat >> /opt/infrazero/infisical/infisical.env <<EOF
POSTGRES_DB=${INFISICAL_POSTGRES_DB}
POSTGRES_USER=${INFISICAL_POSTGRES_USER}
POSTGRES_PASSWORD=${INFISICAL_POSTGRES_PASSWORD}
EOF
}

infrazero_write_infisical_compose() {
  cat > /opt/infrazero/infisical/docker-compose.yml <<EOF
version: "3.8"
services:
  infisical-db:
    image: postgres:15
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "${EGRESS_DOCKER_LOG_MAX_SIZE:-100m}"
        max-file: "${EGRESS_DOCKER_LOG_MAX_FILES:-5}"
    env_file: /opt/infrazero/infisical/infisical.env
    volumes:
      - /opt/infrazero/infisical/db:/var/lib/postgresql/data
  redis:
    image: redis:7
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "${EGRESS_DOCKER_LOG_MAX_SIZE:-100m}"
        max-file: "${EGRESS_DOCKER_LOG_MAX_FILES:-5}"
  infisical:
    image: infisical/infisical:latest
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "${EGRESS_DOCKER_LOG_MAX_SIZE:-100m}"
        max-file: "${EGRESS_DOCKER_LOG_MAX_FILES:-5}"
    env_file: /opt/infrazero/infisical/infisical.env
    depends_on:
      - infisical-db
      - redis
    ports:
      - "${INFISICAL_BIND_ADDR}:8080:8080"
EOF

  if infrazero_bool_is_true "${INFISICAL_KUBERNETES_EXTRA_HOSTS:-false}" && [ -n "$KUBERNETES_FQDN" ] && [ -n "$PRIVATE_IP" ]; then
    cat >> /opt/infrazero/infisical/docker-compose.yml <<EOF
    extra_hosts:
      - "${KUBERNETES_FQDN}:${PRIVATE_IP}"
EOF
  fi
}

infrazero_start_infisical_dependencies() {
  # Retry docker compose up for Infisical dependencies - transient Docker Hub
  # failures (connection reset by peer, rate limiting) must not kill the whole bootstrap.
  for _infra_attempt in {1..5}; do
    if compose_cmd -f /opt/infrazero/infisical/docker-compose.yml up -d infisical-db redis; then
      break
    fi
    echo "[egress] docker compose up infisical-db redis failed (attempt ${_infra_attempt}/5); retrying in 15s" >&2
    sleep 15
    compose_cmd -f /opt/infrazero/infisical/docker-compose.yml down --remove-orphans 2>/dev/null || true
    docker system prune -f 2>/dev/null || true
  done
}

infrazero_wait_infisical_postgres() {
  local i

  for i in {1..120}; do
    if compose_cmd -f /opt/infrazero/infisical/docker-compose.yml exec -T infisical-db pg_isready -U "$INFISICAL_POSTGRES_USER" >/dev/null 2>&1; then
      echo "[egress] postgres ready"
      break
    fi
    if [ "$i" -eq 120 ]; then
      echo "[egress] WARNING: postgres not ready after 120 attempts; continuing anyway" >&2
    fi
    sleep 2
  done
}

infrazero_start_infisical_service() {
  for _infra_attempt in {1..5}; do
    if compose_cmd -f /opt/infrazero/infisical/docker-compose.yml up -d infisical; then
      break
    fi
    echo "[egress] docker compose up infisical failed (attempt ${_infra_attempt}/5); retrying in 15s" >&2
    sleep 15
    compose_cmd -f /opt/infrazero/infisical/docker-compose.yml down --remove-orphans 2>/dev/null || true
  done
}

apt_get() {
  INFRAZERO_APT_ATTEMPTS="${INFRAZERO_APT_ATTEMPTS:-10}" \
  INFRAZERO_APT_RETRY_DELAY="${INFRAZERO_APT_RETRY_DELAY:-10}" \
  INFRAZERO_APT_CLEAN_LISTS="${INFRAZERO_APT_CLEAN_LISTS:-false}" \
    infrazero_apt_get "egress" "$@"
}

ensure_aws_cli() {
  if declare -F infrazero_ensure_aws_cli >/dev/null 2>&1; then
    infrazero_ensure_aws_cli "egress"
  else
    echo "[egress] common-base.sh missing infrazero_ensure_aws_cli" >&2
    return 1
  fi
}

infrazero_install_egress_packages() {
  if ! command -v apt-get >/dev/null 2>&1; then
    return 0
  fi

  export DEBIAN_FRONTEND=noninteractive
  apt_get update -y
  apt_get install -y docker.io docker-compose age jq iptables unzip openssl nginx certbot python3-certbot-dns-cloudflare haproxy
}

infrazero_enable_and_wait_docker() {
  local attempt

  systemctl enable --now docker
  for attempt in {1..30}; do
    docker info >/dev/null 2>&1 && return 0
    echo "[egress] waiting for Docker daemon (attempt ${attempt}/30)..."
    sleep 2
  done

  return 0
}

infrazero_apply_egress_nat_rules() {
  local private_cidr="${1:-}"
  local private_if="${2:-}"
  local public_if="${3:-}"
  local chain="DOCKER-USER"

  if [ -z "$private_cidr" ] || [ -z "$private_if" ] || [ -z "$public_if" ]; then
    return 0
  fi

  if ! iptables -S "$chain" >/dev/null 2>&1; then
    chain="FORWARD"
  fi

  iptables -t nat -C POSTROUTING -s "$private_cidr" -o "$public_if" -j MASQUERADE \
    || iptables -t nat -A POSTROUTING -s "$private_cidr" -o "$public_if" -j MASQUERADE
  iptables -C "$chain" -i "$private_if" -o "$public_if" -s "$private_cidr" -j ACCEPT \
    || iptables -I "$chain" 1 -i "$private_if" -o "$public_if" -s "$private_cidr" -j ACCEPT
  iptables -C "$chain" -i "$public_if" -o "$private_if" -d "$private_cidr" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT \
    || iptables -I "$chain" 1 -i "$public_if" -o "$private_if" -d "$private_cidr" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
}

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

infrazero_persist_iptables_rules() {
  mkdir -p /etc/iptables
  iptables-save > /etc/iptables/rules.v4

  cat > /etc/systemd/system/infrazero-iptables.service <<'EOF'
[Unit]
Description=Restore iptables rules for Infrazero
# Must run after Docker so DOCKER-USER chain already exists when we restore rules.
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/iptables-restore --noflush /etc/iptables/rules.v4
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now infrazero-iptables.service
}

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

cleanup_broken_certbot_lineage() {
  local live_dir="$INFRAZERO_LE_LIVE_DIR"
  local archive_dir="/etc/letsencrypt/archive/${INFRAZERO_CERT_NAME}"
  local renewal_file="/etc/letsencrypt/renewal/${INFRAZERO_CERT_NAME}.conf"
  local backup_dir=""

  if [ -d "$live_dir" ] && [ ! -f "${live_dir}/fullchain.pem" ]; then
    backup_dir="/root/letsencrypt-broken-$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$backup_dir"
    mv "$live_dir" "$backup_dir/live-${INFRAZERO_CERT_NAME}" || true
    [ -d "$archive_dir" ] && mv "$archive_dir" "$backup_dir/archive-${INFRAZERO_CERT_NAME}" || true
    [ -f "$renewal_file" ] && mv "$renewal_file" "$backup_dir/${INFRAZERO_CERT_NAME}.conf" || true
    echo "[egress] moved incomplete certbot state to ${backup_dir}"
    return 0
  fi

  if [ -d "$live_dir" ] && [ -f "${live_dir}/fullchain.pem" ]; then
    local issuer
    issuer=$(openssl x509 -in "${live_dir}/fullchain.pem" -noout -issuer 2>/dev/null || true)
    if [ -n "$issuer" ] && ! echo "$issuer" | grep -qi "Let's Encrypt"; then
      backup_dir="/root/letsencrypt-broken-$(date -u +%Y%m%dT%H%M%SZ)"
      mkdir -p "$backup_dir"
      mv "$live_dir" "$backup_dir/live-${INFRAZERO_CERT_NAME}" || true
      [ -d "$archive_dir" ] && mv "$archive_dir" "$backup_dir/archive-${INFRAZERO_CERT_NAME}" || true
      [ -f "$renewal_file" ] && mv "$renewal_file" "$backup_dir/${INFRAZERO_CERT_NAME}.conf" || true
      echo "[egress] moved non-Let's Encrypt certbot state to ${backup_dir}"
      return 0
    fi
  fi

  if [ -f "$renewal_file" ] && [ ! -f "${live_dir}/fullchain.pem" ]; then
    backup_dir="/root/letsencrypt-broken-$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$backup_dir"
    mv "$renewal_file" "$backup_dir/${INFRAZERO_CERT_NAME}.conf" || true
    [ -d "$archive_dir" ] && mv "$archive_dir" "$backup_dir/archive-${INFRAZERO_CERT_NAME}" || true
    echo "[egress] moved broken certbot renewal config to ${backup_dir}"
  fi
}

install_certbot_retry_service() {
  cat > /usr/local/sbin/infrazero-certbot-certonly.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ -f /etc/infrazero/egress.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /etc/infrazero/egress.env
  set +a
fi

INFRAZERO_CERT_NAME="${INFRAZERO_CERT_NAME:-infrazero-services}"
INFRAZERO_TLS_DIR="/etc/infrazero/tls/${INFRAZERO_CERT_NAME}"
INFRAZERO_LE_LIVE_DIR="/etc/letsencrypt/live/${INFRAZERO_CERT_NAME}"
LETSENCRYPT_EMAIL="${LETSENCRYPT_EMAIL:-${INFISICAL_EMAIL:-}}"

if [ -z "${LETSENCRYPT_EMAIL:-}" ]; then
  echo "[certbot-retry] LETSENCRYPT_EMAIL/INFISICAL_EMAIL is not set" >&2
  exit 1
fi
if [ -z "${CLOUDFLARE_API_TOKEN:-}" ]; then
  echo "[certbot-retry] CLOUDFLARE_API_TOKEN is not set" >&2
  exit 1
fi

domains=()
for var in INFISICAL_FQDN GRAFANA_FQDN LOKI_FQDN ARGOCD_FQDN KUBERNETES_FQDN; do
  value="${!var:-}"
  [ -n "$value" ] && domains+=("$value")
done
if [ "${#domains[@]}" -eq 0 ]; then
  echo "[certbot-retry] no service FQDNs configured" >&2
  exit 1
fi

mkdir -p /etc/letsencrypt /etc/letsencrypt/renewal-hooks/deploy
umask 077
printf 'dns_cloudflare_api_token = %s\n' "$CLOUDFLARE_API_TOKEN" > /etc/letsencrypt/cloudflare.ini
umask 022

live_dir="$INFRAZERO_LE_LIVE_DIR"
archive_dir="/etc/letsencrypt/archive/${INFRAZERO_CERT_NAME}"
renewal_file="/etc/letsencrypt/renewal/${INFRAZERO_CERT_NAME}.conf"
if [ -d "$live_dir" ] && [ ! -f "${live_dir}/fullchain.pem" ]; then
  backup_dir="/root/letsencrypt-broken-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$backup_dir"
  mv "$live_dir" "$backup_dir/live-${INFRAZERO_CERT_NAME}" || true
  [ -d "$archive_dir" ] && mv "$archive_dir" "$backup_dir/archive-${INFRAZERO_CERT_NAME}" || true
  [ -f "$renewal_file" ] && mv "$renewal_file" "$backup_dir/${INFRAZERO_CERT_NAME}.conf" || true
  echo "[certbot-retry] moved incomplete certbot state to ${backup_dir}"
elif [ -d "$live_dir" ] && [ -f "${live_dir}/fullchain.pem" ]; then
  issuer=$(openssl x509 -in "${live_dir}/fullchain.pem" -noout -issuer 2>/dev/null || true)
  if [ -n "$issuer" ] && ! echo "$issuer" | grep -qi "Let's Encrypt"; then
    backup_dir="/root/letsencrypt-broken-$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$backup_dir"
    mv "$live_dir" "$backup_dir/live-${INFRAZERO_CERT_NAME}" || true
    [ -d "$archive_dir" ] && mv "$archive_dir" "$backup_dir/archive-${INFRAZERO_CERT_NAME}" || true
    [ -f "$renewal_file" ] && mv "$renewal_file" "$backup_dir/${INFRAZERO_CERT_NAME}.conf" || true
    echo "[certbot-retry] moved non-Let's Encrypt certbot state to ${backup_dir}"
  fi
elif [ -f "$renewal_file" ]; then
  backup_dir="/root/letsencrypt-broken-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$backup_dir"
  mv "$renewal_file" "$backup_dir/${INFRAZERO_CERT_NAME}.conf" || true
  [ -d "$archive_dir" ] && mv "$archive_dir" "$backup_dir/archive-${INFRAZERO_CERT_NAME}" || true
  echo "[certbot-retry] moved broken certbot renewal config to ${backup_dir}"
fi

domain_args=()
for domain in "${domains[@]}"; do
  domain_args+=("-d" "$domain")
done

certbot certonly --non-interactive --agree-tos --email "$LETSENCRYPT_EMAIL" \
  --dns-cloudflare --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
  --dns-cloudflare-propagation-seconds "${LETSENCRYPT_DNS_PROPAGATION_SECONDS:-90}" \
  --cert-name "$INFRAZERO_CERT_NAME" --expand "${domain_args[@]}"

mkdir -p "$INFRAZERO_TLS_DIR"
ln -sfn "${INFRAZERO_LE_LIVE_DIR}/fullchain.pem" "${INFRAZERO_TLS_DIR}/fullchain.pem"
ln -sfn "${INFRAZERO_LE_LIVE_DIR}/privkey.pem" "${INFRAZERO_TLS_DIR}/privkey.pem"

if command -v nginx >/dev/null 2>&1 && nginx -t; then
  systemctl reload nginx || true
fi
systemctl disable --now infrazero-certbot-retry.timer >/dev/null 2>&1 || true
EOF
  chmod +x /usr/local/sbin/infrazero-certbot-certonly.sh

  cat > /etc/systemd/system/infrazero-certbot-retry.service <<'UNIT'
[Unit]
Description=Retry Let's Encrypt certificate issuance
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/infrazero-certbot-certonly.sh
TimeoutStartSec=900
UNIT

  cat > /etc/systemd/system/infrazero-certbot-retry.timer <<'TIMER'
[Unit]
Description=Retry certbot until the service certificate exists

[Timer]
OnBootSec=10min
OnUnitActiveSec=30min

[Install]
WantedBy=timers.target
TIMER

  systemctl daemon-reload
}

generate_self_signed_service_cert() {
  local primary_domain="$1"
  mkdir -p "$INFRAZERO_TLS_DIR"
  rm -f "$INFISICAL_TLS_CERT" "$INFISICAL_TLS_KEY"
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$INFISICAL_TLS_KEY" \
    -out "$INFISICAL_TLS_CERT" \
    -subj "/CN=${primary_domain}" 2>/dev/null
  chmod 600 "$INFISICAL_TLS_KEY"
  chmod 644 "$INFISICAL_TLS_CERT"
  echo "[egress] self-signed fallback certificate generated at ${INFRAZERO_TLS_DIR}"
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

  mkdir -p /etc/letsencrypt /etc/letsencrypt/renewal-hooks/deploy
  umask 077
  if [ -n "${CLOUDFLARE_API_TOKEN:-}" ]; then
    cat > /etc/letsencrypt/cloudflare.ini <<EOF
dns_cloudflare_api_token = ${CLOUDFLARE_API_TOKEN}
EOF
  fi
  umask 022

  install_certbot_retry_service

  local issued="false"
  if [ -n "${CLOUDFLARE_API_TOKEN:-}" ] && [ -n "${LETSENCRYPT_EMAIL:-}" ]; then
    for attempt in 1 2 3; do
      cleanup_broken_certbot_lineage
      if LETSENCRYPT_DNS_PROPAGATION_SECONDS="${LETSENCRYPT_DNS_PROPAGATION_SECONDS:-60}" /usr/local/sbin/infrazero-certbot-certonly.sh; then
        issued="true"
        echo "[egress] Let's Encrypt cert issued for ${domains[*]}"
        break
      fi
      echo "[egress] Let's Encrypt issuance attempt ${attempt}/3 failed" >&2
      if [ "$attempt" -lt 3 ]; then
        sleep $((attempt * 30))
      fi
    done
  else
    echo "[egress] CLOUDFLARE_API_TOKEN or LETSENCRYPT_EMAIL missing; using self-signed fallback" >&2
  fi

  if [ "$issued" != "true" ]; then
    echo "[egress] Let's Encrypt unavailable; continuing with isolated self-signed fallback" >&2
    generate_self_signed_service_cert "${domains[0]}"
    systemctl enable --now infrazero-certbot-retry.timer || true
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

json_quote() {
  python3 -c 'import json, sys; print(json.dumps(sys.stdin.read()))'
}

append_promtail_drop_pipeline() {
  local config_file="$1"
  local indent="${2:-    }"
  local parse_stage="${3:-}"
  local filter_enabled="false"

  if [ "${LOKI_LOG_FILTER_ENABLED:-false}" = "true" ] && [ -n "${LOKI_LOG_DROP_REGEX:-}" ]; then
    filter_enabled="true"
  fi

  if [ -z "$parse_stage" ] && [ "$filter_enabled" != "true" ]; then
    return 0
  fi

  cat >> "$config_file" <<EOF
${indent}pipeline_stages:
EOF

  if [ -n "$parse_stage" ]; then
    cat >> "$config_file" <<EOF
${indent}  - ${parse_stage}: {}
EOF
  fi

  if [ "$filter_enabled" = "true" ]; then
    local quoted_regex
    quoted_regex=$(printf '%s' "$LOKI_LOG_DROP_REGEX" | json_quote)
    cat >> "$config_file" <<EOF
${indent}  - match:
${indent}      selector: '{container="infisical"}'
${indent}      stages:
${indent}        - drop:
${indent}            expression: ${quoted_regex}
EOF
  fi
}

install_egress_docker_promtail() {
  if [ "${LOKI_EGRESS_DOCKER_LOGS_ENABLED:-true}" != "true" ]; then
    systemctl disable --now promtail-egress-docker >/dev/null 2>&1 || true
    echo "[egress] egress Docker log shipping to Loki disabled"
    return 0
  fi

  if [ ! -x /usr/local/bin/promtail ]; then
    if curl -fsSL -o /tmp/promtail.zip "https://github.com/grafana/loki/releases/download/v2.9.3/promtail-linux-amd64.zip"; then
      unzip -o /tmp/promtail.zip -d /usr/local/bin
      mv /usr/local/bin/promtail-linux-amd64 /usr/local/bin/promtail
      chmod +x /usr/local/bin/promtail
    else
      echo "[egress] promtail download failed; skipping egress Docker log shipping" >&2
      return 0
    fi
  fi

  mkdir -p /etc/promtail /var/lib/promtail
  local config_file="/etc/promtail/egress-docker.yml"
  cat > "$config_file" <<EOF
server:
  http_listen_port: 9081
  grpc_listen_port: 0
positions:
  filename: /var/lib/promtail/egress-docker-positions.yaml
clients:
  - url: http://127.0.0.1:3100/loki/api/v1/push
    external_labels:
      host: ${HOSTNAME}
      role: egress
scrape_configs:
  - job_name: egress-docker
    docker_sd_configs:
      - host: unix:///var/run/docker.sock
        refresh_interval: 10s
EOF

  cat >> "$config_file" <<'EOF'
    relabel_configs:
      - source_labels: ['__meta_docker_container_label_com_docker_compose_service']
        target_label: 'container'
      - source_labels: ['__meta_docker_container_name']
        regex: '/(.*)'
        target_label: 'container_name'
      - source_labels: ['__meta_docker_container_log_stream']
        target_label: 'stream'
EOF

  append_promtail_drop_pipeline "$config_file" "    " "docker"

  cat > /etc/systemd/system/promtail-egress-docker.service <<'EOF'
[Unit]
Description=Promtail egress Docker log shipper
After=docker.service network-online.target
Wants=docker.service network-online.target

[Service]
ExecStart=/usr/local/bin/promtail -config.file=/etc/promtail/egress-docker.yml
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now promtail-egress-docker || echo "[egress] failed to start promtail-egress-docker; continuing"
}
