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
require_env "DB_BACKUP_AGE_PUBLIC_KEY"
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
  apt-get install -y docker.io docker-compose age jq iptables unzip openssl
fi

systemctl enable --now docker

if ! command -v aws >/dev/null 2>&1; then
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
  unzip -q /tmp/awscliv2.zip -d /tmp
  /tmp/aws/install --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli --update
fi

compose_cmd() {
  if command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    docker compose "$@"
  fi
}

mkdir -p /opt/infrazero/egress /opt/infrazero/infisical /opt/infrazero/infisical/backups /opt/infrazero/infisical/certs

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

# NAT/egress setup
cat > /etc/sysctl.d/99-infrazero-forward.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
sysctl --system

PUBLIC_IF=$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
PRIVATE_IF=$(ip -4 -o addr show | awk -v pub="$PUBLIC_IF" '$2 != pub && $2 != "lo" {print $2; exit}')

if [ -z "$PUBLIC_IF" ] || [ -z "$PRIVATE_IF" ]; then
  echo "[egress] unable to determine network interfaces" >&2
  exit 1
fi

PRIVATE_IP=$(ip -4 -o addr show dev "$PRIVATE_IF" | awk '{split($4, parts, "/"); print parts[1]; exit}')
if [ -z "$PRIVATE_IP" ]; then
  echo "[egress] unable to determine private ip address" >&2
  exit 1
fi

iptables -t nat -A POSTROUTING -s "$PRIVATE_CIDR" -o "$PUBLIC_IF" -j MASQUERADE
iptables -A FORWARD -i "$PRIVATE_IF" -o "$PUBLIC_IF" -s "$PRIVATE_CIDR" -j ACCEPT
iptables -A FORWARD -i "$PUBLIC_IF" -o "$PRIVATE_IF" -d "$PRIVATE_CIDR" -m state --state RELATED,ESTABLISHED -j ACCEPT

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

# Infisical + Postgres + Redis
INFISICAL_CERT_IP=${INFISICAL_CERT_IP:-"$PRIVATE_IP"}
INFISICAL_BIND_ADDR=${INFISICAL_BIND_ADDR:-"$PRIVATE_IP"}
INFISICAL_SITE_URL=${INFISICAL_SITE_URL:-"https://${INFISICAL_CERT_IP}:8080"}
if [ -n "${INFISICAL_SITE_URL:-}" ] && [[ "$INFISICAL_SITE_URL" != https://* ]]; then
  echo "[egress] INFISICAL_SITE_URL must be https; overriding to https://${INFISICAL_CERT_IP}:8080"
  INFISICAL_SITE_URL="https://${INFISICAL_CERT_IP}:8080"
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

INFISICAL_CERTS_DIR="/opt/infrazero/infisical/certs"
INFISICAL_CA_CERT="${INFISICAL_CERTS_DIR}/ca.crt"
INFISICAL_CA_KEY="${INFISICAL_CERTS_DIR}/ca.key"
INFISICAL_SERVER_CERT="${INFISICAL_CERTS_DIR}/infisical.crt"
INFISICAL_SERVER_KEY="${INFISICAL_CERTS_DIR}/infisical.key"
INFISICAL_OPENSSL_CONF="${INFISICAL_CERTS_DIR}/openssl.cnf"

setup_infisical_tls() {
  mkdir -p "$INFISICAL_CERTS_DIR"
  chmod 700 "$INFISICAL_CERTS_DIR"

  if [ ! -f "$INFISICAL_CA_CERT" ] || [ ! -f "$INFISICAL_CA_KEY" ]; then
    echo "[egress] generating infisical CA"
    openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
      -subj "/CN=Infisical Local CA" \
      -keyout "$INFISICAL_CA_KEY" \
      -out "$INFISICAL_CA_CERT"
    chmod 600 "$INFISICAL_CA_KEY"
    chmod 644 "$INFISICAL_CA_CERT"
  else
    echo "[egress] infisical CA already present"
  fi

  if [ ! -f "$INFISICAL_SERVER_CERT" ] || [ ! -f "$INFISICAL_SERVER_KEY" ]; then
    echo "[egress] generating infisical TLS cert for ${INFISICAL_CERT_IP}"
    cat > "$INFISICAL_OPENSSL_CONF" <<EOF
[req]
distinguished_name=req_distinguished_name
req_extensions=v3_req
prompt=no

[req_distinguished_name]
CN=infisical

[v3_req]
keyUsage=keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=@alt_names

[alt_names]
IP.1=${INFISICAL_CERT_IP}
EOF
    openssl req -new -newkey rsa:4096 -nodes \
      -keyout "$INFISICAL_SERVER_KEY" \
      -out "${INFISICAL_CERTS_DIR}/infisical.csr" \
      -config "$INFISICAL_OPENSSL_CONF"
    openssl x509 -req \
      -in "${INFISICAL_CERTS_DIR}/infisical.csr" \
      -CA "$INFISICAL_CA_CERT" \
      -CAkey "$INFISICAL_CA_KEY" \
      -CAcreateserial \
      -out "$INFISICAL_SERVER_CERT" \
      -days 825 \
      -extensions v3_req \
      -extfile "$INFISICAL_OPENSSL_CONF"
    rm -f "${INFISICAL_CERTS_DIR}/infisical.csr"
    chmod 600 "$INFISICAL_SERVER_KEY"
    chmod 644 "$INFISICAL_SERVER_CERT"
  else
    echo "[egress] infisical TLS cert already present"
  fi

  if [ -d /usr/local/share/ca-certificates ]; then
    cp "$INFISICAL_CA_CERT" /usr/local/share/ca-certificates/infisical-local-ca.crt
    update-ca-certificates >/dev/null 2>&1 || true
  fi

  echo "[egress] infisical CA cert at ${INFISICAL_CA_CERT}"
  echo "[egress] import this CA cert into your client trust store to avoid browser warnings"
}

setup_infisical_tls

cat > /opt/infrazero/infisical/nginx.conf <<'EOF'
server {
  listen 8080 ssl;
  server_name _;

  ssl_certificate /etc/nginx/certs/infisical.crt;
  ssl_certificate_key /etc/nginx/certs/infisical.key;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers HIGH:!aNULL:!MD5;

  location / {
    proxy_pass http://infisical:8080;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
  }
}
EOF

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
  infisical-proxy:
    image: nginx:1.25-alpine
    restart: unless-stopped
    depends_on:
      - infisical
    ports:
      - "${INFISICAL_BIND_ADDR}:8080:8080"
    volumes:
      - /opt/infrazero/infisical/nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - /opt/infrazero/infisical/certs:/etc/nginx/certs:ro
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

restore_infisical() {
  local tmpdir
  tmpdir=$(mktemp -d /run/infrazero-restore.XXXX)
  chmod 700 "$tmpdir"
  if [ -z "${DB_BACKUP_AGE_PRIVATE_KEY:-}" ]; then
    echo "[egress] no age private key set; skipping restore"
    rm -rf "$tmpdir"
    return 0
  fi

  echo "$DB_BACKUP_AGE_PRIVATE_KEY" > "$tmpdir/age.key"
  chmod 600 "$tmpdir/age.key"

  if ! aws --endpoint-url "$S3_ENDPOINT" s3 cp "s3://${DB_BACKUP_BUCKET}/infisical/latest-dump.json" "$tmpdir/latest-dump.json" >/dev/null 2>&1; then
    echo "[egress] no latest-dump manifest found; skipping restore"
    rm -f "$tmpdir/age.key"
    rm -rf "$tmpdir"
    unset DB_BACKUP_AGE_PRIVATE_KEY
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
    unset DB_BACKUP_AGE_PRIVATE_KEY
    return 1
  fi

  aws --endpoint-url "$S3_ENDPOINT" s3 cp "s3://${DB_BACKUP_BUCKET}/${key}" "$tmpdir/dump.age"
  echo "$sha  $tmpdir/dump.age" | sha256sum -c -

  age -d -i "$tmpdir/age.key" -o "$tmpdir/dump.sql.gz" "$tmpdir/dump.age"
  gunzip -c "$tmpdir/dump.sql.gz" | compose_cmd -f /opt/infrazero/infisical/docker-compose.yml exec -T infisical-db psql -U "$INFISICAL_POSTGRES_USER" -d "$INFISICAL_POSTGRES_DB"

  rm -f "$tmpdir/age.key"
  rm -rf "$tmpdir"
  unset DB_BACKUP_AGE_PRIVATE_KEY
  echo "[egress] restore complete"
}

if [ "${INFISICAL_RESTORE_FROM_S3,,}" = "true" ]; then
  echo "[egress] infisical_restore_from_s3=true; attempting restore"
  restore_infisical
else
  echo "[egress] infisical_restore_from_s3 not true; skipping restore"
fi

compose_cmd -f /opt/infrazero/infisical/docker-compose.yml up -d infisical infisical-proxy

echo "[egress] infisical https enabled at ${INFISICAL_SITE_URL}"
echo "[egress] infisical bootstrap deferred to node1"

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

age -r "$DB_BACKUP_AGE_PUBLIC_KEY" -o "$ENC_PATH" "$DUMP_PATH"
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
