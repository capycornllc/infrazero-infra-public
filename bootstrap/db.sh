#!/usr/bin/env bash
set -euo pipefail

echo "[db] $(date -Is) start"

load_env() {
  local file="$1"
  if [ -f "$file" ]; then
    set -a
    # shellcheck disable=SC1090
    source "$file"
    set +a
  fi
}

load_env /etc/infrazero/db.env
load_env /etc/infrazero/network.env

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[db] missing required env: $name" >&2
    exit 1
  fi
}

require_env "DB_TYPE"
require_env "DB_VERSION"
require_env "APP_DB_NAME"
require_env "APP_DB_USER"
require_env "APP_DB_PASSWORD"
require_env "S3_ACCESS_KEY_ID"
require_env "S3_SECRET_ACCESS_KEY"
require_env "S3_ENDPOINT"
require_env "S3_REGION"
require_env "DB_BACKUP_BUCKET"
require_env "K3S_NODE_CIDRS"

db_type_lower=$(echo "$DB_TYPE" | tr '[:upper:]' '[:lower:]')
if [ "$db_type_lower" != "postgresql" ] && [ "$db_type_lower" != "postgres" ]; then
  echo "[db] unsupported DB_TYPE: $DB_TYPE (only postgresql supported)" >&2
  exit 1
fi

PG_MAJOR="${DB_VERSION%%.*}"
if [ -z "$PG_MAJOR" ]; then
  echo "[db] unable to parse DB_VERSION: $DB_VERSION" >&2
  exit 1
fi

if [[ "$S3_ENDPOINT" != http://* && "$S3_ENDPOINT" != https://* ]]; then
  S3_ENDPOINT="https://${S3_ENDPOINT}"
fi

export AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$S3_SECRET_ACCESS_KEY"
export AWS_DEFAULT_REGION="$S3_REGION"

install_packages() {
  if ! command -v apt-get >/dev/null 2>&1; then
    return
  fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y curl ca-certificates jq age unzip gnupg lsb-release rsync certbot python3-certbot-dns-cloudflare

  if ! apt-cache show "postgresql-${PG_MAJOR}" >/dev/null 2>&1; then
    echo "[db] enabling PGDG repo for PostgreSQL ${PG_MAJOR}"
    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/pgdg.gpg
    echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list
    apt-get update -y
  fi

  apt-get install -y "postgresql-${PG_MAJOR}" "postgresql-client-${PG_MAJOR}" "postgresql-contrib-${PG_MAJOR}"
}

install_packages

if ! command -v aws >/dev/null 2>&1; then
  if curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip; then
    unzip -q /tmp/awscliv2.zip -d /tmp
    /tmp/aws/install --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli --update
  fi
fi

if ! command -v aws >/dev/null 2>&1; then
  echo "[db] aws cli not available; cannot continue" >&2
  exit 1
fi

MOUNT_DIR="/mnt/db"
VOLUME_NAME="${DB_VOLUME_NAME:-}"
VOLUME_FORMAT="${DB_VOLUME_FORMAT:-ext4}"
DEVICE=""

if [ -n "$VOLUME_NAME" ] && [ -e "/dev/disk/by-id/scsi-0HC_Volume_${VOLUME_NAME}" ]; then
  DEVICE="/dev/disk/by-id/scsi-0HC_Volume_${VOLUME_NAME}"
else
  candidate=$(ls -1 /dev/disk/by-id/scsi-0HC_Volume_* 2>/dev/null | head -n 1 || true)
  if [ -n "$candidate" ]; then
    DEVICE="$candidate"
  else
    candidate=$(ls -1 /dev/disk/by-id/*Volume* 2>/dev/null | head -n 1 || true)
    if [ -n "$candidate" ]; then
      DEVICE="$candidate"
    fi
  fi
fi

if [ -z "$DEVICE" ]; then
  echo "[db] no attached volume device found; skipping mount" >&2
  exit 1
fi

mkdir -p "$MOUNT_DIR"

if ! blkid "$DEVICE" >/dev/null 2>&1; then
  echo "[db] formatting $DEVICE as $VOLUME_FORMAT"
  mkfs -t "$VOLUME_FORMAT" "$DEVICE"
fi

UUID=$(blkid -s UUID -o value "$DEVICE" || true)
if [ -z "$UUID" ]; then
  echo "[db] unable to determine UUID for $DEVICE" >&2
  exit 1
fi

if ! grep -q "$UUID" /etc/fstab; then
  echo "UUID=$UUID $MOUNT_DIR $VOLUME_FORMAT defaults,nofail 0 2" >> /etc/fstab
fi

if ! mountpoint -q "$MOUNT_DIR"; then
  mount "$MOUNT_DIR" || mount -a
fi

DATA_MOUNT="${MOUNT_DIR}/postgresql/${PG_MAJOR}/main"
DEFAULT_DATA_DIR="/var/lib/postgresql/${PG_MAJOR}/main"

systemctl stop postgresql || true

mkdir -p "$DATA_MOUNT" "$DEFAULT_DATA_DIR"
if [ -z "$(ls -A "$DATA_MOUNT" 2>/dev/null || true)" ] && [ -d "$DEFAULT_DATA_DIR" ]; then
  rsync -a "$DEFAULT_DATA_DIR/" "$DATA_MOUNT/" || true
fi

chown -R postgres:postgres "${MOUNT_DIR}/postgresql"

if ! mountpoint -q "$DEFAULT_DATA_DIR"; then
  if ! grep -q " ${DEFAULT_DATA_DIR} " /etc/fstab; then
    echo "${DATA_MOUNT} ${DEFAULT_DATA_DIR} none bind 0 0" >> /etc/fstab
  fi
  mount "$DEFAULT_DATA_DIR" || mount -a
fi

systemctl enable --now postgresql

PG_CONF="/etc/postgresql/${PG_MAJOR}/main/postgresql.conf"
HBA_CONF="/etc/postgresql/${PG_MAJOR}/main/pg_hba.conf"

set_conf() {
  local key="$1"
  local value="$2"
  if grep -qE "^[#\\s]*${key}\\s*=" "$PG_CONF"; then
    sed -i "s#^[#\\s]*${key}\\s*=.*#${key} = ${value}#g" "$PG_CONF"
  else
    echo "${key} = ${value}" >> "$PG_CONF"
  fi
}

set_conf "listen_addresses" "'*'"
set_conf "password_encryption" "'scram-sha-256'"

HBA_BEGIN="# BEGIN INFRAZERO"
HBA_END="# END INFRAZERO"

if [ -f "$HBA_CONF" ]; then
  awk -v begin="$HBA_BEGIN" -v end="$HBA_END" '
    $0==begin {skip=1; next}
    $0==end {skip=0; next}
    skip==1 {next}
    {print}
  ' "$HBA_CONF" > "${HBA_CONF}.tmp" && mv "${HBA_CONF}.tmp" "$HBA_CONF"
fi

{
  echo "$HBA_BEGIN"
  if [ -n "${K3S_NODE_CIDRS:-}" ]; then
    IFS=',' read -r -a cidrs <<< "$K3S_NODE_CIDRS"
    for cidr in "${cidrs[@]}"; do
      cidr=$(echo "$cidr" | xargs)
      if [ -n "$cidr" ]; then
        echo "host ${APP_DB_NAME} ${APP_DB_USER} ${cidr} scram-sha-256"
      fi
    done
  fi
  echo "$HBA_END"
} >> "$HBA_CONF"

systemctl restart postgresql

setup_db_tls() {
  local fqdn="${DB_FQDN:-}"
  if [ -z "$fqdn" ]; then
    return 0
  fi

  local cf_token="${CLOUDFLARE_API_TOKEN:-}"
  if [ -z "$cf_token" ]; then
    echo "[db] DB_FQDN set but CLOUDFLARE_API_TOKEN missing; skipping TLS setup" >&2
    return 0
  fi

  local le_email="${LETSENCRYPT_EMAIL:-${INFISICAL_EMAIL:-}}"
  if [ -z "$le_email" ]; then
    echo "[db] LETSENCRYPT_EMAIL or INFISICAL_EMAIL required for TLS" >&2
    return 1
  fi

  mkdir -p /etc/letsencrypt /etc/letsencrypt/renewal-hooks/deploy
  umask 077
  cat > /etc/letsencrypt/cloudflare.ini <<EOF
dns_cloudflare_api_token = ${cf_token}
EOF
  umask 022

  if certbot certonly --non-interactive --agree-tos --email "$le_email" \
    --dns-cloudflare --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
    --dns-cloudflare-propagation-seconds 30 \
    --cert-name infrazero-db --expand -d "$fqdn"; then
    echo "[db] Let's Encrypt cert issued for $fqdn"
  else
    echo "[db] Let's Encrypt issuance failed" >&2
    return 1
  fi

  local cert_dir="/etc/letsencrypt/live/infrazero-db"
  local pg_ssl_dir="/etc/postgresql/${PG_MAJOR}/main/ssl"
  mkdir -p "$pg_ssl_dir"
  cp "$cert_dir/fullchain.pem" "$pg_ssl_dir/server.crt"
  cp "$cert_dir/privkey.pem" "$pg_ssl_dir/server.key"
  chown postgres:postgres "$pg_ssl_dir/server.crt" "$pg_ssl_dir/server.key"
  chmod 644 "$pg_ssl_dir/server.crt"
  chmod 600 "$pg_ssl_dir/server.key"

  set_conf "ssl" "on"
  set_conf "ssl_cert_file" "'${pg_ssl_dir}/server.crt'"
  set_conf "ssl_key_file" "'${pg_ssl_dir}/server.key'"

  cat > /etc/letsencrypt/renewal-hooks/deploy/infrazero-postgres-reload.sh <<EOF
#!/usr/bin/env bash
set -euo pipefail
CERT_DIR="${cert_dir}"
PG_SSL_DIR="${pg_ssl_dir}"
cp "\${CERT_DIR}/fullchain.pem" "\${PG_SSL_DIR}/server.crt"
cp "\${CERT_DIR}/privkey.pem" "\${PG_SSL_DIR}/server.key"
chown postgres:postgres "\${PG_SSL_DIR}/server.crt" "\${PG_SSL_DIR}/server.key"
chmod 644 "\${PG_SSL_DIR}/server.crt"
chmod 600 "\${PG_SSL_DIR}/server.key"
systemctl reload postgresql
EOF
  chmod +x /etc/letsencrypt/renewal-hooks/deploy/infrazero-postgres-reload.sh

  systemctl restart postgresql
  systemctl enable --now certbot.timer || true
}

setup_db_tls || true

psql_as_postgres() {
  sudo -u postgres psql -v ON_ERROR_STOP=1 "$@"
}

user_exists=$(psql_as_postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='${APP_DB_USER}'" || true)
if [ "$user_exists" != "1" ]; then
  psql_as_postgres -v "pass=${APP_DB_PASSWORD}" -c "CREATE ROLE \"${APP_DB_USER}\" WITH LOGIN PASSWORD :'pass';"
else
  psql_as_postgres -v "pass=${APP_DB_PASSWORD}" -c "ALTER ROLE \"${APP_DB_USER}\" WITH PASSWORD :'pass';"
fi

db_exists=$(psql_as_postgres -tAc "SELECT 1 FROM pg_database WHERE datname='${APP_DB_NAME}'" || true)
if [ "$db_exists" != "1" ]; then
  psql_as_postgres -c "CREATE DATABASE \"${APP_DB_NAME}\" OWNER \"${APP_DB_USER}\";"
fi

psql_as_postgres -c "GRANT ALL PRIVILEGES ON DATABASE \"${APP_DB_NAME}\" TO \"${APP_DB_USER}\";"

restore_db() {
  if [ -z "${DB_BACKUP_AGE_PRIVATE_KEY:-}" ]; then
    echo "[db] DB_BACKUP_AGE_PRIVATE_KEY not set; skipping restore"
    return 0
  fi

  local tmpdir
  tmpdir=$(mktemp -d /run/infrazero-db-restore.XXXX)
  chmod 700 "$tmpdir"
  echo "$DB_BACKUP_AGE_PRIVATE_KEY" > "$tmpdir/age.key"
  chmod 600 "$tmpdir/age.key"

  local manifest_key="db/latest-dump.json"
  if ! aws --endpoint-url "$S3_ENDPOINT" s3 cp "s3://${DB_BACKUP_BUCKET}/${manifest_key}" "$tmpdir/latest-dump.json" >/dev/null 2>&1; then
    echo "[db] no latest-dump manifest found; skipping restore"
    rm -rf "$tmpdir"
    unset DB_BACKUP_AGE_PRIVATE_KEY
    return 0
  fi

  local key
  local sha
  key=$(jq -r '.key' "$tmpdir/latest-dump.json")
  sha=$(jq -r '.sha256' "$tmpdir/latest-dump.json")

  if [ -z "$key" ] || [ "$key" = "null" ]; then
    echo "[db] latest-dump manifest missing key" >&2
    rm -rf "$tmpdir"
    unset DB_BACKUP_AGE_PRIVATE_KEY
    return 1
  fi

  aws --endpoint-url "$S3_ENDPOINT" s3 cp "s3://${DB_BACKUP_BUCKET}/${key}" "$tmpdir/dump.age"
  echo "$sha  $tmpdir/dump.age" | sha256sum -c -

  age -d -i "$tmpdir/age.key" -o "$tmpdir/dump.sql.gz" "$tmpdir/dump.age"
  gunzip -c "$tmpdir/dump.sql.gz" | sudo -u postgres psql -d "$APP_DB_NAME"

  rm -rf "$tmpdir"
  unset DB_BACKUP_AGE_PRIVATE_KEY
  echo "[db] restore complete"
}

restore_db

mkdir -p /opt/infrazero/db /opt/infrazero/db/backups

cat > /opt/infrazero/db/backup.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/etc/infrazero/db.env"
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

export AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$S3_SECRET_ACCESS_KEY"
export AWS_DEFAULT_REGION="$S3_REGION"

if [[ "$S3_ENDPOINT" != http://* && "$S3_ENDPOINT" != https://* ]]; then
  S3_ENDPOINT="https://${S3_ENDPOINT}"
fi

TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
WORKDIR="/opt/infrazero/db/backups"
mkdir -p "$WORKDIR"

DUMP_PATH="$WORKDIR/db-${TIMESTAMP}.sql.gz"
ENC_PATH="$DUMP_PATH.age"

sudo -u postgres pg_dump -d "$APP_DB_NAME" | gzip > "$DUMP_PATH"

age -r "$DB_BACKUP_AGE_PUBLIC_KEY" -o "$ENC_PATH" "$DUMP_PATH"
SHA=$(sha256sum "$ENC_PATH" | awk '{print $1}')
KEY="db/${TIMESTAMP}.sql.gz.age"

aws --endpoint-url "$S3_ENDPOINT" s3 cp "$ENC_PATH" "s3://${DB_BACKUP_BUCKET}/${KEY}"

jq -n --arg key "$KEY" --arg sha "$SHA" --arg created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{key:$key, sha256:$sha, created_at:$created_at}' > "$WORKDIR/latest-dump.json"
aws --endpoint-url "$S3_ENDPOINT" s3 cp "$WORKDIR/latest-dump.json" "s3://${DB_BACKUP_BUCKET}/db/latest-dump.json"

rm -f "$DUMP_PATH" "$ENC_PATH"
EOF

chmod +x /opt/infrazero/db/backup.sh

cat > /opt/infrazero/db/restore.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/etc/infrazero/db.env"
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[db-restore] missing required env: $name" >&2
    exit 1
  fi
}

require_env "APP_DB_NAME"
require_env "APP_DB_USER"
require_env "APP_DB_PASSWORD"
require_env "S3_ACCESS_KEY_ID"
require_env "S3_SECRET_ACCESS_KEY"
require_env "S3_ENDPOINT"
require_env "S3_REGION"
require_env "DB_BACKUP_BUCKET"

if ! command -v aws >/dev/null 2>&1; then
  echo "[db-restore] aws cli not available" >&2
  exit 1
fi

backup_key="${1:-}"
if [ -z "$backup_key" ]; then
  echo "Usage: $0 <s3-key-or-s3-url>" >&2
  echo "Example: $0 db/20260201T120000Z.sql.gz.age" >&2
  exit 1
fi

if [[ "$S3_ENDPOINT" != http://* && "$S3_ENDPOINT" != https://* ]]; then
  S3_ENDPOINT="https://${S3_ENDPOINT}"
fi

export AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$S3_SECRET_ACCESS_KEY"
export AWS_DEFAULT_REGION="$S3_REGION"

tmpdir=$(mktemp -d /run/infrazero-db-restore.XXXX)
chmod 700 "$tmpdir"
src_path="$tmpdir/dump.src"
dump_path="$tmpdir/dump.sql"
age_key="$tmpdir/age.key"

if [[ "$backup_key" == s3://* ]]; then
  s3_url="$backup_key"
else
  s3_url="s3://${DB_BACKUP_BUCKET}/${backup_key}"
fi

echo "[db-restore] downloading ${s3_url}"
aws --endpoint-url "$S3_ENDPOINT" s3 cp "$s3_url" "$src_path"

try_decrypt() {
  local key_value="$1"
  printf '%s' "$key_value" > "$age_key"
  chmod 600 "$age_key"
  if age -d -i "$age_key" -o "$dump_path" "$src_path"; then
    return 0
  fi
  return 1
}

is_age_encrypted="false"
if head -c 24 "$src_path" 2>/dev/null | grep -q "age-encryption.org/v1"; then
  is_age_encrypted="true"
fi

detect_gzip() {
  local path="$1"
  if ! command -v od >/dev/null 2>&1; then
    return 1
  fi
  local magic
  magic=$(od -An -t x1 -N 2 "$path" 2>/dev/null | tr -d ' \n')
  if [ "$magic" = "1f8b" ]; then
    return 0
  fi
  return 1
}

is_gzip="false"
if detect_gzip "$src_path"; then
  is_gzip="true"
fi

if [ "$is_age_encrypted" = "true" ]; then
  if ! command -v age >/dev/null 2>&1; then
    echo "[db-restore] age not available for encrypted backup" >&2
    rm -rf "$tmpdir"
    exit 1
  fi
  if [ -n "${DB_BACKUP_AGE_PRIVATE_KEY:-}" ]; then
    if ! try_decrypt "$DB_BACKUP_AGE_PRIVATE_KEY"; then
      echo "[db-restore] decryption failed with DB_BACKUP_AGE_PRIVATE_KEY"
    fi
  fi

  if [ ! -s "$dump_path" ]; then
    echo "[db-restore] enter Age private key to decrypt backup:"
    read -r -s input_key
    echo
    if ! try_decrypt "$input_key"; then
      echo "[db-restore] decryption failed" >&2
      rm -rf "$tmpdir"
      exit 1
    fi
  fi
  if detect_gzip "$dump_path"; then
    is_gzip="true"
  else
    is_gzip="false"
  fi
else
  dump_path="$src_path"
fi

echo "[db-restore] wiping database ${APP_DB_NAME}"
sudo -u postgres psql -v ON_ERROR_STOP=1 -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${APP_DB_NAME}';"
sudo -u postgres psql -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS \"${APP_DB_NAME}\";"
sudo -u postgres psql -v ON_ERROR_STOP=1 -c "CREATE DATABASE \"${APP_DB_NAME}\" OWNER \"${APP_DB_USER}\";"

echo "[db-restore] restoring database"
if [ "$is_gzip" = "true" ]; then
  gunzip -c "$dump_path" | sudo -u postgres psql -v ON_ERROR_STOP=1 -d "$APP_DB_NAME"
else
  cat "$dump_path" | sudo -u postgres psql -v ON_ERROR_STOP=1 -d "$APP_DB_NAME"
fi

rm -rf "$tmpdir"
unset DB_BACKUP_AGE_PRIVATE_KEY
echo "[db-restore] restore complete"
EOF

chmod +x /opt/infrazero/db/restore.sh

cat > /etc/cron.d/infrazero-db-backup <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

20 3 * * * root /opt/infrazero/db/backup.sh >> /var/log/infrazero-db-backup.log 2>&1
EOF

chmod 0644 /etc/cron.d/infrazero-db-backup

echo "[db] $(date -Is) complete"
