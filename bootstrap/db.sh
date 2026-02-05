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
  apt-get install -y curl ca-certificates jq age unzip gnupg lsb-release rsync certbot python3-certbot-dns-cloudflare zstd

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

systemctl stop postgresql || true
systemctl stop "postgresql@${PG_MAJOR}-main" || true

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

mkdir -p "$DATA_MOUNT" "$DEFAULT_DATA_DIR"

chown -R postgres:postgres "${MOUNT_DIR}/postgresql" || true

is_data_dir_empty() {
  if [ ! -d "$DATA_MOUNT" ]; then
    return 0
  fi
  local entry
  entry=$(find "$DATA_MOUNT" -mindepth 1 -maxdepth 1 ! -name "lost+found" -print -quit 2>/dev/null || true)
  if [ -z "$entry" ]; then
    return 0
  fi
  return 1
}

existing_pg_version=""
if [ -f "$DATA_MOUNT/PG_VERSION" ]; then
  existing_pg_version=$(tr -d '\r\n' < "$DATA_MOUNT/PG_VERSION" || true)
fi

if [ -n "$existing_pg_version" ] && [ "$existing_pg_version" != "$PG_MAJOR" ]; then
  echo "[db] volume PG_VERSION $existing_pg_version does not match expected $PG_MAJOR" >&2
  exit 1
fi

data_empty="false"
if is_data_dir_empty; then
  data_empty="true"
fi

drop_stale_cluster_config() {
  local conf_dir="/etc/postgresql/${PG_MAJOR}/main"
  if [ -d "$conf_dir" ]; then
    echo "[db] removing stale PostgreSQL cluster config at $conf_dir"
    if command -v pg_dropcluster >/dev/null 2>&1; then
      if ! pg_dropcluster --stop "$PG_MAJOR" main >/dev/null 2>&1; then
        echo "[db] pg_dropcluster failed; removing config directory manually" >&2
      fi
    fi
    rm -rf "$conf_dir"
  fi

  if ! mountpoint -q "$DEFAULT_DATA_DIR"; then
    rm -rf "$DEFAULT_DATA_DIR"
  fi
}

ensure_bind_mount() {
  mkdir -p "$DEFAULT_DATA_DIR"
  if ! mountpoint -q "$DEFAULT_DATA_DIR"; then
    if ! grep -q " ${DEFAULT_DATA_DIR} " /etc/fstab; then
      echo "${DATA_MOUNT} ${DEFAULT_DATA_DIR} none bind 0 0" >> /etc/fstab
      systemctl daemon-reload || true
    fi
    mount "$DEFAULT_DATA_DIR" || mount -a
  fi
}

if [ -z "$existing_pg_version" ] && [ "$data_empty" = "true" ]; then
  drop_stale_cluster_config
fi

ensure_bind_mount

if [ -n "$existing_pg_version" ]; then
  echo "[db] existing PostgreSQL data directory detected on volume; reusing"
else
  if [ "$data_empty" != "true" ]; then
    echo "[db] data directory not empty but PG_VERSION missing; refusing to initialize" >&2
    exit 1
  fi

  if command -v pg_dropcluster >/dev/null 2>&1; then
    pg_dropcluster --stop "$PG_MAJOR" main >/dev/null 2>&1 || true
  fi

  if command -v pg_createcluster >/dev/null 2>&1; then
    pg_createcluster "$PG_MAJOR" main -d "$DEFAULT_DATA_DIR"
  else
    initdb="/usr/lib/postgresql/${PG_MAJOR}/bin/initdb"
    if [ -x "$initdb" ]; then
      sudo -u postgres "$initdb" -D "$DEFAULT_DATA_DIR"
    else
      echo "[db] initdb not available to create new cluster" >&2
      exit 1
    fi
  fi
fi

systemctl enable --now postgresql

start_cluster() {
  if command -v pg_ctlcluster >/dev/null 2>&1; then
    pg_ctlcluster "$PG_MAJOR" main start || true
    return 0
  fi
  systemctl start "postgresql@${PG_MAJOR}-main" || true
}

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
  if [ -n "${WG_CIDR:-}" ]; then
    echo "host ${APP_DB_NAME} ${APP_DB_USER} ${WG_CIDR} scram-sha-256"
  fi
  echo "$HBA_END"
} >> "$HBA_CONF"

systemctl restart postgresql

wait_for_postgres() {
  for _ in {1..30}; do
    if sudo -u postgres pg_isready -q >/dev/null 2>&1; then
      return 0
    fi
    if systemctl is-active --quiet "postgresql@${PG_MAJOR}-main"; then
      sleep 2
    else
      start_cluster
      sleep 2
    fi
  done
  systemctl status --no-pager postgresql || true
  systemctl status --no-pager "postgresql@${PG_MAJOR}-main" || true
  journalctl -u postgresql -n 50 --no-pager || true
  journalctl -u "postgresql@${PG_MAJOR}-main" -n 50 --no-pager || true
  return 1
}

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

if ! wait_for_postgres; then
  echo "[db] postgresql did not become ready" >&2
  exit 1
fi

psql_as_postgres() {
  sudo -u postgres psql -v ON_ERROR_STOP=1 "$@"
}

sql_escape() {
  printf '%s' "$1" | sed "s/'/''/g"
}

user_exists=$(psql_as_postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='${APP_DB_USER}'" || true)
escaped_app_db_password=$(sql_escape "$APP_DB_PASSWORD")
if [ "$user_exists" != "1" ]; then
  psql_as_postgres -c "CREATE ROLE \"${APP_DB_USER}\" WITH LOGIN PASSWORD '${escaped_app_db_password}';"
else
  psql_as_postgres -c "ALTER ROLE \"${APP_DB_USER}\" WITH PASSWORD '${escaped_app_db_password}';"
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
    echo "[db-restore] missing required env: $name" >&2
    exit 1
  fi
}

require_env "APP_DB_NAME"
require_env "APP_DB_USER"
require_env "APP_DB_PASSWORD"
require_env "DB_VERSION"
require_env "S3_ACCESS_KEY_ID"
require_env "S3_SECRET_ACCESS_KEY"
require_env "S3_ENDPOINT"
require_env "S3_REGION"
require_env "DB_BACKUP_BUCKET"

if ! command -v aws >/dev/null 2>&1; then
  echo "[db-restore] aws cli not available" >&2
  exit 1
fi

format_volume="true"
force_format="${DB_RESTORE_FORCE_FORMAT:-}"
args=()
for arg in "$@"; do
  case "$arg" in
    --no-format)
      format_volume="false"
      ;;
    --format)
      format_volume="true"
      ;;
    --force-format)
      force_format="true"
      ;;
    *)
      args+=("$arg")
      ;;
  esac
done

backup_key="${args[0]:-}"
if [ -z "$backup_key" ]; then
  echo "Usage: $0 [--no-format|--format] [--force-format] <s3-key-or-s3-url>" >&2
  echo "Example: $0 --no-format db/20260201T120000Z.sql.gz.age" >&2
  exit 1
fi

if [[ "$S3_ENDPOINT" != http://* && "$S3_ENDPOINT" != https://* ]]; then
  S3_ENDPOINT="https://${S3_ENDPOINT}"
fi

export AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$S3_SECRET_ACCESS_KEY"
export AWS_DEFAULT_REGION="$S3_REGION"

PG_MAJOR="${DB_VERSION%%.*}"
if [ -z "$PG_MAJOR" ]; then
  echo "[db-restore] unable to parse DB_VERSION: $DB_VERSION" >&2
  exit 1
fi

MOUNT_DIR="/mnt/db"
VOLUME_NAME="${DB_VOLUME_NAME:-}"
VOLUME_FORMAT="${DB_VOLUME_FORMAT:-ext4}"
DATA_MOUNT="${MOUNT_DIR}/postgresql/${PG_MAJOR}/main"
DEFAULT_DATA_DIR="/var/lib/postgresql/${PG_MAJOR}/main"
PG_CONF="/etc/postgresql/${PG_MAJOR}/main/postgresql.conf"
HBA_CONF="/etc/postgresql/${PG_MAJOR}/main/pg_hba.conf"

sql_literal() {
  printf '%s' "$1" | sed "s/'/''/g"
}

sql_ident() {
  printf '%s' "$1" | sed 's/"/""/g'
}

ensure_app_role() {
  local role_lit
  local role_ident
  local pw_lit
  role_lit=$(sql_literal "$APP_DB_USER")
  role_ident=$(sql_ident "$APP_DB_USER")
  pw_lit=$(sql_literal "$APP_DB_PASSWORD")

  sudo -u postgres psql -v ON_ERROR_STOP=1 -c "DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='${role_lit}') THEN CREATE ROLE \"${role_ident}\" WITH LOGIN PASSWORD '${pw_lit}'; ELSE ALTER ROLE \"${role_ident}\" WITH LOGIN PASSWORD '${pw_lit}'; END IF; END \$\$;"
}

find_volume_device() {
  local device=""
  if [ -n "$VOLUME_NAME" ] && [ -e "/dev/disk/by-id/scsi-0HC_Volume_${VOLUME_NAME}" ]; then
    device="/dev/disk/by-id/scsi-0HC_Volume_${VOLUME_NAME}"
  else
    device=$(ls -1 /dev/disk/by-id/scsi-0HC_Volume_* 2>/dev/null | head -n 1 || true)
    if [ -z "$device" ]; then
      device=$(ls -1 /dev/disk/by-id/*Volume* 2>/dev/null | head -n 1 || true)
    fi
  fi
  if [ -z "$device" ]; then
    echo "[db-restore] no attached volume device found" >&2
    exit 1
  fi
  echo "$device"
}

drop_stale_cluster_config() {
  local conf_dir="/etc/postgresql/${PG_MAJOR}/main"
  if [ -d "$conf_dir" ]; then
    echo "[db-restore] removing stale PostgreSQL cluster config at $conf_dir"
    if command -v pg_dropcluster >/dev/null 2>&1; then
      if ! pg_dropcluster --stop "$PG_MAJOR" main >/dev/null 2>&1; then
        echo "[db-restore] pg_dropcluster failed; removing config directory manually" >&2
      fi
    fi
    rm -rf "$conf_dir"
  fi

  if ! mountpoint -q "$DEFAULT_DATA_DIR"; then
    rm -rf "$DEFAULT_DATA_DIR"
  fi
}

ensure_bind_mount() {
  mkdir -p "$DEFAULT_DATA_DIR"
  if ! mountpoint -q "$DEFAULT_DATA_DIR"; then
    if ! grep -q " ${DEFAULT_DATA_DIR} " /etc/fstab; then
      echo "${DATA_MOUNT} ${DEFAULT_DATA_DIR} none bind 0 0" >> /etc/fstab
      systemctl daemon-reload || true
    fi
    mount "$DEFAULT_DATA_DIR" || mount -a
  fi
}

set_conf() {
  local key="$1"
  local value="$2"
  if [ ! -f "$PG_CONF" ]; then
    return 0
  fi
  if grep -qE "^[#\\s]*${key}\\s*=" "$PG_CONF"; then
    sed -i "s#^[#\\s]*${key}\\s*=.*#${key} = ${value}#g" "$PG_CONF"
  else
    echo "${key} = ${value}" >> "$PG_CONF"
  fi
}

apply_infrazero_hba() {
  if [ ! -f "$HBA_CONF" ]; then
    return 0
  fi

  if [ -z "${K3S_NODE_CIDRS:-}" ] && [ -z "${WG_CIDR:-}" ]; then
    echo "[db-restore] warning: K3S_NODE_CIDRS and WG_CIDR are empty; HBA block will be empty" >&2
  fi

  local hba_begin="# BEGIN INFRAZERO"
  local hba_end="# END INFRAZERO"

  awk -v begin="$hba_begin" -v end="$hba_end" '
    $0==begin {skip=1; next}
    $0==end {skip=0; next}
    skip==1 {next}
    {print}
  ' "$HBA_CONF" > "${HBA_CONF}.tmp" && mv "${HBA_CONF}.tmp" "$HBA_CONF"

  {
    echo "$hba_begin"
    if [ -n "${K3S_NODE_CIDRS:-}" ]; then
      IFS=',' read -r -a cidrs <<< "$K3S_NODE_CIDRS"
      for cidr in "${cidrs[@]}"; do
        cidr=$(echo "$cidr" | xargs)
        if [ -n "$cidr" ]; then
          echo "host ${APP_DB_NAME} ${APP_DB_USER} ${cidr} scram-sha-256"
        fi
      done
    fi
    if [ -n "${WG_CIDR:-}" ]; then
      echo "host ${APP_DB_NAME} ${APP_DB_USER} ${WG_CIDR} scram-sha-256"
    fi
    echo "$hba_end"
  } >> "$HBA_CONF"
}

apply_postgres_config() {
  set_conf "listen_addresses" "'*'"
  set_conf "password_encryption" "'scram-sha-256'"
  apply_infrazero_hba

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet postgresql 2>/dev/null; then
      systemctl reload postgresql || systemctl restart postgresql || true
    fi
  fi
}

format_and_reinit() {
  local device
  device=$(find_volume_device)

  echo "[db-restore] WARNING: this will format ${device} and erase all data on the DB volume."
  if [ "$force_format" != "true" ]; then
    if [ ! -t 0 ]; then
      echo "[db-restore] stdin is not a TTY; set DB_RESTORE_FORCE_FORMAT=true or pass --force-format" >&2
      exit 1
    fi
    read -r -p "[db-restore] Type FORMAT to continue: " confirm
    if [ "$confirm" != "FORMAT" ]; then
      echo "[db-restore] aborting"
      exit 1
    fi
  fi

  systemctl stop postgresql || true
  systemctl stop "postgresql@${PG_MAJOR}-main" || true
  umount "$DEFAULT_DATA_DIR" 2>/dev/null || true
  umount "$MOUNT_DIR" 2>/dev/null || true

  mkfs -t "$VOLUME_FORMAT" -F "$device"

  local uuid
  uuid=$(blkid -s UUID -o value "$device" || true)
  if [ -z "$uuid" ]; then
    echo "[db-restore] unable to determine UUID for ${device}" >&2
    exit 1
  fi

  mkdir -p "$MOUNT_DIR"
  if [ -f /etc/fstab ]; then
    awk -v mnt="$MOUNT_DIR" -v bind="$DEFAULT_DATA_DIR" '!(($2==mnt)||($2==bind))' /etc/fstab > /etc/fstab.tmp && mv /etc/fstab.tmp /etc/fstab
  fi
  echo "UUID=$uuid $MOUNT_DIR $VOLUME_FORMAT defaults,nofail 0 2" >> /etc/fstab
  systemctl daemon-reload || true
  mount "$MOUNT_DIR" || mount -a

  mkdir -p "$DATA_MOUNT" "$DEFAULT_DATA_DIR"
  chown -R postgres:postgres "${MOUNT_DIR}/postgresql" || true

  drop_stale_cluster_config
  ensure_bind_mount

  if command -v pg_createcluster >/dev/null 2>&1; then
    pg_createcluster "$PG_MAJOR" main -d "$DEFAULT_DATA_DIR"
  else
    initdb="/usr/lib/postgresql/${PG_MAJOR}/bin/initdb"
    if [ -x "$initdb" ]; then
      sudo -u postgres "$initdb" -D "$DEFAULT_DATA_DIR"
    else
      echo "[db-restore] initdb not available to create new cluster" >&2
      exit 1
    fi
  fi

  systemctl start postgresql || true
}

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

detect_zstd() {
  local path="$1"
  if ! command -v od >/dev/null 2>&1; then
    return 1
  fi
  local magic
  magic=$(od -An -t x1 -N 4 "$path" 2>/dev/null | tr -d ' \n')
  if [ "$magic" = "28b52ffd" ]; then
    return 0
  fi
  return 1
}

detect_pg_dump() {
  local path="$1"
  if head -c 5 "$path" 2>/dev/null | grep -q "PGDMP"; then
    return 0
  fi
  return 1
}

is_gzip="false"
if detect_gzip "$src_path"; then
  is_gzip="true"
fi

is_zstd="false"
if detect_zstd "$src_path"; then
  is_zstd="true"
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
  fi
  if detect_zstd "$dump_path"; then
    is_zstd="true"
  fi
else
  dump_path="$src_path"
fi

restore_source="$dump_path"
if [ "$is_gzip" = "true" ] || [ "$is_zstd" = "true" ]; then
  restore_source="$dump_path"
fi

stream_cmd=()
if [ "$is_gzip" = "true" ]; then
  stream_cmd=(gunzip -c "$restore_source")
elif [ "$is_zstd" = "true" ]; then
  if ! command -v zstd >/dev/null 2>&1; then
    echo "[db-restore] zstd not available for .zst backup" >&2
    rm -rf "$tmpdir"
    exit 1
  fi
  stream_cmd=(zstd -d -q --stdout "$restore_source")
else
  stream_cmd=(cat "$restore_source")
fi

is_custom="false"
if [ "$is_gzip" = "true" ]; then
  header=$(gunzip -c "$restore_source" 2>/dev/null | head -c 5 || true)
  if [ "$header" = "PGDMP" ]; then
    is_custom="true"
  fi
elif [ "$is_zstd" = "true" ]; then
  header=$(zstd -d -q --stdout "$restore_source" 2>/dev/null | head -c 5 || true)
  if [ "$header" = "PGDMP" ]; then
    is_custom="true"
  fi
else
  if detect_pg_dump "$restore_source"; then
    is_custom="true"
  fi
fi

  if [ "$format_volume" = "true" ]; then
    format_and_reinit
  fi

  apply_postgres_config

  ensure_app_role

echo "[db-restore] wiping database ${APP_DB_NAME}"
sudo -u postgres -H psql -v ON_ERROR_STOP=1 -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${APP_DB_NAME}';"
sudo -u postgres -H psql -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS \"${APP_DB_NAME}\";"
sudo -u postgres -H psql -v ON_ERROR_STOP=1 -c "CREATE DATABASE \"${APP_DB_NAME}\" OWNER \"${APP_DB_USER}\";"

role_map="${DB_RESTORE_ROLE_MAP:-}"
skip_acl="${DB_RESTORE_SKIP_ACL:-}"
drop_mapped="${DB_RESTORE_DROP_MAPPED_ROLES:-true}"
if [ -z "$skip_acl" ]; then
  if [ -n "$role_map" ]; then
    skip_acl="false"
  else
    skip_acl="true"
  fi
fi

declare -a mapped_old=()
declare -a mapped_new=()
if [ -n "$role_map" ]; then
  IFS=',' read -r -a pairs <<< "$role_map"
  for pair in "${pairs[@]}"; do
    pair=$(echo "$pair" | xargs)
    if [ -z "$pair" ]; then
      continue
    fi
    old="${pair%%:*}"
    new="${pair#*:}"
    if [ -z "$old" ] || [ -z "$new" ]; then
      echo "[db-restore] invalid DB_RESTORE_ROLE_MAP entry: ${pair}" >&2
      exit 1
    fi
    mapped_old+=("$old")
    mapped_new+=("$new")

    old_lit=$(sql_literal "$old")
    old_ident=$(sql_ident "$old")
    sudo -u postgres -H psql -v ON_ERROR_STOP=1 -c "DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='${old_lit}') THEN CREATE ROLE \"${old_ident}\" NOLOGIN; END IF; END \$\$;"
  done
fi

echo "[db-restore] restoring database"
if [ "$is_custom" = "true" ]; then
  restore_args=(--no-owner -d "$APP_DB_NAME")
  if [ "$skip_acl" = "true" ]; then
    restore_args+=(--no-privileges)
  fi
  "${stream_cmd[@]}" | sudo -u postgres -H pg_restore "${restore_args[@]}"
else
  if [ "$skip_acl" = "true" ]; then
    "${stream_cmd[@]}" | sed -E '/^(GRANT|REVOKE) /d;/^ALTER (TABLE|SEQUENCE|FUNCTION|SCHEMA|VIEW|MATERIALIZED VIEW|DATABASE|TYPE|DOMAIN|EXTENSION) .* OWNER TO /d' | \
      sudo -u postgres -H psql -v ON_ERROR_STOP=1 -d "$APP_DB_NAME"
  else
    "${stream_cmd[@]}" | sudo -u postgres -H psql -v ON_ERROR_STOP=1 -d "$APP_DB_NAME"
  fi
fi

if [ "${#mapped_old[@]}" -gt 0 ]; then
  idx=0
  for old in "${mapped_old[@]}"; do
    new="${mapped_new[$idx]}"
    old_ident=$(sql_ident "$old")
    new_ident=$(sql_ident "$new")
    sudo -u postgres -H psql -v ON_ERROR_STOP=1 -d "$APP_DB_NAME" -c "REASSIGN OWNED BY \"${old_ident}\" TO \"${new_ident}\";"
    sudo -u postgres -H psql -v ON_ERROR_STOP=1 -d "$APP_DB_NAME" -c "DROP OWNED BY \"${old_ident}\";"
    if [ "$drop_mapped" = "true" ]; then
      sudo -u postgres -H psql -v ON_ERROR_STOP=1 -c "DROP ROLE IF EXISTS \"${old_ident}\";"
    fi
    idx=$((idx + 1))
  done
elif [ "$skip_acl" = "true" ]; then
  app_ident=$(sql_ident "$APP_DB_USER")
  sudo -u postgres -H psql -v ON_ERROR_STOP=1 -c "ALTER DATABASE \"${APP_DB_NAME}\" OWNER TO \"${app_ident}\";"
  sudo -u postgres -H psql -v ON_ERROR_STOP=1 -d "$APP_DB_NAME" -c "REASSIGN OWNED BY postgres TO \"${app_ident}\";"
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
