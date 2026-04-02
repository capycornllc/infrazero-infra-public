#!/usr/bin/env bash
set -euo pipefail

echo "[db] $(date -Is) start"

BOOTSTRAP_ROLE="db"

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

cleanup_private_restore_secrets() {
  # The per-DB Age private keys are only needed during bootstrap restore.
  # Scrub them from the persisted bootstrap script to avoid leaving them on disk
  # even when bootstrap fails.
  unset DATABASES_JSON_PRIVATE_B64 || true
  if [ -f /opt/infrazero/bootstrap/run.sh ]; then
    sed -i 's/^export DATABASES_JSON_PRIVATE_B64=.*$/export DATABASES_JSON_PRIVATE_B64=""/' /opt/infrazero/bootstrap/run.sh || true
  fi
}
trap cleanup_private_restore_secrets EXIT

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[db] missing required env: $name" >&2
    exit 1
  fi
}

require_env "DB_TYPE"
require_env "DB_VERSION"
require_env "DATABASES_JSON"
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
  beacon_status "installing_packages" "Installing PostgreSQL packages" 10
  if ! command -v apt-get >/dev/null 2>&1; then
    return
  fi
  export DEBIAN_FRONTEND=noninteractive
  timeout 300 apt-get update -y || { apt-get clean; timeout 300 apt-get update -y; }
  timeout 600 apt-get install -y curl ca-certificates jq age unzip gnupg lsb-release rsync certbot python3-certbot-dns-cloudflare zstd

  if ! apt-cache show "postgresql-${PG_MAJOR}" >/dev/null 2>&1; then
    echo "[db] enabling PGDG repo for PostgreSQL ${PG_MAJOR}"
    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/pgdg.gpg
    echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list
    timeout 300 apt-get update -y
  fi

  timeout 600 apt-get install -y "postgresql-${PG_MAJOR}" "postgresql-client-${PG_MAJOR}" "postgresql-contrib-${PG_MAJOR}"
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

beacon_status "mounting_volume" "Mounting database volume" 30

MOUNT_DIR="/mnt/db"
VOLUME_NAME="${DB_VOLUME_NAME:-}"
VOLUME_FORMAT="${DB_VOLUME_FORMAT:-ext4}"
DEVICE=""

find_db_volume_device() {
  local volume_name="${1:-}"
  local candidate=""

  if [ -n "$volume_name" ] && [ -e "/dev/disk/by-id/scsi-0HC_Volume_${volume_name}" ]; then
    echo "/dev/disk/by-id/scsi-0HC_Volume_${volume_name}"
    return 0
  fi
  if [ -n "$volume_name" ] && [ -e "/dev/disk/by-id/scsi-SHC_Volume_${volume_name}" ]; then
    echo "/dev/disk/by-id/scsi-SHC_Volume_${volume_name}"
    return 0
  fi

  candidate=$(ls -1 /dev/disk/by-id/scsi-0HC_Volume_* 2>/dev/null | head -n 1 || true)
  if [ -n "$candidate" ]; then
    echo "$candidate"
    return 0
  fi

  candidate=$(ls -1 /dev/disk/by-id/scsi-SHC_Volume_* 2>/dev/null | head -n 1 || true)
  if [ -n "$candidate" ]; then
    echo "$candidate"
    return 0
  fi

  candidate=$(ls -1 /dev/disk/by-id/*Volume* 2>/dev/null | head -n 1 || true)
  if [ -n "$candidate" ]; then
    echo "$candidate"
    return 0
  fi

  return 1
}

wait_for_db_volume_device() {
  local volume_name="${1:-}"
  local attempts="${DB_VOLUME_ATTACH_WAIT_ATTEMPTS:-45}"
  local sleep_seconds="${DB_VOLUME_ATTACH_WAIT_SECONDS:-2}"
  local attempt
  local found=""

  for ((attempt = 1; attempt <= attempts; attempt++)); do
    found=$(find_db_volume_device "$volume_name" || true)
    if [ -n "$found" ]; then
      if [ "$attempt" -gt 1 ]; then
        echo "[db] detected volume device on retry ${attempt}/${attempts}: ${found}" >&2
      fi
      echo "$found"
      return 0
    fi

    if command -v udevadm >/dev/null 2>&1; then
      udevadm settle >/dev/null 2>&1 || true
    fi

    if [ "$attempt" -lt "$attempts" ]; then
      sleep "$sleep_seconds"
    fi
  done

  return 1
}

DEVICE=$(wait_for_db_volume_device "$VOLUME_NAME" || true)
if [ -z "$DEVICE" ]; then
  echo "[db] no attached volume device found after waiting for attach" >&2
  echo "[db] expected volume name: ${VOLUME_NAME:-<unset>}" >&2
  ls -1 /dev/disk/by-id 2>/dev/null | grep -i Volume >&2 || true
  lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT >&2 || true
  exit 1
fi

echo "[db] using volume device: ${DEVICE}"

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

fresh_cluster="false"
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
  fresh_cluster="true"
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

resolve_listen_addresses() {
  if [ -n "${DB_LISTEN_ADDRESS:-}" ]; then
    echo "${DB_LISTEN_ADDRESS}"
    return 0
  fi

  local priv_ip=""
  if [ -n "${PRIVATE_CIDR:-}" ] && command -v python3 >/dev/null 2>&1; then
    priv_ip=$(python3 - <<'PY'
import ipaddress
import os
import subprocess

cidr = os.environ.get("PRIVATE_CIDR", "")
try:
    net = ipaddress.ip_network(cidr, strict=False)
except Exception:
    raise SystemExit(1)

output = subprocess.check_output(["ip", "-4", "-o", "addr", "show"]).decode()
for line in output.splitlines():
    parts = line.split()
    if len(parts) < 4:
        continue
    addr = parts[3].split("/")[0]
    try:
        if ipaddress.ip_address(addr) in net:
            print(addr)
            raise SystemExit(0)
    except Exception:
        continue
raise SystemExit(1)
PY
    ) || true
  fi

  if [ -n "$priv_ip" ]; then
    echo "${priv_ip},localhost"
    return 0
  fi

  echo "*"
}

listen_addr=$(resolve_listen_addresses)
set_conf "listen_addresses" "'${listen_addr}'"
set_conf "password_encryption" "'scram-sha-256'"

DATABASES_JSON_EFFECTIVE="${DATABASES_JSON}"

if ! echo "$DATABASES_JSON_EFFECTIVE" | jq -e 'type=="array" and length>0' >/dev/null 2>&1; then
  echo "[db] DATABASES_JSON must be a non-empty JSON array" >&2
  exit 1
fi

if ! echo "$DATABASES_JSON_EFFECTIVE" | jq -e '[.[].name] | length == (unique | length)' >/dev/null 2>&1; then
  echo "[db] DATABASES_JSON has duplicate database names; names must be unique" >&2
  exit 1
fi

if ! echo "$DATABASES_JSON_EFFECTIVE" | jq -e '
  all(.[]; type=="object"
    and (.name|type=="string" and length>0 and (test("[[:space:]]")|not) and (contains("/")|not))
    and (.user|type=="string" and length>0 and (test("[[:space:]]")|not) and (contains("/")|not))
    and (.password|type=="string" and length>0)
    and (.backup_age_public_key|type=="string" and length>0)
    and ((has("restore_latest")|not) or (.restore_latest==null) or (.restore_latest|type=="boolean"))
    and ((.restore_dump_path // "") | (type=="string" and (test("[[:space:]]")|not)))
    and (((.restore_dump_path // "")|length==0) or (((.restore_dump_path // "") | test("^/"))|not))
    and (((.restore_dump_path // "")|length==0) or (((.restore_dump_path // "") | test("^https?://"))|not))
  )' >/dev/null 2>&1; then
  echo "[db] DATABASES_JSON entries must include non-empty name/user/password/backup_age_public_key (no whitespace in name/user) and valid optional restore_latest/restore_dump_path" >&2
  exit 1
fi

DATABASES_JSON_EFFECTIVE=$(echo "$DATABASES_JSON_EFFECTIVE" | jq -c '.')

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
  cidrs=()
  if [ -n "${K3S_NODE_CIDRS:-}" ]; then
    IFS=',' read -r -a cidrs <<< "$K3S_NODE_CIDRS"
  fi

  # WireGuard is the operator/admin access path; allow connecting to any DB as any user
  # from the WireGuard client CIDR(s). (Auth still enforced by password/SCRAM.)
  if [ -n "${WG_CIDR:-}" ]; then
    echo "host all all ${WG_CIDR} scram-sha-256"
  fi

  while IFS= read -r db_b64; do
    db=$(echo "$db_b64" | base64 -d)
    db_name=$(echo "$db" | jq -r '.name')
    db_user=$(echo "$db" | jq -r '.user')
    for cidr in "${cidrs[@]}"; do
      cidr=$(echo "$cidr" | xargs)
      if [ -n "$cidr" ]; then
        echo "host ${db_name} ${db_user} ${cidr} scram-sha-256"
      fi
    done
  done < <(echo "$DATABASES_JSON_EFFECTIVE" | jq -cr '.[] | @base64')
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

sql_ident() {
  printf '%s' "$1" | sed 's/"/""/g'
}

ensure_databases() {
  echo "[db] ensuring roles and databases"
  while IFS= read -r db_b64; do
    db=$(echo "$db_b64" | base64 -d)
    db_name=$(echo "$db" | jq -r '.name')
    db_user=$(echo "$db" | jq -r '.user')
    db_password=$(echo "$db" | jq -r '.password')

    user_lit=$(sql_escape "$db_user")
    user_ident=$(sql_ident "$db_user")
    pw_lit=$(sql_escape "$db_password")

    user_exists=$(psql_as_postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='${user_lit}'" || true)
    if [ "$user_exists" != "1" ]; then
      psql_as_postgres -c "CREATE ROLE \"${user_ident}\" WITH LOGIN PASSWORD '${pw_lit}';"
    else
      psql_as_postgres -c "ALTER ROLE \"${user_ident}\" WITH PASSWORD '${pw_lit}';"
    fi

    db_lit=$(sql_escape "$db_name")
    db_ident=$(sql_ident "$db_name")

    db_exists=$(psql_as_postgres -tAc "SELECT 1 FROM pg_database WHERE datname='${db_lit}'" || true)
    if [ "$db_exists" != "1" ]; then
      psql_as_postgres -c "CREATE DATABASE \"${db_ident}\" OWNER \"${user_ident}\";"
    else
      psql_as_postgres -c "ALTER DATABASE \"${db_ident}\" OWNER TO \"${user_ident}\";"
    fi

    psql_as_postgres -c "GRANT ALL PRIVILEGES ON DATABASE \"${db_ident}\" TO \"${user_ident}\";"

    # Keep existing databases aligned with configured owner/grants as well.
    # This is critical on reused volumes where bootstrap restore may be skipped.
    normalize_db_ownership_and_privileges "$db_name" "$db_user"
  done < <(echo "$DATABASES_JSON_EFFECTIVE" | jq -cr '.[] | @base64')
}

normalize_db_ownership_and_privileges() {
  local db_name="$1"
  local owner="$2"
  local db_ident
  local owner_ident
  db_ident=$(sql_ident "$db_name")
  owner_ident=$(sql_ident "$owner")

  psql_as_postgres -c "ALTER DATABASE \"${db_ident}\" OWNER TO \"${owner_ident}\";"

  echo "[db] ensuring non-system schemas/objects are owned by ${owner} in ${db_name}"
  # Avoid `REASSIGN OWNED BY postgres` (fails on system-owned objects). Instead
  # transfer ownership only for non-system, non-extension-owned objects.
  sudo -u postgres -H psql -v ON_ERROR_STOP=1 -d "$db_name" -v owner="$owner" <<'SQL'
SELECT format('ALTER SCHEMA %I OWNER TO %I;', n.nspname, :'owner')
FROM pg_namespace n
WHERE n.nspname NOT IN ('pg_catalog','information_schema')
  AND n.nspname NOT LIKE 'pg_%'
  AND NOT EXISTS (
    SELECT 1
    FROM pg_depend d
    WHERE d.classid = 'pg_namespace'::regclass
      AND d.objid = n.oid
      AND d.deptype = 'e'
      AND d.refclassid = 'pg_extension'::regclass
  )
\gexec

WITH rels AS (
  SELECT
    n.nspname,
    c.relname,
    c.relkind,
    pg_get_userbyid(c.relowner) AS owner
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname NOT IN ('pg_catalog','information_schema')
    AND n.nspname NOT LIKE 'pg_%'
    AND c.relkind IN ('r','p','v','m','f')
    AND NOT EXISTS (
      SELECT 1
      FROM pg_depend d
      WHERE d.classid = 'pg_class'::regclass
        AND d.objid = c.oid
        AND d.deptype = 'e'
        AND d.refclassid = 'pg_extension'::regclass
    )
)
SELECT format(
  'ALTER %s %I.%I OWNER TO %I;',
  CASE relkind
    WHEN 'v' THEN 'VIEW'
    WHEN 'm' THEN 'MATERIALIZED VIEW'
    WHEN 'f' THEN 'FOREIGN TABLE'
    ELSE 'TABLE'
  END,
  nspname,
  relname,
  :'owner'
)
FROM rels
WHERE owner <> :'owner'
\gexec

WITH seqs AS (
  SELECT
    n.nspname,
    c.relname,
    pg_get_userbyid(c.relowner) AS owner
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname NOT IN ('pg_catalog','information_schema')
    AND n.nspname NOT LIKE 'pg_%'
    AND c.relkind = 'S'
    -- Sequences "owned by" a table column cannot have ownership changed directly.
    -- Their owner is derived from the owning table, so handle those via ALTER TABLE OWNER.
    AND NOT EXISTS (
      SELECT 1
      FROM pg_depend d
      WHERE d.classid = 'pg_class'::regclass
        AND d.objid = c.oid
        AND d.deptype = 'a'
        AND d.refclassid = 'pg_class'::regclass
    )
    AND NOT EXISTS (
      SELECT 1
      FROM pg_depend d
      WHERE d.classid = 'pg_class'::regclass
        AND d.objid = c.oid
        AND d.deptype = 'e'
        AND d.refclassid = 'pg_extension'::regclass
    )
)
SELECT format('ALTER SEQUENCE %I.%I OWNER TO %I;', nspname, relname, :'owner')
FROM seqs
WHERE owner <> :'owner'
\gexec

SELECT format(
  'ALTER FUNCTION %I.%I(%s) OWNER TO %I;',
  n.nspname,
  p.proname,
  pg_get_function_identity_arguments(p.oid),
  :'owner'
)
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname NOT IN ('pg_catalog','information_schema')
  AND n.nspname NOT LIKE 'pg_%'
  AND pg_get_userbyid(p.proowner) <> :'owner'
  AND NOT EXISTS (
    SELECT 1
    FROM pg_depend d
    WHERE d.classid = 'pg_proc'::regclass
      AND d.objid = p.oid
      AND d.deptype = 'e'
      AND d.refclassid = 'pg_extension'::regclass
  )
\gexec

WITH types AS (
  SELECT
    n.nspname,
    t.typname,
    t.typtype,
    pg_get_userbyid(t.typowner) AS owner
  FROM pg_type t
  JOIN pg_namespace n ON n.oid = t.typnamespace
  WHERE n.nspname NOT IN ('pg_catalog','information_schema')
    AND n.nspname NOT LIKE 'pg_%'
    AND t.typtype IN ('e','d')
    AND NOT EXISTS (
      SELECT 1
      FROM pg_depend d
      WHERE d.classid = 'pg_type'::regclass
        AND d.objid = t.oid
        AND d.deptype = 'e'
        AND d.refclassid = 'pg_extension'::regclass
    )
)
SELECT format(
  'ALTER %s %I.%I OWNER TO %I;',
  CASE typtype
    WHEN 'd' THEN 'DOMAIN'
    ELSE 'TYPE'
  END,
  nspname,
  typname,
  :'owner'
)
FROM types
WHERE owner <> :'owner'
\gexec
SQL

  echo "[db] granting schema/table privileges to ${owner} in ${db_name}"
  sudo -u postgres -H psql -v ON_ERROR_STOP=1 -d "$db_name" -v grantee="$owner" -v owner="$owner" <<'SQL'
SELECT format('GRANT USAGE, CREATE ON SCHEMA %I TO %I;', nspname, :'grantee')
FROM pg_namespace
WHERE nspname NOT IN ('pg_catalog','information_schema') AND nspname NOT LIKE 'pg_%'
\gexec

SELECT format('GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA %I TO %I;', nspname, :'grantee')
FROM pg_namespace
WHERE nspname NOT IN ('pg_catalog','information_schema') AND nspname NOT LIKE 'pg_%'
\gexec

SELECT format('GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA %I TO %I;', nspname, :'grantee')
FROM pg_namespace
WHERE nspname NOT IN ('pg_catalog','information_schema') AND nspname NOT LIKE 'pg_%'
\gexec

SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I GRANT ALL ON TABLES TO %I;', :'owner', nspname, :'grantee')
FROM pg_namespace
WHERE nspname NOT IN ('pg_catalog','information_schema') AND nspname NOT LIKE 'pg_%'
\gexec

SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I GRANT ALL ON SEQUENCES TO %I;', :'owner', nspname, :'grantee')
FROM pg_namespace
WHERE nspname NOT IN ('pg_catalog','information_schema') AND nspname NOT LIKE 'pg_%'
\gexec
SQL

  # Heuristic search_path fix:
  # - prefer `main` if it contains relations
  # - otherwise if there is exactly 1 non-public user schema with relations, use it
  local set_search_path="${DB_RESTORE_SET_SEARCH_PATH:-true}"
  if [ "$set_search_path" = "true" ]; then
    local desired_search_path="${DB_RESTORE_SEARCH_PATH:-}"
    if [ -z "$desired_search_path" ]; then
      desired_search_path=$(
        sudo -u postgres -H psql -v ON_ERROR_STOP=1 -d "$db_name" -tAc "
WITH user_schemas AS (
  SELECT n.oid, n.nspname
  FROM pg_namespace n
  WHERE n.nspname NOT IN ('pg_catalog','information_schema')
    AND n.nspname NOT LIKE 'pg_%'
    AND n.nspname <> 'public'
    AND NOT EXISTS (
      SELECT 1
      FROM pg_depend d
      WHERE d.classid = 'pg_namespace'::regclass
        AND d.objid = n.oid
        AND d.deptype = 'e'
        AND d.refclassid = 'pg_extension'::regclass
    )
),
schemas_with_rels AS (
  SELECT DISTINCT n.nspname
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname IN (SELECT nspname FROM user_schemas)
    AND c.relkind IN ('r','p','v','m','f')
    AND NOT EXISTS (
      SELECT 1
      FROM pg_depend d
      WHERE d.classid = 'pg_class'::regclass
        AND d.objid = c.oid
        AND d.deptype = 'e'
        AND d.refclassid = 'pg_extension'::regclass
    )
)
SELECT CASE
  WHEN EXISTS (SELECT 1 FROM schemas_with_rels WHERE nspname='main')
    THEN quote_ident('main') || ', public'
  WHEN (SELECT count(*) FROM schemas_with_rels)=1
    THEN (SELECT quote_ident(nspname) FROM schemas_with_rels LIMIT 1) || ', public'
  ELSE ''
END;
" | tr -d ' \t\r\n'
      )
    fi

    if [ -n "$desired_search_path" ]; then
      local sp_lit
      sp_lit=$(sql_escape "$desired_search_path")
      psql_as_postgres -c "ALTER ROLE \"${owner_ident}\" IN DATABASE \"${db_ident}\" SET search_path = '${sp_lit}';"
    fi
  fi
}

beacon_status "configuring_postgresql" "Configuring PostgreSQL" 50

ensure_databases

restore_databases_from_s3() {
  if [ "$fresh_cluster" != "true" ]; then
    echo "[db] existing PostgreSQL data directory detected; skipping bootstrap restore"
    cleanup_private_restore_secrets
    return 0
  fi

  if [ -z "${DATABASES_JSON_PRIVATE_B64:-}" ]; then
    echo "[db] DATABASES_JSON_PRIVATE_B64 not set; skipping restore"
    cleanup_private_restore_secrets
    return 0
  fi

  local tmpdir
  tmpdir=$(mktemp -d /run/infrazero-db-bootstrap-restore.XXXX)
  chmod 700 "$tmpdir"

  if ! echo "$DATABASES_JSON_PRIVATE_B64" | base64 -d > "$tmpdir/databases.json"; then
    echo "[db] unable to decode DATABASES_JSON_PRIVATE_B64" >&2
    rm -rf "$tmpdir"
    cleanup_private_restore_secrets
    return 1
  fi
  chmod 600 "$tmpdir/databases.json" || true

  if ! jq -e 'type=="array"' "$tmpdir/databases.json" >/dev/null 2>&1; then
    echo "[db] decoded DATABASES_JSON_PRIVATE_B64 is not a JSON array" >&2
    rm -rf "$tmpdir"
    cleanup_private_restore_secrets
    return 1
  fi

  local -a restored=()
  local -a skipped=()
  local -a failed=()

  echo "[db] restoring DB backups (fresh cluster)"
  while IFS= read -r db_b64; do
    local db
    local db_name
    local restore_latest
    local restore_dump_path
    local backup_ref
    local expected_sha
    local manifest_key
    local manifest_path
    local manifest_url
    local manifest_bucket
    local manifest_file
    local key
    local sha
    local pk

    db=$(echo "$db_b64" | base64 -d)
    db_name=$(echo "$db" | jq -r '.name')
    restore_latest=$(echo "$db" | jq -r 'if has("restore_latest") and (.restore_latest!=null) then .restore_latest else true end')
    restore_dump_path=$(echo "$db" | jq -r '.restore_dump_path // empty')

    if [ "$restore_latest" != "true" ] && [ "$restore_latest" != "false" ]; then
      echo "[db] invalid restore_latest for ${db_name}; must be boolean" >&2
      failed+=("$db_name")
      continue
    fi

    if [ "$restore_latest" = "true" ] && [ -n "$restore_dump_path" ]; then
      echo "[db] warning: restore_dump_path set for ${db_name} but restore_latest=true; ignoring restore_dump_path" >&2
    fi

    backup_ref=""
    expected_sha=""
    manifest_bucket=""
    manifest_file="$tmpdir/latest-dump-${db_name}.json"
    rm -f "$manifest_file" || true

    if [ "$restore_latest" = "false" ]; then
      if [ -z "$restore_dump_path" ]; then
        echo "[db] restore disabled for ${db_name} (restore_latest=false and restore_dump_path empty); skipping"
        skipped+=("$db_name")
        continue
      fi

      manifest_path=""
      if [[ "$restore_dump_path" == */ ]]; then
        # Prefix containing a latest-dump.json manifest.
        manifest_path="${restore_dump_path}latest-dump.json"
      elif [[ "$restore_dump_path" == *latest-dump.json ]]; then
        # Explicit manifest path.
        manifest_path="$restore_dump_path"
      fi

      if [ -n "$manifest_path" ]; then
        if [[ "$manifest_path" == s3://* ]]; then
          manifest_url="$manifest_path"
          manifest_bucket="${manifest_path#s3://}"
          manifest_bucket="${manifest_bucket%%/*}"
        else
          manifest_url="s3://${DB_BACKUP_BUCKET}/${manifest_path}"
        fi

        if ! aws --endpoint-url "$S3_ENDPOINT" s3 cp "$manifest_url" "$manifest_file" >/dev/null 2>&1; then
          echo "[db] unable to fetch latest-dump manifest at ${manifest_path} for ${db_name}" >&2
          failed+=("$db_name")
          continue
        fi

        key=$(jq -r '.key' "$manifest_file")
        sha=$(jq -r '.sha256' "$manifest_file")
        if [ -z "$key" ] || [ "$key" = "null" ]; then
          echo "[db] latest-dump manifest missing key for ${db_name}" >&2
          failed+=("$db_name")
          continue
        fi
        if [ -z "$sha" ] || [ "$sha" = "null" ]; then
          echo "[db] latest-dump manifest missing sha256 for ${db_name}" >&2
          failed+=("$db_name")
          continue
        fi

        if [[ "$key" == s3://* ]]; then
          backup_ref="$key"
        elif [ -n "$manifest_bucket" ]; then
          backup_ref="s3://${manifest_bucket}/${key}"
        else
          backup_ref="$key"
        fi
        expected_sha="$sha"
      else
        backup_ref="$restore_dump_path"
      fi
    else
      manifest_key="db/${db_name}/latest-dump.json"
      if ! aws --endpoint-url "$S3_ENDPOINT" s3 cp "s3://${DB_BACKUP_BUCKET}/${manifest_key}" "$manifest_file" >/dev/null 2>&1; then
        echo "[db] no latest-dump manifest found for ${db_name}; skipping restore"
        skipped+=("$db_name")
        continue
      fi

      key=$(jq -r '.key' "$manifest_file")
      sha=$(jq -r '.sha256' "$manifest_file")
      if [ -z "$key" ] || [ "$key" = "null" ]; then
        echo "[db] latest-dump manifest missing key for ${db_name}" >&2
        failed+=("$db_name")
        continue
      fi
      if [ -z "$sha" ] || [ "$sha" = "null" ]; then
        echo "[db] latest-dump manifest missing sha256 for ${db_name}" >&2
        failed+=("$db_name")
        continue
      fi

      backup_ref="$key"
      expected_sha="$sha"
    fi

    pk=$(jq -r --arg name "$db_name" '.[] | select(.name==$name) | .backup_age_private_key // empty' "$tmpdir/databases.json" | tail -n 1)
    restore_env=(DB_RESTORE_NON_INTERACTIVE=true)
    if [ -n "$pk" ]; then
      restore_env+=(DB_RESTORE_AGE_PRIVATE_KEY="$pk")
    fi
    if [ -n "$expected_sha" ] && [ "$expected_sha" != "null" ]; then
      restore_env+=(DB_RESTORE_EXPECTED_SHA256="$expected_sha")
    fi

    echo "[db] restoring ${db_name} from ${backup_ref}"
    # NOTE: `VAR=VAL cmd` environment assignments are parsed by the shell *before* expansion.
    # When constructed via array expansion, `VAR=VAL` becomes the first "word" and is treated
    # as a command name. Use `env` to apply the `VAR=VAL` pairs at runtime.
    if ! env "${restore_env[@]}" /opt/infrazero/db/restore.sh "$db_name" "$backup_ref"; then
      echo "[db] restore failed for ${db_name}" >&2
      failed+=("$db_name")
      continue
    fi

    restored+=("$db_name")
  done < <(echo "$DATABASES_JSON_EFFECTIVE" | jq -cr '.[] | @base64')

  rm -rf "$tmpdir"
  cleanup_private_restore_secrets

  echo "[db] restore summary: restored=${#restored[@]} skipped=${#skipped[@]} failed=${#failed[@]}"
  if [ "${#failed[@]}" -gt 0 ]; then
    echo "[db] restore failures: ${failed[*]}" >&2
    return 1
  fi

  echo "[db] restore complete"
}

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

if [ -z "${DATABASES_JSON:-}" ]; then
  echo "[db-backup] DATABASES_JSON not set" >&2
  exit 1
fi

if ! echo "$DATABASES_JSON" | jq -e 'type=="array" and length>0' >/dev/null 2>&1; then
  echo "[db-backup] DATABASES_JSON must be a non-empty JSON array" >&2
  exit 1
fi

while IFS= read -r db_b64; do
  db=$(echo "$db_b64" | base64 -d)
  db_name=$(echo "$db" | jq -r '.name')
  db_pub=$(echo "$db" | jq -r '.backup_age_public_key')

  if [ -z "$db_name" ] || [ "$db_name" = "null" ]; then
    echo "[db-backup] invalid database name in DATABASES_JSON" >&2
    exit 1
  fi
  if [ -z "$db_pub" ] || [ "$db_pub" = "null" ]; then
    echo "[db-backup] missing backup_age_public_key for ${db_name}" >&2
    exit 1
  fi

  dump_dir="$WORKDIR/${db_name}"
  mkdir -p "$dump_dir"

  dump_path="$dump_dir/${TIMESTAMP}.sql.gz"
  enc_path="$dump_path.age"

  sudo -u postgres pg_dump -d "$db_name" | gzip > "$dump_path"

  age -r "$db_pub" -o "$enc_path" "$dump_path"
  sha=$(sha256sum "$enc_path" | awk '{print $1}')
  key="db/${db_name}/${TIMESTAMP}.sql.gz.age"

  aws --endpoint-url "$S3_ENDPOINT" s3 cp "$enc_path" "s3://${DB_BACKUP_BUCKET}/${key}"

  jq -n --arg key "$key" --arg sha "$sha" --arg created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{key:$key, sha256:$sha, created_at:$created_at}' > "$dump_dir/latest-dump.json"
  aws --endpoint-url "$S3_ENDPOINT" s3 cp "$dump_dir/latest-dump.json" "s3://${DB_BACKUP_BUCKET}/db/${db_name}/latest-dump.json"

  rm -f "$dump_path" "$enc_path"
done < <(echo "$DATABASES_JSON" | jq -cr '.[] | @base64')
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

cd /

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[db-restore] missing required env: $name" >&2
    exit 1
  fi
}

require_env "DATABASES_JSON"
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

if ! command -v jq >/dev/null 2>&1; then
  echo "[db-restore] jq not available" >&2
  exit 1
fi

if ! echo "$DATABASES_JSON" | jq -e 'type=="array" and length>0' >/dev/null 2>&1; then
  echo "[db-restore] DATABASES_JSON must be a non-empty JSON array" >&2
  exit 1
fi

db_name="${1:-}"
backup_key="${2:-}"
if [ -z "$db_name" ] || [ -z "$backup_key" ]; then
  echo "Usage: $0 <db_name> <s3-key-or-s3-url>" >&2
  echo "Example: $0 messenger db/messenger/20260201T120000Z.sql.gz.age" >&2
  exit 1
fi

db_entry=$(echo "$DATABASES_JSON" | jq -c --arg name "$db_name" '.[] | select(.name==$name)' | tail -n 1 || true)
if [ -z "$db_entry" ]; then
  echo "[db-restore] database ${db_name} not found in DATABASES_JSON" >&2
  exit 1
fi

TARGET_DB_NAME="$db_name"
TARGET_DB_USER=$(echo "$db_entry" | jq -r '.user')
TARGET_DB_PASSWORD=$(echo "$db_entry" | jq -r '.password')
if [ -z "$TARGET_DB_USER" ] || [ "$TARGET_DB_USER" = "null" ]; then
  echo "[db-restore] DATABASES_JSON entry for ${TARGET_DB_NAME} missing user" >&2
  exit 1
fi
if [ -z "$TARGET_DB_PASSWORD" ] || [ "$TARGET_DB_PASSWORD" = "null" ]; then
  echo "[db-restore] DATABASES_JSON entry for ${TARGET_DB_NAME} missing password" >&2
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

ensure_db_role() {
  local role_lit
  local role_ident
  local pw_lit
  role_lit=$(sql_literal "$TARGET_DB_USER")
  role_ident=$(sql_ident "$TARGET_DB_USER")
  pw_lit=$(sql_literal "$TARGET_DB_PASSWORD")

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
    cidrs=()
    if [ -n "${K3S_NODE_CIDRS:-}" ]; then
      IFS=',' read -r -a cidrs <<< "$K3S_NODE_CIDRS"
    fi

    # WireGuard is the operator/admin access path; allow connecting to any DB as any user
    # from the WireGuard client CIDR(s). (Auth still enforced by password/SCRAM.)
    if [ -n "${WG_CIDR:-}" ]; then
      echo "host all all ${WG_CIDR} scram-sha-256"
    fi

    while IFS= read -r db_b64; do
      db=$(echo "$db_b64" | base64 -d)
      db_name=$(echo "$db" | jq -r '.name')
      db_user=$(echo "$db" | jq -r '.user')
      for cidr in "${cidrs[@]}"; do
        cidr=$(echo "$cidr" | xargs)
        if [ -n "$cidr" ]; then
          echo "host ${db_name} ${db_user} ${cidr} scram-sha-256"
        fi
      done
    done < <(echo "$DATABASES_JSON" | jq -cr '.[] | @base64')
    echo "$hba_end"
  } >> "$HBA_CONF"
}

apply_postgres_config() {
  local listen_addr="*"
  if [ -n "${DB_LISTEN_ADDRESS:-}" ]; then
    listen_addr="${DB_LISTEN_ADDRESS}"
  else
    local priv_ip=""
    if [ -n "${PRIVATE_CIDR:-}" ] && command -v python3 >/dev/null 2>&1; then
      priv_ip=$(python3 - <<'PY'
import ipaddress
import os
import subprocess

cidr = os.environ.get("PRIVATE_CIDR", "")
try:
    net = ipaddress.ip_network(cidr, strict=False)
except Exception:
    raise SystemExit(1)

output = subprocess.check_output(["ip", "-4", "-o", "addr", "show"]).decode()
for line in output.splitlines():
    parts = line.split()
    if len(parts) < 4:
        continue
    addr = parts[3].split("/")[0]
    try:
        if ipaddress.ip_address(addr) in net:
            print(addr)
            raise SystemExit(0)
    except Exception:
        continue
raise SystemExit(1)
PY
      ) || true
    fi

    if [ -n "$priv_ip" ]; then
      listen_addr="${priv_ip},localhost"
    fi
  fi

  echo "[db-restore] setting listen_addresses to ${listen_addr}"
  set_conf "listen_addresses" "'${listen_addr}'"
  set_conf "password_encryption" "'scram-sha-256'"
  apply_infrazero_hba

  if command -v pg_ctlcluster >/dev/null 2>&1; then
    pg_ctlcluster "$PG_MAJOR" main reload >/dev/null 2>&1 || true
  fi

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet "postgresql@${PG_MAJOR}-main" 2>/dev/null; then
      systemctl reload "postgresql@${PG_MAJOR}-main" || systemctl restart "postgresql@${PG_MAJOR}-main" || true
    elif systemctl is-active --quiet postgresql 2>/dev/null; then
      systemctl reload postgresql || systemctl restart postgresql || true
    fi
  fi
}

tmpdir=$(mktemp -d /run/infrazero-db-restore.XXXX)
chmod 700 "$tmpdir"

cleanup_tmpdir() {
  rm -rf "$tmpdir"
}
trap cleanup_tmpdir EXIT

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

expected_sha="${DB_RESTORE_EXPECTED_SHA256:-}"
if [ -n "$expected_sha" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    echo "${expected_sha}  ${src_path}" | sha256sum -c -
  else
    echo "[db-restore] warning: sha256sum not available; skipping checksum verification" >&2
  fi
fi

detect_utf16_bom() {
  local path="$1"
  if ! command -v od >/dev/null 2>&1; then
    return 1
  fi
  local bom
  bom=$(od -An -t x1 -N 2 "$path" 2>/dev/null | tr -d ' \n')
  if [ "$bom" = "fffe" ] || [ "$bom" = "feff" ]; then
    return 0
  fi
  return 1
}

if detect_utf16_bom "$src_path"; then
  echo "[db-restore] backup begins with UTF-16 BOM (FFFE/FEFF), not a raw dump stream" >&2
  echo "[db-restore] this usually means the file was transcoded in text mode during upload/download" >&2
  echo "[db-restore] use a binary-safe transfer (example: aws s3 cp <local_dump> s3://bucket/key)" >&2
  echo "[db-restore] object is likely corrupted and needs to be re-exported/re-uploaded" >&2
  exit 1
fi

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

detect_xz() {
  local path="$1"
  if ! command -v od >/dev/null 2>&1; then
    return 1
  fi
  local magic
  magic=$(od -An -t x1 -N 6 "$path" 2>/dev/null | tr -d ' \n')
  if [ "$magic" = "fd377a585a00" ]; then
    return 0
  fi
  return 1
}

detect_bzip2() {
  local path="$1"
  if ! command -v od >/dev/null 2>&1; then
    return 1
  fi
  local magic
  magic=$(od -An -t x1 -N 3 "$path" 2>/dev/null | tr -d ' \n')
  if [ "$magic" = "425a68" ]; then
    return 0
  fi
  return 1
}

detect_lz4() {
  local path="$1"
  if ! command -v od >/dev/null 2>&1; then
    return 1
  fi
  local magic
  magic=$(od -An -t x1 -N 4 "$path" 2>/dev/null | tr -d ' \n')
  if [ "$magic" = "04224d18" ]; then
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

detect_tar() {
  local path="$1"
  if ! command -v od >/dev/null 2>&1; then
    return 1
  fi
  local magic
  magic=$(od -An -t x1 -j 257 -N 5 "$path" 2>/dev/null | tr -d ' \n')
  if [ "$magic" = "7573746172" ]; then
    return 0
  fi
  return 1
}

detect_compression_for_path() {
  local path="$1"
  is_gzip="false"
  is_zstd="false"
  is_xz="false"
  is_bzip2="false"
  is_lz4="false"

  if detect_gzip "$path"; then
    is_gzip="true"
  elif detect_zstd "$path"; then
    is_zstd="true"
  elif detect_xz "$path"; then
    is_xz="true"
  elif detect_bzip2 "$path"; then
    is_bzip2="true"
  elif detect_lz4 "$path"; then
    is_lz4="true"
  fi
}

detect_compression_for_path "$src_path"

if [ "$is_age_encrypted" = "true" ]; then
  if ! command -v age >/dev/null 2>&1; then
    echo "[db-restore] age not available for encrypted backup" >&2
    rm -rf "$tmpdir"
    exit 1
  fi

  provided_key="${DB_RESTORE_AGE_PRIVATE_KEY:-}"
  non_interactive="${DB_RESTORE_NON_INTERACTIVE:-false}"
  if [ -n "$provided_key" ]; then
    if ! try_decrypt "$provided_key"; then
      echo "[db-restore] decryption failed with DB_RESTORE_AGE_PRIVATE_KEY" >&2
      rm -rf "$tmpdir"
      exit 1
    fi
  else
    if [ "$non_interactive" = "true" ]; then
      echo "[db-restore] encrypted backup requires DB_RESTORE_AGE_PRIVATE_KEY (non-interactive)" >&2
      rm -rf "$tmpdir"
      exit 1
    fi
    echo "[db-restore] enter Age private key to decrypt backup:"
    read -r -s input_key
    echo
    if ! try_decrypt "$input_key"; then
      echo "[db-restore] decryption failed" >&2
      rm -rf "$tmpdir"
      exit 1
    fi
  fi
  detect_compression_for_path "$dump_path"
else
  dump_path="$src_path"
fi

restore_source="$dump_path"

emit_restore_stream() {
  if [ "$is_gzip" = "true" ]; then
    gunzip -c "$restore_source"
  elif [ "$is_zstd" = "true" ]; then
    zstd -d -q --stdout "$restore_source"
  elif [ "$is_xz" = "true" ]; then
    xz -d -c "$restore_source"
  elif [ "$is_bzip2" = "true" ]; then
    bzip2 -d -c "$restore_source"
  elif [ "$is_lz4" = "true" ]; then
    lz4 -d -c "$restore_source"
  else
    cat "$restore_source"
  fi
}

if [ "$is_zstd" = "true" ] && ! command -v zstd >/dev/null 2>&1; then
  echo "[db-restore] zstd not available for .zst backup" >&2
  rm -rf "$tmpdir"
  exit 1
fi
if [ "$is_xz" = "true" ] && ! command -v xz >/dev/null 2>&1; then
  echo "[db-restore] xz not available for .xz backup" >&2
  rm -rf "$tmpdir"
  exit 1
fi
if [ "$is_bzip2" = "true" ] && ! command -v bzip2 >/dev/null 2>&1; then
  echo "[db-restore] bzip2 not available for .bz2 backup" >&2
  rm -rf "$tmpdir"
  exit 1
fi
if [ "$is_lz4" = "true" ] && ! command -v lz4 >/dev/null 2>&1; then
  echo "[db-restore] lz4 not available for lz4-compressed backup" >&2
  rm -rf "$tmpdir"
  exit 1
fi

detect_stream_gzip() {
  local magic
  magic=$(emit_restore_stream 2>/dev/null | od -An -t x1 -N 2 2>/dev/null | tr -d ' \n' || true)
  if [ "$magic" = "1f8b" ]; then
    return 0
  fi
  return 1
}

detect_stream_zstd() {
  local magic
  magic=$(emit_restore_stream 2>/dev/null | od -An -t x1 -N 4 2>/dev/null | tr -d ' \n' || true)
  if [ "$magic" = "28b52ffd" ]; then
    return 0
  fi
  return 1
}

detect_stream_xz() {
  local magic
  magic=$(emit_restore_stream 2>/dev/null | od -An -t x1 -N 6 2>/dev/null | tr -d ' \n' || true)
  if [ "$magic" = "fd377a585a00" ]; then
    return 0
  fi
  return 1
}

detect_stream_bzip2() {
  local magic
  magic=$(emit_restore_stream 2>/dev/null | od -An -t x1 -N 3 2>/dev/null | tr -d ' \n' || true)
  if [ "$magic" = "425a68" ]; then
    return 0
  fi
  return 1
}

detect_stream_lz4() {
  local magic
  magic=$(emit_restore_stream 2>/dev/null | od -An -t x1 -N 4 2>/dev/null | tr -d ' \n' || true)
  if [ "$magic" = "04224d18" ]; then
    return 0
  fi
  return 1
}

nested_compression="none"
if detect_stream_gzip; then
  nested_compression="gzip"
elif detect_stream_zstd; then
  nested_compression="zstd"
elif detect_stream_xz; then
  nested_compression="xz"
elif detect_stream_bzip2; then
  nested_compression="bzip2"
elif detect_stream_lz4; then
  nested_compression="lz4"
fi

if [ "$nested_compression" = "zstd" ] && ! command -v zstd >/dev/null 2>&1; then
  echo "[db-restore] zstd not available for nested .zst backup" >&2
  rm -rf "$tmpdir"
  exit 1
fi
if [ "$nested_compression" = "xz" ] && ! command -v xz >/dev/null 2>&1; then
  echo "[db-restore] xz not available for nested .xz backup" >&2
  rm -rf "$tmpdir"
  exit 1
fi
if [ "$nested_compression" = "bzip2" ] && ! command -v bzip2 >/dev/null 2>&1; then
  echo "[db-restore] bzip2 not available for nested .bz2 backup" >&2
  rm -rf "$tmpdir"
  exit 1
fi
if [ "$nested_compression" = "lz4" ] && ! command -v lz4 >/dev/null 2>&1; then
  echo "[db-restore] lz4 not available for nested lz4 backup" >&2
  rm -rf "$tmpdir"
  exit 1
fi

emit_payload_stream() {
  case "$nested_compression" in
    gzip)
      emit_restore_stream | gunzip -c
      ;;
    zstd)
      emit_restore_stream | zstd -d -q --stdout
      ;;
    xz)
      emit_restore_stream | xz -d -c
      ;;
    bzip2)
      emit_restore_stream | bzip2 -d -c
      ;;
    lz4)
      emit_restore_stream | lz4 -d -c
      ;;
    *)
      emit_restore_stream
      ;;
  esac
}

detect_stream_pg_dump() {
  local magic
  magic=$(emit_payload_stream 2>/dev/null | od -An -t x1 -N 5 2>/dev/null | tr -d ' \n' || true)
  if [ "$magic" = "5047444d50" ]; then
    return 0
  fi
  return 1
}

detect_stream_tar() {
  local magic
  magic=$(emit_payload_stream 2>/dev/null | od -An -t x1 -j 257 -N 5 2>/dev/null | tr -d ' \n' || true)
  if [ "$magic" = "7573746172" ]; then
    return 0
  fi
  return 1
}

restore_format="plain"
if [ "$is_gzip" = "true" ] || [ "$is_zstd" = "true" ] || [ "$is_xz" = "true" ] || [ "$is_bzip2" = "true" ] || [ "$is_lz4" = "true" ]; then
  if detect_stream_pg_dump; then
    restore_format="custom"
  elif detect_stream_tar; then
    restore_format="tar"
  fi
else
  if detect_pg_dump "$restore_source"; then
    restore_format="custom"
  elif detect_tar "$restore_source"; then
    restore_format="tar"
  fi
fi

  apply_postgres_config

  ensure_db_role

db_lit=$(sql_literal "$TARGET_DB_NAME")
db_ident=$(sql_ident "$TARGET_DB_NAME")
role_ident=$(sql_ident "$TARGET_DB_USER")

wipe_target_database() {
  echo "[db-restore] wiping database ${TARGET_DB_NAME}"
  sudo -u postgres -H psql -v ON_ERROR_STOP=1 -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${db_lit}';"
  sudo -u postgres -H psql -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS \"${db_ident}\";"
  sudo -u postgres -H psql -v ON_ERROR_STOP=1 -c "CREATE DATABASE \"${db_ident}\" OWNER \"${role_ident}\";"
}

wipe_target_database

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
declare -a pg_restore_candidates=()
declare -a _discovered_pg_restore_candidates=()
saw_unsupported_pg_restore_version="false"

add_pg_restore_candidate() {
  local candidate="$1"
  local existing
  if [ -z "$candidate" ] || [ ! -x "$candidate" ]; then
    return 0
  fi
  for existing in "${pg_restore_candidates[@]}"; do
    if [ "$existing" = "$candidate" ]; then
      return 0
    fi
  done
  pg_restore_candidates+=("$candidate")
}

build_pg_restore_candidates() {
  local cmd_path
  local dir
  local candidate
  pg_restore_candidates=()
  _discovered_pg_restore_candidates=()

  if [ -n "${DB_RESTORE_PG_RESTORE_BIN:-}" ]; then
    _discovered_pg_restore_candidates+=("$DB_RESTORE_PG_RESTORE_BIN")
  fi

  if command -v pg_restore >/dev/null 2>&1; then
    cmd_path=$(command -v pg_restore)
    _discovered_pg_restore_candidates+=("$cmd_path")
  fi

  while IFS= read -r candidate; do
    _discovered_pg_restore_candidates+=("$candidate")
  done < <(
    for dir in /usr/lib/postgresql/*; do
      if [ -x "$dir/bin/pg_restore" ]; then
        echo "$dir/bin/pg_restore"
      fi
    done | sort -Vr
  )

  for candidate in "${_discovered_pg_restore_candidates[@]}"; do
    add_pg_restore_candidate "$candidate"
  done
}

install_additional_pg_restore_clients() {
  local installed="false"
  local candidate_major
  local found_newer_pkg="false"

  if [ "${DB_RESTORE_AUTO_INSTALL_CLIENTS:-true}" != "true" ]; then
    return 1
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    return 1
  fi

  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null 2>&1 || true

  for candidate_major in 18 17 16; do
    if apt-cache show "postgresql-client-${candidate_major}" >/dev/null 2>&1; then
      found_newer_pkg="true"
      break
    fi
  done

  # Some base images only have distro PostgreSQL repos configured and therefore
  # cannot install newer pg_restore clients needed for newer dump formats.
  if [ "$found_newer_pkg" != "true" ] && command -v curl >/dev/null 2>&1 && command -v gpg >/dev/null 2>&1 && command -v lsb_release >/dev/null 2>&1; then
    if [ ! -f /etc/apt/sources.list.d/pgdg.list ]; then
      codename="$(lsb_release -cs 2>/dev/null || true)"
      if [ -n "$codename" ]; then
        echo "[db-restore] enabling PGDG repo for newer pg_restore clients"
        curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/pgdg.gpg || true
        echo "deb http://apt.postgresql.org/pub/repos/apt ${codename}-pgdg main" > /etc/apt/sources.list.d/pgdg.list
        apt-get update -y >/dev/null 2>&1 || true
      fi
    fi
  fi

  for candidate_major in 18 17 16 15; do
    if [ "$candidate_major" = "$PG_MAJOR" ]; then
      continue
    fi
    if [ -x "/usr/lib/postgresql/${candidate_major}/bin/pg_restore" ]; then
      continue
    fi
    if ! apt-cache show "postgresql-client-${candidate_major}" >/dev/null 2>&1; then
      continue
    fi
    echo "[db-restore] installing postgresql-client-${candidate_major} for dump compatibility"
    if apt-get install -y "postgresql-client-${candidate_major}" >/dev/null 2>&1; then
      installed="true"
    fi
  done

  if [ "$installed" = "true" ]; then
    return 0
  fi
  return 1
}

run_pg_restore_with_candidates() {
  local bin
  local err_file="$tmpdir/pg_restore.err"
  saw_unsupported_pg_restore_version="false"

  build_pg_restore_candidates
  if [ "${#pg_restore_candidates[@]}" -eq 0 ]; then
    echo "[db-restore] no pg_restore binary available" >&2
    return 1
  fi

  for bin in "${pg_restore_candidates[@]}"; do
    # Each retry must start from a clean DB; otherwise partial restores from
    # previous attempts cause cascaded "already exists" failures.
    wipe_target_database
    echo "[db-restore] trying pg_restore via ${bin}"
    if emit_payload_stream | sudo -u postgres -H "$bin" "${restore_args[@]}" 2>"$err_file"; then
      return 0
    fi

    cat "$err_file" >&2 || true
    if grep -qi "unsupported version" "$err_file" 2>/dev/null; then
      saw_unsupported_pg_restore_version="true"
    fi
  done

  return 1
}

run_pg_restore_with_auto_install() {
  if run_pg_restore_with_candidates; then
    return 0
  fi
  if [ "${saw_unsupported_pg_restore_version:-false}" = "true" ] && install_additional_pg_restore_clients; then
    if run_pg_restore_with_candidates; then
      return 0
    fi
  fi
  return 1
}

payload_looks_text_sql() {
  local probe_file="$tmpdir/payload-probe.bin"
  local total
  local non_printable
  emit_payload_stream 2>/dev/null | head -c 65536 > "$probe_file" || true
  if [ ! -s "$probe_file" ]; then
    return 1
  fi
  total=$(wc -c < "$probe_file" | tr -d '[:space:]')
  non_printable=$(LC_ALL=C tr -d '\11\12\15\40-\176' < "$probe_file" | wc -c | tr -d '[:space:]')
  if [ -z "$total" ] || [ "$total" -eq 0 ]; then
    return 1
  fi
  if [ -z "$non_printable" ]; then
    non_printable=0
  fi
  if [ $((non_printable * 100 / total)) -gt 5 ]; then
    return 1
  fi
  return 0
}

if [ "$restore_format" = "custom" ] || [ "$restore_format" = "tar" ]; then
  restore_args=(--clean --if-exists --no-owner -d "$TARGET_DB_NAME")
  if [ "$restore_format" = "tar" ]; then
    restore_args+=(--format=t)
  fi
  if [ "$skip_acl" = "true" ]; then
    restore_args+=(--no-privileges)
  fi

  if ! run_pg_restore_with_auto_install; then
    echo "[db-restore] pg_restore failed" >&2
    exit 1
  fi
else
  if payload_looks_text_sql; then
    if [ "$skip_acl" = "true" ]; then
      emit_payload_stream | sed -E '/^(GRANT|REVOKE) /d;/^ALTER (TABLE|SEQUENCE|FUNCTION|SCHEMA|VIEW|MATERIALIZED VIEW|DATABASE|TYPE|DOMAIN|EXTENSION) .* OWNER TO /d;/^ALTER DEFAULT PRIVILEGES /d' | \
        sudo -u postgres -H psql -v ON_ERROR_STOP=1 -d "$TARGET_DB_NAME"
    else
      emit_payload_stream | sudo -u postgres -H psql -v ON_ERROR_STOP=1 -d "$TARGET_DB_NAME"
    fi
  else
    echo "[db-restore] payload appears binary; trying pg_restore fallback"
    restore_args=(--clean --if-exists --no-owner -d "$TARGET_DB_NAME")
    if [ "$skip_acl" = "true" ]; then
      restore_args+=(--no-privileges)
    fi

    if ! run_pg_restore_with_auto_install; then
      restore_args=(--clean --if-exists --no-owner --format=t -d "$TARGET_DB_NAME")
      if [ "$skip_acl" = "true" ]; then
        restore_args+=(--no-privileges)
      fi
      if ! run_pg_restore_with_auto_install; then
        echo "[db-restore] restore payload is binary and no pg_restore format succeeded; verify backup file format/key" >&2
        exit 1
      fi
    fi
  fi
fi

if [ "${#mapped_old[@]}" -gt 0 ]; then
  idx=0
  for old in "${mapped_old[@]}"; do
    new="${mapped_new[$idx]}"
    old_ident=$(sql_ident "$old")
    new_ident=$(sql_ident "$new")
    sudo -u postgres -H psql -v ON_ERROR_STOP=1 -d "$TARGET_DB_NAME" -c "REASSIGN OWNED BY \"${old_ident}\" TO \"${new_ident}\";"
    sudo -u postgres -H psql -v ON_ERROR_STOP=1 -d "$TARGET_DB_NAME" -c "DROP OWNED BY \"${old_ident}\";"
    if [ "$drop_mapped" = "true" ]; then
      sudo -u postgres -H psql -v ON_ERROR_STOP=1 -c "DROP ROLE IF EXISTS \"${old_ident}\";"
    fi
    idx=$((idx + 1))
  done
fi

force_owner="${DB_RESTORE_FORCE_TARGET_OWNER:-}"
if [ -z "$force_owner" ]; then
  # Default to normalized ownership so restored objects match TARGET_DB_USER
  # even when dump ACLs/owners are preserved.
  force_owner="true"
fi

if [ "$force_owner" = "true" ]; then
  app_ident=$(sql_ident "$TARGET_DB_USER")
  db_ident=$(sql_ident "$TARGET_DB_NAME")
  sudo -u postgres -H psql -v ON_ERROR_STOP=1 -c "ALTER DATABASE \"${db_ident}\" OWNER TO \"${app_ident}\";"
  echo "[db-restore] ensuring non-system schemas/objects are owned by ${TARGET_DB_USER}"
  # Avoid `REASSIGN OWNED BY postgres` (fails on system-owned objects). Instead
  # transfer ownership only for non-system, non-extension-owned objects.
  sudo -u postgres -H psql -v ON_ERROR_STOP=1 -d "$TARGET_DB_NAME" -v owner="$TARGET_DB_USER" <<'SQL'
SELECT format('ALTER SCHEMA %I OWNER TO %I;', n.nspname, :'owner')
FROM pg_namespace n
WHERE n.nspname NOT IN ('pg_catalog','information_schema')
  AND n.nspname NOT LIKE 'pg_%'
  AND NOT EXISTS (
    SELECT 1
    FROM pg_depend d
    WHERE d.classid = 'pg_namespace'::regclass
      AND d.objid = n.oid
      AND d.deptype = 'e'
      AND d.refclassid = 'pg_extension'::regclass
  )
\gexec

WITH rels AS (
  SELECT
    n.nspname,
    c.relname,
    c.relkind,
    pg_get_userbyid(c.relowner) AS owner
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname NOT IN ('pg_catalog','information_schema')
    AND n.nspname NOT LIKE 'pg_%'
    AND c.relkind IN ('r','p','v','m','f')
    AND NOT EXISTS (
      SELECT 1
      FROM pg_depend d
      WHERE d.classid = 'pg_class'::regclass
        AND d.objid = c.oid
        AND d.deptype = 'e'
        AND d.refclassid = 'pg_extension'::regclass
    )
)
SELECT format(
  'ALTER %s %I.%I OWNER TO %I;',
  CASE relkind
    WHEN 'v' THEN 'VIEW'
    WHEN 'm' THEN 'MATERIALIZED VIEW'
    WHEN 'f' THEN 'FOREIGN TABLE'
    ELSE 'TABLE'
  END,
  nspname,
  relname,
  :'owner'
)
FROM rels
WHERE owner <> :'owner'
\gexec

WITH seqs AS (
  SELECT
    n.nspname,
    c.relname,
    pg_get_userbyid(c.relowner) AS owner
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname NOT IN ('pg_catalog','information_schema')
    AND n.nspname NOT LIKE 'pg_%'
    AND c.relkind = 'S'
    -- Sequences "owned by" a table column cannot have ownership changed directly.
    -- Their owner is derived from the owning table, so handle those via ALTER TABLE OWNER.
    AND NOT EXISTS (
      SELECT 1
      FROM pg_depend d
      WHERE d.classid = 'pg_class'::regclass
        AND d.objid = c.oid
        AND d.deptype = 'a'
        AND d.refclassid = 'pg_class'::regclass
    )
    AND NOT EXISTS (
      SELECT 1
      FROM pg_depend d
      WHERE d.classid = 'pg_class'::regclass
        AND d.objid = c.oid
        AND d.deptype = 'e'
        AND d.refclassid = 'pg_extension'::regclass
    )
)
SELECT format('ALTER SEQUENCE %I.%I OWNER TO %I;', nspname, relname, :'owner')
FROM seqs
WHERE owner <> :'owner'
\gexec

SELECT format(
  'ALTER FUNCTION %I.%I(%s) OWNER TO %I;',
  n.nspname,
  p.proname,
  pg_get_function_identity_arguments(p.oid),
  :'owner'
)
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname NOT IN ('pg_catalog','information_schema')
  AND n.nspname NOT LIKE 'pg_%'
  AND pg_get_userbyid(p.proowner) <> :'owner'
  AND NOT EXISTS (
    SELECT 1
    FROM pg_depend d
    WHERE d.classid = 'pg_proc'::regclass
      AND d.objid = p.oid
      AND d.deptype = 'e'
      AND d.refclassid = 'pg_extension'::regclass
  )
\gexec

WITH types AS (
  SELECT
    n.nspname,
    t.typname,
    t.typtype,
    pg_get_userbyid(t.typowner) AS owner
  FROM pg_type t
  JOIN pg_namespace n ON n.oid = t.typnamespace
  WHERE n.nspname NOT IN ('pg_catalog','information_schema')
    AND n.nspname NOT LIKE 'pg_%'
    AND t.typtype IN ('e','d')
    AND NOT EXISTS (
      SELECT 1
      FROM pg_depend d
      WHERE d.classid = 'pg_type'::regclass
        AND d.objid = t.oid
        AND d.deptype = 'e'
        AND d.refclassid = 'pg_extension'::regclass
    )
)
SELECT format(
  'ALTER %s %I.%I OWNER TO %I;',
  CASE typtype
    WHEN 'd' THEN 'DOMAIN'
    ELSE 'TYPE'
  END,
  nspname,
  typname,
  :'owner'
)
FROM types
WHERE owner <> :'owner'
\gexec
SQL
fi

grant_app_user="${DB_RESTORE_GRANT_APP_USER:-true}"
if [ "$grant_app_user" = "true" ]; then
  echo "[db-restore] granting schema/table privileges to ${TARGET_DB_USER}"
  sudo -u postgres -H psql -v ON_ERROR_STOP=1 -d "$TARGET_DB_NAME" -v grantee="$TARGET_DB_USER" -v owner="$TARGET_DB_USER" <<'SQL'
SELECT format('GRANT USAGE, CREATE ON SCHEMA %I TO %I;', nspname, :'grantee')
FROM pg_namespace
WHERE nspname NOT IN ('pg_catalog','information_schema') AND nspname NOT LIKE 'pg_%'
\gexec

SELECT format('GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA %I TO %I;', nspname, :'grantee')
FROM pg_namespace
WHERE nspname NOT IN ('pg_catalog','information_schema') AND nspname NOT LIKE 'pg_%'
\gexec

SELECT format('GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA %I TO %I;', nspname, :'grantee')
FROM pg_namespace
WHERE nspname NOT IN ('pg_catalog','information_schema') AND nspname NOT LIKE 'pg_%'
\gexec

SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I GRANT ALL ON TABLES TO %I;', :'owner', nspname, :'grantee')
FROM pg_namespace
WHERE nspname NOT IN ('pg_catalog','information_schema') AND nspname NOT LIKE 'pg_%'
\gexec

SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I GRANT ALL ON SEQUENCES TO %I;', :'owner', nspname, :'grantee')
FROM pg_namespace
WHERE nspname NOT IN ('pg_catalog','information_schema') AND nspname NOT LIKE 'pg_%'
\gexec
SQL
fi

set_search_path="${DB_RESTORE_SET_SEARCH_PATH:-true}"
if [ "$set_search_path" = "true" ]; then
  desired_search_path="${DB_RESTORE_SEARCH_PATH:-}"
  if [ -z "$desired_search_path" ]; then
    desired_search_path=$(
      sudo -u postgres -H psql -v ON_ERROR_STOP=1 -d "$TARGET_DB_NAME" -tAc "
WITH user_schemas AS (
  SELECT n.oid, n.nspname
  FROM pg_namespace n
  WHERE n.nspname NOT IN ('pg_catalog','information_schema')
    AND n.nspname NOT LIKE 'pg_%'
    AND n.nspname <> 'public'
    AND NOT EXISTS (
      SELECT 1
      FROM pg_depend d
      WHERE d.classid = 'pg_namespace'::regclass
        AND d.objid = n.oid
        AND d.deptype = 'e'
        AND d.refclassid = 'pg_extension'::regclass
    )
),
schemas_with_rels AS (
  SELECT DISTINCT n.nspname
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname IN (SELECT nspname FROM user_schemas)
    AND c.relkind IN ('r','p','v','m','f')
    AND NOT EXISTS (
      SELECT 1
      FROM pg_depend d
      WHERE d.classid = 'pg_class'::regclass
        AND d.objid = c.oid
        AND d.deptype = 'e'
        AND d.refclassid = 'pg_extension'::regclass
    )
)
SELECT CASE
  WHEN EXISTS (SELECT 1 FROM schemas_with_rels WHERE nspname='main')
    THEN quote_ident('main') || ', public'
  WHEN (SELECT count(*) FROM schemas_with_rels)=1
    THEN (SELECT quote_ident(nspname) FROM schemas_with_rels LIMIT 1) || ', public'
  ELSE ''
END;
" | tr -d ' \t\r\n'
    )
  fi

  if [ -n "$desired_search_path" ]; then
    app_ident=$(sql_ident "$TARGET_DB_USER")
    db_ident=$(sql_ident "$TARGET_DB_NAME")
    sp_lit=$(sql_literal "$desired_search_path")
    sudo -u postgres -H psql -v ON_ERROR_STOP=1 -c "ALTER ROLE \"${app_ident}\" IN DATABASE \"${db_ident}\" SET search_path = '${sp_lit}';"
  fi
fi

rm -rf "$tmpdir"
echo "[db-restore] restore complete"
EOF

chmod +x /opt/infrazero/db/restore.sh

cat > /etc/cron.d/infrazero-db-backup <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

20 3 * * * root /opt/infrazero/db/backup.sh >> /var/log/infrazero-db-backup.log 2>&1
EOF

chmod 0644 /etc/cron.d/infrazero-db-backup

beacon_status "restoring_backups" "Restoring database backups" 70

restore_databases_from_s3

# ------------------------------------------------------------------ #
#  Streaming Replication (primary side)                                #
# ------------------------------------------------------------------ #

setup_replication_primary() {
  local replica_enabled="${DB_REPLICA_ENABLED:-false}"
  if [ "$replica_enabled" != "true" ]; then
    echo "[db] replication not enabled; skipping primary replication setup"
    return 0
  fi

  local replica_count="${DB_REPLICA_COUNT:-0}"
  if [ "$replica_count" -lt 1 ] 2>/dev/null; then
    echo "[db] DB_REPLICA_COUNT < 1; skipping replication setup"
    return 0
  fi

  echo "[db] configuring primary for streaming replication (${replica_count} replicas)"

  # WAL settings for replication
  set_conf "wal_level" "replica"
  set_conf "max_wal_senders" "$((replica_count + 2))"
  set_conf "wal_keep_size" "'512MB'"
  set_conf "hot_standby" "on"

  # Create replication user if not exists
  local repl_user="replicator"
  local repl_password="${DB_REPLICATION_PASSWORD:-$(openssl rand -hex 16)}"
  local repl_user_lit
  repl_user_lit=$(sql_escape "$repl_user")
  local repl_pw_lit
  repl_pw_lit=$(sql_escape "$repl_password")

  local user_exists
  user_exists=$(psql_as_postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='${repl_user_lit}'" || true)
  if [ "$user_exists" != "1" ]; then
    psql_as_postgres -c "CREATE ROLE \"${repl_user}\" WITH REPLICATION LOGIN PASSWORD '${repl_pw_lit}';"
    echo "[db] created replication role: ${repl_user}"
  else
    psql_as_postgres -c "ALTER ROLE \"${repl_user}\" WITH REPLICATION PASSWORD '${repl_pw_lit}';"
    echo "[db] updated replication role: ${repl_user}"
  fi

  # Add replication entries to pg_hba.conf for replica CIDRs
  local replica_cidrs="${DB_REPLICA_CIDRS:-}"
  if [ -n "$replica_cidrs" ]; then
    local HBA_REPL_BEGIN="# BEGIN INFRAZERO REPLICATION"
    local HBA_REPL_END="# END INFRAZERO REPLICATION"

    # Remove existing replication block
    if [ -f "$HBA_CONF" ]; then
      awk -v begin="$HBA_REPL_BEGIN" -v end="$HBA_REPL_END" '
        $0==begin {skip=1; next}
        $0==end {skip=0; next}
        skip==1 {next}
        {print}
      ' "$HBA_CONF" > "${HBA_CONF}.tmp" && mv "${HBA_CONF}.tmp" "$HBA_CONF"
    fi

    {
      echo "$HBA_REPL_BEGIN"
      IFS=',' read -r -a cidrs_arr <<< "$replica_cidrs"
      for cidr in "${cidrs_arr[@]}"; do
        cidr=$(echo "$cidr" | xargs)
        if [ -n "$cidr" ]; then
          echo "host replication ${repl_user} ${cidr} scram-sha-256"
          echo "host all ${repl_user} ${cidr} scram-sha-256"
        fi
      done
      echo "$HBA_REPL_END"
    } >> "$HBA_CONF"
  fi

  systemctl reload postgresql || systemctl restart postgresql
  echo "[db] primary replication setup complete"
}

setup_replication_primary

# ------------------------------------------------------------------ #
#  Patroni HA Setup (optional)                                         #
# ------------------------------------------------------------------ #

setup_patroni() {
  local patroni_enabled="${PATRONI_ENABLED:-false}"
  if [ "$patroni_enabled" != "true" ]; then
    echo "[db] Patroni not enabled; skipping"
    return 0
  fi

  require_env "PATRONI_SCOPE"
  require_env "PATRONI_ETCD_HOSTS"

  local patroni_name="${PATRONI_NAME:-$(hostname)}"
  local patroni_scope="${PATRONI_SCOPE}"
  local etcd_hosts="${PATRONI_ETCD_HOSTS}"
  local patroni_rest_port="${PATRONI_REST_PORT:-8008}"
  local repl_user="${DB_REPLICATION_USER:-replicator}"
  local repl_password="${DB_REPLICATION_PASSWORD:-}"
  local superuser_password="${PATRONI_SUPERUSER_PASSWORD:-}"

  # Resolve private IP for connect_address
  local connect_address=""
  if [ -n "${PRIVATE_CIDR:-}" ] && command -v python3 >/dev/null 2>&1; then
    connect_address=$(python3 - <<'PY'
import ipaddress, os, subprocess
cidr = os.environ.get("PRIVATE_CIDR", "")
try:
    net = ipaddress.ip_network(cidr, strict=False)
except Exception:
    raise SystemExit(1)
output = subprocess.check_output(["ip", "-4", "-o", "addr", "show"]).decode()
for line in output.splitlines():
    parts = line.split()
    if len(parts) < 4:
        continue
    addr = parts[3].split("/")[0]
    try:
        if ipaddress.ip_address(addr) in net:
            print(addr)
            raise SystemExit(0)
    except Exception:
        continue
raise SystemExit(1)
PY
    ) || true
  fi

  if [ -z "$connect_address" ]; then
    echo "[db] unable to determine private IP for Patroni connect_address" >&2
    return 1
  fi

  echo "[db] installing Patroni"
  apt-get install -y python3-pip python3-venv || true

  python3 -m venv /opt/patroni/venv
  /opt/patroni/venv/bin/pip install --upgrade pip
  /opt/patroni/venv/bin/pip install 'patroni[etcd3]' psycopg2-binary

  mkdir -p /etc/patroni

  # Build etcd3 hosts list: "host1:2391,host2:2391" → YAML list
  local etcd_hosts_yaml=""
  IFS=',' read -r -a etcd_arr <<< "$etcd_hosts"
  for h in "${etcd_arr[@]}"; do
    h=$(echo "$h" | xargs)
    if [ -n "$h" ]; then
      # Ensure port is present
      if [[ "$h" != *:* ]]; then
        h="${h}:2391"
      fi
      etcd_hosts_yaml="${etcd_hosts_yaml}    - ${h}
"
    fi
  done

  local pg_data_dir="${DEFAULT_DATA_DIR:-/var/lib/postgresql/${PG_MAJOR}/main}"
  local pg_bin_dir="/usr/lib/postgresql/${PG_MAJOR}/bin"
  local pg_conf_dir="/etc/postgresql/${PG_MAJOR}/main"

  # Escape passwords for YAML (wrap in single quotes, escape internal single quotes)
  local repl_password_yaml
  repl_password_yaml=$(printf '%s' "$repl_password" | sed "s/'/''/g")
  local superuser_password_yaml
  superuser_password_yaml=$(printf '%s' "$superuser_password" | sed "s/'/''/g")

  cat > /etc/patroni/patroni.yml <<PATRONI_EOF
scope: ${patroni_scope}
name: ${patroni_name}

restapi:
  listen: 0.0.0.0:${patroni_rest_port}
  connect_address: ${connect_address}:${patroni_rest_port}

etcd3:
  hosts:
${etcd_hosts_yaml}
bootstrap:
  dcs:
    ttl: 30
    loop_wait: 10
    retry_timeout: 10
    maximum_lag_on_failover: 1048576
    postgresql:
      use_pg_rewind: true
      use_slots: true
      parameters:
        wal_level: replica
        hot_standby: "on"
        max_wal_senders: 5
        max_replication_slots: 5
        wal_keep_size: 512MB

postgresql:
  listen: 0.0.0.0:5432
  connect_address: ${connect_address}:5432
  data_dir: ${pg_data_dir}
  config_dir: ${pg_conf_dir}
  bin_dir: ${pg_bin_dir}
  pgpass: /tmp/pgpass0
  authentication:
    replication:
      username: ${repl_user}
      password: '${repl_password_yaml}'
    superuser:
      username: postgres
      password: '${superuser_password_yaml}'
  parameters:
    unix_socket_directories: '/var/run/postgresql'
  pg_hba:
    - local all postgres peer
    - local all all peer
    - host replication ${repl_user} 0.0.0.0/0 scram-sha-256
    - host all all 0.0.0.0/0 scram-sha-256

tags:
  nofailover: false
  noloadbalancer: false
  clonefrom: false
  nosync: false
PATRONI_EOF

  chmod 600 /etc/patroni/patroni.yml
  chown postgres:postgres /etc/patroni/patroni.yml

  # Stop PostgreSQL — Patroni will manage it
  echo "[db] stopping PostgreSQL systemd unit (Patroni will manage it)"
  systemctl stop postgresql || true
  systemctl stop "postgresql@${PG_MAJOR}-main" || true
  systemctl disable postgresql || true
  systemctl disable "postgresql@${PG_MAJOR}-main" || true

  # Ensure postgres user owns config and data dirs (Patroni writes pg_hba.conf etc.)
  chown -R postgres:postgres "/etc/postgresql/${PG_MAJOR}/main/" || true
  chown -R postgres:postgres "${pg_data_dir}" || true

  # Set postgres superuser password before Patroni takes over
  # (Patroni needs TCP auth with password; db.sh uses peer auth which has no password)
  if [ -n "$superuser_password" ]; then
    echo "[db] setting postgres superuser password for Patroni"
    # Start PG temporarily to set password
    sudo -u postgres pg_ctlcluster "${PG_MAJOR}" main start 2>/dev/null || true
    for _pw_attempt in {1..10}; do
      if sudo -u postgres pg_isready -q 2>/dev/null; then break; fi
      sleep 2
    done
    sudo -u postgres psql -c "ALTER USER postgres PASSWORD '$(printf '%s' "$superuser_password" | sed "s/'/''/g")';" 2>/dev/null || true
    sudo -u postgres pg_ctlcluster "${PG_MAJOR}" main stop 2>/dev/null || true
  fi

  # Remove standby.signal if present — Patroni manages replication itself
  rm -f "${pg_data_dir}/standby.signal" "${pg_data_dir}/recovery.signal" || true

  # Create Patroni systemd unit
  cat > /etc/systemd/system/patroni.service <<'UNIT_EOF'
[Unit]
Description=Patroni PostgreSQL HA
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=postgres
Group=postgres
ExecStart=/opt/patroni/venv/bin/patroni /etc/patroni/patroni.yml
ExecReload=/bin/kill -s HUP $MAINPID
KillMode=process
TimeoutSec=30
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
UNIT_EOF

  systemctl daemon-reload
  systemctl enable --now patroni

  # Wait for Patroni to start
  echo "[db] waiting for Patroni to start"
  for attempt in $(seq 1 30); do
    if curl -sf "http://127.0.0.1:${patroni_rest_port}/health" >/dev/null 2>&1; then
      echo "[db] Patroni is healthy (attempt ${attempt})"
      break
    fi
    if [ "$attempt" -eq 30 ]; then
      echo "[db] Patroni did not become healthy" >&2
      systemctl status patroni --no-pager || true
      journalctl -u patroni -n 50 --no-pager || true
      return 1
    fi
    sleep 5
  done

  # Install patronictl wrapper
  ln -sf /opt/patroni/venv/bin/patronictl /usr/local/bin/patronictl

  echo "[db] Patroni setup complete (scope: ${patroni_scope}, name: ${patroni_name})"
}

setup_patroni

beacon_status "complete" "Bootstrap complete" 100

echo "[db] $(date -Is) complete"
