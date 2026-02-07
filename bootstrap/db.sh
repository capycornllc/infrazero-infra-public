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
  )' >/dev/null 2>&1; then
  echo "[db] DATABASES_JSON entries must include non-empty name/user/password/backup_age_public_key (no whitespace in name/user)" >&2
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
    if [ -n "${WG_CIDR:-}" ]; then
      echo "host ${db_name} ${db_user} ${WG_CIDR} scram-sha-256"
    fi
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

ensure_databases

scrub_databases_json_private_b64_from_run_sh() {
  # The per-DB Age private keys are only needed during bootstrap restore.
  # Scrub them from the persisted bootstrap script to avoid leaving them on disk.
  if [ -f /opt/infrazero/bootstrap/run.sh ]; then
    sed -i 's/^export DATABASES_JSON_PRIVATE_B64=.*$/export DATABASES_JSON_PRIVATE_B64=""/' /opt/infrazero/bootstrap/run.sh || true
  fi
}

restore_databases_from_s3() {
  if [ "$fresh_cluster" != "true" ]; then
    echo "[db] existing PostgreSQL data directory detected; skipping S3 restore"
    unset DATABASES_JSON_PRIVATE_B64
    scrub_databases_json_private_b64_from_run_sh
    return 0
  fi

  if [ -z "${DATABASES_JSON_PRIVATE_B64:-}" ]; then
    echo "[db] DATABASES_JSON_PRIVATE_B64 not set; skipping restore"
    scrub_databases_json_private_b64_from_run_sh
    return 0
  fi

  local tmpdir
  tmpdir=$(mktemp -d /run/infrazero-db-restore.XXXX)
  chmod 700 "$tmpdir"

  echo "$DATABASES_JSON_PRIVATE_B64" | base64 -d > "$tmpdir/databases.json" || {
    echo "[db] unable to decode DATABASES_JSON_PRIVATE_B64" >&2
    rm -rf "$tmpdir"
    unset DATABASES_JSON_PRIVATE_B64
    scrub_databases_json_private_b64_from_run_sh
    return 1
  }
  chmod 600 "$tmpdir/databases.json" || true

  if ! jq -e 'type=="array"' "$tmpdir/databases.json" >/dev/null 2>&1; then
    echo "[db] decoded DATABASES_JSON_PRIVATE_B64 is not a JSON array" >&2
    rm -rf "$tmpdir"
    unset DATABASES_JSON_PRIVATE_B64
    scrub_databases_json_private_b64_from_run_sh
    return 1
  fi

  echo "[db] restoring latest DB backups from S3 (fresh cluster)"
  while IFS= read -r db_b64; do
    db=$(echo "$db_b64" | base64 -d)
    db_name=$(echo "$db" | jq -r '.name')
    db_user=$(echo "$db" | jq -r '.user')

    pk=$(jq -r --arg name "$db_name" '.[] | select(.name==$name) | .backup_age_private_key // empty' "$tmpdir/databases.json" | tail -n 1)
    if [ -z "$pk" ]; then
      echo "[db] no backup_age_private_key found for ${db_name}; skipping restore" >&2
      continue
    fi

    local manifest_key="db/${db_name}/latest-dump.json"
    if ! aws --endpoint-url "$S3_ENDPOINT" s3 cp "s3://${DB_BACKUP_BUCKET}/${manifest_key}" "$tmpdir/latest-dump.json" >/dev/null 2>&1; then
      echo "[db] no latest-dump manifest found for ${db_name}; skipping restore"
      continue
    fi

    key=$(jq -r '.key' "$tmpdir/latest-dump.json")
    sha=$(jq -r '.sha256' "$tmpdir/latest-dump.json")

    if [ -z "$key" ] || [ "$key" = "null" ]; then
      echo "[db] latest-dump manifest missing key for ${db_name}" >&2
      rm -f "$tmpdir/latest-dump.json"
      continue
    fi
    if [ -z "$sha" ] || [ "$sha" = "null" ]; then
      echo "[db] latest-dump manifest missing sha256 for ${db_name}" >&2
      rm -f "$tmpdir/latest-dump.json"
      continue
    fi

    aws --endpoint-url "$S3_ENDPOINT" s3 cp "s3://${DB_BACKUP_BUCKET}/${key}" "$tmpdir/dump.age"
    echo "$sha  $tmpdir/dump.age" | sha256sum -c -

    echo "$pk" > "$tmpdir/age.key"
    chmod 600 "$tmpdir/age.key"
    age -d -i "$tmpdir/age.key" -o "$tmpdir/dump.sql.gz" "$tmpdir/dump.age"

    user_ident=$(sql_ident "$db_user")
    db_ident=$(sql_ident "$db_name")
    db_lit=$(sql_escape "$db_name")

    echo "[db] restoring ${db_name}"
    psql_as_postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${db_lit}';" || true
    psql_as_postgres -c "DROP DATABASE IF EXISTS \"${db_ident}\";"
    psql_as_postgres -c "CREATE DATABASE \"${db_ident}\" OWNER \"${user_ident}\";"
    psql_as_postgres -c "GRANT ALL PRIVILEGES ON DATABASE \"${db_ident}\" TO \"${user_ident}\";"

    gunzip -c "$tmpdir/dump.sql.gz" | sed -E '/^(GRANT|REVOKE) /d;/^ALTER (TABLE|SEQUENCE|FUNCTION|SCHEMA|VIEW|MATERIALIZED VIEW|DATABASE|TYPE|DOMAIN|EXTENSION) .* OWNER TO /d;/^ALTER DEFAULT PRIVILEGES /d' | \
      sudo -u postgres -H psql -v ON_ERROR_STOP=1 -d "$db_name"

    normalize_db_ownership_and_privileges "$db_name" "$db_user"

    rm -f "$tmpdir/age.key" "$tmpdir/dump.age" "$tmpdir/dump.sql.gz" "$tmpdir/latest-dump.json"
  done < <(echo "$DATABASES_JSON_EFFECTIVE" | jq -cr '.[] | @base64')

  rm -rf "$tmpdir"
  unset DATABASES_JSON_PRIVATE_B64
  scrub_databases_json_private_b64_from_run_sh
  echo "[db] restore complete"
}

restore_databases_from_s3

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
      if [ -n "${WG_CIDR:-}" ]; then
        echo "host ${db_name} ${db_user} ${WG_CIDR} scram-sha-256"
      fi
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

  apply_postgres_config

  ensure_db_role

db_lit=$(sql_literal "$TARGET_DB_NAME")
db_ident=$(sql_ident "$TARGET_DB_NAME")
role_ident=$(sql_ident "$TARGET_DB_USER")

echo "[db-restore] wiping database ${TARGET_DB_NAME}"
sudo -u postgres -H psql -v ON_ERROR_STOP=1 -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${db_lit}';"
sudo -u postgres -H psql -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS \"${db_ident}\";"
sudo -u postgres -H psql -v ON_ERROR_STOP=1 -c "CREATE DATABASE \"${db_ident}\" OWNER \"${role_ident}\";"

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
   restore_args=(--no-owner -d "$TARGET_DB_NAME")
   if [ "$skip_acl" = "true" ]; then
     restore_args+=(--no-privileges)
   fi
   "${stream_cmd[@]}" | sudo -u postgres -H pg_restore "${restore_args[@]}"
 else
   if [ "$skip_acl" = "true" ]; then
    "${stream_cmd[@]}" | sed -E '/^(GRANT|REVOKE) /d;/^ALTER (TABLE|SEQUENCE|FUNCTION|SCHEMA|VIEW|MATERIALIZED VIEW|DATABASE|TYPE|DOMAIN|EXTENSION) .* OWNER TO /d;/^ALTER DEFAULT PRIVILEGES /d' | \
       sudo -u postgres -H psql -v ON_ERROR_STOP=1 -d "$TARGET_DB_NAME"
   else
     "${stream_cmd[@]}" | sudo -u postgres -H psql -v ON_ERROR_STOP=1 -d "$TARGET_DB_NAME"
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
  # If we're skipping ACLs or doing role mapping, normalize ownership so the
  # restored DB works even when dumps were taken from a different role.
  if [ "$skip_acl" = "true" ] || [ -n "$role_map" ]; then
    force_owner="true"
  else
    force_owner="false"
  fi
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

echo "[db] $(date -Is) complete"
