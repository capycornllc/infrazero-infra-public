#!/usr/bin/env bash
set -euo pipefail

echo "[db-replica] $(date -Is) start"

load_env() {
  local file="$1"
  if [ -f "$file" ]; then
    set -a
    # shellcheck disable=SC1090
    source "$file"
    set +a
  fi
}

load_env /etc/infrazero/db-replica.env
load_env /etc/infrazero/db.env
load_env /etc/infrazero/network.env

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[db-replica] missing required env: $name" >&2
    exit 1
  fi
}

require_env "DB_TYPE"
require_env "DB_VERSION"
require_env "DB_PRIMARY_HOST"
require_env "DB_REPLICATION_USER"
require_env "DB_REPLICATION_PASSWORD"

db_type_lower=$(echo "$DB_TYPE" | tr '[:upper:]' '[:lower:]')
if [ "$db_type_lower" != "postgresql" ] && [ "$db_type_lower" != "postgres" ]; then
  echo "[db-replica] unsupported DB_TYPE: $DB_TYPE (only postgresql supported)" >&2
  exit 1
fi

PG_MAJOR="${DB_VERSION%%.*}"
if [ -z "$PG_MAJOR" ]; then
  echo "[db-replica] unable to parse DB_VERSION: $DB_VERSION" >&2
  exit 1
fi

# ------------------------------------------------------------------ #
#  Install PostgreSQL                                                  #
# ------------------------------------------------------------------ #

install_packages() {
  if ! command -v apt-get >/dev/null 2>&1; then
    return
  fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y curl ca-certificates jq gnupg lsb-release

  if ! apt-cache show "postgresql-${PG_MAJOR}" >/dev/null 2>&1; then
    echo "[db-replica] enabling PGDG repo for PostgreSQL ${PG_MAJOR}"
    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/pgdg.gpg
    echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list
    apt-get update -y
  fi

  apt-get install -y "postgresql-${PG_MAJOR}" "postgresql-client-${PG_MAJOR}"
}

install_packages

# ------------------------------------------------------------------ #
#  Stop PostgreSQL and prepare data directory                          #
# ------------------------------------------------------------------ #

systemctl stop postgresql || true
systemctl stop "postgresql@${PG_MAJOR}-main" || true

DEFAULT_DATA_DIR="/var/lib/postgresql/${PG_MAJOR}/main"
PG_CONF="/etc/postgresql/${PG_MAJOR}/main/postgresql.conf"

# Ensure a cluster config exists in /etc/postgresql — pg_createcluster creates
# both the config and a fresh data dir. We then wipe the data dir and replace
# it with pg_basebackup output. This avoids the "move_conffile" error that
# occurs when pg_createcluster --no-initdb can't find postgresql.conf in the
# data directory (Debian/Ubuntu keeps configs in /etc, not the data dir).
if [ ! -f "$PG_CONF" ]; then
  # Remove stale data so pg_createcluster can initialise cleanly
  rm -rf "$DEFAULT_DATA_DIR"
  mkdir -p "$DEFAULT_DATA_DIR"
  chown postgres:postgres "$DEFAULT_DATA_DIR"
  chmod 700 "$DEFAULT_DATA_DIR"
  pg_createcluster "$PG_MAJOR" main -d "$DEFAULT_DATA_DIR"
  pg_ctlcluster "$PG_MAJOR" main stop 2>/dev/null || true
fi

# Wipe data dir contents (keep the directory itself and /etc config intact)
rm -rf "${DEFAULT_DATA_DIR:?}"/*
chown postgres:postgres "$DEFAULT_DATA_DIR"
chmod 700 "$DEFAULT_DATA_DIR"

# ------------------------------------------------------------------ #
#  Wait for primary to be ready                                        #
# ------------------------------------------------------------------ #

echo "[db-replica] waiting for primary at ${DB_PRIMARY_HOST}:5432"
for attempt in $(seq 1 60); do
  if pg_isready -h "$DB_PRIMARY_HOST" -p 5432 -U "$DB_REPLICATION_USER" -q 2>/dev/null; then
    echo "[db-replica] primary is ready (attempt ${attempt})"
    break
  fi
  if [ "$attempt" -eq 60 ]; then
    echo "[db-replica] primary not ready after 60 attempts" >&2
    exit 1
  fi
  sleep 5
done

# ------------------------------------------------------------------ #
#  pg_basebackup from primary                                          #
# ------------------------------------------------------------------ #

echo "[db-replica] running pg_basebackup from ${DB_PRIMARY_HOST}"

sudo -u postgres PGPASSWORD="$DB_REPLICATION_PASSWORD" pg_basebackup \
  -h "$DB_PRIMARY_HOST" \
  -p 5432 \
  -U "$DB_REPLICATION_USER" \
  -D "$DEFAULT_DATA_DIR" \
  -Fp -Xs -P -R

echo "[db-replica] pg_basebackup complete"

# pg_basebackup with -R creates standby.signal and sets primary_conninfo
# in postgresql.auto.conf. Verify they exist.
if [ ! -f "$DEFAULT_DATA_DIR/standby.signal" ]; then
  echo "[db-replica] standby.signal not found; creating manually"
  sudo -u postgres touch "$DEFAULT_DATA_DIR/standby.signal"
fi

# Verify primary_conninfo was written
if ! grep -q "primary_conninfo" "$DEFAULT_DATA_DIR/postgresql.auto.conf" 2>/dev/null; then
  echo "[db-replica] primary_conninfo not found in postgresql.auto.conf; writing manually"
  cat >> "$DEFAULT_DATA_DIR/postgresql.auto.conf" <<EOF
primary_conninfo = 'host=${DB_PRIMARY_HOST} port=5432 user=${DB_REPLICATION_USER} password=${DB_REPLICATION_PASSWORD} sslmode=prefer'
EOF
  chown postgres:postgres "$DEFAULT_DATA_DIR/postgresql.auto.conf"
fi

# ------------------------------------------------------------------ #
#  Configure PostgreSQL for hot standby                                #
# ------------------------------------------------------------------ #

PG_CONF="/etc/postgresql/${PG_MAJOR}/main/postgresql.conf"

set_conf() {
  local key="$1"
  local value="$2"
  if [ -f "$PG_CONF" ] && grep -qE "^[#\\s]*${key}\\s*=" "$PG_CONF"; then
    sed -i "s#^[#\\s]*${key}\\s*=.*#${key} = ${value}#g" "$PG_CONF"
  elif [ -f "$PG_CONF" ]; then
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
set_conf "hot_standby" "on"
set_conf "hot_standby_feedback" "on"

# ------------------------------------------------------------------ #
#  Configure pg_hba.conf for read-only access from K3s nodes           #
# ------------------------------------------------------------------ #

HBA_CONF="/etc/postgresql/${PG_MAJOR}/main/pg_hba.conf"

if [ -f "$HBA_CONF" ]; then
  HBA_BEGIN="# BEGIN INFRAZERO REPLICA"
  HBA_END="# END INFRAZERO REPLICA"

  # Remove existing block if present
  awk -v begin="$HBA_BEGIN" -v end="$HBA_END" '
    $0==begin {skip=1; next}
    $0==end {skip=0; next}
    skip==1 {next}
    {print}
  ' "$HBA_CONF" > "${HBA_CONF}.tmp" && mv "${HBA_CONF}.tmp" "$HBA_CONF"

  {
    echo "$HBA_BEGIN"
    # Allow K3s nodes to connect for read queries
    if [ -n "${K3S_NODE_CIDRS:-}" ]; then
      IFS=',' read -r -a cidrs <<< "$K3S_NODE_CIDRS"
      for cidr in "${cidrs[@]}"; do
        cidr=$(echo "$cidr" | xargs)
        if [ -n "$cidr" ]; then
          echo "host all all ${cidr} scram-sha-256"
        fi
      done
    fi
    # Allow WireGuard admin access
    if [ -n "${WG_CIDR:-}" ]; then
      echo "host all all ${WG_CIDR} scram-sha-256"
    fi
    echo "$HBA_END"
  } >> "$HBA_CONF"
fi

# ------------------------------------------------------------------ #
#  Start PostgreSQL in standby mode                                    #
# ------------------------------------------------------------------ #

chown -R postgres:postgres "$DEFAULT_DATA_DIR"

systemctl enable postgresql
systemctl start postgresql

echo "[db-replica] waiting for PostgreSQL to start"
for attempt in $(seq 1 30); do
  if sudo -u postgres pg_isready -q 2>/dev/null; then
    echo "[db-replica] PostgreSQL is ready (standby mode)"
    break
  fi
  if [ "$attempt" -eq 30 ]; then
    echo "[db-replica] PostgreSQL did not start" >&2
    systemctl status postgresql --no-pager || true
    journalctl -u postgresql -n 50 --no-pager || true
    exit 1
  fi
  sleep 2
done

# Verify we're actually in recovery (standby) mode
in_recovery=$(sudo -u postgres psql -tAc "SELECT pg_is_in_recovery();" 2>/dev/null || true)
if [ "$in_recovery" != "t" ]; then
  echo "[db-replica] WARNING: PostgreSQL is NOT in recovery mode; expected standby" >&2
else
  echo "[db-replica] confirmed: PostgreSQL is in recovery (standby) mode"
fi

# Show replication status
echo "[db-replica] replication status:"
sudo -u postgres psql -c "SELECT status, sender_host, sender_port, conninfo FROM pg_stat_wal_receiver;" 2>/dev/null || true

echo "[db-replica] $(date -Is) complete"
