#!/usr/bin/env bash
set -euo pipefail

echo "[pgbouncer] $(date -Is) start"

BOOTSTRAP_ROLE="pgbouncer"

load_env() {
  local file="$1"
  if [ -f "$file" ]; then
    set -a
    # shellcheck disable=SC1090
    source "$file"
    set +a
  fi
}

load_env /etc/infrazero/pgbouncer.env
load_env /etc/infrazero/network.env

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[pgbouncer] missing required env: $name" >&2
    return 1 2>/dev/null || exit 1
  fi
}

require_env "DB_PRIMARY_HOST"
require_env "PGBOUNCER_AUTH_USER"
require_env "PGBOUNCER_AUTH_PASSWORD"

DB_PRIMARY_HOST="${DB_PRIMARY_HOST}"
DB_REPLICA_HOSTS="${DB_REPLICA_HOSTS:-}"
PGBOUNCER_AUTH_USER="${PGBOUNCER_AUTH_USER}"
PGBOUNCER_AUTH_PASSWORD="${PGBOUNCER_AUTH_PASSWORD}"
PGBOUNCER_WRITE_PORT="${PGBOUNCER_WRITE_PORT:-5432}"
PGBOUNCER_READ_PORT="${PGBOUNCER_READ_PORT:-5433}"
PGBOUNCER_POOL_MODE="${PGBOUNCER_POOL_MODE:-transaction}"
PGBOUNCER_MAX_CLIENT_CONN="${PGBOUNCER_MAX_CLIENT_CONN:-200}"
PGBOUNCER_DEFAULT_POOL_SIZE="${PGBOUNCER_DEFAULT_POOL_SIZE:-20}"
PATRONI_REST_PORT="${PATRONI_REST_PORT:-8008}"

# ------------------------------------------------------------------ #
#  Install PgBouncer                                                   #
# ------------------------------------------------------------------ #

install_packages() {
  beacon_status "installing_packages" "Installing PgBouncer" 15
  export DEBIAN_FRONTEND=noninteractive
  timeout 300 apt-get update -y || { apt-get clean; timeout 300 apt-get update -y; }
  timeout 600 apt-get install -y pgbouncer curl jq postgresql-client
}

install_packages

# ------------------------------------------------------------------ #
#  Resolve private IP                                                  #
# ------------------------------------------------------------------ #

resolve_private_ip() {
  if [ -n "${PRIVATE_CIDR:-}" ] && command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY'
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
  fi
}

LISTEN_ADDR=$(resolve_private_ip || echo "0.0.0.0")

# ------------------------------------------------------------------ #
#  Write PgBouncer configs                                             #
# ------------------------------------------------------------------ #

beacon_status "configuring_pools" "Configuring connection pools" 50

mkdir -p /etc/pgbouncer

write_userlist() {
  local path="$1"
  local user="$2"
  local password="$3"
  # PgBouncer expects MD5 or SCRAM hash, or plain "password" in quotes
  echo "\"${user}\" \"${password}\"" > "$path"
  chmod 640 "$path"
  chown postgres:postgres "$path"
}

write_pgbouncer_ini() {
  local config_path="$1"
  local listen_port="$2"
  local backend_host="$3"
  local backend_port="${4:-5432}"
  local userlist_path="$5"

  cat > "$config_path" <<EOF
[databases]
* = host=${backend_host} port=${backend_port}

[pgbouncer]
listen_addr = ${LISTEN_ADDR}
listen_port = ${listen_port}
auth_type = md5
auth_file = ${userlist_path}
pool_mode = ${PGBOUNCER_POOL_MODE}
max_client_conn = ${PGBOUNCER_MAX_CLIENT_CONN}
default_pool_size = ${PGBOUNCER_DEFAULT_POOL_SIZE}
server_reset_query = DISCARD ALL
ignore_startup_parameters = extra_float_digits
log_connections = 0
log_disconnections = 0
log_pooler_errors = 1
pidfile = /var/run/postgresql/pgbouncer-${listen_port}.pid
unix_socket_dir = /var/run/postgresql
EOF
  chmod 640 "$config_path"
  chown postgres:postgres "$config_path"
}

# Determine read backends: all replicas if available, else primary
# PgBouncer supports comma-separated host list for round-robin (1.21+)
read_backend="${DB_PRIMARY_HOST}"
if [ -n "$DB_REPLICA_HOSTS" ]; then
  # Replace commas with commas (already comma-separated) — just trim whitespace
  read_backend=$(echo "$DB_REPLICA_HOSTS" | tr ',' '\n' | xargs | tr ' ' ',')
fi

write_userlist /etc/pgbouncer/userlist-write.txt "$PGBOUNCER_AUTH_USER" "$PGBOUNCER_AUTH_PASSWORD"
write_userlist /etc/pgbouncer/userlist-read.txt "$PGBOUNCER_AUTH_USER" "$PGBOUNCER_AUTH_PASSWORD"

write_pgbouncer_ini \
  /etc/pgbouncer/pgbouncer-write.ini \
  "$PGBOUNCER_WRITE_PORT" \
  "$DB_PRIMARY_HOST" \
  5432 \
  /etc/pgbouncer/userlist-write.txt

write_pgbouncer_ini \
  /etc/pgbouncer/pgbouncer-read.ini \
  "$PGBOUNCER_READ_PORT" \
  "$read_backend" \
  5432 \
  /etc/pgbouncer/userlist-read.txt

# ------------------------------------------------------------------ #
#  Patroni leader watcher: update-pgbouncer.sh                        #
# ------------------------------------------------------------------ #

# This script runs on the pgbouncer server via a systemd timer.
# It polls Patroni REST API on all DB nodes to find the current leader
# and updates the write pool backend if it changed.

cat > /usr/local/sbin/update-pgbouncer.sh <<'WATCHER_EOF'
#!/usr/bin/env bash
set -euo pipefail

WRITE_CONFIG="/etc/pgbouncer/pgbouncer-write.ini"
READ_CONFIG="/etc/pgbouncer/pgbouncer-read.ini"
PATRONI_REST_PORT="${PATRONI_REST_PORT:-8008}"

log() { echo "[update-pgbouncer] $(date -Is) $*"; }

load_env() {
  local file="$1"
  if [ -f "$file" ]; then
    set -a
    # shellcheck disable=SC1090
    source "$file"
    set +a
  fi
}
load_env /etc/infrazero/pgbouncer.env
load_env /etc/infrazero/network.env

# Collect all DB node IPs
all_hosts=""
if [ -n "${DB_PRIMARY_HOST:-}" ]; then
  all_hosts="$DB_PRIMARY_HOST"
fi
if [ -n "${DB_REPLICA_HOSTS:-}" ]; then
  IFS=',' read -r -a replicas <<< "$DB_REPLICA_HOSTS"
  for r in "${replicas[@]}"; do
    r=$(echo "$r" | xargs)
    if [ -n "$r" ]; then
      all_hosts="${all_hosts} ${r}"
    fi
  done
fi

if [ -z "$all_hosts" ]; then
  log "no DB hosts configured; skipping PgBouncer setup"
  beacon_status "complete" "Bootstrap complete (no DB hosts)" 100
  return 0 2>/dev/null || exit 0
fi

# Query Patroni /cluster endpoint to get leader + replicas
new_primary=""
new_replicas=""
for host in $all_hosts; do
  cluster_json=$(curl -sf --max-time 3 "http://${host}:${PATRONI_REST_PORT}/cluster" 2>/dev/null || true)
  if [ -z "$cluster_json" ]; then
    continue
  fi

  # Parse leader and replica IPs from cluster JSON
  new_primary=$(echo "$cluster_json" | jq -r '.members[] | select(.role=="leader") | .host' 2>/dev/null | head -1 || true)
  new_replicas=$(echo "$cluster_json" | jq -r '[.members[] | select(.role=="replica") | .host] | join(",")' 2>/dev/null || true)

  if [ -n "$new_primary" ]; then
    break
  fi
done

if [ -z "$new_primary" ]; then
  log "WARNING: could not determine Patroni leader from any DB node; using first host as primary"
  new_primary=$(echo "$all_hosts" | head -1)
fi

changed=false

# Update write pool
current_primary=$(grep -oP 'host=\K[^ ]+' "$WRITE_CONFIG" 2>/dev/null | head -1 || true)
if [ "$current_primary" != "$new_primary" ]; then
  log "leader changed: ${current_primary} → ${new_primary}"
  sed -i "s|^\* = host=.*|* = host=${new_primary} port=5432|" "$WRITE_CONFIG"
  kill -HUP "$(cat /var/run/postgresql/pgbouncer-5432.pid 2>/dev/null)" 2>/dev/null || true
  changed=true
fi

# Update read pool — point to all replicas (or primary if no replicas)
read_hosts="${new_replicas:-$new_primary}"
current_read=$(grep -oP 'host=\K[^ ]+' "$READ_CONFIG" 2>/dev/null | head -1 || true)
if [ "$current_read" != "$read_hosts" ]; then
  log "read pool changed: ${current_read} → ${read_hosts}"
  sed -i "s|^\* = host=.*|* = host=${read_hosts} port=5432|" "$READ_CONFIG"
  kill -HUP "$(cat /var/run/postgresql/pgbouncer-5433.pid 2>/dev/null)" 2>/dev/null || true
  changed=true
fi

if [ "$changed" = "true" ]; then
  log "pools updated (write=${new_primary}, read=${read_hosts})"
fi
WATCHER_EOF

chmod +x /usr/local/sbin/update-pgbouncer.sh

# Systemd timer to poll Patroni every 5 seconds
cat > /etc/systemd/system/pgbouncer-watcher.service <<'EOF'
[Unit]
Description=PgBouncer Patroni leader watcher
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/update-pgbouncer.sh
EOF

cat > /etc/systemd/system/pgbouncer-watcher.timer <<'EOF'
[Unit]
Description=Poll Patroni leader every 5s

[Timer]
OnBootSec=10s
OnUnitActiveSec=5s
AccuracySec=1s

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now pgbouncer-watcher.timer

# ------------------------------------------------------------------ #
#  Systemd units for both PgBouncer instances                          #
# ------------------------------------------------------------------ #

# Disable the default pgbouncer service (we run two instances)
systemctl stop pgbouncer 2>/dev/null || true
systemctl disable pgbouncer 2>/dev/null || true

create_pgbouncer_service() {
  local name="$1"
  local config="$2"

  cat > "/etc/systemd/system/pgbouncer-${name}.service" <<UNIT_EOF
[Unit]
Description=PgBouncer connection pooler (${name})
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
User=postgres
Group=postgres
ExecStart=/usr/sbin/pgbouncer -d ${config}
ExecReload=/bin/kill -HUP \$MAINPID
PIDFile=/var/run/postgresql/pgbouncer-$(grep listen_port "${config}" | awk -F= '{print $2}' | xargs).pid
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
UNIT_EOF
}

create_pgbouncer_service "write" "/etc/pgbouncer/pgbouncer-write.ini"
create_pgbouncer_service "read" "/etc/pgbouncer/pgbouncer-read.ini"

beacon_status "starting_instances" "Starting PgBouncer instances" 75

systemctl daemon-reload
systemctl enable --now pgbouncer-write
systemctl enable --now pgbouncer-read

# ------------------------------------------------------------------ #
#  Health check                                                        #
# ------------------------------------------------------------------ #

echo "[pgbouncer] waiting for PgBouncer instances to start"
for attempt in $(seq 1 15); do
  write_ok=false
  read_ok=false

  if psql -h 127.0.0.1 -p "$PGBOUNCER_WRITE_PORT" -U "$PGBOUNCER_AUTH_USER" \
    -c "SHOW DATABASES;" pgbouncer >/dev/null 2>&1; then
    write_ok=true
  fi
  if psql -h 127.0.0.1 -p "$PGBOUNCER_READ_PORT" -U "$PGBOUNCER_AUTH_USER" \
    -c "SHOW DATABASES;" pgbouncer >/dev/null 2>&1; then
    read_ok=true
  fi

  if [ "$write_ok" = "true" ] && [ "$read_ok" = "true" ]; then
    echo "[pgbouncer] both instances healthy"
    break
  fi

  if [ "$attempt" -eq 15 ]; then
    echo "[pgbouncer] WARNING: health check failed after ${attempt} attempts" >&2
    systemctl status pgbouncer-write --no-pager || true
    systemctl status pgbouncer-read --no-pager || true
  fi
  sleep 3
done

beacon_status "complete" "Bootstrap complete" 100

echo "[pgbouncer] $(date -Is) complete"
