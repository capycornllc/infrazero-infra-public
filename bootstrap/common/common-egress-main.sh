#!/usr/bin/env bash
# Shared egress bootstrap for all providers. Provider wrappers
# (bootstrap/<provider>/egress.sh) exec this script; cloud specifics come from
# the provider adapter (provider_egress_setup_interfaces - NIC detection and
# self-configuration; see docs/provider-adapter-contract.md). Helper functions
# live in common-egress.sh.
set -euo pipefail

LOG_FILE="/var/log/infrazero-bootstrap.log"
if [ -z "${_INFRAZERO_LOG_REDIRECTED:-}" ]; then
  exec > >(tee -a "$LOG_FILE") 2>&1
  export _INFRAZERO_LOG_REDIRECTED=1
fi

echo "[egress] $(date -Is) start"

BOOTSTRAP_ROLE="egress"
EGRESS_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "${EGRESS_SCRIPT_DIR}/common-base.sh" ]; then
  # shellcheck disable=SC1091
  source "${EGRESS_SCRIPT_DIR}/common-base.sh"
elif [ -f "${EGRESS_SCRIPT_DIR}/../common/common-base.sh" ]; then
  # shellcheck disable=SC1091
  source "${EGRESS_SCRIPT_DIR}/../common/common-base.sh"
fi

if ! declare -F infrazero_load_provider_adapter >/dev/null 2>&1; then
  echo "[egress] common-base.sh missing infrazero_load_provider_adapter; cannot continue" >&2
  exit 1
fi
infrazero_load_provider_adapter "$EGRESS_SCRIPT_DIR"

if [ -f "${EGRESS_SCRIPT_DIR}/common-egress.sh" ]; then
  # shellcheck disable=SC1091
  source "${EGRESS_SCRIPT_DIR}/common-egress.sh"
elif [ -f "${EGRESS_SCRIPT_DIR}/../common/common-egress.sh" ]; then
  # shellcheck disable=SC1091
  source "${EGRESS_SCRIPT_DIR}/../common/common-egress.sh"
else
  echo "[egress] missing shared common-egress.sh" >&2
  exit 1
fi

if ! declare -F beacon_status >/dev/null 2>&1; then
  if [ -f "$EGRESS_SCRIPT_DIR/beacon.sh" ]; then
    # shellcheck disable=SC1091
    source "$EGRESS_SCRIPT_DIR/beacon.sh"
  else
    beacon_status() {
      return 0
    }
  fi
fi

ENV_FILE="/etc/infrazero/egress.env"
infrazero_load_env_file "$ENV_FILE"

BOOTSTRAP_ENV_FILE="/etc/infrazero/egress.bootstrap.env"
download_offloaded_bootstrap_env
infrazero_load_env_file "$BOOTSTRAP_ENV_FILE"

NETWORK_ENV="/etc/infrazero/network.env"
infrazero_load_env_file "$NETWORK_ENV"

infrazero_require_egress_env
infrazero_export_egress_runtime_env

infrazero_enable_egress_forwarding_early
infrazero_install_egress_packages
infrazero_enable_and_wait_docker

infrazero_enable_egress_forwarding

PRIVATE_CIDR="${PRIVATE_CIDR:-}"
if [ -z "$PRIVATE_CIDR" ]; then
  echo "[egress] PRIVATE_CIDR missing; NAT may be incomplete" >&2
fi

# Interface detection is provider-specific (Hetzner: MAC-prefix detection and
# self-configuration race workarounds; OVH: IP-in-CIDR with single-interface
# Floating IP mode). Sets PUBLIC_IF / PRIVATE_IF; see the provider adapter.
PUBLIC_IF=""
PRIVATE_IF=""
if ! provider_egress_setup_interfaces; then
  echo "[egress] unable to determine network interfaces" >&2
  exit 1
fi
echo "[egress] interfaces: public=$PUBLIC_IF, private=$PRIVATE_IF"

PUBLIC_IP=$(ip -4 -o addr show dev "$PUBLIC_IF" | awk '{split($4, parts, "/"); print parts[1]; exit}')
if [ -z "$PUBLIC_IP" ]; then
  echo "[egress] unable to determine public ip address" >&2
fi

PRIVATE_IP=$(ip -4 -o addr show dev "$PRIVATE_IF" | awk '{split($4, parts, "/"); print parts[1]; exit}')
if [ -z "$PRIVATE_IP" ]; then
  echo "[egress] unable to determine private ip address" >&2
  exit 1
fi
echo "[egress] IPs: public=$PUBLIC_IP, private=$PRIVATE_IP"

infrazero_apply_egress_nat_rules "$PRIVATE_CIDR" "$PRIVATE_IF" "$PUBLIC_IF"

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
    logging:
      driver: json-file
      options:
        max-size: "${EGRESS_DOCKER_LOG_MAX_SIZE:-100m}"
        max-file: "${EGRESS_DOCKER_LOG_MAX_FILES:-5}"
    ports:
      - "3100:3100"
    volumes:
      - /opt/infrazero/egress/loki-config.yaml:/etc/loki/config.yaml:ro
      - /opt/infrazero/egress/loki-data:/loki
  grafana:
    image: grafana/grafana:10.4.2
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "${EGRESS_DOCKER_LOG_MAX_SIZE:-100m}"
        max-file: "${EGRESS_DOCKER_LOG_MAX_FILES:-5}"
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

loki_up=false
for _loki_attempt in {1..3}; do
  if compose_cmd -f /opt/infrazero/egress/docker-compose.loki.yml up -d; then
    loki_up=true
    break
  fi
  echo "[egress] WARNING: loki compose up failed (attempt ${_loki_attempt}/3); retrying in 10s" >&2
  sleep 10
  compose_cmd -f /opt/infrazero/egress/docker-compose.loki.yml down --remove-orphans 2>/dev/null || true
done
if [ "$loki_up" != "true" ]; then
  echo "[egress] WARNING: loki compose up failed after 3 attempts; continuing without loki" >&2
fi

loki_ready=false
for i in {1..60}; do
  if curl -sf http://127.0.0.1:3100/ready >/dev/null; then
    echo "[egress] loki ready (attempt $i)"
    loki_ready=true
    break
  fi
  sleep 2
done

if [ "$loki_ready" != "true" ]; then
  echo "[egress] WARNING: loki did not become ready after 120s - dumping container logs:" >&2
  compose_cmd -f /opt/infrazero/egress/docker-compose.loki.yml logs --no-color --tail=50 loki >&2 || true
fi

install_egress_docker_promtail

# Infisical + Postgres + Redis
infrazero_prepare_egress_service_env

if [ -n "$KUBERNETES_FQDN" ]; then
  cleanup_k3s_iptables
fi

infrazero_persist_iptables_rules

infrazero_require_cloudflare_for_public_fqdns
infrazero_write_infisical_env

infrazero_prepare_egress_tls_env
infrazero_write_infisical_compose
infrazero_start_infisical_dependencies
infrazero_wait_infisical_postgres

INFISICAL_RESTORE_FROM_S3="${INFISICAL_RESTORE_FROM_S3:-false}"

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

infrazero_start_infisical_service

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
    infisical_ok=false
    for infisical_attempt in 1 2 3; do
      echo "[egress] infisical-bootstrap.sh attempt ${infisical_attempt}/3"
      if ./infisical-bootstrap.sh; then
        infisical_ok=true
        break
      fi
      echo "[egress] infisical-bootstrap.sh failed (attempt ${infisical_attempt}/3); retrying in 120s" >&2
      sleep 120
    done
    if [ "$infisical_ok" != "true" ]; then
      echo "[egress] WARNING: infisical-bootstrap.sh failed after 3 attempts; installing retry timer" >&2
      cat > /etc/systemd/system/infrazero-infisical-retry.service <<'UNIT'
[Unit]
Description=Retry Infisical bootstrap
After=network-online.target docker.service
ConditionPathExists=!/etc/infrazero/infisical-bootstrap-done

[Service]
Type=oneshot
WorkingDirectory=/opt/infrazero/bootstrap
ExecStart=/bin/bash -c './infisical-bootstrap.sh && touch /etc/infrazero/infisical-bootstrap-done'
TimeoutStartSec=600
UNIT
      cat > /etc/systemd/system/infrazero-infisical-retry.timer <<'TIMER'
[Unit]
Description=Retry Infisical bootstrap every 5 minutes

[Timer]
OnBootSec=3min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
TIMER
      systemctl daemon-reload
      systemctl enable --now infrazero-infisical-retry.timer
      echo "[egress] infrazero-infisical-retry.timer installed"
    fi
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
