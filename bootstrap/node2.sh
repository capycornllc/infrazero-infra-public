#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/infrazero-bootstrap.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[k3s-agent] $(date -Is) start"

load_env() {
  local file="$1"
  if [ -f "$file" ]; then
    set -a
    # shellcheck disable=SC1090
    source "$file"
    set +a
  fi
}

load_env /etc/infrazero/node.env
load_env /etc/infrazero/node2.env
load_env /etc/infrazero/network.env

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[k3s-agent] missing required env: $name" >&2
    exit 1
  fi
}

require_env "K3S_TOKEN"
require_env "K3S_SERVER_URL"
require_env "EGRESS_LOKI_URL"

retry() {
  local attempts="$1"
  local delay="$2"
  shift 2
  local i
  for i in $(seq 1 "$attempts"); do
    if "$@"; then
      return 0
    fi
    echo "[k3s-agent] retry $i/$attempts failed; sleeping ${delay}s"
    sleep "$delay"
  done
  return 1
}

PRIVATE_CIDR="${PRIVATE_CIDR:-}"

detect_private_iface() {
  if [ -n "$PRIVATE_CIDR" ] && command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY'
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
    ifname = parts[1]
    addr = parts[3].split("/")[0]
    try:
        if ipaddress.ip_address(addr) in net:
            print(ifname)
            raise SystemExit(0)
    except Exception:
        continue
raise SystemExit(1)
PY
    return
  fi

  ip -4 -o addr show | awk '$2 != "lo" {print $2; exit}'
}

PRIVATE_IF=$(detect_private_iface || true)
if [ -z "$PRIVATE_IF" ]; then
  echo "[k3s-agent] unable to determine private interface" >&2
  exit 1
fi

NODE_IP=$(ip -4 -o addr show dev "$PRIVATE_IF" | awk '{split($4, parts, "/"); print parts[1]; exit}')
if [ -z "$NODE_IP" ]; then
  echo "[k3s-agent] unable to determine private IP" >&2
  exit 1
fi

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y curl ca-certificates jq unzip
fi

INSTALL_K3S_EXEC="agent --node-ip ${NODE_IP} --flannel-iface ${PRIVATE_IF}"
retry 10 5 curl -sfL https://get.k3s.io -o /tmp/k3s-install.sh
chmod +x /tmp/k3s-install.sh

install_k3s() {
  local attempts=5
  local delay=10
  local i
  for i in $(seq 1 "$attempts"); do
    set +e
    INSTALL_K3S_EXEC="$INSTALL_K3S_EXEC" K3S_URL="$K3S_SERVER_URL" K3S_TOKEN="$K3S_TOKEN" /tmp/k3s-install.sh
    local rc=$?
    set -e

    if [ "$rc" -eq 0 ]; then
      return 0
    fi

    for _ in {1..6}; do
      if systemctl is-active --quiet k3s-agent; then
        echo "[k3s-agent] k3s installer failed (rc=$rc) but k3s-agent service is active; continuing"
        return 0
      fi
      sleep 5
    done

    echo "[k3s-agent] k3s install attempt $i/$attempts failed (rc=$rc)"
    systemctl status k3s-agent --no-pager || true
    journalctl -u k3s-agent -b --no-pager -n 200 || true

    if [ "$i" -lt "$attempts" ]; then
      echo "[k3s-agent] retrying k3s install in ${delay}s"
      sleep "$delay"
      delay=$((delay * 2))
      if [ "$delay" -gt 120 ]; then
        delay=120
      fi
    fi
  done

  return 1
}

install_k3s

# Promtail for journald to Loki
if [ ! -f /usr/local/bin/promtail ]; then
  if curl -fsSL -o /tmp/promtail.zip "https://github.com/grafana/loki/releases/download/v2.9.3/promtail-linux-amd64.zip"; then
    unzip -o /tmp/promtail.zip -d /usr/local/bin
    mv /usr/local/bin/promtail-linux-amd64 /usr/local/bin/promtail
    chmod +x /usr/local/bin/promtail
  else
    echo "[k3s-agent] promtail download failed; skipping"
  fi
fi

mkdir -p /etc/promtail /var/lib/promtail
cat > /etc/promtail/promtail.yml <<EOF
server:
  http_listen_port: 9080
  grpc_listen_port: 0
positions:
  filename: /var/lib/promtail/positions.yaml
clients:
  - url: ${EGRESS_LOKI_URL}
    external_labels:
      host: ${HOSTNAME}
      role: k3s-agent
scrape_configs:
  - job_name: journal
    journal:
      max_age: 12h
      labels:
        job: systemd-journal
    relabel_configs:
      - source_labels: ['__journal__systemd_unit']
        target_label: 'unit'
EOF

cat > /etc/systemd/system/promtail.service <<'EOF'
[Unit]
Description=Promtail log shipper
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/promtail -config.file=/etc/promtail/promtail.yml
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now promtail

echo "[k3s-agent] $(date -Is) complete"
