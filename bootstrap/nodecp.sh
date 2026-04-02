#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/infrazero-bootstrap.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[nodecp] $(date -Is) start"

BOOTSTRAP_ROLE="nodecp"

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
load_env /etc/infrazero/nodecp.env
load_env /etc/infrazero/network.env

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[nodecp] missing required env: $name" >&2
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
    echo "[nodecp] retry $i/$attempts failed; sleeping ${delay}s"
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
  echo "[nodecp] unable to determine private interface" >&2
  exit 1
fi

NODE_IP=$(ip -4 -o addr show dev "$PRIVATE_IF" | awk '{split($4, parts, "/"); print parts[1]; exit}')
if [ -z "$NODE_IP" ]; then
  echo "[nodecp] unable to determine private IP" >&2
  exit 1
fi

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y curl ca-certificates jq unzip
fi

K3S_SERVER_TAINT="${K3S_SERVER_TAINT:-false}"
INSTALL_K3S_EXEC="server --node-ip ${NODE_IP} --advertise-address ${NODE_IP} --flannel-iface ${PRIVATE_IF} --write-kubeconfig-mode 644"
if [ "${K3S_SERVER_TAINT,,}" = "true" ]; then
  INSTALL_K3S_EXEC="${INSTALL_K3S_EXEC} --node-taint node-role.kubernetes.io/control-plane=true:NoSchedule"
fi
if [ -n "${K3S_API_LB_PRIVATE_IP:-}" ]; then
  INSTALL_K3S_EXEC="${INSTALL_K3S_EXEC} --tls-san ${K3S_API_LB_PRIVATE_IP}"
fi
if [ -n "${KUBERNETES_FQDN:-}" ]; then
  INSTALL_K3S_EXEC="${INSTALL_K3S_EXEC} --tls-san ${KUBERNETES_FQDN}"
fi

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

    # systemctl can return failure even if k3s eventually restarts successfully.
    for _ in {1..6}; do
      if systemctl is-active --quiet k3s; then
        echo "[nodecp] k3s installer failed (rc=$rc) but k3s service is active; continuing"
        return 0
      fi
      sleep 5
    done

    echo "[nodecp] k3s install attempt $i/$attempts failed (rc=$rc)"
    systemctl status k3s --no-pager || true
    journalctl -u k3s -b --no-pager -n 200 || true

    if [ "$i" -lt "$attempts" ]; then
      echo "[nodecp] retrying k3s install in ${delay}s"
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

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

for i in {1..60}; do
  if kubectl get nodes >/dev/null 2>&1; then
    if kubectl get nodes --no-headers 2>/dev/null | awk '$2=="Ready" {exit 0} END {exit 1}'; then
      break
    fi
  fi
  sleep 2
done

# Promtail for journald to Loki (optional)
if [ ! -x /usr/local/bin/promtail ]; then
  if curl -fsSL -o /tmp/promtail.zip "https://github.com/grafana/loki/releases/download/v2.9.3/promtail-linux-amd64.zip"; then
    unzip -o /tmp/promtail.zip -d /usr/local/bin
    mv /usr/local/bin/promtail-linux-amd64 /usr/local/bin/promtail
    chmod +x /usr/local/bin/promtail
  else
    echo "[nodecp] promtail download failed; skipping"
  fi
fi

if [ -x /usr/local/bin/promtail ]; then
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
      role: nodecp
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
systemctl enable --now promtail || echo "[nodecp] failed to start promtail; continuing"
else
  echo "[nodecp] promtail binary unavailable; skipping service setup"
fi

# ------------------------------------------------------------------ #
#  Dedicated etcd for Patroni (optional)                               #
# ------------------------------------------------------------------ #

setup_etcd_patroni() {
  local enabled="${ETCD_PATRONI_ENABLED:-false}"
  if [ "$enabled" != "true" ]; then
    echo "[nodecp] etcd-patroni not enabled; skipping"
    return 0
  fi

  echo "[nodecp] installing dedicated etcd for Patroni"

  local etcd_version="${ETCD_PATRONI_VERSION:-3.5.21}"
  local etcd_name="${ETCD_PATRONI_NAME:-$(hostname)}"
  local initial_cluster="${ETCD_PATRONI_INITIAL_CLUSTER:-}"
  local client_port="${ETCD_PATRONI_CLIENT_PORT:-2391}"
  local peer_port="${ETCD_PATRONI_PEER_PORT:-2392}"

  if [ -z "$initial_cluster" ]; then
    echo "[nodecp] ETCD_PATRONI_INITIAL_CLUSTER not set; cannot configure etcd" >&2
    return 1
  fi

  local advertise_ip=""
  if [ -n "${PRIVATE_CIDR:-}" ] && command -v python3 >/dev/null 2>&1; then
    advertise_ip=$(python3 - <<'PY'
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

  if [ -z "$advertise_ip" ]; then
    echo "[nodecp] unable to determine private IP for etcd advertise" >&2
    return 1
  fi

  local arch="amd64"
  local etcd_url="https://github.com/etcd-io/etcd/releases/download/v${etcd_version}/etcd-v${etcd_version}-linux-${arch}.tar.gz"
  local tmpdir
  tmpdir=$(mktemp -d)

  echo "[nodecp] downloading etcd v${etcd_version}"
  timeout 120 curl -fsSL "$etcd_url" -o "${tmpdir}/etcd.tar.gz"
  tar -xzf "${tmpdir}/etcd.tar.gz" -C "${tmpdir}" --strip-components=1
  install -m 0755 "${tmpdir}/etcd" /usr/local/bin/etcd-patroni
  install -m 0755 "${tmpdir}/etcdctl" /usr/local/bin/etcdctl-patroni
  rm -rf "${tmpdir}"

  mkdir -p /var/lib/etcd-patroni
  chmod 700 /var/lib/etcd-patroni

  # Verify ports are free before starting
  for check_port in "$client_port" "$peer_port"; do
    if ss -tlnp | grep -q ":${check_port} "; then
      local occupant
      occupant=$(ss -tlnp | grep ":${check_port} " | head -1)
      echo "[nodecp] ERROR: port ${check_port} already in use: ${occupant}" >&2
      echo "[nodecp] etcd-patroni cannot start — pick different ports via ETCD_PATRONI_CLIENT_PORT / ETCD_PATRONI_PEER_PORT" >&2
      return 1
    fi
  done

  cat > /etc/systemd/system/etcd-patroni.service <<UNIT_EOF
[Unit]
Description=etcd for Patroni DCS
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/etcd-patroni \\
  --name ${etcd_name} \\
  --data-dir /var/lib/etcd-patroni \\
  --listen-client-urls http://0.0.0.0:${client_port} \\
  --advertise-client-urls http://${advertise_ip}:${client_port} \\
  --listen-peer-urls http://0.0.0.0:${peer_port} \\
  --initial-advertise-peer-urls http://${advertise_ip}:${peer_port} \\
  --initial-cluster ${initial_cluster} \\
  --initial-cluster-state new \\
  --initial-cluster-token patroni-etcd
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT_EOF

  systemctl daemon-reload
  systemctl enable --now etcd-patroni

  echo "[nodecp] waiting for etcd-patroni to start"
  for attempt in $(seq 1 30); do
    if ETCDCTL_API=3 /usr/local/bin/etcdctl-patroni \
      --endpoints="http://127.0.0.1:${client_port}" \
      endpoint health >/dev/null 2>&1; then
      echo "[nodecp] etcd-patroni healthy (attempt ${attempt})"
      return 0
    fi
    sleep 3
  done

  echo "[nodecp] etcd-patroni did not become healthy" >&2
  systemctl status etcd-patroni --no-pager || true
  journalctl -u etcd-patroni -n 30 --no-pager || true
  return 1
}

setup_etcd_patroni

beacon_status "complete" "Bootstrap complete" 100

echo "[nodecp] $(date -Is) complete"
