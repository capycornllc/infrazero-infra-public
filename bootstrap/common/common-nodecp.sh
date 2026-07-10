#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/infrazero-bootstrap.log"
if [ -z "${_INFRAZERO_LOG_REDIRECTED:-}" ]; then
  exec > >(tee -a "$LOG_FILE") 2>&1
  export _INFRAZERO_LOG_REDIRECTED=1
fi

echo "[nodecp] $(date -Is) start"

BOOTSTRAP_ROLE="nodecp"
INFRAZERO_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${INFRAZERO_SCRIPT_DIR}/common-base.sh" ]; then
  # shellcheck disable=SC1091
  source "${INFRAZERO_SCRIPT_DIR}/common-base.sh"
elif [ -f "${INFRAZERO_SCRIPT_DIR}/../common/common-base.sh" ]; then
  # shellcheck disable=SC1091
  source "${INFRAZERO_SCRIPT_DIR}/../common/common-base.sh"
fi

infrazero_load_env_files \
  /etc/infrazero/node.env \
  /etc/infrazero/nodecp.env \
  /etc/infrazero/network.env

infrazero_require_env "K3S_TOKEN" "nodecp"
infrazero_require_env "K3S_SERVER_URL" "nodecp"
infrazero_require_env "EGRESS_LOKI_URL" "nodecp"

K3S_CONTROL_PLANE_JOIN_URL="${K3S_CONTROL_PLANE_JOIN_URL:-}"
if [ -z "$K3S_CONTROL_PLANE_JOIN_URL" ] && [ -n "${K3S_SERVER_IP:-}" ]; then
  K3S_CONTROL_PLANE_JOIN_URL="https://${K3S_SERVER_IP}:6443"
fi
if [ -z "$K3S_CONTROL_PLANE_JOIN_URL" ]; then
  K3S_CONTROL_PLANE_JOIN_URL="$K3S_SERVER_URL"
fi

apt_get() {
  INFRAZERO_APT_ATTEMPTS="${INFRAZERO_APT_ATTEMPTS:-12}" \
  INFRAZERO_APT_RETRY_DELAY="${INFRAZERO_APT_RETRY_DELAY:-10}" \
  INFRAZERO_APT_CLEAN_LISTS="${INFRAZERO_APT_CLEAN_LISTS:-false}" \
    infrazero_apt_get "nodecp" "$@"
}

PRIVATE_CIDR="${PRIVATE_CIDR:-}"

PRIVATE_IF=$(infrazero_detect_private_iface "$PRIVATE_CIDR" || true)
if [ -z "$PRIVATE_IF" ]; then
  echo "[nodecp] unable to determine private interface" >&2
  exit 1
fi

NODE_IP=$(infrazero_private_ip_for_iface "$PRIVATE_IF" || true)
if [ -z "$NODE_IP" ]; then
  echo "[nodecp] unable to determine private IP" >&2
  exit 1
fi

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt_get update -y
  apt_get install -y curl ca-certificates jq unzip
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

infrazero_retry "nodecp" 10 5 curl -sfL https://get.k3s.io -o /tmp/k3s-install.sh
chmod +x /tmp/k3s-install.sh

wait_for_k3s_primary_api() {
  echo "[nodecp] waiting for primary K3s API at ${K3S_CONTROL_PLANE_JOIN_URL}"
  local i
  for i in {1..90}; do
    if curl -skf "${K3S_CONTROL_PLANE_JOIN_URL}/cacerts" >/dev/null; then
      echo "[nodecp] primary K3s API is ready"
      return 0
    fi
    if [ "$i" -eq 1 ] || [ $((i % 15)) -eq 0 ]; then
      if declare -F beacon_retrying >/dev/null 2>&1; then
        beacon_retrying "waiting_k3s_primary_api" "Waiting for primary K3s API before control-plane join" 40 "dependency" "K3S_PRIMARY_API_WAIT" "$i" 90
      fi
    fi
    sleep 5
  done

  echo "[nodecp] primary K3s API did not become ready at ${K3S_CONTROL_PLANE_JOIN_URL}" >&2
  if declare -F beacon_failed >/dev/null 2>&1; then
    beacon_failed "waiting_k3s_primary_api" "Primary K3s API did not become ready before control-plane join" 40 "dependency" "K3S_PRIMARY_API_NOT_READY" "nodecp.sh" "" "curl -skf ${K3S_CONTROL_PLANE_JOIN_URL}/cacerts" 1
  fi
  return 1
}

install_k3s() {
  local attempts=5
  local delay=10
  local i
  for i in $(seq 1 "$attempts"); do
    set +e
    INSTALL_K3S_EXEC="$INSTALL_K3S_EXEC" K3S_URL="$K3S_CONTROL_PLANE_JOIN_URL" K3S_TOKEN="$K3S_TOKEN" /tmp/k3s-install.sh
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

wait_for_k3s_primary_api
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

infrazero_install_journald_promtail "nodecp" "nodecp" "$EGRESS_LOKI_URL"

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
  advertise_ip=$(infrazero_private_ip_for_cidr "${PRIVATE_CIDR:-}" || true)

  if [ -z "$advertise_ip" ]; then
    echo "[nodecp] unable to determine private IP for etcd advertise" >&2
    return 1
  fi

  if systemctl is-active --quiet etcd-patroni 2>/dev/null \
    && ss -tln | grep -q ":${client_port} " \
    && ss -tln | grep -q ":${peer_port} "; then
    echo "[nodecp] etcd-patroni already running; skipping install"
    return 0
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

  # Determine initial cluster state based on existing data.
  # Use "new" for first start, "existing" for restart (e.g. after reboot).
  local etcd_initial_state="new"
  if [ -d /var/lib/etcd-patroni/member ]; then
    etcd_initial_state="existing"
    echo "[nodecp] etcd data detected; using initial-cluster-state=existing"
  fi

  # Verify ports are free before starting
  for check_port in "$client_port" "$peer_port"; do
    if ss -tlnp | grep -q ":${check_port} "; then
      local occupant
      occupant=$(ss -tlnp | grep ":${check_port} " | head -1)
      echo "[nodecp] ERROR: port ${check_port} already in use: ${occupant}" >&2
      echo "[nodecp] etcd-patroni cannot start - pick different ports via ETCD_PATRONI_CLIENT_PORT / ETCD_PATRONI_PEER_PORT" >&2
      return 1
    fi
  done

  cat > /etc/systemd/system/etcd-patroni.service <<UNIT_EOF
[Unit]
Description=etcd for Patroni DCS
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/etcd-patroni \\
  --name ${etcd_name} \\
  --data-dir /var/lib/etcd-patroni \\
  --listen-client-urls http://0.0.0.0:${client_port} \\
  --advertise-client-urls http://${advertise_ip}:${client_port} \\
  --listen-peer-urls http://0.0.0.0:${peer_port} \\
  --initial-advertise-peer-urls http://${advertise_ip}:${peer_port} \\
  --initial-cluster ${initial_cluster} \\
  --initial-cluster-state ${etcd_initial_state} \\
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
  for attempt in $(seq 1 60); do
    if ETCDCTL_API=3 /usr/local/bin/etcdctl-patroni \
      --endpoints="http://127.0.0.1:${client_port}" \
      endpoint health >/dev/null 2>&1; then
      echo "[nodecp] etcd-patroni healthy (attempt ${attempt})"
      return 0
    fi
    if ss -tln | grep -q ":${client_port} " && ss -tln | grep -q ":${peer_port} "; then
      echo "[nodecp] etcd-patroni listeners ready (attempt ${attempt})"
      return 0
    fi
    sleep 3
  done

  echo "[nodecp] etcd-patroni did not start listening" >&2
  systemctl status etcd-patroni --no-pager || true
  journalctl -u etcd-patroni -n 30 --no-pager || true
  return 1
}

setup_etcd_patroni

beacon_status "complete" "Bootstrap complete" 100

echo "[nodecp] $(date -Is) complete"
