#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/infrazero-bootstrap.log"
if [ -z "${_INFRAZERO_LOG_REDIRECTED:-}" ]; then
  exec > >(tee -a "$LOG_FILE") 2>&1
  export _INFRAZERO_LOG_REDIRECTED=1
fi

echo "[k3s-agent] $(date -Is) start"

BOOTSTRAP_ROLE="node-agent"
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
  /etc/infrazero/node2.env \
  /etc/infrazero/network.env

infrazero_require_env "K3S_TOKEN" "k3s-agent"
infrazero_require_env "K3S_SERVER_URL" "k3s-agent"
infrazero_require_env "EGRESS_LOKI_URL" "k3s-agent"

apt_get() {
  INFRAZERO_APT_ATTEMPTS="${INFRAZERO_APT_ATTEMPTS:-12}" \
  INFRAZERO_APT_RETRY_DELAY="${INFRAZERO_APT_RETRY_DELAY:-10}" \
  INFRAZERO_APT_CLEAN_LISTS="${INFRAZERO_APT_CLEAN_LISTS:-false}" \
    infrazero_apt_get "k3s-agent" "$@"
}

PRIVATE_CIDR="${PRIVATE_CIDR:-}"

PRIVATE_IF=$(infrazero_detect_private_iface "$PRIVATE_CIDR" || true)
if [ -z "$PRIVATE_IF" ]; then
  echo "[k3s-agent] unable to determine private interface" >&2
  exit 1
fi

NODE_IP=$(infrazero_private_ip_for_iface "$PRIVATE_IF" || true)
if [ -z "$NODE_IP" ]; then
  echo "[k3s-agent] unable to determine private IP" >&2
  exit 1
fi

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt_get update -y
  apt_get install -y curl ca-certificates jq unzip
fi

INSTALL_K3S_EXEC="agent --node-ip ${NODE_IP} --flannel-iface ${PRIVATE_IF}"
infrazero_retry "k3s-agent" 10 5 curl -sfL https://get.k3s.io -o /tmp/k3s-install.sh
chmod +x /tmp/k3s-install.sh

wait_for_k3s_primary_api() {
  echo "[k3s-agent] waiting for primary K3s API at ${K3S_SERVER_URL}"
  local i
  for i in {1..120}; do
    if curl -skf "${K3S_SERVER_URL}/cacerts" >/dev/null; then
      echo "[k3s-agent] primary K3s API is ready"
      return 0
    fi
    if [ "$i" -eq 1 ] || [ $((i % 15)) -eq 0 ]; then
      if declare -F beacon_retrying >/dev/null 2>&1; then
        beacon_retrying "waiting_k3s_primary_api" "Waiting for primary K3s API before agent join" 40 "dependency" "K3S_PRIMARY_API_WAIT" "$i" 120
      fi
    fi
    sleep 5
  done

  echo "[k3s-agent] primary K3s API did not become ready at ${K3S_SERVER_URL}" >&2
  if declare -F beacon_failed >/dev/null 2>&1; then
    beacon_failed "waiting_k3s_primary_api" "Primary K3s API did not become ready before agent join" 40 "dependency" "K3S_PRIMARY_API_NOT_READY" "node2.sh" "" "curl -skf ${K3S_SERVER_URL}/cacerts" 1
  fi
  return 1
}

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

wait_for_k3s_primary_api
install_k3s

infrazero_install_journald_promtail "k3s-agent" "k3s-agent" "$EGRESS_LOKI_URL"

beacon_status "complete" "Bootstrap complete" 100

echo "[k3s-agent] $(date -Is) complete"
