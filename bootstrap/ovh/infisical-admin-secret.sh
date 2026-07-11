#!/usr/bin/env bash
set -euo pipefail

if [ -z "${INFISICAL_KUBERNETES_HOST:-}" ]; then
  if [ -n "${K3S_SERVER_IP:-}" ]; then
    export INFISICAL_KUBERNETES_HOST="https://${K3S_SERVER_IP}:6443"
  elif [ -n "${K3S_SERVER_PRIVATE_IP:-}" ]; then
    export INFISICAL_KUBERNETES_HOST="https://${K3S_SERVER_PRIVATE_IP}:6443"
  elif [ -n "${K3S_API_LB_PRIVATE_IP:-}" ]; then
    export INFISICAL_KUBERNETES_HOST="https://${K3S_API_LB_PRIVATE_IP}:6443"
  elif [ -n "${KUBERNETES_FQDN:-}" ]; then
    export INFISICAL_KUBERNETES_HOST="https://${KUBERNETES_FQDN}"
  fi
fi

_infrazero_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${_infrazero_script_dir}/common-infisical-admin-secret.sh" ]; then
  exec bash "${_infrazero_script_dir}/common-infisical-admin-secret.sh" "$@"
elif [ -f "${_infrazero_script_dir}/../common/common-infisical-admin-secret.sh" ]; then
  exec bash "${_infrazero_script_dir}/../common/common-infisical-admin-secret.sh" "$@"
fi

echo "[infisical-admin-secret] common-infisical-admin-secret.sh not found" >&2
exit 1
