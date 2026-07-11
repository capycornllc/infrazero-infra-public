#!/usr/bin/env bash
set -euo pipefail

if [ -z "${INFISICAL_KUBERNETES_HOST:-}" ] && [ -n "${KUBERNETES_FQDN:-}" ]; then
  export INFISICAL_KUBERNETES_HOST="https://${KUBERNETES_FQDN}:6443"
fi

_infrazero_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${_infrazero_script_dir}/common-infisical-admin-secret.sh" ]; then
  exec bash "${_infrazero_script_dir}/common-infisical-admin-secret.sh" "$@"
elif [ -f "${_infrazero_script_dir}/../common/common-infisical-admin-secret.sh" ]; then
  exec bash "${_infrazero_script_dir}/../common/common-infisical-admin-secret.sh" "$@"
fi

echo "[infisical-admin-secret] common-infisical-admin-secret.sh not found" >&2
exit 1
