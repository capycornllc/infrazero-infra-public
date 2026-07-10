#!/usr/bin/env bash
set -euo pipefail

export INFISICAL_KUBERNETES_HOST_MODE="${INFISICAL_KUBERNETES_HOST_MODE:-private}"

_infrazero_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${_infrazero_script_dir}/common-infisical-admin-secret.sh" ]; then
  exec bash "${_infrazero_script_dir}/common-infisical-admin-secret.sh" "$@"
elif [ -f "${_infrazero_script_dir}/../common/common-infisical-admin-secret.sh" ]; then
  exec bash "${_infrazero_script_dir}/../common/common-infisical-admin-secret.sh" "$@"
fi

echo "[infisical-admin-secret] common-infisical-admin-secret.sh not found" >&2
exit 1
