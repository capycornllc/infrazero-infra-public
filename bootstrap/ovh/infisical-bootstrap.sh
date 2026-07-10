#!/usr/bin/env bash
set -euo pipefail

_infrazero_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${_infrazero_script_dir}/common-infisical-bootstrap.sh" ]; then
  exec bash "${_infrazero_script_dir}/common-infisical-bootstrap.sh" "$@"
elif [ -f "${_infrazero_script_dir}/../common/common-infisical-bootstrap.sh" ]; then
  exec bash "${_infrazero_script_dir}/../common/common-infisical-bootstrap.sh" "$@"
fi

echo "[infisical-bootstrap] common-infisical-bootstrap.sh not found" >&2
exit 1
