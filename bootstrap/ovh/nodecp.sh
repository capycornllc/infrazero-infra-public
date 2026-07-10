#!/usr/bin/env bash
set -euo pipefail

_infrazero_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "${_infrazero_script_dir}/common-nodecp.sh" ]; then
  exec bash "${_infrazero_script_dir}/common-nodecp.sh" "$@"
elif [ -f "${_infrazero_script_dir}/../common/common-nodecp.sh" ]; then
  exec bash "${_infrazero_script_dir}/../common/common-nodecp.sh" "$@"
fi

echo "[nodecp] common-nodecp.sh not found" >&2
exit 1
