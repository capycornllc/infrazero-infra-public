#!/usr/bin/env bash
set -euo pipefail

_infrazero_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "${_infrazero_script_dir}/common-node1.sh" ]; then
  exec bash "${_infrazero_script_dir}/common-node1.sh" "$@"
elif [ -f "${_infrazero_script_dir}/../common/common-node1.sh" ]; then
  exec bash "${_infrazero_script_dir}/../common/common-node1.sh" "$@"
fi

echo "[node1] common-node1.sh not found" >&2
exit 1
