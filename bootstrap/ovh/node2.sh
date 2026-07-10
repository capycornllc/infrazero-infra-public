#!/usr/bin/env bash
set -euo pipefail

_infrazero_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "${_infrazero_script_dir}/common-node-agent.sh" ]; then
  exec bash "${_infrazero_script_dir}/common-node-agent.sh" "$@"
elif [ -f "${_infrazero_script_dir}/../common/common-node-agent.sh" ]; then
  exec bash "${_infrazero_script_dir}/../common/common-node-agent.sh" "$@"
fi

echo "[k3s-agent] common-node-agent.sh not found" >&2
exit 1
