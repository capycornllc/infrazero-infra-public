#!/usr/bin/env bash
set -euo pipefail

_infrazero_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "${_infrazero_script_dir}/common-db-replica.sh" ]; then
  exec bash "${_infrazero_script_dir}/common-db-replica.sh" "$@"
elif [ -f "${_infrazero_script_dir}/../common/common-db-replica.sh" ]; then
  exec bash "${_infrazero_script_dir}/../common/common-db-replica.sh" "$@"
fi

echo "[db-replica] common-db-replica.sh not found" >&2
exit 1
