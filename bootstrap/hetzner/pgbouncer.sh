#!/usr/bin/env bash
set -euo pipefail

_infrazero_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${_infrazero_script_dir}/common-pgbouncer.sh" ]; then
  exec bash "${_infrazero_script_dir}/common-pgbouncer.sh" "$@"
elif [ -f "${_infrazero_script_dir}/../common/common-pgbouncer.sh" ]; then
  exec bash "${_infrazero_script_dir}/../common/common-pgbouncer.sh" "$@"
fi

echo "[pgbouncer] common-pgbouncer.sh not found" >&2
exit 1
