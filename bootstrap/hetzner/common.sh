#!/usr/bin/env bash
set -euo pipefail

# Thin provider wrapper: the shared implementation lives in
# bootstrap/common/common-system.sh; cloud specifics come from
# bootstrap/providers/hetzner/adapter.sh (see docs/provider-adapter-contract.md).
export INFRAZERO_PROVIDER="${INFRAZERO_PROVIDER:-hetzner}"

_infrazero_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "${_infrazero_script_dir}/common-system.sh" ]; then
  exec bash "${_infrazero_script_dir}/common-system.sh" "$@"
elif [ -f "${_infrazero_script_dir}/../common/common-system.sh" ]; then
  exec bash "${_infrazero_script_dir}/../common/common-system.sh" "$@"
fi

echo "[common] common-system.sh not found" >&2
exit 1
