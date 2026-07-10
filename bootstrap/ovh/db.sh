#!/usr/bin/env bash
set -euo pipefail

# Thin provider wrapper: the shared implementation lives in
# bootstrap/common/common-db.sh; cloud specifics come from
# bootstrap/providers/ovh/adapter.sh (see docs/provider-adapter-contract.md).
export INFRAZERO_PROVIDER="${INFRAZERO_PROVIDER:-ovh}"

_infrazero_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "${_infrazero_script_dir}/common-db.sh" ]; then
  exec bash "${_infrazero_script_dir}/common-db.sh" "$@"
elif [ -f "${_infrazero_script_dir}/../common/common-db.sh" ]; then
  exec bash "${_infrazero_script_dir}/../common/common-db.sh" "$@"
fi

echo "[db] common-db.sh not found" >&2
exit 1
