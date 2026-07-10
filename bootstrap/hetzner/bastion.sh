#!/usr/bin/env bash
set -euo pipefail

# Thin provider wrapper: the shared implementation lives in
# bootstrap/common/common-bastion.sh; cloud specifics come from
# bootstrap/providers/hetzner/adapter.sh (see docs/provider-adapter-contract.md).
export INFRAZERO_PROVIDER="${INFRAZERO_PROVIDER:-hetzner}"

_infrazero_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "${_infrazero_script_dir}/common-bastion.sh" ]; then
  exec bash "${_infrazero_script_dir}/common-bastion.sh" "$@"
elif [ -f "${_infrazero_script_dir}/../common/common-bastion.sh" ]; then
  exec bash "${_infrazero_script_dir}/../common/common-bastion.sh" "$@"
fi

echo "[bastion] common-bastion.sh not found" >&2
exit 1
