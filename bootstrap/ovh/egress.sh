#!/usr/bin/env bash
set -euo pipefail

# Thin provider wrapper: the shared implementation lives in
# bootstrap/common/common-egress-main.sh; cloud specifics come from
# bootstrap/providers/ovh/adapter.sh (see docs/provider-adapter-contract.md).
export INFRAZERO_PROVIDER="${INFRAZERO_PROVIDER:-ovh}"

# OVH runs Infisical behind SNAT/single-interface networking: allow internal
# IP connections and extra Kubernetes hosts by default (previous OVH behavior;
# unset on other clouds).
export INFISICAL_ALLOW_INTERNAL_IP_CONNECTIONS="${INFISICAL_ALLOW_INTERNAL_IP_CONNECTIONS:-true}"
export INFISICAL_KUBERNETES_EXTRA_HOSTS="${INFISICAL_KUBERNETES_EXTRA_HOSTS:-true}"

_infrazero_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "${_infrazero_script_dir}/common-egress-main.sh" ]; then
  exec bash "${_infrazero_script_dir}/common-egress-main.sh" "$@"
elif [ -f "${_infrazero_script_dir}/../common/common-egress-main.sh" ]; then
  exec bash "${_infrazero_script_dir}/../common/common-egress-main.sh" "$@"
fi

echo "[egress] common-egress-main.sh not found" >&2
exit 1
