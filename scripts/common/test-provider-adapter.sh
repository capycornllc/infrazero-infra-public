#!/usr/bin/env bash
# Verify the callable bootstrap adapter contract without touching infrastructure.
set -euo pipefail

provider="${1:?provider directory is required}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
adapter="${repo_root}/bootstrap/providers/${provider}/adapter.sh"
if [ ! -f "$adapter" ]; then
  echo "[adapter-contract] missing adapter: ${adapter}" >&2
  exit 2
fi

# shellcheck disable=SC1090
source "$adapter"

required_functions=(
  provider_route_mode
  provider_private_gateway
  provider_detect_private_iface
  provider_configure_private_nic
  provider_find_data_volume
  provider_volume_wait_defaults
  provider_wg_snat_default
  provider_metadata_get
  provider_egress_setup_interfaces
)

missing=0
for function_name in "${required_functions[@]}"; do
  if ! declare -F "$function_name" >/dev/null; then
    echo "[adapter-contract] ${provider}: missing ${function_name}" >&2
    missing=1
  fi
done
if [ "$missing" -ne 0 ]; then
  exit 1
fi

if [ "${INFRAZERO_PROVIDER:-}" != "$provider" ]; then
  echo "[adapter-contract] ${provider}: INFRAZERO_PROVIDER='${INFRAZERO_PROVIDER:-}'" >&2
  exit 1
fi

echo "[adapter-contract] passed: ${provider}"
