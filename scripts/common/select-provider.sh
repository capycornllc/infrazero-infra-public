#!/usr/bin/env bash
# Resolve the selected provider by directory convention and load its CI credentials.
set -euo pipefail
set +x

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/common/provider-contract.sh
source "${repo_root}/scripts/common/provider-contract.sh"
github_env="${GITHUB_ENV:-}"
if [ -z "$github_env" ]; then
  echo "[select-provider] GITHUB_ENV is required" >&2
  exit 2
fi

requested="${CLOUD_PROVIDER:-hetzner}"
requested="$(printf '%s' "$requested" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
if [[ ! "$requested" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
  echo "[select-provider] invalid CLOUD_PROVIDER '${requested}'" >&2
  exit 2
fi

# OVH's public config value is historical; repository directories use `ovh`.
# Standard provider names need no central mapping.
case "$requested" in
  ovh|ovhcloud)
    provider_dir="ovh"
    provider_canonical="ovhcloud"
    ;;
  *)
    provider_dir="$requested"
    provider_canonical="$requested"
    ;;
esac

if ! infrazero_validate_provider_contract "$repo_root" "$provider_dir"; then
  echo "[select-provider] provider '${requested}' is not fully implemented" >&2
  exit 2
fi

{
  echo "CLOUD_PROVIDER_RESOLVED=${provider_canonical}"
  echo "CLOUD_PROVIDER_DIR=${provider_dir}"
  echo "TOFU_DIR=tofu/${provider_dir}"
  echo "SCRIPTS_DIR=scripts/${provider_dir}"
  echo "BOOTSTRAP_DIR=bootstrap/${provider_dir}"
  echo "BOOTSTRAP_PROVIDER=${provider_dir}"
} >> "$github_env"

export CLOUD_PROVIDER_RESOLVED="$provider_canonical"
export CLOUD_PROVIDER_DIR="$provider_dir"
export INFRAZERO_REPO_ROOT="$repo_root"
if [ -n "${SECRETS_JSON:-}" ]; then
  bash "${repo_root}/scripts/${provider_dir}/ci-credentials.sh"
fi

echo "[select-provider] selected ${provider_canonical} (directory: ${provider_dir})"
