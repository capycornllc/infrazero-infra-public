#!/usr/bin/env bash
set -euo pipefail

if [ -z "${DB_VOLUME_NAME:-}" ]; then
  echo "DB_VOLUME_NAME is required" >&2
  exit 1
fi

if tofu state list 2>/dev/null | grep -qx "openstack_blockstorage_volume_v3.db"; then
  echo "DB volume already in state"
  exit 0
fi

# List volumes via OpenStack API and find by name
# Requires OS_AUTH_URL, OS_USERNAME, OS_PASSWORD, OS_TENANT_ID, OS_REGION_NAME
volume_id=""
if command -v openstack &>/dev/null; then
  volume_id=$(openstack volume list --name "$DB_VOLUME_NAME" -f value -c ID 2>/dev/null | head -1 || true)
fi

if [ -n "$volume_id" ]; then
  echo "Importing existing volume $volume_id"
  var_args=()
  if [ -n "${TOFU_VAR_FILE:-}" ]; then
    var_args+=("-var-file=${TOFU_VAR_FILE}")
  elif [ -f "tofu.tfvars.json" ]; then
    var_args+=("-var-file=tofu.tfvars.json")
  fi

  script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  if ! bash "$script_dir/../common/tofu-retry.sh" tofu import -no-color -input=false "${var_args[@]}" openstack_blockstorage_volume_v3.db "$volume_id" 2>&1; then
    echo "Volume import failed; will retry during apply"
  fi
else
  echo "No existing volume found; will create on apply"
fi
