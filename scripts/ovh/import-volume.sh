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
# Prefer the openstack CLI; fall back to a direct Cinder API call (works in
# GitHub Actions and other environments where the CLI is not installed).
volume_id=""
if command -v openstack &>/dev/null; then
  volume_id=$(openstack volume list --name "$DB_VOLUME_NAME" -f value -c ID 2>/dev/null | head -1 || true)
fi

if [ -z "$volume_id" ] && [ -n "${OS_AUTH_URL:-}" ] && [ -n "${OS_USERNAME:-}" ] && [ -n "${OS_PASSWORD:-}" ] && [ -n "${OS_TENANT_ID:-}" ]; then
  echo "[import-volume] openstack CLI not available; using direct Cinder API"
  region="${OS_REGION_NAME:-${CLOUD_REGION:-}}"

  # Obtain Keystone token
  token_json=$(curl -sS -X POST "${OS_AUTH_URL}/auth/tokens" \
    -H "Content-Type: application/json" \
    -d '{"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"'"${OS_USERNAME}"'","password":"'"${OS_PASSWORD}"'","domain":{"name":"Default"}}}},"scope":{"project":{"id":"'"${OS_TENANT_ID}"'"}}}}' \
    -D - 2>/dev/null || true)
  token=$(echo "$token_json" | grep -i '^X-Subject-Token:' | awk '{print $2}' | tr -d '\r')
  if [ -n "$token" ]; then
    # List volumes via Cinder v3 API
    cinder_url="https://volume.${region}.cloud.ovh.net/v3/${OS_TENANT_ID}/volumes?name=${DB_VOLUME_NAME}"
    volume_id=$(curl -sS -H "X-Auth-Token: ${token}" "$cinder_url" 2>/dev/null | jq -r '.volumes[0].id // empty' || true)
    if [ -n "$volume_id" ]; then
      echo "[import-volume] found existing volume via API: $volume_id"
    fi
  else
    echo "[import-volume] unable to obtain Keystone token; skipping API lookup"
  fi
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
