#!/usr/bin/env bash
# Print the OpenStack volume ID for the given volume name (empty if absent).
# Prefers the openstack CLI; falls back to a direct Cinder API call (works in
# GitHub Actions and other environments where the CLI is not installed).
set -euo pipefail

volume_name="${1:?volume name required}"

volume_id=""
if command -v openstack &>/dev/null; then
  volume_id=$(openstack volume list --name "$volume_name" -f value -c ID 2>/dev/null | head -1 || true)
fi

if [ -z "$volume_id" ] && [ -n "${OS_AUTH_URL:-}" ] && [ -n "${OS_USERNAME:-}" ] && [ -n "${OS_PASSWORD:-}" ] && [ -n "${OS_TENANT_ID:-}" ]; then
  echo "[volume-id] openstack CLI not available; using direct Cinder API" >&2
  region="${OS_REGION_NAME:-${CLOUD_REGION:-}}"

  # Obtain Keystone token
  token_json=$(curl -sS -X POST "${OS_AUTH_URL}/auth/tokens" \
    -H "Content-Type: application/json" \
    -d '{"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"'"${OS_USERNAME}"'","password":"'"${OS_PASSWORD}"'","domain":{"name":"Default"}}}},"scope":{"project":{"id":"'"${OS_TENANT_ID}"'"}}}}' \
    -D - 2>/dev/null || true)
  token=$(echo "$token_json" | grep -i '^X-Subject-Token:' | awk '{print $2}' | tr -d '\r')
  if [ -n "$token" ]; then
    cinder_url="https://volume.${region}.cloud.ovh.net/v3/${OS_TENANT_ID}/volumes?name=${volume_name}"
    volume_id=$(curl -sS -H "X-Auth-Token: ${token}" "$cinder_url" 2>/dev/null | jq -r '.volumes[0].id // empty' || true)
    if [ -n "$volume_id" ]; then
      echo "[volume-id] found existing volume via API: $volume_id" >&2
    fi
  else
    echo "[volume-id] unable to obtain Keystone token; skipping API lookup" >&2
  fi
fi

printf '%s\n' "$volume_id"
