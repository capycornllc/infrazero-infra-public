#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "usage: $0 <volume-name>" >&2
  exit 1
fi

if [ -z "${HCLOUD_TOKEN:-}" ]; then
  echo "HCLOUD_TOKEN is required" >&2
  exit 1
fi

name="$1"
response=$(curl -fsSL -H "Authorization: Bearer ${HCLOUD_TOKEN}" "https://api.hetzner.cloud/v1/volumes?name=${name}")
volume_id=$(echo "$response" | jq -r '.volumes[0].id // empty')

if [ -n "$volume_id" ]; then
  echo "$volume_id"
fi
