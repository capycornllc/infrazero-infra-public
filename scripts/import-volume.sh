#!/usr/bin/env bash
set -euo pipefail

if [ -z "${DB_VOLUME_NAME:-}" ]; then
  echo "DB_VOLUME_NAME is required" >&2
  exit 1
fi

if tofu -no-color state list 2>/dev/null | grep -qx "hcloud_volume.db"; then
  echo "DB volume already in state"
  exit 0
fi

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
volume_id=$("$script_dir/hcloud-volume-id.sh" "$DB_VOLUME_NAME" || true)
if [ -n "$volume_id" ]; then
  echo "Importing existing volume $volume_id"
  var_args=()
  if [ -n "${TOFU_VAR_FILE:-}" ]; then
    var_args+=("-var-file=${TOFU_VAR_FILE}")
  elif [ -f "tofu.tfvars.json" ]; then
    var_args+=("-var-file=tofu.tfvars.json")
  fi
  tofu -no-color import "${var_args[@]}" hcloud_volume.db "$volume_id"
else
  echo "No existing volume found; will create on apply"
fi
