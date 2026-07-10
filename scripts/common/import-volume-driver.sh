#!/usr/bin/env bash
# Shared driver for provider import-volume.sh scripts.
# Usage (from the tofu provider dir, like the provider scripts):
#   DB_VOLUME_NAME=<name> import-volume-driver.sh <state-address> <lookup-script>
# <lookup-script> prints the provider volume ID for $1 (or nothing if absent).
set -euo pipefail

state_address="${1:?state address required (e.g. hcloud_volume.db)}"
lookup_script="${2:?volume lookup script required}"

if [ -z "${DB_VOLUME_NAME:-}" ]; then
  echo "DB_VOLUME_NAME is required" >&2
  exit 1
fi

if tofu state list 2>/dev/null | grep -qx "$state_address"; then
  echo "DB volume already in state"
  exit 0
fi

_driver_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

volume_id=$(bash "$lookup_script" "$DB_VOLUME_NAME" || true)
if [ -n "$volume_id" ]; then
  echo "Importing existing volume $volume_id"
  var_args=()
  if [ -n "${TOFU_VAR_FILE:-}" ]; then
    var_args+=("-var-file=${TOFU_VAR_FILE}")
  elif [ -f "tofu.tfvars.json" ]; then
    var_args+=("-var-file=tofu.tfvars.json")
  fi
  if ! bash "${_driver_dir}/tofu-retry.sh" tofu import -no-color -input=false "${var_args[@]}" "$state_address" "$volume_id" 2>&1; then
    echo "Volume import failed (likely for_each planning issue); will retry during apply"
  fi
else
  echo "No existing volume found; will create on apply"
fi
