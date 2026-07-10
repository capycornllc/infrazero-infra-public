#!/usr/bin/env bash
# OVH/OpenStack: import the existing DB volume into state if present.
# Shared logic lives in scripts/common/import-volume-driver.sh.
set -euo pipefail
_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "${_script_dir}/../common/import-volume-driver.sh" \
  "openstack_blockstorage_volume_v3.db" "${_script_dir}/volume-id.sh"
