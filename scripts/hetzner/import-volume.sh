#!/usr/bin/env bash
# Hetzner: import the existing DB volume into state if present.
# Shared logic lives in scripts/common/import-volume-driver.sh.
set -euo pipefail
_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "${_script_dir}/../common/import-volume-driver.sh" \
  "hcloud_volume.db" "${_script_dir}/hcloud-volume-id.sh"
