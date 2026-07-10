#!/usr/bin/env bash
# Sync canonical shared tofu files into every provider directory.
# tofu cannot include variable declarations across directories, so the
# canonical tofu/common/variables-common.tf is copied into each provider root.
#
# Usage:
#   scripts/common/sync-tofu-common.sh          # copy canonical -> providers
#   scripts/common/sync-tofu-common.sh --check  # CI: fail on drift
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
canonical="${repo_root}/tofu/common/variables-common.tf"
mode="${1:-sync}"

if [ ! -f "$canonical" ]; then
  echo "[sync-tofu-common] canonical file missing: ${canonical}" >&2
  exit 1
fi

rc=0
for dir in "${repo_root}"/tofu/*/; do
  name="$(basename "$dir")"
  case "$name" in
    common|modules) continue ;;
  esac
  target="${dir}variables-common.tf"
  if [ "$mode" = "--check" ]; then
    if ! cmp -s "$canonical" "$target"; then
      echo "[sync-tofu-common] DRIFT: ${target} differs from canonical (run scripts/common/sync-tofu-common.sh)" >&2
      rc=1
    fi
  else
    cp "$canonical" "$target"
    echo "[sync-tofu-common] synced ${target}"
  fi
done

if [ "$mode" = "--check" ] && [ "$rc" -eq 0 ]; then
  echo "[sync-tofu-common] all provider copies match canonical"
fi
exit "$rc"
