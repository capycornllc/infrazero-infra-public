#!/usr/bin/env bash
# Sync canonical shared tofu files into every provider directory.
# tofu cannot include declarations across root modules, so canonical shared
# files under tofu/common/ are copied verbatim into each provider root.
#
# Files kept in sync (add new shared tofu files here):
#   - variables-common.tf
#   - bootstrap-artifacts-state.tf
#
# Usage:
#   scripts/common/sync-tofu-common.sh          # copy canonical -> providers
#   scripts/common/sync-tofu-common.sh --check  # CI: fail on drift
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mode="${1:-sync}"

SYNC_FILES=(
  variables-common.tf
  bootstrap-artifacts-state.tf
)

rc=0
for fname in "${SYNC_FILES[@]}"; do
  canonical="${repo_root}/tofu/common/${fname}"
  if [ ! -f "$canonical" ]; then
    echo "[sync-tofu-common] canonical file missing: ${canonical}" >&2
    exit 1
  fi

  for dir in "${repo_root}"/tofu/*/; do
    name="$(basename "$dir")"
    case "$name" in
      common|modules) continue ;;
    esac
    target="${dir}${fname}"
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
done

if [ "$mode" = "--check" ] && [ "$rc" -eq 0 ]; then
  echo "[sync-tofu-common] all provider copies match canonical"
fi
exit "$rc"
