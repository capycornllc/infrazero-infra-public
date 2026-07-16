#!/usr/bin/env bash
# Materialize a single-cloud copy of this repository for end users.
#
# Users deploying to one cloud should not receive every other provider's code.
# This script copies ONLY what the selected cloud needs:
#   bootstrap/common + bootstrap/providers/<cloud> + bootstrap/<cloud>
#   tofu/<cloud> + tofu/modules + tofu/common
#   scripts/common + scripts/<cloud>
#   .github (workflows + select-provider action) + config + docs + README
#
# Usage:
#   scripts/common/materialize-user-repo.sh <cloud> <output-dir>
#   scripts/common/materialize-user-repo.sh hetzner /tmp/infrazero-hetzner
#
# Verification (recommended in CI for every supported cloud):
#   - the copy contains no other provider's directories;
#   - package-bootstrap.sh dry-run succeeds from the copy.
set -euo pipefail

usage() {
  echo "usage: scripts/common/materialize-user-repo.sh <cloud> <output-dir>" >&2
  echo "  <cloud>: one of the directories under bootstrap/providers (e.g. hetzner, ovh)" >&2
}

cloud="${1:-}"
out="${2:-}"
if [ -z "$cloud" ] || [ -z "$out" ]; then
  usage
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/common/provider-contract.sh
source "${repo_root}/scripts/common/provider-contract.sh"
if ! infrazero_validate_provider_contract "$repo_root" "$cloud"; then
  echo "[materialize] cloud '${cloud}' is not fully implemented" >&2
  exit 2
fi

if [ -e "$out" ] && [ -n "$(ls -A "$out" 2>/dev/null)" ]; then
  echo "[materialize] output directory exists and is not empty: ${out}" >&2
  exit 2
fi

copy() {
  local src="$1" dst_rel="${2:-$1}"
  mkdir -p "${out}/$(dirname "$dst_rel")"
  cp -a "${repo_root}/${src}" "${out}/${dst_rel}"
}

echo "[materialize] building single-cloud copy: cloud=${cloud} -> ${out}"
mkdir -p "$out"

# bootstrap: shared + selected provider only
copy bootstrap/common
mkdir -p "${out}/bootstrap/providers"
copy "bootstrap/providers/${cloud}" "bootstrap/providers/${cloud}"
copy "bootstrap/${cloud}" "bootstrap/${cloud}"

# tofu: selected provider + shared module + canonical common vars
copy "tofu/${cloud}" "tofu/${cloud}"
copy tofu/modules
copy tofu/common

# scripts: shared + selected provider only
copy scripts/common
copy "scripts/${cloud}" "scripts/${cloud}"

# CI, config, docs and top-level files
copy .github
copy config
[ -d "${repo_root}/docs" ] && copy docs
for f in README.md .gitignore .gitattributes; do
  if [ -f "${repo_root}/${f}" ]; then
    copy "$f"
  fi
done

# Cleanup: caches and tofu working dirs never belong in a user copy
find "$out" -type d \( -name "__pycache__" -o -name ".terraform" \) -prune -exec rm -rf {} + 2>/dev/null || true
find "$out" -type f \( -name "*.pyc" -o -name ".terraform.lock.hcl" \) -delete 2>/dev/null || true

# Self-check: no foreign provider directories may leak into the copy
leak=0
for p in "${repo_root}/bootstrap/providers"/*/; do
  other="$(basename "$p")"
  [ "$other" = "$cloud" ] && continue
  for d in "bootstrap/${other}" "bootstrap/providers/${other}" "tofu/${other}" "scripts/${other}"; do
    if [ -e "${out}/${d}" ]; then
      echo "[materialize] LEAK: ${d} present in single-cloud copy" >&2
      leak=1
    fi
  done
done
if [ "$leak" -ne 0 ]; then
  exit 1
fi

# Workflows are shared, but they must not name credentials from any cloud.
# The selected provider owns that mapping in scripts/<cloud>/ci-credentials.sh.
bash "${out}/scripts/${cloud}/ci-credentials.sh" --list-secret-names \
  | python "${out}/scripts/common/check-workflow-provider-isolation.py" \
      --github-dir "${out}/.github"

echo "[materialize] done: $(find "$out" -type f | wc -l) files"
echo "[materialize] verify with:"
echo "  cd ${out} && BOOTSTRAP_DIR=bootstrap/${cloud} BOOTSTRAP_OUTPUT_DIR=/tmp/matcheck PACKAGE_BOOTSTRAP_SKIP_UPLOAD=true PACKAGE_BOOTSTRAP_COMPRESSION=none bash scripts/common/package-bootstrap.sh --manifest /tmp/matcheck/manifest.json bastion egress node1 nodecp node2 db db-replica pgbouncer"
