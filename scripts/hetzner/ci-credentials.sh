#!/usr/bin/env bash
# Hetzner-only mapping from GitHub secrets to runtime/OpenTofu variables.
set -euo pipefail
set +x

if [ "${1:-}" = "--list-secret-names" ]; then
  echo "hetzner_cloud_token"
  exit 0
fi

repo_root="${INFRAZERO_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
python "${repo_root}/scripts/common/export-provider-secrets.py" \
  --required hetzner_cloud_token \
  --map HCLOUD_TOKEN=hetzner_cloud_token \
  --map TF_VAR_hcloud_token=hetzner_cloud_token

if [ -z "${PGBOUNCER_SERVER_TYPE:-}" ]; then
  echo "PGBOUNCER_SERVER_TYPE=cx23" >> "${GITHUB_ENV:?GITHUB_ENV is required}"
fi
