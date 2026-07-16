#!/usr/bin/env bash
# Shared driver for provider destroy-without-volume.sh scripts.
#
# The provider script defines (before sourcing this driver):
#   DESTROY_PREFIXES_PRE_S3   - ordered array of state-address prefixes destroyed
#                               BEFORE the S3 bootstrap-data rotation;
#   DESTROY_PREFIXES_POST_S3  - ordered array destroyed AFTER the rotation
#                               (networks last - prevents attachment hangs);
#   provider_no_state_cleanup - optional function used when tofu state is empty
#                               (e.g. OpenStack API cleanup of orphans).
#
# The data volume is intentionally never targeted - it must survive redeploys.
set -euo pipefail

_driver_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

existing=$(tofu state list 2>/dev/null || true)

if [ -z "$existing" ]; then
  if declare -F provider_no_state_cleanup >/dev/null 2>&1; then
    provider_no_state_cleanup
  else
    echo "No state found; skipping destroy"
  fi
  exit 0
fi

destroy_targets_prefix() {
  local prefix="$1"
  local targets=()
  while IFS= read -r res; do
    if [[ "$res" == ${prefix}* ]]; then
      targets+=("-target=${res}")
    fi
  done <<< "$existing"

  if [ ${#targets[@]} -eq 0 ]; then
    return 0
  fi

  local var_args=()
  if [ -n "${TOFU_VAR_FILE:-}" ]; then
    var_args+=("-var-file=${TOFU_VAR_FILE}")
  elif [ -f "tofu.tfvars.json" ]; then
    var_args+=("-var-file=tofu.tfvars.json")
  fi

  bash "${_driver_dir}/tofu-retry.sh" tofu destroy -no-color -auto-approve -parallelism=1 "${var_args[@]}" "${targets[@]}"
}

for _prefix in "${DESTROY_PREFIXES_PRE_S3[@]}"; do
  destroy_targets_prefix "$_prefix"
done

# Rotate old S3 bootstrap data to old_backup/ before new deploy overwrites it
if [ -n "${S3_ENDPOINT:-}" ] && [ -n "${INFRA_STATE_BUCKET:-}" ] && [ -n "${DB_BACKUP_BUCKET:-}" ]; then
  timestamp=$(date +%Y%m%d_%H%M%S)
  echo "[destroy] Rotating old bootstrap data to old_backup/${timestamp}/"

  # Move infra state bootstrap artifacts (not terraform.tfstate - that stays)
  for role in bastion egress db node1 node2 nodecp db-replica pgbouncer; do
    aws --endpoint-url "$S3_ENDPOINT" s3 mv \
      "s3://${INFRA_STATE_BUCKET}/bootstrap/${role}.tar.zst" \
      "s3://${INFRA_STATE_BUCKET}/old_backup/${timestamp}/bootstrap/${role}.tar.zst" \
      2>/dev/null || true
  done

  # Archive the token manifest, but keep the canonical copy. A restored
  # Infisical database still needs the same encrypted admin token so node1 can
  # resume GitOps bootstrap after the egress server is recreated.
  tokens_manifest="s3://${DB_BACKUP_BUCKET}/infisical/bootstrap/latest-tokens.json"
  if aws --endpoint-url "$S3_ENDPOINT" s3 ls "$tokens_manifest" >/dev/null 2>&1; then
    aws --endpoint-url "$S3_ENDPOINT" s3 cp \
      "$tokens_manifest" \
      "s3://${DB_BACKUP_BUCKET}/old_backup/${timestamp}/infisical-latest-tokens.json"
    echo "[destroy] Infisical token manifest archived and retained for restore"
  else
    echo "[destroy] No Infisical token manifest to archive"
  fi

  echo "[destroy] Old data moved to old_backup/${timestamp}/"
fi

for _prefix in "${DESTROY_PREFIXES_POST_S3[@]}"; do
  destroy_targets_prefix "$_prefix"
done
