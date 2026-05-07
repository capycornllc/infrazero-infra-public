#!/usr/bin/env bash
set -euo pipefail

existing=$(tofu state list 2>/dev/null || true)

if [ -z "$existing" ]; then
  echo "No state found; skipping destroy"
  exit 0
fi

destroy_targets() {
  local targets=()
  for res in "$@"; do
    if echo "$existing" | grep -qx "$res"; then
      targets+=("-target=${res}")
    fi
  done

  if [ ${#targets[@]} -eq 0 ]; then
    return 0
  fi

  local var_args=()
  if [ -n "${TOFU_VAR_FILE:-}" ]; then
    var_args+=("-var-file=${TOFU_VAR_FILE}")
  elif [ -f "tofu.tfvars.json" ]; then
    var_args+=("-var-file=tofu.tfvars.json")
  fi

  local script_dir
  script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  bash "$script_dir/../common/tofu-retry.sh" tofu destroy -no-color -auto-approve -parallelism=1 "${var_args[@]}" "${targets[@]}"
}

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

  local script_dir
  script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  bash "$script_dir/../common/tofu-retry.sh" tofu destroy -no-color -auto-approve -parallelism=1 "${var_args[@]}" "${targets[@]}"
}

destroy_targets_prefix hcloud_load_balancer_service
destroy_targets_prefix hcloud_load_balancer_target

# Subnet/network destroy can hang/fail if any LB is still attached to the network.
destroy_targets_prefix hcloud_load_balancer_network
destroy_targets_prefix hcloud_load_balancer.

destroy_targets_prefix hcloud_volume_attachment

# Destroy ALL servers (use prefix to catch indexed resources like server.k3s[0])
destroy_targets_prefix hcloud_server.bastion
destroy_targets_prefix hcloud_server.egress
destroy_targets_prefix hcloud_server.db
destroy_targets_prefix hcloud_server.k3s
destroy_targets_prefix hcloud_server.db_replica
destroy_targets_prefix hcloud_server.pgbouncer

# Destroy ALL firewalls
destroy_targets_prefix hcloud_firewall.bastion
destroy_targets_prefix hcloud_firewall.egress
destroy_targets_prefix hcloud_firewall.k3s
destroy_targets_prefix hcloud_firewall.db
destroy_targets_prefix hcloud_firewall.db_replica
destroy_targets_prefix hcloud_firewall.pgbouncer

# Destroy placement groups
destroy_targets_prefix hcloud_placement_group.

# Destroy only ops SSH keys (project-specific, not user keys)
# Use prefix "hcloud_ssh_key.ops" to match ops["admin"] etc.
destroy_targets_prefix hcloud_ssh_key.ops

destroy_targets_prefix hcloud_network_route

# Rotate old S3 bootstrap data to old_backup/ before new deploy overwrites it
if [ -n "${S3_ENDPOINT:-}" ] && [ -n "${INFRA_STATE_BUCKET:-}" ] && [ -n "${DB_BACKUP_BUCKET:-}" ]; then
  timestamp=$(date +%Y%m%d_%H%M%S)
  echo "[destroy] Rotating old bootstrap data to old_backup/${timestamp}/"
  
  # Move infra state bootstrap artifacts (not terraform.tfstate — that stays)
  for role in bastion egress db node1 node2 nodecp db-replica; do
    aws --endpoint-url "$S3_ENDPOINT" s3 mv \
      "s3://${INFRA_STATE_BUCKET}/${role}.tar.zst" \
      "s3://${INFRA_STATE_BUCKET}/old_backup/${timestamp}/${role}.tar.zst" \
      2>/dev/null || true
  done
  
  # Move infisical bootstrap tokens
  aws --endpoint-url "$S3_ENDPOINT" s3 mv \
    "s3://${DB_BACKUP_BUCKET}/infisical/bootstrap/latest-tokens.json" \
    "s3://${DB_BACKUP_BUCKET}/old_backup/${timestamp}/infisical-latest-tokens.json" \
    2>/dev/null || true
  
  echo "[destroy] Old data moved to old_backup/${timestamp}/"
fi

# Network subnet and network — only destroy AFTER all servers, firewalls, LBs are gone
# This prevents the hang where Hetzner waits for attachments to be released
destroy_targets_prefix hcloud_network_subnet
destroy_targets_prefix hcloud_network.
