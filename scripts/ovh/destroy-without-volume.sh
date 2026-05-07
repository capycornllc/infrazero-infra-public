#!/usr/bin/env bash
set -euo pipefail

existing=$(tofu state list 2>/dev/null || true)

if [ -z "$existing" ]; then
  echo "No state found; skipping destroy"
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

  local script_dir
  script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  bash "$script_dir/../common/tofu-retry.sh" tofu destroy -no-color -auto-approve -parallelism=1 "${var_args[@]}" "${targets[@]}"
}

# Load Balancer members and monitors first
destroy_targets_prefix openstack_lb_member_v2
destroy_targets_prefix openstack_lb_monitor_v2
destroy_targets_prefix openstack_lb_pool_v2
destroy_targets_prefix openstack_lb_listener_v2
destroy_targets_prefix openstack_lb_loadbalancer_v2

# Floating IP associations
destroy_targets_prefix openstack_compute_floatingip_associate_v2
destroy_targets_prefix openstack_networking_floatingip_v2

# Volume attachments (keep the volume itself)
destroy_targets_prefix openstack_compute_volume_attach_v2

# Destroy ALL servers
destroy_targets_prefix openstack_compute_instance_v2.bastion
destroy_targets_prefix openstack_compute_instance_v2.egress
destroy_targets_prefix openstack_compute_instance_v2.db
destroy_targets_prefix openstack_compute_instance_v2.k3s
destroy_targets_prefix openstack_compute_instance_v2.db_replica
destroy_targets_prefix openstack_compute_instance_v2.pgbouncer

# Destroy security groups and rules
destroy_targets_prefix openstack_networking_secgroup_rule_v2
destroy_targets_prefix openstack_networking_secgroup_v2

# Destroy SSH keypairs
destroy_targets_prefix openstack_compute_keypair_v2

# Rotate old S3 bootstrap data to old_backup/ before new deploy overwrites it
if [ -n "${S3_ENDPOINT:-}" ] && [ -n "${INFRA_STATE_BUCKET:-}" ] && [ -n "${DB_BACKUP_BUCKET:-}" ]; then
  timestamp=$(date +%Y%m%d_%H%M%S)
  echo "[destroy] Rotating old bootstrap data to old_backup/${timestamp}/"

  for role in bastion egress db node1 node2 nodecp db-replica; do
    aws --endpoint-url "$S3_ENDPOINT" s3 mv \
      "s3://${INFRA_STATE_BUCKET}/${role}.tar.zst" \
      "s3://${INFRA_STATE_BUCKET}/old_backup/${timestamp}/${role}.tar.zst" \
      2>/dev/null || true
  done

  aws --endpoint-url "$S3_ENDPOINT" s3 mv \
    "s3://${DB_BACKUP_BUCKET}/infisical/bootstrap/latest-tokens.json" \
    "s3://${DB_BACKUP_BUCKET}/old_backup/${timestamp}/infisical-latest-tokens.json" \
    2>/dev/null || true

  echo "[destroy] Old data moved to old_backup/${timestamp}/"
fi

# Network — only destroy AFTER all servers, LBs are gone
destroy_targets_prefix openstack_networking_router_interface_v2
destroy_targets_prefix openstack_networking_router_v2
destroy_targets_prefix openstack_networking_subnet_v2
destroy_targets_prefix openstack_networking_network_v2
