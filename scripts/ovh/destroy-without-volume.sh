#!/usr/bin/env bash
set -euo pipefail

existing=$(tofu state list 2>/dev/null || true)

# ─── Fallback: if no tofu state, clean via OpenStack API directly ─────
if [ -z "$existing" ]; then
  echo "[destroy] No tofu state found — attempting OpenStack API cleanup"

  # Check if openstack CLI is available
  if ! command -v openstack >/dev/null 2>&1; then
    echo "[destroy] openstack CLI not found; cannot clean orphaned resources"
    echo "[destroy] Install with: pip3 install python-openstackclient python-octaviaclient"
    exit 0
  fi

  # Verify auth works
  if ! openstack token issue >/dev/null 2>&1; then
    echo "[destroy] OpenStack auth failed (OS_* env vars missing or invalid); skipping cleanup"
    exit 0
  fi

  echo "[destroy] Deleting instances..."
  for id in $(openstack server list -f value -c ID 2>/dev/null); do
    name=$(openstack server show "$id" -f value -c name 2>/dev/null || echo "$id")
    echo "  Deleting instance $name ($id)"
    openstack server delete "$id" --wait 2>/dev/null || true
  done

  echo "[destroy] Deleting load balancers..."
  for id in $(openstack loadbalancer list -f value -c id 2>/dev/null); do
    echo "  Deleting LB $id (cascade)"
    openstack loadbalancer delete "$id" --cascade --wait 2>/dev/null || true
  done

  echo "[destroy] Deleting floating IPs..."
  for id in $(openstack floating ip list -f value -c ID 2>/dev/null); do
    echo "  Deleting floating IP $id"
    openstack floating ip delete "$id" 2>/dev/null || true
  done

  echo "[destroy] Deleting routers..."
  for router_id in $(openstack router list -f value -c ID 2>/dev/null); do
    # Remove all ports from router
    for port_id in $(openstack port list --router "$router_id" -f value -c ID 2>/dev/null); do
      openstack router remove port "$router_id" "$port_id" 2>/dev/null || true
    done
    echo "  Deleting router $router_id"
    openstack router delete "$router_id" 2>/dev/null || true
  done

  echo "[destroy] Deleting ports..."
  for port_id in $(openstack port list -f value -c ID -c "Device Owner" 2>/dev/null | grep -v "network:dhcp\|network:router" | awk '{print $1}'); do
    openstack port delete "$port_id" 2>/dev/null || true
  done

  echo "[destroy] Deleting networks (internal only)..."
  for net_id in $(openstack network list --internal -f value -c ID 2>/dev/null); do
    for subnet_id in $(openstack subnet list --network "$net_id" -f value -c ID 2>/dev/null); do
      openstack subnet delete "$subnet_id" 2>/dev/null || true
    done
    openstack network delete "$net_id" 2>/dev/null || true
  done

  echo "[destroy] Deleting security groups (non-default)..."
  openstack security group list -f value -c ID -c Name 2>/dev/null | while read -r sg_id sg_name rest; do
    if [ "$sg_name" != "default" ]; then
      echo "  Deleting security group $sg_name ($sg_id)"
      openstack security group delete "$sg_id" 2>/dev/null || true
    fi
  done

  echo "[destroy] Deleting keypairs..."
  for name in $(openstack keypair list -f value -c Name 2>/dev/null); do
    echo "  Deleting keypair $name"
    openstack keypair delete "$name" 2>/dev/null || true
  done

  echo "[destroy] OpenStack API cleanup complete"
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

  for role in bastion egress db node1 node2 nodecp db-replica pgbouncer; do
    aws --endpoint-url "$S3_ENDPOINT" s3 mv \
      "s3://${INFRA_STATE_BUCKET}/bootstrap/${role}.tar.zst" \
      "s3://${INFRA_STATE_BUCKET}/old_backup/${timestamp}/bootstrap/${role}.tar.zst" \
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
