#!/usr/bin/env bash
# OVH/OpenStack: ordered destroy of everything except the data volume.
# Shared logic lives in scripts/common/destroy-without-volume-driver.sh.
set -euo pipefail

_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Fallback when no tofu state exists: clean orphans via the OpenStack API.
provider_no_state_cleanup() {
  echo "[destroy] No tofu state found - attempting OpenStack API cleanup"

  if ! command -v openstack >/dev/null 2>&1; then
    echo "[destroy] openstack CLI not found; cannot clean orphaned resources"
    echo "[destroy] Install with: pip3 install python-openstackclient python-octaviaclient"
    return 0
  fi

  if ! openstack token issue >/dev/null 2>&1; then
    echo "[destroy] OpenStack auth failed (OS_* env vars missing or invalid); skipping cleanup"
    return 0
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
}

DESTROY_PREFIXES_PRE_S3=(
  # Load Balancer members and monitors first
  openstack_lb_member_v2
  openstack_lb_monitor_v2
  openstack_lb_pool_v2
  openstack_lb_listener_v2
  openstack_lb_loadbalancer_v2
  # Floating IP associations
  openstack_compute_floatingip_associate_v2
  openstack_networking_floatingip_v2
  # Volume attachments (keep the volume itself)
  openstack_compute_volume_attach_v2
  # ALL servers
  openstack_compute_instance_v2.bastion
  openstack_compute_instance_v2.egress
  openstack_compute_instance_v2.db
  openstack_compute_instance_v2.k3s
  openstack_compute_instance_v2.db_replica
  openstack_compute_instance_v2.pgbouncer
  # Security groups and rules
  openstack_networking_secgroup_rule_v2
  openstack_networking_secgroup_v2
  # SSH keypairs
  openstack_compute_keypair_v2
)

# Network - only destroy AFTER all servers and LBs are gone
DESTROY_PREFIXES_POST_S3=(
  openstack_networking_router_interface_v2
  openstack_networking_router_v2
  openstack_networking_subnet_v2
  openstack_networking_network_v2
)

# shellcheck disable=SC1091
source "${_script_dir}/../common/destroy-without-volume-driver.sh"
