#!/usr/bin/env bash
# OVH OpenStack full cleanup script
# Deletes ALL resources in a project/region (except volumes if KEEP_VOLUMES=true)
# Usage: bash cleanup-openstack.sh
set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────
export OS_AUTH_URL="https://auth.cloud.ovh.us/"
export OS_PROJECT_ID="17f0d53c3d4249119bbe88db7480d983"
export OS_PROJECT_NAME="2417763858960086"
export OS_USER_DOMAIN_NAME="ovhcloud-us"
export OS_PROJECT_DOMAIN_ID="default"
export OS_USERNAME="zj250-ovh"
export OS_PASSWORD="${OS_PASSWORD:?Set OS_PASSWORD env var}"
export OS_REGION_NAME="${OS_REGION_NAME:-US-EAST-VA-1}"
export OS_INTERFACE=public
export OS_IDENTITY_API_VERSION=3

KEEP_VOLUMES="${KEEP_VOLUMES:-true}"

echo "[cleanup] Region: $OS_REGION_NAME, Project: $OS_PROJECT_ID"
echo "[cleanup] Keep volumes: $KEEP_VOLUMES"
echo ""

# ─── 1. Delete instances ──────────────────────────────────────────────
echo "[cleanup] Deleting instances..."
for id in $(openstack server list -f value -c ID 2>/dev/null); do
  echo "  Deleting instance $id"
  openstack server delete "$id" --wait 2>/dev/null || true
done

# ─── 2. Delete load balancers ─────────────────────────────────────────
echo "[cleanup] Deleting load balancers..."
for id in $(openstack loadbalancer list -f value -c id 2>/dev/null); do
  echo "  Deleting LB $id (cascade)"
  openstack loadbalancer delete "$id" --cascade --wait 2>/dev/null || true
done

# ─── 3. Delete floating IPs ──────────────────────────────────────────
echo "[cleanup] Deleting floating IPs..."
for id in $(openstack floating ip list -f value -c ID 2>/dev/null); do
  echo "  Deleting floating IP $id"
  openstack floating ip delete "$id" 2>/dev/null || true
done

# ─── 4. Delete router interfaces and routers ─────────────────────────
echo "[cleanup] Deleting routers..."
for router_id in $(openstack router list -f value -c ID 2>/dev/null); do
  echo "  Router $router_id — removing interfaces"
  for subnet_id in $(openstack router show "$router_id" -f json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
ifaces = data.get('interfaces_info', [])
if isinstance(ifaces, str):
    import ast; ifaces = ast.literal_eval(ifaces)
for iface in ifaces:
    if isinstance(iface, dict):
        print(iface.get('subnet_id', ''))
" 2>/dev/null); do
    openstack router remove subnet "$router_id" "$subnet_id" 2>/dev/null || true
  done
  # Also try removing ports directly
  for port_id in $(openstack port list --router "$router_id" -f value -c ID 2>/dev/null); do
    openstack router remove port "$router_id" "$port_id" 2>/dev/null || true
  done
  echo "  Deleting router $router_id"
  openstack router delete "$router_id" 2>/dev/null || true
done

# ─── 5. Delete ports (non-system) ────────────────────────────────────
echo "[cleanup] Deleting orphaned ports..."
for port_id in $(openstack port list -f value -c ID 2>/dev/null); do
  device_owner=$(openstack port show "$port_id" -f value -c device_owner 2>/dev/null || echo "")
  # Skip system ports that will be auto-deleted
  if [[ "$device_owner" == "network:dhcp" ]] || [[ "$device_owner" == "network:router_interface_distributed" ]] || [[ "$device_owner" == "network:router_centralized_snat" ]]; then
    continue
  fi
  echo "  Deleting port $port_id (owner: $device_owner)"
  openstack port delete "$port_id" 2>/dev/null || true
done

# ─── 6. Delete subnets and networks (non-external) ───────────────────
echo "[cleanup] Deleting networks..."
for net_id in $(openstack network list --internal -f value -c ID 2>/dev/null); do
  net_name=$(openstack network show "$net_id" -f value -c name 2>/dev/null || echo "$net_id")
  # Delete subnets first
  for subnet_id in $(openstack subnet list --network "$net_id" -f value -c ID 2>/dev/null); do
    echo "  Deleting subnet $subnet_id"
    openstack subnet delete "$subnet_id" 2>/dev/null || true
  done
  echo "  Deleting network $net_name ($net_id)"
  openstack network delete "$net_id" 2>/dev/null || true
done

# ─── 7. Delete security groups (non-default) ─────────────────────────
echo "[cleanup] Deleting security groups..."
for sg_id in $(openstack security group list -f value -c ID -c Name 2>/dev/null | grep -v "^default " | awk '{print $1}'); do
  # Double check it's not default
  sg_name=$(openstack security group show "$sg_id" -f value -c name 2>/dev/null || echo "")
  if [ "$sg_name" = "default" ]; then continue; fi
  echo "  Deleting security group $sg_name ($sg_id)"
  openstack security group delete "$sg_id" 2>/dev/null || true
done

# ─── 8. Delete volumes (optional) ────────────────────────────────────
if [ "$KEEP_VOLUMES" != "true" ]; then
  echo "[cleanup] Deleting volumes..."
  for id in $(openstack volume list -f value -c ID 2>/dev/null); do
    echo "  Deleting volume $id"
    openstack volume delete "$id" 2>/dev/null || true
  done
else
  echo "[cleanup] Keeping volumes (KEEP_VOLUMES=true)"
fi

# ─── 9. Delete SSH keypairs ──────────────────────────────────────────
echo "[cleanup] Deleting keypairs..."
for name in $(openstack keypair list -f value -c Name 2>/dev/null); do
  echo "  Deleting keypair $name"
  openstack keypair delete "$name" 2>/dev/null || true
done

echo ""
echo "[cleanup] Done. Remaining resources:"
openstack server list 2>/dev/null || true
openstack network list 2>/dev/null || true
openstack security group list 2>/dev/null || true
openstack volume list 2>/dev/null || true
