#!/usr/bin/env bash
# OVH OpenStack FULL cleanup — deletes everything except volumes and S3 buckets.
# Run inside a container with openstack CLI and OS_* env vars set.
#
# Usage (on backend server):
#   docker run --rm -it \
#     -e OS_AUTH_URL="https://auth.cloud.ovh.us/" \
#     -e OS_PROJECT_ID="17f0d53c3d4249119bbe88db7480d983" \
#     -e OS_PROJECT_NAME="2417763858960086" \
#     -e OS_USER_DOMAIN_NAME="ovhcloud-us" \
#     -e OS_PROJECT_DOMAIN_ID="default" \
#     -e OS_USERNAME="user-EZa9YuA5RNXYR45jnRyp6grjEeeBkhTAqyMKCmRvhm8R" \
#     -e OS_PASSWORD="<PASSWORD>" \
#     -e OS_REGION_NAME="US-EAST-VA-1" \
#     -e OS_INTERFACE="public" \
#     -e OS_IDENTITY_API_VERSION="3" \
#     -v $(pwd)/infrazero-infra-public/scripts/ovh/nuke-all.sh:/nuke.sh:ro \
#     openstacktools/openstack-client bash /nuke.sh

set -euo pipefail

echo "============================================"
echo " OVH OpenStack NUKE (keep volumes & buckets)"
echo " Region: ${OS_REGION_NAME:-unknown}"
echo " Project: ${OS_PROJECT_ID:-unknown}"
echo "============================================"
echo ""

# Verify auth
if ! openstack token issue -f value -c id >/dev/null 2>&1; then
  echo "ERROR: Authentication failed. Check OS_* env vars."
  exit 1
fi
echo "[OK] Authenticated"
echo ""

# ─── 1. Instances ─────────────────────────────────────────────────────
echo "=== 1. Deleting instances ==="
ids=$(openstack server list -f value -c ID 2>/dev/null || true)
if [ -n "$ids" ]; then
  for id in $ids; do
    name=$(openstack server show "$id" -f value -c name 2>/dev/null || echo "$id")
    echo "  DELETE instance: $name ($id)"
    openstack server delete "$id" --wait 2>/dev/null || true
  done
else
  echo "  (none)"
fi
echo ""

# ─── 2. Load Balancers ────────────────────────────────────────────────
echo "=== 2. Deleting load balancers ==="
ids=$(openstack loadbalancer list -f value -c id 2>/dev/null || true)
if [ -n "$ids" ]; then
  for id in $ids; do
    echo "  DELETE LB: $id (cascade)"
    openstack loadbalancer delete "$id" --cascade --wait 2>/dev/null || true
  done
else
  echo "  (none)"
fi
echo ""

# ─── 3. Floating IPs ─────────────────────────────────────────────────
echo "=== 3. Deleting floating IPs ==="
ids=$(openstack floating ip list -f value -c ID 2>/dev/null || true)
if [ -n "$ids" ]; then
  for id in $ids; do
    ip=$(openstack floating ip show "$id" -f value -c floating_ip_address 2>/dev/null || echo "$id")
    echo "  DELETE floating IP: $ip ($id)"
    openstack floating ip delete "$id" 2>/dev/null || true
  done
else
  echo "  (none)"
fi
echo ""

# ─── 4. Routers ──────────────────────────────────────────────────────
echo "=== 4. Deleting routers ==="
ids=$(openstack router list -f value -c ID 2>/dev/null || true)
if [ -n "$ids" ]; then
  for router_id in $ids; do
    name=$(openstack router show "$router_id" -f value -c name 2>/dev/null || echo "$router_id")
    echo "  Router: $name ($router_id) — removing interfaces"
    # Remove all ports from router
    port_ids=$(openstack port list --router "$router_id" -f value -c ID 2>/dev/null || true)
    for port_id in $port_ids; do
      openstack router remove port "$router_id" "$port_id" 2>/dev/null || true
    done
    # Try removing subnets too
    subnet_ids=$(openstack port list --router "$router_id" -f value -c "Fixed IP Addresses" 2>/dev/null | grep -oP "subnet_id='[^']+'" | cut -d"'" -f2 || true)
    for subnet_id in $subnet_ids; do
      openstack router remove subnet "$router_id" "$subnet_id" 2>/dev/null || true
    done
    echo "  DELETE router: $name"
    openstack router delete "$router_id" 2>/dev/null || true
  done
else
  echo "  (none)"
fi
echo ""

# ─── 5. Ports (non-system) ───────────────────────────────────────────
echo "=== 5. Deleting orphaned ports ==="
port_lines=$(openstack port list -f value -c ID -c "Device Owner" 2>/dev/null || true)
deleted=0
if [ -n "$port_lines" ]; then
  while IFS= read -r line; do
    port_id=$(echo "$line" | awk '{print $1}')
    owner=$(echo "$line" | awk '{print $2}')
    # Skip system-managed ports
    case "$owner" in
      network:dhcp|network:router_interface_distributed|network:router_centralized_snat|network:ha_router_replicated_interface)
        continue ;;
    esac
    echo "  DELETE port: $port_id (owner: $owner)"
    openstack port delete "$port_id" 2>/dev/null || true
    deleted=$((deleted + 1))
  done <<< "$port_lines"
fi
if [ "$deleted" -eq 0 ]; then echo "  (none)"; fi
echo ""

# ─── 6. Networks (internal only) ─────────────────────────────────────
echo "=== 6. Deleting internal networks ==="
ids=$(openstack network list --internal -f value -c ID 2>/dev/null || true)
if [ -n "$ids" ]; then
  for net_id in $ids; do
    name=$(openstack network show "$net_id" -f value -c name 2>/dev/null || echo "$net_id")
    # Delete subnets first
    subnet_ids=$(openstack subnet list --network "$net_id" -f value -c ID 2>/dev/null || true)
    for subnet_id in $subnet_ids; do
      echo "  DELETE subnet in $name ($subnet_id)"
      openstack subnet delete "$subnet_id" 2>/dev/null || true
    done
    echo "  DELETE network: $name ($net_id)"
    openstack network delete "$net_id" 2>/dev/null || true
  done
else
  echo "  (none)"
fi
echo ""

# ─── 7. Security Groups (non-default) ────────────────────────────────
echo "=== 7. Deleting security groups ==="
deleted=0
sg_lines=$(openstack security group list -f value -c ID -c Name 2>/dev/null || true)
if [ -n "$sg_lines" ]; then
  while IFS= read -r line; do
    sg_id=$(echo "$line" | awk '{print $1}')
    sg_name=$(echo "$line" | awk '{$1=""; print $0}' | xargs)
    if [ "$sg_name" = "default" ]; then continue; fi
    echo "  DELETE security group: $sg_name ($sg_id)"
    openstack security group delete "$sg_id" 2>/dev/null || true
    deleted=$((deleted + 1))
  done <<< "$sg_lines"
fi
if [ "$deleted" -eq 0 ]; then echo "  (none)"; fi
echo ""

# ─── 8. Keypairs ─────────────────────────────────────────────────────
echo "=== 8. Deleting keypairs ==="
names=$(openstack keypair list -f value -c Name 2>/dev/null || true)
if [ -n "$names" ]; then
  for name in $names; do
    echo "  DELETE keypair: $name"
    openstack keypair delete "$name" 2>/dev/null || true
  done
else
  echo "  (none)"
fi
echo ""

# ─── Summary ─────────────────────────────────────────────────────────
echo "============================================"
echo " Cleanup complete. Remaining:"
echo "============================================"
echo ""
echo "Instances:"
openstack server list 2>/dev/null || echo "  (error listing)"
echo ""
echo "Networks:"
openstack network list 2>/dev/null || echo "  (error listing)"
echo ""
echo "Security Groups:"
openstack security group list 2>/dev/null || echo "  (error listing)"
echo ""
echo "Volumes (KEPT):"
openstack volume list 2>/dev/null || echo "  (error listing)"
echo ""
echo "Done."
