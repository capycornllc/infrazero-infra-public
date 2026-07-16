#!/usr/bin/env bash
# Infrazero provider adapter: OVHcloud (OpenStack).
#
# Contract: docs/provider-adapter-contract.md
# This file is sourced (not executed) by common bootstrap scripts. It must
# only define provider_* functions and export INFRAZERO_PROVIDER. Everything
# cloud-specific that common scripts need lives here; common scripts must not
# contain any provider branching themselves.

export INFRAZERO_PROVIDER="ovh"

# --- Network ------------------------------------------------------------------

# provider_route_mode: how private/WG routes are managed on this cloud.
#   ovh-dhcp: private NICs are configured by OpenStack DHCP with a proper
#             prefix; the WG subnet must be routed via the bastion private IP
#             because the OpenStack router does not know the WG subnet.
provider_route_mode() {
  echo "ovh-dhcp"
}

# provider_private_gateway [cidr]: print the private network gateway IPv4.
# OVH: prefer the gateway from the kernel route (set by OpenStack DHCP),
# fall back to the first usable address of the CIDR.
provider_private_gateway() {
  local cidr="${1:-${PRIVATE_CIDR:-}}"
  local gw=""
  [ -n "$cidr" ] || return 1

  gw=$(ip route show "$cidr" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via") {print $(i+1); exit}}' || true)
  if [ -n "$gw" ]; then
    echo "$gw"
    return 0
  fi

  command -v python3 >/dev/null 2>&1 || return 1
  PRIVATE_CIDR="$cidr" python3 - <<'PY'
import ipaddress
import os
cidr = os.environ.get("PRIVATE_CIDR", "")
try:
    net = ipaddress.ip_network(cidr, strict=False)
except Exception:
    raise SystemExit(1)
if net.num_addresses > 1:
    gw = net.network_address + 1
else:
    gw = net.network_address
print(str(gw))
PY
}

# provider_detect_private_iface [cidr]: print the private NIC name.
# OVH: the interface holding an IPv4 inside the private CIDR (DHCP assigns
# the address early, so IP-based detection is reliable).
provider_detect_private_iface() {
  local cidr="${1:-${PRIVATE_CIDR:-}}"
  [ -n "$cidr" ] || return 1
  command -v python3 >/dev/null 2>&1 || return 1
  PRIVATE_CIDR="$cidr" python3 - <<'PY'
import ipaddress
import os
import subprocess
cidr = os.environ.get("PRIVATE_CIDR", "")
try:
    net = ipaddress.ip_network(cidr, strict=False)
except Exception:
    raise SystemExit(1)
output = subprocess.check_output(["ip", "-4", "-o", "addr", "show"]).decode()
for line in output.splitlines():
    parts = line.split()
    if len(parts) < 4:
        continue
    ifname = parts[1]
    addr = parts[3].split("/")[0]
    try:
        if ipaddress.ip_address(addr) in net:
            print(ifname)
            raise SystemExit(0)
    except Exception:
        continue
raise SystemExit(1)
PY
}

# provider_configure_private_nic <ipv4>: no-op on OVH. OpenStack DHCP fully
# configures private NICs (address, prefix and subnet route).
provider_configure_private_nic() {
  return 0
}

# provider_wg_snat_default: whether bastion masquerades WG traffic by default.
# OVH: the OpenStack router does not route the WG subnet back to bastion, so
# SNAT is required by default.
provider_wg_snat_default() {
  echo "true"
}

# OVH Ubuntu images can already contain an "admin" group. The historical OVH
# bootstrap used useradd -N for platform admin users to avoid failing when the
# requested username matches an existing group.
provider_admin_useradd_options() {
  echo "-N"
}

# --- Storage ------------------------------------------------------------------

# provider_find_data_volume [volume_name]: print the block device path of the
# attached data volume. OVH first tries /dev/disk/by-id links, then falls back
# to the first unmounted plain disk: OVH can expose attached volumes as a
# plain QEMU disk by serial, without a by-id link containing the OpenStack
# volume name.
provider_find_data_volume() {
  local candidate=""

  # OVH exposes attached volumes as plain QEMU disks (by serial), usually
  # without an OpenStack-name by-id link. Match a generic *Volume* by-id link
  # if present, otherwise fall back to the first unmounted disk (below).
  candidate=$(ls -1 /dev/disk/by-id/*Volume* 2>/dev/null | head -n 1 || true)
  if [ -n "$candidate" ]; then
    echo "$candidate"
    return 0
  fi

  candidate=$(lsblk -rpno NAME,TYPE,MOUNTPOINT 2>/dev/null | awk '
    $2 == "disk" {
      disk = $1
      mounted = 0
      cmd = "lsblk -nrpo MOUNTPOINT " disk
      while ((cmd | getline mp) > 0) {
        if (mp ~ "^/") {
          mounted = 1
        }
      }
      close(cmd)
      if (mounted == 0 && disk !~ "^/dev/(loop|ram|sr)") {
        print disk
        exit
      }
    }
  ' || true)
  if [ -n "$candidate" ]; then
    echo "$candidate"
    return 0
  fi

  return 1
}

# provider_volume_wait_defaults: print "<attempts> <sleep_seconds>" used while
# waiting for the data volume to attach. OVH attach can be slow: 360 x 5 s.
provider_volume_wait_defaults() {
  echo "360 5"
}

# --- Misc ---------------------------------------------------------------------

# provider_metadata_get <key>: best-effort instance metadata lookup
# (OpenStack meta_data.json).
provider_metadata_get() {
  local key="${1:?metadata key required}"
  curl -fsS --max-time 5 "http://169.254.169.254/openstack/latest/meta_data.json" 2>/dev/null \
    | jq -r --arg k "$key" '.[$k] // empty' 2>/dev/null
}

# provider_outbound_defaults: export provider-appropriate defaults for the
# outbound-connectivity wait in infrazero_install_base_packages. Values that
# are already set in the environment are respected.
provider_outbound_defaults() {
  export INFRAZERO_PUBLIC_IPV4_AUTODETECT="${INFRAZERO_PUBLIC_IPV4_AUTODETECT:-true}"
  export INFRAZERO_OUTBOUND_CHECK_URL="${INFRAZERO_OUTBOUND_CHECK_URL:-https://connectivity-check.ubuntu.com}"
  export INFRAZERO_PUBLIC_IPV4_CHECK_URL="${INFRAZERO_PUBLIC_IPV4_CHECK_URL:-https://connectivity-check.ubuntu.com}"
  export INFRAZERO_OUTBOUND_WAIT_ATTEMPTS="${INFRAZERO_OUTBOUND_WAIT_ATTEMPTS:-90}"
  export INFRAZERO_OUTBOUND_WAIT_DELAY="${INFRAZERO_OUTBOUND_WAIT_DELAY:-2}"
  export INFRAZERO_OUTBOUND_RETRY_BEACON_INTERVAL="${INFRAZERO_OUTBOUND_RETRY_BEACON_INTERVAL:-0}"
  export INFRAZERO_OUTBOUND_DEGRADED_ON_TIMEOUT="${INFRAZERO_OUTBOUND_DEGRADED_ON_TIMEOUT:-false}"
  export INFRAZERO_OUTBOUND_DUMP_ON_TIMEOUT="${INFRAZERO_OUTBOUND_DUMP_ON_TIMEOUT:-false}"
}

# provider_egress_setup_interfaces: set PUBLIC_IF / PRIVATE_IF globals for the
# egress role; return 1 when interfaces cannot be determined.
# OVH Floating IPs are usually implemented by OpenStack outside the guest, so a
# public egress VM may still have a single private interface inside the OS.
# PUBLIC_IF = interface with the default route
# PRIVATE_IF = interface with an IP from PRIVATE_CIDR; may equal PUBLIC_IF on OVH
provider_egress_setup_interfaces() {
  PUBLIC_IF=$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')

  PRIVATE_IF=""
  if [ -n "${PRIVATE_CIDR:-}" ] && command -v python3 >/dev/null 2>&1; then
    PRIVATE_IF=$(PRIVATE_CIDR="$PRIVATE_CIDR" python3 - <<'PY'
import ipaddress
import os
import subprocess

cidr = os.environ.get("PRIVATE_CIDR", "")
try:
    net = ipaddress.ip_network(cidr, strict=False)
except Exception:
    raise SystemExit(1)

output = subprocess.check_output(["ip", "-4", "-o", "addr", "show"]).decode()
for line in output.splitlines():
    parts = line.split()
    if len(parts) < 4:
        continue
    ifname = parts[1]
    if ifname == "lo":
        continue
    addr = parts[3].split("/")[0]
    try:
        if ipaddress.ip_address(addr) in net:
            print(ifname)
            raise SystemExit(0)
    except Exception:
        continue
raise SystemExit(1)
PY
    ) || true
  fi

  # Fallbacks keep bootstrapping alive if routing or addressing appears in a
  # different order during early boot.
  if [ -z "$PRIVATE_IF" ]; then
    PRIVATE_IF=$(ip -4 -o addr show | awk -v pub="$PUBLIC_IF" '$2 != pub && $2 != "lo" {print $2; exit}')
  fi
  if [ -z "$PRIVATE_IF" ]; then
    PRIVATE_IF="$PUBLIC_IF"
  fi
  if [ -z "$PUBLIC_IF" ]; then
    PUBLIC_IF="$PRIVATE_IF"
  fi

  if [ -z "$PUBLIC_IF" ] || [ -z "$PRIVATE_IF" ]; then
    echo "[egress] unable to determine network interfaces (public=$PUBLIC_IF, private=$PRIVATE_IF)" >&2
    return 1
  fi

  if [ "$PUBLIC_IF" = "$PRIVATE_IF" ]; then
    echo "[egress] using OVH single-interface mode for Floating IP routing"
  fi
  return 0
}
