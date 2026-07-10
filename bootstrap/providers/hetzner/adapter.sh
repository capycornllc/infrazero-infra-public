#!/usr/bin/env bash
# Infrazero provider adapter: Hetzner Cloud.
#
# Contract: docs/provider-adapter-contract.md
# This file is sourced (not executed) by common bootstrap scripts. It must
# only define provider_* functions and export INFRAZERO_PROVIDER. Everything
# cloud-specific that common scripts need lives here; common scripts must not
# contain any provider branching themselves.

export INFRAZERO_PROVIDER="hetzner"

# --- Network ------------------------------------------------------------------

# provider_route_mode: how private/WG routes are managed on this cloud.
#   hetzner-32: guests get /32 private NICs; routes need an explicit gateway,
#               onlink next-hops and default-route repair.
provider_route_mode() {
  echo "hetzner-32"
}

# provider_private_gateway [cidr]: print the private network gateway IPv4.
# Hetzner: always the first usable address of the private CIDR.
provider_private_gateway() {
  local cidr="${1:-${PRIVATE_CIDR:-}}"
  [ -n "$cidr" ] || return 1
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
# Primary: interface holding an IPv4 inside the private CIDR.
# Fallback: Hetzner private NICs carry the MAC prefix 86:00:00 and can be
# detected before cloud-init assigns an address (the printed interface may
# have no IP yet).
provider_detect_private_iface() {
  local cidr="${1:-${PRIVATE_CIDR:-}}"
  local ifname=""
  if [ -n "$cidr" ] && command -v python3 >/dev/null 2>&1; then
    ifname=$(PRIVATE_CIDR="$cidr" python3 - <<'PY'
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
    ) || true
  fi
  if [ -z "$ifname" ]; then
    ifname=$(ip -o link show 2>/dev/null | awk '
      $2 == "lo:" { next }
      $2 ~ /^docker/ || $2 ~ /^br-/ || $2 ~ /^veth/ || $2 ~ /^tun/ || $2 ~ /^wg/ { next }
      {
        for (i = 1; i <= NF; i++) {
          if ($i ~ /^86:00:00:/) {
            name = $2; gsub(/:$/, "", name); print name; exit
          }
        }
      }
    ') || true
  fi
  [ -n "$ifname" ] || return 1
  echo "$ifname"
}

# provider_configure_private_nic <ipv4>: assign <ipv4>/32 to the not-yet-
# configured private NIC and fix subnet routes. Needed on Hetzner because
# cloud-init may race NIC attachment (observed on bastion and egress).
# Generalized from bastion's configure_bastion_private_if; stage 5 extends it
# with the egress systemd-networkd persistence.
provider_configure_private_nic() {
  local want_ip="${1:-}"
  if [ -z "$want_ip" ] || [ -z "${PRIVATE_CIDR:-}" ]; then
    return 0
  fi
  if ip -4 -o addr show | awk -v ip="$want_ip" '{split($4, parts, "/"); if (parts[1]==ip) found=1} END {exit found ? 0 : 1}'; then
    return 0
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    return 0
  fi

  local public_if private_if private_gw
  public_if=$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
  private_if=$(PUBLIC_IF="$public_if" python3 - <<'PY'
import os
import re
import subprocess

public_if = os.environ.get("PUBLIC_IF", "")
skip_prefixes = ("br-", "docker", "veth", "wg", "tun", "tap")
links = subprocess.check_output(["ip", "-o", "link", "show"]).decode().splitlines()
for line in links:
    match = re.match(r"\d+:\s+([^:@]+)", line)
    if not match:
        continue
    ifname = match.group(1)
    if ifname == "lo" or ifname == public_if or any(ifname.startswith(prefix) for prefix in skip_prefixes):
        continue
    print(ifname)
    raise SystemExit(0)
raise SystemExit(1)
PY
  ) || true
  if [ -z "$private_if" ]; then
    echo "[adapter] unable to find unconfigured private interface for ${want_ip}" >&2
    return 0
  fi

  private_gw=$(provider_private_gateway "$PRIVATE_CIDR") || return 0

  ip link set dev "$private_if" up || true
  sysctl -w "net.ipv4.conf.${private_if}.rp_filter=0" >/dev/null 2>&1 || true
  ip addr replace "${want_ip}/32" dev "$private_if" || true
  ip route replace "${private_gw}/32" dev "$private_if" scope link || true
  ip route del "${private_gw}/32" dev wg0 2>/dev/null || true
  ip route del "$PRIVATE_CIDR" dev wg0 2>/dev/null || true
  if [ -n "$public_if" ]; then
    ip route del "$PRIVATE_CIDR" dev "$public_if" 2>/dev/null || true
  fi
  if [ -n "${WG_CIDR:-}" ] && [ -n "$public_if" ]; then
    ip route del "$WG_CIDR" via "$private_gw" dev "$public_if" 2>/dev/null || true
  fi
  ip route replace "$PRIVATE_CIDR" via "$private_gw" dev "$private_if" onlink metric 50 || true
  echo "[adapter] configured private interface ${private_if} with ${want_ip}/32"
}

# provider_wg_snat_default: whether bastion masquerades WG traffic by default.
# Hetzner routes the WG subnet at the network layer, so SNAT is off.
provider_wg_snat_default() {
  echo "false"
}

# --- Storage ------------------------------------------------------------------

# provider_find_data_volume [volume_name]: print the block device path of the
# attached data volume. Hetzner exposes volumes via stable /dev/disk/by-id
# links (scsi-0HC_Volume_<name> / scsi-SHC_Volume_<name>).
provider_find_data_volume() {
  local volume_name="${1:-}"
  local candidate=""

  if [ -n "$volume_name" ] && [ -e "/dev/disk/by-id/scsi-0HC_Volume_${volume_name}" ]; then
    echo "/dev/disk/by-id/scsi-0HC_Volume_${volume_name}"
    return 0
  fi
  if [ -n "$volume_name" ] && [ -e "/dev/disk/by-id/scsi-SHC_Volume_${volume_name}" ]; then
    echo "/dev/disk/by-id/scsi-SHC_Volume_${volume_name}"
    return 0
  fi

  candidate=$(ls -1 /dev/disk/by-id/scsi-0HC_Volume_* 2>/dev/null | head -n 1 || true)
  if [ -n "$candidate" ]; then
    echo "$candidate"
    return 0
  fi

  candidate=$(ls -1 /dev/disk/by-id/scsi-SHC_Volume_* 2>/dev/null | head -n 1 || true)
  if [ -n "$candidate" ]; then
    echo "$candidate"
    return 0
  fi

  candidate=$(ls -1 /dev/disk/by-id/*Volume* 2>/dev/null | head -n 1 || true)
  if [ -n "$candidate" ]; then
    echo "$candidate"
    return 0
  fi

  return 1
}

# provider_volume_wait_defaults: print "<attempts> <sleep_seconds>" used while
# waiting for the data volume to attach. Hetzner attach is fast: 45 x 2 s.
provider_volume_wait_defaults() {
  echo "45 2"
}

# --- Misc ---------------------------------------------------------------------

# provider_metadata_get <key>: best-effort instance metadata lookup.
provider_metadata_get() {
  local key="${1:?metadata key required}"
  curl -fsS --max-time 5 "http://169.254.169.254/hetzner/v1/metadata/${key}" 2>/dev/null
}

# provider_outbound_defaults: export provider-appropriate defaults for the
# outbound-connectivity wait in infrazero_install_base_packages. Values that
# are already set in the environment are respected.
provider_outbound_defaults() {
  export INFRAZERO_PUBLIC_IPV4_AUTODETECT="${INFRAZERO_PUBLIC_IPV4_AUTODETECT:-false}"
  export INFRAZERO_OUTBOUND_CHECK_URL="${INFRAZERO_OUTBOUND_CHECK_URL:-https://mirror.hetzner.com}"
  export INFRAZERO_OUTBOUND_WAIT_ATTEMPTS="${INFRAZERO_OUTBOUND_WAIT_ATTEMPTS:-300}"
  export INFRAZERO_OUTBOUND_WAIT_DELAY="${INFRAZERO_OUTBOUND_WAIT_DELAY:-5}"
  export INFRAZERO_OUTBOUND_RETRY_BEACON_INTERVAL="${INFRAZERO_OUTBOUND_RETRY_BEACON_INTERVAL:-12}"
  export INFRAZERO_OUTBOUND_TIMEOUT_LABEL="${INFRAZERO_OUTBOUND_TIMEOUT_LABEL:-25 min}"
  export INFRAZERO_OUTBOUND_DEGRADED_ON_TIMEOUT="${INFRAZERO_OUTBOUND_DEGRADED_ON_TIMEOUT:-true}"
  export INFRAZERO_OUTBOUND_DUMP_ON_TIMEOUT="${INFRAZERO_OUTBOUND_DUMP_ON_TIMEOUT:-true}"
}

# provider_egress_setup_interfaces: set PUBLIC_IF / PRIVATE_IF globals for the
# egress role; return 1 when interfaces cannot be determined.
# Hetzner strategy: find the NIC whose MAC starts with 86:00:00: (Hetzner
# private-network prefix), excluding loopback and Docker/bridge/veth
# interfaces. We do NOT rely on the interface having an IP yet - Hetzner
# cloud-init may not have configured it before this runs (race observed in
# prod). If the IP never appears, self-configure from EGRESS_PRIVATE_IP and
# persist via systemd-networkd.
provider_egress_setup_interfaces() {
  _find_private_if() {
    ip -o link show | awk '
      $2 == "lo:" { next }
      $2 ~ /^docker/ || $2 ~ /^br-/ || $2 ~ /^veth/ || $2 ~ /^tun/ || $2 ~ /^wg/ { next }
      {
        for (i = 1; i <= NF; i++) {
          if ($i ~ /^86:00:00:/) {
            name = $2; gsub(/:$/, "", name); print name; exit
          }
        }
      }
    '
  }

  # If Hetzner private-NIC MAC not found, fall back to any non-virtual, non-public NIC.
  _find_private_if_fallback() {
    local pub="$1"
    ip -o link show | awk -v pub="$pub" '
      $2 == "lo:" { next }
      $2 ~ /^docker/ || $2 ~ /^br-/ || $2 ~ /^veth/ || $2 ~ /^tun/ || $2 ~ /^wg/ { next }
      {
        name = $2; gsub(/:$/, "", name)
        if (name != pub) { print name; exit }
      }
    '
  }

  PUBLIC_IF=""
  local private_if_name=""   # interface name (may have no IP yet)
  local _if_i
  for _if_i in $(seq 1 30); do
    PUBLIC_IF=$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
    if [ -n "$PUBLIC_IF" ]; then
      private_if_name=$(_find_private_if)
      if [ -z "$private_if_name" ]; then
        private_if_name=$(_find_private_if_fallback "$PUBLIC_IF")
      fi
    fi
    if [ -n "$PUBLIC_IF" ] && [ -n "$private_if_name" ]; then
      break
    fi
    echo "[egress] waiting for network interfaces (attempt $_if_i/30)..."
    sleep 2
  done

  if [ -z "$PUBLIC_IF" ] || [ -z "$private_if_name" ]; then
    echo "[egress] unable to determine network interfaces after 60s" >&2
    return 1
  fi

  # Ensure the private interface is UP and has its IP.
  # If Hetzner cloud-init hasn't configured it yet, do it ourselves using the
  # EGRESS_PRIVATE_IP variable injected by Terraform cloud-init (egress.env).
  #
  # FIX: wait up to 60s for Hetzner cloud-init to assign the IP before falling
  # through to self-configure. Root cause: _find_private_if() detects enp7s0 by
  # MAC prefix (no IP needed), so the outer interface-detection loop exits early
  # while Hetzner cloud-init is still racing to assign the address.
  # 12 attempts x 5 s = 60 s - covers observed Hetzner NIC configuration delays.
  local _priv_ip_wait
  for _priv_ip_wait in $(seq 1 12); do
    if ip -4 addr show dev "$private_if_name" 2>/dev/null | grep -q "inet "; then
      echo "[egress] $private_if_name has IP after ${_priv_ip_wait} attempt(s)"
      break
    fi
    if [ "$_priv_ip_wait" -eq 12 ]; then
      echo "[egress] $private_if_name still has no IP after 60s; falling back to self-configure" >&2
    else
      echo "[egress] waiting for Hetzner to configure $private_if_name (attempt ${_priv_ip_wait}/12)..."
      sleep 5
    fi
  done

  if ! ip -4 addr show dev "$private_if_name" 2>/dev/null | grep -q "inet "; then
    local _expected_priv_ip _priv_gw _priv_cidr_rt _priv_mac
    _expected_priv_ip="${EGRESS_PRIVATE_IP:-${PRIVATE_IP:-}}"
    if [ -n "$_expected_priv_ip" ]; then
      echo "[egress] private interface $private_if_name has no IP; configuring with $_expected_priv_ip"
      ip link set "$private_if_name" up || true
      ip addr add "${_expected_priv_ip}/32" dev "$private_if_name" 2>/dev/null || true
      _priv_gw=$(echo "$_expected_priv_ip" | awk -F. '{print $1"."$2"."$3".1"}')
      _priv_cidr_rt=$(echo "$_expected_priv_ip" | awk -F. '{print $1"."$2"."$3".0/24"}')
      ip route add "$_priv_cidr_rt" via "$_priv_gw" dev "$private_if_name" onlink 2>/dev/null || true
      # Persist across reboots via systemd-networkd
      _priv_mac=$(ip link show dev "$private_if_name" | awk '/link\/ether/{print $2}')
      mkdir -p /etc/systemd/network
      cat > "/etc/systemd/network/20-priv-${private_if_name}.network" <<NETEOF
[Match]
MACAddress=${_priv_mac}

[Network]
Address=${_expected_priv_ip}/32

[Route]
Destination=${_priv_cidr_rt}
Gateway=${_priv_gw}
GatewayOnLink=yes
NETEOF
      systemctl enable systemd-networkd 2>/dev/null || true
      systemctl reload-or-restart systemd-networkd 2>/dev/null || true
      echo "[egress] private interface $private_if_name persisted via systemd-networkd"
    else
      echo "[egress] WARNING: EGRESS_PRIVATE_IP/PRIVATE_IP not set; private interface $private_if_name left unconfigured" >&2
    fi
  fi

  PRIVATE_IF="$private_if_name"
  return 0
}
