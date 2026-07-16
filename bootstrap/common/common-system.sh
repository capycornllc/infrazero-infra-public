#!/usr/bin/env bash
# Shared "common" bootstrap phase for all providers. Provider wrappers
# (bootstrap/<provider>/common.sh) exec this script; all cloud specifics come
# from the provider adapter (see docs/provider-adapter-contract.md).
set -euo pipefail

LOG_FILE="/var/log/infrazero-bootstrap.log"
if [ -z "${_INFRAZERO_LOG_REDIRECTED:-}" ]; then
  exec > >(tee -a "$LOG_FILE") 2>&1
  export _INFRAZERO_LOG_REDIRECTED=1
fi

echo "[common] $(date -Is) start"

COMMON_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Bootstrap beacon (SOC 2: no secrets, descriptive labels only).
mkdir -p /etc/infrazero
if [ -f "${COMMON_SCRIPT_DIR}/beacon.sh" ]; then
  # shellcheck disable=SC1091
  . "${COMMON_SCRIPT_DIR}/beacon.sh"
elif [ -f "${COMMON_SCRIPT_DIR}/common-beacon.sh" ]; then
  # shellcheck disable=SC1091
  . "${COMMON_SCRIPT_DIR}/common-beacon.sh"
elif [ -f "${COMMON_SCRIPT_DIR}/../common/common-beacon.sh" ]; then
  # shellcheck disable=SC1091
  . "${COMMON_SCRIPT_DIR}/../common/common-beacon.sh"
elif [ -f "${COMMON_SCRIPT_DIR}/common-beacon-fallback.sh" ]; then
  # shellcheck disable=SC1091
  . "${COMMON_SCRIPT_DIR}/common-beacon-fallback.sh"
elif [ -f "${COMMON_SCRIPT_DIR}/../common/common-beacon-fallback.sh" ]; then
  # shellcheck disable=SC1091
  . "${COMMON_SCRIPT_DIR}/../common/common-beacon-fallback.sh"
else
  # Last resort: keep bootstrap alive without status reporting.
  beacon_status() { return 0; }
  beacon_retrying() { return 0; }
  beacon_degraded() { return 0; }
  beacon_failed() { return 0; }
fi

if declare -F infrazero_install_error_trap >/dev/null 2>&1; then
  infrazero_install_error_trap
fi

if [ -f "${COMMON_SCRIPT_DIR}/common-base.sh" ]; then
  # shellcheck disable=SC1091
  source "${COMMON_SCRIPT_DIR}/common-base.sh"
elif [ -f "${COMMON_SCRIPT_DIR}/../common/common-base.sh" ]; then
  # shellcheck disable=SC1091
  source "${COMMON_SCRIPT_DIR}/../common/common-base.sh"
fi

if ! declare -F infrazero_load_provider_adapter >/dev/null 2>&1; then
  echo "[common] common-base.sh missing infrazero_load_provider_adapter; cannot continue" >&2
  exit 1
fi
infrazero_load_provider_adapter "$COMMON_SCRIPT_DIR"

INFRAZERO_ROUTE_MODE="$(provider_route_mode)"

beacon_status "starting" "Bootstrap starting" 0

beacon_status "creating_admins" "Creating admin users" 5

if declare -F infrazero_setup_admin_users >/dev/null 2>&1; then
  infrazero_setup_admin_users "common"
else
  echo "[common] common-base.sh missing infrazero_setup_admin_users; skipping admin user creation" >&2
fi

install_packages() {
  if declare -F infrazero_install_base_packages >/dev/null 2>&1; then
    if declare -F provider_outbound_defaults >/dev/null 2>&1; then
      provider_outbound_defaults
    fi
    infrazero_install_base_packages "common" curl ca-certificates zstd jq e2fsprogs auditd unattended-upgrades
  else
    echo "[common] common-base.sh missing infrazero_install_base_packages; skipping base package install" >&2
  fi
}

install_packages

beacon_status "hardening_ssh" "Hardening SSH" 30

if declare -F infrazero_harden_ssh >/dev/null 2>&1; then
  infrazero_harden_ssh "common"
else
  echo "[common] common-base.sh missing infrazero_harden_ssh; skipping SSH hardening" >&2
fi

beacon_status "configuring_network" "Configuring network routes" 50

if declare -F infrazero_apply_network_baseline >/dev/null 2>&1; then
  infrazero_apply_network_baseline
else
  echo "[common] common-base.sh missing infrazero_apply_network_baseline; skipping network baseline" >&2
fi

# WG routing handled via network route (preferred) or SNAT on bastion; see bastion bootstrap.

if declare -F infrazero_write_network_env >/dev/null 2>&1; then
  infrazero_write_network_env
else
  echo "[common] common-base.sh missing infrazero_write_network_env; route helpers may be incomplete" >&2
fi

# ------------------------------------------------------------------------------
# Generated runtime route scripts. The provider choice is baked in at generation
# time via INFRAZERO_ROUTE_MODE (runtime scripts cannot call the adapter).
#   hetzner-32: /32 private NICs; explicit gateway/onlink routes, default-route
#               repair, WG subnet routed via the private gateway.
#   ovh-dhcp:   DHCP-configured NICs (private-route exits at the /32 check);
#               WG subnet routed via BASTION_PRIVATE_IP.
#   none:       cloud routes natively; both scripts are no-ops.
# ------------------------------------------------------------------------------

# Ensure /32 private NICs route the subnet via the gateway. On providers with
# DHCP subnets this is a no-op (prefix check below).
{
  printf '#!/usr/bin/env bash\nset -euo pipefail\nINFRAZERO_ROUTE_MODE=%q\n' "$INFRAZERO_ROUTE_MODE"
  cat <<'EOF'

NETWORK_ENV="/etc/infrazero/network.env"
if [ -f "$NETWORK_ENV" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$NETWORK_ENV"
  set +a
fi

if [ -z "${PRIVATE_CIDR:-}" ]; then
  exit 0
fi

if [ "$INFRAZERO_ROUTE_MODE" = "none" ]; then
  exit 0
fi

# Resolve the private gateway: prefer the kernel route (set by DHCP on
# OpenStack-like clouds), fall back to the first usable address of the CIDR.
private_gw=""
private_gw=$(ip route show "$PRIVATE_CIDR" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via") {print $(i+1); exit}}' || true)
if [ -z "$private_gw" ] && command -v python3 >/dev/null 2>&1; then
  private_gw=$(python3 - <<'PY'
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
  ) || true
fi
if [ -z "$private_gw" ]; then
  echo "[private-route] unable to resolve private gateway; skipping private route" >&2
  exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
  exit 0
fi

priv_if=$(python3 - <<'PY'
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
) || exit 0

prefix_len=$(ip -4 -o addr show "$priv_if" | awk '{print $4}' | cut -d/ -f2 | head -n 1 || true)
if [ "$prefix_len" != "32" ]; then
  exit 0
fi

ip link set dev "$priv_if" up || true
sysctl -w "net.ipv4.conf.${priv_if}.rp_filter=0" >/dev/null 2>&1 || true

ip route replace "${private_gw}/32" dev "$priv_if" scope link || true
ip route del "$PRIVATE_CIDR" dev "$priv_if" 2>/dev/null || true
ip route replace "$PRIVATE_CIDR" via "$private_gw" dev "$priv_if" onlink metric 50 || true

if [ "$INFRAZERO_ROUTE_MODE" = "hetzner-32" ]; then
  if ! ip route show default 2>/dev/null | grep -q "^default" || ! ip route get 1.1.1.1 >/dev/null 2>&1; then
    ip route replace default via "$private_gw" dev "$priv_if" onlink metric 50 || true
    echo "[private-route] default route repaired via ${private_gw} dev ${priv_if}"
  fi
fi
EOF
} > /usr/local/sbin/infrazero-private-route.sh

chmod +x /usr/local/sbin/infrazero-private-route.sh
/usr/local/sbin/infrazero-private-route.sh || true

cat > /etc/systemd/system/infrazero-private-route.service <<'EOF'
[Unit]
Description=Infrazero private subnet route fix
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/infrazero-private-route.sh

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now infrazero-private-route.service

if declare -F infrazero_install_systemd_timer >/dev/null 2>&1; then
  infrazero_install_systemd_timer \
    "infrazero-private-route" \
    "infrazero-private-route.service" \
    "Periodically repair Infrazero private network routes" \
    "90s" \
    "60s" \
    "10s"
fi

# Ensure the WireGuard subnet routes to bastion on non-WG hosts. The bastion
# owns WG_CIDR locally on wg0, so installing this guest route there creates a
# race that can redirect return traffic into the private network.
if [ "${BOOTSTRAP_ROLE:-}" = "bastion" ]; then
  systemctl disable --now infrazero-wg-route.timer infrazero-wg-route.service >/dev/null 2>&1 || true
  rm -f \
    /etc/systemd/system/infrazero-wg-route.timer \
    /etc/systemd/system/infrazero-wg-route.service \
    /usr/local/sbin/infrazero-wg-route.sh
  systemctl daemon-reload
  echo "[common] bastion owns ${WG_CIDR:-the WireGuard subnet} on wg0; guest WG route disabled"
else
{
  printf '#!/usr/bin/env bash\nset -euo pipefail\nINFRAZERO_ROUTE_MODE=%q\n' "$INFRAZERO_ROUTE_MODE"
  cat <<'EOF'

NETWORK_ENV="/etc/infrazero/network.env"
if [ -f "$NETWORK_ENV" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$NETWORK_ENV"
  set +a
fi

if [ -z "${PRIVATE_CIDR:-}" ] || [ -z "${WG_CIDR:-}" ]; then
  exit 0
fi

if [ "$INFRAZERO_ROUTE_MODE" = "none" ]; then
  exit 0
fi

if ip link show wg0 >/dev/null 2>&1; then
  # Bastion has wg0; kernel route exists already.
  exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
  exit 0
fi

# Resolve the private gateway: prefer the kernel route (set by DHCP on
# OpenStack-like clouds), fall back to the first usable address of the CIDR.
private_gw=""
private_gw=$(ip route show "$PRIVATE_CIDR" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via") {print $(i+1); exit}}' || true)
if [ -z "$private_gw" ]; then
  private_gw=$(python3 - <<'PY'
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
  ) || true
fi
if [ -z "$private_gw" ]; then
  echo "[wg-route] unable to resolve private gateway; cannot add WG route" >&2
  exit 0
fi

# Wait for the private interface to become available (race condition at boot).
# Default 90 attempts x 3 s = 4.5 min - covers slow private NIC attachment.
#
# NOTE: "ip route get $private_gw" is deliberately NOT used for detection.
# When the private NIC has no IP yet, it resolves via the default route and
# returns the public interface, installing the WG route on the wrong device.
# The python IP-in-CIDR check only matches an interface that actually has an
# address inside the private network.
wg_wait_attempts="${INFRAZERO_WG_ROUTE_WAIT_ATTEMPTS:-90}"
wg_wait_sleep="${INFRAZERO_WG_ROUTE_WAIT_SLEEP:-3}"
priv_if=""
for ((_wg_wait = 1; _wg_wait <= wg_wait_attempts; _wg_wait++)); do
  priv_if=$(python3 - <<'PY'
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
  if [ -n "$priv_if" ]; then
    break
  fi
  echo "[wg-route] waiting for private interface (attempt ${_wg_wait}/${wg_wait_attempts})..." >&2
  sleep "$wg_wait_sleep"
done

if [ -z "$priv_if" ]; then
  echo "[wg-route] private interface not found after ${wg_wait_attempts} attempts; cannot add WG route" >&2
  exit 0
fi

ip link set dev "$priv_if" up || true
sysctl -w "net.ipv4.conf.${priv_if}.rp_filter=0" >/dev/null 2>&1 || true

/usr/local/sbin/infrazero-private-route.sh || true

# WG subnet next hop:
#   hetzner-32: the cloud network routes WG_CIDR to bastion at the network
#               layer; guests with /32 NICs use the private gateway as the
#               local next hop.
#   ovh-dhcp:   the network gateway (OpenStack router) does not know the WG
#               subnet; route directly to the bastion private IP.
case "$INFRAZERO_ROUTE_MODE" in
  hetzner-32) wg_gw="$private_gw" ;;
  *) wg_gw="${BASTION_PRIVATE_IP:-$private_gw}" ;;
esac

cleanup_stale_wg_routes() {
  local route_line route_via route_dev route_metric
  local -a route_args

  while IFS= read -r route_line; do
    if [ -z "$route_line" ]; then
      continue
    fi

    route_via=$(printf '%s\n' "$route_line" | awk '{for (i=1;i<=NF;i++) if ($i=="via") {print $(i+1); exit}}')
    route_dev=$(printf '%s\n' "$route_line" | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
    route_metric=$(printf '%s\n' "$route_line" | awk '{for (i=1;i<=NF;i++) if ($i=="metric") {print $(i+1); exit}}')

    if [ "$route_via" = "$wg_gw" ] && [ "$route_dev" = "$priv_if" ] && [ "$route_metric" = "50" ]; then
      continue
    fi

    echo "[wg-route] removing stale ${WG_CIDR} route: ${route_line}"
    read -r -a route_args <<< "$route_line"
    if ! ip route del "${route_args[@]}" 2>/dev/null; then
      if [ -n "$route_via" ] && [ -n "$route_dev" ]; then
        ip route del "$WG_CIDR" via "$route_via" dev "$route_dev" 2>/dev/null || true
      elif [ -n "$route_dev" ]; then
        ip route del "$WG_CIDR" dev "$route_dev" 2>/dev/null || true
      else
        ip route del "$WG_CIDR" 2>/dev/null || true
      fi
    fi
  done < <(ip -4 route show "$WG_CIDR" 2>/dev/null || true)
}

cleanup_stale_wg_routes

ip route replace "$WG_CIDR" via "$wg_gw" dev "$priv_if" onlink metric 50 || true

wg_probe_ip=$(python3 - <<'PY'
import ipaddress
import os
cidr = os.environ.get("WG_CIDR", "")
try:
    net = ipaddress.ip_network(cidr, strict=False)
except Exception:
    raise SystemExit(1)
if net.num_addresses > 2:
    probe = net.network_address + 1
else:
    probe = net.network_address
print(str(probe))
PY
) || wg_probe_ip=""

if [ -n "$wg_probe_ip" ]; then
  selected_route=$(ip -4 route get "$wg_probe_ip" 2>/dev/null || true)
  selected_via=$(printf '%s\n' "$selected_route" | awk '{for (i=1;i<=NF;i++) if ($i=="via") {print $(i+1); exit}}')
  selected_dev=$(printf '%s\n' "$selected_route" | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
  if [ "$selected_via" != "$wg_gw" ] || [ "$selected_dev" != "$priv_if" ]; then
    echo "[wg-route] warning: ${WG_CIDR} selected route is '${selected_route}', expected via ${wg_gw} dev ${priv_if}" >&2
  fi
fi

echo "[wg-route] ensured ${WG_CIDR} via ${wg_gw} dev ${priv_if}"
EOF
} > /usr/local/sbin/infrazero-wg-route.sh

chmod +x /usr/local/sbin/infrazero-wg-route.sh
/usr/local/sbin/infrazero-wg-route.sh || true

cat > /etc/systemd/system/infrazero-wg-route.service <<'EOF'
[Unit]
Description=Infrazero WireGuard subnet route
After=network-online.target infrazero-private-route.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/infrazero-wg-route.sh

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now infrazero-wg-route.service
if declare -F infrazero_install_systemd_timer >/dev/null 2>&1; then
  infrazero_install_systemd_timer \
    "infrazero-wg-route" \
    "infrazero-wg-route.service" \
    "Periodically repair Infrazero WireGuard subnet route" \
    "120s" \
    "60s" \
    "10s"
fi
fi

if declare -F infrazero_configure_base_system >/dev/null 2>&1; then
  infrazero_configure_base_system
else
  echo "[common] common-base.sh missing infrazero_configure_base_system; skipping base system configuration" >&2
fi

beacon_status "common_complete" "Common setup complete" 80

echo "[common] $(date -Is) done"
