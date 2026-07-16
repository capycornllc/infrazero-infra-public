#!/usr/bin/env bash
# Shared bastion bootstrap for all providers. Provider wrappers
# (bootstrap/<provider>/bastion.sh) exec this script; cloud specifics come
# from the provider adapter (see docs/provider-adapter-contract.md):
#   - provider_configure_private_nic: self-configure racing private NICs
#     (Hetzner) or no-op (OVH/DHCP);
#   - provider_wg_snat_default: default for WG_SNAT_ENABLED.
set -euo pipefail

LOG_FILE="/var/log/infrazero-bootstrap.log"
if [ -z "${_INFRAZERO_LOG_REDIRECTED:-}" ]; then
  exec > >(tee -a "$LOG_FILE") 2>&1
  export _INFRAZERO_LOG_REDIRECTED=1
fi

echo "[bastion] $(date -Is) start"

BOOTSTRAP_ROLE="bastion"
BASTION_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "${BASTION_SCRIPT_DIR}/common-base.sh" ]; then
  # shellcheck disable=SC1091
  source "${BASTION_SCRIPT_DIR}/common-base.sh"
elif [ -f "${BASTION_SCRIPT_DIR}/../common/common-base.sh" ]; then
  # shellcheck disable=SC1091
  source "${BASTION_SCRIPT_DIR}/../common/common-base.sh"
fi

if ! declare -F infrazero_load_provider_adapter >/dev/null 2>&1; then
  echo "[bastion] common-base.sh missing infrazero_load_provider_adapter; cannot continue" >&2
  exit 1
fi
infrazero_load_provider_adapter "$BASTION_SCRIPT_DIR"

ENV_FILE="/etc/infrazero/bastion.env"
infrazero_load_env_file "$ENV_FILE"

infrazero_require_env "WG_SERVER_PRIVATE_KEY" "bastion"
infrazero_require_env "WG_SERVER_ADDRESS" "bastion"
infrazero_require_env "WG_LISTEN_PORT" "bastion"
infrazero_require_env "WG_ADMIN_PEERS_JSON" "bastion"
infrazero_require_env "WG_PRESHARED_KEYS_JSON" "bastion"
infrazero_require_env "EGRESS_LOKI_URL" "bastion"

DEBUG_ROOT_PASSWORD="${DEBUG_ROOT_PASSWORD:-}"

# Older common bootstrap versions installed the non-WG-host route repair on
# every role. Remove it here as a second role-local guard so bastion routing
# cannot depend on BOOTSTRAP_ROLE propagation or systemd timing.
systemctl disable --now infrazero-wg-route.timer infrazero-wg-route.service >/dev/null 2>&1 || true
rm -f \
  /etc/systemd/system/infrazero-wg-route.timer \
  /etc/systemd/system/infrazero-wg-route.service \
  /usr/local/sbin/infrazero-wg-route.sh
systemctl daemon-reload

beacon_status "installing_wireguard" "Installing WireGuard" 10

if ! declare -F infrazero_install_wireguard_packages >/dev/null 2>&1 || ! declare -F infrazero_configure_bastion_wireguard >/dev/null 2>&1; then
  echo "[bastion] common-base.sh missing WireGuard helpers" >&2
  exit 1
fi

infrazero_install_wireguard_packages "bastion"
infrazero_configure_bastion_wireguard "bastion"

beacon_status "configuring_firewall" "Configuring firewall and routing" 40

# Enable routing between WireGuard and private subnet
cat > /etc/sysctl.d/99-infrazero-forward.conf <<'EOF'
net.ipv4.ip_forward=1
EOF

sysctl --system

# Self-configure the private NIC when the cloud raced us (no-op on providers
# whose DHCP fully configures private NICs).
provider_configure_private_nic "${BASTION_PRIVATE_IP:-}"

detect_private_if() {
  local private_if=""
  private_if=$(ip -4 route show "$PRIVATE_CIDR" 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
  if [ -z "$private_if" ]; then
    private_if=$(ip -4 route list | awk -v cidr="$PRIVATE_CIDR" '$1==cidr {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
  fi
  if [ -z "$private_if" ] && [ -n "${BASTION_PRIVATE_IP:-}" ]; then
    private_if=$(ip -4 -o addr show | awk -v ip="$BASTION_PRIVATE_IP" '{split($4, parts, "/"); if (parts[1]==ip) {print $2; exit}}')
  fi
  if [ -z "$private_if" ]; then
    local public_if=""
    public_if=$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
    if [ -n "$public_if" ]; then
      private_if=$(ip -4 -o addr show | awk -v pub="$public_if" '$2 != pub && $2 != "lo" && $2 !~ /^wg/ && $2 !~ /^docker/ && $2 !~ /^br-/ && $2 !~ /^veth/ {print $2; exit}')
    fi
  fi
  echo "$private_if"
}

PRIVATE_IF=""
# 90 attempts x 5 s = 7.5 min - covers slow private NIC IP assignment races.
for i in {1..90}; do
  PRIVATE_IF=$(detect_private_if)
  if [ -n "$PRIVATE_IF" ]; then
    break
  fi
  echo "[bastion] waiting for private interface (attempt ${i}/90)..."
  sleep 5
done

SKIP_FORWARDING="false"
if [ -z "$PRIVATE_IF" ]; then
  echo "[bastion] unable to determine private interface for $PRIVATE_CIDR after 7.5 min; skipping WG forwarding" >&2
  SKIP_FORWARDING="true"
fi

PRIVATE_IP=""
if [ "$SKIP_FORWARDING" != "true" ]; then
  PRIVATE_IP=$(ip -4 -o addr show "$PRIVATE_IF" | awk '{print $4}' | cut -d/ -f1 | head -n 1)
  if [ -z "$PRIVATE_IP" ]; then
    echo "[bastion] unable to determine private IP for $PRIVATE_IF; skipping WG forwarding" >&2
    SKIP_FORWARDING="true"
  fi
fi

PUBLIC_IF=$(ip -4 route show table main default 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
PUBLIC_IP=""
if [ -n "$PUBLIC_IF" ]; then
  PUBLIC_IP=$(ip -4 -o addr show "$PUBLIC_IF" | awk '{print $4}' | cut -d/ -f1 | head -n 1)
fi

WG_IF="wg0"
WG_CIDR_RAW="${WG_CIDR:-${WG_SERVER_ADDRESS}}"
WG_CIDR=""
if [ -n "$WG_CIDR_RAW" ] && command -v python3 >/dev/null 2>&1; then
  WG_CIDR=$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network.with_prefixlen)' "$WG_CIDR_RAW" 2>/dev/null || true)
fi
if [ -z "$WG_CIDR" ]; then
  WG_CIDR="$WG_CIDR_RAW"
fi

# Whether to masquerade WG traffic into the private subnet is cloud-specific:
# Hetzner routes the WG subnet at the network layer (default false); OVH's
# OpenStack router does not know the WG subnet (default true).
WG_SNAT_ENABLED="${WG_SNAT_ENABLED:-$(provider_wg_snat_default)}"
WG_ALLOW_WAN="${WG_ALLOW_WAN:-false}"
# Return-path FORWARD rule: stateful (RELATED,ESTABLISHED) by default - safer.
# Set BASTION_STATELESS_RETURN_FORWARD=true to allow all private->WG traffic
# (previous OVH behavior; use if asymmetric flows are dropped).
BASTION_STATELESS_RETURN_FORWARD="${BASTION_STATELESS_RETURN_FORWARD:-false}"
# Targeted SNAT for Loki (:3100): auto = apply only when broad WG SNAT is off
# (matches previous per-cloud behavior: applied on Hetzner, redundant on OVH).
BASTION_TARGETED_LOKI_SNAT="${BASTION_TARGETED_LOKI_SNAT:-auto}"

if [ "$SKIP_FORWARDING" != "true" ]; then
  # Disable rp_filter on the private interface - required for asymmetric
  # routing (packets from egress arrive on the private NIC with dst in the WG
  # subnet, reverse path is wg0). Harmless where routing is symmetric.
  sysctl -w "net.ipv4.conf.${PRIVATE_IF}.rp_filter=0" >/dev/null 2>&1 || true
  sysctl -w "net.ipv4.conf.all.rp_filter=0" >/dev/null 2>&1 || true

  # The bastion hosts WG_CIDR locally. Remove routes left by older bootstrap
  # versions and make wg0 the only valid path before firewall rules are saved.
  if [ -n "${WG_CIDR:-}" ]; then
    while IFS= read -r _stale_wg_route; do
      [ -n "$_stale_wg_route" ] || continue
      _stale_wg_dev=$(printf '%s\n' "$_stale_wg_route" | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
      [ "$_stale_wg_dev" = "$WG_IF" ] && continue
      read -r -a _stale_wg_args <<< "$_stale_wg_route"
      if ! ip route del "${_stale_wg_args[@]}"; then
        echo "[bastion] unable to remove stale WG route: ${_stale_wg_route}" >&2
        beacon_status "failed" "Unable to repair WireGuard route" 0 || true
        exit 1
      fi
    done < <(ip -4 route show "$WG_CIDR" 2>/dev/null || true)

    if ! ip route replace "$WG_CIDR" dev "$WG_IF" scope link; then
      echo "[bastion] unable to route ${WG_CIDR} through ${WG_IF}" >&2
      beacon_status "failed" "Unable to configure WireGuard route" 0 || true
      exit 1
    fi

    _wg_probe_ip=$(echo "$WG_ADMIN_PEERS_JSON" | jq -r '[.[]?.ip // empty | select(length > 0)][0] // empty' | cut -d/ -f1)
    if [ -n "$_wg_probe_ip" ]; then
      _wg_selected_route=$(ip -4 route get "$_wg_probe_ip" 2>/dev/null || true)
      _wg_selected_dev=$(printf '%s\n' "$_wg_selected_route" | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
      if [ "$_wg_selected_dev" != "$WG_IF" ]; then
        echo "[bastion] invalid route for ${_wg_probe_ip}: ${_wg_selected_route:-not found}; expected dev ${WG_IF}" >&2
        beacon_status "failed" "WireGuard route validation failed" 0 || true
        exit 1
      fi
      echo "[bastion] WireGuard route verified: ${_wg_probe_ip} via ${WG_IF}"
    fi
  fi

  if [ "${WG_SNAT_ENABLED,,}" = "true" ]; then
    # SNAT WG clients to bastion private IP for private subnet access.
    iptables -t nat -C POSTROUTING -s "$WG_CIDR" -d "$PRIVATE_CIDR" -o "$PRIVATE_IF" -j MASQUERADE \
      || iptables -t nat -A POSTROUTING -s "$WG_CIDR" -d "$PRIVATE_CIDR" -o "$PRIVATE_IF" -j MASQUERADE
  fi

  iptables -C FORWARD -i "$WG_IF" -o "$PRIVATE_IF" -s "$WG_CIDR" -d "$PRIVATE_CIDR" -j ACCEPT \
    || iptables -A FORWARD -i "$WG_IF" -o "$PRIVATE_IF" -s "$WG_CIDR" -d "$PRIVATE_CIDR" -j ACCEPT
  if [ "${BASTION_STATELESS_RETURN_FORWARD,,}" = "true" ]; then
    # Allow all return traffic from private subnet to WG clients (stateless).
    iptables -C FORWARD -i "$PRIVATE_IF" -o "$WG_IF" -s "$PRIVATE_CIDR" -d "$WG_CIDR" -j ACCEPT \
      || iptables -A FORWARD -i "$PRIVATE_IF" -o "$WG_IF" -s "$PRIVATE_CIDR" -d "$WG_CIDR" -j ACCEPT
  else
    iptables -C FORWARD -i "$PRIVATE_IF" -o "$WG_IF" -s "$PRIVATE_CIDR" -d "$WG_CIDR" -m state --state RELATED,ESTABLISHED -j ACCEPT \
      || iptables -A FORWARD -i "$PRIVATE_IF" -o "$WG_IF" -s "$PRIVATE_CIDR" -d "$WG_CIDR" -m state --state RELATED,ESTABLISHED -j ACCEPT
  fi

  if [ -n "$PUBLIC_IF" ] && [ "${WG_ALLOW_WAN,,}" != "true" ]; then
    iptables -C FORWARD -i "$WG_IF" -o "$PUBLIC_IF" -j REJECT \
      || iptables -A FORWARD -i "$WG_IF" -o "$PUBLIC_IF" -j REJECT
  fi

  if [ -n "${WG_LISTEN_PORT:-}" ]; then
    if [ -n "$PUBLIC_IF" ]; then
      iptables -C INPUT -i "$PUBLIC_IF" -p udp --dport "$WG_LISTEN_PORT" -j ACCEPT 2>/dev/null \
        || iptables -I INPUT 1 -i "$PUBLIC_IF" -p udp --dport "$WG_LISTEN_PORT" -j ACCEPT
    else
      iptables -C INPUT -p udp --dport "$WG_LISTEN_PORT" -j ACCEPT 2>/dev/null \
        || iptables -I INPUT 1 -p udp --dport "$WG_LISTEN_PORT" -j ACCEPT
    fi
  fi

  # Targeted SNAT for Loki (port 3100) only.
  # Some private networks (Hetzner) reject packets whose source IP is not
  # within the private CIDR (e.g. WG client IPs). Rather than enabling broad
  # WG_SNAT_ENABLED (which masquerades ALL WG traffic), SNAT only the specific
  # port that Loki uses, limiting the security surface. Skipped when broad WG
  # SNAT is already enabled (would be redundant).
  _apply_loki_snat="false"
  case "${BASTION_TARGETED_LOKI_SNAT,,}" in
    true) _apply_loki_snat="true" ;;
    auto) [ "${WG_SNAT_ENABLED,,}" != "true" ] && _apply_loki_snat="true" ;;
  esac
  if [ "$_apply_loki_snat" = "true" ] && [ -n "${EGRESS_LOKI_URL:-}" ]; then
    _loki_host=$(python3 -c "from urllib.parse import urlparse; print(urlparse('${EGRESS_LOKI_URL}').hostname)" 2>/dev/null || true)
    if [ -n "$_loki_host" ]; then
      iptables -t nat -C POSTROUTING -s "$WG_CIDR" -d "$_loki_host" -p tcp --dport 3100 -o "$PRIVATE_IF" -j MASQUERADE 2>/dev/null \
        || iptables -t nat -A POSTROUTING -s "$WG_CIDR" -d "$_loki_host" -p tcp --dport 3100 -o "$PRIVATE_IF" -j MASQUERADE
      echo "[bastion] Loki SNAT rule applied: WG clients -> ${_loki_host}:3100 via ${PRIVATE_IF}"
    fi
  fi

  mkdir -p /etc/iptables
  iptables-save > /etc/iptables/rules.v4

  cat > /etc/systemd/system/infrazero-iptables.service <<'EOF'
[Unit]
Description=Restore iptables rules for Infrazero
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/iptables-restore /etc/iptables/rules.v4
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now infrazero-iptables.service
fi

# Persist private network CIDR for routing helpers
mkdir -p /etc/infrazero
cat > /etc/infrazero/network.env <<EOF
PRIVATE_CIDR=${PRIVATE_CIDR}
EOF
chmod 600 /etc/infrazero/network.env

# Policy routing: steer bastion outbound via egress while keeping WG on public
cat > /usr/local/sbin/infrazero-egress-routing.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# Cloud-agnostic: skip egress policy routing when the host does NOT have
# a separate egress server configured (single-NIC providers where the cloud
# router handles all outbound traffic). Providers opt out by omitting
# EGRESS_PRIVATE_IP from bastion.env.
EGRESS_IP=$(grep -oP "EGRESS_PRIVATE_IP=['\"]?\K[0-9.]+" /etc/infrazero/bastion.env 2>/dev/null || echo "")
if [ -z "$EGRESS_IP" ]; then
  # No egress configured - skip policy routing
  echo "[bastion-routing] no EGRESS_PRIVATE_IP configured; skipping egress policy routing"
  exit 0
fi

NETWORK_ENV="/etc/infrazero/network.env"
BASTION_ENV="/etc/infrazero/bastion.env"

if [ -f "$NETWORK_ENV" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$NETWORK_ENV"
  set +a
fi

if [ -f "$BASTION_ENV" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$BASTION_ENV"
  set +a
fi

if [ -z "${PRIVATE_CIDR:-}" ]; then
  echo "[bastion-routing] PRIVATE_CIDR missing; skipping policy routing" >&2
  exit 0
fi

public_if=""
for _pub_attempt in {1..30}; do
  public_if=$(ip -4 route show table main default 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
  if [ -n "$public_if" ]; then break; fi
  sleep 2
done

public_ip=""
if [ -n "$public_if" ]; then
  for _pub_ip_attempt in {1..30}; do
    public_ip=$(ip -4 -o addr show "$public_if" | awk '{print $4}' | cut -d/ -f1 | head -n 1)
    if [ -n "$public_ip" ]; then break; fi
    sleep 2
  done
fi

if [ -z "$public_if" ]; then
  echo "[bastion-routing] unable to determine public interface; skipping policy routing" >&2
  exit 0
fi

WG_CIDR_RAW="${WG_CIDR:-${WG_SERVER_ADDRESS:-}}"
WG_CIDR=""
if [ -n "$WG_CIDR_RAW" ] && command -v python3 >/dev/null 2>&1; then
  WG_CIDR=$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network.with_prefixlen)' "$WG_CIDR_RAW" 2>/dev/null || true)
fi
if [ -z "$WG_CIDR" ]; then
  WG_CIDR="$WG_CIDR_RAW"
fi

private_gw=""
# Prefer the kernel route (set by DHCP on OpenStack-like clouds), fall back to
# the first usable address of the CIDR.
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
  echo "[bastion-routing] unable to compute private gateway; skipping policy routing" >&2
  exit 0
fi

detect_private_if() {
  local ifname=""
  if command -v python3 >/dev/null 2>&1; then
    ifname=$(python3 - <<'PY'
import ipaddress
import os
import subprocess

cidr = os.environ.get("PRIVATE_CIDR", "")
public_if = os.environ.get("PUBLIC_IF", "")

def is_rfc1918(ip):
    addr = ipaddress.ip_address(ip)
    return addr.is_private

output = subprocess.check_output(["ip", "-4", "-o", "addr", "show"]).decode()
for line in output.splitlines():
    parts = line.split()
    if len(parts) < 4:
        continue
    ifname = parts[1]
    if ifname == "lo" or ifname == public_if or ifname.startswith(("wg", "docker", "br-", "veth")):
        continue
    addr = parts[3].split("/")[0]
    try:
        if cidr:
            net = ipaddress.ip_network(cidr, strict=False)
            if ipaddress.ip_address(addr) in net:
                print(ifname)
                raise SystemExit(0)
        if is_rfc1918(addr):
            print(ifname)
            raise SystemExit(0)
    except Exception:
        continue
raise SystemExit(1)
PY
    ) || true
  fi

  if [ -z "$ifname" ]; then
    ifname=$(ip -4 -o addr show | awk -v pub="$public_if" '$2 != pub && $2 != "lo" && $2 !~ /^wg/ && $2 !~ /^docker/ && $2 !~ /^br-/ && $2 !~ /^veth/ {print $2; exit}')
  fi
  echo "$ifname"
}

private_if=""
for _ in {1..30}; do
  PRIVATE_IF_CANDIDATE=$(PUBLIC_IF="$public_if" detect_private_if)
  if [ -n "$PRIVATE_IF_CANDIDATE" ]; then
    private_if="$PRIVATE_IF_CANDIDATE"
    break
  fi
  sleep 2
done

if [ -z "$private_if" ]; then
  echo "[bastion-routing] unable to determine private interface; skipping policy routing" >&2
  exit 0
fi

table_id=100
table_name="egress"
if ! grep -qE "^${table_id}[[:space:]]+${table_name}$" /etc/iproute2/rt_tables; then
  echo "${table_id} ${table_name}" >> /etc/iproute2/rt_tables
fi

ip link set dev "$private_if" up || true
sysctl -w "net.ipv4.conf.${private_if}.rp_filter=0" >/dev/null 2>&1 || true

ip route replace "$private_gw/32" dev "$private_if" scope link || true
prefix_len=$(ip -4 -o addr show "$private_if" | awk '{print $4}' | cut -d/ -f2 | head -n 1 || true)
if [ "$prefix_len" = "32" ]; then
  ip route del "$PRIVATE_CIDR" dev "$private_if" 2>/dev/null || true
  ip route replace "$PRIVATE_CIDR" via "$private_gw" dev "$private_if" onlink metric 50 || true
else
  ip route replace "$PRIVATE_CIDR" dev "$private_if" scope link || true
fi
ip route replace default via "$private_gw" dev "$private_if" onlink table "$table_name" || \
  echo "[bastion-routing] WARNING: could not set default route in egress table; ip rules will still be configured" >&2

ip rule del pref 100 || true
if [ -n "$WG_CIDR" ]; then
  ip rule add pref 100 from "$WG_CIDR" lookup main
  ip rule del pref 110 || true
  ip rule add pref 110 to "$WG_CIDR" lookup main
fi

ip rule del pref 120 || true
if [ -n "$public_ip" ]; then
  ip rule add pref 120 from "$public_ip/32" lookup main
fi

# Bastion's own private IP traffic must also use main table (-> public IF)
# so that bastion's services (apt, curl, monitoring) always go via bastion's
# own public interface, NOT via the private gateway.
private_ip_local=$(ip -4 -o addr show "$private_if" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n 1 || true)
ip rule del pref 130 2>/dev/null || true
if [ -n "$private_ip_local" ]; then
  ip rule add pref 130 from "$private_ip_local/32" lookup main
fi

# REMOVED: pref 200 catch-all lookup egress
# Bastion has its own public IP - it must NOT route its outbound traffic via
# the private gateway. That catch-all caused all unbound-socket traffic (apt,
# curl, bootstrap downloads) to go through the private gateway -> egress
# MASQUERADE, which is not ready during bastion's own bootstrap.
# Without pref 200, unmatched traffic falls to the kernel default (pref 32766
# = main table -> public IF). That is the correct behaviour.
ip rule del pref 200 2>/dev/null || true
EOF

chmod +x /usr/local/sbin/infrazero-egress-routing.sh
/usr/local/sbin/infrazero-egress-routing.sh || true

cat > /etc/systemd/system/infrazero-egress-routing.service <<'EOF'
[Unit]
Description=Infrazero bastion egress policy routing
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/infrazero-egress-routing.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now infrazero-egress-routing.service

# Bind SSH to WireGuard address only (unless debug root password is set)
mkdir -p /etc/ssh/sshd_config.d

LISTEN_ADDRESSES=()

if [ -n "$DEBUG_ROOT_PASSWORD" ]; then
  LISTEN_ADDRESSES=("0.0.0.0")
else
  LISTEN_ADDRESSES=("${WG_SERVER_IP}")
  if [ -n "$PRIVATE_IP" ]; then
    LISTEN_ADDRESSES+=("${PRIVATE_IP}")
  fi
  # Allow SSH from GitHub Actions runner via public IP for bootstrap monitoring
  if [ -n "$PUBLIC_IP" ]; then
    LISTEN_ADDRESSES+=("${PUBLIC_IP}")
  fi
fi

rm -f /etc/ssh/sshd_config.d/infrazero.conf
{
  for addr in "${LISTEN_ADDRESSES[@]}"; do
    echo "ListenAddress ${addr}"
  done
} > /etc/ssh/sshd_config.d/91-infrazero-bastion.conf

systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true

beacon_status "installing_promtail" "Installing Promtail" 85

if declare -F infrazero_install_journald_promtail >/dev/null 2>&1; then
  infrazero_install_journald_promtail "bastion" "bastion" "$EGRESS_LOKI_URL"
else
  echo "[bastion] common-base.sh missing infrazero_install_journald_promtail; skipping promtail setup" >&2
fi

beacon_status "complete" "Bootstrap complete" 100

echo "[bastion] $(date -Is) complete"
