#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/infrazero-bootstrap.log"
if [ -z "${_INFRAZERO_LOG_REDIRECTED:-}" ]; then
  exec > >(tee -a "$LOG_FILE") 2>&1
  export _INFRAZERO_LOG_REDIRECTED=1
fi

echo "[bastion] $(date -Is) start"

BOOTSTRAP_ROLE="bastion"

ENV_FILE="/etc/infrazero/bastion.env"
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[bastion] missing required env: $name" >&2
    exit 1
  fi
}

require_env "WG_SERVER_PRIVATE_KEY"
require_env "WG_SERVER_ADDRESS"
require_env "WG_LISTEN_PORT"
require_env "WG_ADMIN_PEERS_JSON"
require_env "WG_PRESHARED_KEYS_JSON"
require_env "EGRESS_LOKI_URL"

DEBUG_ROOT_PASSWORD="${DEBUG_ROOT_PASSWORD:-}"

beacon_status "installing_wireguard" "Installing WireGuard" 10

install_wireguard_packages() {
  if ! command -v apt-get >/dev/null 2>&1; then
    return 0
  fi

  export DEBIAN_FRONTEND=noninteractive
  for attempt in {1..20}; do
    if timeout 300 apt-get update -y && timeout 600 apt-get install -y wireguard wireguard-tools unzip; then
      return 0
    fi
    echo "[bastion] apt-get install wireguard failed (attempt ${attempt}/20); retrying in 10s" >&2
    sleep 10
  done

  echo "[bastion] unable to install WireGuard packages" >&2
  return 1
}

install_wireguard_packages

mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

WG_SERVER_IP="${WG_SERVER_ADDRESS%%/*}"

cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = ${WG_SERVER_ADDRESS}
ListenPort = ${WG_LISTEN_PORT}
PrivateKey = ${WG_SERVER_PRIVATE_KEY}
SaveConfig = false

EOF

# Validate WG peers JSON before parsing
if ! echo "$WG_ADMIN_PEERS_JSON" | jq empty 2>/dev/null; then
  echo "[bastion] FATAL: WG_ADMIN_PEERS_JSON is not valid JSON" >&2
  beacon_status "failed" "Invalid WireGuard peers config" 0
  return 1 2>/dev/null || exit 1
fi

peers=$(echo "$WG_ADMIN_PEERS_JSON" | jq -r 'to_entries[] | "\(.key)|\(.value.publicKey)|\(.value.ip)"')

while IFS='|' read -r name pubkey ip; do
  if [ -z "$pubkey" ] || [ -z "$ip" ] || [ "$pubkey" = "null" ] || [ "$ip" = "null" ]; then
    echo "[bastion] skipping peer $name with missing fields"
    continue
  fi
  psk=$(echo "$WG_PRESHARED_KEYS_JSON" | jq -r --arg name "$name" '.[$name] // empty')

  {
    echo "[Peer]"
    echo "PublicKey = $pubkey"
    if [ -n "$psk" ] && [ "$psk" != "null" ]; then
      echo "PresharedKey = $psk"
    fi
    echo "AllowedIPs = $ip"
    echo
  } >> /etc/wireguard/wg0.conf

done <<< "$peers"

systemctl enable --now wg-quick@wg0

beacon_status "configuring_firewall" "Configuring firewall and routing" 40

# Enable routing between WireGuard and private subnet
cat > /etc/sysctl.d/99-infrazero-forward.conf <<'EOF'
net.ipv4.ip_forward=1
EOF

sysctl --system

configure_bastion_private_if() {
  if [ -z "${BASTION_PRIVATE_IP:-}" ] || [ -z "${PRIVATE_CIDR:-}" ]; then
    return 0
  fi
  if ip -4 -o addr show | awk -v ip="$BASTION_PRIVATE_IP" '{split($4, parts, "/"); if (parts[1]==ip) found=1} END {exit found ? 0 : 1}'; then
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
    echo "[bastion] unable to find unconfigured private interface for ${BASTION_PRIVATE_IP}" >&2
    return 0
  fi

  private_gw=$(python3 - <<'PY'
import ipaddress
import os
cidr = os.environ.get("PRIVATE_CIDR", "")
try:
    net = ipaddress.ip_network(cidr, strict=False)
except Exception:
    raise SystemExit(1)
print(str(net.network_address + 1 if net.num_addresses > 1 else net.network_address))
PY
  ) || return 0

  ip link set dev "$private_if" up || true
  sysctl -w "net.ipv4.conf.${private_if}.rp_filter=0" >/dev/null 2>&1 || true
  ip addr replace "${BASTION_PRIVATE_IP}/32" dev "$private_if" || true
  ip route replace "${private_gw}/32" dev "$private_if" scope link || true
  ip route del "${private_gw}/32" dev wg0 2>/dev/null || true
  ip route del "$PRIVATE_CIDR" dev wg0 2>/dev/null || true
  ip route del "$PRIVATE_CIDR" dev "$public_if" 2>/dev/null || true
  if [ -n "${WG_CIDR:-}" ] && [ -n "$public_if" ]; then
    ip route del "$WG_CIDR" via "$private_gw" dev "$public_if" 2>/dev/null || true
  fi
  ip route replace "$PRIVATE_CIDR" via "$private_gw" dev "$private_if" onlink metric 50 || true
  echo "[bastion] configured private interface ${private_if} with ${BASTION_PRIVATE_IP}/32"
}

configure_bastion_private_if

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
# 90 attempts × 5 s = 7.5 min — covers slow Hetzner private NIC IP assignment races.
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

WG_SNAT_ENABLED="${WG_SNAT_ENABLED:-false}"
WG_ALLOW_WAN="${WG_ALLOW_WAN:-false}"

if [ "$SKIP_FORWARDING" != "true" ]; then
  if [ "${WG_SNAT_ENABLED,,}" = "true" ]; then
    # SNAT WG clients to bastion private IP for private subnet access.
    iptables -t nat -C POSTROUTING -s "$WG_CIDR" -d "$PRIVATE_CIDR" -o "$PRIVATE_IF" -j MASQUERADE \
      || iptables -t nat -A POSTROUTING -s "$WG_CIDR" -d "$PRIVATE_CIDR" -o "$PRIVATE_IF" -j MASQUERADE
  fi

  iptables -C FORWARD -i "$WG_IF" -o "$PRIVATE_IF" -s "$WG_CIDR" -d "$PRIVATE_CIDR" -j ACCEPT \
    || iptables -A FORWARD -i "$WG_IF" -o "$PRIVATE_IF" -s "$WG_CIDR" -d "$PRIVATE_CIDR" -j ACCEPT
  iptables -C FORWARD -i "$PRIVATE_IF" -o "$WG_IF" -s "$PRIVATE_CIDR" -d "$WG_CIDR" -m state --state RELATED,ESTABLISHED -j ACCEPT \
    || iptables -A FORWARD -i "$PRIVATE_IF" -o "$WG_IF" -s "$PRIVATE_CIDR" -d "$WG_CIDR" -m state --state RELATED,ESTABLISHED -j ACCEPT

  if [ -n "$PUBLIC_IF" ] && [ "${WG_ALLOW_WAN,,}" != "true" ]; then
    iptables -C FORWARD -i "$WG_IF" -o "$PUBLIC_IF" -j REJECT \
      || iptables -A FORWARD -i "$WG_IF" -o "$PUBLIC_IF" -j REJECT
  fi

  # Targeted SNAT for Loki (port 3100) only.
  # Hetzner private network rejects packets whose source IP is not within the
  # private CIDR (e.g. WG client IPs in WG_CIDR). Rather than enabling broad
  # WG_SNAT_ENABLED (which masquerades ALL WG traffic), we SNAT only the
  # specific port that Loki uses, limiting the security surface.
  # OLD broad approach (kept for reference):
  #   iptables -t nat -A POSTROUTING -s "$WG_CIDR" -d "$PRIVATE_CIDR" -o "$PRIVATE_IF" -j MASQUERADE
  if [ -n "${EGRESS_LOKI_URL:-}" ]; then
    _loki_host=$(python3 -c "from urllib.parse import urlparse; print(urlparse('${EGRESS_LOKI_URL}').hostname)" 2>/dev/null || true)
    if [ -n "$_loki_host" ]; then
      iptables -t nat -C POSTROUTING -s "$WG_CIDR" -d "$_loki_host" -p tcp --dport 3100 -o "$PRIVATE_IF" -j MASQUERADE 2>/dev/null \
        || iptables -t nat -A POSTROUTING -s "$WG_CIDR" -d "$_loki_host" -p tcp --dport 3100 -o "$PRIVATE_IF" -j MASQUERADE
      echo "[bastion] Loki SNAT rule applied: WG clients → ${_loki_host}:3100 via ${PRIVATE_IF}"
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
if command -v python3 >/dev/null 2>&1; then
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

# Bastion's own private IP traffic must also use main table (eth0 → public)
# so that bastion's services (apt, curl, monitoring) always go via bastion's
# own public interface, NOT via the private gateway.
private_ip_local=$(ip -4 -o addr show "$private_if" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n 1 || true)
ip rule del pref 130 2>/dev/null || true
if [ -n "$private_ip_local" ]; then
  ip rule add pref 130 from "$private_ip_local/32" lookup main
fi

# REMOVED: pref 200 catch-all lookup egress
# Bastion has its own public IP — it must NOT route its outbound traffic via
# the private gateway. That catch-all caused all unbound-socket traffic (apt,
# curl, bootstrap downloads) to go through 10.10.0.1 → egress MASQUERADE,
# which is not ready during bastion's own bootstrap, breaking everything.
# Without pref 200, unmatched traffic falls to the kernel default (pref 32766
# = main table → eth0 → public IP). That is the correct behaviour.
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

# Promtail for journald to Loki (optional)
if [ ! -x /usr/local/bin/promtail ]; then
  promtail_downloaded=false
  for _pt_attempt in {1..5}; do
    if curl -fsSL --connect-timeout 10 --max-time 120 -o /tmp/promtail.zip "https://github.com/grafana/loki/releases/download/v2.9.3/promtail-linux-amd64.zip"; then
      promtail_downloaded=true
      break
    fi
    echo "[bastion] promtail download attempt ${_pt_attempt}/5 failed; retrying in 15s"
    sleep 15
  done
  if [ "$promtail_downloaded" = "true" ]; then
    unzip -o /tmp/promtail.zip -d /usr/local/bin
    mv /usr/local/bin/promtail-linux-amd64 /usr/local/bin/promtail
    chmod +x /usr/local/bin/promtail
  else
    echo "[bastion] promtail download failed after 5 attempts; skipping"
  fi
fi

if [ -x /usr/local/bin/promtail ]; then
mkdir -p /etc/promtail /var/lib/promtail
cat > /etc/promtail/promtail.yml <<EOF
server:
  http_listen_port: 9080
  grpc_listen_port: 0
positions:
  filename: /var/lib/promtail/positions.yaml
clients:
  - url: ${EGRESS_LOKI_URL}
    external_labels:
      host: ${HOSTNAME}
      role: bastion
scrape_configs:
  - job_name: systemd-journal
    journal:
      max_age: 12h
      labels:
        job: systemd-journal
    relabel_configs:
      - source_labels: ["__journal__systemd_unit"]
        target_label: unit
EOF

cat > /etc/systemd/system/promtail.service <<'EOF'
[Unit]
Description=Promtail log shipper
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/promtail -config.file=/etc/promtail/promtail.yml
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now promtail || echo "[bastion] failed to start promtail; continuing"
else
  echo "[bastion] promtail binary unavailable; skipping service setup"
fi

beacon_status "complete" "Bootstrap complete" 100

echo "[bastion] $(date -Is) complete"
