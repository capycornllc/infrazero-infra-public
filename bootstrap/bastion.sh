#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/infrazero-bootstrap.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[bastion] $(date -Is) start"

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

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y wireguard wireguard-tools unzip
fi

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

# Enable routing between WireGuard and private subnet
cat > /etc/sysctl.d/99-infrazero-forward.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
sysctl --system

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
      private_if=$(ip -4 -o addr show | awk -v pub="$public_if" '$2 != pub && $2 != "lo" {print $2; exit}')
    fi
  fi
  echo "$private_if"
}

PRIVATE_IF=""
for i in {1..30}; do
  PRIVATE_IF=$(detect_private_if)
  if [ -n "$PRIVATE_IF" ]; then
    break
  fi
  sleep 2
done

SKIP_FORWARDING="false"
if [ -z "$PRIVATE_IF" ]; then
  echo "[bastion] unable to determine private interface for $PRIVATE_CIDR after retries; skipping WG forwarding" >&2
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

WG_SNAT_ENABLED="${WG_SNAT_ENABLED:-true}"
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

private_if=""
if command -v python3 >/dev/null 2>&1; then
  private_if=$(python3 - <<'PY'
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

if [ -z "$private_if" ]; then
  echo "[bastion-routing] unable to determine private interface; skipping policy routing" >&2
  exit 0
fi

public_if=$(ip -4 route show table main default 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
public_ip=""
if [ -n "$public_if" ]; then
  public_ip=$(ip -4 -o addr show "$public_if" | awk '{print $4}' | cut -d/ -f1 | head -n 1)
fi

if [ -z "$public_if" ]; then
  echo "[bastion-routing] unable to determine public interface; skipping policy routing" >&2
  exit 0
fi

table_id=100
table_name="egress"
if ! grep -qE "^${table_id}[[:space:]]+${table_name}$" /etc/iproute2/rt_tables; then
  echo "${table_id} ${table_name}" >> /etc/iproute2/rt_tables
fi

ip route replace "$private_gw/32" dev "$private_if" scope link || true
ip route replace "$PRIVATE_CIDR" dev "$private_if" scope link || true
ip route replace default via "$private_gw" dev "$private_if" onlink table "$table_name"

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

ip rule del pref 200 || true
ip rule add pref 200 lookup "$table_name"
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

SSH_PASSWORD_AUTH="no"
SSH_KBD_INTERACTIVE="no"
SSH_CHALLENGE="no"
SSH_PERMIT_ROOT="no"
SSH_ALLOW_GROUPS="infrazero-admins"
LISTEN_ADDRESSES=()

if [ -n "$DEBUG_ROOT_PASSWORD" ]; then
  SSH_PASSWORD_AUTH="yes"
  SSH_KBD_INTERACTIVE="yes"
  SSH_CHALLENGE="yes"
  SSH_PERMIT_ROOT="yes"
  SSH_ALLOW_GROUPS="infrazero-admins root"
  LISTEN_ADDRESSES=("0.0.0.0")
else
  LISTEN_ADDRESSES=("${WG_SERVER_IP}")
  if [ -n "$PRIVATE_IP" ]; then
    LISTEN_ADDRESSES+=("${PRIVATE_IP}")
  fi
fi

{
  for addr in "${LISTEN_ADDRESSES[@]}"; do
    echo "ListenAddress ${addr}"
  done
  echo "AllowGroups ${SSH_ALLOW_GROUPS}"
  echo "PasswordAuthentication ${SSH_PASSWORD_AUTH}"
  echo "KbdInteractiveAuthentication ${SSH_KBD_INTERACTIVE}"
  echo "ChallengeResponseAuthentication ${SSH_CHALLENGE}"
  echo "PermitRootLogin ${SSH_PERMIT_ROOT}"
} > /etc/ssh/sshd_config.d/infrazero.conf

systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true

# Promtail for journald to Loki
if [ ! -f /usr/local/bin/promtail ]; then
  curl -fsSL -o /tmp/promtail.zip "https://github.com/grafana/loki/releases/download/v2.9.3/promtail-linux-amd64.zip"
  unzip -o /tmp/promtail.zip -d /usr/local/bin
  mv /usr/local/bin/promtail-linux-amd64 /usr/local/bin/promtail
  chmod +x /usr/local/bin/promtail
fi

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
systemctl enable --now promtail

echo "[bastion] $(date -Is) complete"
