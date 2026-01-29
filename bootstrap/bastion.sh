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

PRIVATE_IF=$(ip route show "$PRIVATE_CIDR" 2>/dev/null | awk '{print $3; exit}')
if [ -z "$PRIVATE_IF" ]; then
  echo "[bastion] unable to determine private interface for $PRIVATE_CIDR" >&2
  exit 1
fi

PRIVATE_IP=$(ip -4 -o addr show "$PRIVATE_IF" | awk '{print $4}' | cut -d/ -f1 | head -n 1)
if [ -z "$PRIVATE_IP" ]; then
  echo "[bastion] unable to determine private IP for $PRIVATE_IF" >&2
  exit 1
fi

WG_IF="wg0"
WG_CIDR="${WG_SERVER_ADDRESS}"

iptables -t nat -A POSTROUTING -s "$WG_CIDR" -d "$PRIVATE_CIDR" -o "$PRIVATE_IF" -j MASQUERADE
iptables -A FORWARD -i "$WG_IF" -o "$PRIVATE_IF" -s "$WG_CIDR" -d "$PRIVATE_CIDR" -j ACCEPT
iptables -A FORWARD -i "$PRIVATE_IF" -o "$WG_IF" -s "$PRIVATE_CIDR" -d "$WG_CIDR" -m state --state RELATED,ESTABLISHED -j ACCEPT

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

# Bind SSH to WireGuard address only
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/infrazero.conf <<EOF
ListenAddress ${WG_SERVER_IP}
ListenAddress ${PRIVATE_IP}
AllowUsers ops
PasswordAuthentication no
PermitRootLogin no
EOF

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
