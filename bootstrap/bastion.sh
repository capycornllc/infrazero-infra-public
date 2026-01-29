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

# Bind SSH to WireGuard address only
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/infrazero.conf <<EOF
ListenAddress ${WG_SERVER_IP}
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
