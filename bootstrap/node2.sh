#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/infrazero-bootstrap.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[node2] $(date -Is) start"

ENV_FILE="/etc/infrazero/node2.env"
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[node2] missing required env: $name" >&2
    exit 1
  fi
}

require_env "EGRESS_LOKI_URL"
require_env "S3_ACCESS_KEY_ID"
require_env "S3_SECRET_ACCESS_KEY"
require_env "S3_ENDPOINT"
require_env "S3_REGION"
require_env "INFRA_STATE_BUCKET"
require_env "K3S_TOKEN_NAME"
require_env "K3S_SERVER_IP"

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y curl jq unzip
fi

if ! command -v aws >/dev/null 2>&1; then
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
  unzip -q /tmp/awscliv2.zip -d /tmp
  /tmp/aws/install --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli --update
fi

export AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$S3_SECRET_ACCESS_KEY"
export AWS_DEFAULT_REGION="$S3_REGION"

token_key() {
  local prefix="${STATE_PREFIX:-}"
  local name="$K3S_TOKEN_NAME"
  prefix="${prefix#/}"
  prefix="${prefix%/}"
  if [ -n "$prefix" ]; then
    echo "k3s/${prefix}/${name}"
  else
    echo "k3s/${name}"
  fi
}

fetch_k3s_token() {
  local key
  key=$(token_key)
  local dest="/run/k3s-token"
  for i in {1..60}; do
    if aws --endpoint-url "$S3_ENDPOINT" s3 cp "s3://${INFRA_STATE_BUCKET}/${key}" "$dest" >/dev/null 2>&1; then
      if [ -s "$dest" ]; then
        echo "$dest"
        return 0
      fi
    fi
    sleep 5
  done
  return 1
}

install_k3s_agent() {
  if systemctl is-active --quiet k3s-agent; then
    echo "[node2] k3s-agent already running"
    return 0
  fi

  local token_file
  token_file=$(fetch_k3s_token)
  if [ -z "$token_file" ] || [ ! -s "$token_file" ]; then
    echo "[node2] failed to fetch k3s token from S3" >&2
    return 1
  fi

  local token
  token=$(tr -d '\n' < "$token_file")
  if [ -z "$token" ]; then
    echo "[node2] k3s token is empty" >&2
    return 1
  fi

  local server_url="https://${K3S_SERVER_IP}:6443"
  echo "[node2] joining k3s server at ${server_url}"
  curl -sfL https://get.k3s.io | K3S_URL="$server_url" K3S_TOKEN="$token" sh -
}

install_k3s_agent

setup_promtail() {
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
      role: node2
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
}

setup_promtail

echo "[node2] $(date -Is) complete"
