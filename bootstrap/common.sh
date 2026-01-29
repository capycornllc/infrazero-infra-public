#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/infrazero-bootstrap.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[common] $(date -Is) start"

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y curl ca-certificates zstd jq e2fsprogs auditd
fi

# Create admin users from OPS_SSH_KEYS_JSON (base64) if provided
if [ -n "${ADMIN_USERS_JSON_B64:-}" ]; then
  mkdir -p /etc/infrazero
  echo "$ADMIN_USERS_JSON_B64" | base64 -d > /etc/infrazero/admins.json
  chmod 600 /etc/infrazero/admins.json

  if ! getent group infrazero-admins >/dev/null 2>&1; then
    groupadd infrazero-admins
  fi
  echo "%infrazero-admins ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/90-infrazero-admins
  chmod 440 /etc/sudoers.d/90-infrazero-admins

  jq -c 'to_entries[]' /etc/infrazero/admins.json | while read -r entry; do
    username=$(echo "$entry" | jq -r '.key')
    if [ -z "$username" ] || [ "$username" = "null" ]; then
      continue
    fi

    if ! id -u "$username" >/dev/null 2>&1; then
      useradd -m -s /bin/bash -G infrazero-admins "$username"
    else
      usermod -aG infrazero-admins "$username" || true
    fi

    install -d -m 0700 "/home/$username/.ssh"
    : > "/home/$username/.ssh/authorized_keys"

    echo "$entry" | jq -r '.value[]' | while IFS= read -r key; do
      if [ -n "$key" ] && [ "$key" != "null" ]; then
        echo "$key" >> "/home/$username/.ssh/authorized_keys"
      fi
    done

    chmod 0600 "/home/$username/.ssh/authorized_keys"
    chown -R "$username:$username" "/home/$username/.ssh"
  done
fi

# SSH hardening
SSHD_CONFIG="/etc/ssh/sshd_config"
set_sshd_config() {
  local key="$1"
  local value="$2"
  if grep -q "^${key} " "$SSHD_CONFIG"; then
    sed -i "s/^${key}.*/${key} ${value}/" "$SSHD_CONFIG"
  else
    echo "${key} ${value}" >> "$SSHD_CONFIG"
  fi
}

set_sshd_config "PasswordAuthentication" "no"
set_sshd_config "ChallengeResponseAuthentication" "no"
set_sshd_config "PermitRootLogin" "no"

systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true

# Route WG subnet via bastion for all non-bastion hosts
if [ "${BOOTSTRAP_ROLE:-}" != "bastion" ] && [ -n "${WG_SERVER_ADDRESS:-}" ] && [ -n "${BASTION_PRIVATE_IP:-}" ]; then
  ip route replace "$WG_SERVER_ADDRESS" via "$BASTION_PRIVATE_IP" || true

  cat > /etc/systemd/system/infrazero-wg-route.service <<EOF
[Unit]
Description=Route WireGuard subnet via bastion
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ip route replace ${WG_SERVER_ADDRESS} via ${BASTION_PRIVATE_IP}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now infrazero-wg-route.service
fi

# Enable auditd
systemctl enable --now auditd || true

# Journald persistence
mkdir -p /var/log/journal
sed -i 's/^#\?Storage=.*/Storage=persistent/' /etc/systemd/journald.conf
systemctl restart systemd-journald || true

# DNS fallback
sed -i 's/^#\?FallbackDNS=.*/FallbackDNS=1.1.1.1 1.0.0.1 8.8.8.8/' /etc/systemd/resolved.conf
systemctl restart systemd-resolved || true

echo "[common] $(date -Is) done"
