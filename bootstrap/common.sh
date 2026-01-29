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

# Create ops user and copy root authorized_keys if present
if ! id -u ops >/dev/null 2>&1; then
  useradd -m -s /bin/bash ops
  usermod -aG sudo ops
fi

if [ -f /root/.ssh/authorized_keys ]; then
  install -d -m 0700 /home/ops/.ssh
  install -m 0600 /root/.ssh/authorized_keys /home/ops/.ssh/authorized_keys
  chown -R ops:ops /home/ops/.ssh
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
