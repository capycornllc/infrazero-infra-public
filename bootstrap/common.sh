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

# Relax rp_filter for asymmetric routing (WG via bastion)
cat > /etc/sysctl.d/99-infrazero-rpfilter.conf <<'EOF'
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF
sysctl --system || true

# Route WG subnet via bastion for all non-bastion hosts (netplan)
WG_ROUTE_CIDR_RAW="${WG_CIDR:-${WG_SERVER_ADDRESS:-}}"
WG_ROUTE_CIDR=""
if [ -n "$WG_ROUTE_CIDR_RAW" ] && command -v python3 >/dev/null 2>&1; then
  WG_ROUTE_CIDR=$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network.with_prefixlen)' "$WG_ROUTE_CIDR_RAW" 2>/dev/null || true)
fi
if [ -z "$WG_ROUTE_CIDR" ]; then
  WG_ROUTE_CIDR="$WG_ROUTE_CIDR_RAW"
fi

if [ "${BOOTSTRAP_ROLE:-}" != "bastion" ] && [ -n "$WG_ROUTE_CIDR" ] && [ -n "${BASTION_PRIVATE_IP:-}" ]; then
  if systemctl list-unit-files 2>/dev/null | grep -q "^infrazero-wg-route.service"; then
    systemctl disable --now infrazero-wg-route.service || true
    rm -f /etc/systemd/system/infrazero-wg-route.service
    systemctl daemon-reload || true
  fi

  PRIVATE_IF=""
  if [ -n "${PRIVATE_CIDR:-}" ]; then
    for _ in $(seq 1 30); do
      PRIVATE_IF=$(ip -4 route show "$PRIVATE_CIDR" 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
      if [ -n "$PRIVATE_IF" ]; then
        break
      fi
      sleep 2
    done
  fi

  if [ -z "$PRIVATE_IF" ]; then
    echo "[common] unable to determine private interface for $PRIVATE_CIDR; skipping WG route" >&2
  elif command -v netplan >/dev/null 2>&1; then
    echo "net.ipv4.conf.${PRIVATE_IF}.rp_filter=0" >> /etc/sysctl.d/99-infrazero-rpfilter.conf
    sysctl --system || true

    cat > /etc/netplan/60-infrazero-wg-route.yaml <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${PRIVATE_IF}:
      routes:
        - to: ${WG_ROUTE_CIDR}
          via: ${BASTION_PRIVATE_IP}
EOF

    netplan apply || true
  else
    echo "[common] netplan not available; skipping WG route" >&2
  fi
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
