#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/infrazero-bootstrap.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[common] $(date -Is) start"

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

  tmp_keys="/tmp/infrazero-admin-keys"
  : > "$tmp_keys"
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY' > "$tmp_keys" || true
import json
from pathlib import Path

data = json.loads(Path("/etc/infrazero/admins.json").read_text())
def emit(user, key):
    if not user or not key:
        return
    print(f"{user}|{key}")

if isinstance(data, dict):
    for user, keys in data.items():
        if isinstance(keys, str):
            keys = [keys]
        if not isinstance(keys, list):
            continue
        for key in keys:
            if isinstance(key, str):
                key = key.strip()
                if key:
                    emit(str(user).strip(), key)
PY
  elif command -v jq >/dev/null 2>&1; then
    jq -r 'to_entries[] | .key as $u | .value[] | select(. != null and . != "") | "\($u)|\(.)"' \
      /etc/infrazero/admins.json > "$tmp_keys" || true
  else
    echo "[common] python3/jq not available; skipping admin user creation" >&2
  fi

  if [ -s "$tmp_keys" ]; then
    declare -A seen_users
    while IFS='|' read -r username key; do
      if [ -z "$username" ] || [ -z "$key" ]; then
        continue
      fi

      if ! id -u "$username" >/dev/null 2>&1; then
        useradd -m -s /bin/bash -G infrazero-admins "$username"
      else
        usermod -aG infrazero-admins "$username" || true
      fi

      install -d -m 0700 "/home/$username/.ssh"
      if [ -z "${seen_users[$username]+x}" ]; then
        : > "/home/$username/.ssh/authorized_keys"
        seen_users["$username"]=1
      fi
      echo "$key" >> "/home/$username/.ssh/authorized_keys"
      chmod 0600 "/home/$username/.ssh/authorized_keys"
      chown -R "$username:$username" "/home/$username/.ssh"
    done < "$tmp_keys"
  fi
  rm -f "$tmp_keys"
fi

install_packages() {
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    for _ in {1..5}; do
      if apt-get update -y && apt-get install -y curl ca-certificates zstd jq e2fsprogs auditd; then
        return 0
      fi
      sleep 5
    done
    echo "[common] apt-get failed after retries; continuing without packages" >&2
  fi
}

install_packages

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

DEBUG_ROOT_PASSWORD="${DEBUG_ROOT_PASSWORD:-}"
SSH_PASSWORD_AUTH="no"
SSH_KBD_INTERACTIVE="no"
SSH_CHALLENGE="no"
SSH_PERMIT_ROOT="no"
SSH_ALLOW_GROUPS="infrazero-admins"

if [ -n "$DEBUG_ROOT_PASSWORD" ]; then
  echo "[common] DEBUG_ROOT_PASSWORD set; enabling root password auth"
  echo "root:${DEBUG_ROOT_PASSWORD}" | chpasswd || echo "[common] unable to set root password" >&2
  passwd -u root >/dev/null 2>&1 || usermod -U root >/dev/null 2>&1 || true
  SSH_PASSWORD_AUTH="yes"
  SSH_KBD_INTERACTIVE="yes"
  SSH_CHALLENGE="yes"
  SSH_PERMIT_ROOT="yes"
  SSH_ALLOW_GROUPS="infrazero-admins root"
fi

set_sshd_config "PasswordAuthentication" "$SSH_PASSWORD_AUTH"
set_sshd_config "KbdInteractiveAuthentication" "$SSH_KBD_INTERACTIVE"
set_sshd_config "ChallengeResponseAuthentication" "$SSH_CHALLENGE"
set_sshd_config "PermitRootLogin" "$SSH_PERMIT_ROOT"

DEBUG_SSH_BEGIN="# BEGIN INFRAZERO DEBUG SSH"
DEBUG_SSH_END="# END INFRAZERO DEBUG SSH"

strip_debug_block() {
  if [ -f "$SSHD_CONFIG" ]; then
    awk -v begin="$DEBUG_SSH_BEGIN" -v end="$DEBUG_SSH_END" '
      $0==begin {skip=1; next}
      $0==end {skip=0; next}
      skip==1 {next}
      {print}
    ' "$SSHD_CONFIG" > "${SSHD_CONFIG}.tmp" && mv "${SSHD_CONFIG}.tmp" "$SSHD_CONFIG"
  fi
}

strip_debug_block
if [ -n "$DEBUG_ROOT_PASSWORD" ]; then
  cat >> "$SSHD_CONFIG" <<EOF
${DEBUG_SSH_BEGIN}
Match all
  PermitRootLogin yes
  PasswordAuthentication yes
  KbdInteractiveAuthentication yes
  ChallengeResponseAuthentication yes
  AllowGroups infrazero-admins root
${DEBUG_SSH_END}
EOF
fi

mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/infrazero.conf <<EOF
PasswordAuthentication ${SSH_PASSWORD_AUTH}
KbdInteractiveAuthentication ${SSH_KBD_INTERACTIVE}
ChallengeResponseAuthentication ${SSH_CHALLENGE}
PermitRootLogin ${SSH_PERMIT_ROOT}
AllowGroups ${SSH_ALLOW_GROUPS}
EOF

systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true

# Relax rp_filter for asymmetric routing (WG via bastion)
cat > /etc/sysctl.d/99-infrazero-rpfilter.conf <<'EOF'
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF
sysctl --system || true

# WG routing handled via network route (preferred) or SNAT on bastion; see bastion bootstrap.

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
