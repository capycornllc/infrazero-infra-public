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
      if apt-get update -y && apt-get install -y curl ca-certificates zstd jq e2fsprogs auditd unattended-upgrades; then
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

ensure_sshd_include() {
  if ! grep -Eq '^[#[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/\*.conf' "$SSHD_CONFIG"; then
    echo "Include /etc/ssh/sshd_config.d/*.conf" >> "$SSHD_CONFIG"
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

ensure_sshd_include
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

mkdir -p /etc/ssh/sshd_config.d
rm -f /etc/ssh/sshd_config.d/infrazero.conf
cat > /etc/ssh/sshd_config.d/90-infrazero.conf <<EOF
PasswordAuthentication ${SSH_PASSWORD_AUTH}
KbdInteractiveAuthentication ${SSH_KBD_INTERACTIVE}
ChallengeResponseAuthentication ${SSH_CHALLENGE}
PermitRootLogin ${SSH_PERMIT_ROOT}
AllowGroups ${SSH_ALLOW_GROUPS}
EOF

if [ -n "$DEBUG_ROOT_PASSWORD" ]; then
  cat > /etc/ssh/sshd_config.d/99-infrazero-debug.conf <<'EOF'
Match all
  PermitRootLogin yes
  PasswordAuthentication yes
  KbdInteractiveAuthentication yes
  ChallengeResponseAuthentication yes
  AllowGroups infrazero-admins root
EOF
else
  rm -f /etc/ssh/sshd_config.d/99-infrazero-debug.conf
fi

systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true

# Relax rp_filter for asymmetric routing (WG via bastion)
cat > /etc/sysctl.d/99-infrazero-rpfilter.conf <<'EOF'
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF

# Disable IPv6 cluster-wide
cat > /etc/sysctl.d/99-infrazero-disable-ipv6.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
EOF
sysctl --system || true

# WG routing handled via network route (preferred) or SNAT on bastion; see bastion bootstrap.

# Persist network CIDR for routing helpers
mkdir -p /etc/infrazero
cat > /etc/infrazero/network.env <<EOF
PRIVATE_CIDR=${PRIVATE_CIDR:-}
WG_CIDR=${WG_CIDR:-}
EOF
chmod 600 /etc/infrazero/network.env

# Ensure /32 private NICs route the subnet via the gateway (Hetzner private nets)
cat > /usr/local/sbin/infrazero-private-route.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

NETWORK_ENV="/etc/infrazero/network.env"
if [ -f "$NETWORK_ENV" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$NETWORK_ENV"
  set +a
fi

if [ -z "${PRIVATE_CIDR:-}" ]; then
  exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
  exit 0
fi

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
) || exit 0

priv_if=$(python3 - <<'PY'
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
) || exit 0

prefix_len=$(ip -4 -o addr show "$priv_if" | awk '{print $4}' | cut -d/ -f2 | head -n 1 || true)
if [ "$prefix_len" != "32" ]; then
  exit 0
fi

ip link set dev "$priv_if" up || true
sysctl -w "net.ipv4.conf.${priv_if}.rp_filter=0" >/dev/null 2>&1 || true

ip route replace "${private_gw}/32" dev "$priv_if" scope link || true
ip route del "$PRIVATE_CIDR" dev "$priv_if" 2>/dev/null || true
ip route replace "$PRIVATE_CIDR" via "$private_gw" dev "$priv_if" onlink metric 50 || true
EOF

chmod +x /usr/local/sbin/infrazero-private-route.sh
/usr/local/sbin/infrazero-private-route.sh || true

cat > /etc/systemd/system/infrazero-private-route.service <<'EOF'
[Unit]
Description=Infrazero private subnet route fix
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/infrazero-private-route.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now infrazero-private-route.service

# Ensure WireGuard subnet routes to bastion via the private gateway on non-WG hosts
cat > /usr/local/sbin/infrazero-wg-route.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

NETWORK_ENV="/etc/infrazero/network.env"
if [ -f "$NETWORK_ENV" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$NETWORK_ENV"
  set +a
fi

if [ -z "${PRIVATE_CIDR:-}" ] || [ -z "${WG_CIDR:-}" ]; then
  exit 0
fi

if ip link show wg0 >/dev/null 2>&1; then
  # Bastion has wg0; kernel route exists already.
  exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
  exit 0
fi

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
) || exit 0

priv_if=$(ip -4 route get "$private_gw" 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
if [ -z "$priv_if" ]; then
  priv_if=$(python3 - <<'PY'
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
  ) || exit 0
fi

ip link set dev "$priv_if" up || true
sysctl -w "net.ipv4.conf.${priv_if}.rp_filter=0" >/dev/null 2>&1 || true

/usr/local/sbin/infrazero-private-route.sh || true

ip route replace "$WG_CIDR" via "$private_gw" dev "$priv_if" onlink metric 50 || true
EOF

chmod +x /usr/local/sbin/infrazero-wg-route.sh
/usr/local/sbin/infrazero-wg-route.sh || true

cat > /etc/systemd/system/infrazero-wg-route.service <<'EOF'
[Unit]
Description=Infrazero WireGuard subnet route
After=network-online.target infrazero-private-route.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/infrazero-wg-route.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now infrazero-wg-route.service

# Unattended upgrades (security-only, no reboot)
if command -v unattended-upgrades >/dev/null 2>&1; then
  cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}-security";
};

Unattended-Upgrade::Package-Blacklist {
        "linux-*";
        "libc6";
        "openssl";
        "docker*";
        "containerd*";
        "kube*";
};

Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
EOF

  systemctl enable unattended-upgrades || true
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
