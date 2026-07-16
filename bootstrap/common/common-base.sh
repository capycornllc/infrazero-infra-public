#!/usr/bin/env bash

infrazero_load_env_file() {
  local file="${1:-}"

  if [ -n "$file" ] && [ -f "$file" ]; then
    set -a
    # shellcheck disable=SC1090
    source "$file"
    set +a
  fi
}

infrazero_load_env_files() {
  local file

  for file in "$@"; do
    infrazero_load_env_file "$file"
  done
}

infrazero_require_env() {
  local name="${1:-}"
  local log_prefix="${2:-${BOOTSTRAP_ROLE:-common}}"

  if [ -z "$name" ] || [ -z "${!name:-}" ]; then
    echo "[${log_prefix}] missing required env: ${name:-<empty>}" >&2
    return 1 2>/dev/null || exit 1
  fi
}

infrazero_retry() {
  if [ "$#" -lt 4 ]; then
    echo "[common] invalid retry invocation" >&2
    return 1
  fi

  local log_prefix="${1:-common}"
  local attempts="$2"
  local delay="$3"
  shift 3
  local i

  if [ -z "$attempts" ] || [ -z "$delay" ]; then
    echo "[${log_prefix}] invalid retry invocation" >&2
    return 1
  fi

  for i in $(seq 1 "$attempts"); do
    if "$@"; then
      return 0
    fi
    echo "[${log_prefix}] retry ${i}/${attempts} failed; sleeping ${delay}s"
    sleep "$delay"
  done
  return 1
}

infrazero_apt_get() {
  local log_prefix="${1:-common}"
  shift || true
  local attempts="${INFRAZERO_APT_ATTEMPTS:-5}"
  local retry_delay="${INFRAZERO_APT_RETRY_DELAY:-10}"
  local command_timeout="${INFRAZERO_APT_TIMEOUT:-1200}"
  local lock_timeout="${INFRAZERO_APT_LOCK_TIMEOUT:-600}"
  local clean_lists="${INFRAZERO_APT_CLEAN_LISTS:-true}"
  local attempt=0

  for attempt in $(seq 1 "$attempts"); do
    if timeout "$command_timeout" apt-get -o DPkg::Lock::Timeout="$lock_timeout" "$@"; then
      return 0
    fi
    echo "[${log_prefix}] apt-get $* failed (attempt ${attempt}/${attempts}); retrying in ${retry_delay}s" >&2
    if declare -F beacon_retrying >/dev/null 2>&1; then
      beacon_retrying "installing_packages" "apt-get failed or timed out; retrying" 15 "external" "APT_INSTALL_RETRY" "$attempt" "$attempts"
    fi
    apt-get clean 2>/dev/null || true
    if [ "$clean_lists" = "true" ]; then
      rm -rf /var/lib/apt/lists/* 2>/dev/null || true
    fi
    sleep "$retry_delay"
  done
  return 1
}

infrazero_dump_network_snapshot() {
  local log_prefix="${1:-common}"
  echo "[${log_prefix}] network diagnostics snapshot:"
  ip -4 addr 2>/dev/null || true
  ip -4 route 2>/dev/null || true
  ip route get 1.1.1.1 2>/dev/null || true
  if command -v resolvectl >/dev/null 2>&1; then
    resolvectl status 2>/dev/null || true
  fi
  getent hosts connectivity-check.ubuntu.com 2>/dev/null || true
  getent hosts deb.debian.org 2>/dev/null || true
}

infrazero_detect_private_iface() {
  local private_cidr="${1:-${PRIVATE_CIDR:-}}"

  if [ -n "$private_cidr" ] && command -v python3 >/dev/null 2>&1; then
    PRIVATE_CIDR="$private_cidr" python3 - <<'PY'
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
    return
  fi

  ip -4 -o addr show | awk '$2 != "lo" && $2 !~ /^wg/ && $2 !~ /^docker/ && $2 !~ /^br-/ && $2 !~ /^veth/ && $2 !~ /^tun/ && $2 !~ /^tap/ {print $2; exit}'
}

infrazero_private_ip_for_iface() {
  local iface="${1:-}"

  if [ -z "$iface" ]; then
    return 1
  fi

  ip -4 -o addr show dev "$iface" | awk '{split($4, parts, "/"); print parts[1]; exit}'
}

infrazero_private_ip_for_cidr() {
  local private_cidr="${1:-${PRIVATE_CIDR:-}}"
  local iface=""

  if [ -z "$private_cidr" ]; then
    return 1
  fi

  iface=$(infrazero_detect_private_iface "$private_cidr" || true)
  if [ -z "$iface" ]; then
    return 1
  fi

  infrazero_private_ip_for_iface "$iface"
}

infrazero_bool_is_true() {
  case "${1:-}" in
    true|TRUE|True|1|yes|YES|Yes) return 0 ;;
    *) return 1 ;;
  esac
}

infrazero_install_base_packages() {
  local log_prefix="${1:-common}"
  shift || true
  local packages=("$@")
  local check_url="${INFRAZERO_OUTBOUND_CHECK_URL:-https://connectivity-check.ubuntu.com}"
  local public_check_url="${INFRAZERO_PUBLIC_IPV4_CHECK_URL:-$check_url}"
  local wait_attempts="${INFRAZERO_OUTBOUND_WAIT_ATTEMPTS:-90}"
  local wait_delay="${INFRAZERO_OUTBOUND_WAIT_DELAY:-2}"
  local retry_beacon_interval="${INFRAZERO_OUTBOUND_RETRY_BEACON_INTERVAL:-0}"
  local timeout_label="${INFRAZERO_OUTBOUND_TIMEOUT_LABEL:-}"
  local wait_i=0
  local attempt=0

  if [ "${#packages[@]}" -eq 0 ]; then
    packages=(curl ca-certificates zstd jq e2fsprogs auditd unattended-upgrades)
  fi

  if declare -F beacon_status >/dev/null 2>&1; then
    beacon_status "installing_packages" "Installing base packages" 15
  fi

  if [ -z "${HAS_PUBLIC_IPV4:-}" ] && infrazero_bool_is_true "${INFRAZERO_PUBLIC_IPV4_AUTODETECT:-false}"; then
    if curl -sf --connect-timeout 3 --max-time 5 -o /dev/null "$public_check_url" 2>/dev/null; then
      HAS_PUBLIC_IPV4=true
      echo "[${log_prefix}] auto-detected public IPv4 (direct internet access)"
    fi
  fi

  if [ -z "${HAS_PUBLIC_IPV4:-}" ] || [ "${HAS_PUBLIC_IPV4:-}" = "false" ]; then
    echo "[${log_prefix}] waiting for outbound internet (egress NAT)..."
    for wait_i in $(seq 1 "$wait_attempts"); do
      if curl -sf --connect-timeout 3 --max-time 5 -o /dev/null "$check_url" 2>/dev/null; then
        echo "[${log_prefix}] outbound internet available (attempt ${wait_i})"
        break
      fi

      if [ "$retry_beacon_interval" -gt 0 ] && { [ "$wait_i" -eq 1 ] || [ $((wait_i % retry_beacon_interval)) -eq 0 ]; }; then
        if declare -F beacon_retrying >/dev/null 2>&1; then
          beacon_retrying "waiting_outbound_internet" "Waiting for outbound internet via egress NAT" 14 "network" "NET_OUTBOUND_WAIT" "$wait_i" "$wait_attempts"
        fi
      fi

      if [ "$wait_i" -eq "$wait_attempts" ]; then
        if [ -n "$timeout_label" ]; then
          echo "[${log_prefix}] WARNING: outbound internet not available after ${wait_attempts} attempts (${timeout_label}); continuing anyway" >&2
        else
          echo "[${log_prefix}] WARNING: outbound internet not available after ${wait_attempts} attempts; continuing anyway" >&2
        fi
        if infrazero_bool_is_true "${INFRAZERO_OUTBOUND_DEGRADED_ON_TIMEOUT:-false}" && declare -F beacon_degraded >/dev/null 2>&1; then
          beacon_degraded "waiting_outbound_internet" "Outbound internet unavailable after retries; continuing for diagnostics" 14 "network" "NET_OUTBOUND_UNAVAILABLE"
        fi
        if infrazero_bool_is_true "${INFRAZERO_OUTBOUND_DUMP_ON_TIMEOUT:-false}"; then
          infrazero_dump_network_snapshot "$log_prefix"
        fi
      fi
      sleep "$wait_delay"
    done
  fi

  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    if declare -F infrazero_apt_get >/dev/null 2>&1; then
      if infrazero_apt_get "$log_prefix" update -y \
        && infrazero_apt_get "$log_prefix" install -y "${packages[@]}"; then
        return 0
      fi
    else
      for attempt in {1..5}; do
        if timeout 1200 apt-get -o DPkg::Lock::Timeout=600 update -y \
          && timeout 1200 apt-get -o DPkg::Lock::Timeout=600 install -y "${packages[@]}"; then
          return 0
        fi
        echo "[${log_prefix}] apt-get attempt ${attempt}/5 failed or timed out; retrying in 10s..." >&2
        if declare -F beacon_retrying >/dev/null 2>&1; then
          beacon_retrying "installing_packages" "apt-get failed or timed out; retrying" 15 "external" "APT_INSTALL_RETRY" "$attempt" 5
        fi
        apt-get clean 2>/dev/null || true
        rm -rf /var/lib/apt/lists/* 2>/dev/null || true
        sleep 10
      done
    fi
    echo "[${log_prefix}] apt-get failed after 5 retries; continuing without packages" >&2
    if declare -F beacon_degraded >/dev/null 2>&1; then
      beacon_degraded "installing_packages" "apt-get failed after retries; continuing without confirmed base packages" 15 "external" "APT_INSTALL_FAILED"
    fi
  fi
}

infrazero_setup_admin_users() {
  local log_prefix="${1:-common}"
  local admins_file="/etc/infrazero/admins.json"
  local tmp_keys="/tmp/infrazero-admin-keys"

  if [ -z "${ADMIN_USERS_JSON_B64:-}" ]; then
    return 0
  fi

  mkdir -p /etc/infrazero
  echo "$ADMIN_USERS_JSON_B64" | base64 -d > "$admins_file"
  chmod 600 "$admins_file"

  if ! getent group infrazero-admins >/dev/null 2>&1; then
    groupadd infrazero-admins
  fi
  echo "%infrazero-admins ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/90-infrazero-admins
  chmod 440 /etc/sudoers.d/90-infrazero-admins

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
      "$admins_file" > "$tmp_keys" || true
  else
    echo "[${log_prefix}] python3/jq not available; skipping admin user creation" >&2
  fi

  if [ -s "$tmp_keys" ]; then
    declare -A seen_users
    while IFS='|' read -r username key; do
      if [ -z "$username" ] || [ -z "$key" ]; then
        continue
      fi

      if ! id -u "$username" >/dev/null 2>&1; then
        local useradd_extra_raw=""
        local -a useradd_extra_args=()
        if declare -F provider_admin_useradd_options >/dev/null 2>&1; then
          useradd_extra_raw="$(provider_admin_useradd_options "$username" 2>/dev/null || true)"
          if [ -n "$useradd_extra_raw" ]; then
            # shellcheck disable=SC2206
            useradd_extra_args=($useradd_extra_raw)
          fi
        fi
        useradd -m -s /bin/bash "${useradd_extra_args[@]}" -G infrazero-admins "$username"
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
}

infrazero_set_sshd_config() {
  local sshd_config="${1:-/etc/ssh/sshd_config}"
  local key="$2"
  local value="$3"

  if grep -q "^${key} " "$sshd_config"; then
    sed -i "s/^${key}.*/${key} ${value}/" "$sshd_config"
  else
    echo "${key} ${value}" >> "$sshd_config"
  fi
}

infrazero_ensure_sshd_include() {
  local sshd_config="${1:-/etc/ssh/sshd_config}"

  if ! grep -Eq '^[#[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/\*.conf' "$sshd_config"; then
    echo "Include /etc/ssh/sshd_config.d/*.conf" >> "$sshd_config"
  fi
}

infrazero_strip_sshd_debug_block() {
  local sshd_config="${1:-/etc/ssh/sshd_config}"
  local begin="# BEGIN INFRAZERO DEBUG SSH"
  local end="# END INFRAZERO DEBUG SSH"

  if [ -f "$sshd_config" ]; then
    awk -v begin="$begin" -v end="$end" '
      $0==begin {skip=1; next}
      $0==end {skip=0; next}
      skip==1 {next}
      {print}
    ' "$sshd_config" > "${sshd_config}.tmp" && mv "${sshd_config}.tmp" "$sshd_config"
  fi
}

infrazero_harden_ssh() {
  local log_prefix="${1:-common}"
  local sshd_config="${SSHD_CONFIG:-/etc/ssh/sshd_config}"
  local debug_root_password="${DEBUG_ROOT_PASSWORD:-}"
  local ssh_password_auth="no"
  local ssh_kbd_interactive="no"
  local ssh_challenge="no"
  local ssh_permit_root="no"
  local ssh_allow_groups="infrazero-admins"

  if [ -n "$debug_root_password" ]; then
    echo "[${log_prefix}] DEBUG_ROOT_PASSWORD set; enabling root password auth"
    echo "root:${debug_root_password}" | chpasswd || echo "[${log_prefix}] unable to set root password" >&2
    passwd -u root >/dev/null 2>&1 || usermod -U root >/dev/null 2>&1 || true
    ssh_password_auth="yes"
    ssh_kbd_interactive="yes"
    ssh_challenge="yes"
    ssh_permit_root="yes"
    ssh_allow_groups="infrazero-admins root"
  fi

  infrazero_ensure_sshd_include "$sshd_config"
  infrazero_set_sshd_config "$sshd_config" "PasswordAuthentication" "$ssh_password_auth"
  infrazero_set_sshd_config "$sshd_config" "KbdInteractiveAuthentication" "$ssh_kbd_interactive"
  infrazero_set_sshd_config "$sshd_config" "ChallengeResponseAuthentication" "$ssh_challenge"
  infrazero_set_sshd_config "$sshd_config" "PermitRootLogin" "$ssh_permit_root"
  infrazero_strip_sshd_debug_block "$sshd_config"

  mkdir -p /etc/ssh/sshd_config.d
  rm -f /etc/ssh/sshd_config.d/infrazero.conf
  cat > /etc/ssh/sshd_config.d/90-infrazero.conf <<EOF
PasswordAuthentication ${ssh_password_auth}
KbdInteractiveAuthentication ${ssh_kbd_interactive}
ChallengeResponseAuthentication ${ssh_challenge}
PermitRootLogin ${ssh_permit_root}
AllowGroups ${ssh_allow_groups}
EOF

  if [ -n "$debug_root_password" ]; then
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
}

infrazero_apply_network_baseline() {
  cat > /etc/sysctl.d/99-infrazero-rpfilter.conf <<'EOF'
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF

  cat > /etc/sysctl.d/99-infrazero-disable-ipv6.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
EOF
  sysctl --system || true

  if [ -d /proc/sys/net/ipv6/conf ]; then
    for f in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
      echo 1 > "$f" 2>/dev/null || true
    done
  fi

  if command -v ip >/dev/null 2>&1; then
    ip -6 route del default 2>/dev/null || true
  fi
}

infrazero_write_network_env() {
  mkdir -p /etc/infrazero
  cat > /etc/infrazero/network.env <<EOF
PRIVATE_CIDR=${PRIVATE_CIDR:-}
WG_CIDR=${WG_CIDR:-}
BASTION_PRIVATE_IP=${BASTION_PRIVATE_IP:-}
EOF
  chmod 600 /etc/infrazero/network.env
}

infrazero_install_systemd_timer() {
  local timer_name="${1:-}"
  local service_name="${2:-}"
  local description="${3:-Infrazero periodic task}"
  local on_boot_sec="${4:-120s}"
  local on_unit_active_sec="${5:-60s}"
  local accuracy_sec="${6:-10s}"

  if [ -z "$timer_name" ] || [ -z "$service_name" ]; then
    return 1
  fi

  local timer_unit="${timer_name%.timer}.timer"
  local service_unit="${service_name%.service}.service"

  cat > "/etc/systemd/system/${timer_unit}" <<EOF
[Unit]
Description=${description}

[Timer]
OnBootSec=${on_boot_sec}
OnUnitActiveSec=${on_unit_active_sec}
AccuracySec=${accuracy_sec}
Unit=${service_unit}

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload || true
  systemctl enable --now "$timer_unit" || true
}

infrazero_install_wireguard_packages() {
  local log_prefix="${1:-wireguard}"

  if ! command -v apt-get >/dev/null 2>&1; then
    return 0
  fi

  export DEBIAN_FRONTEND=noninteractive

  # Prefer the shared apt helper (retries, lock timeout, beacon reporting) - the
  # same mechanism used for base packages. Fall back to the standalone loop if
  # the helper is not loaded, so resilience is never reduced.
  if declare -F infrazero_apt_get >/dev/null 2>&1; then
    if infrazero_apt_get "$log_prefix" update -y \
      && infrazero_apt_get "$log_prefix" install -y wireguard wireguard-tools unzip; then
      return 0
    fi
    echo "[${log_prefix}] unable to install WireGuard packages" >&2
    return 1
  fi

  local attempt
  for attempt in {1..20}; do
    if timeout 1200 apt-get -o DPkg::Lock::Timeout=600 update -y && timeout 1200 apt-get -o DPkg::Lock::Timeout=600 install -y wireguard wireguard-tools unzip; then
      return 0
    fi
    echo "[${log_prefix}] apt-get install wireguard failed (attempt ${attempt}/20); retrying in 10s" >&2
    sleep 10
  done

  echo "[${log_prefix}] unable to install WireGuard packages" >&2
  return 1
}

infrazero_configure_bastion_wireguard() {
  local log_prefix="${1:-bastion}"
  local peers name pubkey ip psk

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

  if ! echo "$WG_ADMIN_PEERS_JSON" | jq empty 2>/dev/null; then
    echo "[${log_prefix}] FATAL: WG_ADMIN_PEERS_JSON is not valid JSON" >&2
    if declare -F beacon_status >/dev/null 2>&1; then
      beacon_status "failed" "Invalid WireGuard peers config" 0
    fi
    return 1
  fi

  peers=$(echo "$WG_ADMIN_PEERS_JSON" | jq -r 'to_entries[] | "\(.key)|\(.value.publicKey)|\(.value.ip)"')

  while IFS='|' read -r name pubkey ip; do
    if [ -z "$pubkey" ] || [ -z "$ip" ] || [ "$pubkey" = "null" ] || [ "$ip" = "null" ]; then
      echo "[${log_prefix}] skipping peer $name with missing fields"
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
}

infrazero_ensure_aws_cli() {
  local log_prefix="${1:-awscli}"

  if command -v aws >/dev/null 2>&1; then
    return 0
  fi

  if command -v apt-get >/dev/null 2>&1; then
    if ! command -v unzip >/dev/null 2>&1; then
      if declare -F apt_get >/dev/null 2>&1; then
        apt_get install -y unzip
      elif declare -F infrazero_apt_get >/dev/null 2>&1; then
        infrazero_apt_get "$log_prefix" install -y unzip
      else
        timeout 1200 apt-get -o DPkg::Lock::Timeout=600 install -y unzip
      fi
    fi
    if ! command -v curl >/dev/null 2>&1; then
      if declare -F apt_get >/dev/null 2>&1; then
        apt_get install -y curl
      elif declare -F infrazero_apt_get >/dev/null 2>&1; then
        infrazero_apt_get "$log_prefix" install -y curl
      else
        timeout 1200 apt-get -o DPkg::Lock::Timeout=600 install -y curl
      fi
    fi
  fi

  if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
    echo "[${log_prefix}] awscli install requires curl and unzip" >&2
    return 1
  fi

  local tmp_dir=""
  local archive=""
  local attempt=0
  local awscli_arch=""
  case "$(uname -m)" in
    x86_64|amd64) awscli_arch="x86_64" ;;
    aarch64|arm64) awscli_arch="aarch64" ;;
    *)
      echo "[${log_prefix}] unsupported architecture for awscli install: $(uname -m)" >&2
      return 1
      ;;
  esac
  tmp_dir=$(mktemp -d)
  archive="$tmp_dir/awscliv2.zip"

  for attempt in {1..20}; do
    if curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-${awscli_arch}.zip" -o "$archive"; then
      rm -rf "$tmp_dir/aws"
      if unzip -q "$archive" -d "$tmp_dir" \
        && "$tmp_dir/aws/install" --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli --update \
        && command -v aws >/dev/null 2>&1; then
        rm -rf "$tmp_dir"
        return 0
      fi
    fi
    echo "[${log_prefix}] awscli install attempt ${attempt}/20 failed; retrying in 3s" >&2
    sleep 3
  done

  rm -rf "$tmp_dir"
  return 1
}

infrazero_install_journald_promtail() {
  local log_prefix="${1:-bootstrap}"
  local role="${2:-}"
  local loki_url="${3:-}"
  local service_name="${4:-promtail}"
  local config_file="${5:-/etc/promtail/promtail.yml}"
  local positions_file="${6:-/var/lib/promtail/positions.yaml}"
  local promtail_url="${INFRAZERO_PROMTAIL_URL:-https://github.com/grafana/loki/releases/download/v2.9.3/promtail-linux-amd64.zip}"
  local service_id="${service_name%.service}"
  local service_unit="${service_id}.service"
  local host_label="${HOSTNAME:-}"

  if [ -z "$role" ] || [ -z "$loki_url" ]; then
    echo "[${log_prefix}] promtail role or Loki URL is missing; skipping" >&2
    return 0
  fi

  if [ -z "$host_label" ]; then
    host_label="$(hostname 2>/dev/null || echo unknown)"
  fi

  if [ ! -x /usr/local/bin/promtail ]; then
    local promtail_downloaded=false
    local pt_attempt
    for pt_attempt in {1..5}; do
      if curl -fsSL --connect-timeout 10 --max-time 120 -o /tmp/promtail.zip "$promtail_url"; then
        promtail_downloaded=true
        break
      fi
      echo "[${log_prefix}] promtail download attempt ${pt_attempt}/5 failed; retrying in 15s"
      sleep 15
    done

    if [ "$promtail_downloaded" = "true" ]; then
      unzip -o /tmp/promtail.zip -d /usr/local/bin
      mv /usr/local/bin/promtail-linux-amd64 /usr/local/bin/promtail
      chmod +x /usr/local/bin/promtail
    else
      echo "[${log_prefix}] promtail download failed after 5 attempts; skipping"
    fi
  fi

  if [ ! -x /usr/local/bin/promtail ]; then
    echo "[${log_prefix}] promtail binary unavailable; skipping service setup"
    return 0
  fi

  mkdir -p "$(dirname "$config_file")" "$(dirname "$positions_file")"
  cat > "$config_file" <<EOF
server:
  http_listen_port: 9080
  grpc_listen_port: 0
positions:
  filename: ${positions_file}
clients:
  - url: ${loki_url}
    external_labels:
      host: ${host_label}
      role: ${role}
scrape_configs:
  - job_name: systemd-journal
    journal:
      max_age: 12h
      labels:
        job: systemd-journal
    relabel_configs:
      - source_labels: ["__journal__systemd_unit"]
        target_label: unit
  - job_name: infrazero-bootstrap
    static_configs:
      - targets:
          - localhost
        labels:
          job: infrazero-bootstrap
          host: "${host_label}"
          role: "${role}"
          __path__: /var/log/infrazero-bootstrap.log
EOF

  cat > "/etc/systemd/system/${service_unit}" <<EOF
[Unit]
Description=Promtail log shipper
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/promtail -config.file=${config_file}
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "$service_id" || echo "[${log_prefix}] failed to start ${service_id}; continuing"
}

infrazero_configure_base_system() {
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

  systemctl enable --now auditd || true

  mkdir -p /var/log/journal
  sed -i 's/^#\?Storage=.*/Storage=persistent/' /etc/systemd/journald.conf
  systemctl restart systemd-journald || true

  sed -i 's/^#\?FallbackDNS=.*/FallbackDNS=1.1.1.1 1.0.0.1 8.8.8.8/' /etc/systemd/resolved.conf
  systemctl restart systemd-resolved || true
}

# Load the provider adapter (see docs/provider-adapter-contract.md).
# Lookup order:
#   1. adapter.sh next to the calling script (flat bootstrap archive layout);
#   2. bootstrap/providers/${INFRAZERO_PROVIDER}/adapter.sh (repo layout;
#      INFRAZERO_PROVIDER is exported by the provider wrapper scripts).
# Fails hard when no adapter is found: guessing a provider would silently
# apply wrong-cloud behavior.
infrazero_load_provider_adapter() {
  if declare -F provider_route_mode >/dev/null 2>&1; then
    return 0
  fi

  local base_dir="${1:-}"
  if [ -z "$base_dir" ]; then
    base_dir="$(cd "$(dirname "${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}")" && pwd)"
  fi

  local candidate
  for candidate in \
    "${base_dir}/adapter.sh" \
    "${base_dir}/../providers/${INFRAZERO_PROVIDER:-}/adapter.sh" \
    "${base_dir}/../../providers/${INFRAZERO_PROVIDER:-}/adapter.sh"; do
    case "$candidate" in
      *"/providers//adapter.sh") continue ;;
    esac
    if [ -f "$candidate" ]; then
      # shellcheck disable=SC1090
      source "$candidate"
      return 0
    fi
  done

  echo "[common-base] provider adapter not found (looked near ${base_dir}; INFRAZERO_PROVIDER='${INFRAZERO_PROVIDER:-}')" >&2
  return 1
}
