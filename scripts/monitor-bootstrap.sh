#!/usr/bin/env bash
# monitor-bootstrap.sh — Poll bootstrap status from all servers via bastion SSH.
# Outputs [BOOTSTRAP:<role>] lines for the Infrazero UI to parse.
# SOC 2: No secrets in output. All lines are sanitized before printing.
set -euo pipefail

BASTION_IP="${BASTION_PUBLIC_IP:-}"
SSH_KEY="${SSH_PRIVATE_KEY_PATH:-${RUNNER_TEMP}/ssh_key}"
POLL_INTERVAL="${BOOTSTRAP_POLL_INTERVAL:-10}"
TIMEOUT_MINUTES="${BOOTSTRAP_TIMEOUT_MINUTES:-15}"
STATUS_FILE="/etc/infrazero/bootstrap-status.json"

# Server list: role|ip pairs (set by workflow via env)
# Format: "bastion:1.2.3.4,egress:10.0.0.2,node1:10.0.0.3,db:10.0.0.4"
SERVER_LIST="${BOOTSTRAP_SERVER_LIST:-}"

if [ -z "$BASTION_IP" ]; then
  echo "[BOOTSTRAP:monitor] ERROR: BASTION_PUBLIC_IP not set"
  exit 1
fi

if [ -z "$SERVER_LIST" ]; then
  echo "[BOOTSTRAP:monitor] ERROR: BOOTSTRAP_SERVER_LIST not set"
  exit 1
fi

# SOC 2: Sanitize output — strip anything that looks like a secret
sanitize_line() {
  local line="$1"
  # Strip password=, token=, key=, secret= values (GNU sed case-insensitive flag is I)
  line=$(printf '%s' "$line" | sed -E 's/(password|token|key|secret|private_key)=[^ ]*/\1=***REDACTED***/gI' 2>/dev/null || printf '%s' "$line")
  # Strip long base64 blocks (>40 chars) that might be keys
  line=$(printf '%s' "$line" | sed -E 's/[A-Za-z0-9+/=]{40,}/***REDACTED***/g')
  printf '%s' "$line"
}

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o BatchMode=yes -o LogLevel=ERROR"
SSH_USER="${BOOTSTRAP_SSH_USER:-root}"

ssh_bastion() {
  ssh $SSH_OPTS -i "$SSH_KEY" "${SSH_USER}@${BASTION_IP}" "$@"
}

ssh_via_bastion() {
  local target_ip="$1"
  shift
  # Admin users have sudo; use sudo to read the status file
  ssh $SSH_OPTS -i "$SSH_KEY" -J "${SSH_USER}@${BASTION_IP}" "${SSH_USER}@${target_ip}" "sudo cat ${STATUS_FILE} 2>/dev/null" 2>/dev/null
}

# Parse server list into arrays
declare -A SERVER_IPS
IFS=',' read -ra PAIRS <<< "$SERVER_LIST"
for pair in "${PAIRS[@]}"; do
  role="${pair%%:*}"
  ip="${pair#*:}"
  SERVER_IPS["$role"]="$ip"
done

ROLES=("${!SERVER_IPS[@]}")
echo "[BOOTSTRAP:monitor] Monitoring ${#ROLES[@]} servers: ${ROLES[*]}"

deadline=$((SECONDS + TIMEOUT_MINUTES * 60))
declare -A COMPLETED

echo "::group::Server Bootstrap Progress"

while [ "$SECONDS" -lt "$deadline" ]; do
  all_done=true

  for role in "${ROLES[@]}"; do
    if [ -n "${COMPLETED[$role]:-}" ]; then
      continue
    fi

    ip="${SERVER_IPS[$role]}"
    status_json=""

    # Bastion is accessed directly; others via bastion jump
    if [ "$role" = "bastion" ]; then
      status_json=$(ssh_bastion "sudo cat ${STATUS_FILE} 2>/dev/null" 2>/dev/null || true)
    else
      status_json=$(ssh_via_bastion "$ip" 2>/dev/null || true)
    fi

    if [ -z "$status_json" ]; then
      echo "[BOOTSTRAP:${role}] Waiting for server..."
      all_done=false
      continue
    fi

    phase=$(echo "$status_json" | jq -r '.phase // "unknown"' 2>/dev/null || echo "unknown")
    message=$(echo "$status_json" | jq -r '.message // "No status"' 2>/dev/null || echo "No status")
    progress=$(echo "$status_json" | jq -r '.progress // 0' 2>/dev/null || echo "0")

    safe_message=$(sanitize_line "$message")

    if [ "$phase" = "complete" ]; then
      echo "[BOOTSTRAP:${role}] Complete (${progress}%)"
      COMPLETED["$role"]="true"
    elif [ "$phase" = "failed" ]; then
      echo "[BOOTSTRAP:${role}] FAILED: ${safe_message}"
      COMPLETED["$role"]="failed"
    else
      echo "[BOOTSTRAP:${role}] ${safe_message} (${progress}%)"
      all_done=false
    fi
  done

  if [ "$all_done" = "true" ]; then
    echo "[BOOTSTRAP:monitor] All servers completed bootstrap"
    break
  fi

  sleep "$POLL_INTERVAL"
done

echo "::endgroup::"

# Check for failures
has_failure=false
for role in "${ROLES[@]}"; do
  if [ "${COMPLETED[$role]:-}" = "failed" ]; then
    echo "[BOOTSTRAP:monitor] ERROR: ${role} failed bootstrap"
    has_failure=true
  fi
  if [ -z "${COMPLETED[$role]:-}" ]; then
    echo "[BOOTSTRAP:monitor] WARNING: ${role} did not complete within timeout"
  fi
done

if [ "$has_failure" = "true" ]; then
  exit 1
fi
