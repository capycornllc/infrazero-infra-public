#!/usr/bin/env bash
# monitor-bootstrap.sh — Stream live bootstrap logs from all servers via bastion SSH.
# Outputs [BOOTSTRAP:<role>] lines for the Infrazero UI to parse.
# Two types of output:
#   [BOOTSTRAP:<role>] STATUS <phase> <progress> <message>   — summary status
#   [BOOTSTRAP:<role>] LOG <line>                             — raw log line
# SOC 2: No secrets in output. All lines are sanitized before printing.
set -euo pipefail

BASTION_IP="${BASTION_PUBLIC_IP:-}"
SSH_KEY="${SSH_PRIVATE_KEY_PATH:-${RUNNER_TEMP}/ssh_key}"
POLL_INTERVAL="${BOOTSTRAP_POLL_INTERVAL:-8}"
TIMEOUT_MINUTES="${BOOTSTRAP_TIMEOUT_MINUTES:-15}"
STATUS_FILE="/etc/infrazero/bootstrap-status.json"
LOG_FILE="/var/log/infrazero-bootstrap.log"
SSH_USER="${BOOTSTRAP_SSH_USER:-root}"

# Server list: role:ip pairs (set by workflow via env)
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
  line=$(printf '%s' "$line" | sed -E 's/(password|token|key|secret|private_key|preshared)=[^ ]*/\1=***REDACTED***/gI' 2>/dev/null || printf '%s' "$line")
  line=$(printf '%s' "$line" | sed -E 's/[A-Za-z0-9+/=]{40,}/***REDACTED***/g')
  printf '%s' "$line"
}

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o BatchMode=yes -o LogLevel=ERROR"

ssh_cmd() {
  local target_ip="$1"
  shift
  if [ "$target_ip" = "$BASTION_IP" ]; then
    ssh $SSH_OPTS -i "$SSH_KEY" "${SSH_USER}@${BASTION_IP}" "$@"
  else
    ssh $SSH_OPTS -i "$SSH_KEY" -J "${SSH_USER}@${BASTION_IP}" "${SSH_USER}@${target_ip}" "$@"
  fi
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
declare -A LOG_OFFSETS  # track how many lines we've already printed per server

for role in "${ROLES[@]}"; do
  LOG_OFFSETS["$role"]=0
done

echo "::group::Server Bootstrap Progress"

while [ "$SECONDS" -lt "$deadline" ]; do
  all_done=true

  for role in "${ROLES[@]}"; do
    if [ -n "${COMPLETED[$role]:-}" ]; then
      continue
    fi

    ip="${SERVER_IPS[$role]}"
    offset="${LOG_OFFSETS[$role]}"

    # 1. Fetch status summary
    status_json=$(ssh_cmd "$ip" "sudo cat ${STATUS_FILE} 2>/dev/null" 2>/dev/null || true)

    phase="unknown"
    message="Waiting for server..."
    progress=0

    if [ -n "$status_json" ]; then
      phase=$(echo "$status_json" | jq -r '.phase // "unknown"' 2>/dev/null || echo "unknown")
      message=$(echo "$status_json" | jq -r '.message // "No status"' 2>/dev/null || echo "No status")
      progress=$(echo "$status_json" | jq -r '.progress // 0' 2>/dev/null || echo "0")
    fi

    safe_message=$(sanitize_line "$message")
    echo "[BOOTSTRAP:${role}] STATUS ${phase} ${progress} ${safe_message}"

    # 2. Fetch new log lines (incremental — only lines after offset)
    new_lines=$(ssh_cmd "$ip" "sudo tail -n +$((offset + 1)) ${LOG_FILE} 2>/dev/null | head -200" 2>/dev/null || true)

    if [ -n "$new_lines" ]; then
      line_count=0
      while IFS= read -r line; do
        safe_line=$(sanitize_line "$line")
        echo "[BOOTSTRAP:${role}] LOG ${safe_line}"
        line_count=$((line_count + 1))
      done <<< "$new_lines"
      LOG_OFFSETS["$role"]=$((offset + line_count))
    fi

    # 3. Check completion
    if [ "$phase" = "complete" ]; then
      COMPLETED["$role"]="true"
    elif [ "$phase" = "failed" ]; then
      COMPLETED["$role"]="failed"
      # On failure, grab last 50 lines for context
      tail_lines=$(ssh_cmd "$ip" "sudo tail -50 ${LOG_FILE} 2>/dev/null" 2>/dev/null || true)
      if [ -n "$tail_lines" ]; then
        while IFS= read -r line; do
          safe_line=$(sanitize_line "$line")
          echo "[BOOTSTRAP:${role}] LOG ${safe_line}"
        done <<< "$tail_lines"
      fi
    else
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

# Summary
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
