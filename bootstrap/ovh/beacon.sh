#!/usr/bin/env bash
# beacon_status — writes bootstrap progress to /etc/infrazero/bootstrap-status.json
# Sourced by role scripts to report progress. No side effects beyond writing the file.

beacon_status() {
  local phase="$1" message="$2" progress="${3:-0}"
  message=$(printf '%s' "$message" | sed -E 's/(password|token|key|secret)=[^ ]*/\1=***REDACTED***/gI' 2>/dev/null || printf '%s' "$message")
  mkdir -p /etc/infrazero
  if command -v jq >/dev/null 2>&1; then
    jq -n \
      --arg role "${BOOTSTRAP_ROLE:-unknown}" \
      --arg phase "$phase" \
      --arg message "$message" \
      --argjson progress "$progress" \
      --arg updated_at "$(date -Is)" \
      '{role:$role,phase:$phase,message:$message,progress:$progress,updated_at:$updated_at}' \
      > /etc/infrazero/bootstrap-status.json 2>/dev/null || true
  else
    local safe_msg
    safe_msg=$(printf '%s' "$message" | sed 's/"/\\"/g')
    cat > /etc/infrazero/bootstrap-status.json <<EOF
{"role":"${BOOTSTRAP_ROLE:-unknown}","phase":"${phase}","message":"${safe_msg}","progress":${progress},"updated_at":"$(date -Is)"}
EOF
  fi
  chmod 600 /etc/infrazero/bootstrap-status.json 2>/dev/null || true
}
