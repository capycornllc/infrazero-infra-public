#!/usr/bin/env bash
# Shared bootstrap status helpers. Sourced by provider beacon.sh wrappers.

infrazero_redact() {
  local value="${1:-}"
  value=$(printf '%s' "$value" | sed -E 's/(password|token|key|secret|private_key|preshared)=[^ ]*/\1=***REDACTED***/gI' 2>/dev/null || printf '%s' "$value")
  value=$(printf '%s' "$value" | sed -E 's/[A-Za-z0-9+/=]{40,}/***REDACTED***/g' 2>/dev/null || printf '%s' "$value")
  printf '%s' "$value"
}

infrazero_json_escape() {
  printf '%s' "${1:-}" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

infrazero_state_for_phase() {
  case "${1:-}" in
    complete) printf 'complete' ;;
    failed) printf 'failed' ;;
    *) printf 'running' ;;
  esac
}

beacon_write() {
  local state="$1"
  local phase="$2"
  local message="$3"
  local progress="${4:-0}"
  local category="${5:-}"
  local code="${6:-}"
  local file="${7:-}"
  local line="${8:-}"
  local command="${9:-}"
  local exit_code="${10:-}"
  local attempt="${11:-}"
  local max_attempts="${12:-}"
  local recoverable="${13:-}"
  local updated_at

  message=$(infrazero_redact "$message")
  command=$(infrazero_redact "$command")
  updated_at="$(date -Is)"

  export INFRAZERO_CURRENT_PHASE="$phase"
  export INFRAZERO_CURRENT_PROGRESS="$progress"

  mkdir -p /etc/infrazero
  if command -v jq >/dev/null 2>&1; then
    jq -n \
      --arg role "${BOOTSTRAP_ROLE:-unknown}" \
      --arg state "$state" \
      --arg phase "$phase" \
      --arg message "$message" \
      --argjson progress "$progress" \
      --arg updated_at "$updated_at" \
      --arg category "$category" \
      --arg code "$code" \
      --arg file "$file" \
      --arg line "$line" \
      --arg command "$command" \
      --arg exit_code "$exit_code" \
      --arg attempt "$attempt" \
      --arg max_attempts "$max_attempts" \
      --arg recoverable "$recoverable" \
      '{
        role:$role,
        state:$state,
        phase:$phase,
        message:$message,
        progress:$progress,
        updated_at:$updated_at,
        category:(if $category == "" then null else $category end),
        code:(if $code == "" then null else $code end),
        file:(if $file == "" then null else $file end),
        line:(if $line == "" then null else $line end),
        command:(if $command == "" then null else $command end),
        exit_code:(if $exit_code == "" then null else $exit_code end),
        attempt:(if $attempt == "" then null else $attempt end),
        max_attempts:(if $max_attempts == "" then null else $max_attempts end),
        recoverable:(if $recoverable == "" then null else ($recoverable == "true") end)
      }' \
      > /etc/infrazero/bootstrap-status.json 2>/dev/null || true
  else
    local safe_message safe_command safe_category safe_code safe_file safe_line safe_exit_code safe_attempt safe_max_attempts safe_recoverable
    safe_message=$(infrazero_json_escape "$message")
    safe_command=$(infrazero_json_escape "$command")
    safe_category=$(infrazero_json_escape "$category")
    safe_code=$(infrazero_json_escape "$code")
    safe_file=$(infrazero_json_escape "$file")
    safe_line=$(infrazero_json_escape "$line")
    safe_exit_code=$(infrazero_json_escape "$exit_code")
    safe_attempt=$(infrazero_json_escape "$attempt")
    safe_max_attempts=$(infrazero_json_escape "$max_attempts")
    safe_recoverable=$(infrazero_json_escape "$recoverable")
    cat > /etc/infrazero/bootstrap-status.json <<EOF
{"role":"${BOOTSTRAP_ROLE:-unknown}","state":"${state}","phase":"${phase}","message":"${safe_message}","progress":${progress},"updated_at":"${updated_at}","category":"${safe_category}","code":"${safe_code}","file":"${safe_file}","line":"${safe_line}","command":"${safe_command}","exit_code":"${safe_exit_code}","attempt":"${safe_attempt}","max_attempts":"${safe_max_attempts}","recoverable":"${safe_recoverable}"}
EOF
  fi
  chmod 600 /etc/infrazero/bootstrap-status.json 2>/dev/null || true
}

beacon_status() {
  local phase="$1" message="$2" progress="${3:-0}"
  beacon_write "$(infrazero_state_for_phase "$phase")" "$phase" "$message" "$progress"
}

beacon_retrying() {
  local phase="$1" message="$2" progress="${3:-0}" category="${4:-}" code="${5:-}" attempt="${6:-}" max_attempts="${7:-}"
  beacon_write "retrying" "$phase" "$message" "$progress" "$category" "$code" "" "" "" "" "$attempt" "$max_attempts" "true"
}

beacon_degraded() {
  local phase="$1" message="$2" progress="${3:-0}" category="${4:-}" code="${5:-}"
  beacon_write "degraded" "$phase" "$message" "$progress" "$category" "$code" "" "" "" "" "" "" "true"
}

beacon_failed() {
  local phase="$1" message="$2" progress="${3:-0}" category="${4:-script}" code="${5:-SCRIPT_ERROR}" file="${6:-}" line="${7:-}" command="${8:-}" exit_code="${9:-}"
  beacon_write "failed" "$phase" "$message" "$progress" "$category" "$code" "$file" "$line" "$command" "$exit_code" "" "" "false"
}

infrazero_trap_error() {
  local exit_code="$1" line="$2" command="$3"
  beacon_failed "${INFRAZERO_CURRENT_PHASE:-failed}" "Script failed at line ${line}" "${INFRAZERO_CURRENT_PROGRESS:-0}" "script" "SCRIPT_ERROR" "${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}" "$line" "$command" "$exit_code"
  exit "$exit_code"
}

infrazero_install_error_trap() {
  trap 'infrazero_trap_error "$?" "$LINENO" "$BASH_COMMAND"' ERR
}
