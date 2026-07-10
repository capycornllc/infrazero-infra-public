#!/usr/bin/env bash
# Minimal beacon fallback used only when common-beacon.sh is unavailable.
# Single source of truth for the fallback previously copied into provider
# beacon.sh and common.sh (4 copies). SOC 2: no secrets, descriptive labels.

beacon_status() {
  local phase="$1" message="$2" progress="${3:-0}" state="running"
  case "$phase" in
    complete) state="complete" ;;
    failed) state="failed" ;;
  esac
  message=$(printf '%s' "$message" | sed -E 's/(password|token|key|secret|private_key|preshared)=[^ ]*/\1=***REDACTED***/gI' 2>/dev/null || printf '%s' "$message")
  mkdir -p /etc/infrazero
  printf '{"role":"%s","state":"%s","phase":"%s","message":"%s","progress":%s,"updated_at":"%s"}\n' \
    "${BOOTSTRAP_ROLE:-unknown}" "$state" "$phase" "$(printf '%s' "$message" | sed 's/\\/\\\\/g; s/"/\\"/g')" "$progress" "$(date -Is)" \
    > /etc/infrazero/bootstrap-status.json 2>/dev/null || true
  chmod 600 /etc/infrazero/bootstrap-status.json 2>/dev/null || true
}

beacon_retrying() { beacon_status "$1" "$2" "${3:-0}"; }
beacon_degraded() { beacon_status "$1" "$2" "${3:-0}"; }
beacon_failed() {
  local message="${2:-${1:-Bootstrap failed}}"
  beacon_status failed "$message" "${3:-0}"
}
