#!/usr/bin/env bash
set -euo pipefail

# Retry wrapper for transient OpenTofu failures (e.g. Hetzner API 429 rate limits).
#
# Usage:
#   bash scripts/tofu-retry.sh tofu -chdir=tofu apply ...
#
# Tunables:
#   TOFU_RETRY_ATTEMPTS (default: 6)
#   TOFU_RETRY_BASE_DELAY_SECONDS (default: 15)
#   TOFU_RETRY_MAX_DELAY_SECONDS (default: 180)

attempts="${TOFU_RETRY_ATTEMPTS:-6}"
base_delay="${TOFU_RETRY_BASE_DELAY_SECONDS:-15}"
max_delay="${TOFU_RETRY_MAX_DELAY_SECONDS:-180}"

if [ "${attempts}" -lt 1 ] 2>/dev/null; then
  echo "[tofu-retry] TOFU_RETRY_ATTEMPTS must be >= 1" >&2
  exit 2
fi

if [ $# -lt 1 ]; then
  echo "usage: $0 <command...>" >&2
  exit 2
fi

delay="$base_delay"
for i in $(seq 1 "$attempts"); do
  tmp="$(mktemp)"

  set +e
  # Stream output while also capturing it for retry classification.
  "$@" 2>&1 | tee "$tmp"
  rc=${PIPESTATUS[0]}
  set -e

  if [ "$rc" -eq 0 ]; then
    rm -f "$tmp"
    exit 0
  fi

  if grep -qiE '(^|[^0-9])429([^0-9]|$)|too many requests|rate limit|exceeded retry limit' "$tmp"; then
    echo "[tofu-retry] retryable failure (attempt ${i}/${attempts}); sleeping ${delay}s" >&2
    rm -f "$tmp"
    sleep "$delay"
    delay=$((delay * 2))
    if [ "$delay" -gt "$max_delay" ]; then
      delay="$max_delay"
    fi
    continue
  fi

  rm -f "$tmp"
  exit "$rc"
done

echo "[tofu-retry] exceeded retry attempts (${attempts})" >&2
exit 1

