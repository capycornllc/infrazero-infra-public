#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "usage: $0 <volume-name>" >&2
  exit 1
fi

if [ -z "${HCLOUD_TOKEN:-}" ]; then
  echo "HCLOUD_TOKEN is required" >&2
  exit 1
fi

name="$1"

url="https://api.hetzner.cloud/v1/volumes?name=${name}"
delay=2
response=""
for attempt in {1..6}; do
  tmp=$(mktemp)
  code=$(curl -sS -o "$tmp" -w "%{http_code}" -H "Authorization: Bearer ${HCLOUD_TOKEN}" "$url" || true)
  if [ "$code" = "200" ]; then
    response=$(cat "$tmp")
    rm -f "$tmp"
    break
  fi

  if [ "$code" = "429" ]; then
    rm -f "$tmp"
    echo "Hetzner API rate limited (429). Retry ${attempt}/6 in ${delay}s..." >&2
    sleep "$delay"
    delay=$((delay * 2))
    continue
  fi

  echo "Hetzner API request failed (http ${code:-unknown})" >&2
  cat "$tmp" >&2 || true
  rm -f "$tmp"
  exit 1
done

volume_id=$(echo "$response" | jq -r '.volumes[0].id // empty')

if [ -n "$volume_id" ]; then
  echo "$volume_id"
fi
