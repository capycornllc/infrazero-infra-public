#!/usr/bin/env bash
# Provider compatibility entrypoint for shared bootstrap beacon helpers.

_infrazero_beacon_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${_infrazero_beacon_dir}/common-beacon.sh" ]; then
  # shellcheck disable=SC1091
  . "${_infrazero_beacon_dir}/common-beacon.sh"
elif [ -f "${_infrazero_beacon_dir}/../common/common-beacon.sh" ]; then
  # shellcheck disable=SC1091
  . "${_infrazero_beacon_dir}/../common/common-beacon.sh"
elif [ -f "${_infrazero_beacon_dir}/common-beacon-fallback.sh" ]; then
  # shellcheck disable=SC1091
  . "${_infrazero_beacon_dir}/common-beacon-fallback.sh"
elif [ -f "${_infrazero_beacon_dir}/../common/common-beacon-fallback.sh" ]; then
  # shellcheck disable=SC1091
  . "${_infrazero_beacon_dir}/../common/common-beacon-fallback.sh"
else
  # Last resort: keep bootstrap alive without status reporting.
  beacon_status() { return 0; }
  beacon_retrying() { return 0; }
  beacon_degraded() { return 0; }
  beacon_failed() { return 0; }
fi
unset _infrazero_beacon_dir
