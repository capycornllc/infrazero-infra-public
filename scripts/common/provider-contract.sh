#!/usr/bin/env bash
# Shared validation contract for a fully implemented cloud provider.

infrazero_provider_required_paths() {
  local provider="$1"
  printf '%s\n' \
    "bootstrap/providers/${provider}/adapter.sh" \
    "bootstrap/${provider}" \
    "tofu/${provider}" \
    "scripts/${provider}/ci-credentials.sh" \
    "scripts/${provider}/tofu-resources.sh" \
    "scripts/${provider}/destroy-without-volume.sh" \
    "scripts/${provider}/import-volume.sh" \
    "scripts/${provider}/import-ssh-keys.py"
}

infrazero_validate_provider_contract() {
  local repo_root="$1" provider="$2" path
  local missing=0

  if [[ ! "$provider" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
    echo "[provider-contract] invalid provider directory '${provider}'" >&2
    return 2
  fi

  while IFS= read -r path; do
    if [ ! -e "${repo_root}/${path}" ]; then
      echo "[provider-contract] missing: ${path}" >&2
      missing=1
    fi
  done < <(infrazero_provider_required_paths "$provider")

  return "$missing"
}
