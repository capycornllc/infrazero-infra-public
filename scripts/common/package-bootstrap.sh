#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: scripts/common/package-bootstrap.sh --manifest <path> <role...>

Environment:
  BOOTSTRAP_DIR                  Provider bootstrap directory, e.g. bootstrap/hetzner.
  S3_ENDPOINT                    Object storage endpoint.
  INFRA_STATE_BUCKET             Object storage bucket for bootstrap artifacts.
  BOOTSTRAP_PRESIGN_EXPIRY       Presigned URL lifetime in seconds.

Optional environment:
  BOOTSTRAP_PROVIDER             Provider name for adapter selection,
                                 default: basename of BOOTSTRAP_DIR.
  BOOTSTRAP_PROVIDERS_DIR        Providers directory, default bootstrap/providers.

Optional test-only environment:
  BOOTSTRAP_COMMON_DIR           Common bootstrap directory, default bootstrap/common.
  BOOTSTRAP_OUTPUT_DIR           Output directory, default build/bootstrap.
  PACKAGE_BOOTSTRAP_SKIP_UPLOAD  If true, do not call aws; write file:// URLs.
  PACKAGE_BOOTSTRAP_COMPRESSION  zstd (default) or none.
EOF
}

manifest_path=""
if [ "${1:-}" = "--manifest" ]; then
  manifest_path="${2:-}"
  shift 2
fi

if [ -z "$manifest_path" ] || [ "$#" -lt 1 ]; then
  usage
  exit 2
fi

: "${BOOTSTRAP_DIR:?BOOTSTRAP_DIR is required}"

repo_root="$(pwd -P)"
provider_dir="${repo_root}/${BOOTSTRAP_DIR}"
common_dir="${repo_root}/${BOOTSTRAP_COMMON_DIR:-bootstrap/common}"
bootstrap_provider="${BOOTSTRAP_PROVIDER:-$(basename "$BOOTSTRAP_DIR")}"
providers_root="${repo_root}/${BOOTSTRAP_PROVIDERS_DIR:-bootstrap/providers}"
adapter_dir="${providers_root}/${bootstrap_provider}"
output_dir="${BOOTSTRAP_OUTPUT_DIR:-build/bootstrap}"
skip_upload="${PACKAGE_BOOTSTRAP_SKIP_UPLOAD:-false}"
compression="${PACKAGE_BOOTSTRAP_COMPRESSION:-zstd}"

if [ ! -d "$provider_dir" ]; then
  echo "[package-bootstrap] provider bootstrap directory not found: ${BOOTSTRAP_DIR}" >&2
  exit 1
fi

if [ ! -d "$common_dir" ]; then
  echo "[package-bootstrap] common bootstrap directory not found: ${common_dir}" >&2
  exit 1
fi

if [ ! -f "${adapter_dir}/adapter.sh" ]; then
  echo "[package-bootstrap] provider adapter not found: ${adapter_dir}/adapter.sh (BOOTSTRAP_PROVIDER=${bootstrap_provider})" >&2
  exit 1
fi

if [ "$skip_upload" != "true" ]; then
  : "${S3_ENDPOINT:?S3_ENDPOINT is required}"
  : "${INFRA_STATE_BUCKET:?INFRA_STATE_BUCKET is required}"
  : "${BOOTSTRAP_PRESIGN_EXPIRY:?BOOTSTRAP_PRESIGN_EXPIRY is required}"
fi

case "$compression" in
  zstd) tar_compression_args=(--zstd) ;;
  none) tar_compression_args=() ;;
  *)
    echo "[package-bootstrap] unsupported PACKAGE_BOOTSTRAP_COMPRESSION: ${compression}" >&2
    exit 2
    ;;
esac

mkdir -p "$output_dir"
chmod +x "${provider_dir}"/*.sh
chmod +x "${common_dir}"/*.sh
chmod +x "${adapter_dir}/adapter.sh"

roles=("$@")

package_role() {
  local role="$1"
  local archive="${output_dir}/${role}.tar.zst"
  local role_script="${provider_dir}/${role}.sh"
  local extra_files=()
  local sha url

  for required in "${provider_dir}/common.sh" "${provider_dir}/beacon.sh" "$role_script" "${common_dir}/common-beacon.sh" "${common_dir}/common-beacon-fallback.sh" "${common_dir}/common-base.sh" "${common_dir}/common-system.sh"; do
    if [ ! -f "$required" ]; then
      echo "[package-bootstrap] required file missing for role ${role}: ${required}" >&2
      exit 1
    fi
  done

  extra_files=(-C "$common_dir" common-beacon.sh common-beacon-fallback.sh common-base.sh common-system.sh -C "$adapter_dir" adapter.sh)

  if [ "$role" = "egress" ]; then
    if [ ! -f "${provider_dir}/infisical-bootstrap.sh" ] || [ ! -f "${common_dir}/common-infisical-bootstrap.sh" ] || [ ! -f "${common_dir}/common-egress.sh" ]; then
      echo "[package-bootstrap] egress role requires infisical-bootstrap.sh, common-infisical-bootstrap.sh, and common-egress.sh" >&2
      exit 1
    fi
    if [ ! -f "${common_dir}/common-egress-main.sh" ]; then
      echo "[package-bootstrap] egress role requires common-egress-main.sh" >&2
      exit 1
    fi
    extra_files+=(-C "$provider_dir" infisical-bootstrap.sh -C "$common_dir" common-infisical-bootstrap.sh common-egress.sh common-egress-main.sh)
  fi

  if [ "$role" = "node1" ]; then
    if [ ! -f "${common_dir}/common-node1.sh" ] || [ ! -f "${provider_dir}/infisical-admin-secret.sh" ] || [ ! -f "${common_dir}/common-infisical-admin-secret.sh" ]; then
      echo "[package-bootstrap] node1 role requires common-node1.sh, infisical-admin-secret.sh, and common-infisical-admin-secret.sh" >&2
      exit 1
    fi
    extra_files+=(-C "$common_dir" common-node1.sh -C "$provider_dir" infisical-admin-secret.sh -C "$common_dir" common-infisical-admin-secret.sh)
  fi

  if [ "$role" = "node2" ]; then
    if [ ! -f "${common_dir}/common-node-agent.sh" ]; then
      echo "[package-bootstrap] node2 role requires common-node-agent.sh" >&2
      exit 1
    fi
    extra_files+=(-C "$common_dir" common-node-agent.sh)
  fi

  if [ "$role" = "nodecp" ]; then
    if [ ! -f "${common_dir}/common-nodecp.sh" ]; then
      echo "[package-bootstrap] nodecp role requires common-nodecp.sh" >&2
      exit 1
    fi
    extra_files+=(-C "$common_dir" common-nodecp.sh)
  fi

  if [ "$role" = "db" ] || [ "$role" = "db-replica" ]; then
    if [ ! -f "${common_dir}/db-patroni.sh" ]; then
      echo "[package-bootstrap] ${role} role requires db-patroni.sh" >&2
      exit 1
    fi
    extra_files+=(-C "$common_dir" db-patroni.sh)
  fi

  if [ "$role" = "bastion" ]; then
    if [ ! -f "${common_dir}/common-bastion.sh" ]; then
      echo "[package-bootstrap] bastion role requires common-bastion.sh" >&2
      exit 1
    fi
    extra_files+=(-C "$common_dir" common-bastion.sh)
  fi

  if [ "$role" = "db" ]; then
    if [ ! -f "${common_dir}/common-db.sh" ]; then
      echo "[package-bootstrap] db role requires common-db.sh" >&2
      exit 1
    fi
    extra_files+=(-C "$common_dir" common-db.sh)
  fi

  if [ "$role" = "db-replica" ]; then
    if [ ! -f "${common_dir}/common-db-replica.sh" ]; then
      echo "[package-bootstrap] db-replica role requires common-db-replica.sh" >&2
      exit 1
    fi
    extra_files+=(-C "$common_dir" common-db-replica.sh)
  fi

  if [ "$role" = "pgbouncer" ]; then
    if [ ! -f "${common_dir}/common-pgbouncer.sh" ]; then
      echo "[package-bootstrap] pgbouncer role requires common-pgbouncer.sh" >&2
      exit 1
    fi
    extra_files+=(-C "$common_dir" common-pgbouncer.sh)
  fi

  echo "[package-bootstrap] packaging ${role}"
  tar "${tar_compression_args[@]}" -cf "$archive" \
    -C "$provider_dir" common.sh beacon.sh "${role}.sh" \
    "${extra_files[@]}"

  sha=$(sha256sum "$archive" | awk '{print $1}')
  echo "$sha" > "${output_dir}/${role}.sha256"

  if [ "$skip_upload" = "true" ]; then
    url="file://${archive}"
  else
    aws --endpoint-url "$S3_ENDPOINT" s3 cp "$archive" "s3://${INFRA_STATE_BUCKET}/bootstrap/${role}.tar.zst"
    url=$(aws --endpoint-url "$S3_ENDPOINT" s3 presign "s3://${INFRA_STATE_BUCKET}/bootstrap/${role}.tar.zst" --expires-in "$BOOTSTRAP_PRESIGN_EXPIRY")
  fi
  echo "$url" > "${output_dir}/${role}.url"
}

for role in "${roles[@]}"; do
  package_role "$role"
done

json_escape() {
  printf '%s' "${1:-}" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

manifest='{'
manifest_first=true
for role in "${roles[@]}"; do
  sha=$(cat "${output_dir}/${role}.sha256")
  url=$(cat "${output_dir}/${role}.url")
  if [ "$manifest_first" = "true" ]; then
    manifest_first=false
  else
    manifest="${manifest},"
  fi
  manifest="${manifest}\"$(json_escape "$role")\":{\"url\":\"$(json_escape "$url")\",\"sha256\":\"$(json_escape "$sha")\"}"
done
manifest="${manifest}}"

mkdir -p "$(dirname "$manifest_path")"
printf '%s\n' "$manifest" > "$manifest_path"
