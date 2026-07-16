#!/usr/bin/env bash
# OVHcloud-only mapping from GitHub secrets to OpenTofu variables.
set -euo pipefail
set +x

if [ "${1:-}" = "--list-secret-names" ]; then
  printf '%s\n' \
    ovh_application_key \
    ovh_application_secret \
    ovh_consumer_key \
    ovh_cloud_project_id \
    openstack_user_name \
    openstack_password \
    openstack_tenant_id
  exit 0
fi

repo_root="${INFRAZERO_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
python "${repo_root}/scripts/common/export-provider-secrets.py" \
  --required ovh_application_key \
  --required ovh_application_secret \
  --required ovh_consumer_key \
  --required ovh_cloud_project_id \
  --required openstack_user_name \
  --required openstack_password \
  --map TF_VAR_ovh_application_key=ovh_application_key \
  --map TF_VAR_ovh_application_secret=ovh_application_secret \
  --map TF_VAR_ovh_consumer_key=ovh_consumer_key \
  --map TF_VAR_ovh_cloud_project_id=ovh_cloud_project_id \
  --map TF_VAR_openstack_user_name=openstack_user_name \
  --map TF_VAR_openstack_password=openstack_password \
  --map TF_VAR_openstack_tenant_id=openstack_tenant_id,ovh_cloud_project_id

region_lower="$(printf '%s' "${CLOUD_REGION:-}" | tr '[:upper:]' '[:lower:]')"
if [[ "$region_lower" == us-* ]]; then
  auth_url="https://auth.cloud.ovh.us/v3"
  endpoint="ovh-us"
else
  auth_url="https://auth.cloud.ovh.net/v3"
  endpoint="ovh-eu"
fi

{
  echo "TF_VAR_openstack_auth_url=${auth_url}"
  echo "TF_VAR_ovh_endpoint=${endpoint}"
} >> "${GITHUB_ENV:?GITHUB_ENV is required}"

if [ -z "${PGBOUNCER_SERVER_TYPE:-}" ]; then
  echo "PGBOUNCER_SERVER_TYPE=b2-7" >> "$GITHUB_ENV"
fi
