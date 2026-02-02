#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/infrazero-bootstrap.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[infisical-admin-secret] $(date -Is) start"

LOCK_FILE="/var/lock/infisical-admin-secret.lock"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[infisical-admin-secret] another instance is running; exiting"
  exit 0
fi

load_env() {
  local file="$1"
  if [ -f "$file" ]; then
    set -a
    # shellcheck disable=SC1090
    source "$file"
    set +a
  fi
}

load_env /etc/infrazero/node.env
load_env /etc/infrazero/node1.env

if [ -z "${KUBECONFIG:-}" ] && [ -f /etc/rancher/k3s/k3s.yaml ]; then
  export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
fi

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[infisical-admin-secret] missing required env: $name" >&2
    exit 1
  fi
}

INFISICAL_FQDN="${INFISICAL_FQDN:-}"
INFISICAL_SITE_URL="${INFISICAL_SITE_URL:-}"
if [ -z "$INFISICAL_SITE_URL" ] && [ -n "$INFISICAL_FQDN" ]; then
  INFISICAL_SITE_URL="https://${INFISICAL_FQDN}"
fi

require_env "INFISICAL_SITE_URL"
require_env "INFISICAL_ORGANIZATION"
require_env "INFISICAL_PROJECT_NAME"
require_env "S3_ACCESS_KEY_ID"
require_env "S3_SECRET_ACCESS_KEY"
require_env "S3_ENDPOINT"
require_env "S3_REGION"
require_env "DB_BACKUP_BUCKET"
require_env "DB_BACKUP_AGE_PRIVATE_KEY"

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y curl ca-certificates jq age unzip
fi

if ! command -v aws >/dev/null 2>&1; then
  if curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip; then
    unzip -q /tmp/awscliv2.zip -d /tmp
    /tmp/aws/install --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli --update
  fi
fi

if ! command -v aws >/dev/null 2>&1; then
  echo "[infisical-admin-secret] aws cli not available; cannot continue" >&2
  exit 1
fi

export AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$S3_SECRET_ACCESS_KEY"
export AWS_DEFAULT_REGION="$S3_REGION"

if [[ "$S3_ENDPOINT" != http://* && "$S3_ENDPOINT" != https://* ]]; then
  S3_ENDPOINT="https://${S3_ENDPOINT}"
fi

tokens_manifest_key="infisical/bootstrap/latest-tokens.json"

workdir=$(mktemp -d /run/infisical-admin-secret.XXXX)
chmod 700 "$workdir"

echo "$DB_BACKUP_AGE_PRIVATE_KEY" > "$workdir/age.key"
chmod 600 "$workdir/age.key"

if ! aws --endpoint-url "$S3_ENDPOINT" s3 cp "s3://${DB_BACKUP_BUCKET}/${tokens_manifest_key}" "$workdir/latest-tokens.json" >/dev/null 2>&1; then
  echo "[infisical-admin-secret] latest tokens manifest not found" >&2
  rm -f "$workdir/age.key"
  rm -rf "$workdir"
  exit 1
fi

admin_key=$(jq -r '.admin_token_key // empty' "$workdir/latest-tokens.json")
admin_sha=$(jq -r '.admin_token_sha256 // empty' "$workdir/latest-tokens.json")
if [ -z "$admin_key" ] || [ "$admin_key" = "null" ]; then
  echo "[infisical-admin-secret] tokens manifest missing admin_token_key" >&2
  rm -f "$workdir/age.key"
  rm -rf "$workdir"
  exit 1
fi

aws --endpoint-url "$S3_ENDPOINT" s3 cp "s3://${DB_BACKUP_BUCKET}/${admin_key}" "$workdir/admin.token.age"
if [ -n "$admin_sha" ] && [ "$admin_sha" != "null" ]; then
  echo "$admin_sha  $workdir/admin.token.age" | sha256sum -c -
fi

age -d -i "$workdir/age.key" -o "$workdir/admin.token" "$workdir/admin.token.age"
ADMIN_TOKEN=$(cat "$workdir/admin.token")
if [ -z "$ADMIN_TOKEN" ]; then
  echo "[infisical-admin-secret] decrypted admin token is empty" >&2
  rm -f "$workdir/age.key"
  rm -rf "$workdir"
  exit 1
fi

kubectl get namespace kube-system >/dev/null 2>&1 || kubectl create namespace kube-system
kubectl -n kube-system create secret generic infisical-admin-token \
  --from-literal=token="$ADMIN_TOKEN" \
  --from-literal=host="$INFISICAL_SITE_URL" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n kube-system create secret generic infisical-organization \
  --from-literal=infisical_organization="$INFISICAL_ORGANIZATION" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n kube-system create secret generic infisical-project-name \
  --from-literal=infisical_project_name="$INFISICAL_PROJECT_NAME" \
  --dry-run=client -o yaml | kubectl apply -f -

rm -f "$workdir/age.key" "$workdir/admin.token" "$workdir/admin.token.age" "$workdir/latest-tokens.json"
rm -rf "$workdir"
unset DB_BACKUP_AGE_PRIVATE_KEY

echo "[infisical-admin-secret] $(date -Is) complete"
