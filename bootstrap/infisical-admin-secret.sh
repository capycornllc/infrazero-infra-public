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

require_env "KUBERNETES_FQDN"
require_env "INFISICAL_FQDN"
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
  apt-get install -y curl ca-certificates jq age unzip git
fi

wait_for_url() {
  local url="$1"
  echo "[infisical-admin-secret] waiting for $url"
  for _ in {1..60}; do
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 "$url" || true)
    case "$code" in
      200|301|302|401|403|404)
        return 0
        ;;
      502|503|504|000|"")
        ;;
      *)
        return 0
        ;;
    esac
    sleep 5
  done
  return 1
}

wait_for_url "https://${INFISICAL_FQDN}" || {
  echo "[infisical-admin-secret] infisical_fqdn not ready (still returning 5xx/000)" >&2
  exit 1
}

wait_for_manifest() {
  local key="$1"
  echo "[infisical-admin-secret] waiting for s3://${DB_BACKUP_BUCKET}/${key}"
  for _ in {1..60}; do
    if aws --endpoint-url "$S3_ENDPOINT" s3 ls "s3://${DB_BACKUP_BUCKET}/${key}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 5
  done
  return 1
}

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

wait_for_manifest "$tokens_manifest_key" || {
  echo "[infisical-admin-secret] latest tokens manifest not found after waiting" >&2
  rm -rf "$workdir"
  exit 1
}

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
  --from-literal=value="$INFISICAL_ORGANIZATION" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n kube-system create secret generic infisical-project-name \
  --from-literal=infisical_project_name="$INFISICAL_PROJECT_NAME" \
  --from-literal=value="$INFISICAL_PROJECT_NAME" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl get namespace infisical-bootstrap >/dev/null 2>&1 || kubectl create namespace infisical-bootstrap
kubectl -n infisical-bootstrap create secret generic infisical-admin-token \
  --from-literal=token="$ADMIN_TOKEN" \
  --from-literal=host="$INFISICAL_SITE_URL" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n infisical-bootstrap create secret generic infisical-organization \
  --from-literal=infisical_organization="$INFISICAL_ORGANIZATION" \
  --from-literal=value="$INFISICAL_ORGANIZATION" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n infisical-bootstrap create secret generic infisical-project-name \
  --from-literal=infisical_project_name="$INFISICAL_PROJECT_NAME" \
  --from-literal=value="$INFISICAL_PROJECT_NAME" \
  --dry-run=client -o yaml | kubectl apply -f -

ENVIRONMENT="${ENVIRONMENT:-${ENV:-}}"
if [ -z "$ENVIRONMENT" ]; then
  echo "[infisical-admin-secret] missing required env: ENVIRONMENT" >&2
  exit 1
fi
ENV="$ENVIRONMENT"
INFISICAL_ENV_SLUG="${INFISICAL_ENV_SLUG:-$ENV}"
if [ -z "$INFISICAL_ENV_SLUG" ]; then
  echo "[infisical-admin-secret] unable to determine Infisical env slug" >&2
  exit 1
fi

export INFISICAL_KUBERNETES_HOST="https://${KUBERNETES_FQDN}"
echo "[infisical-admin-secret] using INFISICAL_KUBERNETES_HOST=${INFISICAL_KUBERNETES_HOST}"

GITOPS_DIR="${GITOPS_DIR:-/opt/infrazero/gitops}"

ensure_gitops_repo() {
  if [ -d "$GITOPS_DIR/.git" ]; then
    return 0
  fi
  if [ -d "$GITOPS_DIR" ]; then
    echo "[infisical-admin-secret] ${GITOPS_DIR} exists but is not a git repo" >&2
    exit 1
  fi
  require_env "ARGOCD_APP_REPO_URL"
  require_env "GH_TOKEN"
  local auth_header
  auth_header=$(printf 'x-access-token:%s' "$GH_TOKEN" | base64 | tr -d '\n')
  git -c http.extraheader="AUTHORIZATION: basic ${auth_header}" clone "$ARGOCD_APP_REPO_URL" "$GITOPS_DIR"
}

ensure_gitops_repo

bootstrap_kustomize_dir="${GITOPS_DIR}/clusters/${ENV}/bootstrap/infisical-k8s-auth"
if [ ! -d "$bootstrap_kustomize_dir" ]; then
  echo "[infisical-admin-secret] missing gitops bootstrap dir: ${bootstrap_kustomize_dir}" >&2
  exit 1
fi

job_succeeded="false"
if kubectl -n infisical-bootstrap get job infisical-k8s-auth-bootstrap >/dev/null 2>&1; then
  job_success_count=$(kubectl -n infisical-bootstrap get job infisical-k8s-auth-bootstrap -o jsonpath='{.status.succeeded}' 2>/dev/null || true)
  if [ -n "$job_success_count" ] && [ "$job_success_count" != "0" ]; then
    job_succeeded="true"
  fi
  job_failed_count=$(kubectl -n infisical-bootstrap get job infisical-k8s-auth-bootstrap -o jsonpath='{.status.failed}' 2>/dev/null || true)
  if [ "$job_succeeded" != "true" ] && [ -n "$job_failed_count" ] && [ "$job_failed_count" != "0" ]; then
    echo "[infisical-admin-secret] infisical-k8s-auth-bootstrap failed; dumping logs" >&2
    kubectl -n infisical-bootstrap logs job/infisical-k8s-auth-bootstrap --all-containers --tail=200 || true
    exit 1
  fi
fi

if [ "$job_succeeded" != "true" ]; then
  echo "[infisical-admin-secret] applying infisical k8s auth bootstrap job"
  kubectl apply -k "$bootstrap_kustomize_dir"
  if ! kubectl -n infisical-bootstrap wait --for=condition=complete job/infisical-k8s-auth-bootstrap --timeout=10m; then
    echo "[infisical-admin-secret] infisical-k8s-auth-bootstrap did not complete; dumping logs" >&2
    kubectl -n infisical-bootstrap logs job/infisical-k8s-auth-bootstrap --all-containers --tail=200 || true
    kubectl -n infisical-bootstrap get pods -o wide || true
    exit 1
  fi
fi

IDENTITY_ID=$(kubectl -n kube-system get secret infisical-bootstrap-result -o jsonpath='{.data.identityId}' | base64 -d)
PROJECT_ID=$(kubectl -n kube-system get secret infisical-bootstrap-result -o jsonpath='{.data.projectId}' | base64 -d)
if [ -z "$IDENTITY_ID" ] || [ -z "$PROJECT_ID" ]; then
  echo "[infisical-admin-secret] infisical-bootstrap-result missing identityId/projectId" >&2
  exit 1
fi

INFISICAL_HOST=$(kubectl -n kube-system get secret infisical-admin-token -o jsonpath='{.data.host}' | base64 -d)
if [ -z "$INFISICAL_HOST" ]; then
  echo "[infisical-admin-secret] infisical-admin-token host is empty" >&2
  exit 1
fi

overlay_dir="${GITOPS_DIR}/overlays/infisical"
overlay_kustomization="${overlay_dir}/kustomization.yaml"
patch_file="${overlay_dir}/secretproviderclass-patch.yaml"
spc_file="${GITOPS_DIR}/platform/infisical/secretproviderclass.yaml"

if [ ! -f "$spc_file" ]; then
  echo "[infisical-admin-secret] missing ${spc_file}; cannot patch SecretProviderClass" >&2
  exit 1
fi

spc_name=$(awk '
  $1 == "metadata:" {in_meta=1; next}
  in_meta && $1 == "name:" {print $2; exit}
  in_meta && $1 ~ /^[a-zA-Z0-9_.-]+:$/ && $0 ~ /^[^[:space:]]/ {exit}
' "$spc_file")

if [ -z "$spc_name" ]; then
  echo "[infisical-admin-secret] unable to determine SecretProviderClass name" >&2
  exit 1
fi

spc_namespace=$(awk '
  $1 == "metadata:" {in_meta=1; next}
  in_meta && $1 == "namespace:" {print $2; exit}
  in_meta && $1 ~ /^[a-zA-Z0-9_.-]+:$/ && $0 ~ /^[^[:space:]]/ {exit}
' "$spc_file")

ca_cert=""
if [ -n "${INFISICAL_CA_CERT_B64:-}" ]; then
  ca_cert=$(printf '%s' "$INFISICAL_CA_CERT_B64" | base64 -d)
elif [ -n "${INFISICAL_CA_CERT_PATH:-}" ] && [ -f "$INFISICAL_CA_CERT_PATH" ]; then
  ca_cert=$(cat "$INFISICAL_CA_CERT_PATH")
fi

mkdir -p "$overlay_dir"
cat > "$patch_file" <<EOF
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: ${spc_name}
EOF
if [ -n "$spc_namespace" ]; then
  printf '  namespace: %s\n' "$spc_namespace" >> "$patch_file"
fi
cat >> "$patch_file" <<EOF
spec:
  parameters:
    infisicalUrl: "${INFISICAL_HOST}"
    identityId: "${IDENTITY_ID}"
    projectId: "${PROJECT_ID}"
    envSlug: "${INFISICAL_ENV_SLUG}"
    useDefaultAudience: "false"
EOF

if [ -n "$ca_cert" ]; then
  {
    echo "    caCertificate: |"
    while IFS= read -r line; do
      echo "      ${line}"
    done <<< "$ca_cert"
  } >> "$patch_file"
fi

ensure_kustomization_entry() {
  local file="$1"
  local header="$2"
  local entry="$3"
  if grep -q "^${header}$" "$file"; then
    if grep -qF "$entry" "$file"; then
      return 0
    fi
    awk -v header="$header" -v entry="$entry" '
      $0 == header {print; print entry; next}
      {print}
    ' "$file" > "${file}.tmp"
    mv "${file}.tmp" "$file"
    return 0
  fi
  printf '\n%s\n%s\n' "$header" "$entry" >> "$file"
}

if [ ! -f "$overlay_kustomization" ]; then
  cat > "$overlay_kustomization" <<'EOF'
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../platform/infisical
patchesStrategicMerge:
  - secretproviderclass-patch.yaml
EOF
else
  ensure_kustomization_entry "$overlay_kustomization" "resources:" "  - ../../platform/infisical"
  if ! grep -qF "secretproviderclass-patch.yaml" "$overlay_kustomization"; then
    if grep -q "^patchesStrategicMerge:" "$overlay_kustomization"; then
      ensure_kustomization_entry "$overlay_kustomization" "patchesStrategicMerge:" "  - secretproviderclass-patch.yaml"
    elif grep -q "^patches:" "$overlay_kustomization"; then
      ensure_kustomization_entry "$overlay_kustomization" "patches:" "  - path: secretproviderclass-patch.yaml"
    else
      printf '\npatchesStrategicMerge:\n  - secretproviderclass-patch.yaml\n' >> "$overlay_kustomization"
    fi
  fi
fi

sync_resources=()
if [ -n "${INFISICAL_SECRET_SYNCS_JSON:-}" ]; then
  if ! echo "$INFISICAL_SECRET_SYNCS_JSON" | jq -e 'type=="array"' >/dev/null 2>&1; then
    echo "[infisical-admin-secret] INFISICAL_SECRET_SYNCS_JSON must be a JSON array" >&2
    exit 1
  fi
  mapfile -t sync_items < <(echo "$INFISICAL_SECRET_SYNCS_JSON" | jq -c '.[]')
  for sync_item in "${sync_items[@]}"; do
    sync_name=$(echo "$sync_item" | jq -r '.name // empty')
    sync_namespace=$(echo "$sync_item" | jq -r '.namespace // "default"')
    sync_secret_path=$(echo "$sync_item" | jq -r '.secretPath // .path // "/"')
    sync_target_secret=$(echo "$sync_item" | jq -r '.secretName // empty')
    sync_sa_name=$(echo "$sync_item" | jq -r '.serviceAccountRef.name // .serviceAccountName // empty')
    sync_sa_namespace=$(echo "$sync_item" | jq -r '.serviceAccountRef.namespace // .serviceAccountNamespace // empty')
    if [ -z "$sync_sa_namespace" ]; then
      sync_sa_namespace="$sync_namespace"
    fi
    sync_env_slug=$(echo "$sync_item" | jq -r '.environment // empty')
    if [ -z "$sync_env_slug" ]; then
      sync_env_slug="$INFISICAL_ENV_SLUG"
    fi
    if [ -z "$sync_name" ] || [ -z "$sync_target_secret" ] || [ -z "$sync_sa_name" ]; then
      echo "[infisical-admin-secret] invalid sync entry in INFISICAL_SECRET_SYNCS_JSON" >&2
      exit 1
    fi

    sync_resource_name=$(echo "$sync_name" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9-]+/-/g; s/^-+|-+$//g')
    if [ -z "$sync_resource_name" ]; then
      echo "[infisical-admin-secret] invalid sync name for InfisicalSecret" >&2
      exit 1
    fi

    sync_file="infisicalsecret-${sync_resource_name}.yaml"
    sync_path="${overlay_dir}/${sync_file}"
    cat > "$sync_path" <<EOF
apiVersion: secrets.infisical.com/v1alpha1
kind: InfisicalSecret
metadata:
  name: ${sync_resource_name}
  namespace: ${sync_namespace}
spec:
  hostAPI: ${INFISICAL_HOST}
  identityId: ${IDENTITY_ID}
  projectId: ${PROJECT_ID}
  environment: ${sync_env_slug}
  secretPath: ${sync_secret_path}
  secretName: ${sync_target_secret}
  serviceAccountRef:
    name: ${sync_sa_name}
    namespace: ${sync_sa_namespace}
EOF
    sync_resources+=("$sync_file")
  done
fi

if [ "${#sync_resources[@]}" -gt 0 ]; then
  for resource in "${sync_resources[@]}"; do
    if ! grep -qF "$resource" "$overlay_kustomization"; then
      ensure_kustomization_entry "$overlay_kustomization" "resources:" "  - ${resource}"
    fi
  done
fi

git -C "$GITOPS_DIR" config user.email "infrazero-bootstrap@local"
git -C "$GITOPS_DIR" config user.name "infrazero-bootstrap"
git -C "$GITOPS_DIR" add "$overlay_dir"
if ! git -C "$GITOPS_DIR" diff --cached --quiet; then
  git -C "$GITOPS_DIR" commit -m "Configure Infisical k8s auth overlay"
else
  echo "[infisical-admin-secret] gitops overlay already up to date"
fi

rm -f "$workdir/age.key" "$workdir/admin.token" "$workdir/admin.token.age" "$workdir/latest-tokens.json"
rm -rf "$workdir"
unset DB_BACKUP_AGE_PRIVATE_KEY

echo "[infisical-admin-secret] $(date -Is) complete"
