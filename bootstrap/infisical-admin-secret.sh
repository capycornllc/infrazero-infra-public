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
  apt-get install -y curl ca-certificates jq age unzip git python3-yaml
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

KUBERNETES_API_PORT="${KUBERNETES_API_PORT:-6443}"
if [[ "$KUBERNETES_FQDN" == *:* ]]; then
  INFISICAL_KUBERNETES_HOST="https://${KUBERNETES_FQDN}"
else
  INFISICAL_KUBERNETES_HOST="https://${KUBERNETES_FQDN}:${KUBERNETES_API_PORT}"
fi
export INFISICAL_KUBERNETES_HOST
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

git_sync_repo() {
  if [ -z "${GH_TOKEN:-}" ]; then
    return 0
  fi
  if ! git -C "$GITOPS_DIR" diff --quiet || ! git -C "$GITOPS_DIR" diff --cached --quiet; then
    echo "[infisical-admin-secret] gitops repo has local changes; skipping pre-sync" >&2
    return 0
  fi
  local auth_header
  auth_header=$(printf 'x-access-token:%s' "$GH_TOKEN" | base64 | tr -d '\n')
  local branch
  branch=$(git -C "$GITOPS_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
  if [ -z "$branch" ] || [ "$branch" = "HEAD" ]; then
    branch="main"
  fi
  if ! git -C "$GITOPS_DIR" -c http.extraheader="AUTHORIZATION: basic ${auth_header}" fetch origin "$branch"; then
    echo "[infisical-admin-secret] git fetch failed; continuing without pre-sync" >&2
    return 0
  fi
  if ! git -C "$GITOPS_DIR" rebase -X theirs "origin/${branch}"; then
    git -C "$GITOPS_DIR" rebase --abort || true
    echo "[infisical-admin-secret] git rebase failed; continuing without pre-sync" >&2
    return 0
  fi
}

git_sync_repo

git_push_changes() {
  if [ -z "${GH_TOKEN:-}" ]; then
    echo "[infisical-admin-secret] GH_TOKEN missing; skipping git push" >&2
    return 1
  fi
  local auth_header
  auth_header=$(printf 'x-access-token:%s' "$GH_TOKEN" | base64 | tr -d '\n')
  local branch
  branch=$(git -C "$GITOPS_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
  if [ -z "$branch" ] || [ "$branch" = "HEAD" ]; then
    branch="main"
  fi
  if ! git -C "$GITOPS_DIR" -c http.extraheader="AUTHORIZATION: basic ${auth_header}" fetch origin "$branch"; then
    echo "[infisical-admin-secret] git fetch failed; please push manually" >&2
    return 1
  fi
  if ! git -C "$GITOPS_DIR" rebase -X theirs "origin/${branch}"; then
    git -C "$GITOPS_DIR" rebase --abort || true
    echo "[infisical-admin-secret] git rebase failed; please resolve and push manually" >&2
    return 1
  fi
  if ! git -C "$GITOPS_DIR" -c http.extraheader="AUTHORIZATION: basic ${auth_header}" push origin "HEAD:${branch}"; then
    echo "[infisical-admin-secret] git push failed; please push manually" >&2
    return 1
  fi
  return 0
}

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

cluster_root="${GITOPS_DIR}/clusters/${ENV}"
cluster_patch_file="${cluster_root}/infisical-secretproviderclass-patch.yaml"
sync_overlay_dir="${cluster_root}/overlays/infisical"

find_spc_file() {
  local search_root="$1"
  local candidate
  if [ ! -d "$search_root" ]; then
    return 1
  fi
  while IFS= read -r candidate; do
    if grep -qE '^kind:\s*SecretProviderClass' "$candidate" && grep -qi 'infisical' "$candidate"; then
      echo "$candidate"
      return 0
    fi
  done < <(find "$search_root" -type f \( -name "*.yaml" -o -name "*.yml" \) 2>/dev/null)
  return 1
}

spc_file="$(find_spc_file "$cluster_root" || true)"
if [ -z "$spc_file" ]; then
  spc_file="$(find_spc_file "$GITOPS_DIR" || true)"
fi

if [ -z "$spc_file" ] || [ ! -f "$spc_file" ]; then
  echo "[infisical-admin-secret] unable to locate SecretProviderClass manifest to patch" >&2
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

spc_namespace_base="$spc_namespace"
spc_namespace_override="${INFISICAL_SPC_NAMESPACE:-}"
if [ -n "$spc_namespace_override" ]; then
  spc_namespace_target="$spc_namespace_override"
elif [ -z "$spc_namespace_base" ] || [ "$spc_namespace_base" = "example" ]; then
  spc_namespace_target="default"
else
  spc_namespace_target="$spc_namespace_base"
fi

spc_app_file=""
if [ -d "$cluster_root" ]; then
  spc_app_file=$(find "$cluster_root" -type f -path "*/applications/*" \( -name "*infisical*secretproviderclass*.y*ml" -o -name "*secretproviderclass*.y*ml" \) 2>/dev/null | head -n1 || true)
  if [ -n "$spc_app_file" ] && ! grep -qE '^kind:\s*Application' "$spc_app_file"; then
    spc_app_file=""
  fi
fi

app_config_file=""
if [ -f "${GITOPS_DIR}/config/app-config.yaml" ]; then
  app_config_file="${GITOPS_DIR}/config/app-config.yaml"
else
  app_config_file=$(find "$GITOPS_DIR" -type f -path "*/config/app-config.yaml" 2>/dev/null | head -n1 || true)
fi

workloads_json=""
if [ -n "$app_config_file" ] && [ -f "$app_config_file" ]; then
  if python3 - <<'PY' "$app_config_file" >/tmp/infisical-workloads.json
import json
import sys

try:
    import yaml
except Exception as exc:
    raise SystemExit(1)

path = sys.argv[1]
cfg = yaml.safe_load(open(path, "r", encoding="utf-8")) or {}
workloads = cfg.get("workloads") or []

def get_namespace(obj):
    for key in ("namespace",):
        value = obj.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    meta = obj.get("metadata") or {}
    if isinstance(meta, dict):
        value = meta.get("namespace")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""

default_ns = (
    get_namespace(cfg)
    or get_namespace(cfg.get("app") or {})
    or "default"
)

items = []
for item in workloads:
    if not isinstance(item, dict):
        continue
    name = str(item.get("name", "")).strip()
    if not name:
        continue
    secrets_folder = str(item.get("secretsFolder", "") or "").strip()
    workload_type = str(item.get("type", "") or "").strip()
    namespace = get_namespace(item) or default_ns
    items.append(
        {
            "name": name,
            "type": workload_type,
            "secretsFolder": secrets_folder,
            "namespace": namespace,
        }
    )

print(json.dumps(items))
PY
  then
    workloads_json="$(cat /tmp/infisical-workloads.json)"
  else
    echo "[infisical-admin-secret] python3-yaml is required to parse ${app_config_file}" >&2
  fi
fi

ca_cert=""
if [ -n "${INFISICAL_CA_CERT_B64:-}" ]; then
  ca_cert=$(printf '%s' "$INFISICAL_CA_CERT_B64" | base64 -d)
elif [ -n "${INFISICAL_CA_CERT_PATH:-}" ] && [ -f "$INFISICAL_CA_CERT_PATH" ]; then
  ca_cert=$(cat "$INFISICAL_CA_CERT_PATH")
fi

normalize_name() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9-]+/-/g; s/^-+|-+$//g'
}

update_workload_spc() {
  local root="$1"
  local workload_name="$2"
  local workload_type="$3"
  local spc_name="$4"
  python3 - <<'PY' "$root" "$workload_name" "$workload_type" "$spc_name"
import sys
from pathlib import Path

try:
    import yaml
except Exception:
    sys.exit(0)

root = Path(sys.argv[1])
target_name = sys.argv[2]
target_kind = sys.argv[3]
spc_name = sys.argv[4]

kinds = [target_kind] if target_kind else [
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "Job",
    "CronJob",
]

def template_spec(doc):
    kind = doc.get("kind")
    if kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"):
        return doc.setdefault("spec", {}).setdefault("template", {}).setdefault("spec", {})
    if kind == "CronJob":
        return (
            doc.setdefault("spec", {})
            .setdefault("jobTemplate", {})
            .setdefault("spec", {})
            .setdefault("template", {})
            .setdefault("spec", {})
        )
    return None

def update_doc(doc):
    if not isinstance(doc, dict):
        return False
    if doc.get("kind") not in kinds:
        return False
    meta = doc.get("metadata") or {}
    if meta.get("name") != target_name:
        return False
    spec = template_spec(doc)
    if spec is None:
        return False
    volumes = spec.get("volumes") or []
    updated = False
    for vol in volumes:
        if not isinstance(vol, dict):
            continue
        csi = vol.get("csi")
        if not isinstance(csi, dict):
            continue
        if csi.get("driver") != "secrets-store.csi.x-k8s.io":
            continue
        attrs = csi.setdefault("volumeAttributes", {})
        if attrs.get("secretProviderClass") != spc_name:
            attrs["secretProviderClass"] = spc_name
            updated = True
    return updated

changed_paths = []

for path in root.rglob("*.yml"):
    docs = list(yaml.safe_load_all(path.read_text()))
    changed = False
    for doc in docs:
        if update_doc(doc):
            changed = True
    if changed:
        path.write_text(yaml.safe_dump_all(docs, sort_keys=False))
        changed_paths.append(str(path))

for path in root.rglob("*.yaml"):
    docs = list(yaml.safe_load_all(path.read_text()))
    changed = False
    for doc in docs:
        if update_doc(doc):
            changed = True
    if changed:
        path.write_text(yaml.safe_dump_all(docs, sort_keys=False))
        changed_paths.append(str(path))

for path in changed_paths:
    print(path)
PY
}

if [ -n "$spc_app_file" ]; then
  spc_render_dir="${cluster_root}/infisical-secretproviderclass"
  mkdir -p "$spc_render_dir"
  spc_files=()
  workload_changed_files=()
  if [ -f "$cluster_patch_file" ]; then
    rm -f "$cluster_patch_file"
  fi

  if [ -n "$workloads_json" ] && [ "$workloads_json" != "[]" ]; then
    infisical_api="${INFISICAL_HOST%/}/api/v4/secrets"
    while IFS= read -r workload; do
      workload_name=$(echo "$workload" | jq -r '.name')
      workload_type=$(echo "$workload" | jq -r '.type // empty')
      secrets_folder=$(echo "$workload" | jq -r '.secretsFolder // empty')
      workload_namespace=$(echo "$workload" | jq -r '.namespace // "default"')
      if [ -z "$secrets_folder" ] || [ "$secrets_folder" = "null" ]; then
        continue
      fi
      norm_name=$(normalize_name "$workload_name")
      if [ -z "$norm_name" ]; then
        continue
      fi
      spc_name="infisical-${norm_name}"
      spc_file="spc-${norm_name}.yaml"
      secret_path="/${secrets_folder#/}"

      curl_args=(-fsSL -H "Authorization: Bearer ${ADMIN_TOKEN}" -H "Accept: application/json")
      if [ -n "$ca_cert" ]; then
        ca_file="${workdir}/infisical-ca.pem"
        printf '%s' "$ca_cert" > "$ca_file"
        curl_args+=(--cacert "$ca_file")
      fi

      secrets_json=$(curl "${curl_args[@]}" --get \
        --data-urlencode "projectId=${PROJECT_ID}" \
        --data-urlencode "environment=${INFISICAL_ENV_SLUG}" \
        --data-urlencode "secretPath=${secret_path}" \
        --data-urlencode "viewSecretValue=false" \
        "$infisical_api" || true)
      secret_keys=$(echo "$secrets_json" | jq -r '.secrets[]?.secretKey' | sed '/^$/d' || true)
      if [ -z "$secret_keys" ]; then
        echo "[infisical-admin-secret] no secrets found for ${workload_name} (${secret_path}); skipping SPC" >&2
        continue
      fi

      secrets_block=""
      while IFS= read -r key; do
        key_escaped=${key//\"/\\\"}
        path_escaped=${secret_path//\"/\\\"}
        secrets_block+="- secretPath: \"${path_escaped}\""$'\n'
        secrets_block+="  fileName: \"${key_escaped}\""$'\n'
        secrets_block+="  secretKey: \"${key_escaped}\""$'\n'
      done <<< "$secret_keys"

      {
        echo "apiVersion: secrets-store.csi.x-k8s.io/v1"
        echo "kind: SecretProviderClass"
        echo "metadata:"
        echo "  name: ${spc_name}"
        echo "  namespace: ${workload_namespace}"
        echo "spec:"
        echo "  provider: infisical"
        echo "  parameters:"
        echo "    authMethod: \"kubernetes\""
        echo "    infisicalUrl: \"${INFISICAL_HOST}\""
        echo "    identityId: \"${IDENTITY_ID}\""
        echo "    projectId: \"${PROJECT_ID}\""
        echo "    envSlug: \"${INFISICAL_ENV_SLUG}\""
        echo "    useDefaultAudience: \"false\""
        if [ -n "$ca_cert" ]; then
          echo "    caCertificate: |"
          while IFS= read -r line; do
            echo "      ${line}"
          done <<< "$ca_cert"
        fi
        echo "    secrets: |"
        printf '%s' "$secrets_block" | sed 's/^/      /'
      } > "${spc_render_dir}/${spc_file}"

      spc_files+=("$spc_file")
      changed_files=$(update_workload_spc "$GITOPS_DIR" "$workload_name" "$workload_type" "$spc_name" || true)
      if [ -n "$changed_files" ]; then
        while IFS= read -r changed_file; do
          [ -n "$changed_file" ] || continue
          workload_changed_files+=("$changed_file")
        done <<< "$changed_files"
      fi
    done < <(echo "$workloads_json" | jq -c '.[]')
  else
    echo "[infisical-admin-secret] no workloads with secretsFolder found in app config; skipping SPC generation" >&2
  fi

  if [ "${#spc_files[@]}" -gt 0 ]; then
    {
      echo "apiVersion: kustomize.config.k8s.io/v1beta1"
      echo "kind: Kustomization"
      echo "resources:"
      for file in "${spc_files[@]}"; do
        echo "  - ${file}"
      done
    } > "${spc_render_dir}/kustomization.yaml"
  fi

  if [ -d "$spc_render_dir" ]; then
    for file in "$spc_render_dir"/spc-*.yaml; do
      [ -e "$file" ] || continue
      base_name=$(basename "$file")
      keep="false"
      for resource in "${spc_files[@]}"; do
        if [ "$resource" = "$base_name" ]; then
          keep="true"
          break
        fi
      done
      if [ "$keep" != "true" ]; then
        rm -f "$file"
      fi
    done
  fi

  python3 - <<'PY' "$spc_app_file" "$ENV"
import re
import sys

path = sys.argv[1]
env = sys.argv[2]
new_path = f"clusters/{env}/infisical-secretproviderclass"

lines = open(path, "r", encoding="utf-8").read().splitlines()
changed = False
for i, line in enumerate(lines):
    match = re.match(r'^(\s*path:\s*).+$', line)
    if match:
        lines[i] = f"{match.group(1)}{new_path}"
        changed = True
        break

if changed:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
PY
else
cat > "$cluster_patch_file" <<EOF
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: ${spc_name}
EOF
if [ -n "$spc_namespace_target" ]; then
  printf '  namespace: %s\n' "$spc_namespace_target" >> "$cluster_patch_file"
fi
cat >> "$cluster_patch_file" <<EOF
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
  } >> "$cluster_patch_file"
fi
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

cluster_kustomization="${cluster_root}/kustomization.yaml"
if [ -f "$cluster_kustomization" ]; then
  python3 - <<'PY' "$cluster_kustomization"
import sys

path = sys.argv[1]
text = open(path, "r", encoding="utf-8").read()
if "\\n" in text or "\\r" in text:
    text = text.replace("\\r", "")
    text = text.replace("\\n", "\n")
    text = text.replace("\r\n", "\n")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text.strip() + "\n")
PY
  python3 - <<'PY' "$cluster_kustomization"
import re
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    lines = fh.read().splitlines()

out = []
for line in lines:
    if re.match(r'^\s*-\s*overlays/infisical', line):
        continue
    out.append(line)

with open(path, "w", encoding="utf-8") as fh:
    fh.write("\n".join(out) + "\n")
PY
  if [ -z "$spc_app_file" ]; then
    python3 - <<'PY' "$cluster_kustomization" "$(basename "$cluster_patch_file")" "$spc_name"
import re
import sys

path = sys.argv[1]
patch_file = sys.argv[2]
spc_name = sys.argv[3]

with open(path, "r", encoding="utf-8") as fh:
    lines = fh.read().splitlines()

if any(patch_file in line for line in lines):
    sys.exit(0)

patches_idx = None
for idx, line in enumerate(lines):
    if re.match(r'^patches:\s*$', line):
        patches_idx = idx
        break

def build_block(indent: str):
    item_indent = indent
    return [
        f"{item_indent}- target:",
        f"{item_indent}    group: secrets-store.csi.x-k8s.io",
        f"{item_indent}    version: v1",
        f"{item_indent}    kind: SecretProviderClass",
        f"{item_indent}    name: {spc_name}",
        f"{item_indent}  path: {patch_file}",
    ]

if patches_idx is None:
    lines.append("")
    lines.append("patches:")
    lines.extend(build_block(""))
else:
    end = len(lines)
    for idx in range(patches_idx + 1, len(lines)):
        if re.match(r'^[^\\s#]', lines[idx]):
            end = idx
            break
    indent = ""
    for idx in range(patches_idx + 1, end):
        match = re.match(r'^(\\s*)-\\s', lines[idx])
        if match:
            indent = match.group(1)
            break
    lines[end:end] = build_block(indent)

with open(path, "w", encoding="utf-8") as fh:
    fh.write("\\n".join(lines) + "\\n")
PY
  else
    python3 - <<'PY' "$cluster_kustomization" "$(basename "$cluster_patch_file")"
import sys

path = sys.argv[1]
patch_file = sys.argv[2]

lines = open(path, "r", encoding="utf-8").read().splitlines()
out = [line for line in lines if patch_file not in line]

# Remove empty patches: if no list items remain under it.
cleaned = []
skip = False
for idx, line in enumerate(out):
    if line.strip() == "patches:":
        # look ahead for any list items
        has_items = False
        for j in range(idx + 1, len(out)):
            if out[j].strip() == "":
                continue
            if out[j].lstrip().startswith("-"):
                has_items = True
            break
        if not has_items:
            continue
    cleaned.append(line)

with open(path, "w", encoding="utf-8") as fh:
    fh.write("\n".join(cleaned).strip() + "\n")
PY
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

    mkdir -p "$sync_overlay_dir"
    sync_file="infisicalsecret-${sync_resource_name}.yaml"
    sync_path="${sync_overlay_dir}/${sync_file}"
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
    sync_resources+=("overlays/infisical/${sync_file}")
  done
fi

if [ "${#sync_resources[@]}" -gt 0 ] && [ -f "$cluster_kustomization" ]; then
  resource_indent=$(awk '
    $1 == "resources:" {inres=1; next}
    inres && $0 ~ /^[[:space:]]*-/ {match($0,/^[[:space:]]*/); print substr($0,RSTART,RLENGTH); found=1; exit}
    inres && $0 ~ /^[^[:space:]]/ {exit}
    END {if(!found) print ""}
  ' "$cluster_kustomization")
  for resource in "${sync_resources[@]}"; do
    ensure_kustomization_entry "$cluster_kustomization" "resources:" "${resource_indent}- ${resource}"
  done
fi

git -C "$GITOPS_DIR" config user.email "infrazero-bootstrap@local"
git -C "$GITOPS_DIR" config user.name "infrazero-bootstrap"
if [ -n "$spc_app_file" ]; then
  if [ -n "${spc_render_dir:-}" ] && [ -d "$spc_render_dir" ]; then
    git -C "$GITOPS_DIR" add "$spc_render_dir"
  fi
  git -C "$GITOPS_DIR" add -A "$cluster_patch_file" 2>/dev/null || true
  git -C "$GITOPS_DIR" add "$spc_app_file"
  if [ "${#workload_changed_files[@]}" -gt 0 ]; then
    for changed_file in "${workload_changed_files[@]}"; do
      git -C "$GITOPS_DIR" add "$changed_file"
    done
  fi
else
  git -C "$GITOPS_DIR" add "$cluster_patch_file"
fi
if [ -d "$sync_overlay_dir" ]; then
  git -C "$GITOPS_DIR" add "$sync_overlay_dir"
fi
if [ -f "$cluster_kustomization" ]; then
  git -C "$GITOPS_DIR" add "$cluster_kustomization"
fi
if ! git -C "$GITOPS_DIR" diff --cached --quiet; then
  git -C "$GITOPS_DIR" commit -m "Configure Infisical k8s auth overlay"
  git_push_changes || true
else
  echo "[infisical-admin-secret] gitops overlay already up to date"
  git_push_changes || true
fi

rm -f "$workdir/age.key" "$workdir/admin.token" "$workdir/admin.token.age" "$workdir/latest-tokens.json"
rm -rf "$workdir"
unset DB_BACKUP_AGE_PRIVATE_KEY

echo "[infisical-admin-secret] $(date -Is) complete"
