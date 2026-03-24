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
require_env "INFISICAL_DB_BACKUP_AGE_PRIVATE_KEY"

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y curl ca-certificates jq age unzip git python3-yaml
  apt-get install -y python3-ruamel.yaml || true
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
  local attempt=0
  echo "[infisical-admin-secret] waiting for s3://${DB_BACKUP_BUCKET}/${key}"
  while true; do
    if aws --endpoint-url "$S3_ENDPOINT" s3 ls "s3://${DB_BACKUP_BUCKET}/${key}" >/dev/null 2>&1; then
      if [ "$attempt" -gt 0 ]; then
        echo "[infisical-admin-secret] tokens manifest found after $((attempt * 5))s"
      fi
      return 0
    fi
    attempt=$((attempt + 1))
    if [ $((attempt % 12)) -eq 0 ]; then
      echo "[infisical-admin-secret] tokens manifest still not found; continuing to wait"
    fi
    sleep 5
  done
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

echo "$INFISICAL_DB_BACKUP_AGE_PRIVATE_KEY" > "$workdir/age.key"
chmod 600 "$workdir/age.key"

# Fetch and validate admin token from S3.
# During a fresh deploy, egress may not have finished bootstrap yet, so the
# manifest in S3 can point to a stale token from a previous deployment.
# We download the manifest, decrypt the token, and verify it against the
# Infisical API.  If the token is invalid (401) we delete the local copy and
# wait for egress to upload a fresh manifest.
MAX_TOKEN_ATTEMPTS=60
TOKEN_RETRY_INTERVAL=10
ADMIN_TOKEN=""

for _token_attempt in $(seq 1 "$MAX_TOKEN_ATTEMPTS"); do
  # 1. Wait for manifest to appear in S3
  wait_for_manifest "$tokens_manifest_key"

  # 2. Download manifest
  if ! aws --endpoint-url "$S3_ENDPOINT" s3 cp "s3://${DB_BACKUP_BUCKET}/${tokens_manifest_key}" "$workdir/latest-tokens.json" >/dev/null 2>&1; then
    echo "[infisical-admin-secret] latest tokens manifest download failed; retrying in ${TOKEN_RETRY_INTERVAL}s"
    sleep "$TOKEN_RETRY_INTERVAL"
    continue
  fi

  admin_key=$(jq -r '.admin_token_key // empty' "$workdir/latest-tokens.json")
  admin_sha=$(jq -r '.admin_token_sha256 // empty' "$workdir/latest-tokens.json")
  manifest_created=$(jq -r '.created_at // empty' "$workdir/latest-tokens.json")
  if [ -z "$admin_key" ] || [ "$admin_key" = "null" ]; then
    echo "[infisical-admin-secret] tokens manifest missing admin_token_key; retrying in ${TOKEN_RETRY_INTERVAL}s"
    rm -f "$workdir/latest-tokens.json"
    sleep "$TOKEN_RETRY_INTERVAL"
    continue
  fi

  # 3. Download and decrypt admin token
  if ! aws --endpoint-url "$S3_ENDPOINT" s3 cp "s3://${DB_BACKUP_BUCKET}/${admin_key}" "$workdir/admin.token.age" >/dev/null 2>&1; then
    echo "[infisical-admin-secret] admin token download failed; retrying in ${TOKEN_RETRY_INTERVAL}s"
    rm -f "$workdir/latest-tokens.json"
    sleep "$TOKEN_RETRY_INTERVAL"
    continue
  fi

  if [ -n "$admin_sha" ] && [ "$admin_sha" != "null" ]; then
    if ! echo "$admin_sha  $workdir/admin.token.age" | sha256sum -c - >/dev/null 2>&1; then
      echo "[infisical-admin-secret] admin token checksum mismatch; retrying in ${TOKEN_RETRY_INTERVAL}s"
      rm -f "$workdir/latest-tokens.json" "$workdir/admin.token.age"
      sleep "$TOKEN_RETRY_INTERVAL"
      continue
    fi
  fi

  if ! age -d -i "$workdir/age.key" -o "$workdir/admin.token" "$workdir/admin.token.age" 2>/dev/null; then
    echo "[infisical-admin-secret] admin token decryption failed; retrying in ${TOKEN_RETRY_INTERVAL}s"
    rm -f "$workdir/latest-tokens.json" "$workdir/admin.token.age" "$workdir/admin.token"
    sleep "$TOKEN_RETRY_INTERVAL"
    continue
  fi

  candidate_token=$(cat "$workdir/admin.token")
  if [ -z "$candidate_token" ]; then
    echo "[infisical-admin-secret] decrypted admin token is empty; retrying in ${TOKEN_RETRY_INTERVAL}s"
    rm -f "$workdir/latest-tokens.json" "$workdir/admin.token.age" "$workdir/admin.token"
    sleep "$TOKEN_RETRY_INTERVAL"
    continue
  fi

  # 4. Validate token against Infisical API
  validate_code=$(curl -sS -o /dev/null -w "%{http_code}" \
    --connect-timeout 5 --max-time 10 \
    -H "Authorization: Bearer ${candidate_token}" \
    "${INFISICAL_SITE_URL}/api/v1/projects" 2>/dev/null || true)

  if [ "$validate_code" = "401" ] || [ "$validate_code" = "403" ]; then
    echo "[infisical-admin-secret] admin token is stale (HTTP ${validate_code}, manifest created_at=${manifest_created:-unknown}); waiting for fresh token (attempt ${_token_attempt}/${MAX_TOKEN_ATTEMPTS})"
    rm -f "$workdir/latest-tokens.json" "$workdir/admin.token.age" "$workdir/admin.token"
    sleep "$TOKEN_RETRY_INTERVAL"
    continue
  fi

  # Token is valid (or Infisical returned a non-auth error which is fine)
  ADMIN_TOKEN="$candidate_token"
  echo "[infisical-admin-secret] admin token validated (HTTP ${validate_code}, created_at=${manifest_created:-unknown})"
  break
done

rm -f "$workdir/admin.token.age" "$workdir/admin.token"

if [ -z "$ADMIN_TOKEN" ]; then
  echo "[infisical-admin-secret] failed to obtain a valid admin token after ${MAX_TOKEN_ATTEMPTS} attempts" >&2
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

INFISICAL_KUBERNETES_HOST="${INFISICAL_KUBERNETES_HOST:-}"
if [ -z "$INFISICAL_KUBERNETES_HOST" ]; then
  INFISICAL_KUBERNETES_HOST="https://${KUBERNETES_FQDN}"
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

spc_app_files=()
if [ -d "$cluster_root" ]; then
  while IFS= read -r candidate; do
    [ -n "$candidate" ] || continue
    if grep -qE '^kind:\s*Application' "$candidate"; then
      spc_app_files+=("$candidate")
    fi
  done < <(find "$cluster_root" -type f -path "*/applications/*" \( -name "*infisical*secretproviderclass*.y*ml" -o -name "*secretproviderclass*.y*ml" \) 2>/dev/null | sort)
fi
spc_app_file="${spc_app_files[0]:-}"

legacy_app_config_file=""
use_app_config="false"
if [ -f "${GITOPS_DIR}/config/app-config.yaml" ]; then
  legacy_app_config_file="${GITOPS_DIR}/config/app-config.yaml"
else
  legacy_app_config_file=$(find "$GITOPS_DIR" -type f -path "*/config/app-config.yaml" 2>/dev/null | head -n1 || true)
fi
app_config_targets=()
if [ -n "$legacy_app_config_file" ] && [ -f "$legacy_app_config_file" ]; then
  app_config_targets+=("$legacy_app_config_file")
fi
if [ -d "${GITOPS_DIR}/config/apps" ]; then
  while IFS= read -r app_values_file; do
    [ -n "$app_values_file" ] || continue
    app_config_targets+=("$app_values_file")
  done < <(find "${GITOPS_DIR}/config/apps" -maxdepth 1 -type f -name "*.y*ml" 2>/dev/null | sort)
fi

workloads_json=""
if [ "${#app_config_targets[@]}" -gt 0 ]; then
  if python3 - <<'PY' "${app_config_targets[@]}" >/tmp/infisical-workloads.json
import json
import sys

try:
    import yaml
except Exception as exc:
    raise SystemExit(1)

paths = [value for value in sys.argv[1:] if str(value).strip()]

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

items = []
seen = set()
for path in paths:
    cfg = yaml.safe_load(open(path, "r", encoding="utf-8")) or {}
    spec = cfg.get("spec") if isinstance(cfg, dict) else {}
    if not isinstance(spec, dict):
        spec = {}
    workloads = spec.get("workloads") or cfg.get("workloads") or []
    global_cfg = spec.get("global") if isinstance(spec, dict) else {}
    if not isinstance(global_cfg, dict):
        global_cfg = {}

    default_ns = (
        get_namespace(global_cfg)
        or get_namespace(spec)
        or get_namespace(cfg)
        or "default"
    )

    for item in workloads:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        if not name:
            continue
        secrets_folder = str(item.get("secretsFolder", "") or "").strip()
        workload_type = str(item.get("type", "") or "").strip()
        csi_cfg = item.get("csi") if isinstance(item.get("csi"), dict) else {}
        csi_enabled = csi_cfg.get("enabled") is True
        namespace = get_namespace(item) or default_ns
        dedupe_key = (name, workload_type, secrets_folder, namespace)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        items.append(
            {
                "name": name,
                "type": workload_type,
                "secretsFolder": secrets_folder,
                "csiEnabled": csi_enabled,
                "namespace": namespace,
            }
        )

print(json.dumps(items))
PY
  then
    workloads_json="$(cat /tmp/infisical-workloads.json)"
    use_app_config="true"
  else
    echo "[infisical-admin-secret] python3-yaml is required to parse app config values files" >&2
  fi
fi

update_all_app_configs() {
  local workload_name="$1"
  local spc_name="$2"
  local csi_enabled="$3"
  local target
  local changed
  local merged=""
  local current
  for target in "${app_config_targets[@]}"; do
    [ -f "$target" ] || continue
    changed=$(update_app_config "$target" "$workload_name" "$spc_name" "$csi_enabled" || true)
    if [ -n "$changed" ]; then
      merged+="${changed}"$'\n'
    fi
  done
  if [ -z "$merged" ]; then
    return 0
  fi
  while IFS= read -r current; do
    [ -n "$current" ] || continue
    echo "$current"
  done < <(printf '%s' "$merged" | awk 'NF && !seen[$0]++')
}

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
        driver = str(csi.get("driver", "") or "")
        if driver not in ("secrets-store.csi.k8s.io", "secrets-store.csi.x-k8s.io", ""):
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

update_app_config() {
  local config_path="$1"
  local workload_name="$2"
  local spc_name="$3"
  local csi_enabled="${4:-true}"
  python3 - <<'PY' "$config_path" "$workload_name" "$spc_name" "$csi_enabled"
import sys
import os

path = sys.argv[1]
target_name = sys.argv[2]
spc_name = sys.argv[3]
csi_enabled = str(sys.argv[4]).strip().lower() == "true"

def update_cfg(cfg):
    spec = cfg.get("spec") if isinstance(cfg, dict) else {}
    if not isinstance(spec, dict):
        spec = {}

    workloads = spec.get("workloads") or cfg.get("workloads") or []
    updated = False

    for item in workloads:
        if not isinstance(item, dict):
            continue
        if str(item.get("name", "")).strip() != target_name:
            continue
        csi = item.get("csi") if isinstance(item.get("csi"), dict) else {}
        if csi_enabled:
            if csi.get("enabled") is not True:
                csi["enabled"] = True
            if csi.get("secretProviderClass") != spc_name:
                csi["secretProviderClass"] = spc_name
        else:
            if csi.get("enabled") is not False:
                csi["enabled"] = False
            if csi.get("secretProviderClass"):
                csi["secretProviderClass"] = ""
            attrs = csi.get("volumeAttributes")
            if isinstance(attrs, dict) and "secretProviderClass" in attrs:
                attrs.pop("secretProviderClass", None)
        item["csi"] = csi
        updated = True

    if updated and isinstance(cfg, dict) and "spec" in cfg and isinstance(spec, dict):
        cfg["spec"] = spec

    return updated, cfg

try:
    from ruamel.yaml import YAML
except Exception:
    YAML = None

if YAML is not None:
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.width = 4096
    yaml.allow_duplicate_keys = True
    with open(path, "r", encoding="utf-8") as fh:
        cfg = yaml.load(fh) or {}
    updated, cfg = update_cfg(cfg)
    if updated:
        with open(path, "w", encoding="utf-8") as fh:
            yaml.dump(cfg, fh)
        print(path)
    sys.exit(0)

try:
    import yaml  # PyYAML fallback
except Exception:
    sys.exit(0)

allow_rewrite = os.environ.get("INFISICAL_ALLOW_APP_CONFIG_REWRITE", "").lower() in ("1", "true", "yes")
if not allow_rewrite:
    print("[infisical-admin-secret] ruamel.yaml not available; skipping app-config mutation to avoid rewrite", file=sys.stderr)
    sys.exit(0)

cfg = yaml.safe_load(open(path, "r", encoding="utf-8")) or {}
updated, cfg = update_cfg(cfg)
if updated:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(yaml.safe_dump(cfg, sort_keys=False))
    print(path)
PY
}

if [ -n "$spc_app_file" ]; then
  spc_render_dir="${cluster_root}/infisical-secretproviderclass"
  mkdir -p "$spc_render_dir"
  spc_files=()
  workload_changed_files=()
  append_unique_spc_file() {
    local candidate="$1"
    local existing
    for existing in "${spc_files[@]}"; do
      if [ "$existing" = "$candidate" ]; then
        return 0
      fi
    done
    spc_files+=("$candidate")
  }
  if [ -f "$cluster_patch_file" ]; then
    rm -f "$cluster_patch_file"
  fi

  if [ -n "$workloads_json" ] && [ "$workloads_json" != "[]" ]; then
    infisical_api="${INFISICAL_HOST%/}/api/v4/secrets"
    while IFS= read -r workload; do
      workload_name=$(echo "$workload" | jq -r '.name')
      workload_type=$(echo "$workload" | jq -r '.type // empty')
      secrets_folder=$(echo "$workload" | jq -r '.secretsFolder // empty')
      csi_enabled=$(echo "$workload" | jq -r '.csiEnabled // false')
      workload_namespace=$(echo "$workload" | jq -r '.namespace // "default"')
      if [ -z "$secrets_folder" ] || [ "$secrets_folder" = "null" ]; then
        if [ "$csi_enabled" = "true" ]; then
          echo "[infisical-admin-secret] workload ${workload_name} has csi.enabled=true but secretsFolder is empty" >&2
          exit 1
        fi
        continue
      fi
      norm_name=$(normalize_name "$secrets_folder")
      if [ -z "$norm_name" ]; then
        continue
      fi
      spc_name="infisical-${norm_name}"
      spc_file="spc-${norm_name}.yaml"
      secret_path="/${secrets_folder#/}"

      curl_args=(-sSL -H "Authorization: Bearer ${ADMIN_TOKEN}" -H "Accept: application/json")
      if [ -n "$ca_cert" ]; then
        ca_file="${workdir}/infisical-ca.pem"
        printf '%s' "$ca_cert" > "$ca_file"
        curl_args+=(--cacert "$ca_file")
      fi

      secrets_response_file=$(mktemp "${workdir}/infisical-secrets.XXXX")
      secrets_http_code=$(curl "${curl_args[@]}" -o "$secrets_response_file" -w "%{http_code}" --get \
        --data-urlencode "projectId=${PROJECT_ID}" \
        --data-urlencode "environment=${INFISICAL_ENV_SLUG}" \
        --data-urlencode "secretPath=${secret_path}" \
        --data-urlencode "viewSecretValue=false" \
        "$infisical_api" || true)

      if [ "$secrets_http_code" = "200" ]; then
        secrets_json=$(cat "$secrets_response_file")
      elif [ "$secrets_http_code" = "404" ]; then
        echo "[infisical-admin-secret] no secrets found for ${workload_name} (${secret_path}); workload CSI will be disabled" >&2
        secrets_json='{"secrets":[]}'
      else
        echo "[infisical-admin-secret] failed to fetch secrets for ${workload_name} (${secret_path}); http=${secrets_http_code:-000}" >&2
        cat "$secrets_response_file" >&2 || true
        rm -f "$secrets_response_file"
        exit 1
      fi
      rm -f "$secrets_response_file"

      if ! echo "$secrets_json" | jq -e . >/dev/null 2>&1; then
        echo "[infisical-admin-secret] invalid JSON while fetching ${workload_name} (${secret_path})" >&2
        exit 1
      fi

      secret_keys=$(echo "$secrets_json" | jq -r '.secrets[]?.secretKey' | sed '/^$/d' || true)
      if [ -z "$secret_keys" ]; then
        echo "[infisical-admin-secret] no secrets found for ${workload_name} (${secret_path}); disabling CSI for workload" >&2
        if [ "$use_app_config" = "true" ] && [ "${#app_config_targets[@]}" -gt 0 ]; then
          changed_files=$(update_all_app_configs "$workload_name" "" "false" || true)
        else
          changed_files=""
        fi
        if [ -n "$changed_files" ]; then
          while IFS= read -r changed_file; do
            [ -n "$changed_file" ] || continue
            workload_changed_files+=("$changed_file")
          done <<< "$changed_files"
        fi
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

      append_unique_spc_file "$spc_file"
      if [ "$use_app_config" = "true" ] && [ "${#app_config_targets[@]}" -gt 0 ]; then
        changed_files=$(update_all_app_configs "$workload_name" "$spc_name" "true" || true)
      else
        changed_files=$(update_workload_spc "$GITOPS_DIR" "$workload_name" "$workload_type" "$spc_name" || true)
      fi
      if [ -n "$changed_files" ]; then
        while IFS= read -r changed_file; do
          [ -n "$changed_file" ] || continue
          workload_changed_files+=("$changed_file")
        done <<< "$changed_files"
      fi
    done < <(echo "$workloads_json" | jq -c '.[]')
  else
    echo "[infisical-admin-secret] no workloads with secretsFolder found in app config values; skipping SPC generation" >&2
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

  for spc_app_target in "${spc_app_files[@]}"; do
  python3 - <<'PY' "$spc_app_target" "$ENV"
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
  done
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
  if [ "${#spc_app_files[@]}" -gt 0 ]; then
    for spc_app_target in "${spc_app_files[@]}"; do
      git -C "$GITOPS_DIR" add "$spc_app_target"
    done
  fi
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
unset INFISICAL_DB_BACKUP_AGE_PRIVATE_KEY

echo "[infisical-admin-secret] $(date -Is) complete"
