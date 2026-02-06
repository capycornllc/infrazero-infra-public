#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/infrazero-bootstrap.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[infisical-bootstrap] $(date -Is) start"

LOCK_FILE="/var/lock/infisical-bootstrap.lock"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[infisical-bootstrap] another instance is running; exiting"
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

load_env /etc/infrazero/egress.env
load_env /etc/infrazero/node.env

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[infisical-bootstrap] missing required env: $name" >&2
    exit 1
  fi
}

retry() {
  local attempts="$1"
  local delay="$2"
  shift 2
  local i
  for i in $(seq 1 "$attempts"); do
    if "$@"; then
      return 0
    fi
    echo "[infisical-bootstrap] retry $i/$attempts failed; sleeping ${delay}s"
    sleep "$delay"
  done
  return 1
}

INFISICAL_FQDN="${INFISICAL_FQDN:-}"
INFISICAL_SITE_URL="${INFISICAL_SITE_URL:-}"
if [ -z "$INFISICAL_SITE_URL" ] && [ -n "$INFISICAL_FQDN" ]; then
  INFISICAL_SITE_URL="https://${INFISICAL_FQDN}"
fi

require_env "INFISICAL_SITE_URL"
require_env "INFISICAL_RESTORE_FROM_S3"
require_env "S3_ACCESS_KEY_ID"
require_env "S3_SECRET_ACCESS_KEY"
require_env "S3_ENDPOINT"
require_env "S3_REGION"
require_env "DB_BACKUP_BUCKET"
require_env "INFISICAL_DB_BACKUP_AGE_PUBLIC_KEY"
require_env "INFISICAL_EMAIL"
require_env "INFISICAL_PASSWORD"
require_env "INFISICAL_ORGANIZATION"
require_env "INFISICAL_PROJECT_NAME"

if [ -z "$INFISICAL_FQDN" ]; then
  echo "[infisical-bootstrap] INFISICAL_FQDN not set; cannot verify readiness" >&2
  exit 1
fi

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
  echo "[infisical-bootstrap] aws cli not available; cannot continue" >&2
  exit 1
fi

export AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$S3_SECRET_ACCESS_KEY"
export AWS_DEFAULT_REGION="$S3_REGION"

if [[ "$S3_ENDPOINT" != http://* && "$S3_ENDPOINT" != https://* ]]; then
  S3_ENDPOINT="https://${S3_ENDPOINT}"
fi

INFISICAL_SITE_URL="${INFISICAL_SITE_URL%/}"
INFISICAL_API_BASE="${INFISICAL_SITE_URL}/api"

wait_for_url() {
  local url="$1"
  echo "[infisical-bootstrap] waiting for $url"
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
        # Non-retryable response from upstream
        return 0
        ;;
    esac
    sleep 5
  done
  return 1
}

wait_for_url "https://${INFISICAL_FQDN}" || {
  echo "[infisical-bootstrap] infisical_fqdn not ready (still returning 5xx/000)" >&2
  exit 1
}
wait_for_url "${INFISICAL_SITE_URL}" || {
  echo "[infisical-bootstrap] INFISICAL_SITE_URL not ready (still returning 5xx/000)" >&2
  exit 1
}

restore_requested="${INFISICAL_RESTORE_FROM_S3,,}"
backup_manifest_key="infisical/latest-dump.json"
if [ "$restore_requested" = "true" ]; then
  if aws --endpoint-url "$S3_ENDPOINT" s3 ls "s3://${DB_BACKUP_BUCKET}/${backup_manifest_key}" >/dev/null 2>&1; then
    echo "[infisical-bootstrap] restore requested and backup manifest exists; skipping bootstrap"
    exit 0
  fi
  echo "[infisical-bootstrap] restore requested but no backup manifest; continuing with bootstrap"
fi

tokens_manifest_key="infisical/bootstrap/latest-tokens.json"
tokens_manifest_exists="false"
if aws --endpoint-url "$S3_ENDPOINT" s3 ls "s3://${DB_BACKUP_BUCKET}/${tokens_manifest_key}" >/dev/null 2>&1; then
  tokens_manifest_exists="true"
fi
if [ "$restore_requested" != "true" ] && [ "$tokens_manifest_exists" = "true" ]; then
  echo "[infisical-bootstrap] tokens manifest exists; rotating tokens and updating manifest"
fi

bootstrap_payload=$(jq -n \
  --arg email "$INFISICAL_EMAIL" \
  --arg password "$INFISICAL_PASSWORD" \
  --arg org "$INFISICAL_ORGANIZATION" \
  '{email:$email, password:$password, organization:$org}')

bootstrap_tmp=$(mktemp)
bootstrap_code=""
for _ in {1..30}; do
  bootstrap_code=$(curl -sS -o "$bootstrap_tmp" -w "%{http_code}" \
    --connect-timeout 5 --max-time 15 \
    -H "Content-Type: application/json" \
    -d "$bootstrap_payload" \
    "${INFISICAL_API_BASE}/v1/admin/bootstrap" || true)
  case "$bootstrap_code" in
    502|503|504|000|"")
      echo "[infisical-bootstrap] bootstrap endpoint not ready (http ${bootstrap_code}); retrying"
      sleep 5
      ;;
    *)
      break
      ;;
  esac
done

if [[ "$bootstrap_code" != 2* ]]; then
  message=$(jq -r '.message // empty' "$bootstrap_tmp" 2>/dev/null || true)
  if echo "$message" | grep -qi "bootstrapped"; then
    if [ "$tokens_manifest_exists" = "true" ]; then
      echo "[infisical-bootstrap] instance already bootstrapped; tokens manifest exists; exiting"
      exit 0
    fi
    echo "[infisical-bootstrap] instance already bootstrapped; no tokens manifest present" >&2
    exit 1
  fi
  echo "[infisical-bootstrap] bootstrap failed (http ${bootstrap_code})" >&2
  cat "$bootstrap_tmp" >&2 || true
  exit 1
fi

ADMIN_TOKEN=$(jq -r '.identity.credentials.token // empty' "$bootstrap_tmp")

if [ -z "$ADMIN_TOKEN" ]; then
  echo "[infisical-bootstrap] bootstrap response missing required fields" >&2
  cat "$bootstrap_tmp" >&2 || true
  exit 1
fi

PROJECT_NAME="${INFISICAL_PROJECT_NAME}"
PROJECT_SLUG="${INFISICAL_PROJECT_SLUG:-}"
if [ -z "$PROJECT_SLUG" ]; then
  PROJECT_SLUG=$(echo "$PROJECT_NAME" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+|-+$//g')
fi
if [ -z "$PROJECT_SLUG" ]; then
  echo "[infisical-bootstrap] unable to derive project slug" >&2
  exit 1
fi

project_tmp=$(mktemp)
project_code=$(curl -sS -o "$project_tmp" -w "%{http_code}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${INFISICAL_API_BASE}/v1/projects/slug/${PROJECT_SLUG}" || true)

if [ "$project_code" = "404" ]; then
  project_description="${INFISICAL_PROJECT_DESCRIPTION:-${PROJECT_NAME} secrets}"
  create_payload=$(jq -n \
    --arg name "$PROJECT_NAME" \
    --arg slug "$PROJECT_SLUG" \
    --arg desc "$project_description" \
    '{projectName:$name, projectDescription:$desc, slug:$slug, template:"default", type:"secret-manager", shouldCreateDefaultEnvs:false}')
  project_code=$(curl -sS -o "$project_tmp" -w "%{http_code}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$create_payload" \
    "${INFISICAL_API_BASE}/v1/projects" || true)
  if [[ "$project_code" != 2* ]]; then
    echo "[infisical-bootstrap] failed to create project (http ${project_code})" >&2
    cat "$project_tmp" >&2 || true
    exit 1
  fi
fi

PROJECT_ID=$(jq -r '.id // .project.id // empty' "$project_tmp")
if [ -z "$PROJECT_ID" ]; then
  echo "[infisical-bootstrap] unable to resolve project id" >&2
  cat "$project_tmp" >&2 || true
  exit 1
fi

admin_role_slug=""
roles_tmp=$(mktemp)
roles_code=$(curl -sS -o "$roles_tmp" -w "%{http_code}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${INFISICAL_API_BASE}/v1/projects/${PROJECT_ID}/roles" || true)
if [[ "$roles_code" == 2* ]]; then
  admin_role_slug=$(jq -r '.roles[] | select((.slug|test("admin|owner";"i")) or (.name|test("admin|owner";"i"))) | .slug' "$roles_tmp" | head -n 1)
  if [ -z "$admin_role_slug" ]; then
    admin_role_slug=$(jq -r '.roles[0].slug // empty' "$roles_tmp")
  fi
fi
rm -f "$roles_tmp"

if [ -z "$admin_role_slug" ]; then
  admin_role_slug="member"
fi

membership_payload=$(jq -n \
  --arg email "$INFISICAL_EMAIL" \
  --arg role "$admin_role_slug" \
  '{emails:[$email], roleSlugs:[$role]}')
membership_tmp=$(mktemp)
membership_code=$(curl -sS -o "$membership_tmp" -w "%{http_code}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$membership_payload" \
  "${INFISICAL_API_BASE}/v1/projects/${PROJECT_ID}/memberships" || true)
if [[ "$membership_code" != 2* ]]; then
  message=$(jq -r '.message // empty' "$membership_tmp" 2>/dev/null || true)
  if echo "$message" | grep -qi "already"; then
    echo "[infisical-bootstrap] admin already added to project; continuing"
  else
    echo "[infisical-bootstrap] failed to add admin to project (http ${membership_code})" >&2
    cat "$membership_tmp" >&2 || true
    exit 1
  fi
fi
rm -f "$membership_tmp"

existing_envs=$(jq -r '.environments[]?.slug' "$project_tmp" 2>/dev/null | tr '\n' ' ')

declare -a default_envs=("dev:Development:1" "staging:Staging:2" "prod:Production:3")
for env_def in "${default_envs[@]}"; do
  IFS=":" read -r env_slug env_name env_pos <<< "$env_def"
  if echo "$existing_envs" | grep -qw "$env_slug"; then
    continue
  fi
  env_payload=$(jq -n --arg name "$env_name" --arg slug "$env_slug" --argjson pos "$env_pos" '{name:$name, slug:$slug, position:$pos}')
  curl -sS -o /dev/null \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$env_payload" \
    "${INFISICAL_API_BASE}/v1/projects/${PROJECT_ID}/environments" || true
done

if [ -n "${INFISICAL_BOOTSTRAP_SECRETS:-}" ]; then
  env_list=$(echo "$INFISICAL_BOOTSTRAP_SECRETS" | jq -r '
    [to_entries[] | .value[] | to_entries[] | .value | keys[]] | unique[]' 2>/dev/null)
else
  env_list="${ENVIRONMENT:-}"
fi

if [ -z "$env_list" ]; then
  env_list="dev"
fi

ensure_folder_path() {
  local env_slug="$1"
  local folder_path="$2"

  if [ -z "$folder_path" ] || [ "$folder_path" = "/" ]; then
    return 0
  fi

  local trimmed="${folder_path#/}"
  local current="/"
  IFS='/' read -r -a parts <<< "$trimmed"
  for part in "${parts[@]}"; do
    if [ -z "$part" ]; then
      continue
    fi
    local payload
    payload=$(jq -n \
      --arg projectId "$PROJECT_ID" \
      --arg environment "$env_slug" \
      --arg name "$part" \
      --arg path "$current" \
      '{projectId:$projectId, environment:$environment, name:$name, path:$path}')
    curl -sS -o /dev/null \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "$payload" \
      "${INFISICAL_API_BASE}/v2/folders" || true
    if [ "$current" = "/" ]; then
      current="/${part}"
    else
      current="${current}/${part}"
    fi
  done
}

upsert_secret() {
  local env_slug="$1"
  local secret_path="$2"
  local secret_name="$3"
  local secret_value="$4"

  local payload
  payload=$(jq -n \
    --arg projectId "$PROJECT_ID" \
    --arg environment "$env_slug" \
    --arg secretValue "$secret_value" \
    --arg secretPath "$secret_path" \
    '{projectId:$projectId, environment:$environment, secretValue:$secretValue, secretPath:$secretPath, type:"shared", skipMultilineEncoding:true}')

  local tmp
  tmp=$(mktemp)
  local code
  code=$(curl -sS -o "$tmp" -w "%{http_code}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$payload" \
    "${INFISICAL_API_BASE}/v4/secrets/${secret_name}" || true)

  if [[ "$code" == 2* ]]; then
    rm -f "$tmp"
    return 0
  fi

  code=$(curl -sS -o "$tmp" -w "%{http_code}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$payload" \
    -X PATCH \
    "${INFISICAL_API_BASE}/v4/secrets/${secret_name}" || true)

  if [[ "$code" != 2* ]]; then
    echo "[infisical-bootstrap] failed to upsert secret ${secret_name} (${env_slug}:${secret_path})" >&2
    cat "$tmp" >&2 || true
  fi
  rm -f "$tmp"
}

if [ -n "${INFISICAL_BOOTSTRAP_SECRETS:-}" ]; then
  echo "[infisical-bootstrap] loading bootstrap secrets into Infisical"
  echo "$INFISICAL_BOOTSTRAP_SECRETS" | jq -c 'to_entries[]' | while read -r folder_entry; do
    folder_name=$(echo "$folder_entry" | jq -r '.key')
    folder_path="/${folder_name#/}"
    if [ "$folder_name" = "/" ] || [ -z "$folder_name" ]; then
      folder_path="/"
    fi
    echo "$folder_entry" | jq -c '.value[]' | while read -r secret_entry; do
      secret_name=$(echo "$secret_entry" | jq -r 'keys[0]')
      env_map=$(echo "$secret_entry" | jq -c '.[keys[0]]')
      echo "$env_map" | jq -r 'keys[]' | while read -r env_slug; do
        secret_value=$(echo "$env_map" | jq -r --arg env "$env_slug" '.[$env]')
        if [ "$secret_value" = "null" ]; then
          continue
        fi
        ensure_folder_path "$env_slug" "$folder_path"
        upsert_secret "$env_slug" "$folder_path" "$secret_name" "$secret_value"
      done
    done
  done
else
  echo "[infisical-bootstrap] INFISICAL_BOOTSTRAP_SECRETS not set; skipping secrets population"
fi

tmpdir=$(mktemp -d /run/infisical-bootstrap.XXXX)
chmod 700 "$tmpdir"
printf '%s' "$ADMIN_TOKEN" > "$tmpdir/admin.token"

age -r "$INFISICAL_DB_BACKUP_AGE_PUBLIC_KEY" -o "$tmpdir/admin.token.age" "$tmpdir/admin.token"

admin_sha=$(sha256sum "$tmpdir/admin.token.age" | awk '{print $1}')

token_timestamp=$(date -u +%Y%m%dT%H%M%SZ)
token_prefix="infisical/bootstrap/${token_timestamp}"
admin_key="${token_prefix}/admin.token.age"

aws --endpoint-url "$S3_ENDPOINT" s3 cp "$tmpdir/admin.token.age" "s3://${DB_BACKUP_BUCKET}/${admin_key}"

manifest=$(jq -n \
  --arg created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg site "$INFISICAL_SITE_URL" \
  --arg admin_key "$admin_key" \
  --arg admin_sha "$admin_sha" \
  '{created_at:$created_at, infisical_site_url:$site, admin_token_key:$admin_key, admin_token_sha256:$admin_sha}')

echo "$manifest" > "$tmpdir/latest-tokens.json"
aws --endpoint-url "$S3_ENDPOINT" s3 cp "$tmpdir/latest-tokens.json" "s3://${DB_BACKUP_BUCKET}/${tokens_manifest_key}"

rm -f "$tmpdir/admin.token"
rm -f "$tmpdir/admin.token.age" "$tmpdir/latest-tokens.json"
rmdir "$tmpdir" || true

echo "[infisical-bootstrap] $(date -Is) complete"
