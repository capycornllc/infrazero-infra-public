#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/infrazero-bootstrap.log"
if [ -z "${_INFRAZERO_LOG_REDIRECTED:-}" ]; then
  exec > >(tee -a "$LOG_FILE") 2>&1
  export _INFRAZERO_LOG_REDIRECTED=1
fi

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

BOOTSTRAP_ENV_FILE="/etc/infrazero/egress.bootstrap.env"
download_offloaded_bootstrap_env() {
  local payload_url="${INFISICAL_BOOTSTRAP_SECRETS_ENV_URL:-}"
  local payload_sha256="${INFISICAL_BOOTSTRAP_SECRETS_ENV_SHA256:-}"
  local payload_endpoint="${INFISICAL_BOOTSTRAP_SECRETS_ENV_ENDPOINT:-${S3_ENDPOINT:-}}"
  local payload_bucket="${INFISICAL_BOOTSTRAP_SECRETS_ENV_BUCKET:-}"
  local payload_key="${INFISICAL_BOOTSTRAP_SECRETS_ENV_KEY:-}"
  local tmp_file
  local http_code=""
  local -a aws_args=()

  if [ -f "$BOOTSTRAP_ENV_FILE" ]; then
    return 0
  fi

  if [ -z "$payload_url" ] && { [ -z "$payload_bucket" ] || [ -z "$payload_key" ]; }; then
    return 0
  fi

  tmp_file=$(mktemp)
  if [ -n "$payload_url" ]; then
    for _ in {1..20}; do
      http_code=$(curl -sS -L -o "$tmp_file" -w "%{http_code}" --connect-timeout 5 --max-time 30 "$payload_url" || true)
      if [ "$http_code" != "200" ]; then
        sleep 3
        continue
      fi

      if [ -n "$payload_sha256" ] && ! echo "$payload_sha256  $tmp_file" | sha256sum -c - >/dev/null; then
        rm -f "$tmp_file"
        echo "[infisical-bootstrap] offloaded payload checksum mismatch; continuing without split payload file" >&2
        return 0
      fi

      install -D -m 0600 "$tmp_file" "$BOOTSTRAP_ENV_FILE"
      rm -f "$tmp_file"
      load_env "$BOOTSTRAP_ENV_FILE"
      echo "[infisical-bootstrap] loaded offloaded bootstrap payload (url)"
      return 0
    done
  fi

  if command -v aws >/dev/null 2>&1 && [ -n "$payload_bucket" ] && [ -n "$payload_key" ]; then
    if [ -n "$payload_endpoint" ]; then
      aws_args=(--endpoint-url "$payload_endpoint")
    fi
    for _ in {1..20}; do
      if aws "${aws_args[@]}" s3 cp "s3://${payload_bucket}/${payload_key}" "$tmp_file" >/dev/null 2>&1; then
        if [ -n "$payload_sha256" ] && ! echo "$payload_sha256  $tmp_file" | sha256sum -c - >/dev/null; then
          rm -f "$tmp_file"
          echo "[infisical-bootstrap] offloaded payload checksum mismatch (s3); continuing without split payload file" >&2
          return 0
        fi

        install -D -m 0600 "$tmp_file" "$BOOTSTRAP_ENV_FILE"
        rm -f "$tmp_file"
        load_env "$BOOTSTRAP_ENV_FILE"
        echo "[infisical-bootstrap] loaded offloaded bootstrap payload (s3)"
        return 0
      fi
      sleep 3
    done
  fi

  rm -f "$tmp_file"
  echo "[infisical-bootstrap] unable to download offloaded payload (http ${http_code:-000}); continuing" >&2
  return 0
}

download_offloaded_bootstrap_env
load_env "$BOOTSTRAP_ENV_FILE"

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

log_infisical_response() {
  local context="$1"
  local file="$2"

  if [ ! -f "$file" ]; then
    echo "[infisical-bootstrap] ${context} response file missing" >&2
    return 0
  fi

  # Redact sensitive values before logging response payloads.
  local sanitized
  sanitized=$(jq -c '
    def sanitize:
      if type == "object" then
        with_entries(
          .value |= sanitize
          | if (.key | test("token|secret|password|authorization|private[_-]?key|api[_-]?key|jwt|access[_-]?token|refresh[_-]?token"; "i"))
            then .value = "***REDACTED***"
            else .
            end
        )
      elif type == "array" then
        map(sanitize)
      else
        .
      end;
    sanitize
  ' "$file" 2>/dev/null || true)

  if [ -n "$sanitized" ]; then
    echo "[infisical-bootstrap] ${context} response: ${sanitized}" >&2
  else
    local bytes
    bytes=$(wc -c < "$file" 2>/dev/null || echo "0")
    echo "[infisical-bootstrap] ${context} response unavailable (non-JSON, ${bytes} bytes)" >&2
  fi
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
  log_infisical_response "bootstrap" "$bootstrap_tmp"
  exit 1
fi

ADMIN_TOKEN=$(jq -r '.identity.credentials.token // empty' "$bootstrap_tmp")
ORGANIZATION_ID=$(jq -r '.organization.id // .organization._id // empty' "$bootstrap_tmp")

if [ -z "$ADMIN_TOKEN" ]; then
  echo "[infisical-bootstrap] bootstrap response missing required fields" >&2
  log_infisical_response "bootstrap" "$bootstrap_tmp"
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
  # Keep payload minimal for API compatibility across Infisical versions.
  # Older/newer versions can reject extra fields (for example slug/description).
  create_payload=$(jq -n \
    --arg name "$PROJECT_NAME" \
    '{projectName:$name, template:"default", type:"secret-manager", shouldCreateDefaultEnvs:true}')
  project_code=$(curl -sS -o "$project_tmp" -w "%{http_code}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$create_payload" \
    "${INFISICAL_API_BASE}/v1/projects" || true)
fi

if [[ "$project_code" != 2* ]]; then
  # Fallback: project may already exist (e.g. 422) or slug lookup may be unavailable.
  # Resolve by listing projects and matching slug/name.
  projects_tmp=$(mktemp)
  projects_code=$(curl -sS -o "$projects_tmp" -w "%{http_code}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    "${INFISICAL_API_BASE}/v1/projects" || true)
  if [[ "$projects_code" == 2* ]]; then
    resolved_project=$(jq -c --arg slug "$PROJECT_SLUG" --arg name "$PROJECT_NAME" '
      .projects
      | map(select((.slug // "") == $slug))
      | if length > 0 then .[0] else empty end
    ' "$projects_tmp")
    if [ -z "$resolved_project" ] || [ "$resolved_project" = "null" ]; then
      resolved_project=$(jq -c --arg name "$PROJECT_NAME" '
        .projects
        | map(select((.name // "") == $name))
        | if length > 0 then .[0] else empty end
      ' "$projects_tmp")
    fi
    if [ -n "$resolved_project" ] && [ "$resolved_project" != "null" ]; then
      jq -n --argjson project "$resolved_project" '{project:$project}' > "$project_tmp"
      project_code="200"
    fi
  fi
  rm -f "$projects_tmp"
fi

if [[ "$project_code" != 2* ]]; then
  echo "[infisical-bootstrap] failed to create/resolve project (http ${project_code})" >&2
  log_infisical_response "project create/resolve" "$project_tmp"
  exit 1
fi

PROJECT_ID=$(jq -r '.id // .project.id // empty' "$project_tmp")
if [ -z "$PROJECT_ID" ]; then
  echo "[infisical-bootstrap] unable to resolve project id" >&2
  log_infisical_response "project id lookup" "$project_tmp"
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

SEED_USER_ACCESS_TOKEN=""

login_seed_user() {
  local login_payload login_tmp login_code
  local select_payload select_tmp select_code selected_token

  login_payload=$(jq -n \
    --arg email "$INFISICAL_EMAIL" \
    --arg password "$INFISICAL_PASSWORD" \
    '{email:$email, password:$password}')
  login_tmp=$(mktemp)
  login_code=$(curl -sS -o "$login_tmp" -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -H "User-Agent: infrazero-bootstrap/1.0" \
    -d "$login_payload" \
    "${INFISICAL_SITE_URL}/api/v3/auth/login" || true)

  if [[ "$login_code" != 2* ]]; then
    echo "[infisical-bootstrap] failed to log in seed admin via /api/v3/auth/login (http ${login_code})" >&2
    log_infisical_response "seed login" "$login_tmp"
    rm -f "$login_tmp"
    return 1
  fi

  SEED_USER_ACCESS_TOKEN=$(jq -r '.accessToken // empty' "$login_tmp")
  rm -f "$login_tmp"
  if [ -z "$SEED_USER_ACCESS_TOKEN" ]; then
    echo "[infisical-bootstrap] /api/v3/auth/login response missing accessToken" >&2
    return 1
  fi

  if [ -z "${ORGANIZATION_ID:-}" ]; then
    echo "[infisical-bootstrap] organization id is missing; cannot scope seed token to organization" >&2
    return 1
  fi

  select_payload=$(jq -n \
    --arg organization_id "$ORGANIZATION_ID" \
    '{"organizationId":$organization_id,"userAgent":"cli"}')
  select_tmp=$(mktemp)
  select_code=$(curl -sS -o "$select_tmp" -w "%{http_code}" \
    -H "Authorization: Bearer ${SEED_USER_ACCESS_TOKEN}" \
    -H "Content-Type: application/json" \
    -H "User-Agent: infrazero-bootstrap/1.0" \
    -d "$select_payload" \
    "${INFISICAL_SITE_URL}/api/v3/auth/select-organization" || true)

  if [[ "$select_code" != 2* ]]; then
    echo "[infisical-bootstrap] failed to select organization for seed admin (http ${select_code})" >&2
    log_infisical_response "seed select organization" "$select_tmp"
    rm -f "$select_tmp"
    return 1
  fi

  selected_token=$(jq -r '.token // empty' "$select_tmp")
  rm -f "$select_tmp"
  if [ -z "$selected_token" ]; then
    echo "[infisical-bootstrap] /api/v3/auth/select-organization response missing token" >&2
    return 1
  fi
  SEED_USER_ACCESS_TOKEN="$selected_token"
  return 0
}

derive_first_name() {
  local email="$1" local_part candidate
  local_part="${email%@*}"
  candidate=$(echo "$local_part" | sed -E 's/[^A-Za-z0-9]+/ /g' | awk '{print $1}')
  if [ -z "$candidate" ]; then
    candidate="Admin"
  fi
  echo "$candidate"
}

parse_query_param_from_link() {
  local link="$1"
  local key="$2"
  local value=""
  if command -v python3 >/dev/null 2>&1; then
    value=$(python3 - "$link" "$key" <<'PY'
import sys
from urllib.parse import urlparse, parse_qs, unquote

link = sys.argv[1] if len(sys.argv) > 1 else ""
key = sys.argv[2] if len(sys.argv) > 2 else ""
parsed = urlparse(link)
qs = parse_qs(parsed.query, keep_blank_values=True)
value = (qs.get(key) or [""])[0]
print(unquote(value))
PY
    ) || true
  fi

  if [ -z "$value" ]; then
    case "$key" in
      token)
        value=$(echo "$link" | sed -n 's/.*[?&]token=\([^&]*\).*/\1/p')
        ;;
      to)
        value=$(echo "$link" | sed -n 's/.*[?&]to=\([^&]*\).*/\1/p')
        ;;
      organization_id)
        value=$(echo "$link" | sed -n 's/.*[?&]organization_id=\([^&]*\).*/\1/p')
        ;;
    esac
  fi

  value=$(printf '%s' "$value" | tr -d '\r\n')
  echo "$value"
}

parse_signup_code_from_link() {
  parse_query_param_from_link "$1" "token"
}

parse_invite_email_from_link() {
  parse_query_param_from_link "$1" "to"
}

parse_invite_org_from_link() {
  parse_query_param_from_link "$1" "organization_id"
}

exchange_invite_code_for_signup_token() {
  local email="$1"
  local organization_id="$2"
  local invite_code="$3"
  local verify_payload verify_tmp verify_code signup_token

  verify_payload=$(jq -n \
    --arg email "$email" \
    --arg organization_id "$organization_id" \
    --arg code "$invite_code" \
    '{email:$email, organizationId:$organization_id, code:$code}')
  verify_tmp=$(mktemp)
  verify_code=$(curl -sS -o "$verify_tmp" -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -H "User-Agent: infrazero-bootstrap/1.0" \
    -d "$verify_payload" \
    "${INFISICAL_API_BASE}/v1/invite-org/verify" || true)

  if [[ "$verify_code" != 2* ]]; then
    echo "[infisical-bootstrap] failed to verify invite code for ${email} (http ${verify_code})" >&2
    log_infisical_response "verify invite ${email}" "$verify_tmp"
    rm -f "$verify_tmp"
    return 1
  fi

  signup_token=$(jq -r '.token // empty' "$verify_tmp" 2>/dev/null || true)
  rm -f "$verify_tmp"
  if [ -z "$signup_token" ]; then
    echo "[infisical-bootstrap] invite verify response missing signup token for ${email}" >&2
    return 1
  fi
  printf '%s' "$signup_token"
  return 0
}

complete_invited_user_signup() {
  local email="$1"
  local password="$2"
  local signup_token="$3"
  local first_name complete_payload complete_tmp complete_code message token_dot_count

  # Some Infisical responses include "Bearer <jwt>" in token fields.
  # This endpoint expects the raw JWT in the bearer header value.
  signup_token="${signup_token#Bearer }"
  signup_token="${signup_token#bearer }"

  token_dot_count=$(printf '%s' "$signup_token" | awk -F'.' '{print NF-1}')
  if [ "$token_dot_count" -ne 2 ]; then
    echo "[infisical-bootstrap] extracted signup token for ${email} is not a JWT (segments=$((token_dot_count+1)))" >&2
    return 1
  fi

  first_name=$(derive_first_name "$email")
  complete_payload=$(jq -n \
    --arg email "$email" \
    --arg password "$password" \
    --arg first_name "$first_name" \
    '{email:$email, password:$password, firstName:$first_name}')
  complete_tmp=$(mktemp)
  complete_code=$(curl -sS -o "$complete_tmp" -w "%{http_code}" \
    -H "Authorization: Bearer ${signup_token}" \
    -H "Content-Type: application/json" \
    -H "User-Agent: infrazero-bootstrap/1.0" \
    -d "$complete_payload" \
    "${INFISICAL_SITE_URL}/api/v3/signup/complete-account/invite" || true)

  if [[ "$complete_code" != 2* ]]; then
    message=$(jq -r '.message // empty' "$complete_tmp" 2>/dev/null || true)
    if echo "$message" | grep -Eqi "already|accepted|complete"; then
      echo "[infisical-bootstrap] ${email} already has a completed account; continuing"
      rm -f "$complete_tmp"
      return 0
    fi
    echo "[infisical-bootstrap] failed to complete invited signup for ${email} (http ${complete_code})" >&2
    log_infisical_response "complete invited signup ${email}" "$complete_tmp"
    rm -f "$complete_tmp"
    return 1
  fi

  rm -f "$complete_tmp"
  return 0
}

provision_platform_admin_local_users() {
  local extra_admin_count

  if [ -z "${PLATFORM_ADMINS_JSON:-}" ]; then
    return 0
  fi
  if ! command -v jq >/dev/null 2>&1; then
    echo "[infisical-bootstrap] jq is required to process PLATFORM_ADMINS_JSON" >&2
    return 1
  fi
  if [ -z "$ORGANIZATION_ID" ]; then
    echo "[infisical-bootstrap] organization id is missing from bootstrap response; cannot provision local users" >&2
    return 1
  fi

  extra_admin_count=$(echo "$PLATFORM_ADMINS_JSON" | jq --arg seed "${INFISICAL_EMAIL,,}" '[.[]? | select((.email // "" | ascii_downcase) != $seed and (.email // "") != "" and (.infisical_password // "") != "")] | length' 2>/dev/null || echo "0")
  if [ "$extra_admin_count" = "0" ]; then
    return 0
  fi

  if ! login_seed_user; then
    return 1
  fi

  while read -r admin; do
    local email password invite_payload invite_tmp invite_code invite_link signup_code signup_token message
    local invite_email invite_org_id token_dot_count
    email=$(echo "$admin" | jq -r '.email // empty' | tr '[:upper:]' '[:lower:]')
    password=$(echo "$admin" | jq -r '.infisical_password // empty')

    if [ -z "$email" ] || [ -z "$password" ]; then
      continue
    fi
    if [ "$email" = "${INFISICAL_EMAIL,,}" ]; then
      continue
    fi

    invite_payload=$(jq -n \
      --arg email "$email" \
      --arg org "$ORGANIZATION_ID" \
      '{inviteeEmails:[$email], organizationId:$org, organizationRoleSlug:"admin"}')
    invite_tmp=$(mktemp)
    invite_code=$(curl -sS -o "$invite_tmp" -w "%{http_code}" \
      -H "Authorization: Bearer ${SEED_USER_ACCESS_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "$invite_payload" \
      "${INFISICAL_API_BASE}/v1/invite-org/signup" || true)

    if [[ "$invite_code" != 2* ]]; then
      message=$(jq -r '.message // empty' "$invite_tmp" 2>/dev/null || true)
      if echo "$message" | grep -Eqi "already|exists|accepted|member"; then
        echo "[infisical-bootstrap] invite skipped for ${email}; membership already exists"
        rm -f "$invite_tmp"
        continue
      fi
      echo "[infisical-bootstrap] failed to create invite for ${email} (http ${invite_code})" >&2
      log_infisical_response "invite ${email}" "$invite_tmp"
      rm -f "$invite_tmp"
      return 1
    fi

    invite_link=$(jq -r '.completeInviteLinks[0].link // .signUpTokens[0].link // empty' "$invite_tmp" 2>/dev/null || true)
    rm -f "$invite_tmp"

    if [ -z "$invite_link" ]; then
      echo "[infisical-bootstrap] no completeInviteLinks token returned for ${email}; skipping password provisioning"
      continue
    fi

    signup_code=$(parse_signup_code_from_link "$invite_link")
    if [ -z "$signup_code" ]; then
      echo "[infisical-bootstrap] unable to extract signup token for ${email}" >&2
      return 1
    fi
    signup_token="$signup_code"
    token_dot_count=$(printf '%s' "$signup_token" | awk -F'.' '{print NF-1}')
    if [ "$token_dot_count" -ne 2 ]; then
      invite_email=$(parse_invite_email_from_link "$invite_link")
      invite_org_id=$(parse_invite_org_from_link "$invite_link")
      if [ -z "$invite_email" ]; then
        invite_email="$email"
      fi
      invite_email=$(printf '%s' "$invite_email" | tr '[:upper:]' '[:lower:]')
      if [ -z "$invite_org_id" ]; then
        invite_org_id="$ORGANIZATION_ID"
      fi
      signup_token=$(exchange_invite_code_for_signup_token "$invite_email" "$invite_org_id" "$signup_code") || return 1
    fi

    complete_invited_user_signup "$email" "$password" "$signup_token" || return 1
  done < <(echo "$PLATFORM_ADMINS_JSON" | jq -c '.[]?' 2>/dev/null || true)

  return 0
}

provision_platform_admin_local_users

ensure_project_membership() {
  local email="$1"
  local membership_payload membership_tmp membership_code message

  if [ -z "$email" ]; then
    return 0
  fi

  membership_payload=$(jq -n \
    --arg email "$email" \
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
      echo "[infisical-bootstrap] ${email} already added to project; continuing"
    else
      echo "[infisical-bootstrap] failed to add ${email} to project (http ${membership_code})" >&2
      log_infisical_response "project membership ${email}" "$membership_tmp"
      rm -f "$membership_tmp"
      return 1
    fi
  fi
  rm -f "$membership_tmp"
  return 0
}

declare -A membership_emails_seen
membership_emails_seen["${INFISICAL_EMAIL,,}"]=1
ensure_project_membership "$INFISICAL_EMAIL"

if [ -n "${PLATFORM_ADMINS_JSON:-}" ] && command -v jq >/dev/null 2>&1; then
  while IFS= read -r platform_email; do
    [ -z "$platform_email" ] && continue
    key="${platform_email,,}"
    if [ -n "${membership_emails_seen[$key]:-}" ]; then
      continue
    fi
    membership_emails_seen["$key"]=1
    ensure_project_membership "$platform_email"
  done < <(echo "$PLATFORM_ADMINS_JSON" | jq -r '.[]?.email // empty' 2>/dev/null || true)
fi

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

if [ -z "${INFISICAL_BOOTSTRAP_SECRETS:-}" ] && [ -n "${INFISICAL_BOOTSTRAP_SECRETS_GZ_B64:-}" ]; then
  if ! command -v python3 >/dev/null 2>&1; then
    echo "[infisical-bootstrap] python3 required to decode INFISICAL_BOOTSTRAP_SECRETS_GZ_B64" >&2
    exit 1
  fi
  if ! INFISICAL_BOOTSTRAP_SECRETS=$(python3 - <<'PY'
import base64
import gzip
import os
import sys

data = os.environ.get("INFISICAL_BOOTSTRAP_SECRETS_GZ_B64", "")
try:
    decoded = base64.b64decode(data.encode("utf-8"))
    sys.stdout.write(gzip.decompress(decoded).decode("utf-8"))
except Exception:
    raise SystemExit(1)
PY
  ); then
    echo "[infisical-bootstrap] failed to decode INFISICAL_BOOTSTRAP_SECRETS_GZ_B64" >&2
    exit 1
  fi
fi

# Merge split payload secrets (INFISICAL_BOOTSTRAP_SECRETS__*) into the
# canonical INFISICAL_BOOTSTRAP_SECRETS object expected below.
split_vars=$(compgen -A variable INFISICAL_BOOTSTRAP_SECRETS__ || true)
if [ -n "$split_vars" ]; then
  payloads_tmp=$(mktemp)
  if [ -n "${INFISICAL_BOOTSTRAP_SECRETS:-}" ]; then
    printf '%s\n' "$INFISICAL_BOOTSTRAP_SECRETS" >> "$payloads_tmp"
  fi

  while read -r var_name; do
    [ -z "$var_name" ] && continue
    payload_value="${!var_name:-}"
    [ -z "$payload_value" ] && continue
    printf '%s\n' "$payload_value" >> "$payloads_tmp"
  done <<< "$split_vars"

  if [ -s "$payloads_tmp" ]; then
    if ! INFISICAL_BOOTSTRAP_SECRETS=$(jq -cs '
      reduce .[] as $item ({};
        if ($item | type) != "object" then
          error("bootstrap payload entry must be a JSON object")
        else
          reduce ($item | to_entries[]) as $folder (.;
            if ($folder.value | type) != "array" then
              error("bootstrap folder payload must be an array")
            else
              .[$folder.key] = ((.[ $folder.key ] // []) + $folder.value)
            end
          )
        end
      )' "$payloads_tmp"); then
      rm -f "$payloads_tmp"
      echo "[infisical-bootstrap] failed to merge split INFISICAL_BOOTSTRAP_SECRETS payloads" >&2
      exit 1
    fi
  fi

  rm -f "$payloads_tmp"
fi

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
    log_infisical_response "secret upsert ${secret_name}" "$tmp"
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
    folder_norm=$(printf '%s' "$folder_path" | sed -E 's#^/+##; s#/*$##')
    folder_norm_lc=$(printf '%s' "$folder_norm" | tr '[:upper:]' '[:lower:]')
    decode_values="true"
    # The UI base64-encodes secret values for non-infra folders. Keep infra plain.
    if [ "$folder_norm_lc" = "infra" ] || [[ "$folder_norm_lc" == infra/* ]]; then
      decode_values="false"
    fi
    echo "$folder_entry" | jq -c '.value[]' | while read -r secret_entry; do
      secret_name=$(echo "$secret_entry" | jq -r 'keys[0]')
      env_map=$(echo "$secret_entry" | jq -c '.[keys[0]]')
      echo "$env_map" | jq -r 'keys[]' | while read -r env_slug; do
        secret_value=$(echo "$env_map" | jq -r --arg env "$env_slug" '.[$env]')
        if [ "$secret_value" = "null" ]; then
          continue
        fi
        if [ "$decode_values" = "true" ]; then
          # Decode as bytes, keep special characters/newlines intact for jq/curl.
          if ! decoded_value=$(printf '%s' "$secret_value" | base64 -d 2>/dev/null); then
            echo "[infisical-bootstrap] failed to base64 decode secret ${secret_name} (${env_slug}:${folder_path})" >&2
            exit 1
          fi
          secret_value="$decoded_value"
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
