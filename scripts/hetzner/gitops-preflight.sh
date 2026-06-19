#!/usr/bin/env bash
set -euo pipefail

echo "[gitops-preflight] starting"

if [ -z "${GH_GITOPS_REPO:-}" ]; then
  echo "[gitops-preflight] GH_GITOPS_REPO not set; GitOps preflight skipped"
  exit 0
fi

if [ -z "${GH_TOKEN:-}" ]; then
  echo "[gitops-preflight] ERROR config/GITHUB_TOKEN_MISSING: GH_TOKEN is required when GH_GITOPS_REPO is set" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "[gitops-preflight] ERROR script/CURL_MISSING: curl is required for GitOps preflight" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "[gitops-preflight] ERROR script/PYTHON3_MISSING: python3 is required for GitOps preflight" >&2
  exit 1
fi

repo_ref="${GH_GITOPS_REPO}"
repo_ref="${repo_ref#https://github.com/}"
repo_ref="${repo_ref#http://github.com/}"
repo_ref="${repo_ref%.git}"
repo_ref="${repo_ref#/}"
repo_ref="${repo_ref%/}"

if [[ "$repo_ref" != */* ]]; then
  if [ -z "${GH_OWNER:-}" ]; then
    echo "[gitops-preflight] ERROR config/GH_OWNER_MISSING: GH_OWNER is required when GH_GITOPS_REPO is not owner/repo" >&2
    exit 1
  fi
  repo_ref="${GH_OWNER}/${repo_ref}"
fi

repo_owner="${repo_ref%%/*}"
repo_name="${repo_ref#*/}"

if [ -z "$repo_owner" ] || [ -z "$repo_name" ] || [[ "$repo_name" == */* ]]; then
  echo "[gitops-preflight] ERROR config/GITOPS_REPO_INVALID: GH_GITOPS_REPO must be repo, owner/repo, or github.com URL" >&2
  exit 1
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

headers_file="${tmpdir}/headers"
body_file="${tmpdir}/body.json"

github_api() {
  local method="$1"
  local path="$2"
  local output_file="$3"
  local http_code
  http_code=$(curl -sS \
    -X "$method" \
    -D "$headers_file" \
    -o "$output_file" \
    -w "%{http_code}" \
    -H "Authorization: Bearer ${GH_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com${path}" || true)
  printf '%s' "$http_code"
}

user_code=$(github_api GET "/user" "$body_file")
if [ "$user_code" != "200" ]; then
  echo "[gitops-preflight] ERROR auth/GITHUB_TOKEN_INVALID: GET /user returned HTTP ${user_code}" >&2
  python3 - "$body_file" <<'PY' >&2 || true
import json
import sys
from pathlib import Path
try:
    data = json.loads(Path(sys.argv[1]).read_text())
except Exception:
    raise SystemExit(0)
message = data.get("message")
if message:
    print(f"[gitops-preflight] GitHub response: {message}")
PY
  exit 1
fi

scopes=$(awk '
  {
    line=$0
    sub(/\r$/, "", line)
    if (tolower(line) ~ /^x-oauth-scopes:/) {
      sub(/^[^:]*:[[:space:]]*/, "", line)
      value=line
    }
  }
  END {print value}
' "$headers_file")
scopes_compact=$(printf '%s' "$scopes" | tr -d '[:space:]')
scopes_compact=",${scopes_compact},"
missing_scopes=()
if [[ "$scopes_compact" != *",repo,"* ]]; then
  missing_scopes+=("repo")
fi
if [[ "$scopes_compact" != *",workflow,"* ]]; then
  missing_scopes+=("workflow")
fi
if [ "${#missing_scopes[@]}" -gt 0 ]; then
  echo "[gitops-preflight] ERROR auth/GITHUB_TOKEN_SCOPE_MISSING: GH_TOKEN must include scopes: ${missing_scopes[*]} (x-oauth-scopes='${scopes:-<empty>}')" >&2
  exit 1
fi

repo_code=$(github_api GET "/repos/${repo_owner}/${repo_name}" "$body_file")
if [ "$repo_code" != "200" ]; then
  echo "[gitops-preflight] ERROR auth/GITOPS_REPO_INACCESSIBLE: GET /repos/${repo_owner}/${repo_name} returned HTTP ${repo_code}" >&2
  python3 - "$body_file" <<'PY' >&2 || true
import json
import sys
from pathlib import Path
try:
    data = json.loads(Path(sys.argv[1]).read_text())
except Exception:
    raise SystemExit(0)
message = data.get("message")
if message:
    print(f"[gitops-preflight] GitHub response: {message}")
PY
  exit 1
fi

default_branch=$(python3 - "$body_file" <<'PY'
import json
import sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text())
value = data.get("default_branch") or ""
print(value)
PY
)

if [ -z "$default_branch" ]; then
  echo "[gitops-preflight] ERROR config/GIT_REPO_NO_DEFAULT_BRANCH: GitOps repo ${repo_owner}/${repo_name} has no default branch. Initialize the repo or enable initial commit creation before deploy." >&2
  exit 1
fi

branch_code=$(github_api GET "/repos/${repo_owner}/${repo_name}/branches/${default_branch}" "$body_file")
if [ "$branch_code" != "200" ]; then
  echo "[gitops-preflight] ERROR config/GIT_REPO_NO_DEFAULT_BRANCH: default branch '${default_branch}' is not readable for ${repo_owner}/${repo_name} (HTTP ${branch_code})" >&2
  exit 1
fi

echo "[gitops-preflight] ok: token scopes and GitOps repo ${repo_owner}/${repo_name}@${default_branch} are valid"
