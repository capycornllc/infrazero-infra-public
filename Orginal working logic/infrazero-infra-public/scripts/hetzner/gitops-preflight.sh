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
  local input_file="${4:-}"
  local http_code
  local curl_args=(
    -sS
    -X "$method" \
    -D "$headers_file" \
    -o "$output_file" \
    -w "%{http_code}" \
    -H "Authorization: Bearer ${GH_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28"
  )
  if [ -n "$input_file" ]; then
    curl_args+=(-H "Content-Type: application/json" --data-binary "@${input_file}")
  fi
  http_code=$(curl "${curl_args[@]}" "https://api.github.com${path}" || true)
  printf '%s' "$http_code"
}

create_initial_commit() {
  local request_file="${tmpdir}/initial-readme.json"
  python3 - "$request_file" <<'PY'
import base64
import json
import sys
from pathlib import Path

content = """# Infrazero GitOps

Initial commit created automatically by Infrazero so deployment can sync GitOps manifests.
"""

Path(sys.argv[1]).write_text(json.dumps({
    "message": "Infrazero: initialize GitOps repo",
    "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
}), encoding="utf-8")
PY

  local init_code
  init_code=$(github_api PUT "/repos/${repo_owner}/${repo_name}/contents/README.md" "$body_file" "$request_file")
  if [ "$init_code" != "200" ] && [ "$init_code" != "201" ]; then
    echo "[gitops-preflight] ERROR config/GIT_REPO_INITIAL_COMMIT_FAILED: failed to create README.md initial commit in ${repo_owner}/${repo_name} (HTTP ${init_code})" >&2
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
  echo "[gitops-preflight] initialized empty GitOps repo ${repo_owner}/${repo_name} with README.md"
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
  create_initial_commit
  repo_code=$(github_api GET "/repos/${repo_owner}/${repo_name}" "$body_file")
  if [ "$repo_code" != "200" ]; then
    echo "[gitops-preflight] ERROR auth/GITOPS_REPO_INACCESSIBLE: GET /repos/${repo_owner}/${repo_name} returned HTTP ${repo_code} after initial commit" >&2
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
fi

branch_code=$(github_api GET "/repos/${repo_owner}/${repo_name}/branches/${default_branch}" "$body_file")
if [ "$branch_code" != "200" ]; then
  if [ "$branch_code" = "404" ]; then
    create_initial_commit
    repo_code=$(github_api GET "/repos/${repo_owner}/${repo_name}" "$body_file")
    if [ "$repo_code" = "200" ]; then
      default_branch=$(python3 - "$body_file" <<'PY'
import json
import sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text())
value = data.get("default_branch") or ""
print(value)
PY
)
    fi
    branch_code=$(github_api GET "/repos/${repo_owner}/${repo_name}/branches/${default_branch}" "$body_file")
  fi
fi
if [ "$branch_code" != "200" ]; then
  echo "[gitops-preflight] ERROR config/GIT_REPO_NO_DEFAULT_BRANCH: default branch '${default_branch}' is not readable for ${repo_owner}/${repo_name} (HTTP ${branch_code})" >&2
  exit 1
fi

echo "[gitops-preflight] ok: token scopes and GitOps repo ${repo_owner}/${repo_name}@${default_branch} are valid"
