#!/usr/bin/env bash
set -euo pipefail

if [ "${1:-}" = "" ]; then
  echo "usage: $0 <tfvars-json-path>" >&2
  exit 1
fi

TFVARS_PATH="$1"
if [ ! -f "$TFVARS_PATH" ]; then
  echo "[offload-egress-secrets] tfvars file not found: $TFVARS_PATH" >&2
  exit 1
fi

if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  echo "[offload-egress-secrets] python3/python interpreter not found" >&2
  exit 1
fi

PAYLOAD_FILE="build/bootstrap/egress-bootstrap-secrets.env"
mkdir -p "$(dirname "$PAYLOAD_FILE")"

EXTRACT_RESULT=$("$PYTHON_BIN" - "$TFVARS_PATH" "$PAYLOAD_FILE" <<'PY'
import json
import pathlib
import shlex
import sys

tfvars_path = pathlib.Path(sys.argv[1])
payload_file = pathlib.Path(sys.argv[2])
data = json.loads(tfvars_path.read_text(encoding="utf-8"))

egress_secrets = data.get("egress_secrets")
if not isinstance(egress_secrets, dict):
    print('{"offloaded":false}')
    raise SystemExit(0)

offload = {}
for key in ("INFISICAL_BOOTSTRAP_SECRETS", "INFISICAL_BOOTSTRAP_SECRETS_GZ_B64"):
    value = egress_secrets.get(key, "")
    if isinstance(value, str) and value:
        offload[key] = value

if not offload:
    print('{"offloaded":false}')
    raise SystemExit(0)

with payload_file.open("w", encoding="utf-8", newline="\n") as handle:
    for key in sorted(offload):
        handle.write(f"{key}={shlex.quote(offload[key])}\n")

for key in offload:
    egress_secrets.pop(key, None)

tfvars_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

print(json.dumps({
    "offloaded": True,
    "payload_file": str(payload_file).replace("\\", "/"),
    "payload_bytes": payload_file.stat().st_size,
}))
PY
)

OFFLOADED=$(printf '%s' "$EXTRACT_RESULT" | "$PYTHON_BIN" -c 'import json,sys;print("true" if json.loads(sys.stdin.read()).get("offloaded") else "false")')
if [ "$OFFLOADED" != "true" ]; then
  echo "[offload-egress-secrets] no oversized bootstrap payload found; skipping."
  exit 0
fi

if [ -z "${S3_ENDPOINT:-}" ] || [ -z "${INFRA_STATE_BUCKET:-}" ]; then
  echo "[offload-egress-secrets] required env missing (S3_ENDPOINT, INFRA_STATE_BUCKET)" >&2
  exit 1
fi

RUN_ID="${GITHUB_RUN_ID:-local}"
RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-0}"
OBJECT_KEY="bootstrap/egress-bootstrap-secrets/${RUN_ID}-${RUN_ATTEMPT}.env"
PAYLOAD_PRESIGN_EXPIRY="${OFFLOADED_BOOTSTRAP_SECRETS_PRESIGN_EXPIRY:-604800}"

if ! printf '%s' "$PAYLOAD_PRESIGN_EXPIRY" | grep -Eq '^[0-9]+$'; then
  PAYLOAD_PRESIGN_EXPIRY="604800"
fi
if [ "$PAYLOAD_PRESIGN_EXPIRY" -gt 604800 ]; then
  PAYLOAD_PRESIGN_EXPIRY="604800"
fi
if [ "$PAYLOAD_PRESIGN_EXPIRY" -lt 60 ]; then
  PAYLOAD_PRESIGN_EXPIRY="60"
fi

aws --endpoint-url "$S3_ENDPOINT" s3 cp "$PAYLOAD_FILE" "s3://${INFRA_STATE_BUCKET}/${OBJECT_KEY}"
PAYLOAD_URL=$(aws --endpoint-url "$S3_ENDPOINT" s3 presign "s3://${INFRA_STATE_BUCKET}/${OBJECT_KEY}" --expires-in "$PAYLOAD_PRESIGN_EXPIRY")
PAYLOAD_SHA256=$(sha256sum "$PAYLOAD_FILE" | awk '{print $1}')

"$PYTHON_BIN" - "$TFVARS_PATH" "$PAYLOAD_URL" "$PAYLOAD_SHA256" "$S3_ENDPOINT" "$INFRA_STATE_BUCKET" "$OBJECT_KEY" <<'PY'
import json
import pathlib
import sys

tfvars_path = pathlib.Path(sys.argv[1])
payload_url = sys.argv[2]
payload_sha256 = sys.argv[3]
s3_endpoint = sys.argv[4]
s3_bucket = sys.argv[5]
s3_key = sys.argv[6]

data = json.loads(tfvars_path.read_text(encoding="utf-8"))
egress_secrets = data.get("egress_secrets")
if not isinstance(egress_secrets, dict):
    raise SystemExit("egress_secrets missing in tfvars after offload extraction")

egress_secrets["INFISICAL_BOOTSTRAP_SECRETS_ENV_URL"] = payload_url
egress_secrets["INFISICAL_BOOTSTRAP_SECRETS_ENV_SHA256"] = payload_sha256
egress_secrets["INFISICAL_BOOTSTRAP_SECRETS_ENV_ENDPOINT"] = s3_endpoint
egress_secrets["INFISICAL_BOOTSTRAP_SECRETS_ENV_BUCKET"] = s3_bucket
egress_secrets["INFISICAL_BOOTSTRAP_SECRETS_ENV_KEY"] = s3_key

tfvars_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
PY

rm -f "$PAYLOAD_FILE"
echo "[offload-egress-secrets] offloaded INFISICAL bootstrap payload and updated tfvars."
