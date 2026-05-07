#!/usr/bin/env bash
set -euo pipefail

# Clean Terraform state and bootstrap artifacts from S3 Object Storage.
# This allows a fresh deploy without "name already used" errors.
#
# Usage:
#   S3_ACCESS_KEY_ID=... S3_SECRET_ACCESS_KEY=... S3_ENDPOINT=... \
#     bash scripts/clean-s3-state.sh <bucket-name> [prefix]
#
# Examples:
#   bash scripts/clean-s3-state.sh darkspidertest-infra-state
#   bash scripts/clean-s3-state.sh darkspidertest-infra-state infrazero/dev

BUCKET="${1:-}"
PREFIX="${2:-}"

if [ -z "$BUCKET" ]; then
  echo "Usage: $0 <bucket-name> [prefix]" >&2
  echo "" >&2
  echo "Required env vars:" >&2
  echo "  S3_ACCESS_KEY_ID" >&2
  echo "  S3_SECRET_ACCESS_KEY" >&2
  echo "  S3_ENDPOINT (e.g. https://hel1.your-objectstorage.com)" >&2
  exit 1
fi

for var in S3_ACCESS_KEY_ID S3_SECRET_ACCESS_KEY S3_ENDPOINT; do
  if [ -z "${!var:-}" ]; then
    echo "Error: $var is required" >&2
    exit 1
  fi
done

if [[ "$S3_ENDPOINT" != http://* && "$S3_ENDPOINT" != https://* ]]; then
  S3_ENDPOINT="https://${S3_ENDPOINT}"
fi

export AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$S3_SECRET_ACCESS_KEY"
export AWS_DEFAULT_REGION="${S3_REGION:-us-east-1}"

S3_PATH="s3://${BUCKET}"
if [ -n "$PREFIX" ]; then
  S3_PATH="s3://${BUCKET}/${PREFIX}"
fi

echo "=== S3 State Cleanup ==="
echo "Endpoint: $S3_ENDPOINT"
echo "Path:     $S3_PATH"
echo ""

# List what will be deleted
echo "Files to delete:"
aws --endpoint-url "$S3_ENDPOINT" s3 ls "$S3_PATH/" --recursive 2>/dev/null || true
echo ""

read -r -p "Delete all files in ${S3_PATH}? [y/N] " confirm
if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
  echo "Aborted."
  exit 0
fi

echo "Deleting..."
aws --endpoint-url "$S3_ENDPOINT" s3 rm "$S3_PATH/" --recursive

echo ""
echo "Done. S3 state cleaned. You can now deploy fresh."
