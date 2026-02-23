#!/usr/bin/env python3
"""Export Infisical bootstrap secrets from GitHub secrets JSON into GITHUB_ENV."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

SPLIT_PREFIX = "INFISICAL_BOOTSTRAP_SECRETS__"
LEGACY_JSON_KEYS = ("INFISICAL_BOOTSTRAP_SECRETS", "infisical_bootstrap_secrets")
LEGACY_GZ_KEYS = ("INFISICAL_BOOTSTRAP_SECRETS_GZ_B64", "infisical_bootstrap_secrets_gz_b64")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export split Infisical bootstrap secrets to a GitHub env file."
    )
    parser.add_argument(
        "--secrets-json",
        required=True,
        help="Path to JSON generated from ${{ toJson(secrets) }}",
    )
    parser.add_argument(
        "--github-env",
        required=True,
        help="Path to GITHUB_ENV file to append exports into",
    )
    return parser.parse_args()


def load_secrets(path: Path) -> Dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid secrets JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit("Secrets JSON must be an object")
    return payload


def to_env_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def validate_split_payload(name: str, payload_raw: str) -> None:
    if not payload_raw.strip():
        return
    try:
        parsed = json.loads(payload_raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{name} is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SystemExit(f"{name} must be a JSON object")


def find_split_secrets(secrets: Dict[str, Any]) -> List[Tuple[str, str]]:
    collected: List[Tuple[str, str]] = []
    for key, raw_value in secrets.items():
        normalized = key.upper()
        if not normalized.startswith(SPLIT_PREFIX):
            continue
        value = to_env_value(raw_value)
        validate_split_payload(normalized, value)
        if value.strip():
            collected.append((normalized, value))
    collected.sort(key=lambda item: item[0])
    return collected


def find_legacy_secret(secrets: Dict[str, Any], candidates: Tuple[str, ...]) -> str:
    for key in candidates:
        if key in secrets:
            value = to_env_value(secrets[key]).strip()
            if value:
                return value
    return ""


def write_multiline_env(path: Path, key: str, value: str) -> None:
    marker = "__INFRAZERO_EOF__"
    while marker in value:
        marker += "_X"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{key}<<{marker}\n")
        handle.write(value)
        handle.write("\n")
        handle.write(f"{marker}\n")


def main() -> None:
    args = parse_args()
    secrets = load_secrets(Path(args.secrets_json))
    github_env_path = Path(args.github_env)

    split = find_split_secrets(secrets)
    if split:
        for key, value in split:
            write_multiline_env(github_env_path, key, value)
        print(f"Exported {len(split)} split Infisical bootstrap secret payload(s).")
        return

    legacy_json = find_legacy_secret(secrets, LEGACY_JSON_KEYS)
    legacy_gz = find_legacy_secret(secrets, LEGACY_GZ_KEYS)
    if legacy_json:
        validate_split_payload("INFISICAL_BOOTSTRAP_SECRETS", legacy_json)
        write_multiline_env(github_env_path, "INFISICAL_BOOTSTRAP_SECRETS", legacy_json)
        print("Exported legacy INFISICAL_BOOTSTRAP_SECRETS payload.")
    elif legacy_gz:
        write_multiline_env(github_env_path, "INFISICAL_BOOTSTRAP_SECRETS_GZ_B64", legacy_gz)
        print("Exported legacy INFISICAL_BOOTSTRAP_SECRETS_GZ_B64 payload.")
    else:
        print("No Infisical bootstrap payload secrets found.")


if __name__ == "__main__":
    main()
