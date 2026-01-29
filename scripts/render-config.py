import argparse
import json
import os
import sys
from pathlib import Path

import yaml

REQUIRED_ROLES = ["bastion", "egress", "node1", "node2", "db"]


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text()) or {}


def load_json(path: Path):
    return json.loads(path.read_text())


def main() -> int:
    parser = argparse.ArgumentParser(description="Render config/infra.yaml into tofu.tfvars.json")
    parser.add_argument("--config", default="config/infra.yaml")
    parser.add_argument("--output", default="tofu/tofu.tfvars.json")
    parser.add_argument("--bootstrap-artifacts", default=None)
    args = parser.parse_args()

    config_path = Path(args.config)
    output_path = Path(args.output)

    config = load_yaml(config_path)

    project_slug = os.getenv("PROJECT_SLUG", "").strip()
    environment = str(config.get("environment", "")).strip()
    if project_slug:
        if environment:
            config["name_prefix"] = f"{project_slug}-{environment}"
        else:
            config["name_prefix"] = project_slug

    services = {svc.get("name") for svc in config.get("load_balancer", {}).get("services", [])}
    missing_services = [svc for svc in ("http", "https") if svc not in services]
    if missing_services:
        print(f"load_balancer.services must include: {', '.join(missing_services)}", file=sys.stderr)
        return 1

    ssh_keys_json = os.getenv("OPS_SSH_KEYS_JSON")
    if not ssh_keys_json:
        print("OPS_SSH_KEYS_JSON is required to render ssh_public_keys", file=sys.stderr)
        return 1
    try:
        raw_keys = json.loads(ssh_keys_json)
    except json.JSONDecodeError as exc:
        print(f"OPS_SSH_KEYS_JSON is not valid JSON: {exc}", file=sys.stderr)
        return 1

    ssh_public_keys = []
    if isinstance(raw_keys, dict):
        for value in raw_keys.values():
            if isinstance(value, list):
                ssh_public_keys.extend(value)
            elif isinstance(value, str):
                ssh_public_keys.append(value)
            else:
                print("OPS_SSH_KEYS_JSON values must be strings or lists of strings", file=sys.stderr)
                return 1
    elif isinstance(raw_keys, list):
        ssh_public_keys = raw_keys
    else:
        print("OPS_SSH_KEYS_JSON must be a map or list", file=sys.stderr)
        return 1

    ssh_public_keys = [key for key in ssh_public_keys if isinstance(key, str) and key.strip()]
    if not ssh_public_keys:
        print("OPS_SSH_KEYS_JSON did not contain any SSH public keys", file=sys.stderr)
        return 1

    config["ssh_public_keys"] = ssh_public_keys

    missing_env = []

    def require_env(name: str) -> str:
        value = os.getenv(name, "").strip()
        if not value:
            missing_env.append(name)
        return value

    s3_access_key = os.getenv("S3_ACCESS_KEY_ID") or os.getenv("AWS_ACCESS_KEY_ID", "")
    s3_secret_key = os.getenv("S3_SECRET_ACCESS_KEY") or os.getenv("AWS_SECRET_ACCESS_KEY", "")
    s3_endpoint = os.getenv("S3_ENDPOINT", "").strip()
    s3_region = (
        os.getenv("S3_REGION")
        or os.getenv("AWS_REGION")
        or os.getenv("AWS_DEFAULT_REGION")
        or os.getenv("CLOUD_REGION")
        or "us-east-1"
    )

    if not s3_access_key:
        missing_env.append("S3_ACCESS_KEY_ID")
    if not s3_secret_key:
        missing_env.append("S3_SECRET_ACCESS_KEY")
    if not s3_endpoint:
        missing_env.append("S3_ENDPOINT")

    db_backup_age_private_key = require_env("DB_BACKUP_AGE_PRIVATE_KEY")

    egress_secrets = {
        "S3_ACCESS_KEY_ID": s3_access_key,
        "S3_SECRET_ACCESS_KEY": s3_secret_key,
        "S3_ENDPOINT": s3_endpoint,
        "S3_REGION": s3_region,
        "DB_BACKUP_BUCKET": require_env("DB_BACKUP_BUCKET"),
        "DB_BACKUP_AGE_PUBLIC_KEY": require_env("DB_BACKUP_AGE_PUBLIC_KEY"),
        "INFISICAL_PASSWORD": require_env("INFISICAL_PASSWORD"),
        "INFISICAL_EMAIL": require_env("INFISICAL_EMAIL"),
        "INFISICAL_ORGANIZATION": require_env("INFISICAL_ORGANIZATION"),
        "INFISICAL_NAME": require_env("INFISICAL_NAME"),
        "INFISICAL_SURNAME": require_env("INFISICAL_SURNAME"),
        "INFISICAL_POSTGRES_DB": require_env("INFISICAL_POSTGRES_DB"),
        "INFISICAL_POSTGRES_USER": require_env("INFISICAL_POSTGRES_USER"),
        "INFISICAL_POSTGRES_PASSWORD": require_env("INFISICAL_POSTGRES_PASSWORD"),
        "INFISICAL_ENCRYPTION_KEY": require_env("INFISICAL_ENCRYPTION_KEY"),
        "INFISICAL_AUTH_SECRET": require_env("INFISICAL_AUTH_SECRET"),
    }

    infisical_site_url = os.getenv("INFISICAL_SITE_URL", "").strip()
    if infisical_site_url:
        egress_secrets["INFISICAL_SITE_URL"] = infisical_site_url

    if project_slug:
        egress_secrets["PROJECT_SLUG"] = project_slug
    if environment:
        egress_secrets["ENVIRONMENT"] = environment

    if missing_env:
        missing_env = sorted(set(missing_env))
        print(f"Missing required environment variables for egress bootstrap: {', '.join(missing_env)}", file=sys.stderr)
        return 1

    config["egress_secrets"] = egress_secrets
    config["db_backup_age_private_key"] = db_backup_age_private_key

    if args.bootstrap_artifacts:
        artifacts = load_json(Path(args.bootstrap_artifacts))
        missing = [role for role in REQUIRED_ROLES if role not in artifacts]
        if missing:
            print(f"Missing bootstrap artifacts for roles: {', '.join(missing)}", file=sys.stderr)
            return 1
        config["bootstrap_artifacts"] = artifacts
    else:
        config["bootstrap_artifacts"] = {}

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(config, indent=2))
    print(f"Rendered {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
