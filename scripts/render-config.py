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
    if project_slug:
        environment = str(config.get("environment", "")).strip()
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
