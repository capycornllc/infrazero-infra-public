import argparse
import argparse
import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text()) or {}


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate infra config against schema.")
    parser.add_argument("--config", default="config/infra.yaml")
    parser.add_argument("--schema", default="config/schema.json")
    args = parser.parse_args()

    config_path = Path(args.config)
    schema_path = Path(args.schema)

    config = load_yaml(config_path)
    schema = json.loads(schema_path.read_text())

    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(config), key=lambda e: e.path)

    if errors:
        print("Config validation failed:", file=sys.stderr)
        for error in errors:
            path = ".".join([str(p) for p in error.path]) or "$"
            print(f"- {path}: {error.message}", file=sys.stderr)
        return 1

    print("Config validation OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
