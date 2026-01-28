import argparse
import os
import sys
from pathlib import Path

import yaml


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text()) or {}


def main() -> int:
    parser = argparse.ArgumentParser(description="Render OpenTofu S3 backend config.")
    parser.add_argument("--config", default="config/infra.yaml")
    parser.add_argument("--output", default="tofu/backend.hcl")
    args = parser.parse_args()

    config = load_yaml(Path(args.config))
    s3_cfg = config.get("s3_backend", {})

    bucket = os.getenv("INFRA_STATE_BUCKET")
    if not bucket:
        print("INFRA_STATE_BUCKET is required", file=sys.stderr)
        return 1

    endpoint = os.getenv("S3_ENDPOINT", "")
    region = os.getenv("S3_REGION", "")
    state_prefix = s3_cfg.get("state_prefix", "")

    if not endpoint or not region or not state_prefix:
        print("S3_ENDPOINT, S3_REGION, and s3_backend.state_prefix are required", file=sys.stderr)
        return 1

    key = f"{state_prefix}/terraform.tfstate"

    backend_hcl = "\n".join([
        f"bucket = \"{bucket}\"",
        f"key = \"{key}\"",
        f"region = \"{region}\"",
        f"endpoint = \"{endpoint}\"",
        "skip_credentials_validation = true",
        "skip_metadata_api_check = true",
        "skip_requesting_account_id = true",
        "force_path_style = true",
    ])

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(backend_hcl + "\n")
    print(f"Rendered {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
