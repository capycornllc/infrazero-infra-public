#!/usr/bin/env python3
"""
Import existing OpenStack SSH keypairs into the current OpenTofu state.

Why: SSH keypairs are unique by name in OpenStack. If the keypair already exists
in the project, a fresh/empty state will fail on apply with a conflict error.
Importing avoids that.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Tuple


def _eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def _load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _run(cmd: List[str], cwd: str, env: Dict[str, str]) -> Tuple[int, str]:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return proc.returncode, proc.stdout


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="Import existing OpenStack SSH keypairs into OpenTofu state")
    parser.add_argument("--tofu-dir", default="tofu/ovh", help="Directory containing *.tf files (default: tofu/ovh)")
    parser.add_argument(
        "--tfvars",
        default=None,
        help="Path to tofu.tfvars.json (default: <tofu-dir>/tofu.tfvars.json)",
    )
    args = parser.parse_args(argv)

    tofu_dir = os.path.abspath(args.tofu_dir)
    tfvars_path = os.path.abspath(args.tfvars or os.path.join(tofu_dir, "tofu.tfvars.json"))

    if not os.path.isdir(tofu_dir):
        _eprint(f"--tofu-dir does not exist or is not a directory: {tofu_dir}")
        return 2
    if not os.path.isfile(tfvars_path):
        _eprint(f"tfvars file not found: {tfvars_path}")
        return 2

    tfvars = _load_json(tfvars_path)
    ssh_public_keys = tfvars.get("ssh_public_keys")
    if not isinstance(ssh_public_keys, list) or not all(isinstance(x, str) for x in ssh_public_keys):
        _eprint("Expected ssh_public_keys to be a list(string) in tfvars")
        return 2

    name_prefix = tfvars.get("name_prefix", "")
    if not name_prefix:
        _eprint("name_prefix is required in tfvars for SSH key naming")
        return 2

    # Get state list
    env = dict(os.environ)
    env.setdefault("TF_INPUT", "0")
    env.setdefault("TOFU_INPUT", "0")
    state_rc, state_out = _run(["tofu", "state", "list"], cwd=tofu_dir, env=env)
    existing_state = set()
    if state_rc == 0:
        existing_state = {line.strip() for line in state_out.splitlines() if line.strip()}

    imported = 0

    for idx in range(len(ssh_public_keys)):
        addr = f'openstack_compute_keypair_v2.ops["{idx}"]'
        if addr in existing_state:
            print(f"SSH keypair already in state: {addr}")
            continue

        keypair_name = f"{name_prefix}-ops-{idx}"
        print(f"Importing existing SSH keypair for {addr}: name={keypair_name}")
        rc, out = _run(
            [
                "tofu",
                "import",
                "-no-color",
                "-input=false",
                f"-var-file={os.path.relpath(tfvars_path, tofu_dir)}",
                addr,
                keypair_name,
            ],
            cwd=tofu_dir,
            env=env,
        )
        print(out, end="" if out.endswith("\n") else "\n")
        if rc != 0:
            # Keypair may not exist yet — that's fine, apply will create it
            print(f"Import failed for {addr} (name={keypair_name}); will create on apply")
        else:
            imported += 1

    print(f"SSH keypair import summary: imported={imported}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
