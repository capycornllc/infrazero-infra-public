"""Shared skeleton for provider import-ssh-keys scripts.

Providers (scripts/<provider>/import-ssh-keys.py) supply a `plan_imports`
callback that maps desired keys to (state_address, import_id) pairs; this
module owns argument parsing, tfvars validation, state inspection and the
import loop. No provider-specific code lives here.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def key_material(public_key: str) -> Optional[str]:
    """Normalize an OpenSSH public key for matching: '<type> <base64>', comment ignored."""
    s = public_key.strip()
    if not s:
        return None
    parts = s.split()
    if len(parts) < 2:
        return None
    return f"{parts[0]} {parts[1]}"


def run(cmd: List[str], cwd: str, env: Dict[str, str]) -> Tuple[int, str]:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return proc.returncode, proc.stdout


class ImportItem:
    """One planned import: state address + provider import id (None = create on apply)."""

    def __init__(self, address: str, import_id: Optional[str], label: str = "", tolerate_failure: bool = False):
        self.address = address
        self.import_id = import_id
        self.label = label or (import_id or "")
        self.tolerate_failure = tolerate_failure


PlanImports = Callable[[Dict[str, Any], List[str]], Iterable[ImportItem]]


def main_skeleton(
    argv: List[str],
    description: str,
    default_tofu_dir: str,
    plan_imports: PlanImports,
) -> int:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--tofu-dir", default=default_tofu_dir, help=f"Directory containing *.tf files (default: {default_tofu_dir})")
    parser.add_argument("--tfvars", default=None, help="Path to tofu.tfvars.json (default: <tofu-dir>/tofu.tfvars.json)")
    args = parser.parse_args(argv)

    tofu_dir = os.path.abspath(args.tofu_dir)
    tfvars_path = os.path.abspath(args.tfvars or os.path.join(tofu_dir, "tofu.tfvars.json"))

    if not os.path.isdir(tofu_dir):
        eprint(f"--tofu-dir does not exist or is not a directory: {tofu_dir}")
        return 2
    if not os.path.isfile(tfvars_path):
        eprint(f"tfvars file not found: {tfvars_path}")
        return 2

    tfvars = load_json(tfvars_path)
    ssh_public_keys = tfvars.get("ssh_public_keys")
    if not isinstance(ssh_public_keys, list) or not all(isinstance(x, str) for x in ssh_public_keys):
        eprint("Expected ssh_public_keys to be a list(string) in tfvars")
        return 2

    try:
        items = list(plan_imports(tfvars, ssh_public_keys))
    except SystemExit:
        raise
    except Exception as exc:  # planning errors are configuration/API errors
        eprint(str(exc))
        return 2

    env = dict(os.environ)
    env.setdefault("TF_INPUT", "0")
    env.setdefault("TOFU_INPUT", "0")
    state_rc, state_out = run(["tofu", "state", "list"], cwd=tofu_dir, env=env)
    existing_state = set()
    if state_rc == 0:
        existing_state = {line.strip() for line in state_out.splitlines() if line.strip()}

    imported = 0
    missing = 0

    for item in items:
        if item.address in existing_state:
            print(f"SSH key already in state: {item.address}")
            continue

        if item.import_id is None:
            print(f"No existing SSH key found for {item.address}; will create on apply")
            missing += 1
            continue

        print(f"Importing existing SSH key for {item.address}: {item.label}")
        rc, out = run(
            [
                "tofu",
                "import",
                "-no-color",
                "-input=false",
                f"-var-file={os.path.relpath(tfvars_path, tofu_dir)}",
                item.address,
                item.import_id,
            ],
            cwd=tofu_dir,
            env=env,
        )
        print(out, end="" if out.endswith("\n") else "\n")
        if rc != 0:
            if item.tolerate_failure:
                print(f"Import failed for {item.address} ({item.label}); will create on apply")
                continue
            eprint(f"Import failed for {item.address} ({item.label})")
            return rc
        imported += 1

    print(f"SSH key import summary: imported={imported}, not_found={missing}")
    return 0
