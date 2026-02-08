#!/usr/bin/env python3
"""
Import existing Hetzner Cloud SSH keys into the current OpenTofu state.

Why: SSH keys are globally unique by fingerprint in Hetzner Cloud. If the key
already exists in the account (common), a fresh/empty state will fail on apply
with "SSH key not unique". Importing avoids that.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


HCLOUD_API_BASE = "https://api.hetzner.cloud/v1"


def _eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def _load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _key_material(public_key: str) -> Optional[str]:
    """
    Normalize an OpenSSH public key for matching.
    We match on "<type> <base64>" and ignore any trailing comment.
    """

    s = public_key.strip()
    if not s:
        return None
    parts = s.split()
    if len(parts) < 2:
        return None
    return f"{parts[0]} {parts[1]}"


def _hcloud_get_json(url: str, token: str) -> Dict[str, Any]:
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8")
        except Exception:
            pass
        raise RuntimeError(f"Hetzner API error {e.code} for {url}: {body or e.reason}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Hetzner API request failed for {url}: {e.reason}") from e
    return json.loads(payload)


def _list_hcloud_ssh_keys(token: str) -> List[Dict[str, Any]]:
    keys: List[Dict[str, Any]] = []
    page = 1
    per_page = 50

    while True:
        url = f"{HCLOUD_API_BASE}/ssh_keys?page={page}&per_page={per_page}"
        data = _hcloud_get_json(url, token)
        batch = data.get("ssh_keys") or []
        if not isinstance(batch, list):
            raise RuntimeError("Unexpected Hetzner API response: ssh_keys is not a list")
        keys.extend(batch)

        # Prefer meta.pagination if available; otherwise fall back to short-page termination.
        pagination = (data.get("meta") or {}).get("pagination") or {}
        next_page = pagination.get("next_page")
        last_page = pagination.get("last_page")
        cur_page = pagination.get("page")

        if isinstance(next_page, int) and next_page > page:
            page = next_page
            continue
        if isinstance(cur_page, int) and isinstance(last_page, int):
            if cur_page >= last_page:
                break
            page += 1
            continue

        if len(batch) < per_page:
            break
        page += 1

    return keys


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
    parser = argparse.ArgumentParser(description="Import existing Hetzner Cloud SSH keys into OpenTofu state")
    parser.add_argument("--tofu-dir", default="tofu", help="Directory containing *.tf files (default: tofu)")
    parser.add_argument(
        "--tfvars",
        default=None,
        help="Path to tofu.tfvars.json (default: <tofu-dir>/tofu.tfvars.json)",
    )
    args = parser.parse_args(argv)

    tofu_dir = os.path.abspath(args.tofu_dir)
    tfvars_path = os.path.abspath(args.tfvars or os.path.join(tofu_dir, "tofu.tfvars.json"))

    token = os.environ.get("HCLOUD_TOKEN", "").strip()
    if not token:
        _eprint("HCLOUD_TOKEN is required for importing SSH keys")
        return 2

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

    desired_materials: List[str] = []
    for idx, pk in enumerate(ssh_public_keys):
        mat = _key_material(pk)
        if not mat:
            _eprint(f"Invalid ssh_public_keys[{idx}] (expected 'type base64 [comment]'): {pk!r}")
            return 2
        desired_materials.append(mat)

    # Duplicates are almost certainly a configuration mistake and can lead to confusing import/apply failures.
    seen_mat: Dict[str, int] = {}
    for idx, mat in enumerate(desired_materials):
        prev = seen_mat.get(mat)
        if prev is not None:
            _eprint(f"Duplicate ssh_public_keys entries detected at indices {prev} and {idx}")
            return 2
        seen_mat[mat] = idx

    # Prepare API lookup map: material -> id
    remote_keys = _list_hcloud_ssh_keys(token)
    material_to_id: Dict[str, int] = {}
    for k in remote_keys:
        pk = k.get("public_key") or ""
        mat = _key_material(pk)
        kid = k.get("id")
        if not mat or not isinstance(kid, int):
            continue
        material_to_id.setdefault(mat, kid)

    # Get state list (may fail if no state yet).
    env = dict(os.environ)
    env.setdefault("TF_INPUT", "0")
    env.setdefault("TOFU_INPUT", "0")
    state_rc, state_out = _run(["tofu", "-no-color", "state", "list"], cwd=tofu_dir, env=env)
    existing_state = set()
    if state_rc == 0:
        existing_state = {line.strip() for line in state_out.splitlines() if line.strip()}

    imported = 0
    missing = 0

    for idx, mat in enumerate(desired_materials):
        addr = f'hcloud_ssh_key.ops["{idx}"]'
        if addr in existing_state:
            print(f"SSH key already in state: {addr}")
            continue

        remote_id = material_to_id.get(mat)
        if not remote_id:
            print(f"No existing SSH key found for {addr}; will create on apply")
            missing += 1
            continue

        print(f"Importing existing SSH key for {addr}: id={remote_id}")
        rc, out = _run(
            [
                "tofu",
                "-no-color",
                "import",
                "-input=false",
                f"-var-file={os.path.relpath(tfvars_path, tofu_dir)}",
                addr,
                str(remote_id),
            ],
            cwd=tofu_dir,
            env=env,
        )
        print(out, end="" if out.endswith("\n") else "\n")
        if rc != 0:
            _eprint(f"Import failed for {addr} (id={remote_id})")
            return rc

        imported += 1

    print(f"SSH key import summary: imported={imported}, not_found={missing}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
