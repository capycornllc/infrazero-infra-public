#!/usr/bin/env python3
"""
Import existing Hetzner Cloud SSH keys into the current OpenTofu state.

Why: SSH keys are globally unique by fingerprint in Hetzner Cloud. If the key
already exists in the account (common), a fresh/empty state will fail on apply
with "SSH key not unique". Importing avoids that.

Shared skeleton: scripts/common/import_ssh_keys_common.py. This file only
resolves Hetzner key IDs via the hcloud API.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
from import_ssh_keys_common import ImportItem, eprint, key_material, main_skeleton  # noqa: E402

HCLOUD_API_BASE = "https://api.hetzner.cloud/v1"


def _hcloud_get_json(url: str, token: str) -> Dict[str, Any]:
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        method="GET",
    )

    attempts = 6
    delay = 2.0
    max_delay = 30.0
    retryable_http = {429, 500, 502, 503, 504}

    last_err: Optional[BaseException] = None
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = resp.read().decode("utf-8")
            return json.loads(payload)
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8")
            except Exception:
                pass

            if e.code not in retryable_http or attempt >= attempts:
                raise RuntimeError(f"Hetzner API error {e.code} for {url}: {body or e.reason}") from e

            retry_after = e.headers.get("Retry-After", "") if hasattr(e, "headers") else ""
            sleep_for = delay
            if retry_after and retry_after.isdigit():
                sleep_for = float(retry_after)
            eprint(f"Hetzner API rate limited/unavailable (http {e.code}); retry {attempt}/{attempts} in {sleep_for:.0f}s")
            time.sleep(sleep_for)
            delay = min(max_delay, delay * 2.0)
            last_err = e
            continue
        except urllib.error.URLError as e:
            if attempt >= attempts:
                raise RuntimeError(f"Hetzner API request failed for {url}: {e.reason}") from e
            eprint(f"Hetzner API request failed ({e.reason}); retry {attempt}/{attempts} in {delay:.0f}s")
            time.sleep(delay)
            delay = min(max_delay, delay * 2.0)
            last_err = e
            continue

    raise RuntimeError(f"Hetzner API request failed for {url}") from last_err


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


def plan_imports(tfvars: Dict[str, Any], ssh_public_keys: List[str]) -> List[ImportItem]:
    token = os.environ.get("HCLOUD_TOKEN", "").strip()
    if not token:
        raise RuntimeError("HCLOUD_TOKEN is required for importing SSH keys")

    desired_materials: List[str] = []
    for idx, pk in enumerate(ssh_public_keys):
        mat = key_material(pk)
        if not mat:
            raise RuntimeError(f"Invalid ssh_public_keys[{idx}] (expected 'type base64 [comment]'): {pk!r}")
        desired_materials.append(mat)

    # Duplicates are almost certainly a configuration mistake and can lead to
    # confusing import/apply failures.
    seen_mat: Dict[str, int] = {}
    for idx, mat in enumerate(desired_materials):
        prev = seen_mat.get(mat)
        if prev is not None:
            raise RuntimeError(f"Duplicate ssh_public_keys entries detected at indices {prev} and {idx}")
        seen_mat[mat] = idx

    remote_keys = _list_hcloud_ssh_keys(token)
    material_to_id: Dict[str, int] = {}
    for k in remote_keys:
        pk = k.get("public_key") or ""
        mat = key_material(pk)
        kid = k.get("id")
        if not mat or not isinstance(kid, int):
            continue
        material_to_id.setdefault(mat, kid)

    items: List[ImportItem] = []
    for idx, mat in enumerate(desired_materials):
        addr = f'hcloud_ssh_key.ops["{idx}"]'
        remote_id = material_to_id.get(mat)
        items.append(ImportItem(addr, str(remote_id) if remote_id else None, label=f"id={remote_id}"))
    return items


if __name__ == "__main__":
    raise SystemExit(main_skeleton(
        sys.argv[1:],
        description="Import existing Hetzner Cloud SSH keys into OpenTofu state",
        default_tofu_dir="tofu/hetzner",
        plan_imports=plan_imports,
    ))
