#!/usr/bin/env python3
"""
Import existing OpenStack SSH keypairs into the current OpenTofu state.

Why: SSH keypairs are unique by name in OpenStack. If the keypair already exists
in the project, a fresh/empty state will fail on apply with a conflict error.
Importing avoids that.

Shared skeleton: scripts/common/import_ssh_keys_common.py. This file only maps
key indices to OpenStack keypair names; import failures are tolerated (the
keypair may simply not exist yet).
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
from import_ssh_keys_common import ImportItem, main_skeleton  # noqa: E402


def plan_imports(tfvars: Dict[str, Any], ssh_public_keys: List[str]) -> List[ImportItem]:
    name_prefix = tfvars.get("name_prefix", "")
    if not name_prefix:
        raise RuntimeError("name_prefix is required in tfvars for SSH key naming")

    items: List[ImportItem] = []
    for idx in range(len(ssh_public_keys)):
        addr = f'openstack_compute_keypair_v2.ops["{idx}"]'
        keypair_name = f"{name_prefix}-ops-{idx}"
        items.append(ImportItem(addr, keypair_name, label=f"name={keypair_name}", tolerate_failure=True))
    return items


if __name__ == "__main__":
    raise SystemExit(main_skeleton(
        sys.argv[1:],
        description="Import existing OpenStack SSH keypairs into OpenTofu state",
        default_tofu_dir="tofu/ovh",
        plan_imports=plan_imports,
    ))
