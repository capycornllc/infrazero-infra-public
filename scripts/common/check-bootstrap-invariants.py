#!/usr/bin/env python3
"""Protect bootstrap invariants that are easy to break during commonization."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"bootstrap invariant failed: {message}")


common_system = read("bootstrap/common/common-system.sh")
bastion = read("bootstrap/common/common-bastion.sh")
infisical = read("bootstrap/common/common-infisical-bootstrap.sh")
destroy = read("scripts/common/destroy-without-volume-driver.sh")

role_guard = 'if [ "${BOOTSTRAP_ROLE:-}" = "bastion" ]; then'
guest_route_script = "# Ensure the WireGuard subnet routes to bastion on non-WG hosts."
require(role_guard in common_system, "common-system must exclude bastion from the guest WG route")
require(
    common_system.index(guest_route_script) < common_system.index(role_guard),
    "the bastion role guard must wrap the guest WG route implementation",
)
require(
    "systemctl disable --now infrazero-wg-route.timer infrazero-wg-route.service" in common_system,
    "bastion upgrades must remove legacy WG route units",
)
require(
    "systemctl disable --now infrazero-wg-route.timer infrazero-wg-route.service" in bastion,
    "common-bastion must independently remove legacy WG route units",
)
require(
    'ip route replace "$WG_CIDR" dev "$WG_IF" scope link' in bastion,
    "bastion must own WG_CIDR on its WireGuard interface",
)
require(
    "WireGuard route verified" in bastion,
    "bastion bootstrap must validate the selected WG route",
)

tokens_declaration = 'tokens_manifest_key="infisical/bootstrap/latest-tokens.json"'
restore_branch = 'if [ "$restore_requested" = "true" ]; then'
require(
    infisical.index(tokens_declaration) < infisical.index(restore_branch),
    "Infisical token manifest must be checked before restore can exit successfully",
)
restore_block = infisical[
    infisical.index(restore_branch) : infisical.index(
        'if [ "$restore_requested" != "true" ]', infisical.index(restore_branch)
    )
]
require(
    'if [ "$tokens_manifest_exists" = "true" ]; then' in restore_block,
    "restored Infisical database must require its token manifest",
)
require(
    "restore_archived_tokens_manifest" in restore_block,
    "restore must migrate a validated archived token manifest",
)

archive_start = destroy.index("# Archive the token manifest")
archive_end = destroy.index('echo "[destroy] Old data moved', archive_start)
archive_block = destroy[archive_start:archive_end]
require("s3 cp" in archive_block, "destroy must archive the Infisical manifest with copy")
require("s3 mv" not in archive_block, "destroy must retain the canonical Infisical manifest")

print("bootstrap route and Infisical token lifecycle invariants passed")
