#!/usr/bin/env python3
"""Fail when shared GitHub files bind a provider-owned secret directly.

Provider secret names are read from stdin, one per line. Keeping those names in
provider-local scripts prevents this shared checker from learning cloud fields.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--github-dir", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    names = {line.strip().lower() for line in sys.stdin if line.strip()}
    if not args.github_dir.is_dir():
        print(f"GitHub directory not found: {args.github_dir}", file=sys.stderr)
        return 2

    leaks: list[str] = []
    for path in sorted(args.github_dir.rglob("*")):
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            print(f"cannot inspect {path}: {exc}", file=sys.stderr)
            return 2
        for line_number, line in enumerate(lines, 1):
            lowered = line.lower()
            for name in names:
                if f"secrets.{name}" in lowered:
                    leaks.append(f"{path}:{line_number}: direct binding of {name}")

    if leaks:
        for leak in leaks:
            print(leak, file=sys.stderr)
        return 1

    print(f"workflow provider isolation passed ({len(names)} credential names checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
