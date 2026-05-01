#!/usr/bin/env python3
"""Regenerate index.json from the contents of pkg/.

Walks every *.openvex.json file under pkg/, extracts the product PURLs
from each statement, normalises them (drops version and qualifiers),
and writes a fresh index.json conforming to the Aqua VEX Repository
specification.

Idempotent: produces the same `packages` list for the same on-disk
state. Authors should run this whenever they add, modify, or remove a
VEX statement file. A CI check (`--check`) asserts the on-disk
index.json is in sync with the tree.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def index_id_for_purl(purl: str) -> str:
    """Return the canonical index id for a PURL: version and qualifiers stripped."""
    head = purl
    if "?" in head:
        head, _ = head.split("?", 1)
    if "@" in head:
        head, _ = head.split("@", 1)
    return head


def collect_packages(hub_root: Path) -> list[dict]:
    """Walk pkg/ and produce a sorted, deduplicated list of index entries."""
    pkg_root = hub_root / "pkg"
    if not pkg_root.exists():
        return []
    entries: dict[str, dict] = {}
    for vex_file in sorted(pkg_root.rglob("*.openvex.json")):
        try:
            with vex_file.open() as f:
                doc = json.load(f)
        except json.JSONDecodeError as exc:
            sys.exit(f"invalid OpenVEX JSON in {vex_file}: {exc}")
        rel_location = vex_file.relative_to(hub_root).as_posix()
        purls: set[str] = set()
        for statement in doc.get("statements", []):
            for product in statement.get("products", []):
                pid = product.get("@id")
                if pid and pid.startswith("pkg:"):
                    purls.add(pid)
        for purl in sorted(purls):
            pid = index_id_for_purl(purl)
            existing = entries.get(pid)
            if existing and existing["location"] != rel_location:
                sys.exit(
                    f"PURL {pid} appears in multiple files: "
                    f"{existing['location']} and {rel_location}. "
                    "Each PURL must live in a single VEX file."
                )
            entries[pid] = {
                "id": pid,
                "location": rel_location,
                "format": "openvex",
            }
    return sorted(entries.values(), key=lambda e: e["id"])


def main() -> None:
    parser = argparse.ArgumentParser(description="Regenerate index.json from pkg/.")
    parser.add_argument(
        "--hub-root",
        type=Path,
        default=Path.cwd(),
        help="Path to the vexhub repo root (default: current directory).",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if the on-disk index.json differs from the regenerated one (CI mode).",
    )
    args = parser.parse_args()

    packages = collect_packages(args.hub_root)
    fresh = {
        "updated_at": now_iso(),
        "packages": packages,
    }
    index_path = args.hub_root / "index.json"

    if args.check:
        if index_path.exists():
            with index_path.open() as f:
                current = json.load(f)
        else:
            current = {"packages": []}
        if current.get("packages") != packages:
            print(
                "index.json is out of sync with pkg/ contents.\n"
                "Run: python3 tools/build_index.py",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"index.json is in sync ({len(packages)} package(s))")
        return

    with index_path.open("w") as f:
        json.dump(fresh, f, indent=2)
        f.write("\n")
    print(f"Regenerated {index_path} ({len(packages)} package(s))")


if __name__ == "__main__":
    main()
