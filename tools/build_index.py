#!/usr/bin/env python3
"""Regenerate index.json from the contents of pkg/.

Walks every *.openvex.json file under pkg/, extracts the product PURLs
from each statement, normalises them for VEX repository lookup, and
writes a fresh index.json conforming to the Aqua/Rancher VEX repository
index shape.

Idempotent: produces the same `packages` list for the same on-disk
state. Authors should run this whenever they add, modify, or remove a
VEX statement file. A CI check (`--check`) asserts the on-disk
index.json is in sync with the tree.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import parse_qsl, quote


def index_id_for_purl(purl: str) -> str:
    """Return the Rancher-compatible VEX repository index ID for a PURL.

    Package versions are not part of the repository index key, but qualifiers
    can be identity-bearing. OCI image products rely on `repository_url`, so
    keep qualifiers and percent-encode their values the same way Rancher's hub
    does in index.json.
    """
    base, _, query = purl.partition("?")
    if "@" in base:
        base, _ = base.rsplit("@", 1)
    if not query:
        return base

    qualifiers = []
    for key, value in parse_qsl(query, keep_blank_values=True):
        qualifiers.append(f"{quote(key, safe='')}={quote(value, safe='')}")
    if not qualifiers:
        return base
    return f"{base}?{'&'.join(qualifiers)}"


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
        "version": 1,
        "packages": packages,
    }
    index_path = args.hub_root / "index.json"

    if args.check:
        if index_path.exists():
            with index_path.open() as f:
                current = json.load(f)
        else:
            current = {"version": 1, "packages": []}
        if current != fresh:
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
