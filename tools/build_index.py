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
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, unquote


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_QUALIFIER_KEY_RE = re.compile(r"^[a-z_][a-z0-9._-]*$")


def _where(source: Path | None) -> str:
    return f" in {source}" if source else ""


def _ensure_percent_encoded(value: str, key: str, purl: str, source: Path | None) -> None:
    """Reject qualifier values that are not fully percent-encoded.

    PURL qualifier values must percent-encode anything outside the RFC 3986
    unreserved set (``[A-Za-z0-9-._~]``). For ``repository_url`` that means
    every ``/`` must appear as ``%2F`` (and every ``:`` in a non-default
    port as ``%3A``). We normalise by decoding then re-encoding with
    ``quote(..., safe="")``; if the result differs from the input (case
    insensitively, since ``%2f`` and ``%2F`` are equivalent), the input
    was not properly encoded.
    """
    canonical = quote(unquote(value), safe="")
    if canonical.lower() != value.lower():
        sys.exit(
            f"PURL qualifier {key}={value!r} in {purl!r}{_where(source)} "
            f"is not properly percent-encoded. Expected {key}={canonical}."
        )


def _parse_purl(purl: str, source: Path | None) -> tuple[str, dict[str, str]]:
    """Parse a PURL into (head, qualifiers).

    ``head`` is ``pkg:<type>/<namespace>/<name>`` with version and subpath
    stripped. ``qualifiers`` preserves the original (validated) encoding so
    callers can re-emit byte-identical strings.

    Grammar enforced: ``pkg:type/namespace/name@version?qualifiers#subpath``
    with qualifier values percent-encoded per RFC 3986.
    """
    if not purl.startswith("pkg:"):
        sys.exit(f"{purl!r}{_where(source)} is not a PURL (must start with 'pkg:').")
    head = purl
    # Subpath (#...) and qualifiers (?...) come after version; strip both
    # before splitting on '@' so version sweeps don't accidentally cross a
    # qualifier/subpath boundary.
    if "#" in head:
        head, _ = head.split("#", 1)
    qualifiers: dict[str, str] = {}
    if "?" in head:
        head, qual_str = head.split("?", 1)
        for pair in qual_str.split("&"):
            if "=" not in pair:
                sys.exit(
                    f"PURL qualifier {pair!r} in {purl!r}{_where(source)} "
                    "is malformed (expected key=value)."
                )
            key, value = pair.split("=", 1)
            if not _QUALIFIER_KEY_RE.fullmatch(key):
                sys.exit(
                    f"PURL qualifier key {key!r} in {purl!r}{_where(source)} "
                    "is invalid (must be lowercase ASCII identifier)."
                )
            _ensure_percent_encoded(value, key, purl, source)
            qualifiers[key] = value
    if "@" in head:
        head, _ = head.split("@", 1)
    return head, qualifiers


def index_id_for_purl(purl: str, source: Path | None = None) -> str:
    """Return the canonical index id for a PURL.

    Per the VEX Repository Specification, version, subpath, and qualifiers
    are stripped from the index id; for ``pkg:oci/*`` PURLs the
    ``repository_url`` qualifier MUST be preserved (and must be
    percent-encoded) so Trivy can match the entry against the image PURL it
    generates at scan time.
    """
    head, qualifiers = _parse_purl(purl, source)
    if head.startswith("pkg:oci/"):
        if "repository_url" not in qualifiers:
            sys.exit(
                f"OCI PURL {purl!r}{_where(source)} is missing the required "
                "'repository_url' qualifier. Per the VEX Repository "
                "Specification, OCI product @id values must include "
                "?repository_url=<registry>/<namespace>/<image> with "
                "slashes percent-encoded as %2F."
            )
        repo = qualifiers["repository_url"]
        if not repo:
            sys.exit(
                f"OCI PURL {purl!r}{_where(source)} has an empty "
                "'repository_url' qualifier."
            )
        return f"{head}?repository_url={repo}"
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
            pid = index_id_for_purl(purl, source=vex_file)
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
