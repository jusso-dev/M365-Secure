#!/usr/bin/env python3
"""Build controls/junction-catalog.json: the subset of Junction's operation catalogue m365-assess uses.

Junction (https://github.com/jusso-dev/junction) regenerates its catalogue daily from Microsoft's published
API specifications. Shipping the whole thing (hundreds of MB) makes no sense for a CLI that calls a few dozen
operations, so this script copies just the operations listed in controls/junction-operations.txt, with the
schema definitions they reference, into one RegistryManifest the binary embeds at build time.

Usage:
    scripts/junction-catalog.py /path/to/junction/checkout

Re-run it when adding operations to controls/junction-operations.txt or when bumping the Junction revision in
Cargo.toml; commit the result.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OPS_FILE = ROOT / "controls" / "junction-operations.txt"
OUT_FILE = ROOT / "controls" / "junction-catalog.json"
REF = re.compile(r"^#/(.+)$")


def wanted_ops() -> list[str]:
    return [
        line.strip()
        for line in OPS_FILE.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]


def walk_refs(node, found: set[str]) -> None:
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str):
            m = REF.match(ref)
            if m:
                found.add(m.group(1))
        for v in node.values():
            walk_refs(v, found)
    elif isinstance(node, list):
        for v in node:
            walk_refs(v, found)


def resolve_pointer(schemas, pointer: str):
    node = schemas
    for part in pointer.split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def set_pointer(target, pointer: str, value) -> None:
    parts = pointer.split("/")
    node = target
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    registry_dir = Path(sys.argv[1]) / "generated" / "registry"
    if not registry_dir.is_dir():
        print(f"{registry_dir} not found; pass the root of a junction checkout", file=sys.stderr)
        return 2

    wanted = wanted_ops()
    remaining = set(wanted)
    operations: list[dict] = []
    schemas: dict = {}
    sources: list[str] = []

    for manifest_path in sorted(registry_dir.glob("*.json")):
        # operations.json is the union of every product file; skip it to keep provenance per product.
        if manifest_path.name in {"operations.json"} or manifest_path.name.startswith("graph-"):
            continue
        manifest = json.loads(manifest_path.read_text())
        hits = [op for op in manifest.get("operations", []) if op["id"] in remaining]
        if not hits:
            continue
        sources.append(manifest_path.name)
        file_schemas = manifest.get("schemas") or {}
        for op in hits:
            operations.append(op)
            remaining.discard(op["id"])
            refs: set[str] = set()
            walk_refs(op, refs)
            # Follow nested references until closure.
            seen: set[str] = set()
            while refs - seen:
                pointer = (refs - seen).pop()
                seen.add(pointer)
                value = resolve_pointer(file_schemas, pointer)
                if value is None:
                    continue
                set_pointer(schemas, pointer, value)
                walk_refs(value, refs)

    if remaining:
        print("operations not found in the Junction catalogue:\n  " + "\n  ".join(sorted(remaining)), file=sys.stderr)
        return 1

    # Deterministic output so diffs stay reviewable.
    operations.sort(key=lambda op: (op["id"], op.get("api_version") or ""))
    out = {
        "format_version": 1,
        "generated_from": {
            "project": "https://github.com/jusso-dev/junction",
            "files": sources,
        },
        "operations": operations,
        "schemas": schemas,
    }
    OUT_FILE.write_text(json.dumps(out, indent=1, sort_keys=False) + "\n")
    print(f"wrote {OUT_FILE.relative_to(ROOT)}: {len(operations)} operations from {len(sources)} catalogue files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
