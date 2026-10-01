#!/usr/bin/env python3
"""Import OSV advisories into MALX's local advisory database (offline).

MALX never downloads advisories on its own and never invents CVEs. Download the
OSV dumps yourself (one zip per ecosystem), then import them:

    # https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip   (also npm, Maven, Go, crates.io, Packagist, RubyGems, NuGet)
    python scripts/import_osv.py ~/Downloads/PyPI-all.zip ~/Downloads/npm-all.zip

Each input may be an OSV ``all.zip``, a directory of OSV JSON files, or a single
JSON file. The result is written as JSONL to ``rules/advisories/<ecosystem>.jsonl``
(or ``--out DIR``). Only the fields MALX needs are kept.
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEEP = ("id", "aliases", "summary", "details", "affected", "severity", "database_specific", "modified", "published")


def _records(path: Path):
    if path.is_dir():
        for p in sorted(path.rglob("*.json")):
            yield json.loads(p.read_text("utf-8"))
    elif path.suffix == ".zip":
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if name.endswith(".json"):
                    info = zf.getinfo(name)
                    if info.file_size < 16 * 1024 * 1024:
                        yield json.loads(zf.read(info))
    else:
        data = json.loads(path.read_text("utf-8"))
        yield from (data if isinstance(data, list) else [data])


def slim(rec: dict) -> dict:
    out = {k: rec[k] for k in KEEP if k in rec}
    if "details" in out:
        out["details"] = out["details"][:600]
    affected = []
    for a in rec.get("affected", []) or []:
        affected.append({k: a[k] for k in ("package", "ranges", "versions") if k in a})
    out["affected"] = affected
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="+", type=Path)
    ap.add_argument("--out", type=Path, default=ROOT / "rules" / "advisories")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    by_eco: dict[str, list[dict]] = defaultdict(list)
    total = 0
    for inp in args.inputs:
        for rec in _records(inp):
            if not isinstance(rec, dict) or "id" not in rec or rec.get("withdrawn"):
                continue
            ecos = {(a.get("package") or {}).get("ecosystem") for a in rec.get("affected", []) or []}
            for eco in filter(None, ecos):
                by_eco[eco.split(":")[0]].append(slim(rec))
            total += 1
    for eco, recs in by_eco.items():
        safe = "".join(c if c.isalnum() or c in "-._" else "_" for c in eco)
        path = args.out / f"{safe}.jsonl"
        with open(path, "w", encoding="utf-8") as fh:
            for r in recs:
                fh.write(json.dumps(r, separators=(",", ":")) + "\n")
        print(f"{eco}: {len(recs)} advisories -> {path}")
    print(f"imported {total} advisories")
    return 0


if __name__ == "__main__":
    sys.exit(main())
