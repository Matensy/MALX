#!/usr/bin/env python3
"""Write the synthetic MALX test lab to tests/samples/generated/ (git-ignored).

All samples are harmless: tiny hand-built binaries that only return, and inert text.
They are useful for exploring the UI:  python scripts/generate_samples.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.samples.factory import ALL_SAMPLES  # noqa: E402


def main() -> None:
    out = ROOT / "tests" / "samples" / "generated"
    out.mkdir(parents=True, exist_ok=True)
    for name, builder in ALL_SAMPLES.items():
        (out / name).write_bytes(builder())
        print(f"wrote {out / name}")


if __name__ == "__main__":
    main()
