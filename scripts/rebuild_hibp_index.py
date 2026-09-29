#!/usr/bin/env python3
"""Rebuild a local readiness index when a complete corpus lost its downloader index."""

from __future__ import annotations

import os
import re
from pathlib import Path

EXPECTED_RANGES = 16**5
RANGE_NAME = re.compile(r"^[0-9A-F]{5}\.txt$")


def main() -> int:
    base = Path(os.environ.get("HIBP_LOCAL_DIR", "data/hibp/sha1"))
    files = sorted(p.name for p in base.glob("*.txt"))
    if len(files) != EXPECTED_RANGES or not all(RANGE_NAME.fullmatch(name) for name in files):
        raise SystemExit("refusing to rebuild: corpus must contain exactly 1,048,576 SHA-1 range files")

    target = base / "sha1.index"
    tmp = base / "sha1.index.tmp"
    with tmp.open("w", encoding="utf-8") as stream:
        for name in files:
            stream.write(f"{name[:-4].upper()}\tLOCAL\n")
    tmp.replace(target)
    print(f"rebuilt local index: {target} ({len(files):,} entries)")
    print("note: LOCAL entries are readiness markers, not HIBP HTTP ETags; the official downloader should refresh them on the next corpus update.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
