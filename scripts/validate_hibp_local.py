#!/usr/bin/env python3
"""Validate the local HIBP SHA-1 corpus used by VaultLocal."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

EXPECTED_RANGES = 16**5
RANGE_NAME = re.compile(r"^[0-9A-F]{5}\.txt$")


def main() -> int:
    base = Path(os.environ.get("HIBP_LOCAL_DIR", "data/hibp/sha1"))
    index = base / "sha1.index"
    files = sorted(p.name for p in base.glob("*.txt"))

    if len(files) != EXPECTED_RANGES:
        raise SystemExit(f"expected {EXPECTED_RANGES} ranges, found {len(files)}")
    if not all(RANGE_NAME.fullmatch(name) for name in files):
        raise SystemExit("corpus contains an invalid range filename")
    if not index.is_file() or index.stat().st_size == 0:
        raise SystemExit("sha1.index is missing or empty")

    entries = index.read_text(encoding="utf-8").splitlines()
    prefixes = {line.split("\t", 1)[0].upper() for line in entries if "\t" in line}
    if len(entries) != EXPECTED_RANGES or len(prefixes) != EXPECTED_RANGES:
        raise SystemExit(
            f"index must contain {EXPECTED_RANGES} unique entries, found {len(entries)} lines / {len(prefixes)} prefixes"
        )

    # Known HIBP corpus fixture: "password" is SHA-1 5BAA61... and must be present.
    password_hash = hashlib.sha1(b"password").hexdigest().upper()
    prefix, suffix = password_hash[:5], password_hash[5:]
    range_file = base / f"{prefix}.txt"
    match = next(
        (line for line in range_file.read_text(encoding="utf-8").splitlines() if line.startswith(suffix + ":")),
        None,
    )
    if match is None or int(match.rsplit(":", 1)[1]) <= 0:
        raise SystemExit("known HIBP fixture 'password' was not found in the local corpus")

    print(f"HIBP local corpus: OK ({len(files):,} ranges)")
    print(f"HIBP index: OK ({len(entries):,} entries)")
    print(f"Known fixture 'password': OK ({match.split(':', 1)[1]} occurrences)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
