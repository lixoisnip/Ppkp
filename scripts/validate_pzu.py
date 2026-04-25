#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import argparse

from pzu_common import discover_pzu_files, load_intel_hex


def main() -> int:
    p = argparse.ArgumentParser(description="Validate all *.PZU Intel HEX files.")
    p.add_argument("--root", type=Path, default=Path("."))
    args = p.parse_args()

    files = discover_pzu_files(args.root)
    if not files:
        print("No .PZU files found")
        return 1

    print(f"Found {len(files)} firmware images")
    bad = 0
    for path in files:
        _mem, st = load_intel_hex(path)
        rng = f"0x{st.min_addr:04X}-0x{st.max_addr:04X}" if st.min_addr is not None else "n/a"
        print(
            f"{st.file}: valid={st.valid_hex} checksum_errors={st.checksum_errors} "
            f"records={st.data_records} bytes={st.data_bytes} range={rng}"
        )
        if not st.valid_hex:
            bad += 1

    print(f"Invalid images: {bad}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
