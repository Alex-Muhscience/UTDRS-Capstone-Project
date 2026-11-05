#!/usr/bin/env python3
"""
Check an audit log exported from UTDRS (GET /api/v1/audit-log/export, JSON Lines), without
UTDRS: every entry must hash to its `hash`, and name the entry before it as `prev_hash`.

    python3 verify_audit_export.py utdrs-audit.jsonl

A full export (no filters) is checked from the start of the log. A filtered one, or one
starting part-way (`since`), can only be checked for consecutive entries: gaps between
them are expected and reported as such.

Exit status: 0 when every entry checks out, 1 when one does not, 2 when the file cannot be read.
Needs only Python 3.
"""
import hashlib
import json
import sys

GENESIS = "0" * 64


def main(path: str) -> int:
    previous_seq, previous_hash, checked, gaps = None, None, 0, 0
    try:
        handle = open(path, encoding="utf-8")
    except OSError as e:
        print(f"Cannot read {path}: {e}")
        return 2
    with handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                print(f"Line {number} is not JSON")
                return 1
            body = {k: v for k, v in entry.items() if k != "hash"}
            digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
            if digest != entry.get("hash"):
                print(f"Entry {entry.get('seq')} (line {number}) has been altered")
                return 1
            seq = entry.get("seq")
            if previous_seq is None:
                if seq == 1 and entry.get("prev_hash") != GENESIS:
                    print("Entry 1 does not start the chain")
                    return 1
            elif seq == previous_seq + 1:
                if entry.get("prev_hash") != previous_hash:
                    print(f"Entry {seq} does not follow entry {previous_seq}")
                    return 1
            elif seq <= previous_seq:
                print(f"Entry {seq} (line {number}) is out of order")
                return 1
            else:
                gaps += 1
            previous_seq, previous_hash, checked = seq, entry["hash"], checked + 1
    note = f"; {gaps} gaps between entries (expected in a filtered export)" if gaps else ""
    print(f"OK: {checked} entries, each as it was written{note}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
