"""
zeek_conn_parser.py
-------------------
Parse Zeek conn.log files and surface potential beaconing candidates.

Usage:
    python zeek_conn_parser.py --file conn.log --threshold 10

MITRE ATT&CK: T1071 - Application Layer Protocol
"""

import argparse
from collections import defaultdict
from pathlib import Path


def parse_conn_log(filepath: str) -> list:
    """Read a Zeek conn.log (TSV format) and return a list of connection records."""
    records = []
    with open(filepath, "r") as f:
        headers = []
        for line in f:
            line = line.strip()
            if line.startswith("#fields"):
                headers = line.split("\t")[1:]
            elif line.startswith("#"):
                continue
            else:
                values = line.split("\t")
                if headers:
                    records.append(dict(zip(headers, values)))
    return records


def find_beaconing_candidates(records: list, threshold: int = 10) -> dict:
    """
    Group connections by (src_ip, dst_ip, dst_port) and flag those
    with repeated check-ins above the threshold.
    """
    groups = defaultdict(list)
    for r in records:
        key = (r.get("id.orig_h"), r.get("id.resp_h"), r.get("id.resp_p"))
        groups[key].append(r)

    return {k: v for k, v in groups.items() if len(v) >= threshold}


def main():
    parser = argparse.ArgumentParser(description="Zeek conn.log beaconing analyzer")
    parser.add_argument("--file", required=True, help="Path to conn.log")
    parser.add_argument("--threshold", type=int, default=10,
                        help="Min connections to flag as candidate (default: 10)")
    args = parser.parse_args()

    print(f"[*] Parsing {args.file}...")
    records = parse_conn_log(args.file)
    print(f"[*] Loaded {len(records)} connection records.")

    candidates = find_beaconing_candidates(records, args.threshold)

    if not candidates:
        print("[+] No beaconing candidates found above threshold.")
    else:
        print(f"\n[!] {len(candidates)} beaconing candidate(s) found:\n")
        for (src, dst, port), conns in candidates.items():
            print(f"  SRC: {src}  ->  DST: {dst}:{port}  |  Count: {len(conns)}")


if __name__ == "__main__":
    main()
