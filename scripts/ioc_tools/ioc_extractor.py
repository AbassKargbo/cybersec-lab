"""
ioc_extractor.py
----------------
Extract IOCs (IPs, domains, hashes, URLs) from raw text input.

Usage:
    python ioc_extractor.py --input report.txt
    python ioc_extractor.py --input report.txt --output iocs.json
"""

import argparse
import json
import re
from pathlib import Path

PATTERNS = {
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
    "domain": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "url": r"https?://[^\s\"'<>]+",
}

EXCLUDE_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}


def extract_iocs(text: str) -> dict:
    results = {}
    for ioc_type, pattern in PATTERNS.items():
        matches = list(set(re.findall(pattern, text)))
        if ioc_type == "ipv4":
            matches = [ip for ip in matches if ip not in EXCLUDE_IPS]
        if matches:
            results[ioc_type] = sorted(matches)
    return results


def main():
    parser = argparse.ArgumentParser(description="Extract IOCs from text")
    parser.add_argument("--input", required=True, help="Path to input file")
    parser.add_argument("--output", help="Optional: save results to JSON file")
    args = parser.parse_args()

    text = Path(args.input).read_text(errors="ignore")
    iocs = extract_iocs(text)
    print(json.dumps(iocs, indent=2))

    if args.output:
        Path(args.output).write_text(json.dumps(iocs, indent=2))
        print(f"\n[+] IOCs saved to {args.output}")


if __name__ == "__main__":
    main()
