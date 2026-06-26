"""
virustotal_lookup.py
--------------------
Look up IPs, domains, or file hashes against the VirusTotal API v3.

Usage:
    export VT_API_KEY=your_key_here
    python virustotal_lookup.py --type ip --ioc 8.8.8.8
    python virustotal_lookup.py --type hash --ioc <sha256>

Requires: requests, python-dotenv
"""

import argparse
import os
import sys

import requests
from dotenv import load_dotenv

load_dotenv()

BASE_URL = "https://www.virustotal.com/api/v3"

ENDPOINTS = {
    "ip": "/ip_addresses/{ioc}",
    "domain": "/domains/{ioc}",
    "hash": "/files/{ioc}",
    "url": "/urls/{ioc}",
}


def lookup(ioc_type: str, ioc: str, api_key: str) -> dict:
    endpoint = ENDPOINTS[ioc_type].format(ioc=ioc)
    headers = {"x-apikey": api_key}
    response = requests.get(f"{BASE_URL}{endpoint}", headers=headers)
    response.raise_for_status()
    return response.json()


def summarize(result: dict) -> None:
    stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    name = result.get("data", {}).get("id", "unknown")
    print(f"\n[+] IOC: {name}")
    print(f"    Malicious : {stats.get('malicious', 0)}")
    print(f"    Suspicious: {stats.get('suspicious', 0)}")
    print(f"    Clean     : {stats.get('undetected', 0)}")
    print(f"    Harmless  : {stats.get('harmless', 0)}")


def main():
    parser = argparse.ArgumentParser(description="VirusTotal IOC lookup")
    parser.add_argument("--type", required=True, choices=ENDPOINTS.keys())
    parser.add_argument("--ioc", required=True, help="The IOC to look up")
    args = parser.parse_args()

    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        sys.exit("[!] VT_API_KEY not set. Add it to .env or export it.")

    result = lookup(args.type, args.ioc, api_key)
    summarize(result)


if __name__ == "__main__":
    main()
