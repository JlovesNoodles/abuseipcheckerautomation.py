#!/usr/bin/env python3
"""
ipcheck.py — Simple bulk IP reputation checker
Usage: python3 ipcheck.py ips.txt --vt YOUR_KEY --abuse YOUR_KEY
"""

import sys
import time
import argparse
import ipaddress
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

VT_URL    = "https://www.virustotal.com/api/v3/ip_addresses/{}"
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"

def is_valid_public_ip(ip):
    try:
        obj = ipaddress.ip_address(ip.strip())
        return not obj.is_private and not obj.is_loopback
    except ValueError:
        return False

def check_virustotal(ip, api_key):
    try:
        r = requests.get(
            VT_URL.format(ip),
            headers={"x-apikey": api_key},
            timeout=10
        )
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            return malicious > 0
    except Exception:
        pass
    return False

def check_abuseipdb(ip, api_key):
    try:
        r = requests.get(
            ABUSE_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        if r.status_code == 200:
            score = r.json()["data"]["abuseConfidenceScore"]
            return score > 0
    except Exception:
        pass
    return False

def check_ip(ip, vt_key, abuse_key):
    ip = ip.strip()
    vt_hit    = check_virustotal(ip, vt_key)
    time.sleep(0.25)
    abuse_hit = check_abuseipdb(ip, abuse_key)
    block     = vt_hit and abuse_hit
    return ip, vt_hit, abuse_hit, block

def main():
    p = argparse.ArgumentParser()
    p.add_argument("file",          help="Text file with one IP per line")
    p.add_argument("--vt",          required=True, help="VirusTotal API key")
    p.add_argument("--abuse",       required=True, help="AbuseIPDB API key")
    p.add_argument("--threads", "-t", type=int, default=5)
    args = p.parse_args()

    try:
        ips = [l.strip() for l in open(args.file) if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        print(f"[!] File not found: {args.file}")
        sys.exit(1)

    valid = [ip for ip in ips if is_valid_public_ip(ip)]
    skipped = len(ips) - len(valid)

    print(f"\n  Checking {len(valid)} IPs...\n")

    to_block = []
    benign   = []

    with ThreadPoolExecutor(max_workers=args.threads) as exe:
        futures = {exe.submit(check_ip, ip, args.vt, args.abuse): ip for ip in valid}
        for future in as_completed(futures):
            ip, vt_hit, abuse_hit, block = future.result()
            vt_tag    = "VT: HIT" if vt_hit else "VT:NO HIT"
            abuse_tag = "Abuse: HIT" if abuse_hit else "Abuse:NO HIT"
            verdict   = "BLOCK" if block else "benign"
            print(f"  {ip:<20} {vt_tag}  {abuse_tag}  →  {verdict}")
            if block:
                to_block.append(ip)
            else:
                benign.append(ip)

    print(f"\n  {'─'*40}")
    print(f"  Block  : {len(to_block)}")
    print(f"  Benign : {len(benign)}")
    if skipped:
        print(f"  Skipped: {skipped} (private/invalid)")
    print(f"  {'─'*40}")

    if to_block:
        print(f"\n  IPs to block:")
        for ip in to_block:
            print(f"    {ip}")

if __name__ == "__main__":
    main()
