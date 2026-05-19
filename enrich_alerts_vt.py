#!/usr/bin/env python3
"""
Wazuh Alert IP Enrichment Script — VirusTotal Edition
Reads Wazuh alerts.json → extracts IPs → queries VirusTotal → outputs enriched report

Author  : Bartam Leela Sagar (Shag)
Lab     : SOC Home Lab — GCP
Usage   : python3 enrich_alerts_vt.py
          python3 enrich_alerts_vt.py --last 50
          python3 enrich_alerts_vt.py --export
"""

import json
import requests
import argparse
import csv
import os
import time
from datetime import datetime

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

VT_API_KEY       = "a56dff0fd930078543c4afcb85f4a7aaed92d6ce5eedf928bc5c14ba4bbb533c"

ALERTS_JSON_PATH = "/var/ossec/logs/alerts/alerts.json"  # Wazuh Manager VM
MAX_ALERTS       = 100
EXPORT_PATH      = "./enriched_report_vt.csv"
MALICIOUS_THRESHOLD = 3   # number of VT engines flagging IP as malicious

# Wazuh rule IDs to focus on
TARGET_RULE_IDS  = ["100001", "100002", "100009", "100010", "100023",
                    "5763", "5760", "5712"]

# ─────────────────────────────────────────────
# FUNCTIONS
# ─────────────────────────────────────────────

def parse_alerts(filepath, max_alerts):
    """Read Wazuh alerts.json and extract alerts with source IPs."""
    alerts = []
    if not os.path.exists(filepath):
        print(f"[ERROR] File not found: {filepath}")
        print("        Run this script on the Wazuh Manager VM")
        print("        or update ALERTS_JSON_PATH to the correct path.")
        return alerts

    with open(filepath, "r") as f:
        lines = f.readlines()[-max_alerts:]

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            alert = json.loads(line)
            rule_id = str(alert.get("rule", {}).get("id", ""))
            src_ip  = (alert.get("data", {}).get("srcip") or
                       alert.get("data", {}).get("src_ip") or
                       alert.get("data", {}).get("source", {}).get("ip"))

            if rule_id in TARGET_RULE_IDS and src_ip:
                alerts.append({
                    "timestamp"  : alert.get("timestamp", ""),
                    "agent"      : alert.get("agent", {}).get("name", "unknown"),
                    "rule_id"    : rule_id,
                    "rule_desc"  : alert.get("rule", {}).get("description", ""),
                    "rule_level" : alert.get("rule", {}).get("level", 0),
                    "src_ip"     : src_ip,
                    "dst_user"   : alert.get("data", {}).get("dstuser", "-")
                })
        except json.JSONDecodeError:
            continue

    return alerts


def check_virustotal(ip, api_key):
    """Query VirusTotal v3 API for IP reputation."""
    url     = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data       = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats      = attributes.get("last_analysis_stats", {})
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless   = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total      = malicious + suspicious + harmless + undetected

            country    = attributes.get("country", "??")
            asn        = attributes.get("asn", "N/A")
            as_owner   = attributes.get("as_owner", "Unknown")
            reputation = attributes.get("reputation", 0)

            # Verdict logic
            if malicious >= MALICIOUS_THRESHOLD:
                verdict = "MALICIOUS"
            elif suspicious >= 1 or malicious >= 1:
                verdict = "SUSPICIOUS"
            else:
                verdict = "CLEAN"

            return {
                "vt_malicious"  : malicious,
                "vt_suspicious" : suspicious,
                "vt_harmless"   : harmless,
                "vt_total"      : total,
                "vt_reputation" : reputation,
                "country"       : country,
                "asn"           : asn,
                "isp"           : as_owner,
                "verdict"       : verdict
            }

        elif response.status_code == 401:
            print("[ERROR] Invalid VirusTotal API key.")
            return None
        elif response.status_code == 429:
            print("[WARN]  VT rate limit hit. Free tier = 500 requests/day, 4/min.")
            print("        Waiting 20 seconds before retrying...")
            time.sleep(20)
            return check_virustotal(ip, api_key)  # retry once
        elif response.status_code == 404:
            return {
                "vt_malicious": 0, "vt_suspicious": 0,
                "vt_harmless": 0, "vt_total": 0,
                "vt_reputation": 0, "country": "??",
                "asn": "N/A", "isp": "Not in VT database",
                "verdict": "UNKNOWN"
            }
        else:
            print(f"[WARN]  VT returned {response.status_code} for {ip}")
            return None

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Network error for {ip}: {e}")
        return None


def enrich_alerts(alerts, api_key):
    """Enrich each unique IP with VirusTotal data."""
    enriched = []
    seen_ips = {}  # cache — don't query same IP twice
    request_count = 0

    print(f"\n{'='*65}")
    print(f"  Wazuh Alert Enrichment (VirusTotal)")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Alerts to process : {len(alerts)}")
    print(f"  Unique IPs        : {len(set(a['src_ip'] for a in alerts))}")
    print(f"{'='*65}\n")

    for alert in alerts:
        ip = alert["src_ip"]

        if ip in seen_ips:
            rep = seen_ips[ip]
        else:
            print(f"[*] Querying VT for {ip} ...")
            rep = check_virustotal(ip, api_key)
            seen_ips[ip] = rep
            request_count += 1
            # VT free tier: max 4 requests/min — add small delay
            if request_count % 4 == 0:
                print("[*] Pausing 15s (VT rate limit) ...")
                time.sleep(15)

        if rep:
            result = {**alert, **rep}
        else:
            result = {**alert,
                      "vt_malicious": "N/A", "vt_suspicious": "N/A",
                      "vt_harmless": "N/A", "vt_total": "N/A",
                      "vt_reputation": "N/A", "country": "N/A",
                      "asn": "N/A", "isp": "N/A", "verdict": "UNKNOWN"}
        enriched.append(result)

    return enriched


def print_report(enriched):
    """Print enriched results to terminal."""
    print(f"\n{'='*65}")
    print(f"  ENRICHMENT RESULTS")
    print(f"{'='*65}")

    malicious  = [e for e in enriched if e.get("verdict") == "MALICIOUS"]
    suspicious = [e for e in enriched if e.get("verdict") == "SUSPICIOUS"]
    clean      = [e for e in enriched if e.get("verdict") == "CLEAN"]
    unknown    = [e for e in enriched if e.get("verdict") == "UNKNOWN"]

    print(f"\n  🔴 MALICIOUS  : {len(malicious)}")
    print(f"  🟠 SUSPICIOUS : {len(suspicious)}")
    print(f"  🟢 CLEAN      : {len(clean)}")
    print(f"  ⚪ UNKNOWN    : {len(unknown)}")
    print(f"\n{'─'*65}")

    # Print malicious first, then suspicious, then rest
    priority_order = malicious + suspicious + clean + unknown

    for e in priority_order:
        icon = {"MALICIOUS": "🔴", "SUSPICIOUS": "🟠",
                "CLEAN": "🟢", "UNKNOWN": "⚪"}.get(e.get("verdict"), "⚪")

        print(f"\n{icon} {e['src_ip']} — Rule {e['rule_id']} (Level {e['rule_level']})")
        print(f"   Agent      : {e['agent']}")
        print(f"   Rule       : {e['rule_desc']}")
        print(f"   Target User: {e['dst_user']}")
        print(f"   Time       : {e['timestamp']}")
        print(f"   VT Engines : {e.get('vt_malicious')} malicious / "
              f"{e.get('vt_suspicious')} suspicious / "
              f"{e.get('vt_total')} total")
        print(f"   Reputation : {e.get('vt_reputation')}  |  "
              f"Country: {e.get('country')}  |  "
              f"ISP: {e.get('isp')}")
        print(f"   ASN        : {e.get('asn')}")
        print(f"   Verdict    : {e.get('verdict')}")

    print(f"\n{'='*65}\n")


def export_csv(enriched, path):
    """Export enriched results to CSV."""
    if not enriched:
        return
    keys = enriched[0].keys()
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(enriched)
    print(f"[✓] Report exported to: {path}")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Wazuh Alert IP Enrichment via VirusTotal")
    parser.add_argument("--last",   type=int, default=MAX_ALERTS, help="Number of recent alerts to process")
    parser.add_argument("--export", action="store_true",          help="Export results to CSV")
    args = parser.parse_args()

    # Step 1 — Parse alerts
    alerts = parse_alerts(ALERTS_JSON_PATH, args.last)
    if not alerts:
        print("[INFO] No matching alerts found.")
        print("       Check ALERTS_JSON_PATH or wait for brute force activity.")
        return

    # Step 2 — Enrich
    enriched = enrich_alerts(alerts, VT_API_KEY)

    # Step 3 — Report
    print_report(enriched)

    # Step 4 — Export
    if args.export:
        export_csv(enriched, EXPORT_PATH)


if __name__ == "__main__":
    main()
