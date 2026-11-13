#!/usr/bin/env python3
"""
Snort Alert Parser Script
Author: Mark Edward Brown (mark-brown-cybersecurity)
Description: Parses raw Snort log files, filters high-severity alerts, 
             and exports structured JSON or CSV summaries.
"""

import argparse
import csv
import json
import re
import sys

# Regex pattern matching standard Snort fast log format:
# 06/13-12:34:56.789012 [**] [1:1000001:2] EXPLOIT-KIT SQL Injection Attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 192.168.1.50:54321 -> 10.0.0.5:80
SNORT_PATTERN = re.compile(
    r'(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+'
    r'\[\*\*\]\s+\[(?P<gen_id>\d+):(?P<sig_id>\d+):(?P<rev>\d+)\]\s+'
    r'(?P<message>.+?)\s+\[\*\*\]\s+'
    r'\[Classification:\s*(?P<classification>[^\]]+)\]\s+'
    r'\[Priority:\s*(?P<priority>\d+)\]\s+'
    r'\{(?P<protocol>\w+)\}\s+'
    r'(?P<src_ip>[\d\.]+):?(?P<src_port>\d*)\s*->\s*'
    r'(?P<dst_ip>[\d\.]+):?(?P<dst_port>\d*)'
)


def parse_snort_logs(log_file_path: str, min_priority: int = 2) -> list:
    parsed_alerts = []
    try:
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = SNORT_PATTERN.search(line.strip())
                if match:
                    data = match.groupdict()
                    data['priority'] = int(data['priority'])
                    # Filter by priority (Priority 1 is highest severity in Snort)
                    if data['priority'] <= min_priority:
                        parsed_alerts.append(data)
    except FileNotFoundError:
        print(f"[!] Error: Log file not found at '{log_file_path}'.", file=sys.stderr)
        sys.exit(1)
    return parsed_alerts


def export_json(alerts: list, output_path: str):
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(alerts, f, indent=2)
    print(f"[+] Successfully exported {len(alerts)} alerts to JSON: {output_path}")


def export_csv(alerts: list, output_path: str):
    if not alerts:
        print("[!] No alerts to export.")
        return
    fieldnames = list(alerts[0].keys())
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(alerts)
    print(f"[+] Successfully exported {len(alerts)} alerts to CSV: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Parse and filter Snort IDS alert logs into structured formats.")
    parser.add_argument("logfile", help="Path to Snort alert file (e.g., alert.fast)")
    parser.add_argument("--priority", type=int, default=1, help="Max priority level to include (1=High, 2=Medium, 3=Low). Default: 1")
    parser.add_argument("--json", help="Export filtered alerts to specified JSON file path")
    parser.add_argument("--csv", help="Export filtered alerts to specified CSV file path")
    
    args = parser.parse_args()

    print(f"[*] Parsing Snort logs from '{args.logfile}' (Max Priority: {args.priority})...")
    alerts = parse_snort_logs(args.logfile, min_priority=args.priority)
    print(f"[*] Found {len(alerts)} matching high-severity alerts.")

    if args.json:
        export_json(alerts, args.json)
    if args.csv:
        export_csv(alerts, args.csv)
    
    if not args.json and not args.csv:
        # Print summary to stdout if no export format is specified
        for alert in alerts:
            print(f"[{alert['timestamp']}] Priority {alert['priority']} | {alert['message']} | Src: {alert['src_ip']} -> Dst: {alert['dst_ip']}")


if __name__ == "__main__":
    main()
