# Snort & Wireshark Intrusion Detection Lab 🛡️🔍

A reproducible network defense and intrusion detection lab repository demonstrating custom **Snort IDS** rules with false-positive tuning notes, annotated **Wireshark** packet capture baselines, and an automated **Python** alert parser for structured JSON/CSV incident reporting.

## Repository Structure

```text
snort-wireshark-intrusion-lab/
├── README.md
├── rules/
│   └── local.rules
├── analysis/
│   └── pcap-baseline-analysis.md
└── scripts/
    └── snort_alert_parser.py
```

## Key Deliverables
1. **`rules/local.rules`**: Custom Snort signatures for SQL Injection (`UNION SELECT`), outbound reverse shell activity, and SSH brute-force spikes, paired with documented false-positive tuning guidance.
2. **`analysis/pcap-baseline-analysis.md`**: Comparative Wireshark traffic analysis documenting normal pre-attack network baselines against simulated intrusion anomalies.
3. **`scripts/snort_alert_parser.py`**: Python CLI log parser that extracts high-severity Snort alerts into structured JSON or CSV summaries.

## Quick Start

```bash
# Parse high-priority Snort alerts to stdout
python3 scripts/snort_alert_parser.py /var/log/snort/alert.fast --priority 1

# Export filtered alerts to JSON
python3 scripts/snort_alert_parser.py /var/log/snort/alert.fast --priority 2 --json high_severity_alerts.json

# Export filtered alerts to CSV
python3 scripts/snort_alert_parser.py /var/log/snort/alert.fast --priority 1 --csv security_incidents.csv
```
