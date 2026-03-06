# 🛡️ SIEM Log Parser

A Python-based security event analyzer that parses multiple log formats, detects threats and suspicious behavior, and generates a polished interactive HTML report. Built as a portfolio project to demonstrate applied cybersecurity and Python programming skills.

---

## 📋 Overview

This tool simulates the core function of a Security Information and Event Management (SIEM) system — ingesting raw log data, applying detection rules, and surfacing actionable security findings. It auto-detects the log format, runs analysis across multiple detection categories, and outputs a filterable HTML report with severity-ranked findings.

---

## ✨ Features

- **Multi-format log support** — Apache/Nginx access logs, Windows Event Logs (CSV export), and generic CSV logs
- **Automatic format detection** — no need to specify the log type manually
- **Threat detection across 8+ categories** — see full list below
- **Interactive HTML report** — filterable by severity with a dark-themed security dashboard aesthetic
- **Optional JSON export** — for integration with other tools or further analysis
- **Zero external dependencies** — built entirely on the Python standard library

---

## 🔍 Detection Categories

| Category | Log Source | Severity |
|---|---|---|
| Brute Force / Credential Attack | Windows Events, Apache | CRITICAL / HIGH |
| Log Tampering (Event 1102) | Windows Events | CRITICAL |
| Suspicious Scanner / User-Agent | Apache | HIGH |
| Account Creation & Privilege Escalation | Windows Events | HIGH |
| Persistence (New Services, Scheduled Tasks) | Windows Events | HIGH |
| HTTP Error Spike | Apache | HIGH / MEDIUM |
| Suspicious Path Access | Apache | MEDIUM |
| After-Hours Activity | Apache | LOW |
| Suspicious Keywords | Generic CSV | HIGH / MEDIUM / LOW |

---

## 🚀 Getting Started

### Prerequisites
- Python 3.7 or higher
- No additional packages required

### Installation
```bash
git clone https://github.com/StevenRyckeley/siem-log-parser.git
cd siem-log-parser
```

### Usage
```bash
# Analyze a single file
python SIEM_Parser.py access.log

# Analyze multiple files at once
python SIEM_Parser.py access.log events.csv firewall.csv

# Specify a custom output path
python SIEM_Parser.py access.log --output my_report.html

# Also export findings as JSON
python SIEM_Parser.py access.log --json
```

The tool will print a summary to the terminal and generate `siem_report.html` in the current directory. Open the HTML file in any browser to view the full report.

---

## 🧪 Testing with Sample Logs

Three sample log files are included to demonstrate the tool against realistic attack scenarios:

| File | Type | Scenarios Included |
|---|---|---|
| `test_apache.log` | Apache access log | SQLmap scanner, Nikto scanner, directory traversal, large file transfer, after-hours access |
| `test_windows_events.csv` | Windows Event Log | Brute force (Event 4625), privilege escalation, new services, scheduled tasks, log clearing (Event 1102) |
| `test_firewall.csv` | Generic CSV | SSH brute force, external RDP attempts, SMB lateral movement, port scanning, SQL injection |

Run all three at once:
```bash
python SIEM_Parser.py test_apache.log test_windows_events.csv test_firewall.csv
```

---

## 📁 Project Structure

```
siem-log-parser/
├── SIEM_Parser.py            # Main script
├── test_apache.log           # Sample Apache access log
├── test_windows_events.csv   # Sample Windows Event Log export
├── test_firewall.csv         # Sample firewall/network CSV log
└── README.md
```

---

## 🪟 Using with Real Windows Event Logs

1. Open **Event Viewer** (`Win + R` → `eventvwr`)
2. Navigate to `Windows Logs → Security`
3. In the right panel, click **"Save All Events As..."**
4. Save as **CSV (Comma Separated)**
5. Run the parser against the exported file:
```bash
python SIEM_Parser.py Security_Events.csv
```

> ⚠️ **Note:** Do not upload real exported event logs to public repositories. They may contain sensitive system and user information.

---

## 🗺️ MITRE ATT&CK Mapping

Several detections in this tool map directly to the [MITRE ATT&CK Framework](https://attack.mitre.org/):

| Detection | MITRE Technique |
|---|---|
| Brute Force Login Attempts | [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/) |
| New Service Installed | [T1543.003 - Create or Modify System Process](https://attack.mitre.org/techniques/T1543/003/) |
| Scheduled Task Created | [T1053.005 - Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) |
| Audit Log Cleared | [T1070.001 - Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/) |
| Suspicious User-Agent (Scanner) | [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/) |
| After-Hours Activity | [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/) |

---

## 🛠️ Built With

- **Python 3** — core language
- **re** — regex-based log parsing
- **csv** — CSV log ingestion
- **collections** — threat aggregation logic
- **argparse** — CLI interface
- **HTML / CSS / JavaScript** — report generation

---

## 📄 License

This project is intended for educational and portfolio purposes only. Do not use against systems you do not own or have explicit permission to test.

---

*Portfolio Project — Steven Ryckeley | Information Systems, University of Texas at Arlington*
