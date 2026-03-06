"""
SIEM Log Parser - Basic Security Event Analyzer
Supports: Apache/Nginx access logs, Windows Even logs (CSV export), Generic CSV logs
Author: Steven Ryckeley | Portfolio Project 
Date: 06-March-2026 | Version: 1.0
"""

import re
import csv
import json
import argparse
import os
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path

# ----------- DETECTION THRESHOLDS -----------
THRESHOLDS = {
    "bruteforce_attempts": 5,             # Failed logins from same IP within log window
    "http_error_spike": 10,               # 4xx/5xx errors from same IP
    "large_transfer_bytes": 50_000_000,   # 50MB in a single transfer
    "after_hours_start": 20,              # 8 PM
    "after_hours_end": 6,                 # 6 AM
    "rare_user_agent_keywords": [
        "sqlmap", "nikto", "nmap", "masscan", "zgrab", 
        "hydra", "medusa", "burp", "dirbuster", "gobuster",
        "python-requests", "curl", "wget", "scrapy"
    ],
    "suspicious_paths": [
        "/admin", "/wp-admin", "/.env", "/config", "/passwd",
        "/etc/shadow", "/../", "/.git", "/phpmyadmin",
        "/xmlrpc.php", "/shell", "cmd=", "exec(", "eval("
    ],
    "windows_critical_events": {
        "4625": "Failed Login",
        "4648": "Logon with Explicit Credentials",
        "4720": "User Account Created",
        "4722": "User Account Enabled",
        "4723": "Password Change Attempted",
        "4724": "Password Reset Attempted",
        "4725": "User Account Disabled",
        "4726": "User Account Deleted",
        "4728": "Member Added to Security Group",
        "4732": "Member Added to Local Group",
        "4756": "Member Added to Universal Group",
        "4768": "Kerberos TGT Requested",
        "4769": "Kerberos Service Ticket Requested",
        "4771": "Kerberos Pre-auth Failed",
        "4776": "NTLM Auth Attempted",
        "1102": "Audit Log Cleared",
        "4698": "Scheduled Task Created",
        "7045": "New Service Installed",
        "4688": "New Process Created",
    }
}

# ----------- DATA STRUCTURES -----------
class Finding:
    SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

    def __init__(self, severity, category, description, detail, source_file, count = 1):
        self.severity = severity
        self.category = category
        self.description = description
        self.detail = detail
        self.source_file = source_file
        self.count = count
        self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return {
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "detail": self.detail,
            "source_file": self.source_file,
            "count": self.count
        }
    
# ----------- APACHE/NGINX LOG PARSER -----------
APACHE_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

def parse_apache_log(filepath):
    findings = []
    ip_errors = defaultdict(int)
    ip_requests = defaultdict(int)
    ip_paths = defaultdict(set)
    after_hours_ips = defaultdict(int)
    agent_hits = defaultdict(list)

    with open(filepath, "r", errors = "replace") as f:
        for line in f:
            m = APACHE_PATTERN.match(line.strip())
            if not m:
                continue
            ip = m.group("ip")
            status = int(m.group("status"))
            path = m.group("path")
            agent = m.group("agent")
            raw_bytes = m.group("bytes")
            try:
                byte_count = int(raw_bytes)
            except ValueError:
                byte_count = 0

            ip_requests[ip] += 1
            ip_paths[ip].add(path)

            # Parse timestamp for after-hours chack
            try:
                dt = datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S")
                hour = dt.hour
                if hour >= THRESHOLDS["after_hours_start"] or hour < THRESHOLDS["after_hours_end"]:
                    after_hours_ips[ip] += 1
            except Exception:
                pass

            # Error spike detection
            if status >= 400:
                ip_errors[ip] += 1

            #Large transfer detection
            if byte_count > THRESHOLDS["large_transfer_bytes"]:
                findings.append(Finding(
                    "HIGH", "Data Exfiltration",
                    f"Unusually large response to {ip}",
                    f"Path: {path} | Size: {byte_count:,} bytes | Status: {status}",
                    filepath
                ))

            # Suspicious user agent
            agent_lower = agent.lower()
            for kw in THRESHOLDS["rare_user_agent_keywords"]:
                if kw in agent_lower:
                    agent_hits[ip].append(f"{path} (agent: {agent[:80]})")
                    break

            # Suspicious path
            for sp in THRESHOLDS["suspicious_paths"]:
                if sp.lower() in path.lower():
                    findings.append(Finding(
                        "MEDIUM", "Suspicious Path Access",
                        f"Sensitive path accessed by {ip}",
                        f"Path: {path} | Status: {status}",
                        filepath
                    ))
                    break

    # Aggregate findings
    for ip, count in ip_errors.items():
        if count >= THRESHOLDS["http_error_spike"]:
            sev = "HIGH" if count >= 50 else "MEDIUM"
            findings.append(Finding(
                sev, "HTTP Error Spike",
                f"High error rate from {ip}",
                f"{count} HTTP 4xx/5xx errors detected",
                filepath, count
            ))

    for ip, count in after_hours_ips.items():
        if count >= 3:
            findings.append(Finding(
                "LOW", "After-Hours Activity",
                f"Off-hours requests from {ip}",
                f"{count} requests between 8PM-6AM",
                filepath, count
            ))

    for ip, hits in agent_hits.items():
        findings.append(Finding(
            "HIGH", "Suspicious User-Agent / Scanner",
            f"Known attack tool signature form {ip}",
            f"Paths Hit: {'; '.join(hits[:5])}",
            filepath, len(hits)
        ))

    return findings
    
# ----------- WINDOWS EVENT LOG PARSER -----------
def parse_windows_event_log(filepath):
    """
    Expects CSV export from Windows Event Viewer.
    Common columns: Level, Date and Time, Source, Event ID, Task Category, Description
    """
    findings = []
    failed_logins = defaultdict(list)
    account_changes = []
    log_cleared = False
    new_services = []
    scheduled_tasks = []

    with open(filepath, "r", errors = "replace") as f:
        reader = csv.DictReader(f)
        # Normalize headers (strip whitespace, lowercase for matching)
        fieldnames = [h.strip() for h in (reader.fieldnames or [])]

        for raw_row in reader:
            row = {k.strip(): v.strip() for k, v in raw_row.items() if k}

            # Try to get Event ID - handle different column names
            event_id = (
                row.get("Event ID") or row.get("EventID") or
                row.get("event_id") or row.get("Id") or ""
            ).strip()

            description = (
                row.get("Description") or row.get("Message") or
                row.get("description") or ""
            )

            timestamp = (
                row.get("Date and Time") or row.get("TimeCreated") or
                row.get("date") or row.get("Time") or "Unknown"
            )

            # Extract username/IP from description when possible
            user_match = re.search(r"Account Name:\s+(\S+)", description)
            ip_match = re.search(r"Source Network Address:\s+(\S+)", description)
            username = user_match.group(1) if user_match else "Unknown"
            src_ip = ip_match.group(1) if ip_match else "Unknown"

            if event_id == "4625":  # Failed login
                failed_logins[src_ip].append({"user": username, "time": timestamp})

            elif event_id in ("4720", "4726", "4728", "4732", "4756"):
                label = THRESHOLDS["windows_critical_events"].get(event_id, "Account Change")
                account_changes.append({"event": label, "user": username, "time": timestamp})

            elif event_id == "1102":
                log_cleared = True
                findings.append(Finding(
                    "CRITICAL", "Log Tampering",
                    "Security audit log was cleared",
                    f"Timestamp: {timestamp} | User: {username}",
                    filepath
                ))

            elif event_id == "7045":
                service_match = re.search(r"Service Name:\s+(.+)", description)
                svc = service_match.group(1).strip() if service_match else "Unknown Service"
                new_services.append({"service": svc, "time": timestamp})

            elif event_id == "4698":
                task_match = re.search(r"Task Name:\s+(.+)", description)
                task = task_match.group(1).strip() if task_match else "Unknown Task"
                scheduled_tasks.append({"task": task, "time": timestamp})

    # Aggregate failed logins
    for ip, attempts in failed_logins.items():
        count = len(attempts)
        if count >= THRESHOLDS["bruteforce_attempts"]:
            sev = "CRITICAL" if count >= 20 else "HIGH"
            users = list(set(a["user"] for a in attempts))
            findings.append(Finding(
                sev, "Brute Force Attack",
                f"Multiple failed logins from {ip}",
                f"{count} failed attempts | Accounts Targeted: {', '.join(users[:5])}",
                filepath, count
            ))

    for change in account_changes:
        findings.append(Finding(
            "HIGH", "Account Modification",
            change["event"],
            f"User: {change['user']} | Time: {change['time']}",
            filepath
        ))

    for svc in new_services:
        findings.append(Finding(
            "HIGH", "Persistence Mechanism",
            f"New service installed: {svc['service']}",
            f"Time: {svc['time']}",
            filepath
        ))

    for task in scheduled_tasks:
        findings.append(Finding(
            "MEDIUM", "Persistence Mechanism",
            f"Scheduled task created: {task['task']}",
            f"Time: {task['time']}",
            filepath
        ))

    return findings

# ----------- GENERIC CSV LOG PARSER -----------
GENERIC_SUSPICIOUS_KEYWORDS = [
    "failed", "failure", "denied", "blocked", "error", "unauthorized",
    "attack", "malicious", "exploit", "injection", "overflow", "brute",
    "scan", "probe", "suspect", "anomaly", "alert", "critical", "warning"
]

def parse_generic_csv(filepath):
    findings = []
    keyword_hits = defaultdict(list)
    row_count = 0

    with open(filepath, "r", errors = "replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row_count += 1
            row_str = " ".join(str(v) for v in row.values()).lower()

            for kw in GENERIC_SUSPICIOUS_KEYWORDS:
                if kw in row_str:
                    keyword_hits[kw].append(dict(row))
                    break  # One finding per row

    for kw, rows in keyword_hits.items():
        count = len(rows)
        sev = "HIGH" if kw in ("attack", "exploit", "injection", "overflow", "malicious") else \
              "MEDIUM" if kw in ("failed", "failure", "denied", "blocked", "brute", "scan") else "LOW"
        sample = str(rows[0])[:200] if rows else ""
        findings.append(Finding(
            sev, "Suspicious Log Entry",
            f'Keyword "{kw}" found in CSV log',
            f"{count} occurrence(s) | Sample: {sample}",
            filepath, count
        ))

    if not findings and row_count > 0:
        findings.append(Finding(
            "INFO", "Clean Log",
            "No suspicious keywords detected in generic CSV log",
            f"{row_count} rows analyzed",
            filepath
        ))

    return findings

# ----------- AUTO-DETECT LOG TYPE -----------
def detect_and_parse(filepath):
    path = Path(filepath)
    ext = path.suffix.lower()
    name = path.name.lower()

    # Read first few lines to sniff format
    with open(filepath, "r", errors = "replace") as f:
        sample = f.read(2000)

    # Windows Event Log CSV detection
    if ext == ".csv":
        if any(h in sample for h in ["Event ID", "EventID", "Task Category", "Date and Time"]):
            print(f"  [+] Detected: Windows Event Log CSV → {path.name}")
            return parse_windows_event_log(filepath), "Windows Event Log"
        else:
            print(f"  [+] Detected: Generic CSV → {path.name}")
            return parse_generic_csv(filepath), "Generic CSV"

    # Apache/Nginx detection
    if APACHE_PATTERN.search(sample):
        print(f"  [+] Detected: Apache/Nginx Access Log → {path.name}")
        return parse_apache_log(filepath), "Apache/Nginx Access Log"

    # Fallback: try Apache then generic
    print(f"  [?] Unknown format, attempting Apache parse → {path.name}")
    return parse_apache_log(filepath), "Unknown (Apache attempted)"

# ----------- HTML REPOPRT GENERATOR -----------
SEVERITY_COLORS = {
    "CRITICAL": ("#ff3b3b", "#2a0a0a"),
    "HIGH":     ("#ff8c42", "#1f1208"),
    "MEDIUM":   ("#f5d020", "#1e1a03"),
    "LOW":      ("#4fc3f7", "#031d26"),
    "INFO":     ("#90a4ae", "#0d1317"),
}

def generate_html_report(all_findings, log_sources, output_path):
    now = datetime.now().strftime("%B %d, %Y at %H:%M:%S")

    counts = Counter(f.severity for f in all_findings)
    total = len(all_findings)

    # Sort by severity
    severity_order = Finding.SEVERITY_ORDER
    sorted_findings = sorted(all_findings, key = lambda f: severity_order.get(f.severity, 99))

# Build findings rows
    rows_html = ""
    for f in sorted_findings:
        color, bg = SEVERITY_COLORS.get(f.severity, ("#ccc", "#111"))
        rows_html += f"""
        <tr class="finding-row" data-severity="{f.severity}">
          <td><span class="badge" style="background:{bg};color:{color};border:1px solid {color}40">{f.severity}</span></td>
          <td class="cat">{f.category}</td>
          <td>{f.description}</td>
          <td class="detail">{f.detail}</td>
          <td class="src">{Path(f.source_file).name}</td>
          <td class="cnt">{f.count}</td>
        </tr>"""

    # Source file summary
    sources_html = ""
    for src, log_type in log_sources.items():
        src_count = sum(1 for f in all_findings if f.source_file == src)
        sources_html += f"""
        <div class="source-card">
          <div class="source-name">{Path(src).name}</div>
          <div class="source-type">{log_type}</div>
          <div class="source-count">{src_count} finding(s)</div>
        </div>"""

 # Severity summary cards
    sev_cards = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        color, bg = SEVERITY_COLORS[sev]
        cnt = counts.get(sev, 0)
        sev_cards += f"""
        <div class="stat-card" style="border-color:{color}33;background:{bg}">
          <div class="stat-num" style="color:{color}">{cnt}</div>
          <div class="stat-label">{sev}</div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SIEM Report — {now}</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=DM+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg: #0a0d12;
    --surface: #0f1419;
    --border: #1e2a35;
    --text: #c8d6e0;
    --muted: #4a6070;
    --accent: #00e5ff;
    --mono: 'Share Tech Mono', monospace;
    --sans: 'DM Sans', sans-serif;
  }}
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    min-height: 100vh;
  }}

  /* ── HEADER ── */
  .header {{
    background: linear-gradient(135deg, #0d1f2d 0%, #0a0d12 60%);
    border-bottom: 1px solid var(--border);
    padding: 2.5rem 3rem;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute;
    top: -40px; right: -40px;
    width: 300px; height: 300px;
    border-radius: 50%;
    background: radial-gradient(circle, #00e5ff08 0%, transparent 70%);
  }}
  .header-top {{
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-bottom: 0.5rem;
  }}
  .shield {{
    width: 40px; height: 40px;
    background: linear-gradient(135deg, #00e5ff22, #00e5ff08);
    border: 1px solid #00e5ff44;
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.3rem;
  }}
  h1 {{
    font-family: var(--mono);
    font-size: 1.5rem;
    color: #fff;
    letter-spacing: 0.05em;
  }}
  .header-meta {{
    font-size: 0.78rem;
    color: var(--muted);
    font-family: var(--mono);
    margin-top: 0.3rem;
  }}
  .header-meta span {{ color: var(--accent); }}

  /* ── MAIN ── */
  main {{ padding: 2rem 3rem; max-width: 1400px; margin: 0 auto; }}

  /* ── STAT CARDS ── */
  .stats-row {{
    display: flex;
    gap: 1rem;
    margin-bottom: 2rem;
    flex-wrap: wrap;
  }}
  .stat-card {{
    flex: 1;
    min-width: 100px;
    padding: 1.2rem 1.5rem;
    border-radius: 10px;
    border: 1px solid;
    text-align: center;
  }}
  .stat-num {{
    font-family: var(--mono);
    font-size: 2rem;
    font-weight: 700;
    line-height: 1;
  }}
  .stat-label {{
    font-size: 0.7rem;
    color: var(--muted);
    letter-spacing: 0.1em;
    margin-top: 0.4rem;
    font-family: var(--mono);
  }}
  .total-card {{
    background: #111820;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1.2rem 2rem;
    display: flex;
    align-items: center;
    gap: 1rem;
  }}
  .total-num {{
    font-family: var(--mono);
    font-size: 2.5rem;
    color: #fff;
  }}
  .total-label {{
    font-size: 0.75rem;
    color: var(--muted);
    letter-spacing: 0.08em;
  }}

  /* ── SECTION TITLES ── */
  .section-title {{
    font-family: var(--mono);
    font-size: 0.7rem;
    letter-spacing: 0.15em;
    color: var(--accent);
    text-transform: uppercase;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }}
  .section-title::after {{
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border);
  }}

  /* ── SOURCES ── */
  .sources-row {{
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
    margin-bottom: 2.5rem;
  }}
  .source-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.9rem 1.2rem;
  }}
  .source-name {{
    font-family: var(--mono);
    font-size: 0.85rem;
    color: #fff;
    margin-bottom: 0.2rem;
  }}
  .source-type {{
    font-size: 0.72rem;
    color: var(--accent);
  }}
  .source-count {{
    font-size: 0.72rem;
    color: var(--muted);
    margin-top: 0.2rem;
  }}

  /* ── FILTER BUTTONS ── */
  .filter-row {{
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1rem;
    flex-wrap: wrap;
  }}
  .filter-btn {{
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--muted);
    padding: 0.35rem 0.9rem;
    border-radius: 20px;
    font-size: 0.75rem;
    font-family: var(--mono);
    cursor: pointer;
    transition: all 0.2s;
    letter-spacing: 0.05em;
  }}
  .filter-btn:hover, .filter-btn.active {{
    border-color: var(--accent);
    color: var(--accent);
    background: #00e5ff0d;
  }}

  /* ── TABLE ── */
  .table-wrap {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
  }}
  table {{ width: 100%; border-collapse: collapse; }}
  thead tr {{
    background: #111820;
    border-bottom: 1px solid var(--border);
  }}
  th {{
    padding: 0.8rem 1rem;
    text-align: left;
    font-family: var(--mono);
    font-size: 0.65rem;
    letter-spacing: 0.12em;
    color: var(--muted);
    text-transform: uppercase;
    font-weight: 400;
  }}
  td {{
    padding: 0.85rem 1rem;
    border-bottom: 1px solid #1a2430;
    vertical-align: top;
    font-size: 0.82rem;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr.finding-row {{ transition: background 0.15s; }}
  tr.finding-row:hover {{ background: #ffffff05; }}
  tr.finding-row.hidden {{ display: none; }}

  .badge {{
    display: inline-block;
    padding: 0.2rem 0.55rem;
    border-radius: 4px;
    font-family: var(--mono);
    font-size: 0.65rem;
    letter-spacing: 0.08em;
    white-space: nowrap;
  }}
  .cat {{ color: #8ab4c8; font-size: 0.8rem; }}
  .detail {{ color: var(--muted); font-size: 0.78rem; font-family: var(--mono); max-width: 380px; word-break: break-word; }}
  .src {{ color: var(--muted); font-family: var(--mono); font-size: 0.75rem; }}
  .cnt {{ text-align: center; font-family: var(--mono); color: var(--muted); }}

  /* ── FOOTER ── */
  footer {{
    text-align: center;
    padding: 2rem;
    font-family: var(--mono);
    font-size: 0.7rem;
    color: var(--muted);
    border-top: 1px solid var(--border);
    margin-top: 3rem;
  }}

  /* ── EMPTY STATE ── */
  .empty {{
    text-align: center;
    padding: 3rem;
    color: var(--muted);
    font-family: var(--mono);
    font-size: 0.85rem;
  }}
</style>
</head>
<body>

<div class="header">
  <div class="header-top">
    <div class="shield">🛡</div>
    <h1>SIEM LOG ANALYSIS REPORT</h1>
  </div>
  <div class="header-meta">
    Generated: <span>{now}</span> &nbsp;|&nbsp;
    Files analyzed: <span>{len(log_sources)}</span> &nbsp;|&nbsp;
    Total findings: <span>{total}</span>
  </div>
</div>

<main>
  <!-- SEVERITY SUMMARY -->
  <div class="section-title">Severity Summary</div>
  <div style="display:flex;gap:1rem;margin-bottom:2rem;flex-wrap:wrap;align-items:stretch">
    <div class="total-card">
      <div class="total-num">{total}</div>
      <div>
        <div style="color:#fff;font-weight:500">Total Findings</div>
        <div class="total-label">Across all log sources</div>
      </div>
    </div>
    <div class="stats-row" style="margin:0;flex:1">
      {sev_cards}
    </div>
  </div>

  <!-- SOURCES -->
  <div class="section-title">Log Sources Analyzed</div>
  <div class="sources-row">{sources_html}</div>

  <!-- FINDINGS TABLE -->
  <div class="section-title">Findings</div>
  <div class="filter-row">
    <button class="filter-btn active" onclick="filterFindings('ALL')">ALL</button>
    <button class="filter-btn" onclick="filterFindings('CRITICAL')" style="border-color:#ff3b3b44;color:#ff3b3b">CRITICAL</button>
    <button class="filter-btn" onclick="filterFindings('HIGH')" style="border-color:#ff8c4244;color:#ff8c42">HIGH</button>
    <button class="filter-btn" onclick="filterFindings('MEDIUM')" style="border-color:#f5d02044;color:#f5d020">MEDIUM</button>
    <button class="filter-btn" onclick="filterFindings('LOW')" style="border-color:#4fc3f744;color:#4fc3f7">LOW</button>
    <button class="filter-btn" onclick="filterFindings('INFO')" style="border-color:#90a4ae44;color:#90a4ae">INFO</button>
  </div>
  <div class="table-wrap">
    {"<div class='empty'>✓ No findings detected. All logs appear clean.</div>" if not sorted_findings else f"""
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Category</th>
          <th>Description</th>
          <th>Detail</th>
          <th>Source</th>
          <th>Count</th>
        </tr>
      </thead>
      <tbody id="findings-body">
        {rows_html}
      </tbody>
    </table>"""}
  </div>

</main>

<footer>
  SIEM Log Parser · Portfolio Project · Steven &nbsp;|&nbsp;
  This report is for educational purposes only
</footer>

<script>
function filterFindings(severity) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding-row').forEach(row => {{
    if (severity === 'ALL' || row.dataset.severity === severity) {{
      row.classList.remove('hidden');
    }} else {{
      row.classList.add('hidden');
    }}
  }});
}}
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n  [✓] Report saved to: {output_path}")

# ----------- MAIN -----------
def main():
    parser = argparse.ArgumentParser(
        description = "SIEM Log Parser — Analyzes Apache, Windows Event, and CSV logs for threats",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = """
Examples:
  python siem_parser.py access.log
  python siem_parser.py events.csv
  python siem_parser.py *.log *.csv --output my_report.html
        """
    )
    parser.add_argument("files", nargs = "+", help = "Log file(s) to analyze")
    parser.add_argument("--output", "-o", default = "siem_report.html",
                        help = "Output HTML report path (default: siem_report.html)")
    parser.add_argument("--json", "-j", action = "store_true",
                        help = "Also save findings as JSON")
    args = parser.parse_args()

    print("\n╔══════════════════════════════════════╗")
    print("║      SIEM Log Parser  v1.0           ║")
    print("╚══════════════════════════════════════╝\n")

    all_findings = []
    log_sources = {}

    for filepath in args.files:
        if not os.path.exists(filepath):
            print(f"  [!] File not found: {filepath}")
            continue
        print(f"Parsing: {filepath}")
        try:
            findings, log_type = detect_and_parse(filepath)
            all_findings.extend(findings)
            log_sources[filepath] = log_type
            print(f"      → {len(findings)} finding(s)\n")
        except Exception as e:
            print(f"  [!] Error parsing {filepath}: {e}\n")

    # Summary
    counts = Counter(f.severity for f in all_findings)
    print("─" * 42)
    print(f"  Total findings : {len(all_findings)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if counts.get(sev, 0):
            print(f"  {sev:<12}: {counts[sev]}")
    print("─" * 42)

    # Generate report
    generate_html_report(all_findings, log_sources, args.output)

    # Optional JSON export
    if args.json:
        json_path = args.output.replace(".html", ".json")
        with open(json_path, "w") as jf:
            json.dump([f.to_dict() for f in all_findings], jf, indent=2)
        print(f"  [✓] JSON saved to: {json_path}")

    print()

if __name__ == "__main__":
    main()