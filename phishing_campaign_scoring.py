import csv
import re
import argparse
import sys
import os
from difflib import SequenceMatcher
from collections import defaultdict
from datetime import datetime

"""
Phishing Campaign Scoring Tool
==============================

Version   : v1.2 (Stable)
Status    : Locked
Date      : 2026-04-16

Purpose:
--------
Batch analysis of phishing emails to identify campaigns using
high-accuracy, graph-based clustering on normalized subject lines.

Key Properties:
---------------
- Order-independent clustering (connected components)
- Transitive similarity handling (A~B~C ⇒ same campaign)
- Deterministic and explainable
- No external dependencies (stdlib only)
- SOC / IR friendly
- Offline-safe
- Audit-ready

Change Summary (v1.2):
---------------------
- Added Singleton Emails section to HTML report

Change Policy:
--------------
Any further functional or analytical change requires v1.3+
"""

# =========================
# Argument parsing
# =========================

parser = argparse.ArgumentParser(
    description="Cluster and score phishing emails from an XSOAR CSV export (30-day snapshot)"
)

parser.add_argument("input_csv", help="Path to the XSOAR phishing email CSV export")
parser.add_argument("--summary-only", action="store_true",
                    help="Print campaign summary only (no per-email details)")
parser.add_argument("--export-csv", nargs="?", const="AUTO", metavar="FILE",
                    help="Export campaign summary to CSV (optional filename)")
parser.add_argument("--include-singletons", action="store_true",
                    help="Include singleton (1-email) clusters in the output")
parser.add_argument("--export-html", nargs="?", const="AUTO", metavar="FILE",
                    help="Export results to an HTML report (optional filename)")

args = parser.parse_args()
INPUT_CSV = args.input_csv

# =========================
# Configuration
# =========================

SIMILARITY_THRESHOLD = 0.85

WEIGHTS = {
    "subject": 0.50,
    "sender": 0.30,
    "ip": 0.20,
}

# =========================
# Normalization helpers
# =========================

def normalize_subject(s):
    if not s:
        return ""

    s = s.lower().strip()

    while s.startswith(("re:", "fw:", "fwd:", "sv:")):
        s = s.split(":", 1)[1].strip()

    if s.startswith("phishing:"):
        s = s.replace("phishing:", "", 1)

    s = re.sub(r'\b[a-f0-9]{8,}\b', '', s)
    s = re.sub(r'#\w+', '', s)
    s = re.sub(r'\b\d{1,2}/\d{1,2}/\d{2,4}\b', '', s)
    s = re.sub(r'\b\d{1,2}:\d{2}(:\d{2})?\s*(am|pm)?\b', '', s)

    s = re.sub(r'\([^)]*\)', '', s)
    s = re.sub(r'[^a-z0-9\s]', ' ', s)
    s = re.sub(r'\s+', ' ', s)

    return s.strip()

def similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()

# =========================
# Scoring helpers
# =========================

def frequency_score(count):
    if count >= 10:
        return 1.0
    elif count >= 5:
        return 0.8
    elif count >= 2:
        return 0.6
    return 0.3

def confidence_band(score):
    if score >= 0.80:
        return "High"
    elif score >= 0.60:
        return "Medium-High"
    elif score >= 0.40:
        return "Medium"
    return "Low"

def auto_html_filename():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"phishing_campaign_report_{ts}.html"

def auto_csv_filename():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"phishing_campaign_summary_{ts}.csv"

# =========================
# Load CSV data
# =========================

emails = []

try:
    with open(INPUT_CSV, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            subject = (row.get("EOC Phish EmailSubject") or "").strip()
            sender = (row.get("EOC Email From") or "").strip().lower()
            ip = (row.get("EOC Sender IP") or "").strip()

            emails.append({
                "raw_subject": subject,
                "norm_subject": normalize_subject(subject),
                "sender": sender,
                "ip": ip
            })
except FileNotFoundError:
    print(f"\n❌ Error: file not found: {INPUT_CSV}")
    sys.exit(1)

# =========================
# Frequency analysis
# =========================

subject_counts = defaultdict(int)
sender_counts = defaultdict(int)
ip_counts = defaultdict(int)

for e in emails:
    if e["norm_subject"]:
        subject_counts[e["norm_subject"]] += 1
    if e["sender"]:
        sender_counts[e["sender"]] += 1
    if e["ip"]:
        ip_counts[e["ip"]] += 1

# =========================
# Email-level scoring
# =========================

for e in emails:
    score_sum = 0.0
    weight_sum = 0.0

    if e["norm_subject"]:
        score_sum += frequency_score(subject_counts[e["norm_subject"]]) * WEIGHTS["subject"]
        weight_sum += WEIGHTS["subject"]

    if e["sender"]:
        score_sum += frequency_score(sender_counts[e["sender"]]) * WEIGHTS["sender"]
        weight_sum += WEIGHTS["sender"]

    if e["ip"]:
        score_sum += frequency_score(ip_counts[e["ip"]]) * WEIGHTS["ip"]
        weight_sum += WEIGHTS["ip"]

    e["email_score"] = round(score_sum / weight_sum, 3) if weight_sum else 0.0
    e["email_confidence"] = confidence_band(e["email_score"])

# =========================
# Graph-based clustering
# =========================

n = len(emails)
adj = [set() for _ in range(n)]

for i in range(n):
    for j in range(i + 1, n):
        if similarity(emails[i]["norm_subject"], emails[j]["norm_subject"]) >= SIMILARITY_THRESHOLD:
            adj[i].add(j)
            adj[j].add(i)

visited = set()
clusters = []

for i in range(n):
    if i in visited:
        continue

    stack = [i]
    component = []

    while stack:
        cur = stack.pop()
        if cur in visited:
            continue
        visited.add(cur)
        component.append(emails[cur])
        stack.extend(adj[cur] - visited)

    clusters.append(component)

campaigns = [c for c in clusters if len(c) >= 2]
singletons = [c[0] for c in clusters if len(c) == 1]

# =========================
# Campaign aggregation
# =========================

campaign_results = []

for idx, c in enumerate(sorted(campaigns, key=len, reverse=True), 1):
    scores = [e["email_score"] for e in c if e["email_score"] > 0]
    avg_score = round(sum(scores) / len(scores), 3) if scores else 0.0

    campaign_results.append({
        "campaign_id": f"C{idx:03}",
        "subject_sample": c[0]["raw_subject"],
        "email_count": len(c),
        "avg_score": avg_score,
        "confidence": confidence_band(avg_score),
        "unique_senders": len(set(e["sender"] for e in c if e["sender"])),
        "unique_ips": len(set(e["ip"] for e in c if e["ip"])),
        "emails": c
    })

# =========================
# Console output
# =========================

print("\n✅ Phishing Campaign Evaluation (30-day snapshot)\n")
print(f"Total emails analyzed      : {len(emails)}")
print(f"Campaigns (≥2 emails)      : {len(campaign_results)}")
print(f"Singleton emails (isolated): {len(singletons)}\n")

for c in campaign_results:
    print(f"{c['campaign_id']}")
    print(f"  Emails         : {c['email_count']}")
    print(f"  Avg score      : {c['avg_score']}")
    print(f"  Confidence     : {c['confidence']}")
    print(f"  Unique senders : {c['unique_senders']}")
    print(f"  Unique IPs     : {c['unique_ips']}")
    print(f"  Subject sample : {c['subject_sample']}\n")

    if not args.summary_only:
        print("  Emails in this campaign:")
        for e in c["emails"]:
            print(f"    - Subject : {e['raw_subject']}")
            print(f"      Sender  : {e['sender'] or '[empty]'}")
            print(f"      IP      : {e['ip'] or '[empty]'}")
            print(f"      Score   : {e['email_score']} ({e['email_confidence']})\n")

# =========================
# Singleton output (optional)
# =========================

if args.include_singletons and singletons:
    print("\n🧍 Singleton Emails (isolated activity)\n")
    for idx, e in enumerate(singletons, 1):
        print(f"S{idx:03}")
        print(f"  Subject : {e['raw_subject']}")
        print(f"  Sender  : {e['sender'] or '[empty]'}")
        print(f"  IP      : {e['ip'] or '[empty]'}")
        print(f"  Score   : {e['email_score']} ({e['email_confidence']})\n")

# =========================
# HTML Export (with singletons)
# =========================

if args.export_html:
    output_html = auto_html_filename() if args.export_html == "AUTO" else args.export_html
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def conf_class(c):
        return {
            "High": "high",
            "Medium-High": "medhigh",
            "Medium": "medium",
            "Low": "low"
        }[c]

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Phishing Campaign Report</title>
<style>
body {{ font-family: Arial, sans-serif; background:#fff; color:#000; }}
table {{ border-collapse: collapse; width:100%; }}
th, td {{ border:1px solid #ccc; padding:6px; }}
th {{ background:#f0f0f0; }}
.high {{ background:#d32f2f; color:#fff; }}
.medhigh {{ background:#f57c00; color:#fff; }}
.medium {{ background:#fbc02d; }}
.low {{ background:#388e3c; color:#fff; }}
</style>
</head>
<body>

<h1>Phishing Campaign Report</h1>
<p>Generated: {ts}</p>

<h2>Campaigns</h2>
<table>
<tr><th>ID</th><th>Confidence</th><th>Emails</th><th>Subject</th></tr>
"""

    for c in campaign_results:
        html += f"""
<tr>
<td>{c['campaign_id']}</td>
<td class="{conf_class(c['confidence'])}">{c['confidence']}</td>
<td>{c['email_count']}</td>
<td>{c['subject_sample']}</td>
</tr>
"""

    html += "</table>"

    if singletons:
        html += """
<h2>Singleton Emails (isolated activity)</h2>
<table>
<tr><th>Subject</th><th>Sender</th><th>IP</th><th>Score</th></tr>
"""
        for e in singletons:
            html += f"""
<tr>
<td>{e['raw_subject']}</td>
<td>{e['sender'] or '[empty]'}</td>
<td>{e['ip'] or '[empty]'}</td>
<td>{e['email_score']} ({e['email_confidence']})</td>
</tr>
"""
        html += "</table>"

    html += "</body></html>"

    with open(output_html, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n✅ HTML report exported to {output_html}")

# =========================
# CSV Export (polished filename only)
# =========================

if args.export_csv:
    output_file = auto_csv_filename() if args.export_csv == "AUTO" else args.export_csv

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "campaign_id",
                "subject_sample",
                "email_count",
                "avg_score",
                "confidence",
                "unique_senders",
                "unique_ips"
            ]
        )
        writer.writeheader()
        for c in campaign_results:
            writer.writerow({k: c[k] for k in writer.fieldnames})

    print(f"\n✅ Campaign summary exported to {output_file}")
