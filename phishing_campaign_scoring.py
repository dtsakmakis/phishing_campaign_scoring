import csv
import re
import argparse
import sys
import html
import logging
from difflib import SequenceMatcher
from collections import defaultdict
from datetime import datetime

"""
Phishing Campaign Scoring Tool
==============================

Version   : v1.5
Status    : Stable
Date      : 2026-04-17

Purpose:
--------
Batch analysis of phishing emails to identify probable phishing campaigns
using graph-based clustering on normalized subject lines, enriched with
sender, sender domain, and sender IP correlation.

CSV format expected:
--------------------
The script always parses the CSV by column position:
- Column 1 = subject
- Column 2 = sender address
- Column 3 = sender IP

Header names are ignored, so all of the following work:
- EOC Phish EmailSubject,EOC Email From,EOC Sender IP
- EmailSubject,EmailFrom,SenderIP
- 1,2,3
"""

# =========================
# Argument parsing
# =========================

parser = argparse.ArgumentParser(
    description=(
        "Cluster phishing emails from CSV into probable campaigns.\n\n"
        "CSV format expected:\n"
        "  The script always parses the CSV by column position.\n"
        "  Column 1 = subject\n"
        "  Column 2 = sender address\n"
        "  Column 3 = sender IP\n\n"
        "  Header names are ignored, so all of the following work:\n"
        "    EOC Phish EmailSubject,EOC Email From,EOC Sender IP\n"
        "    EmailSubject,EmailFrom,SenderIP\n"
        "    1,2,3"
    ),
    formatter_class=argparse.RawTextHelpFormatter
)

parser.add_argument("input_csv", help="Path to the phishing email CSV export")
parser.add_argument("--summary-only", action="store_true",
                    help="Print cluster summary only (no per-email details)")
parser.add_argument("--export-csv", nargs="?", const="AUTO", metavar="FILE",
                    help="Export cluster summary to CSV (optional filename)")
parser.add_argument("--include-singletons", action="store_true",
                    help="Include singleton (1-email) clusters in console output")
parser.add_argument("--include-pairs", action="store_true",
                    help="Include suspicious 2-email clusters in console output")
parser.add_argument("--export-html", nargs="?", const="AUTO", metavar="FILE",
                    help="Export results to an HTML report (optional filename)")
parser.add_argument("--debug", action="store_true",
                    help="Enable verbose debug logging")

args = parser.parse_args()
INPUT_CSV = args.input_csv

# =========================
# Logging setup
# =========================

logging.basicConfig(
    level=logging.DEBUG if args.debug else logging.INFO,
    format="%(levelname)s: %(message)s"
)
log = logging.getLogger(__name__)

# =========================
# Configuration
# =========================

SUBJECT_SIM_STRONG = 0.92
SUBJECT_SIM_MEDIUM = 0.85
MIN_SUBJECT_LEN = 8

WEIGHTS = {
    "subject": 0.50,
    "sender": 0.25,
    "domain": 0.15,
    "ip": 0.10,
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
        s = s.replace("phishing:", "", 1).strip()

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

def extract_sender_domain(sender):
    if not sender or "@" not in sender:
        return ""
    return sender.split("@", 1)[1].strip().lower()

# =========================
# Scoring helpers
# =========================

def frequency_score(count):
    if count >= 10:
        return 1.0
    elif count >= 5:
        return 0.8
    elif count >= 3:
        return 0.6
    elif count >= 2:
        return 0.4
    return 0.2

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

def h(value):
    return html.escape(str(value), quote=True)

# =========================
# Pairwise clustering logic
# =========================

def should_link(a, b):
    subj_a = a["norm_subject"]
    subj_b = b["norm_subject"]

    if not subj_a or not subj_b:
        return False

    if len(subj_a) < MIN_SUBJECT_LEN or len(subj_b) < MIN_SUBJECT_LEN:
        return False

    subj_sim = similarity(subj_a, subj_b)

    same_sender = bool(a["sender"] and b["sender"] and a["sender"] == b["sender"])
    same_domain = bool(a["sender_domain"] and b["sender_domain"] and a["sender_domain"] == b["sender_domain"])
    same_ip = bool(a["ip"] and b["ip"] and a["ip"] == b["ip"])

    if subj_sim >= SUBJECT_SIM_STRONG:
        if args.debug:
            log.debug(
                "Strong link: subj_sim=%.3f | '%s' <-> '%s'",
                subj_sim, a["raw_subject"], b["raw_subject"]
            )
        return True

    if subj_sim >= SUBJECT_SIM_MEDIUM and (same_sender or same_domain or same_ip):
        if args.debug:
            reasons = []
            if same_sender:
                reasons.append("same_sender")
            if same_domain:
                reasons.append("same_domain")
            if same_ip:
                reasons.append("same_ip")
            log.debug(
                "Corroborated link: subj_sim=%.3f | reasons=%s | '%s' <-> '%s'",
                subj_sim, ",".join(reasons), a["raw_subject"], b["raw_subject"]
            )
        return True

    return False

# =========================
# Load CSV data
# =========================

emails = []

try:
    with open(INPUT_CSV, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)

        header = next(reader, None)
        if not header:
            print("\n❌ Error: CSV appears to be empty.")
            sys.exit(1)

        if len(header) < 3:
            print("\n❌ Error: CSV must contain at least 3 columns.")
            sys.exit(1)

        log.info("Using positional CSV parsing")
        log.info("Column 1 -> subject | Column 2 -> sender | Column 3 -> ip")
        log.debug("Detected header row (ignored for mapping): %s", header)

        for row_num, row in enumerate(reader, start=2):
            if len(row) < 3:
                log.debug("Skipping short row %d: %s", row_num, row)
                continue

            subject = (row[0] or "").strip()
            sender = (row[1] or "").strip().lower()
            ip = (row[2] or "").strip()
            sender_domain = extract_sender_domain(sender)

            emails.append({
                "raw_subject": subject,
                "norm_subject": normalize_subject(subject),
                "sender": sender,
                "sender_domain": sender_domain,
                "ip": ip,
                "row_num": row_num,
            })

except FileNotFoundError:
    print(f"\n❌ Error: file not found: {INPUT_CSV}")
    sys.exit(1)

log.info("Loaded %d emails", len(emails))

# =========================
# Frequency analysis
# =========================

subject_counts = defaultdict(int)
sender_counts = defaultdict(int)
domain_counts = defaultdict(int)
ip_counts = defaultdict(int)

for e in emails:
    if e["norm_subject"]:
        subject_counts[e["norm_subject"]] += 1
    if e["sender"]:
        sender_counts[e["sender"]] += 1
    if e["sender_domain"]:
        domain_counts[e["sender_domain"]] += 1
    if e["ip"]:
        ip_counts[e["ip"]] += 1

if args.debug:
    log.debug("Unique normalized subjects: %d", len(subject_counts))
    log.debug("Unique senders: %d", len(sender_counts))
    log.debug("Unique sender domains: %d", len(domain_counts))
    log.debug("Unique IPs: %d", len(ip_counts))

# =========================
# Email-level signal scoring
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

    if e["sender_domain"]:
        score_sum += frequency_score(domain_counts[e["sender_domain"]]) * WEIGHTS["domain"]
        weight_sum += WEIGHTS["domain"]

    if e["ip"]:
        score_sum += frequency_score(ip_counts[e["ip"]]) * WEIGHTS["ip"]
        weight_sum += WEIGHTS["ip"]

    e["signal_score"] = round(score_sum / weight_sum, 3) if weight_sum else 0.0
    e["signal_confidence"] = confidence_band(e["signal_score"])

# =========================
# Graph-based clustering
# =========================

n = len(emails)
adj = [set() for _ in range(n)]

for i in range(n):
    for j in range(i + 1, n):
        if should_link(emails[i], emails[j]):
            adj[i].add(j)
            adj[j].add(i)

if args.debug:
    edge_count = sum(len(x) for x in adj) // 2
    log.debug("Constructed graph with %d nodes and %d edges", n, edge_count)

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

campaigns = [c for c in clusters if len(c) >= 3]
pairs = [c for c in clusters if len(c) == 2]
singletons = [c[0] for c in clusters if len(c) == 1]

# =========================
# Cluster aggregation
# =========================

campaign_results = []
pair_results = []

def summarize_cluster(cluster, cluster_id):
    scores = [e["signal_score"] for e in cluster if e["signal_score"] > 0]
    avg_score = round(sum(scores) / len(scores), 3) if scores else 0.0

    return {
        "cluster_id": cluster_id,
        "subject_sample": cluster[0]["raw_subject"],
        "email_count": len(cluster),
        "avg_score": avg_score,
        "confidence": confidence_band(avg_score),
        "unique_senders": len(set(e["sender"] for e in cluster if e["sender"])),
        "unique_domains": len(set(e["sender_domain"] for e in cluster if e["sender_domain"])),
        "unique_ips": len(set(e["ip"] for e in cluster if e["ip"])),
        "emails": cluster,
    }

for idx, c in enumerate(sorted(campaigns, key=len, reverse=True), 1):
    campaign_results.append(summarize_cluster(c, f"C{idx:03}"))

for idx, c in enumerate(sorted(pairs, key=len, reverse=True), 1):
    pair_results.append(summarize_cluster(c, f"P{idx:03}"))

# =========================
# Console output
# =========================

print("\n✅ Phishing Campaign Evaluation (30-day snapshot)\n")
print(f"Total emails analyzed         : {len(emails)}")
print(f"Campaigns (≥3 emails)         : {len(campaign_results)}")
print(f"Suspicious pairs (2 emails)   : {len(pair_results)}")
print(f"Singleton emails (isolated)   : {len(singletons)}\n")

if campaign_results:
    print("=== Campaigns ===\n")
    for c in campaign_results:
        print(f"{c['cluster_id']}")
        print(f"  Emails          : {c['email_count']}")
        print(f"  Avg signal score: {c['avg_score']}")
        print(f"  Confidence      : {c['confidence']}")
        print(f"  Unique senders  : {c['unique_senders']}")
        print(f"  Unique domains  : {c['unique_domains']}")
        print(f"  Unique IPs      : {c['unique_ips']}")
        print(f"  Subject sample  : {c['subject_sample']}\n")

        if not args.summary_only:
            print("  Emails in this campaign:")
            for e in c["emails"]:
                print(f"    - Row     : {e['row_num']}")
                print(f"      Subject : {e['raw_subject']}")
                print(f"      Sender  : {e['sender'] or '[empty]'}")
                print(f"      Domain  : {e['sender_domain'] or '[empty]'}")
                print(f"      IP      : {e['ip'] or '[empty]'}")
                print(f"      Score   : {e['signal_score']} ({e['signal_confidence']})\n")

if args.include_pairs and pair_results:
    print("\n=== Suspicious Pairs (2 emails) ===\n")
    for c in pair_results:
        print(f"{c['cluster_id']}")
        print(f"  Emails          : {c['email_count']}")
        print(f"  Avg signal score: {c['avg_score']}")
        print(f"  Confidence      : {c['confidence']}")
        print(f"  Unique senders  : {c['unique_senders']}")
        print(f"  Unique domains  : {c['unique_domains']}")
        print(f"  Unique IPs      : {c['unique_ips']}")
        print(f"  Subject sample  : {c['subject_sample']}\n")

        if not args.summary_only:
            print("  Emails in this pair:")
            for e in c["emails"]:
                print(f"    - Row     : {e['row_num']}")
                print(f"      Subject : {e['raw_subject']}")
                print(f"      Sender  : {e['sender'] or '[empty]'}")
                print(f"      Domain  : {e['sender_domain'] or '[empty]'}")
                print(f"      IP      : {e['ip'] or '[empty]'}")
                print(f"      Score   : {e['signal_score']} ({e['signal_confidence']})\n")

if args.include_singletons and singletons:
    print("\n=== Singleton Emails (isolated activity) ===\n")
    for idx, e in enumerate(singletons, 1):
        print(f"S{idx:03}")
        print(f"  Row     : {e['row_num']}")
        print(f"  Subject : {e['raw_subject']}")
        print(f"  Sender  : {e['sender'] or '[empty]'}")
        print(f"  Domain  : {e['sender_domain'] or '[empty]'}")
        print(f"  IP      : {e['ip'] or '[empty]'}")
        print(f"  Score   : {e['signal_score']} ({e['signal_confidence']})\n")

# =========================
# HTML Export
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

    html_report = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Phishing Campaign Report</title>
<style>
body {{ font-family: Arial, sans-serif; background:#fff; color:#000; margin:20px; }}
table {{ border-collapse: collapse; width:100%; margin-bottom:24px; }}
th, td {{ border:1px solid #ccc; padding:6px; text-align:left; vertical-align:top; }}
th {{ background:#f0f0f0; }}
.high {{ background:#d32f2f; color:#fff; }}
.medhigh {{ background:#f57c00; color:#fff; }}
.medium {{ background:#fbc02d; color:#000; }}
.low {{ background:#388e3c; color:#fff; }}
</style>
</head>
<body>

<h1>Phishing Campaign Report</h1>
<p>Generated: {h(ts)}</p>

<h2>Summary</h2>
<ul>
<li>Total emails analyzed: {len(emails)}</li>
<li>Campaigns (≥3 emails): {len(campaign_results)}</li>
<li>Suspicious pairs (2 emails): {len(pair_results)}</li>
<li>Singleton emails: {len(singletons)}</li>
</ul>

<h2>Campaigns</h2>
<table>
<tr>
<th>ID</th>
<th>Confidence</th>
<th>Emails</th>
<th>Unique Senders</th>
<th>Unique Domains</th>
<th>Unique IPs</th>
<th>Subject</th>
</tr>
"""

    for c in campaign_results:
        html_report += f"""
<tr>
<td>{h(c['cluster_id'])}</td>
<td class="{h(conf_class(c['confidence']))}">{h(c['confidence'])}</td>
<td>{c['email_count']}</td>
<td>{c['unique_senders']}</td>
<td>{c['unique_domains']}</td>
<td>{c['unique_ips']}</td>
<td>{h(c['subject_sample'])}</td>
</tr>
"""

    html_report += "</table>"

    if pair_results:
        html_report += """
<h2>Suspicious Pairs (2 emails)</h2>
<table>
<tr>
<th>ID</th>
<th>Confidence</th>
<th>Emails</th>
<th>Unique Senders</th>
<th>Unique Domains</th>
<th>Unique IPs</th>
<th>Subject</th>
</tr>
"""
        for c in pair_results:
            html_report += f"""
<tr>
<td>{h(c['cluster_id'])}</td>
<td class="{h(conf_class(c['confidence']))}">{h(c['confidence'])}</td>
<td>{c['email_count']}</td>
<td>{c['unique_senders']}</td>
<td>{c['unique_domains']}</td>
<td>{c['unique_ips']}</td>
<td>{h(c['subject_sample'])}</td>
</tr>
"""
        html_report += "</table>"

    if singletons:
        html_report += """
<h2>Singleton Emails (isolated activity)</h2>
<table>
<tr><th>Row</th><th>Subject</th><th>Sender</th><th>Domain</th><th>IP</th><th>Score</th></tr>
"""
        for e in singletons:
            html_report += f"""
<tr>
<td>{e['row_num']}</td>
<td>{h(e['raw_subject'])}</td>
<td>{h(e['sender'] or '[empty]')}</td>
<td>{h(e['sender_domain'] or '[empty]')}</td>
<td>{h(e['ip'] or '[empty]')}</td>
<td>{h(f"{e['signal_score']} ({e['signal_confidence']})")}</td>
</tr>
"""
        html_report += "</table>"

    html_report += "</body></html>"

    with open(output_html, "w", encoding="utf-8") as f:
        f.write(html_report)

    print(f"\n✅ HTML report exported to {output_html}")

# =========================
# CSV Export
# =========================

if args.export_csv:
    output_file = auto_csv_filename() if args.export_csv == "AUTO" else args.export_csv

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "cluster_id",
                "cluster_type",
                "subject_sample",
                "email_count",
                "avg_score",
                "confidence",
                "unique_senders",
                "unique_domains",
                "unique_ips"
            ]
        )
        writer.writeheader()

        for c in campaign_results:
            writer.writerow({
                "cluster_id": c["cluster_id"],
                "cluster_type": "campaign",
                "subject_sample": c["subject_sample"],
                "email_count": c["email_count"],
                "avg_score": c["avg_score"],
                "confidence": c["confidence"],
                "unique_senders": c["unique_senders"],
                "unique_domains": c["unique_domains"],
                "unique_ips": c["unique_ips"],
            })

        for c in pair_results:
            writer.writerow({
                "cluster_id": c["cluster_id"],
                "cluster_type": "pair",
                "subject_sample": c["subject_sample"],
                "email_count": c["email_count"],
                "avg_score": c["avg_score"],
                "confidence": c["confidence"],
                "unique_senders": c["unique_senders"],
                "unique_domains": c["unique_domains"],
                "unique_ips": c["unique_ips"],
            })

    print(f"\n✅ Cluster summary exported to {output_file}")
