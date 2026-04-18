import csv
import re
import argparse
import sys
import html
import json
import logging
from difflib import SequenceMatcher
from collections import defaultdict, Counter
from datetime import datetime

"""
Phishing Campaign Scoring Tool
==============================

Version   : v1.8
Status    : Stable
Date      : 2026-04-18

Purpose:
--------
Batch analysis of phishing emails to identify probable phishing campaigns
using graph-based clustering on normalized subject lines, enriched with
sender, sender domain, sender IP, analyst-provided classification, and
analyst-provided resolution.

CSV format expected:
--------------------
The script always parses the CSV by column position:
- Column 1 = subject
- Column 2 = sender address
- Column 3 = sender IP
- Column 4 = analyst classification
- Column 5 = resolution

Header names are ignored.

Example accepted first row:
- Subject,Sender,SenderIP,Classification,Resolution
- 1,2,3,4,5
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
        "  Column 3 = sender IP\n"
        "  Column 4 = analyst classification\n"
        "  Column 5 = resolution\n\n"
        "  Header names are ignored."
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
parser.add_argument("--min-campaign-size", type=int, default=3,
                    help="Minimum cluster size to classify as a campaign (default: 3)")

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

TREND_LIMIT = 5

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

def normalize_sender(sender):
    if not sender:
        return ""

    sender = sender.strip().lower()
    match = re.search(r'<?([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})>?', sender)
    if match:
        return match.group(1)

    return sender

def extract_sender_domain(sender):
    if not sender or "@" not in sender:
        return ""
    return sender.split("@", 1)[1].strip().lower()

def h(value):
    return html.escape(str(value), quote=True)

def json_html(obj):
    return html.escape(json.dumps(obj), quote=True)

def slugify(value):
    value = str(value).lower()
    value = re.sub(r'[^a-z0-9]+', '-', value)
    return value.strip('-') or "item"

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

def confidence_css_class(conf):
    return {
        "High": "badge-high",
        "Medium-High": "badge-medhigh",
        "Medium": "badge-medium",
        "Low": "badge-low",
    }.get(conf, "badge-neutral")

def classification_css_class(classification):
    key = classification.strip().lower()
    mapping = {
        "phishing": "class-phishing",
        "c-level impersonation": "class-impersonation",
        "malicious attachment": "class-malicious-attachment",
        "bec": "class-bec",
        "credential harvesting": "class-credential",
        "[empty]": "class-empty",
    }
    return mapping.get(key, "class-generic")

def resolution_css_class(resolution):
    key = resolution.strip().lower()
    mapping = {
        "harmless": "res-harmless",
        "false positive": "res-fp",
        "impacted": "res-impacted",
        "insufficient information": "res-insufficient",
        "[empty]": "res-empty",
    }
    return mapping.get(key, "res-generic")

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

    if subj_sim >= SUBJECT_SIM_MEDIUM and (same_sender or same_domain):
        if args.debug:
            reasons = []
            if same_sender:
                reasons.append("same_sender")
            if same_domain:
                reasons.append("same_domain")
            log.debug(
                "Corroborated link: subj_sim=%.3f | reasons=%s | '%s' <-> '%s'",
                subj_sim, ",".join(reasons), a["raw_subject"], b["raw_subject"]
            )
        return True

    if subj_sim >= SUBJECT_SIM_STRONG and same_ip:
        if args.debug:
            log.debug(
                "IP-supported strong link: subj_sim=%.3f | '%s' <-> '%s'",
                subj_sim, a["raw_subject"], b["raw_subject"]
            )
        return True

    return False

# =========================
# Load CSV data
# =========================

emails = []

try:
    with open(INPUT_CSV, newline="", encoding="utf-8-sig", errors="ignore") as f:
        reader = csv.reader(f)

        header = next(reader, None)
        if not header:
            print("\n❌ Error: CSV appears to be empty.")
            sys.exit(1)

        if len(header) < 5:
            print("\n❌ Error: CSV must contain at least 5 columns.")
            print("Expected order:")
            print("  column 1 = subject")
            print("  column 2 = sender address")
            print("  column 3 = sender IP")
            print("  column 4 = classification")
            print("  column 5 = resolution")
            sys.exit(1)

        log.info("Using positional CSV parsing")
        log.info("Column 1 -> subject | Column 2 -> sender | Column 3 -> ip | Column 4 -> classification | Column 5 -> resolution")
        log.debug("Detected header row (ignored for mapping): %s", header)

        for row_num, row in enumerate(reader, start=2):
            if len(row) < 5:
                log.debug("Skipping short row %d: %s", row_num, row)
                continue

            subject = (row[0] or "").strip()
            sender = normalize_sender(row[1] or "")
            ip = (row[2] or "").strip()
            classification = (row[3] or "").strip()
            resolution = (row[4] or "").strip()
            sender_domain = extract_sender_domain(sender)

            emails.append({
                "raw_subject": subject,
                "norm_subject": normalize_subject(subject),
                "sender": sender,
                "sender_domain": sender_domain,
                "ip": ip,
                "classification": classification,
                "resolution": resolution,
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

    component.sort(key=lambda x: (x["sender"], x["raw_subject"], x["ip"], x["classification"], x["resolution"]))
    clusters.append(component)

campaigns = [c for c in clusters if len(c) >= args.min_campaign_size]
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

    classifications = [e["classification"] for e in cluster if e["classification"]]
    class_counter = Counter(classifications)

    if class_counter:
        dominant_classification, dominant_count = class_counter.most_common(1)[0]
        classification_consistency = f"{dominant_count}/{len(cluster)} emails"
    else:
        dominant_classification = "[empty]"
        classification_consistency = f"0/{len(cluster)} emails"

    resolutions = [e["resolution"] for e in cluster if e["resolution"]]
    resolution_counter = Counter(resolutions)

    if resolution_counter:
        dominant_resolution, dominant_resolution_count = resolution_counter.most_common(1)[0]
        resolution_consistency = f"{dominant_resolution_count}/{len(cluster)} emails"
    else:
        dominant_resolution = "[empty]"
        resolution_consistency = f"0/{len(cluster)} emails"

    subject_counter = Counter(e["raw_subject"] for e in cluster if e["raw_subject"])
    subject_sample = subject_counter.most_common(1)[0][0] if subject_counter else cluster[0]["raw_subject"]

    return {
        "cluster_id": cluster_id,
        "subject_sample": subject_sample,
        "email_count": len(cluster),
        "avg_score": avg_score,
        "confidence": confidence_band(avg_score),
        "unique_senders": len(set(e["sender"] for e in cluster if e["sender"])),
        "unique_domains": len(set(e["sender_domain"] for e in cluster if e["sender_domain"])),
        "unique_ips": len(set(e["ip"] for e in cluster if e["ip"])),
        "campaign_classification": dominant_classification,
        "classification_consistency": classification_consistency,
        "unique_classifications": len(class_counter),
        "classification_breakdown": dict(class_counter),
        "campaign_resolution": dominant_resolution,
        "resolution_consistency": resolution_consistency,
        "unique_resolutions": len(resolution_counter),
        "resolution_breakdown": dict(resolution_counter),
        "emails": cluster,
    }

for idx, c in enumerate(sorted(campaigns, key=len, reverse=True), 1):
    campaign_results.append(summarize_cluster(c, f"C{idx:03}"))

for idx, c in enumerate(sorted(pairs, key=len, reverse=True), 1):
    pair_results.append(summarize_cluster(c, f"P{idx:03}"))

# =========================
# Trend / summary helpers
# =========================

classification_counter = Counter(
    e["classification"] for e in emails if e["classification"]
)
resolution_counter_all = Counter(
    e["resolution"] for e in emails if e["resolution"]
)
sender_domain_counter = Counter(
    e["sender_domain"] for e in emails if e["sender_domain"]
)
ip_counter = Counter(
    e["ip"] for e in emails if e["ip"]
)

top_classifications = classification_counter.most_common(TREND_LIMIT)
top_resolutions = resolution_counter_all.most_common(TREND_LIMIT)
top_domains = sender_domain_counter.most_common(TREND_LIMIT)
top_ips = ip_counter.most_common(TREND_LIMIT)

largest_campaign_size = max((c["email_count"] for c in campaign_results), default=0)
most_common_classification = top_classifications[0][0] if top_classifications else "[empty]"
most_common_resolution = top_resolutions[0][0] if top_resolutions else "[empty]"
mixed_campaigns_count = sum(1 for c in campaign_results if c["unique_classifications"] > 1)
mixed_resolution_campaigns_count = sum(1 for c in campaign_results if c["unique_resolutions"] > 1)

# =========================
# Console output
# =========================

print("\n✅ Phishing Campaign Evaluation (30-day snapshot)\n")
print(f"Total emails analyzed         : {len(emails)}")
print(f"Campaigns (>={args.min_campaign_size} emails)      : {len(campaign_results)}")
print(f"Suspicious pairs (2 emails)   : {len(pair_results)}")
print(f"Singleton emails (isolated)   : {len(singletons)}\n")

if campaign_results:
    print("=== Campaigns ===\n")
    for c in campaign_results:
        print(f"{c['cluster_id']}")
        print(f"  Emails                : {c['email_count']}")
        print(f"  Avg signal score      : {c['avg_score']}")
        print(f"  Confidence            : {c['confidence']}")
        print(f"  Unique senders        : {c['unique_senders']}")
        print(f"  Unique domains        : {c['unique_domains']}")
        print(f"  Unique IPs            : {c['unique_ips']}")
        print(f"  Subject sample        : {c['subject_sample']}")
        print(f"  Classification        : {c['campaign_classification']}")
        print(f"  Class consistency     : {c['classification_consistency']}")
        print(f"  Unique classifications: {c['unique_classifications']}")
        print(f"  Resolution            : {c['campaign_resolution']}")
        print(f"  Resolution consistency: {c['resolution_consistency']}")
        print(f"  Unique resolutions    : {c['unique_resolutions']}")
        if c["unique_classifications"] > 1:
            print("  Warning               : Mixed analyst classifications inside cluster")
        if c["unique_resolutions"] > 1:
            print("  Warning               : Mixed analyst resolutions inside cluster")
        print()

        if not args.summary_only:
            print("  Emails in this campaign:")
            for e in c["emails"]:
                print(f"    - Row       : {e['row_num']}")
                print(f"      Subject   : {e['raw_subject']}")
                print(f"      Sender    : {e['sender'] or '[empty]'}")
                print(f"      Domain    : {e['sender_domain'] or '[empty]'}")
                print(f"      IP        : {e['ip'] or '[empty]'}")
                print(f"      Class     : {e['classification'] or '[empty]'}")
                print(f"      Resolution: {e['resolution'] or '[empty]'}")
                print(f"      Score     : {e['signal_score']} ({e['signal_confidence']})\n")

if args.include_pairs and pair_results:
    print("\n=== Suspicious Pairs (2 emails) ===\n")
    for c in pair_results:
        print(f"{c['cluster_id']}")
        print(f"  Emails                : {c['email_count']}")
        print(f"  Avg signal score      : {c['avg_score']}")
        print(f"  Confidence            : {c['confidence']}")
        print(f"  Unique senders        : {c['unique_senders']}")
        print(f"  Unique domains        : {c['unique_domains']}")
        print(f"  Unique IPs            : {c['unique_ips']}")
        print(f"  Subject sample        : {c['subject_sample']}")
        print(f"  Classification        : {c['campaign_classification']}")
        print(f"  Class consistency     : {c['classification_consistency']}")
        print(f"  Unique classifications: {c['unique_classifications']}")
        print(f"  Resolution            : {c['campaign_resolution']}")
        print(f"  Resolution consistency: {c['resolution_consistency']}")
        print(f"  Unique resolutions    : {c['unique_resolutions']}")
        if c["unique_classifications"] > 1:
            print("  Warning               : Mixed analyst classifications inside cluster")
        if c["unique_resolutions"] > 1:
            print("  Warning               : Mixed analyst resolutions inside cluster")
        print()

        if not args.summary_only:
            print("  Emails in this pair:")
            for e in c["emails"]:
                print(f"    - Row       : {e['row_num']}")
                print(f"      Subject   : {e['raw_subject']}")
                print(f"      Sender    : {e['sender'] or '[empty]'}")
                print(f"      Domain    : {e['sender_domain'] or '[empty]'}")
                print(f"      IP        : {e['ip'] or '[empty]'}")
                print(f"      Class     : {e['classification'] or '[empty]'}")
                print(f"      Resolution: {e['resolution'] or '[empty]'}")
                print(f"      Score     : {e['signal_score']} ({e['signal_confidence']})\n")

if args.include_singletons and singletons:
    print("\n=== Singleton Emails (isolated activity) ===\n")
    for idx, e in enumerate(singletons, 1):
        print(f"S{idx:03}")
        print(f"  Row       : {e['row_num']}")
        print(f"  Subject   : {e['raw_subject']}")
        print(f"  Sender    : {e['sender'] or '[empty]'}")
        print(f"  Domain    : {e['sender_domain'] or '[empty]'}")
        print(f"  IP        : {e['ip'] or '[empty]'}")
        print(f"  Class     : {e['classification'] or '[empty]'}")
        print(f"  Resolution: {e['resolution'] or '[empty]'}")
        print(f"  Score     : {e['signal_score']} ({e['signal_confidence']})\n")

# =========================
# HTML helpers
# =========================

def render_counter_list(items):
    if not items:
        return '<div class="muted">No data available.</div>'
    rows = []
    for label, count in items:
        rows.append(
            f"""
            <div class="trend-item">
                <span class="trend-label">{h(label)}</span>
                <span class="trend-count">{count}</span>
            </div>
            """
        )
    return "\n".join(rows)

def render_breakdown_badges(counter_dict, kind="classification"):
    if not counter_dict:
        return '<span class="badge badge-neutral">[empty]</span>'
    parts = []
    for label, count in sorted(counter_dict.items(), key=lambda x: (-x[1], x[0].lower())):
        badge_class = classification_css_class(label) if kind == "classification" else resolution_css_class(label)
        parts.append(
            f'<span class="badge {badge_class}">{h(label)}: {count}</span>'
        )
    return " ".join(parts)

def render_mini_stat_bars(cluster):
    total = max(cluster["email_count"], 1)

    sender_pct = round((cluster["unique_senders"] / total) * 100)
    domain_pct = round((cluster["unique_domains"] / total) * 100)
    ip_pct = round((cluster["unique_ips"] / total) * 100)

    return f"""
    <div class="mini-bars">
        <div class="mini-bar-row">
            <div class="mini-bar-label">Unique senders</div>
            <div class="mini-bar-track">
                <div class="mini-bar-fill mini-bar-senders" style="width:{sender_pct}%"></div>
            </div>
            <div class="mini-bar-value">{cluster['unique_senders']}</div>
        </div>
        <div class="mini-bar-row">
            <div class="mini-bar-label">Unique domains</div>
            <div class="mini-bar-track">
                <div class="mini-bar-fill mini-bar-domains" style="width:{domain_pct}%"></div>
            </div>
            <div class="mini-bar-value">{cluster['unique_domains']}</div>
        </div>
        <div class="mini-bar-row">
            <div class="mini-bar-label">Unique IPs</div>
            <div class="mini-bar-track">
                <div class="mini-bar-fill mini-bar-ips" style="width:{ip_pct}%"></div>
            </div>
            <div class="mini-bar-value">{cluster['unique_ips']}</div>
        </div>
    </div>
    """

def render_breakdown_table(counter_dict, kind="classification"):
    if not counter_dict:
        return '<div class="muted">No breakdown available.</div>'

    total = sum(counter_dict.values()) or 1
    rows = []
    for label, count in sorted(counter_dict.items(), key=lambda x: (-x[1], x[0].lower())):
        pct = round((count / total) * 100, 1)
        badge_class = classification_css_class(label) if kind == "classification" else resolution_css_class(label)
        rows.append(f"""
        <tr>
            <td><span class="badge {badge_class}">{h(label)}</span></td>
            <td>{count}</td>
            <td>{pct}%</td>
        </tr>
        """)
    return f"""
    <div class="table-wrap">
        <table class="sortable">
            <tr>
                <th>{'Classification' if kind == 'classification' else 'Resolution'}</th>
                <th>Count</th>
                <th>Percent</th>
            </tr>
            {''.join(rows)}
        </table>
    </div>
    """

def render_email_table(cluster_emails):
    rows = []
    for e in cluster_emails:
        rows.append(f"""
        <tr>
            <td>{e['row_num']}</td>
            <td>{h(e['raw_subject'])}</td>
            <td class="mono">{h(e['sender'] or '[empty]')}</td>
            <td class="mono">{h(e['sender_domain'] or '[empty]')}</td>
            <td class="mono">{h(e['ip'] or '[empty]')}</td>
            <td><span class="badge {classification_css_class(e['classification'] or '[empty]')}">{h(e['classification'] or '[empty]')}</span></td>
            <td><span class="badge {resolution_css_class(e['resolution'] or '[empty]')}">{h(e['resolution'] or '[empty]')}</span></td>
            <td><span class="badge {confidence_css_class(e['signal_confidence'])}">{h(e['signal_confidence'])}</span> <span class="score-inline">{e['signal_score']}</span></td>
        </tr>
        """)
    return "\n".join(rows)

def render_cluster_details(clusters, title, prefix):
    if not clusters:
        return f'<div class="section-card"><h2 id="{slugify(title)}">{h(title)}</h2><div class="muted">No entries.</div></div>'

    blocks = [f'<div class="section-card"><h2 id="{slugify(title)}">{h(title)}</h2>']
    for cluster in clusters:
        mixed_class_warning = ""
        mixed_resolution_warning = ""

        if cluster["unique_classifications"] > 1:
            mixed_class_warning = '<div class="warning-banner">Mixed analyst classifications inside cluster</div>'
        if cluster["unique_resolutions"] > 1:
            mixed_resolution_warning = '<div class="warning-banner">Mixed analyst resolutions inside cluster</div>'

        details_id = f"{prefix}-{cluster['cluster_id']}"
        blocks.append(f"""
        <details class="cluster-details searchable-block" id="{details_id}"
                 data-search="{h(cluster['cluster_id'])} {h(cluster['subject_sample'])} {h(cluster['campaign_classification'])} {h(cluster['campaign_resolution'])}">
            <summary>
                <div class="summary-main">
                    <span class="cluster-id">{h(cluster['cluster_id'])}</span>
                    <span class="cluster-subject">{h(cluster['subject_sample'])}</span>
                </div>
                <div class="summary-badges">
                    <span class="badge {confidence_css_class(cluster['confidence'])}">{h(cluster['confidence'])}</span>
                    <span class="badge {classification_css_class(cluster['campaign_classification'])}">{h(cluster['campaign_classification'])}</span>
                    <span class="badge {resolution_css_class(cluster['campaign_resolution'])}">{h(cluster['campaign_resolution'])}</span>
                    <span class="badge badge-neutral">{cluster['email_count']} emails</span>
                </div>
            </summary>

            <div class="cluster-meta-grid">
                <div><strong>Avg signal score:</strong> {cluster['avg_score']}</div>
                <div><strong>Confidence:</strong> {h(cluster['confidence'])}</div>
                <div><strong>Unique senders:</strong> {cluster['unique_senders']}</div>
                <div><strong>Unique domains:</strong> {cluster['unique_domains']}</div>
                <div><strong>Unique IPs:</strong> {cluster['unique_ips']}</div>
                <div><strong>Class consistency:</strong> {h(cluster['classification_consistency'])}</div>
                <div><strong>Resolution consistency:</strong> {h(cluster['resolution_consistency'])}</div>
            </div>

            <div class="breakdown-block">
                <div><strong>Classification breakdown:</strong></div>
                <div class="badge-row">{render_breakdown_badges(cluster['classification_breakdown'], kind='classification')}</div>
            </div>

            <div class="breakdown-block">
                <div><strong>Resolution breakdown:</strong></div>
                <div class="badge-row">{render_breakdown_badges(cluster['resolution_breakdown'], kind='resolution')}</div>
            </div>

            <div class="breakdown-block">
                <div><strong>Cluster diversity snapshot:</strong></div>
                {render_mini_stat_bars(cluster)}
            </div>

            <div class="breakdown-block">
                <div><strong>Detailed classification breakdown:</strong></div>
                {render_breakdown_table(cluster['classification_breakdown'], kind='classification')}
            </div>

            <div class="breakdown-block">
                <div><strong>Detailed resolution breakdown:</strong></div>
                {render_breakdown_table(cluster['resolution_breakdown'], kind='resolution')}
            </div>

            {mixed_class_warning}
            {mixed_resolution_warning}

            <div class="table-wrap">
                <table class="sortable">
                    <tr>
                        <th>Row</th>
                        <th>Subject</th>
                        <th>Sender</th>
                        <th>Domain</th>
                        <th>IP</th>
                        <th>Classification</th>
                        <th>Resolution</th>
                        <th>Signal</th>
                    </tr>
                    {render_email_table(cluster['emails'])}
                </table>
            </div>
        </details>
        """)
    blocks.append("</div>")
    return "\n".join(blocks)

# =========================
# HTML Export
# =========================

if args.export_html:
    output_html = auto_html_filename() if args.export_html == "AUTO" else args.export_html
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    campaign_rows = []
    for c in campaign_results:
        warnings = []
        if c["unique_classifications"] > 1:
            warnings.append('<span class="badge badge-warning">Mixed classes</span>')
        if c["unique_resolutions"] > 1:
            warnings.append('<span class="badge badge-warning">Mixed resolutions</span>')
        warning_html = " ".join(warnings)

        campaign_rows.append(f"""
        <tr class="searchable-block"
            data-search="{h(c['cluster_id'])} {h(c['subject_sample'])} {h(c['campaign_classification'])} {h(c['campaign_resolution'])}">
            <td><a href="#campaign-{h(c['cluster_id'])}">{h(c['cluster_id'])}</a></td>
            <td><span class="badge {confidence_css_class(c['confidence'])}">{h(c['confidence'])}</span></td>
            <td>{c['email_count']}</td>
            <td>{c['unique_senders']}</td>
            <td>{c['unique_domains']}</td>
            <td>{c['unique_ips']}</td>
            <td><span class="badge {classification_css_class(c['campaign_classification'])}">{h(c['campaign_classification'])}</span></td>
            <td>{h(c['classification_consistency'])}</td>
            <td><span class="badge {resolution_css_class(c['campaign_resolution'])}">{h(c['campaign_resolution'])}</span></td>
            <td>{h(c['resolution_consistency'])}</td>
            <td>{warning_html}</td>
            <td>{h(c['subject_sample'])}</td>
        </tr>
        """)

    pairs_rows = []
    for c in pair_results:
        warnings = []
        if c["unique_classifications"] > 1:
            warnings.append('<span class="badge badge-warning">Mixed classes</span>')
        if c["unique_resolutions"] > 1:
            warnings.append('<span class="badge badge-warning">Mixed resolutions</span>')
        warning_html = " ".join(warnings)

        pairs_rows.append(f"""
        <tr class="searchable-block"
            data-search="{h(c['cluster_id'])} {h(c['subject_sample'])} {h(c['campaign_classification'])} {h(c['campaign_resolution'])}">
            <td><a href="#pair-{h(c['cluster_id'])}">{h(c['cluster_id'])}</a></td>
            <td><span class="badge {confidence_css_class(c['confidence'])}">{h(c['confidence'])}</span></td>
            <td>{c['email_count']}</td>
            <td>{c['unique_senders']}</td>
            <td>{c['unique_domains']}</td>
            <td>{c['unique_ips']}</td>
            <td><span class="badge {classification_css_class(c['campaign_classification'])}">{h(c['campaign_classification'])}</span></td>
            <td>{h(c['classification_consistency'])}</td>
            <td><span class="badge {resolution_css_class(c['campaign_resolution'])}">{h(c['campaign_resolution'])}</span></td>
            <td>{h(c['resolution_consistency'])}</td>
            <td>{warning_html}</td>
            <td>{h(c['subject_sample'])}</td>
        </tr>
        """)

    singleton_rows = []
    for e in singletons:
        singleton_rows.append(f"""
        <tr class="searchable-block"
            data-search="{h(e['raw_subject'])} {h(e['classification'])} {h(e['resolution'])} {h(e['sender_domain'])}">
            <td>{e['row_num']}</td>
            <td>{h(e['raw_subject'])}</td>
            <td class="mono">{h(e['sender'] or '[empty]')}</td>
            <td class="mono">{h(e['sender_domain'] or '[empty]')}</td>
            <td class="mono">{h(e['ip'] or '[empty]')}</td>
            <td><span class="badge {classification_css_class(e['classification'] or '[empty]')}">{h(e['classification'] or '[empty]')}</span></td>
            <td><span class="badge {resolution_css_class(e['resolution'] or '[empty]')}">{h(e['resolution'] or '[empty]')}</span></td>
            <td><span class="badge {confidence_css_class(e['signal_confidence'])}">{h(e['signal_confidence'])}</span> <span class="score-inline">{e['signal_score']}</span></td>
        </tr>
        """)

    classification_matrix_rows = []
    for c in campaign_results + pair_results:
        for label, count in sorted(c["classification_breakdown"].items(), key=lambda x: (-x[1], x[0].lower())):
            total = sum(c["classification_breakdown"].values()) or 1
            pct = round((count / total) * 100, 1)
            classification_matrix_rows.append(f"""
            <tr>
                <td>{h(c['cluster_id'])}</td>
                <td>{"campaign" if c['cluster_id'].startswith('C') else "pair"}</td>
                <td><span class="badge {classification_css_class(label)}">{h(label)}</span></td>
                <td>{count}</td>
                <td>{pct}%</td>
                <td>{h(c['subject_sample'])}</td>
            </tr>
            """)

    resolution_matrix_rows = []
    for c in campaign_results + pair_results:
        for label, count in sorted(c["resolution_breakdown"].items(), key=lambda x: (-x[1], x[0].lower())):
            total = sum(c["resolution_breakdown"].values()) or 1
            pct = round((count / total) * 100, 1)
            resolution_matrix_rows.append(f"""
            <tr>
                <td>{h(c['cluster_id'])}</td>
                <td>{"campaign" if c['cluster_id'].startswith('C') else "pair"}</td>
                <td><span class="badge {resolution_css_class(label)}">{h(label)}</span></td>
                <td>{count}</td>
                <td>{pct}%</td>
                <td>{h(c['subject_sample'])}</td>
            </tr>
            """)

    html_report = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Phishing Campaign Report</title>
<style>
:root {{
    --bg: #f5f7fb;
    --card: #ffffff;
    --text: #18212f;
    --muted: #617085;
    --border: #d9e0ea;
    --header: #eef3f9;
    --accent: #1f4b99;
    --shadow: 0 8px 24px rgba(16, 24, 40, 0.06);
}}

* {{ box-sizing: border-box; }}
body {{
    font-family: Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 24px;
    line-height: 1.4;
}}

body.dark-mode {{
    --bg: #0f172a;
    --card: #111827;
    --text: #e5e7eb;
    --muted: #94a3b8;
    --border: #334155;
    --header: #1e293b;
    --accent: #93c5fd;
    --shadow: 0 10px 26px rgba(0, 0, 0, 0.35);
}}

body.dark-mode .hero {{
    background: linear-gradient(135deg, #111827 0%, #172554 100%);
}}

body.dark-mode .trend-card,
body.dark-mode details.cluster-details summary,
body.dark-mode tr:nth-child(even) td,
body.dark-mode tr:hover td {{
    background: transparent;
}}

body.dark-mode .summary-card,
body.dark-mode .section-card,
body.dark-mode details.cluster-details,
body.dark-mode .trend-card,
body.dark-mode .search-input,
body.dark-mode table {{
    background: var(--card);
    color: var(--text);
}}

body.dark-mode th {{
    background: var(--header);
}}

body.dark-mode .theme-toggle {{
    background: #1e293b;
    color: #e5e7eb;
    border-color: #475569;
}}

h1, h2, h3 {{
    margin-top: 0;
}}

a {{
    color: var(--accent);
    text-decoration: none;
}}
a:hover {{
    text-decoration: underline;
}}

.page {{
    max-width: 1500px;
    margin: 0 auto;
}}

.hero {{
    background: linear-gradient(135deg, #ffffff 0%, #edf4ff 100%);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 24px;
    box-shadow: var(--shadow);
    margin-bottom: 20px;
}}

.hero-meta {{
    color: var(--muted);
    margin-top: 8px;
}}

.nav-links {{
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-top: 16px;
}}
.nav-links a {{
    background: #fff;
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 8px 12px;
    font-size: 0.95rem;
}}

.theme-toggle {{
    background: #fff;
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 8px 12px;
    font-size: 0.95rem;
    cursor: pointer;
    color: var(--text);
}}

.summary-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 14px;
    margin-bottom: 20px;
}}

.summary-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 18px;
    box-shadow: var(--shadow);
}}
.summary-label {{
    font-size: 0.95rem;
    color: var(--muted);
    margin-bottom: 8px;
}}
.summary-value {{
    font-size: 1.9rem;
    font-weight: bold;
}}
.summary-sub {{
    margin-top: 8px;
    color: var(--muted);
    font-size: 0.92rem;
}}

.section-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 20px;
    box-shadow: var(--shadow);
    margin-bottom: 20px;
}}

.trends-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
}}

.trend-card {{
    background: #fbfcfe;
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 16px;
}}

.trend-item {{
    display: flex;
    justify-content: space-between;
    gap: 16px;
    padding: 8px 0;
    border-bottom: 1px dashed #e3e8f0;
}}
.trend-item:last-child {{
    border-bottom: none;
}}
.trend-label {{
    word-break: break-word;
}}
.trend-count {{
    font-weight: bold;
    white-space: nowrap;
}}

.search-wrap {{
    margin: 14px 0 18px 0;
}}
.search-input {{
    width: 100%;
    padding: 12px 14px;
    border: 1px solid var(--border);
    border-radius: 12px;
    font-size: 1rem;
    background: #fff;
}}

.table-wrap {{
    overflow-x: auto;
}}

table {{
    border-collapse: collapse;
    width: 100%;
    background: #fff;
}}

th, td {{
    border: 1px solid var(--border);
    padding: 9px 10px;
    text-align: left;
    vertical-align: top;
}}

th {{
    background: var(--header);
    position: sticky;
    top: 0;
    z-index: 1;
}}

.sortable th {{
    cursor: pointer;
    user-select: none;
}}

.sortable th.sort-asc::after {{
    content: " ▲";
    font-size: 0.8rem;
}}

.sortable th.sort-desc::after {{
    content: " ▼";
    font-size: 0.8rem;
}}

tr:nth-child(even) td {{
    background: #fcfdff;
}}

tr:hover td {{
    background: #f6faff;
}}

details.cluster-details {{
    border: 1px solid var(--border);
    border-radius: 14px;
    margin-bottom: 14px;
    background: #fff;
    overflow: hidden;
}}

details.cluster-details summary {{
    list-style: none;
    cursor: pointer;
    padding: 14px 16px;
    display: flex;
    justify-content: space-between;
    gap: 16px;
    align-items: flex-start;
    background: #f9fbff;
}}

details.cluster-details summary::-webkit-details-marker {{
    display: none;
}}

.summary-main {{
    min-width: 0;
}}

.cluster-id {{
    display: inline-block;
    font-weight: bold;
    margin-right: 8px;
}}

.cluster-subject {{
    color: var(--text);
    word-break: break-word;
}}

.summary-badges {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    justify-content: flex-end;
}}

.cluster-meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 10px;
    padding: 16px;
}}

.breakdown-block {{
    padding: 0 16px 14px 16px;
}}

.badge-row {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 8px;
}}

.badge {{
    display: inline-block;
    border-radius: 999px;
    padding: 5px 10px;
    font-size: 0.88rem;
    font-weight: bold;
    border: 1px solid transparent;
}}

.badge-high {{
    background: #8b1e2d;
    color: #fff;
}}
.badge-medhigh {{
    background: #d97706;
    color: #fff;
}}
.badge-medium {{
    background: #facc15;
    color: #2b2b2b;
}}
.badge-low {{
    background: #15803d;
    color: #fff;
}}
.badge-neutral {{
    background: #e9eef5;
    color: #243447;
    border-color: #d6dee9;
}}
.badge-warning {{
    background: #fff4db;
    color: #9a6700;
    border-color: #f0d58a;
}}

.class-phishing {{
    background: #dbeafe;
    color: #0f3e8a;
    border-color: #a9c7f7;
}}
.class-impersonation {{
    background: #fde2e2;
    color: #8b1e2d;
    border-color: #f2b0b5;
}}
.class-malicious-attachment {{
    background: #ede9fe;
    color: #5b21b6;
    border-color: #c9b7ff;
}}
.class-bec {{
    background: #ffe8cc;
    color: #a34a00;
    border-color: #f4c38b;
}}
.class-credential {{
    background: #dcfce7;
    color: #166534;
    border-color: #a8e3bc;
}}
.class-empty {{
    background: #f1f5f9;
    color: #475569;
    border-color: #d8e0ea;
}}
.class-generic {{
    background: #eef2ff;
    color: #3730a3;
    border-color: #c7d2fe;
}}

.res-harmless {{
    background: #dcfce7;
    color: #166534;
    border-color: #a8e3bc;
}}
.res-fp {{
    background: #e0f2fe;
    color: #075985;
    border-color: #bae6fd;
}}
.res-impacted {{
    background: #fee2e2;
    color: #991b1b;
    border-color: #fecaca;
}}
.res-insufficient {{
    background: #fef3c7;
    color: #92400e;
    border-color: #fcd34d;
}}
.res-empty {{
    background: #f1f5f9;
    color: #475569;
    border-color: #d8e0ea;
}}
.res-generic {{
    background: #f3e8ff;
    color: #6b21a8;
    border-color: #e9d5ff;
}}

.warning-banner {{
    margin: 0 16px 16px 16px;
    padding: 10px 12px;
    border-radius: 10px;
    background: #fff1f2;
    border: 1px solid #fecdd3;
    color: #9f1239;
    font-weight: bold;
}}

.mini-bars {{
    margin-top: 10px;
}}

.mini-bar-row {{
    display: grid;
    grid-template-columns: 130px 1fr 50px;
    gap: 10px;
    align-items: center;
    margin-bottom: 8px;
}}

.mini-bar-label {{
    font-size: 0.92rem;
    color: var(--muted);
}}

.mini-bar-track {{
    width: 100%;
    height: 10px;
    background: #e7edf5;
    border-radius: 999px;
    overflow: hidden;
}}

.mini-bar-fill {{
    height: 100%;
    border-radius: 999px;
}}

.mini-bar-senders {{
    background: #2563eb;
}}

.mini-bar-domains {{
    background: #7c3aed;
}}

.mini-bar-ips {{
    background: #ea580c;
}}

.mini-bar-value {{
    font-weight: bold;
    text-align: right;
}}

.mono {{
    font-family: Consolas, Menlo, Monaco, monospace;
    font-size: 0.93rem;
}}

.muted {{
    color: var(--muted);
}}

.methodology {{
    color: var(--muted);
    font-size: 0.95rem;
}}

.score-inline {{
    margin-left: 6px;
    color: var(--muted);
    font-size: 0.9rem;
}}

.footer-note {{
    color: var(--muted);
    font-size: 0.9rem;
    margin-top: 10px;
}}

@media (max-width: 900px) {{
    details.cluster-details summary {{
        flex-direction: column;
    }}
    .summary-badges {{
        justify-content: flex-start;
    }}
    .mini-bar-row {{
        grid-template-columns: 1fr;
    }}
}}
</style>
</head>
<body>
<div class="page">

    <div class="hero">
        <h1>Phishing Campaign Report</h1>
        <div class="hero-meta">Generated: {h(ts)}</div>
        <div class="hero-meta">Input: positional CSV parsing (col1=subject, col2=sender, col3=IP, col4=classification, col5=resolution)</div>

        <div class="nav-links">
            <a href="#summary">Summary</a>
            <a href="#top-trends">Top Trends</a>
            <a href="#campaign-summary">Campaign Summary</a>
            <a href="#campaign-details">Campaign Details</a>
            <a href="#pairs-details">Suspicious Pairs</a>
            <a href="#singletons-details">Singletons</a>
            <a href="#classification-matrix">Classification Matrix</a>
            <a href="#resolution-matrix">Resolution Matrix</a>
            <a href="#methodology">Methodology</a>
            <button type="button" id="themeToggle" class="theme-toggle">Toggle dark mode</button>
        </div>
    </div>

    <div id="summary" class="summary-grid">
        <div class="summary-card">
            <div class="summary-label">Total Emails Analyzed</div>
            <div class="summary-value">{len(emails)}</div>
            <div class="summary-sub">All rows successfully parsed from the CSV input.</div>
        </div>
        <div class="summary-card">
            <div class="summary-label">Campaigns</div>
            <div class="summary-value">{len(campaign_results)}</div>
            <div class="summary-sub">Clusters with at least {args.min_campaign_size} emails.</div>
        </div>
        <div class="summary-card">
            <div class="summary-label">Suspicious Pairs</div>
            <div class="summary-value">{len(pair_results)}</div>
            <div class="summary-sub">Two-email clusters kept separate from campaigns.</div>
        </div>
        <div class="summary-card">
            <div class="summary-label">Singletons</div>
            <div class="summary-value">{len(singletons)}</div>
            <div class="summary-sub">Isolated emails not linked to other activity.</div>
        </div>
        <div class="summary-card">
            <div class="summary-label">Most Common Classification</div>
            <div class="summary-value" style="font-size:1.2rem;">
                <span class="badge {classification_css_class(most_common_classification)}">{h(most_common_classification)}</span>
            </div>
            <div class="summary-sub">Most frequent analyst classification across all emails.</div>
        </div>
        <div class="summary-card">
            <div class="summary-label">Most Common Resolution</div>
            <div class="summary-value" style="font-size:1.2rem;">
                <span class="badge {resolution_css_class(most_common_resolution)}">{h(most_common_resolution)}</span>
            </div>
            <div class="summary-sub">Most frequent analyst resolution across all emails.</div>
        </div>
        <div class="summary-card">
            <div class="summary-label">Largest Campaign Size</div>
            <div class="summary-value">{largest_campaign_size}</div>
            <div class="summary-sub">Largest cluster classified as a campaign.</div>
        </div>
        <div class="summary-card">
            <div class="summary-label">Mixed-Classification Campaigns</div>
            <div class="summary-value">{mixed_campaigns_count}</div>
            <div class="summary-sub">Campaigns containing more than one analyst classification.</div>
        </div>
        <div class="summary-card">
            <div class="summary-label">Mixed-Resolution Campaigns</div>
            <div class="summary-value">{mixed_resolution_campaigns_count}</div>
            <div class="summary-sub">Campaigns containing more than one analyst resolution.</div>
        </div>
    </div>

    <div id="top-trends" class="section-card">
        <h2>Top Trends</h2>
        <div class="trends-grid">
            <div class="trend-card">
                <h3>Top Classifications</h3>
                {render_counter_list(top_classifications)}
            </div>
            <div class="trend-card">
                <h3>Top Resolutions</h3>
                {render_counter_list(top_resolutions)}
            </div>
            <div class="trend-card">
                <h3>Top Sender Domains</h3>
                {render_counter_list(top_domains)}
            </div>
            <div class="trend-card">
                <h3>Top Sender IPs</h3>
                {render_counter_list(top_ips)}
            </div>
        </div>
    </div>

    <div id="campaign-summary" class="section-card">
        <h2>Campaign Summary</h2>
        <div class="search-wrap">
            <input type="text" class="search-input" id="reportSearch"
                   placeholder="Filter report by campaign ID, subject, classification, resolution, domain, or singleton details...">
        </div>
        <div class="table-wrap">
            <table class="sortable">
                <tr>
                    <th>ID</th>
                    <th>Confidence</th>
                    <th>Emails</th>
                    <th>Unique Senders</th>
                    <th>Unique Domains</th>
                    <th>Unique IPs</th>
                    <th>Classification</th>
                    <th>Class Consistency</th>
                    <th>Resolution</th>
                    <th>Resolution Consistency</th>
                    <th>Warnings</th>
                    <th>Subject</th>
                </tr>
                {"".join(campaign_rows) if campaign_rows else '<tr><td colspan="12" class="muted">No campaigns found.</td></tr>'}
            </table>
        </div>
    </div>

    <div id="campaign-details">
        {render_cluster_details(campaign_results, "Campaign Details", "campaign")}
    </div>

    <div id="pairs-details" class="section-card">
        <h2>Suspicious Pairs Summary</h2>
        <div class="table-wrap">
            <table class="sortable">
                <tr>
                    <th>ID</th>
                    <th>Confidence</th>
                    <th>Emails</th>
                    <th>Unique Senders</th>
                    <th>Unique Domains</th>
                    <th>Unique IPs</th>
                    <th>Classification</th>
                    <th>Class Consistency</th>
                    <th>Resolution</th>
                    <th>Resolution Consistency</th>
                    <th>Warnings</th>
                    <th>Subject</th>
                </tr>
                {"".join(pairs_rows) if pairs_rows else '<tr><td colspan="12" class="muted">No suspicious pairs found.</td></tr>'}
            </table>
        </div>
    </div>

    <div>
        {render_cluster_details(pair_results, "Suspicious Pair Details", "pair")}
    </div>

    <div id="singletons-details" class="section-card">
        <h2>Singleton Emails</h2>
        <div class="table-wrap">
            <table class="sortable">
                <tr>
                    <th>Row</th>
                    <th>Subject</th>
                    <th>Sender</th>
                    <th>Domain</th>
                    <th>IP</th>
                    <th>Classification</th>
                    <th>Resolution</th>
                    <th>Signal</th>
                </tr>
                {"".join(singleton_rows) if singleton_rows else '<tr><td colspan="8" class="muted">No singleton emails.</td></tr>'}
            </table>
        </div>
    </div>

    <div id="classification-matrix" class="section-card">
        <h2>Detailed Classification Breakdown Matrix</h2>
        <div class="table-wrap">
            <table class="sortable">
                <tr>
                    <th>Cluster ID</th>
                    <th>Type</th>
                    <th>Classification</th>
                    <th>Count</th>
                    <th>Percent</th>
                    <th>Subject</th>
                </tr>
                {"".join(classification_matrix_rows) if classification_matrix_rows else '<tr><td colspan="6" class="muted">No classification breakdown data.</td></tr>'}
            </table>
        </div>
    </div>

    <div id="resolution-matrix" class="section-card">
        <h2>Detailed Resolution Breakdown Matrix</h2>
        <div class="table-wrap">
            <table class="sortable">
                <tr>
                    <th>Cluster ID</th>
                    <th>Type</th>
                    <th>Resolution</th>
                    <th>Count</th>
                    <th>Percent</th>
                    <th>Subject</th>
                </tr>
                {"".join(resolution_matrix_rows) if resolution_matrix_rows else '<tr><td colspan="6" class="muted">No resolution breakdown data.</td></tr>'}
            </table>
        </div>
    </div>

    <div id="methodology" class="section-card">
        <h2>Methodology</h2>
        <div class="methodology">
            <p>This report clusters emails into probable campaigns using graph-based connected components built from pairwise similarity checks.</p>
            <p>Linking logic uses normalized subject similarity as the primary signal, with sender or sender-domain corroboration for medium-confidence links and IP support only for very strong subject similarity.</p>
            <p>Classification and resolution are not used to create links. They are treated as analyst-validated metadata for cluster summarization, consistency checks, and reporting.</p>
            <p>Thresholds currently in use: strong subject similarity = {SUBJECT_SIM_STRONG}, medium similarity = {SUBJECT_SIM_MEDIUM}, minimum subject length = {MIN_SUBJECT_LEN}, minimum campaign size = {args.min_campaign_size}.</p>
            <div class="footer-note">
                Interpretation note: this output represents probable campaign grouping for reporting and analysis, not definitive attribution.
            </div>
        </div>
    </div>

</div>

<script>
(function() {{
    const input = document.getElementById("reportSearch");
    if (!input) return;

    input.addEventListener("input", function() {{
        const q = input.value.toLowerCase().trim();
        const items = document.querySelectorAll(".searchable-block");

        items.forEach(item => {{
            const hay = (item.getAttribute("data-search") || item.textContent || "").toLowerCase();
            const show = !q || hay.includes(q);
            item.style.display = show ? "" : "none";
        }});
    }});
}})();
</script>

<script>
(function() {{
    function getCellValue(row, index) {{
        const cell = row.children[index];
        return cell ? cell.innerText.trim() : "";
    }}

    function asNumber(value) {{
        const cleaned = value.replace(/[^0-9.\\-]/g, "");
        const n = parseFloat(cleaned);
        return isNaN(n) ? null : n;
    }}

    document.querySelectorAll("table.sortable").forEach(table => {{
        const headers = table.querySelectorAll("th");
        headers.forEach((th, index) => {{
            th.addEventListener("click", () => {{
                const rows = Array.from(table.querySelectorAll("tr")).slice(1);
                const currentAsc = th.classList.contains("sort-asc");

                headers.forEach(h => h.classList.remove("sort-asc", "sort-desc"));
                th.classList.add(currentAsc ? "sort-desc" : "sort-asc");

                rows.sort((a, b) => {{
                    const av = getCellValue(a, index);
                    const bv = getCellValue(b, index);

                    const an = asNumber(av);
                    const bn = asNumber(bv);

                    let cmp;
                    if (an !== null && bn !== null) {{
                        cmp = an - bn;
                    }} else {{
                        cmp = av.localeCompare(bv, undefined, {{
                            numeric: true,
                            sensitivity: "base"
                        }});
                    }}

                    return currentAsc ? -cmp : cmp;
                }});

                rows.forEach(row => table.appendChild(row));
            }});
        }});
    }});
}})();
</script>

<script>
(function() {{
    const btn = document.getElementById("themeToggle");
    if (!btn) return;

    const key = "phish-report-dark-mode";
    const saved = localStorage.getItem(key);

    if (saved === "1") {{
        document.body.classList.add("dark-mode");
    }}

    btn.addEventListener("click", function() {{
        document.body.classList.toggle("dark-mode");
        localStorage.setItem(
            key,
            document.body.classList.contains("dark-mode") ? "1" : "0"
        );
    }});
}})();
</script>

</body>
</html>
"""

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
                "unique_ips",
                "campaign_classification",
                "classification_consistency",
                "unique_classifications",
                "classification_breakdown",
                "campaign_resolution",
                "resolution_consistency",
                "unique_resolutions",
                "resolution_breakdown",
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
                "campaign_classification": c["campaign_classification"],
                "classification_consistency": c["classification_consistency"],
                "unique_classifications": c["unique_classifications"],
                "classification_breakdown": json.dumps(c["classification_breakdown"], ensure_ascii=False, sort_keys=True),
                "campaign_resolution": c["campaign_resolution"],
                "resolution_consistency": c["resolution_consistency"],
                "unique_resolutions": c["unique_resolutions"],
                "resolution_breakdown": json.dumps(c["resolution_breakdown"], ensure_ascii=False, sort_keys=True),
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
                "campaign_classification": c["campaign_classification"],
                "classification_consistency": c["classification_consistency"],
                "unique_classifications": c["unique_classifications"],
                "classification_breakdown": json.dumps(c["classification_breakdown"], ensure_ascii=False, sort_keys=True),
                "campaign_resolution": c["campaign_resolution"],
                "resolution_consistency": c["resolution_consistency"],
                "unique_resolutions": c["unique_resolutions"],
                "resolution_breakdown": json.dumps(c["resolution_breakdown"], ensure_ascii=False, sort_keys=True),
            })

    print(f"\n✅ Cluster summary exported to {output_file}")
