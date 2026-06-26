import json
from pathlib import Path
from datetime import datetime

SRC = Path("output/latest_hunt.json")
OUT_DIR = Path("reports")
OUT_DIR.mkdir(exist_ok=True)

data = json.loads(SRC.read_text(encoding="utf-8"))

def md_table(headers, rows):
    lines = []
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("|" + "|".join(["---"] * len(headers)) + "|")
    for r in rows:
        lines.append("| " + " | ".join(str(x) for x in r) + " |")
    return "\n".join(lines)

overview = data.get("overview", {})
campaigns = data.get("campaigns", [])
attack_chain = data.get("attack_chain", [])
iocs = data.get("iocs", {})
recs = data.get("recommendations", [])
valid_agents = data.get("valid_agents", [])

high_campaigns = [c for c in campaigns if c.get("risk_score", 0) >= 80]

top_campaign_rows = []
for idx, c in enumerate(campaigns[:10], start=1):
    top_campaign_rows.append([
        idx,
        c.get("agent", "-"),
        c.get("srcip", "-"),
        c.get("risk_score", "-"),
        c.get("event_count", "-"),
        c.get("techniques", "-"),
        str(c.get("confidence", "-")) + "%"
    ])

chain_rows = []
for idx, t in enumerate(attack_chain[:20], start=1):
    chain_rows.append([
        idx,
        ", ".join(t.get("tactics", [])),
        t.get("technique_id", "-"),
        t.get("name", "-"),
        t.get("atomic_tests", 0),
        t.get("attack_flow_refs", 0)
    ])

ioc_rows = [
    ["IPs", len([x for x in iocs.get("ips", []) if x and x != "-"])],
    ["URLs", len([x for x in iocs.get("urls", []) if x and x != "-"])],
    ["Files", len([x for x in iocs.get("files", []) if x and x != "-"])],
    ["Users", len([x for x in iocs.get("users", []) if x and x != "-"])],
    ["Hosts", len([x for x in iocs.get("hosts", []) if x and x != "-"])],
]

lines = []

lines.append("# Auto Threat Hunt — Executive Summary Report")
lines.append("")
lines.append(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
lines.append("")
lines.append("## 1. System Scope")
lines.append("")
lines.append("The system performs automated threat hunting on Wazuh alerts by combining OpenSearch queries, Wazuh agent inventory, MITRE ATT&CK mapping, campaign clustering, risk scoring, IOC extraction, and MITRE-based recommendations.")
lines.append("")
lines.append("**Valid Wazuh agents used for hunting:**")
lines.append("")
for a in valid_agents:
    lines.append(f"- {a}")
lines.append("")
lines.append("## 2. Hunt Overview")
lines.append("")
lines.append(md_table(
    ["Metric", "Value"],
    [
        ["Total pivot events", overview.get("total_events", 0)],
        ["Seed alerts", overview.get("seeds", 0)],
        ["Timeline events", overview.get("timeline_events", 0)],
        ["Campaigns", overview.get("campaigns", 0)],
        ["High-risk campaigns", overview.get("high_risk", 0)],
        ["MITRE techniques", overview.get("mitre_techniques", 0)],
        ["Chain confidence", str(overview.get("chain_confidence", 0)) + "%"],
    ]
))
lines.append("")
lines.append("## 3. Key Findings")
lines.append("")
if high_campaigns:
    lines.append(f"- The hunt identified **{len(high_campaigns)} high-risk campaigns** with risk score >= 80.")
else:
    lines.append("- No high-risk campaign was identified.")
lines.append(f"- The system reconstructed an ATT&CK chain containing **{len(attack_chain)} observed techniques**.")
lines.append(f"- The hunt extracted IOC categories including IPs, URLs, files, users, and hosts.")
lines.append(f"- Results were filtered against real Wazuh agents to reduce noise from sample or stale data.")
lines.append("")
lines.append("## 4. Top Campaigns")
lines.append("")
lines.append(md_table(
    ["Rank", "Agent", "Src IP", "Risk", "Events", "Techniques", "Confidence"],
    top_campaign_rows
))
lines.append("")
lines.append("## 5. ATT&CK Chain Summary")
lines.append("")
lines.append(md_table(
    ["Order", "Tactic", "Technique", "Name", "Atomic Tests", "Attack Flow Refs"],
    chain_rows
))
lines.append("")
lines.append("## 6. IOC Summary")
lines.append("")
lines.append(md_table(["IOC Type", "Count"], ioc_rows))
lines.append("")
lines.append("### Notable IOCs")
lines.append("")
for category in ["ips", "files", "users", "hosts"]:
    values = [x for x in iocs.get(category, []) if x and x != "-"][:20]
    if values:
        lines.append(f"**{category.upper()}**")
        lines.append("")
        for v in values:
            lines.append(f"- {v}")
        lines.append("")
lines.append("## 7. MITRE-Based Recommendations")
lines.append("")
shown = 0
for r in recs:
    if shown >= 10:
        break
    lines.append(f"### {r.get('technique_id')} — {r.get('technique_name')}")
    for m in (r.get("mitigations") or [])[:5]:
        lines.append(f"- {m.get('mitigation_id')}: {m.get('name')}")
    lines.append("")
    shown += 1

lines.append("## 8. Current System Capabilities")
lines.append("")
lines.append("- Wazuh/OpenSearch alert collection")
lines.append("- Valid-agent filtering using Wazuh API")
lines.append("- Seed alert selection")
lines.append("- Pivot expansion")
lines.append("- Campaign clustering")
lines.append("- Risk and confidence scoring")
lines.append("- ATT&CK chain reconstruction")
lines.append("- IOC extraction")
lines.append("- MITRE mitigation recommendation")
lines.append("- Wazuh Dashboard plugin visualization")
lines.append("")
lines.append("## 9. Analyst Conclusion")
lines.append("")
lines.append("The current Auto Threat Hunt system successfully transforms raw Wazuh alerts into campaign-level investigation views. It reduces alert noise by filtering valid agents, groups related alerts into campaigns, maps activity to MITRE ATT&CK, extracts IOCs, and generates actionable recommendations for analysts.")

out = OUT_DIR / f"executive_hunt_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
out.write_text("\n".join(lines), encoding="utf-8")

print(f"[OK] Executive summary generated: {out}")
