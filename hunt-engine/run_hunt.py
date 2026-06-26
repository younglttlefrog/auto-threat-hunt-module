import os
import re
import json
from pathlib import Path
from datetime import datetime, UTC

from app.connectors.opensearch_conn import get_level_seeds, pivot_by_seed, pivot_archives_by_seed
from app.connectors.local_archives import read_local_archives
from app.connectors.wazuh_api import valid_agent_names
from app.normalizers.alert import normalize_hit
from app.normalizers.archive import normalize_archive
from app.correlation.timeline import build_timeline
from app.campaign.cluster import cluster_events
from app.campaign.analyze import analyze_campaign
from app.reporting.markdown import generate_report
from app.reporting.pdf import markdown_to_pdf
from app.chain.reconstruct import reconstruct_attack_chain
from app.ioc.extract import extract_iocs
from app.playbooks.mitre import get_recommendations, collect_techniques

REPORT_DIR = "reports"
OUTPUT_DIR = "output"

os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

hunt_name = os.getenv("HUNT_NAME", "Threat Hunt")
report_format = os.getenv("REPORT_FORMAT", "md").lower()

time_from = os.getenv("TIME_FROM", "now-24h")
time_to = os.getenv("TIME_TO", "now")
min_level = int(os.getenv("MIN_LEVEL", "12"))
seed_size = int(os.getenv("SEED_SIZE", "30"))
pivot_minutes = int(os.getenv("PIVOT_MINUTES", "30"))

if report_format not in ["md", "pdf"]:
    report_format = "md"

safe_name = re.sub(r"[^a-zA-Z0-9_-]+", "_", hunt_name).strip("_")
if not safe_name:
    safe_name = "Threat_Hunt"

valid_agents = valid_agent_names(include_manager=True, only_active=False)
print(f"[OK] Valid Wazuh agents: {valid_agents}")

seed_res = get_level_seeds(
    time_from=time_from,
    time_to=time_to,
    min_level=min_level,
    size=seed_size,
    agent_names=valid_agents
)

seeds = [normalize_hit(h) for h in seed_res["hits"]["hits"]]
seeds = [s for s in seeds if s.get("agent") in valid_agents]

alert_events = []
archive_events = []
truncated_pivots = {
    "alerts": 0,
    "archives": 0,
}

for seed in seeds:
    pivot_res = pivot_by_seed(
        seed,
        minutes=pivot_minutes,
        size=200,
        agent_names=valid_agents
    )

    if pivot_res.get("truncated"):
        truncated_pivots["alerts"] += 1

    for h in pivot_res["hits"]["hits"]:
        ev = normalize_hit(h)
        if ev.get("agent") in valid_agents:
            alert_events.append(ev)

    archive_res = pivot_archives_by_seed(
        seed,
        minutes=pivot_minutes,
        size=1000,
        agent_names=valid_agents
    )

    if archive_res.get("truncated"):
        truncated_pivots["archives"] += 1

    for h in archive_res["hits"]["hits"]:
        ev = normalize_archive(h)
        if ev.get("agent") in valid_agents:
            archive_events.append(ev)

# Fallback: if wazuh-archives-* index does not exist, read local Wazuh archives.json
if len(archive_events) == 0:
    local_res = read_local_archives(
        time_from=time_from,
        time_to=time_to,
        limit=int(os.getenv("LOCAL_ARCHIVE_LIMIT", "10000")),
        agent_names=valid_agents,
    )

    if local_res.get("truncated"):
        truncated_pivots["archives"] += 1

    for h in local_res["hits"]["hits"]:
        ev = normalize_archive(h)
        if ev.get("agent") in valid_agents:
            archive_events.append(ev)

all_events = alert_events + archive_events

timeline = build_timeline(all_events)
timeline = [e for e in timeline if e.get("agent") in valid_agents]

clusters = cluster_events(timeline)

campaigns = [
    analyze_campaign(key, evs)
    for key, evs in clusters.items()
    if evs and evs[0].get("agent") in valid_agents
]

campaigns = sorted(campaigns, key=lambda x: x["risk_score"], reverse=True)

chain_result = reconstruct_attack_chain(timeline)
iocs = extract_iocs(timeline)
recommendations = get_recommendations(timeline)
techniques = collect_techniques(timeline)

report = generate_report(all_events, seeds, timeline, campaigns=campaigns)
report = report.replace("\\n", "\n")

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
md_filename = f"{REPORT_DIR}/{safe_name}_{timestamp}.md"

with open(md_filename, "w", encoding="utf-8") as f:
    f.write(report)

final_report_file = md_filename

if report_format == "pdf":
    pdf_filename = md_filename.replace(".md", ".pdf")
    markdown_to_pdf(report, pdf_filename)
    final_report_file = pdf_filename

def safe_event(e):
    return {
        "timestamp": e.get("timestamp", "-"),
        "agent": e.get("agent", "-"),
        "source": e.get("source", "-"),
        "rule_id": e.get("rule_id", "-"),
        "level": e.get("level", 0),
        "description": e.get("description", "-"),
        "mitre_id": e.get("mitre_id", []),
        "tactic": e.get("tactic", []),
        "srcip": e.get("srcip", "-"),
        "url": e.get("url", "-"),
        "decoder": e.get("decoder", "-"),
        "location": e.get("location", "-"),
        "full_log": e.get("full_log", "-"),
    }

def safe_campaign(c):
    return {
        "key": c.get("key"),
        "agent": c.get("agent"),
        "srcip": c.get("srcip"),
        "campaign_type": c.get("campaign_type", "unknown"),
        "event_count": c.get("event_count"),
        "risk_score": c.get("risk_score"),
        "score_breakdown": c.get("score_breakdown", {}),
        "evidence_summary": c.get("evidence_summary", {}),
        "recommended_actions": c.get("recommended_actions", []),
        "techniques": c.get("chain", {}).get("technique_count", 0),
        "confidence": c.get("chain", {}).get("confidence", 0),
        "chain": c.get("chain", {}).get("chain", []),
        "edges": c.get("chain", {}).get("edges", []),
        "events": [safe_event(e) for e in c.get("events", [])[:150]],
    }

result = {
    "hunt_name": hunt_name,
    "report_format": report_format,
    "hunt_params": {
        "time_from": time_from,
        "time_to": time_to,
        "min_level": min_level,
        "seed_size": seed_size,
        "pivot_minutes": pivot_minutes,
    },
    "valid_agents": valid_agents,
    "overview": {
        "total_events": len(timeline),
        "raw_events": len(all_events),
        "alert_events": len([e for e in timeline if e.get("source") == "alert"]),
        "archive_events": len([e for e in timeline if e.get("source") == "archive"]),
        "seeds": len(seeds),
        "timeline_events": len(timeline),
        "campaigns": len(campaigns),
        "high_risk": len([c for c in campaigns if c["risk_score"] >= 80]),
        "mitre_techniques": len(techniques),
        "chain_confidence": chain_result.get("confidence", 0),
    },
    "attack_chain": chain_result.get("chain", []),
    "attack_edges": chain_result.get("edges", []),
    "truncated_pivots": truncated_pivots,
    "campaigns": [safe_campaign(c) for c in campaigns[:20]],
    "iocs": iocs,
    "timeline": [safe_event(e) for e in timeline[:800]],
    "recommendations": recommendations,
    "report_file": final_report_file,
    "generated_at": datetime.now(UTC).isoformat(),
}

json_filename = f"{OUTPUT_DIR}/{safe_name}_{timestamp}.json"
result["report_json_file"] = json_filename

Path(json_filename).write_text(
    json.dumps(result, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path(f"{OUTPUT_DIR}/latest_hunt.json").write_text(
    json.dumps(result, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

print(f"[OK] Report generated: {final_report_file}")
print(f"[OK] JSON generated: {OUTPUT_DIR}/latest_hunt.json")
print(f"[OK] Seeds: {len(seeds)} | Alerts: {len(alert_events)} | Archives: {len(archive_events)} | Timeline: {len(timeline)} | Campaigns: {len(campaigns)}")
