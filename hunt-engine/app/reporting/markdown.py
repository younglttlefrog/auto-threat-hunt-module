from datetime import datetime
from app.playbooks.mitre import get_recommendations, collect_techniques
from app.chain.reconstruct import reconstruct_attack_chain
from app.ioc.extract import extract_iocs

def fmt_mitre(x):
    if isinstance(x, list):
        return ", ".join(x)
    return str(x) if x else "-"

def generate_report(events, seeds, timeline, campaigns=None):
    recs = get_recommendations(timeline)
    techniques = collect_techniques(timeline)
    campaigns = campaigns or []
    chain_result = reconstruct_attack_chain(timeline)
    iocs = extract_iocs(timeline)

    lines = []
    lines.append("# Automated Threat Hunting Report")
    lines.append("")
    lines.append(f"Generated at: {datetime.utcnow().isoformat()}Z")
    lines.append("")
    lines.append("## 1. Executive Summary")
    lines.append("")
    lines.append(f"- Total events analyzed: {len(events)}")
    lines.append(f"- Seed alerts level >= 12: {len(seeds)}")
    lines.append(f"- Timeline events: {len(timeline)}")
    lines.append(f"- MITRE techniques observed: {len(techniques)}")
    lines.append("")
    lines.append("## 2. Seed Alerts")
    lines.append("")
    lines.append("| Time | Agent | Rule | Level | Description | MITRE |")
    lines.append("|---|---|---:|---:|---|---|")
    for e in seeds[:50]:
        lines.append(
            f"| {e['timestamp']} | {e['agent']} | {e['rule_id']} | {e['level']} | {e['description']} | {fmt_mitre(e['mitre_id'])} |"
        )

    lines.append("")
    lines.append("## 3. MITRE ATT&CK Techniques")
    lines.append("")
    if techniques:
        for tid in techniques:
            lines.append(f"- {tid}")
    else:
        lines.append("No MITRE technique detected in timeline.")


    lines.append("")
    lines.append("## 4. ATT&CK Chain Reconstruction")
    lines.append("")
    lines.append(f"- Techniques in chain: {chain_result['technique_count']}")
    lines.append(f"- Tactics observed: {chain_result['tactic_count']}")
    lines.append(f"- Chain confidence: {chain_result['confidence']}%")
    lines.append("")
    lines.append("| Order | Tactic | Technique | Name | Atomic Tests | Attack Flow Refs |")
    lines.append("|---:|---|---|---|---:|---:|")
    for idx, c in enumerate(chain_result["chain"], start=1):
        lines.append(
            f"| {idx} | {', '.join(c['tactics']) if c['tactics'] else '-'} | {c['technique_id']} | {c['name']} | {c['atomic_tests']} | {c['attack_flow_refs']} |"
        )


    lines.append("")
    lines.append("## 5. Campaign Clustering")
    lines.append("")
    if not campaigns:
        lines.append("No campaign cluster generated.")
    else:
        lines.append("| Rank | Agent | Src IP | Events | Risk | Techniques | Confidence |")
        lines.append("|---:|---|---|---:|---:|---:|---:|")
        for idx, c in enumerate(campaigns[:20], start=1):
            chain = c["chain"]
            lines.append(
                f"| {idx} | {c['agent']} | {c['srcip']} | {c['event_count']} | {c['risk_score']} | {chain['technique_count']} | {chain['confidence']}% |"
            )

        for idx, c in enumerate(campaigns[:5], start=1):
            lines.append("")
            lines.append(f"### Campaign {idx}: {c['agent']} / {c['srcip']}")
            lines.append("")
            lines.append(f"- Risk Score: {c['risk_score']}/100")
            lines.append(f"- Events: {c['event_count']}")
            lines.append(f"- Techniques: {c['chain']['technique_count']}")
            lines.append(f"- Chain Confidence: {c['chain']['confidence']}%")
            lines.append("")
            lines.append("| Order | Tactic | Technique | Name |")
            lines.append("|---:|---|---|---|")
            for j, item in enumerate(c["chain"]["chain"], start=1):
                lines.append(
                    f"| {j} | {', '.join(item['tactics']) if item['tactics'] else '-'} | {item['technique_id']} | {item['name']} |"
                )


    lines.append("")
    lines.append("## 6. IOC Summary")
    lines.append("")
    if not iocs:
        lines.append("No IOC extracted.")
    else:
        for category, values in iocs.items():
            lines.append(f"### {category.upper()}")
            lines.append("")
            if values:
                for v in values[:50]:
                    lines.append(f"- {v}")
            else:
                lines.append("- None")
            lines.append("")

    lines.append("")
    lines.append("## 7. Timeline")
    lines.append("")
    lines.append("| Time | Agent | Rule | Level | Description | SrcIP | URL | MITRE |")
    lines.append("|---|---|---:|---:|---|---|---|---|")
    for e in timeline[:150]:
        lines.append(
            f"| {e['timestamp']} | {e['agent']} | {e['rule_id']} | {e['level']} | {e['description']} | {e['srcip']} | {e['url']} | {fmt_mitre(e['mitre_id'])} |"
        )

    lines.append("")
    lines.append("## 8. MITRE-Based Recommendations")
    lines.append("")
    if not recs:
        lines.append("No MITRE mitigation playbook matched.")
    else:
        for item in recs:
            lines.append(f"### {item['technique_id']} — {item['technique_name']}")
            lines.append("")
            lines.append(f"**Tactics:** {', '.join(item['tactics']) if item['tactics'] else '-'}")
            lines.append("")
            if item["mitigations"]:
                lines.append("| Mitigation ID | Mitigation |")
                lines.append("|---|---|")
                for m in item["mitigations"]:
                    lines.append(f"| {m.get('mitigation_id')} | {m.get('name')} |")
            else:
                lines.append("No mitigation available from MITRE CTI.")
            lines.append("")

    lines.append("## 9. Analyst Notes")
    lines.append("")
    lines.append("- MITRE mitigations are used as rule-based recommendations.")
    lines.append("- Analyst must validate whether the activity is malicious or benign administration.")
    lines.append("- Use pivoted evidence, timeline coherence, and affected assets before triggering response.")

    return "\\n".join(lines)
