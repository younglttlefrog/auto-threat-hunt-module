from collections import Counter

from app.chain.reconstruct import reconstruct_attack_chain
from app.scoring import score_campaign_with_breakdown
from app.campaign.explain import campaign_type, evidence_summary
from app.playbooks.response import get_recommended_actions_for_techniques

PLACEHOLDERS = {"", "-", "unknown", "none", "null", "n/a"}


def valid(v):
    return v is not None and str(v).strip().lower() not in PLACEHOLDERS


def most_common(events, field):
    vals = [e.get(field) for e in events if valid(e.get(field))]
    return Counter(vals).most_common(1)[0][0] if vals else "-"


def analyze_campaign(key, events):
    chain = reconstruct_attack_chain(events)

    result = {
        "key": key,
        "agent": most_common(events, "agent"),
        "srcip": most_common(events, "srcip"),
        "event_count": len(events),
        "campaign_type": campaign_type(events),
        "chain": chain,
        "events": events,
    }

    risk_score, score_breakdown = score_campaign_with_breakdown(result)

    result["risk_score"] = risk_score
    result["score_breakdown"] = score_breakdown
    result["evidence_summary"] = evidence_summary(events, chain, score_breakdown)
    result["recommended_actions"] = get_recommended_actions_for_techniques(
        chain.get("observed_techniques", []),
        max_actions=8,
    )

    return result
