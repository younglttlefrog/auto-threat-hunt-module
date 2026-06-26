PLACEHOLDERS = {"", "-", "unknown", "none", "null", "n/a"}


def valid(v):
    return v is not None and str(v).strip().lower() not in PLACEHOLDERS


def has_network_anchor(events):
    return any(valid(e.get("srcip")) or valid(e.get("url")) for e in events)


def unique_rule_count(events):
    return len(set(
        str(e.get("rule_id", "-"))
        for e in events
        if str(e.get("rule_id", "-")).strip().lower() not in PLACEHOLDERS
    ))


def score_campaign_with_breakdown(campaign):
    events = campaign.get("events", [])
    chain = campaign.get("chain", {})

    if not events:
        return 0, {"caps_applied": ["no_events"]}

    max_level = max([int(e.get("level", 0) or 0) for e in events] or [0])
    event_count = len(events)
    technique_count = chain.get("technique_count", 0)
    tactic_count = chain.get("tactic_count", 0)
    confidence = chain.get("confidence", 0)

    network_anchor = has_network_anchor(events)
    rule_count = unique_rule_count(events)

    max_level_score = min(max_level * 3, 35)
    event_volume_score = min(event_count // 5, 15)
    technique_score = min(technique_count * 5, 20)
    tactic_score = min(tactic_count * 3, 12)
    confidence_score = confidence // 6

    high_risk_techniques = {
        "T1003", "T1003.001",
        "T1105",
        "T1190",
        "T1505.003",
        "T1547.001",
        "T1485", "T1486",
    }

    observed = set(chain.get("observed_techniques", []))
    high_risk_bonus = 10 if observed.intersection(high_risk_techniques) else 0

    score = (
        max_level_score
        + event_volume_score
        + technique_score
        + tactic_score
        + confidence_score
        + high_risk_bonus
    )

    caps = []

    if rule_count > 0 and technique_count > rule_count:
        score = min(score, 65)
        caps.append("multi_mitre_single_rule_cap")

    if event_count <= 3 and technique_count >= 3:
        score = min(score, 60)
        caps.append("low_event_multi_technique_cap")

    if not network_anchor and event_count < 5:
        score = min(score, 75)
        caps.append("host_only_low_evidence_cap")

    if not network_anchor and technique_count <= 1:
        score = min(score, 70)
        caps.append("host_only_single_technique_cap")

    if technique_count == 0:
        score = min(score, 40)
        caps.append("no_mitre_cap")

    breakdown = {
        "max_level": max_level_score,
        "event_volume": event_volume_score,
        "technique_score": technique_score,
        "tactic_score": tactic_score,
        "confidence_score": confidence_score,
        "high_risk_bonus": high_risk_bonus,
        "raw_score_before_caps": (
            max_level_score
            + event_volume_score
            + technique_score
            + tactic_score
            + confidence_score
            + high_risk_bonus
        ),
        "final_score": min(100, score),
        "max_rule_level": max_level,
        "event_count": event_count,
        "technique_count": technique_count,
        "tactic_count": tactic_count,
        "confidence": confidence,
        "unique_rule_count": rule_count,
        "has_network_anchor": network_anchor,
        "caps_applied": caps,
    }

    return min(100, score), breakdown


def score_campaign(campaign):
    score, _ = score_campaign_with_breakdown(campaign)
    return score
