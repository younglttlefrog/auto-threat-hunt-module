from collections import Counter

PLACEHOLDERS = {"", "-", "unknown", "none", "null", "n/a"}


def valid(v):
    return v is not None and str(v).strip().lower() not in PLACEHOLDERS


def as_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def campaign_type(events):
    has_network = any(valid(e.get("srcip")) or valid(e.get("url")) for e in events)
    has_host = any(valid(e.get("agent")) for e in events)

    if has_network and has_host:
        return "mixed"
    if has_network:
        return "network_campaign"
    return "host_behavior"


def collect_primary_rules(events, limit=5):
    rules = Counter(
        str(e.get("rule_id"))
        for e in events
        if valid(e.get("rule_id")) and str(e.get("rule_id")) != "archive"
    )
    return [r for r, _ in rules.most_common(limit)]


def collect_primary_techniques(chain, limit=5):
    items = chain.get("chain", []) or []
    items = sorted(items, key=lambda x: x.get("event_count", 0), reverse=True)
    return [x.get("technique_id") for x in items[:limit] if valid(x.get("technique_id"))]


def build_hypothesis(techniques):
    s = set(techniques)

    if "T1053.005" in s and "T1036" in s:
        return "Possible scheduled task execution with masquerading behavior"

    if "T1053.005" in s:
        return "Possible scheduled task based execution or persistence"

    if "T1036" in s:
        return "Possible masquerading behavior"

    if "T1059.001" in s and "T1547.001" in s:
        return "Possible persistence via PowerShell registry run key modification"

    if "T1190" in s and "T1505.003" in s:
        return "Possible web exploit followed by web shell persistence"

    if any(t.startswith("T1003") for t in s):
        return "Possible credential dumping activity"

    if "T1105" in s and any(t.startswith("T1059") for t in s):
        return "Possible remote payload transfer and command execution"

    if "T1110" in s or "T1078" in s:
        return "Possible account abuse or authentication-based intrusion"

    if "T1547.001" in s:
        return "Possible registry-based persistence behavior"

    if any(t.startswith("T1059") for t in s):
        return "Possible command or script execution activity"

    return "Suspicious correlated activity requiring analyst review"


def evidence_summary(events, chain, score_breakdown=None):
    primary_rules = collect_primary_rules(events)
    primary_techniques = collect_primary_techniques(chain)

    max_level = max([int(e.get("level", 0) or 0) for e in events] or [0])
    event_count = len(events)
    ctype = campaign_type(events)

    risk_factors = []
    limitations = []

    if max_level >= 12:
        risk_factors.append(f"High severity alert level {max_level}")

    if event_count >= 10:
        risk_factors.append("Repeated behavior observed across multiple events")
    elif event_count >= 2:
        risk_factors.append("Multiple related events observed in the same session")

    if any(t in primary_techniques for t in ["T1547.001", "T1505.003"]):
        risk_factors.append("Persistence technique observed")

    if any(t.startswith("T1059") for t in primary_techniques):
        risk_factors.append("Command or scripting execution observed")

    if any(t.startswith("T1003") for t in primary_techniques):
        risk_factors.append("Credential access technique observed")

    if "T1105" in primary_techniques:
        risk_factors.append("Ingress tool transfer or payload download observed")

    if "T1053.005" in primary_techniques:
        risk_factors.append("Scheduled task activity observed")

    if "T1036" in primary_techniques:
        risk_factors.append("Masquerading technique observed")

    if ctype == "host_behavior":
        limitations.append("No source IP or URL observed; this appears to be host-only evidence")

    if len(primary_rules) <= 1 and len(primary_techniques) > 1:
        limitations.append("Multiple MITRE techniques may originate from a small number of Wazuh rules")

    if event_count <= 3:
        limitations.append("Low event volume; analyst validation is recommended")

    hypothesis = build_hypothesis(primary_techniques)

    if ctype == "host_behavior":
        reason = "Host-based suspicious behavior was observed within a short time window"
    elif ctype == "network_campaign":
        reason = "Network indicators were correlated across related events"
    else:
        reason = "Host and network indicators were correlated into a single investigation session"

    return {
        "campaign_type": ctype,
        "primary_rules": primary_rules,
        "primary_techniques": primary_techniques,
        "hypothesis": hypothesis,
        "reason": reason,
        "risk_factors": risk_factors,
        "limitations": limitations,
        "score_caps": (score_breakdown or {}).get("caps_applied", []),
    }
