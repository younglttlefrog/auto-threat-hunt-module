import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime

KB_PATH = Path("playbooks/generated/attack_chain_kb.json")
EDGE_PATH = Path("playbooks/generated/attack_flow_edges.json")

TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


def as_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def count_field(v):
    if isinstance(v, list):
        return len(v)
    if isinstance(v, dict):
        return len(v)
    try:
        return int(v or 0)
    except Exception:
        return 0


def load_json(path, default):
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default


def parse_ts(ts):
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return None


def tactic_order(tactics):
    vals = as_list(tactics)
    return min([TACTIC_ORDER.index(t) for t in vals if t in TACTIC_ORDER] or [999])


def reconstruct_attack_chain(events):
    kb = load_json(KB_PATH, {})
    edge_kb = load_json(EDGE_PATH, [])

    technique_events = defaultdict(list)
    first_seen = {}

    for e in events:
        for tid in as_list(e.get("mitre_id")):
            if tid is None:
                continue

            tid = str(tid).strip()
            if not tid or tid.lower() in ["-", "unknown", "null", "none", "n/a"]:
                continue

            technique_events[tid].append(e)

            ts = parse_ts(e.get("timestamp"))
            if ts and (tid not in first_seen or ts < first_seen[tid]):
                first_seen[tid] = ts

    observed = sorted(technique_events.keys())

    if not observed:
        return {
            "observed_techniques": [],
            "chain": [],
            "edges": [],
            "tactic_count": 0,
            "technique_count": 0,
            "confidence": 0,
        }

    chain = []

    for tid in observed:
        meta = kb.get(tid, {})
        tactics = as_list(meta.get("tactics", []))

        atomic_tests = count_field(meta.get("atomic_tests", 0))
        attack_flow_refs = count_field(meta.get("attack_flow_refs", 0))

        rule_ids = sorted(set(
            str(e.get("rule_id", "-"))
            for e in technique_events[tid]
            if str(e.get("rule_id", "-")) not in ["-", "unknown", "null", "none"]
        ))

        sources = sorted(set(
            str(e.get("source", "-"))
            for e in technique_events[tid]
            if str(e.get("source", "-")) not in ["-", "unknown", "null", "none"]
        ))

        chain.append({
            "technique_id": tid,
            "name": meta.get("name", tid),
            "tactics": tactics,
            "order": tactic_order(tactics),
            "atomic_tests": atomic_tests,
            "attack_flow_refs": attack_flow_refs,
            "event_count": len(technique_events[tid]),
            "rule_ids": rule_ids,
            "rule_count": len(rule_ids),
            "sources": sources,
            "source_count": len(sources),
            "first_seen": first_seen.get(tid).isoformat() if tid in first_seen else None,
        })

    chain = sorted(chain, key=lambda x: (x["order"], x.get("first_seen") or ""))

    observed_set = set(observed)
    edges = []

    for edge in edge_kb:
        src = edge.get("source")
        dst = edge.get("target")

        if src in observed_set and dst in observed_set:
            src_time = first_seen.get(src)
            dst_time = first_seen.get(dst)

            temporal_ok = bool(src_time and dst_time and src_time <= dst_time)

            src_order = next((c["order"] for c in chain if c["technique_id"] == src), 999)
            dst_order = next((c["order"] for c in chain if c["technique_id"] == dst), 999)

            tactic_ok = src_order <= dst_order

            weight = count_field(edge.get("weight", 1)) or 1
            score = weight

            if temporal_ok:
                score += 2
            if tactic_ok:
                score += 1

            edges.append({
                "source": src,
                "target": dst,
                "weight": weight,
                "score": score,
                "temporal_ok": temporal_ok,
                "tactic_ok": tactic_ok,
            })

    edges = sorted(edges, key=lambda e: e["score"], reverse=True)

    tactic_count = len(set(t for c in chain for t in as_list(c.get("tactics"))))
    technique_count = len(chain)

    ordered_times = [first_seen.get(c["technique_id"]) for c in chain if first_seen.get(c["technique_id"])]

    chain_is_time_ordered = True
    if len(ordered_times) >= 2:
        chain_is_time_ordered = all(
            ordered_times[i] <= ordered_times[i + 1]
            for i in range(len(ordered_times) - 1)
        )

    evidence_count = sum(c["event_count"] for c in chain)

    evidence_score = min(evidence_count * 4, 25)
    tactic_score = min(tactic_count * 5, 25)
    graph_score = min(len(edges) * 5, 20)
    temporal_score = 10 if chain_is_time_ordered and evidence_count >= technique_count else 0

    confidence = min(100, evidence_score + tactic_score + graph_score + temporal_score)

    # Calibration: tiny campaigns should not receive high confidence just
    # because they have multiple tactics or graph edges.
    all_rule_ids = set()
    for e in events:
        rid = str(e.get("rule_id", "-"))
        if rid not in ["-", "unknown", "null", "none"]:
            all_rule_ids.add(rid)

    unique_rule_count = len(all_rule_ids)

    # Technique inflation guard:
    # One Wazuh rule can map to multiple MITRE IDs. That should not be treated
    # as independent evidence for each technique.
    if technique_count > unique_rule_count and unique_rule_count > 0:
        confidence = min(confidence, 55)

    if evidence_count <= 3 and technique_count >= 3:
        confidence = min(confidence, 50)

    if evidence_count < 3:
        confidence = min(confidence, 45)
    elif evidence_count < 5:
        confidence = min(confidence, 65)

    return {
        "observed_techniques": observed,
        "chain": chain,
        "edges": edges,
        "tactic_count": tactic_count,
        "technique_count": technique_count,
        "confidence": confidence,
    }
