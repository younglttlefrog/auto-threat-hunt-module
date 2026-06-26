from datetime import datetime

PLACEHOLDERS = {"", "-", "unknown", "none", "null", "n/a"}


def valid(v):
    return v is not None and str(v).strip().lower() not in PLACEHOLDERS


def as_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def parse_ts(ts):
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return None


def event_entities(e):
    anchors = set()
    context = set()
    weak = set()

    # Anchor entities are strong pivots that can connect campaigns.
    # Agent is intentionally NOT an anchor because one busy host can generate
    # unrelated events within the same hunt window.
    for k in ["srcip", "url", "user"]:
        if valid(e.get(k)):
            anchors.add(f"{k}:{str(e.get(k)).strip()}")

    # Context helps only when combined with another signal.
    if valid(e.get("agent")):
        context.add(f"agent:{str(e.get('agent')).strip()}")

    # MITRE is weak. It should not merge unrelated campaigns by itself.
    for tid in as_list(e.get("mitre_id")):
        if valid(tid):
            weak.add(f"mitre:{str(tid).strip()}")

    return anchors, context, weak


def is_weak_archive(e):
    if e.get("source") != "archive":
        return False

    anchors, context, weak = event_entities(e)

    # Raw archive event with only agent/context and no useful pivot should not
    # create or expand campaign.
    has_anchor = bool(anchors)
    has_mitre = bool(weak)

    return not has_anchor and not has_mitre


def cluster_events(events, window_minutes=30, weak_window_minutes=5, min_campaign_events=2):
    sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))

    campaigns = []

    for ev in sorted_events:
        if is_weak_archive(ev):
            continue

        ts = parse_ts(ev.get("timestamp"))
        anchors, context, weak = event_entities(ev)

        # Must have at least one meaningful signal.
        # Agent-only event is not enough.
        if not ts or (not anchors and not weak):
            continue

        matched = []

        for idx, c in enumerate(campaigns):
            if not c["last_ts"]:
                continue

            delta = abs((ts - c["last_ts"]).total_seconds()) / 60

            anchor_hit = bool(anchors.intersection(c.get("anchors", set())))
            same_agent = bool(context.intersection(c.get("context", set())))
            weak_hit = bool(weak.intersection(c.get("weak_entities", set())))

            # Rule 1: anchor match can connect within normal campaign window.
            if delta <= window_minutes and anchor_hit:
                matched.append(idx)
                continue

            # Rule 2: MITRE can connect only if same agent and very close in time.
            # This prevents 120-day hunts from merging unrelated T1059/T1078 events.
            if delta <= weak_window_minutes and same_agent and weak_hit:
                matched.append(idx)
                continue

        if not matched:
            campaigns.append({
                "events": [ev],
                "anchors": set(anchors),
                "context": set(context),
                "weak_entities": set(weak),
                "last_ts": ts,
            })
            continue

        base = matched[0]
        campaigns[base]["events"].append(ev)
        campaigns[base]["anchors"].update(anchors)
        campaigns[base]["context"].update(context)
        campaigns[base]["weak_entities"].update(weak)
        campaigns[base]["last_ts"] = max(campaigns[base]["last_ts"], ts)

        for idx in reversed(matched[1:]):
            campaigns[base]["events"].extend(campaigns[idx]["events"])
            campaigns[base]["anchors"].update(campaigns[idx]["anchors"])
            campaigns[base]["context"].update(campaigns[idx]["context"])
            campaigns[base]["weak_entities"].update(campaigns[idx]["weak_entities"])
            if campaigns[idx]["last_ts"] and campaigns[idx]["last_ts"] > campaigns[base]["last_ts"]:
                campaigns[base]["last_ts"] = campaigns[idx]["last_ts"]
            del campaigns[idx]

    result = {}
    counter = 1

    for c in campaigns:
        evs = sorted(c["events"], key=lambda e: e.get("timestamp", ""))
        if len(evs) < min_campaign_events:
            continue

        key = f"campaign-{counter:03d}"
        result[key] = evs
        counter += 1

    return result
