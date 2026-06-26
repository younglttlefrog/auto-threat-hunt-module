def build_timeline(events):
    seen = set()
    unique = []
    for e in events:
        key = (e["timestamp"], e["agent"], e["rule_id"], e["description"], e["full_log"])
        if key not in seen:
            seen.add(key)
            unique.append(e)
    return sorted(unique, key=lambda x: x["timestamp"])
