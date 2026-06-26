def normalize_hit(hit):
    src = hit.get("_source", {})

    rule = src.get("rule", {})
    mitre = rule.get("mitre", {})
    data = src.get("data", {})

    mitre_id = mitre.get("id", [])
    tactic = mitre.get("tactic", [])

    if isinstance(mitre_id, str):
        mitre_id = [mitre_id]

    if isinstance(tactic, str):
        tactic = [tactic]

    return {
        "timestamp": src.get("@timestamp", "-"),
        "agent": src.get("agent", {}).get("name", "-"),
        "rule_id": rule.get("id", "-"),
        "level": rule.get("level", 0),
        "description": rule.get("description", "-"),
        "mitre_id": mitre_id,
        "tactic": tactic,
        "srcip": data.get("srcip", "-"),
        "url": data.get("url", "-"),
        "full_log": src.get("full_log", "-"),
        "source": "alert",
        "decoder": src.get("decoder", {}).get("name", "-"),
        "location": src.get("location", "-"),
        "raw": src,
    }
