import json
from pathlib import Path

PLAYBOOK_PATH = Path("playbooks/generated/technique_playbooks.json")

def load_playbooks():
    if not PLAYBOOK_PATH.exists():
        return {}
    return json.loads(PLAYBOOK_PATH.read_text(encoding="utf-8"))

def collect_techniques(events):
    techniques = set()
    for e in events:
        mids = e.get("mitre_id", [])
        if isinstance(mids, str):
            mids = [mids]
        for mid in mids:
            if mid:
                techniques.add(mid)
    return sorted(techniques)

def get_recommendations(events):
    playbooks = load_playbooks()
    techniques = collect_techniques(events)

    output = []
    for tid in techniques:
        pb = playbooks.get(tid)
        if not pb:
            continue

        output.append({
            "technique_id": tid,
            "technique_name": pb.get("name", ""),
            "tactics": pb.get("tactics", []),
            "mitigations": pb.get("mitigations", []),
        })

    return output
