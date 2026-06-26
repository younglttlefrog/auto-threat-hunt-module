import json
from pathlib import Path
from collections import defaultdict

SRC = Path("playbooks/cti/enterprise-attack/enterprise-attack.json")
OUT = Path("playbooks/generated")
OUT.mkdir(parents=True, exist_ok=True)

data = json.loads(SRC.read_text(encoding="utf-8"))
objects = data["objects"]

techniques = {}
mitigations = {}
relationships = []

def external_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None

for obj in objects:
    if obj.get("revoked") or obj.get("x_mitre_deprecated"):
        continue

    oid = obj.get("id")
    typ = obj.get("type")

    if typ == "attack-pattern":
        tid = external_id(obj)
        if tid:
            techniques[oid] = {
                "technique_id": tid,
                "name": obj.get("name"),
                "description": obj.get("description", ""),
                "tactics": [
                    p.get("phase_name")
                    for p in obj.get("kill_chain_phases", [])
                    if p.get("kill_chain_name") == "mitre-attack"
                ],
                "mitigations": [],
            }

    elif typ == "course-of-action":
        mid = external_id(obj)
        if mid:
            mitigations[oid] = {
                "mitigation_id": mid,
                "name": obj.get("name"),
                "description": obj.get("description", ""),
            }

    elif typ == "relationship":
        relationships.append(obj)

for rel in relationships:
    if rel.get("relationship_type") != "mitigates":
        continue

    src = rel.get("source_ref")
    dst = rel.get("target_ref")

    if src in mitigations and dst in techniques:
        techniques[dst]["mitigations"].append(mitigations[src])

technique_playbooks = {
    v["technique_id"]: v
    for v in techniques.values()
}

(OUT / "technique_playbooks.json").write_text(
    json.dumps(technique_playbooks, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

print(f"[OK] Techniques: {len(technique_playbooks)}")
print(f"[OK] Output: {OUT / 'technique_playbooks.json'}")

for tid in ["T1003.001", "T1110", "T1190", "T1059.001", "T1562.001"]:
    print("\\n==", tid, "==")
    item = technique_playbooks.get(tid)
    if not item:
        print("Not found")
        continue
    print(item["name"])
    print("Tactics:", item["tactics"])
    print("Mitigations:", [m["mitigation_id"] + " " + m["name"] for m in item["mitigations"]])
