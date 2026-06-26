import json
import re
import yaml
from pathlib import Path
from collections import defaultdict

OUT = Path("playbooks/generated")
OUT.mkdir(parents=True, exist_ok=True)

MITRE_PLAYBOOK = Path("playbooks/generated/technique_playbooks.json")
ATOMIC_DIR = Path("playbooks/atomic-red-team/atomics")
ATTACK_FLOW_DIR = Path("playbooks/attack-flow")

tech_re = re.compile(r"T\d{4}(?:\.\d{3})?")

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

techniques = json.loads(MITRE_PLAYBOOK.read_text(encoding="utf-8"))

chain_kb = {}
for tid, obj in techniques.items():
    tactics = obj.get("tactics", [])
    order_values = [TACTIC_ORDER.index(t) for t in tactics if t in TACTIC_ORDER]

    chain_kb[tid] = {
        "technique_id": tid,
        "name": obj.get("name", ""),
        "tactics": tactics,
        "tactic_order": min(order_values) if order_values else 999,
        "mitigations": obj.get("mitigations", []),
        "atomic_tests": [],
        "attack_flow_refs": [],
    }

# Atomic Red Team
if ATOMIC_DIR.exists():
    for path in ATOMIC_DIR.glob("T*/T*.yaml"):
        tid = path.parent.name
        if tid not in chain_kb:
            continue

        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            continue

        for test in data.get("atomic_tests", []) or []:
            chain_kb[tid]["atomic_tests"].append({
                "name": test.get("name", ""),
                "description": test.get("description", ""),
                "supported_platforms": test.get("supported_platforms", []),
            })

# Attack Flow references and rough edges
flow_edges = defaultdict(lambda: defaultdict(int))
flow_refs = defaultdict(list)

flow_files = []
for pattern in ["**/*.json", "**/*.afb"]:
    flow_files.extend(ATTACK_FLOW_DIR.glob(pattern))

for path in flow_files:
    if "node_modules" in str(path):
        continue

    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        continue

    found = tech_re.findall(text)
    if not found:
        continue

    ordered = []
    for t in found:
        if not ordered or ordered[-1] != t:
            ordered.append(t)

    for t in set(ordered):
        if t in chain_kb:
            flow_refs[t].append(str(path))

    for a, b in zip(ordered, ordered[1:]):
        if a != b:
            flow_edges[a][b] += 1

for tid, refs in flow_refs.items():
    chain_kb[tid]["attack_flow_refs"] = sorted(set(refs))[:20]

edges = []
for src, dsts in flow_edges.items():
    for dst, weight in dsts.items():
        edges.append({
            "source": src,
            "target": dst,
            "weight": weight,
        })

(OUT / "attack_chain_kb.json").write_text(
    json.dumps(chain_kb, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

(OUT / "attack_flow_edges.json").write_text(
    json.dumps(edges, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

print(f"[OK] Techniques in KB: {len(chain_kb)}")
print(f"[OK] Flow edges: {len(edges)}")
print(f"[OK] Output: {OUT / 'attack_chain_kb.json'}")
print(f"[OK] Output: {OUT / 'attack_flow_edges.json'}")

for tid in ["T1595.002", "T1190", "T1059.001", "T1105", "T1546.011", "T1003.001"]:
    item = chain_kb.get(tid)
    print("\n==", tid, "==")
    if not item:
        print("Not found")
        continue
    print(item["name"])
    print("Tactics:", item["tactics"])
    print("Atomic tests:", len(item["atomic_tests"]))
    print("Attack Flow refs:", len(item["attack_flow_refs"]))
