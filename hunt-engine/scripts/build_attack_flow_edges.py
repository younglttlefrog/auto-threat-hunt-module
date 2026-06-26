import json
import re
from pathlib import Path
from collections import Counter

TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

ATTACK_FLOW_DIR = Path("playbooks/attack-flow")
OUT = Path("playbooks/generated/attack_flow_edges.json")
OUT.parent.mkdir(parents=True, exist_ok=True)

counter = Counter()

for path in ATTACK_FLOW_DIR.rglob("*"):
    if not path.is_file():
        continue
    if path.suffix.lower() not in [".json", ".afb", ".stix"]:
        continue

    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        continue

    techniques = TECH_RE.findall(text)

    seen = []
    for tid in techniques:
        if tid not in seen:
            seen.append(tid)

    for a, b in zip(seen, seen[1:]):
        if a != b:
            counter[(a, b)] += 1

edges = [
    {"source": a, "target": b, "weight": w}
    for (a, b), w in counter.most_common()
]

OUT.write_text(json.dumps(edges, indent=2, ensure_ascii=False), encoding="utf-8")

print(f"[OK] Edges: {len(edges)}")
print(f"[OK] Output: {OUT}")
