import json
import re
from pathlib import Path

SRC_DIR = Path("playbooks/codebyharri-playbooks")
OUT = Path("playbooks/generated/response_actions.json")
OUT.parent.mkdir(parents=True, exist_ok=True)

TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

FIELD_MAP = {
    "log sources to investigate": "log_sources",
    "log sources": "log_sources",
    "key indicators": "key_indicators",
    "questions for analysis": "questions",
    "decision for escalation": "escalate_if",
    "additional analysis steps for l1": "l1_actions",
    "l1 analyst actions": "l1_actions",
    "t2 analyst actions": "l2_actions",
    "tier 2 analyst actions": "l2_actions",
    "containment and further analysis": "containment",
}

def clean_text(s):
    s = str(s or "")
    s = re.sub(r"<br\s*/?>", "\n", s, flags=re.I)
    s = s.replace("&nbsp;", " ")
    s = s.replace("**", "").replace("`", "")
    s = s.replace("\r", "\n")
    return s.strip()

def clean_item(s):
    s = clean_text(s)
    s = re.sub(r"^\s*[-*]\s*", "", s)
    s = re.sub(r"^\s*\d+[\.)]\s*", "", s)
    s = " ".join(s.split())
    return s.strip(" |")

def split_items(value):
    value = clean_text(value)

    lines = []
    for raw in value.splitlines():
        raw = raw.strip()
        if not raw:
            continue

        # split only numbered list markers, not Event ID 4698/4700
        parts = re.split(r"(?:(?<=^)|(?<=\s))(?=\d+[\.)]\s+)", raw)

        for p in parts:
            item = clean_item(p)
            if not item:
                continue
            if item.lower().startswith("escalate to tier"):
                continue
            if re.fullmatch(r"[-:| ]+", item):
                continue
            lines.append(item)

    return list(dict.fromkeys(lines))

def parse_table_sections(text):
    sections = {v: [] for v in FIELD_MAP.values()}

    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("|") or "|" not in line[1:]:
            continue

        cells = [clean_item(c) for c in line.strip("|").split("|")]
        cells = [c for c in cells if c]

        if len(cells) < 2:
            continue

        key = cells[0].lower()
        value = " | ".join(cells[1:])

        if key in FIELD_MAP:
            sections[FIELD_MAP[key]].extend(split_items(value))

    for k in sections:
        sections[k] = list(dict.fromkeys(sections[k]))

    return sections

def technique_name_from_file(path, tid):
    name = path.stem.replace("_", " ").replace("-", " ")
    name = name.replace(tid, "")
    name = re.sub(r"^\s*\d+\s*", "", name)
    name = re.sub(r"^\s*0+\d+\s*", "", name)
    name = re.sub(r"\bMasquerading\b\s+", "", name)
    name = re.sub(r"\s+", " ", name).strip()
    return name or tid

def priority_for(tid, sections):
    high = {"T1003", "T1003.001", "T1190", "T1505.003", "T1485", "T1486", "T1105"}
    medium = {"T1059", "T1059.001", "T1059.003", "T1547.001", "T1110", "T1078", "T1053.005", "T1036"}

    text = " ".join(sections.get("key_indicators", []) + sections.get("escalate_if", [])).lower()

    if tid in high or "credential" in text or "ransom" in text or "web shell" in text:
        return "high"
    if tid in medium:
        return "medium"
    return "low"

def build_actions(tid, name, sections):
    actions = []

    for item in sections.get("l1_actions", [])[:4]:
        actions.append({
            "priority": "medium",
            "stage": "triage",
            "action": item,
            "reason": f"L1 validation step for {tid} {name}",
            "safe_mode": "manual_review",
            "commands": [],
        })

    for item in sections.get("l2_actions", [])[:4]:
        actions.append({
            "priority": "high",
            "stage": "investigation",
            "action": item,
            "reason": f"L2 investigation step for {tid} {name}",
            "safe_mode": "manual_review",
            "commands": [],
        })

    for item in sections.get("containment", [])[:3]:
        actions.append({
            "priority": "high",
            "stage": "containment_guidance",
            "action": item,
            "reason": f"Containment or further analysis guidance for {tid} {name}",
            "safe_mode": "requires_analyst_approval",
            "commands": [],
        })

    seen = set()
    out = []
    for a in actions:
        key = (a["stage"], a["action"])
        if key not in seen:
            seen.add(key)
            out.append(a)

    return out

result = {}

for path in SRC_DIR.rglob("*.md"):
    text = path.read_text(encoding="utf-8", errors="ignore")
    tids = TECH_RE.findall(path.name + "\n" + text)

    if not tids:
        continue

    tid = tids[0]
    name = technique_name_from_file(path, tid)
    sections = parse_table_sections(text)

    result[tid] = {
        "technique_id": tid,
        "name": name,
        "source": "CodeByHarri/MITRE-ATT_CK-Playbooks",
        "priority": priority_for(tid, sections),
        "log_sources": sections.get("log_sources", []),
        "key_indicators": sections.get("key_indicators", []),
        "questions": sections.get("questions", []),
        "escalate_if": sections.get("escalate_if", []),
        "recommended_actions": build_actions(tid, name, sections),
    }

OUT.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

print(f"[OK] Techniques: {len(result)}")
print(f"[OK] Output: {OUT}")
