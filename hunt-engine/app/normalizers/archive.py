import re

PLACEHOLDERS = {"", "-", "unknown", "none", "null", "n/a"}

PATTERNS = [
    (r"\bpowershell(?:\.exe)?\b|\bpwsh(?:\.exe)?\b", "T1059.001", "execution"),
    (r"\bcmd\.exe\b|\bcmd\s+/c\b", "T1059.003", "execution"),
    (r"\bbash\b|\bsh\s+-c\b", "T1059.004", "execution"),
    (r"\b(?:curl|wget)\s+https?://", "T1105", "command-and-control"),
    (r"\bcertutil(?:\.exe)?\b.*\b-urlcache\b", "T1105", "command-and-control"),
    (r"\bwhoami\b", "T1033", "discovery"),
    (r"\bnet\s+user\b", "T1087", "discovery"),
    (r"\bnet\s+localgroup\b", "T1069", "discovery"),
    (r"\breg(?:\.exe)?\s+add\b", "T1112", "defense-evasion"),
    (r"\bschtasks(?:\.exe)?\s+/create\b", "T1053.005", "execution"),
    (r"currentversion\\run|\\runonce\b", "T1547.001", "persistence"),
    (r"\blsass(?:\.exe)?\b.*(?:dump|procdump|access|handle)", "T1003.001", "credential-access"),
    (r"\bmimikatz\b", "T1003", "credential-access"),
    (r"\bshell\.php\b|\bwebshell\b", "T1505.003", "persistence"),
    (r"\bcat\s+/etc/shadow\b|\b/etc/shadow\b", "T1003.008", "credential-access"),
    (r"\brm\s+-rf\s+/\b|\bvssadmin(?:\.exe)?\s+delete\s+shadows\b|\bdel\s+/f\s+/s\b", "T1485", "impact"),
]


def valid(v):
    return v is not None and str(v).strip().lower() not in PLACEHOLDERS


def infer_mitre_from_archive(full_log: str):
    log = full_log or ""
    techniques = []
    tactics = []

    for pattern, tid, tactic in PATTERNS:
        if re.search(pattern, log, re.I):
            if tid not in techniques:
                techniques.append(tid)
            if tactic not in tactics:
                tactics.append(tactic)

    return techniques, tactics


def extract_srcip(src):
    data = src.get("data", {}) or {}

    for key in ["srcip", "src_ip", "dstip", "dst_ip"]:
        if valid(data.get(key)):
            return data.get(key)

    full_log = src.get("full_log", "") or ""
    m = re.search(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", full_log)

    return m.group(0) if m else "-"


def normalize_archive(hit):
    src = hit.get("_source", {})
    full_log = src.get("full_log", "") or ""
    mitre_ids, tactics = infer_mitre_from_archive(full_log)

    return {
        "timestamp": src.get("@timestamp", "-"),
        "agent": src.get("agent", {}).get("name", "-"),
        "rule_id": "archive",
        "level": 0,
        "description": full_log[:300] if full_log else "Archived raw event",
        "mitre_id": mitre_ids,
        "tactic": tactics,
        "mitre_inferred": bool(mitre_ids),
        "srcip": extract_srcip(src),
        "url": src.get("data", {}).get("url", "-") if isinstance(src.get("data"), dict) else "-",
        "full_log": full_log,
        "source": "archive",
        "decoder": src.get("decoder", {}).get("name", "-"),
        "location": src.get("location", "-"),
        "raw": src,
    }
